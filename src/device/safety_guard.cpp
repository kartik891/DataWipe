#include "device/safety_guard.hpp"

#ifdef __linux__
#include <linux/major.h>  // LOOP_MAJOR
#include <sys/sysmacros.h>
#endif
#ifdef _WIN32
#include "device/win_storage.hpp"
#include "platform/win_device.hpp"
#endif
#include <sys/stat.h>
#include <unistd.h>

#include <charconv>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <regex>
#include <istream>
#include <ostream>

#include "core/log.hpp"
#include "device/sysfs.hpp"

namespace dw {

namespace {

Error refuse(const std::string& path, const std::string& why) {
    return error("REFUSED " + path + ": " + why);
}

}  // namespace

#ifdef _WIN32

// Windows: image files, and whole physical disks named \\.\PhysicalDriveN. Volumes (\\.\C:,
// \\?\Volume{...}) and anything else in the device namespace are refused before any handle
// exists. A disk is "in use" while Windows has any volume on it (platform/win_device.cpp).
uid_t invoking_uid() { return ::getuid(); }

Result<TargetAssessment> assess_target(const std::string& path) {
    TargetAssessment t;
    t.requested_path = path;
    if (const auto n = winstorage::parse_disk_path(path)) {
        t.canonical_path = winstorage::disk_path(*n);
        if (auto e = win::disk_exists(*n); !e) return refuse(t.canonical_path, e.error().message);
        t.kind = BackendKind::PhysicalBlock;
        t.block_name = "PhysicalDrive" + std::to_string(*n);
        t.rdev = static_cast<dev_t>(*n);
        t.in_use = win::disk_usage(*n);
        t.notes.push_back("PHYSICAL DISK: read-only detection allowed; writing requires "
                          "--i-understand-this-is-destructive, serial confirmation, Administrator rights and no "
                          "volume on the disk");
        return t;
    }
    if (winstorage::is_device_namespace(path) || path.starts_with("/dev/"))
        return refuse(path, "not a whole disk: volumes and partitions are never wipe targets. Name the disk as "
                            "\\\\.\\PhysicalDriveN (Get-Disk in PowerShell lists the numbers)");

    char resolved[PATH_MAX];
    if (!::realpath(path.c_str(), resolved)) return sys_error("realpath " + path);
    t.canonical_path = resolved;

    struct stat st{};
    if (::stat(resolved, &st) != 0) return sys_error("stat " + t.canonical_path);
    if (!S_ISREG(st.st_mode)) return refuse(t.canonical_path, "not a regular file");
    t.kind = BackendKind::ImageFile;
    if (st.st_size <= 0) return refuse(t.canonical_path, "image file is empty");
    if (st.st_size % 512 != 0)
        return refuse(t.canonical_path, "image size " + std::to_string(st.st_size) +
                                            " is not a multiple of 512 bytes (not a plausible disk image)");
    if (!win::file_identity(resolved, t.file_volume, t.file_index))
        return refuse(t.canonical_path, "cannot read the file's identity (volume serial and file index)");
    return t;
}

#else

namespace {

std::string join(const std::vector<std::string>& v) {
    std::string out;
    for (const auto& s : v) out += (out.empty() ? "" : ", ") + s;
    return out;
}

// Mounted filesystems or stacked devices (dm-crypt, LVM, md) on the device or any partition.
std::vector<std::string> usage(dev_t rdev, const std::string& name) {
    std::vector<std::string> out;
    if (auto m = sysfs::mount_points(rdev); !m.empty()) out.push_back("device is mounted at " + join(m));
    if (auto s = sysfs::swap_areas(rdev); !s.empty()) out.push_back("device is active swap (" + join(s) + ")");
    if (auto h = sysfs::holders(name); !h.empty()) out.push_back("device is held by " + join(h));
    for (const auto& part : sysfs::partitions(name)) {
        auto dev = sysfs::read_file(sysfs::block_dir(part) + "/dev");  // "M:m"
        if (!dev) continue;
        unsigned maj = 0, min = 0;
        if (std::sscanf(dev->c_str(), "%u:%u", &maj, &min) != 2) continue;
        if (auto m = sysfs::mount_points(makedev(maj, min)); !m.empty())
            out.push_back("partition " + part + " is mounted at " + join(m));
        if (auto s = sysfs::swap_areas(makedev(maj, min)); !s.empty())
            out.push_back("partition " + part + " is active swap (" + join(s) + ")");
        if (auto h = sysfs::holders(part); !h.empty()) out.push_back("partition " + part + " is held by " + join(h));
    }
    return out;
}

Result<void> check_not_in_use(const std::string& path, dev_t rdev, const std::string& name) {
    if (auto u = usage(rdev, name); !u.empty()) return refuse(path, "in use (" + u.front() + ")");
    return ok();
}

Result<void> assess_image(TargetAssessment& t, const struct stat& st) {
    const uid_t me = invoking_uid();
    if (me == 0)
        return refuse(t.canonical_path, "cannot determine the invoking user (running as root without "
                                        "sudo); image targets must be owned by a regular user");
    if (st.st_uid != me)
        return refuse(t.canonical_path, "image file is owned by uid " + std::to_string(st.st_uid) +
                                            ", not the invoking user (uid " + std::to_string(me) + ")");
    if (st.st_size <= 0) return refuse(t.canonical_path, "image file is empty");
    if (st.st_size % 512 != 0)
        return refuse(t.canonical_path, "image size " + std::to_string(st.st_size) +
                                            " is not a multiple of 512 bytes (not a plausible disk image)");
    if (auto loops = sysfs::loops_backed_by(st.st_dev, st.st_ino); !loops.empty())
        return refuse(t.canonical_path, "image is attached as /dev/" + join(loops) +
                                            "; target the loop device instead, or detach it first");
    return ok();
}

Result<void> assess_loop(TargetAssessment& t) {
    auto backing = sysfs::loop_backing_file(t.block_name);
    if (!backing) return refuse(t.canonical_path, "loop device is not attached to a backing file");
    t.backing_file = *backing;

    struct stat bst{};
    if (::stat(backing->c_str(), &bst) != 0)
        return refuse(t.canonical_path, "cannot stat backing file '" + *backing + "' (deleted?)");
    if (!S_ISREG(bst.st_mode))
        return refuse(t.canonical_path, "backing '" + *backing + "' is not a regular file");

    const uid_t me = invoking_uid();
    if (me == 0)
        return refuse(t.canonical_path, "cannot determine the invoking user (running as root without "
                                        "sudo); loop targets must be backed by a user-owned image");
    if (bst.st_uid != me)
        return refuse(t.canonical_path, "backing file '" + *backing + "' is owned by uid " +
                                            std::to_string(bst.st_uid) + ", not the invoking user (uid " +
                                            std::to_string(me) + ")");

    if (auto ro = sysfs::read_file(sysfs::block_dir(t.block_name) + "/ro"); ro && *ro == "1") {
        t.read_only = true;
        t.notes.push_back("loop device is attached read-only");
    }
    return check_not_in_use(t.canonical_path, t.rdev, t.block_name);
}

}  // namespace

uid_t invoking_uid() {
    uid_t uid = ::getuid();
    if (uid == 0) {
        if (const char* s = std::getenv("SUDO_UID")) {
            unsigned long v = 0;
            auto r = std::from_chars(s, s + std::char_traits<char>::length(s), v);
            if (r.ec == std::errc{} && *r.ptr == '\0') uid = static_cast<uid_t>(v);
        }
    }
    return uid;
}

Result<TargetAssessment> assess_target(const std::string& path) {
    TargetAssessment t;
    t.requested_path = path;

    char resolved[PATH_MAX];
    if (!::realpath(path.c_str(), resolved)) return sys_error("realpath " + path);
    t.canonical_path = resolved;

    struct stat st{};
    if (::stat(resolved, &st) != 0) return sys_error("stat " + t.canonical_path);
    t.st_dev = st.st_dev;
    t.st_ino = st.st_ino;
    t.rdev = st.st_rdev;

    if (S_ISREG(st.st_mode)) {
        t.kind = BackendKind::ImageFile;
        if (auto r = assess_image(t, st); !r) return r.error();
        return t;
    }

    if (!S_ISBLK(st.st_mode))
        return refuse(t.canonical_path, "not a regular file or block device");

    auto name = sysfs::block_name(st.st_rdev);
    if (!name) return refuse(t.canonical_path, name.error().describe());
    t.block_name = *name;

    if (sysfs::is_partition(t.block_name))
        return refuse(t.canonical_path, "is a partition; sanitization targets whole devices only");
    if (std::regex_match(t.block_name, std::regex(R"(mmcblk\d+(boot\d+|rpmb|gp\d+))")))
        return refuse(t.canonical_path, "is an eMMC hardware partition (boot/RPMB/general-purpose); target the eMMC "
                                        "device itself (its plan reports these areas)");

    if (major(st.st_rdev) == LOOP_MAJOR) {
        t.kind = BackendKind::LoopDevice;
        if (auto r = assess_loop(t); !r) return r.error();
        return t;
    }

    // Anything else is treated as real hardware. Assessment succeeds: read-only detection is
    // allowed (even while mounted), and open_target() enforces the rules for writable access.
    t.kind = BackendKind::PhysicalBlock;
    t.in_use = usage(t.rdev, t.block_name);
    t.notes.push_back("PHYSICAL DEVICE: read-only detection allowed; writing requires "
                      "--i-understand-this-is-destructive, serial confirmation, and an unused device");
    return t;
}

#endif  // _WIN32

// Friend of PhysicalOverride; the only code path that can mint one.
struct PhysicalConfirm {
    static Result<PhysicalOverride> run(const TargetAssessment& t, bool destructive_flag,
                                        const std::string& kernel_serial, ConfirmIO io) {
        if (t.kind != BackendKind::PhysicalBlock)
            return error("confirmation is only meaningful for physical block devices");
        if (!destructive_flag)
            return refuse(t.canonical_path, "physical device requires --i-understand-this-is-destructive");
        if (!io.interactive)
            return refuse(t.canonical_path, "physical device confirmation requires an interactive terminal");
        if (kernel_serial.empty())
            return refuse(t.canonical_path, "kernel reports no serial number; cannot confirm device identity");

        io.out << "\n"
               << "  !!! DESTRUCTIVE OPERATION ON A PHYSICAL DEVICE !!!\n"
               << "  device : " << t.canonical_path << " (" << t.block_name << ")\n"
               << "  All data on this device will be irreversibly destroyed.\n\n"
               << "  Type the device SERIAL NUMBER to continue: " << std::flush;
        std::string typed;
        if (!std::getline(io.in, typed) || typed != kernel_serial) {
            log::warn("physical confirmation failed: serial mismatch for {}", t.canonical_path);
            return refuse(t.canonical_path, "serial number confirmation did not match");
        }

        io.out << "  Type the full device path (" << t.canonical_path << ") to confirm: " << std::flush;
        if (!std::getline(io.in, typed) || typed != t.canonical_path) {
            log::warn("physical confirmation failed: path mismatch for {}", t.canonical_path);
            return refuse(t.canonical_path, "device path confirmation did not match");
        }

        log::warn("physical device {} (serial {}) CONFIRMED for destructive access by uid {}",
                  t.canonical_path, kernel_serial, invoking_uid());
        return PhysicalOverride(t.canonical_path, t.rdev, kernel_serial);
    }
};

Result<PhysicalOverride> confirm_physical_target(const TargetAssessment& target, bool destructive_flag,
                                                 const std::string& kernel_serial, ConfirmIO io) {
    return PhysicalConfirm::run(target, destructive_flag, kernel_serial, io);
}

}  // namespace dw
