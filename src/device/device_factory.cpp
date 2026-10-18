#include "device/device_factory.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "core/log.hpp"
#include "device/backends.hpp"
#ifdef _WIN32
#include "platform/win_device.hpp"
#endif

namespace dw {

Result<OpenedTarget> open_target(const std::string& path, OpenOptions opts, const PhysicalOverride* override) {
    auto assessed = assess_target(path);
    if (!assessed) return assessed.error();
    TargetAssessment t = std::move(assessed).value();

    if (t.kind == BackendKind::PhysicalBlock && opts.writable) {
        if (!override)
            return error("REFUSED " + t.canonical_path + ": writing to a physical device requires explicit confirmation");
        if (override->canonical_path() != t.canonical_path || override->rdev() != t.rdev)
            return error("REFUSED " + t.canonical_path + ": confirmation was given for a different device (" +
                         override->canonical_path() + ")");
        if (!t.in_use.empty()) return error("REFUSED " + t.canonical_path + ": in use (" + t.in_use.front() + ")");
    }
    if (opts.writable && t.read_only) return error("REFUSED " + t.canonical_path + ": attached read-only");

    const bool is_block = t.kind != BackendKind::ImageFile;
    int flags = O_CLOEXEC | (opts.writable ? O_RDWR : O_RDONLY);
    if (opts.direct_io) flags |= O_DIRECT;
    // For writable block opens, O_EXCL (without O_CREAT) is a Linux-specific exclusive claim: open
    // fails with EBUSY if the device, or any partition of it, is mounted or claimed by another
    // holder, and nobody else can claim it while we hold the fd. Read-only detection skips it so
    // a mounted disk can still be identified.
    // For files, O_NOFOLLOW guarantees the final component didn't become a symlink since realpath().
    if (is_block && opts.writable) flags |= O_EXCL;
    if (!is_block) flags |= O_NOFOLLOW;

#ifdef _WIN32
    // A Win32 handle. Image files: unbuffered when direct I/O is asked for, one writer at a time.
    // Disks: always unbuffered (sector-aligned I/O straight to the drive).
    (void)flags;
    int fd = win::open_file(t.canonical_path.c_str(), opts.writable, opts.direct_io || is_block, is_block);
#else
    int fd = ::open(t.canonical_path.c_str(), flags);
#endif
    if (fd < 0) {
        const int err = errno;
        if (err == EBUSY) return error("REFUSED " + t.canonical_path + ": device is busy (mounted or claimed)");
        if (err == EACCES && t.kind == BackendKind::LoopDevice)
            return sys_error("open " + t.canonical_path + " (loop nodes are root:disk 0660; run via sudo, the "
                             "backing-file ownership check uses SUDO_UID)", err);
        return sys_error("open " + t.canonical_path, err);
    }

    // TOCTOU check: the inode we opened must be the inode we assessed.
#ifdef _WIN32
    std::uint64_t volume = 0, index = 0;
    unsigned disk = 0;
    const bool same = is_block ? win::disk_number(fd, disk) && disk == static_cast<unsigned>(t.rdev)
                               : win::file_identity(fd, volume, index) && volume == t.file_volume &&
                                     index == t.file_index;
#else
    struct stat st{};
    if (::fstat(fd, &st) != 0) {
        auto e = sys_error("fstat " + t.canonical_path);
        ::close(fd);
        return e;
    }
    const bool same = st.st_dev == t.st_dev && st.st_ino == t.st_ino && st.st_rdev == t.rdev;
#endif
    if (!same) {
        ::close(fd);
        return error("REFUSED " + t.canonical_path + ": target changed between safety check and open");
    }

    auto dev = is_block ? detail::make_block_device(fd, t, opts) : detail::make_image_device(fd, t, opts);
    if (!dev) return dev.error();

    log::info("opened {} [{}] {} ({} bytes, {}B logical / {}B physical sectors){}", t.canonical_path,
              to_string(t.kind), opts.writable ? "read-write" : "read-only", (*dev)->geometry().size_bytes,
              (*dev)->geometry().logical_sector_size, (*dev)->geometry().physical_sector_size,
              t.backing_file.empty() ? "" : " backing=" + t.backing_file);
    return OpenedTarget{std::move(dev).value(), std::move(t)};
}

}  // namespace dw
