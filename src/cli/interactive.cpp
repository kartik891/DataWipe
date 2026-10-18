// Guided mode: `datawipe` with no command on a terminal, or `datawipe interactive`.
//
// A menu over the same commands the scripted CLI offers. It adds no capability and removes no
// check: a wipe still goes through cmd_run, so a physical disk still needs the destructive
// flag on the command line and the operator retyping its serial number and path.
//
// This is the only place that enumerates drives. Without the destructive flag the list holds
// loop devices backed by an image the invoking user owns (none on Windows), and nothing else;
// physical disks (/dev/sdX, or \\.\PhysicalDriveN on Windows) appear only when the flag was
// given when starting the program.

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <format>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

#include "cli/cli.hpp"
#include "core/portable.hpp"
#include "core/cancel.hpp"
#include "core/log.hpp"
#include "device/safety_guard.hpp"
#include "device/sysfs.hpp"
#include "engine/command_support.hpp"
#include "engine/run_journal.hpp"
#ifdef _WIN32
#include "device/win_storage.hpp"
#include "platform/win_device.hpp"
#endif

namespace dwcli {

namespace {

namespace fs = std::filesystem;

// ---- Terminal -----------------------------------------------------------------------------

struct Style {
    bool on = false;
    std::string wrap(const char* code, std::string_view s) const {
        return on ? std::format("\x1b[{}m{}\x1b[0m", code, s) : std::string(s);
    }
    std::string bold(std::string_view s) const { return wrap("1", s); }
    std::string dim(std::string_view s) const { return wrap("2", s); }
    std::string good(std::string_view s) const { return wrap("1;32", s); }
    std::string bad(std::string_view s) const { return wrap("1;31", s); }
    std::string warn(std::string_view s) const { return wrap("1;33", s); }
};

Style make_style() {
    const char* term = std::getenv("TERM");
    return Style{::isatty(STDOUT_FILENO) && !std::getenv("NO_COLOR") && !(term && std::string_view(term) == "dumb")};
}

void rule() { std::cout << std::string(74, '-') << "\n"; }

// A line from the operator; nullopt at end of input, which every caller treats as "leave".
std::optional<std::string> ask(const std::string& prompt) {
    std::cout << prompt << std::flush;
    std::string line;
    if (!std::getline(std::cin, line)) {
        std::cout << "\n";
        return std::nullopt;
    }
    const auto b = line.find_first_not_of(" \t\r");
    if (b == std::string::npos) return std::string();
    return line.substr(b, line.find_last_not_of(" \t\r") - b + 1);
}

bool yes(const std::string& prompt, bool fallback) {
    auto a = ask(prompt + (fallback ? " [Y/n] " : " [y/N] "));
    if (!a || a->empty()) return a ? fallback : false;
    return (*a)[0] == 'y' || (*a)[0] == 'Y';
}

void pause() { ask("  Press Enter to continue "); }

std::string human_size(std::uint64_t bytes) {
    constexpr double kGiB = 1024.0 * 1024.0 * 1024.0;
    if (bytes >= 1024ull * 1024 * 1024 * 1024) return std::format("{:.2f} TiB", double(bytes) / (kGiB * 1024));
    if (bytes >= 1024ull * 1024 * 1024) return std::format("{:.1f} GiB", double(bytes) / kGiB);
    return std::format("{:.0f} MiB", double(bytes) / (1024.0 * 1024.0));
}

std::string human_minutes(double minutes) {
    const long m = std::max(1L, std::lround(minutes));
    return m >= 60 ? std::format("{} h {:02} min", m / 60, m % 60) : std::format("{} min", m);
}

// ---- Drives -------------------------------------------------------------------------------

struct Drive {
    std::string path, model, serial, bus;
    std::uint64_t bytes = 0;
    bool physical = false;
    bool boot_media = false;          // the DataWipe live image this system was started from
    std::string backing_file;         // loop devices
    std::vector<std::string> in_use;  // physical disks: what blocks wiping
    double usb_mbit = 0;              // negotiated USB speed, 0 = not USB
};

std::string sys_text(const std::string& path) {
    auto r = dw::sysfs::read_file(path);
    return r ? *r : std::string();
}

// Negotiated speed of the USB device a disk hangs off (Mbit/s): the "speed" attribute of the
// first ancestor that has one.
double usb_speed(const std::string& name) {
    std::error_code ec;
    fs::path dir = fs::canonical("/sys/block/" + name + "/device", ec);
    if (ec || dir.string().find("/usb") == std::string::npos) return 0;
    for (; dir.has_parent_path() && dir != dir.root_path(); dir = dir.parent_path())
        if (const std::string s = sys_text((dir / "speed").string()); !s.empty()) return std::atof(s.c_str());
    return 0;
}

// An ISO 9660 volume named DATAWIPE: the live image itself. Read-only: one aligned 4 KiB read
// holding the primary volume descriptor (sector 16 of 2048), so it also works on handles that
// only take sector-aligned I/O (Windows disks).
bool is_boot_media(const std::string& path) {
#ifdef _WIN32
    const int fd = dw::win::open_file(path.c_str(), false, true, true);
#else
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK);
#endif
    if (fd < 0) return false;
    std::unique_ptr<char, decltype(&dw::aligned_free)> buf(static_cast<char*>(dw::aligned_alloc_bytes(4096, 4096)),
                                                           &dw::aligned_free);
    const bool read_ok = buf && ::pread(fd, buf.get(), 4096, 16 * 2048) == 4096;
    ::close(fd);
    const char* id = buf.get() + 40;
    return read_ok && std::string_view(id, 8) == "DATAWIPE" && id[8] == ' ';
}

#ifdef _WIN32
std::string short_bus(dw::winstorage::Bus b) {
    using dw::winstorage::Bus;
    switch (b) {
        case Bus::FileBackedVirtual: return "VHD";
        case Bus::Fibre: return "FC";
        case Bus::Ieee1394: return "1394";
        case Bus::IScsi: return "iSCSI";
        default: return dw::winstorage::to_string(b).substr(0, 5);
    }
}
#endif

std::vector<Drive> list_drives([[maybe_unused]] bool include_physical) {
    std::vector<Drive> out;
#ifdef _WIN32
    // \\.\PhysicalDriveN, only under the destructive flag; queried with no access rights.
    if (!include_physical) return out;
    for (unsigned n : dw::win::disk_numbers()) {
        auto q = dw::win::query_disk(n);
        if (!q) continue;
        Drive d;
        d.path = dw::winstorage::disk_path(n);
        d.physical = true;
        d.bytes = q->inputs.disk_bytes;
        d.model = dw::winstorage::build_identity(q->inputs).model;
        d.serial = q->inputs.descriptor.serial;
        d.bus = short_bus(q->inputs.descriptor.bus);
        d.in_use = dw::win::disk_usage(n);
        d.boot_media = is_boot_media(d.path);
        out.push_back(std::move(d));
    }
    return out;
#endif
    std::error_code ec;
    std::vector<std::string> names;
    for (const auto& e : fs::directory_iterator("/sys/block", ec)) names.push_back(e.path().filename().string());
    std::sort(names.begin(), names.end());
    for (const auto& n : names) {
        // Never candidates: RAM disks, optical drives, stacked devices, eMMC hardware partitions.
        if (n.starts_with("ram") || n.starts_with("zram") || n.starts_with("sr") || n.starts_with("dm-") ||
            n.starts_with("md") || n.starts_with("fd") || n.starts_with("nbd") ||
            (n.starts_with("mmcblk") && ((n.find("boot") != std::string::npos) || (n.find("rpmb") != std::string::npos))))
            continue;
        const bool loop = n.starts_with("loop");
        if (!loop && !include_physical) continue;
        Drive d;
        d.path = "/dev/" + n;
        d.bytes = std::strtoull(sys_text("/sys/block/" + n + "/size").c_str(), nullptr, 10) * 512;
        if (d.bytes == 0) continue;
        auto assessed = dw::assess_target(d.path);
        if (loop) {
            // The guard's own rule decides: attached, backed by a file the invoking user owns.
            if (!assessed || assessed->kind != dw::BackendKind::LoopDevice) continue;
            d.backing_file = assessed->backing_file;
            d.bus = "loop";
            d.model = "image " + d.backing_file;
        } else {
            if (!assessed || assessed->kind != dw::BackendKind::PhysicalBlock) continue;
            d.physical = true;
            d.in_use = assessed->in_use;
            const std::string dev = "/sys/block/" + n + "/device/";
            d.model = sys_text(dev + "model");
            if (d.model.empty()) d.model = sys_text(dev + "name");
            if (auto s = dw::sysfs::device_serial(n)) d.serial = *s;
            d.usb_mbit = usb_speed(n);
            d.bus = d.usb_mbit > 0 ? "USB" : n.starts_with("nvme") ? "NVMe" : n.starts_with("mmcblk") ? "eMMC" : "SATA";
            d.boot_media = is_boot_media(d.path);
        }
        out.push_back(std::move(d));
    }
    return out;
}

void print_drives(const std::vector<Drive>& drives, const Style& st) {
    std::cout << st.bold(std::format("   #  {:<14} {:>10}  {:<5} {:<28} {}", "DEVICE", "SIZE", "BUS", "MODEL", "SERIAL"))
              << "\n";
    for (std::size_t i = 0; i < drives.size(); ++i) {
        const auto& d = drives[i];
        std::cout << std::format("  {:>2}  {:<14} {:>10}  {:<5} {:<28} {}", i + 1, d.path, human_size(d.bytes), d.bus,
                                 d.model.substr(0, 28), d.serial);
        if (d.boot_media) std::cout << "  " << st.warn("[this DataWipe boot media]");
        else if (!d.in_use.empty()) std::cout << "  " << st.warn("[IN USE: " + d.in_use.front() + "]");
        std::cout << "\n";
    }
}

// ---- Session ------------------------------------------------------------------------------

struct Session {
    Args base;  // options from the command line, applied to every action
    Style st;
    std::string identity;  // last simulated-drive profile used

    std::string state_dir() const {
        const char* d = std::getenv("DATAWIPE_STATE_DIR");
        return d && *d ? d : ".";
    }

    // --sign-key, else $DATAWIPE_SIGN_KEY, else the first key under <state dir>/keys.
    std::optional<std::string> sign_key() const {
        if (base.sign_key) return base.sign_key;
        if (const char* k = std::getenv("DATAWIPE_SIGN_KEY"); k && *k) return std::string(k);
        return first_in_keys(".key.pem");
    }

    std::optional<std::string> first_in_keys(std::string_view suffix) const {
        std::error_code ec;
        std::vector<std::string> found;
        for (const auto& e : fs::directory_iterator(fs::path(state_dir()) / "keys", ec))
            if (e.path().filename().string().ends_with(suffix)) found.push_back(e.path().string());
        if (found.empty()) return std::nullopt;
        return *std::min_element(found.begin(), found.end());
    }
};

void banner(const Session& s) {
    const auto key = s.sign_key();
    rule();
    std::cout << "  " << s.st.bold(std::string("DataWipe ") + DW_VERSION) << "  guided mode\n"
              << "  State directory  " << s.state_dir() << "  (journals, certificates, keys/)\n"
              << "  Signing key      " << (key ? *key : s.st.warn("none: certificates will be UNSIGNED")) << "\n"
              << "  Physical disks   "
              << (s.base.destructive ? s.st.warn("LISTED: wiping one still needs its serial number and path retyped")
                                     : std::string("hidden (start with ") + kDestructiveFlag + " to list them)")
              << "\n"
              << "  Firmware methods "
              << (s.base.experimental ? s.st.warn("including ones not yet validated on hardware (--experimental)")
                                      : std::string("validated ones only"))
              << "\n";
    rule();
}

// The drive to act on: a number from the list, or a path typed in. Fills the profile path for
// image files and loop devices, which need one to say what drive they simulate.
std::optional<Args> choose_target(Session& s, const std::string& verb) {
    const auto drives = list_drives(s.base.destructive);
    if (drives.empty())
        std::cout << "  No drives to list"
                  << (s.base.destructive ? "." : std::string(" (physical disks are hidden without ") + kDestructiveFlag + ").")
                  << "\n";
    else print_drives(drives, s.st);
    auto pick = ask(std::format("\n  Drive to {}: number, or the path of an image file or device (Enter cancels): ", verb));
    if (!pick || pick->empty()) return std::nullopt;

    Args a = s.base;
    const Drive* chosen = nullptr;
    if (std::all_of(pick->begin(), pick->end(), [](unsigned char c) { return std::isdigit(c); })) {
        const std::size_t i = std::strtoul(pick->c_str(), nullptr, 10);
        if (i < 1 || i > drives.size()) {
            std::cout << "  no such number\n";
            return std::nullopt;
        }
        chosen = &drives[i - 1];
        a.target = chosen->path;
    } else {
        a.target = *pick;
    }
    auto assessed = dw::assess_target(a.target);
    if (!assessed) {
        std::cout << "  " << s.st.bad("Refused: ") << assessed.error().describe() << "\n";
        return std::nullopt;
    }
    if (assessed->kind == dw::BackendKind::PhysicalBlock) {
        a.identity.reset();
        return a;
    }
    // Simulated drive: which profile describes it.
    const std::string fallback = !s.identity.empty() ? s.identity : s.base.identity.value_or("");
    auto prof = ask(std::format("  {} [{}] stands in for a drive. Profile of the drive it simulates (.json){}: ",
                                a.target, dw::to_string(assessed->kind), fallback.empty() ? "" : " [" + fallback + "]"));
    if (!prof) return std::nullopt;
    if (prof->empty()) *prof = fallback;
    if (prof->empty()) {
        std::cout << "  a profile is needed (the profiles folder next to the program, or /usr/share/datawipe/profiles)\n";
        return std::nullopt;
    }
    a.identity = s.identity = *prof;
    return a;
}

// ---- Plain-language screens ---------------------------------------------------------------

void describe_drive(const dw::DeviceProfile& p, const Style& st) {
    const auto& id = p.identity;
    std::cout << "  Drive            " << st.bold(id.model.empty() ? "(no model reported)" : id.model) << "\n"
              << "  Serial number    " << (id.serial.empty() ? "(none reported)" : id.serial) << "\n"
              << "  Device           " << p.path << "  [" << dw::to_string(p.backend) << "]\n"
              << "  Size             " << human_size(p.geometry.size_bytes) << "  (" << p.geometry.sector_count()
              << " sectors)\n"
              << "  Type             " << dw::to_string(p.media) << " on " << dw::to_string(id.transport)
              << (p.encrypted ? ", self-encrypting" : "") << "\n";
    if (p.identity_source == dw::IdentitySource::Simulated)
        std::cout << "  Identity         " << st.warn("SIMULATED") << " from " << p.identity_origin << "\n";
    if (p.identity_source == dw::IdentitySource::WindowsStorage) {
        std::cout << "  Capabilities     " << st.warn("not read by the Windows build: host overwrite (Clear) only") << "\n"
                  << "  Hidden area      " << st.warn("not checked (HPA/DCO): sectors hidden there are not wiped") << "\n";
    } else if (p.identity_source == dw::IdentitySource::Sysfs) {
        std::cout << "  Capabilities     " << st.warn("not read: run as root to query the drive itself") << "\n";
    } else {
        std::cout << "  Hidden area      "
                  << (p.hidden_sectors() ? st.warn(std::format("{} sectors (HPA/DCO)", p.hidden_sectors())) : "none") << "\n";
        std::string fw;
        if (id.security_supported) {
            fw = id.enhanced_erase_supported ? "ATA Secure Erase (enhanced)" : "ATA Secure Erase";
            if (id.security_locked) fw += ", " + st.bad("LOCKED");
            else if (id.security_frozen) fw += ", " + st.warn("FROZEN until the drive is power-cycled");
            else if (id.security_enabled) fw += ", " + st.warn("password set");
        }
        if (id.sanitize_supported) fw += std::string(fw.empty() ? "" : "; ") + "SANITIZE";
        std::cout << "  Firmware erase   " << (fw.empty() ? "none reported" : fw) << "\n";
    }
    for (const auto& w : p.warnings) std::cout << "  " << st.warn("Note") << "             " << w << "\n";
}

// Sustained sequential write speed to assume before anything has been measured (MiB/s). Only
// for the estimate on the plan screen; the progress bar reports the real figure.
double assumed_mib_per_s(const dw::DeviceProfile& p, double usb_mbit) {
    double v = 100;
    switch (p.media) {
        case dw::MediaType::HDD: v = 100; break;
        case dw::MediaType::SSD_SATA: v = 300; break;
        case dw::MediaType::SSD_NVMe: v = 800; break;
        case dw::MediaType::eMMC: v = 50; break;
        case dw::MediaType::Unknown: v = 100; break;
    }
    if (usb_mbit > 0 && usb_mbit <= 480) v = std::min(v, 30.0);  // USB 2.0 tops out near 30 MiB/s
    return v;
}

void describe_plan(const dw::DeviceProfile& p, const dw::WipePlan& plan, double usb_mbit, const Session& s) {
    const auto& st = s.st;
    std::cout << "\n  " << st.bold("What will happen") << "\n";
    double minutes = 0;
    bool unknown_firmware_time = false;
    const double rate = assumed_mib_per_s(p, usb_mbit);
    for (std::size_t i = 0; i < plan.steps.size(); ++i) {
        const auto& step = plan.steps[i];
        std::string note;
        if (step.execution == dw::Execution::Simulated) note = "  " + st.warn("(simulated: nothing is sent or written)");
        else if (step.execution == dw::Execution::Emulated) note = "  " + st.dim("(emulated by a host pass)");
        std::cout << std::format("    {}. {}", i + 1, step.title) << note << "\n";
        if (step.overwrite) {
            minutes += double(step.overwrite->sector_count) * p.geometry.logical_sector_size / (1024.0 * 1024.0) / rate / 60;
        } else if (step.execution == dw::Execution::Real && step.level != dw::SanitizationLevel::None) {
            const std::uint32_t m = (plan.method_id.find("ata-se-enhanced") != std::string::npos) ? p.identity.ata_enhanced_erase_minutes
                                    : (plan.method_id.find("ata-se-normal") != std::string::npos) ? p.identity.ata_erase_minutes
                                                                                : 0;
            if (m && m != dw::AtaIdentity::kEraseTimeOver508) minutes += m;
            else unknown_firmware_time = true;
        }
    }
    const bool purge = plan.level == dw::SanitizationLevel::Purge;
    std::cout << "\n  Method           " << plan.method_name << "\n"
              << "  Level reached    " << (purge ? st.good("Purge") : st.warn(std::string(dw::to_string(plan.level))))
              << "  (NIST SP 800-88)\n"
              << "  Verification     " << plan.verification.reason << "\n";
    if (!plan.fully_simulated()) {
        std::cout << "  Rough duration   about " << human_minutes(minutes) << " at " << std::format("{:.0f}", rate)
                  << " MiB/s" << (unknown_firmware_time ? ", plus the firmware erase (the drive gives no estimate)" : "")
                  << ", plus verification\n"
                  << "                   " << st.dim("an assumption until the first minute of writing shows the real speed")
                  << "\n";
    }
    const auto key = s.sign_key();
    std::cout << "  Certificate      " << (key ? "signed with " + *key : st.warn("UNSIGNED (no signing key)")) << "\n";
    for (const auto& w : plan.warnings) std::cout << "  " << st.warn("Warning") << "          " << w << "\n";
}

// ---- Actions ------------------------------------------------------------------------------

void action_list(Session& s) {
    const auto drives = list_drives(s.base.destructive);
    if (drives.empty()) std::cout << "  No drives to list.\n";
    else print_drives(drives, s.st);
#ifdef _WIN32
    if (!s.base.destructive)
        std::cout << "\n  Physical disks are hidden. To list them, start from an Administrator terminal:\n"
                  << "    datawipe interactive " << kDestructiveFlag
                  << "\n  Image files are never listed: give their path when asked for a drive.\n";
    else
        std::cout << "\n  A disk with volumes (drive letters, EFI or recovery partitions) is refused: take it offline\n"
                  << "  first (Set-Disk -Number N -IsOffline $true). The Windows build wipes by host overwrite (Clear).\n";
#else
    if (!s.base.destructive)
        std::cout << "\n  Physical disks are hidden. To list them, start: sudo datawipe interactive " << kDestructiveFlag
                  << "\n  Image files are never listed: give their path when asked for a drive.\n";
#endif
}

void action_inspect(Session& s) {
    auto a = choose_target(s, "inspect");
    if (!a) return;
    auto r = probe_target(*a, false);
    if (std::holds_alternative<int>(r)) return;
    const auto& p = std::get<Probed>(r).profile;
    std::cout << "\n";
    describe_drive(p, s.st);
    if (yes("\n  Show the full technical report?", false)) {
        std::cout << "\n";
        print_profile(p);
    }
}

void result_screen(const Session& s, int code, const std::string& target) {
    const auto& st = s.st;
    std::cout << "\n";
    rule();
    switch (code) {
        case 0:
            std::cout << "  " << st.good("DONE") << "  " << target << ": the plan completed. The verification result, the "
                      << "certificate, its PDF\n        copy and the session log are listed above.\n";
            break;
        case 7:
            std::cout << "  " << st.warn("PAUSED") << "  Progress is saved. Choose Wipe and the same drive again to resume.\n";
            break;
        case 10:
            std::cout << "  " << st.warn("ONE MORE RUN NEEDED") << "  The hidden area was removed. Choose Wipe and the same "
                      << "drive again to wipe\n        the full capacity (after a power cycle, if the message above asks "
                      << "for one).\n";
            break;
        case 8:
            std::cout << "  " << st.bad("NOT VERIFIED") << "  The wipe ran but the read-back found problems. Do not treat "
                      << "this drive as sanitized.\n";
            break;
        case 2:
            std::cout << "  " << st.bad("REFUSED") << "  Nothing was written. The reason is above.\n";
            break;
        case 6:
            std::cout << "  " << st.bad("FAILED") << "  A step failed; the journal is kept. Fix the cause shown above, "
                      << "then choose Wipe again.\n";
            break;
        default:
            std::cout << "  " << st.bad("STOPPED") << "  datawipe ended with code " << code << "; see the messages above.\n";
    }
    rule();
}

void action_wipe(Session& s) {
    auto chosen = choose_target(s, "WIPE");
    if (!chosen) return;
    Args a = *chosen;
    a.sign_key = s.sign_key();

    auto r = probe_target(a, false);
    if (std::holds_alternative<int>(r)) return;
    auto& probed = std::get<Probed>(r);
    const auto& p = probed.profile;
    const bool physical = p.backend == dw::BackendKind::PhysicalBlock;

    std::cout << "\n";
    describe_drive(p, s.st);
    double usb_mbit = 0;
    if (physical) {
        auto fresh = dw::assess_target(p.path);
        const std::vector<std::string> in_use = fresh ? fresh->in_use : std::vector<std::string>{};
        if (!in_use.empty()) {
#ifdef _WIN32
            std::cout << "\n  " << s.st.bad("Refused: ") << "this disk is in use (" << in_use.front() << ").\n  "
                      << dw::win::offline_hint(static_cast<unsigned>(fresh->rdev)) << ".\n";
#else
            std::cout << "\n  " << s.st.bad("Refused: ") << "this disk is in use (" << in_use.front()
                      << "). Unmount it and deactivate swap or stacked devices first.\n";
#endif
            return;
        }
        if (is_boot_media(p.path)) {
            std::cout << "\n  " << s.st.bad("Refused: ") << "this is the DataWipe boot media.\n";
            return;
        }
        if (auto name = fs::path(p.path).filename().string(); !name.empty()) usb_mbit = usb_speed(name);
    }

    auto plan = make_plan(a, p);
    if (!plan) return;

    // A stronger plan that needs commands this build has not seen work on real hardware.
    if (physical && !a.experimental) {
        dw::DeviceProfile full = p;
        dw::SelectorOptions opts = a.selector;
        dw::mask_unvalidated_capabilities(full, opts, true);
        if (auto stronger = dw::select_method(full, opts); stronger && stronger->method_id != plan->method_id) {
            describe_plan(p, *plan, usb_mbit, s);
            std::cout << "\n  The drive also supports: " << s.st.bold(stronger->method_name) << " ("
                      << dw::to_string(stronger->level) << ").\n"
#ifdef _WIN32
                      << "  It needs firmware commands sent through Windows' SCSI pass-through, which this project\n"
                      << "  has not yet run on real hardware (the same commands are validated on Linux). If Windows\n"
                      << "  or the drive rejects one, nothing is changed. The result is checked by read-back.\n";
#else
                      << "  It needs firmware commands that have not yet been validated on real hardware by this\n"
                      << "  project. The result is still checked by read-back afterwards.\n";
#endif
            if (yes("  Use that method instead?", false)) {
                a.experimental = true;
                plan = make_plan(a, p);
                if (!plan) return;
            }
        }
    }
    describe_plan(p, *plan, usb_mbit, s);

    // An interrupted wipe of this drive?
    if (!plan->fully_simulated()) {
        const auto journal = a.journal ? dw::Result<std::string>(*a.journal) : dw::RunJournal::default_path(p);
        std::error_code ec;
        if (journal && fs::exists(*journal, ec)) {
            std::cout << "\n  " << s.st.warn("An interrupted wipe of this drive is recorded") << " (" << *journal << ").\n";
            auto c = ask("  [r]esume it, [s]tart over, or Enter to cancel: ");
            if (!c || c->empty()) return;
            if ((*c)[0] == 'r' || (*c)[0] == 'R') a.resume = true;
            else if ((*c)[0] == 's' || (*c)[0] == 'S') a.restart = true;
            else return;
        }
    }

    std::cout << "\n";
    if (plan->fully_simulated()) {
        if (!yes("  This plan is simulated: nothing is written. Run it?", true)) return;
    } else if (physical) {
        std::cout << "  " << s.st.bad("ALL DATA ON " + p.path + " WILL BE DESTROYED.") << "\n"
                  << "  Next you are asked to retype the drive's serial number and its device path.\n";
        if (!yes("  Continue to that confirmation?", false)) return;
    } else {
        std::cout << "  " << s.st.bad("ALL DATA IN " + p.path + " WILL BE OVERWRITTEN.") << "\n";
        auto c = ask("  Type WIPE to continue: ");
        if (!c || *c != "WIPE") {
            std::cout << "  cancelled\n";
            return;
        }
    }
    std::cout << "  " << s.st.dim("Ctrl-C pauses safely at any time: progress is saved and can be resumed from this menu.")
              << "\n";

    probed.target.reset();  // cmd_run opens the target itself
    a.brief = true;
    const std::string target = a.target;
    const int code = cmd_run(a);
    dw::clear_cancel_signal_handlers();
    result_screen(s, code, target);
}

void action_verify_cert(Session& s) {
    std::vector<std::string> certs;
    std::error_code ec;
    for (const auto& e : fs::directory_iterator(s.state_dir(), ec))
        if (e.path().filename().string().ends_with(".dwcert.json")) certs.push_back(e.path().string());
    std::sort(certs.begin(), certs.end());
    for (std::size_t i = 0; i < certs.size(); ++i) std::cout << std::format("  {:>2}  {}\n", i + 1, certs[i]);
    if (certs.empty()) std::cout << "  No certificates in " << s.state_dir() << ".\n";
    auto pick = ask("\n  Certificate: number, or the path of a .dwcert.json / .pdf (Enter cancels): ");
    if (!pick || pick->empty()) return;
    Args a = s.base;
    a.target = *pick;
    if (std::all_of(pick->begin(), pick->end(), [](unsigned char c) { return std::isdigit(c); })) {
        const std::size_t i = std::strtoul(pick->c_str(), nullptr, 10);
        if (i < 1 || i > certs.size()) {
            std::cout << "  no such number\n";
            return;
        }
        a.target = certs[i - 1];
    }
    if (!a.pubkey) a.pubkey = s.first_in_keys(".pub.pem");
    if (!a.pubkey) {
        auto k = ask("  Issuer's public key (.pub.pem), or Enter to check integrity only: ");
        if (!k) return;
        if (!k->empty()) a.pubkey = *k;
    } else {
        std::cout << "  Checking against the public key " << *a.pubkey << "\n";
    }
    std::cout << "\n";
    const int code = cmd_verify_cert(a);
    std::cout << "\n  " << (code == 0 ? s.st.good("CERTIFICATE CHECK PASSED") : s.st.bad("CERTIFICATE CHECK FAILED")) << "\n";
}

void action_keygen(Session& s) {
    std::cout << "  A signing key identifies your organisation as the issuer of certificates. The private\n"
              << "  half is stored encrypted under a passphrase; the public half is what auditors need.\n";
    auto name = ask("  Key name, e.g. your organisation (letters, digits, - and _; Enter cancels): ");
    if (!name || name->empty()) return;
    if (!std::all_of(name->begin(), name->end(), [](unsigned char c) { return std::isalnum(c) || c == '-' || c == '_'; })) {
        std::cout << "  letters, digits, - and _ only\n";
        return;
    }
    const fs::path dir = fs::path(s.state_dir()) / "keys";
    std::error_code ec;
    fs::create_directories(dir, ec);
    ::chmod(dir.string().c_str(), 0700);
    const std::string prefix = (dir / *name).string();
    if (fs::exists(prefix + ".key.pem", ec)) {
        std::cout << "  " << prefix << ".key.pem already exists; choose another name\n";
        return;
    }
    Args a = s.base;
    a.target = prefix;
    if (cmd_keygen(a) == 0) {
        s.base.sign_key = prefix + ".key.pem";
        std::cout << "\n  " << s.st.good("Key created.") << " Certificates from this session are now signed with it.\n";
    }
}

void action_settings(Session& s) {
    std::cout << "   1) State directory     " << s.state_dir() << "\n"
              << "   2) Signing key         " << s.sign_key().value_or("none") << "\n"
              << "   3) Unvalidated firmware methods (--experimental): " << (s.base.experimental ? "ON" : "off") << "\n";
    auto c = ask("  Change which (Enter to go back): ");
    if (!c || c->empty()) return;
    if (*c == "1") {
        auto d = ask("  Directory for journals, certificates and keys: ");
        if (!d || d->empty()) return;
        std::error_code ec;
        fs::create_directories(*d, ec);
        if (!fs::is_directory(*d, ec)) {
            std::cout << "  cannot use " << *d << "\n";
            return;
        }
        ::setenv("DATAWIPE_STATE_DIR", d->c_str(), 1);
    } else if (*c == "2") {
        auto k = ask("  Private key file (.key.pem), or 'none': ");
        if (!k || k->empty()) return;
        if (*k == "none") {
            s.base.sign_key.reset();
            ::unsetenv("DATAWIPE_SIGN_KEY");
            if (s.sign_key()) std::cout << "  (a key under the state directory's keys/ is still picked up)\n";
        } else if (::access(k->c_str(), R_OK) != 0) {
            std::cout << "  cannot read " << *k << "\n";
        } else {
            s.base.sign_key = *k;
        }
    } else if (*c == "3") {
        s.base.experimental = !s.base.experimental;
        std::cout << "  now " << (s.base.experimental ? "ON" : "off") << "\n";
    }
}

}  // namespace

int cmd_interactive(const Args& args) {
    if (args.json) {
        dw::log::error("the guided mode has no --json output; use the probe/plan/run commands");
        return 1;
    }
    // The step-by-step command trace is for logs; the screens here say what is happening.
    if (!args.verbose) dw::log::set_level(dw::log::Level::Warn);
    Session s{args, make_style(), {}};
    s.base.command.clear();
    s.base.target.clear();
    s.base.resume = s.base.restart = false;  // asked per wipe
    while (true) {
        std::cout << "\n";
        banner(s);
        std::cout << "   1) List drives\n"
                  << "   2) Inspect a drive (read-only)\n"
                  << "   3) " << s.st.bold("WIPE a drive") << "\n"
                  << "   4) Verify a certificate\n"
                  << "   5) Create a signing key\n"
                  << "   6) Settings\n"
                  << "   q) Quit\n";
        auto c = ask("  Choice: ");
        if (!c || *c == "q" || *c == "Q") return 0;
        if (c->empty()) continue;
        rule();
        if (*c == "1") action_list(s);
        else if (*c == "2") action_inspect(s);
        else if (*c == "3") action_wipe(s);
        else if (*c == "4") action_verify_cert(s);
        else if (*c == "5") action_keygen(s);
        else if (*c == "6") action_settings(s);
        else continue;
        if (!std::cin) return 0;
        pause();
        if (!std::cin) return 0;
    }
}

}  // namespace dwcli
