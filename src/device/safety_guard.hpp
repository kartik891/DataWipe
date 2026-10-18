#pragma once
// Safety guard: decides whether a path may be opened at all, before any fd exists.
//
// Policy:
//   Regular file   -> allowed if owned by the invoking user, non-empty, sector-multiple size,
//                     and not currently attached to a loop device (use the loop device instead;
//                     writing both views at once bypasses the loop driver's cache).
//   Loop device    -> allowed if attached, the backing file is a regular file owned by the
//                     invoking (non-root) user, and nothing is mounted/stacked on it.
//                     The ownership rule is what rejects the system's own snap loop devices.
//   Partition      -> always refused (sanitization is whole-device).
//   Other block    -> classified PhysicalBlock. Read-only opens are allowed for detection, even
//                     while mounted. Writable opens need a PhysicalOverride (only
//                     confirm_physical_target() can create one) AND a device nothing is using.
//   Anything else  -> refused.
//
// The guard never enumerates disks: it only ever looks at the single path it was given. The one
// place that lists drives is the guided mode (cli/interactive.cpp), which passes each candidate
// through assess_target() and shows physical disks only under the destructive flag.

#include <sys/types.h>

#include <cstdint>

#include <iosfwd>
#include <string>
#include <vector>

#include "core/result.hpp"
#include "device/types.hpp"

namespace dw {

struct TargetAssessment {
    std::string requested_path;
    std::string canonical_path;  // realpath(): symlinks like /dev/disk/by-id/* resolved
    BackendKind kind = BackendKind::ImageFile;

    // Identity of the inode we assessed. open_target() re-checks these on the opened fd so a
    // path swapped between assessment and open() is detected (TOCTOU).
    dev_t st_dev = 0;
    ino_t st_ino = 0;
    dev_t rdev = 0;
    // Windows has no usable st_dev/st_ino: the volume serial number and file index instead.
    std::uint64_t file_volume = 0;
    std::uint64_t file_index = 0;

    std::string block_name;    // kernel name, block devices only
    std::string backing_file;  // loop devices only
    bool read_only = false;    // loop device attached read-only
    std::vector<std::string> in_use;  // physical devices: mounts/holders (blocks writable access)
    std::vector<std::string> notes;
};

// uid of the human behind this process: SUDO_UID when running under sudo, else getuid().
uid_t invoking_uid();

Result<TargetAssessment> assess_target(const std::string& path);

// Proof that a human confirmed a destructive operation on one specific physical device.
// Cannot be constructed except by confirm_physical_target().
class PhysicalOverride {
public:
    const std::string& canonical_path() const { return canonical_path_; }
    dev_t rdev() const { return rdev_; }
    const std::string& serial() const { return serial_; }

private:
    PhysicalOverride(std::string path, dev_t rdev, std::string serial)
        : canonical_path_(std::move(path)), rdev_(rdev), serial_(std::move(serial)) {}
    friend struct PhysicalConfirm;

    std::string canonical_path_;
    dev_t rdev_;
    std::string serial_;
};

struct ConfirmIO {
    std::istream& in;
    std::ostream& out;
    bool interactive;  // caller must pass isatty(STDIN_FILENO); piped answers are refused
};

// Requires: the --i-understand-this-is-destructive flag, an interactive terminal, the user
// retyping the kernel-reported serial number exactly, then retyping the device path.
Result<PhysicalOverride> confirm_physical_target(const TargetAssessment& target, bool destructive_flag,
                                                 const std::string& kernel_serial, ConfirmIO io);

}  // namespace dw
