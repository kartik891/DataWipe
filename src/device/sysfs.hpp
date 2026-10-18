#pragma once
// Read-only helpers over /sys and /proc used by the safety guard. None of these open the
// target device itself, so they are safe to call on anything, including real disks.

#include <sys/types.h>

#include <optional>
#include <string>
#include <vector>

#include "core/result.hpp"

namespace dw::sysfs {

// Contents of a small sysfs/procfs file with trailing whitespace removed.
Result<std::string> read_file(const std::string& path);

// Kernel name ("loop3", "sda", "nvme0n1p2") for a block device number, via /sys/dev/block/M:m.
Result<std::string> block_name(dev_t rdev);

// Directory /sys/class/block/<name>.
std::string block_dir(const std::string& name);

bool is_partition(const std::string& name);

// Partition names of a whole-disk device (e.g. "loop3p1").
std::vector<std::string> partitions(const std::string& name);

// Devices stacked on top of this one (device-mapper, md, ...): /sys/class/block/<name>/holders.
std::vector<std::string> holders(const std::string& name);

// Mount points whose source is this device number, from /proc/self/mountinfo.
std::vector<std::string> mount_points(dev_t rdev);
// Ask the SCSI layer to re-read a disk's capacity (/sys/block/<name>/device/rescan).
Result<void> rescan_disk(const std::string& block_name);
// Active swap areas on block device `rdev` (from /proc/swaps). Swap is neither a mount nor a
// holder, so mount_points() and holders() cannot see it.
std::vector<std::string> swap_areas(dev_t rdev, const std::string& swaps_file = "/proc/swaps");

// For a loop device: the backing file path the kernel reports, or nullopt if detached.
std::optional<std::string> loop_backing_file(const std::string& loop_name);

// Loop devices currently backed by the file with this (st_dev, st_ino).
std::vector<std::string> loops_backed_by(dev_t file_dev, ino_t file_ino);

// Serial number of a physical device as the kernel exposes it, without opening the device:
// device/serial (NVMe, virtio, some USB), then SCSI VPD page 0x80 (SATA via libata's SAT
// layer, SAS), then device/wwid. Used only for the destructive-confirmation prompt.
Result<std::string> device_serial(const std::string& name);

}  // namespace dw::sysfs
