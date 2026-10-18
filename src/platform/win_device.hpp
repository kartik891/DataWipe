#pragma once
// Windows build only: physical disk queries behind the safety guard, the device factory,
// detection and the guided mode's drive list. Nothing here writes to a disk.

#include <cstdint>
#include <string>
#include <vector>

#include "core/result.hpp"
#include "device/win_storage.hpp"

namespace dw::win {

struct DiskQuery {
    winstorage::Inputs inputs;           // descriptor, size, logical sector, seek penalty, TRIM
    std::uint32_t physical_sector = 0;   // 0 = not reported
};

// Whether \\.\PhysicalDriveN exists and is a disk. Opens it with no access rights (works
// without Administrator) and checks IOCTL_STORAGE_GET_DEVICE_NUMBER.
Result<void> disk_exists(unsigned number);

// Read-only identity and geometry of disk N, through a handle opened with no access rights.
Result<DiskQuery> query_disk(unsigned number);

// What makes disk N unsafe to write: every volume with an extent on it (mounted or not; a
// volume Windows still has would be damaged mid-wipe and blocks raw writes to its sectors), and
// the disk holding the running Windows installation, and membership of a Storage Spaces pool or
// a dynamic-disk group (read from the partition table; needs Administrator rights).
std::vector<std::string> disk_usage(unsigned number);

// Disks present, ascending (\\.\PhysicalDrive0 .. 127).
std::vector<unsigned> disk_numbers();

// The disk number behind an open fd (IOCTL_STORAGE_GET_DEVICE_NUMBER). False if not a disk.
bool disk_number(int fd, unsigned& number);

// How the operator makes a disk with volumes writable.
std::string offline_hint(unsigned number);

}  // namespace dw::win
