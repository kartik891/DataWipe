#pragma once

#include <cstdint>
#include <string_view>

namespace dw {

// How the target is reached. This is decided by the safety guard from stat()/sysfs,
// never from what the user claims.
enum class BackendKind { ImageFile, LoopDevice, PhysicalBlock };

// What kind of medium the identity data describes. Drives method selection in Phase 2.
enum class MediaType { HDD, SSD_SATA, SSD_NVMe, eMMC, Unknown };

// Where the AtaIdentity came from. Every downstream record (logs, certificate) carries this
// so a simulated identity can never be mistaken for one read from hardware.
enum class IdentitySource {
    Simulated,     // profile JSON describing the drive an image/loop device stands in for
    AtaIdentify,   // IDENTIFY DEVICE (+ native max, DCO, TCG) read from a real SATA drive
    NvmeIdentify,  // Identify Controller/Namespace (+ TCG) read from a real NVMe drive
    EmmcExtCsd,    // EXT_CSD register (CMD8) + CID from a real eMMC device
    Sysfs,         // what the kernel exposes in /sys, without opening the device (no root needed)
    // Windows: the storage stack's device descriptor and geometry for a disk opened by the
    // operator (model, serial, bus, size, seek penalty, TRIM). These come from the drive via
    // its driver, but no firmware feature is queried.
    WindowsStorage,
};

// Identity good enough to act on a real drive: read from the drive with its own commands, or
// (Windows) from the storage stack's descriptor of a disk the process has opened. Not
// simulated, and not Linux sysfs-only detection.
constexpr bool is_hardware_identity(IdentitySource s) {
    return s == IdentitySource::AtaIdentify || s == IdentitySource::NvmeIdentify || s == IdentitySource::EmmcExtCsd ||
           s == IdentitySource::WindowsStorage;
}

// Whether firmware features (Secure Erase, SANITIZE, HPA/DCO, encryption) were read. When not,
// "false" in the identity means unknown, and plans fall to host overwrite.
constexpr bool capabilities_queried(IdentitySource s) {
    return s != IdentitySource::Sysfs && s != IdentitySource::WindowsStorage;
}

// Bus the identity was obtained over. Not an ATA field; on real hardware it is implied by
// which command set answered (ATA IDENTIFY vs NVMe Identify Controller vs eMMC EXT_CSD).
enum class Transport { SATA, NVMe, eMMC };

// Measured by the kernel right now (ioctl / fstat). Treated as ground truth.
struct DeviceGeometry {
    std::uint64_t size_bytes = 0;
    std::uint32_t logical_sector_size = 512;   // BLKSSZGET
    std::uint32_t physical_sector_size = 512;  // BLKPBSZGET
    std::uint64_t sector_count() const { return size_bytes / logical_sector_size; }
};

constexpr std::string_view to_string(BackendKind k) {
    switch (k) {
        case BackendKind::ImageFile: return "image-file";
        case BackendKind::LoopDevice: return "loop-device";
        case BackendKind::PhysicalBlock: return "physical-block";
    }
    return "?";
}

constexpr std::string_view to_string(MediaType m) {
    switch (m) {
        case MediaType::HDD: return "HDD";
        case MediaType::SSD_SATA: return "SSD-SATA";
        case MediaType::SSD_NVMe: return "SSD-NVMe";
        case MediaType::eMMC: return "eMMC";
        case MediaType::Unknown: return "unknown";
    }
    return "?";
}

constexpr std::string_view to_string(IdentitySource s) {
    switch (s) {
        case IdentitySource::Simulated: return "simulated";
        case IdentitySource::AtaIdentify: return "ata-identify";
        case IdentitySource::NvmeIdentify: return "nvme-identify";
        case IdentitySource::EmmcExtCsd: return "emmc-ext-csd";
        case IdentitySource::Sysfs: return "sysfs";
        case IdentitySource::WindowsStorage: return "windows-storage";
    }
    return "?";
}

constexpr std::string_view to_string(Transport t) {
    switch (t) {
        case Transport::SATA: return "sata";
        case Transport::NVMe: return "nvme";
        case Transport::eMMC: return "emmc";
    }
    return "?";
}

}  // namespace dw
