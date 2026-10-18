#pragma once
// Windows disk identity, decoded from what the Windows storage stack reports. Pure functions
// over byte buffers, so they build and are unit-tested on every platform; the IOCTLs that fill
// the buffers are in platform/win_device.cpp.
//
//   STORAGE_DEVICE_DESCRIPTOR     IOCTL_STORAGE_QUERY_PROPERTY(StorageDeviceProperty): vendor,
//                                 product, revision and serial strings, bus type
//   DISK_GEOMETRY_EX              IOCTL_DISK_GET_DRIVE_GEOMETRY_EX: bytes per sector, disk size
//   seek penalty, TRIM            StorageDeviceSeekPenaltyProperty / StorageDeviceTrimProperty
//
// The strings come from the drive (the driver's IDENTIFY / INQUIRY data). Firmware features
// (Secure Erase, SANITIZE, HPA/DCO, encryption) are not part of these, so an identity built
// here has them all unknown, and says so in probe_notes.

#include <cstdint>
#include <optional>
#include <span>
#include <string>

#include "core/result.hpp"
#include "device/identity.hpp"

namespace dw::winstorage {

// STORAGE_BUS_TYPE values (winioctl.h).
enum class Bus : std::uint32_t {
    Unknown = 0x00, Scsi = 0x01, Atapi = 0x02, Ata = 0x03, Ieee1394 = 0x04, Ssa = 0x05, Fibre = 0x06,
    Usb = 0x07, Raid = 0x08, IScsi = 0x09, Sas = 0x0A, Sata = 0x0B, Sd = 0x0C, Mmc = 0x0D,
    Virtual = 0x0E, FileBackedVirtual = 0x0F, Spaces = 0x10, Nvme = 0x11, Scm = 0x12, Ufs = 0x13,
};
std::string to_string(Bus b);

struct Descriptor {
    std::string vendor, product, revision, serial;
    Bus bus = Bus::Unknown;
    bool removable = false;
};

// Decodes a STORAGE_DEVICE_DESCRIPTOR. Offsets are bounds-checked; a zero offset means the
// string is absent. Strings are trimmed of padding.
Result<Descriptor> decode_descriptor(std::span<const std::uint8_t> buf);

// "\\.\PhysicalDrive3", "//./physicaldrive3", "\\?\PhysicalDrive3" -> 3. Anything else nullopt.
std::optional<unsigned> parse_disk_path(const std::string& path);
std::string disk_path(unsigned number);  // -> "\\.\PhysicalDrive3"

// True for paths in the Windows device namespace that are not whole disks (volumes such as
// "\\.\C:", "\\?\Volume{...}", CD-ROMs): never wipe targets.
bool is_device_namespace(const std::string& path);

// Partitions that mean another Windows storage layer owns the disk, so wiping it would break
// something that is not visible as a volume of this disk: a Storage Spaces pool member, or a
// dynamic (LDM) disk whose volumes may span other disks. Nullopt for ordinary partitions.
// `guid` is a GPT partition type GUID in Windows' in-memory layout (Data1-3 little-endian).
std::optional<std::string> owning_layer_gpt(std::span<const std::uint8_t, 16> guid);
std::optional<std::string> owning_layer_mbr(std::uint8_t partition_type);
std::string guid_string(std::span<const std::uint8_t, 16> guid);  // "E75CAF8F-F680-4CEE-AFA3-B001E56EFC2D"

struct Inputs {
    Descriptor descriptor;
    std::uint64_t disk_bytes = 0;
    std::uint32_t logical_sector = 512;
    std::optional<bool> seek_penalty;  // nullopt: the query failed (common behind USB bridges)
    std::optional<bool> trim;
};

// The identity a Windows disk gets: model/serial/firmware from the descriptor, capacity from
// the geometry (no HPA/DCO knowledge, so native max = user-addressable), transport from the
// bus, rotation from the seek penalty. Every firmware capability is false and recorded as
// not queried.
AtaIdentity build_identity(const Inputs& in);

}  // namespace dw::winstorage
