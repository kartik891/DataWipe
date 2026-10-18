#pragma once
// ReadOnlyPassthrough: sends *query* commands to real hardware for device detection.
//
// Why a whitelist and not just an O_RDONLY fd: the kernel does not tie passthrough ioctls to
// the open mode. With CAP_SYS_RAWIO, SG_IO on a read-only fd will carry SECURITY ERASE UNIT;
// with CAP_SYS_ADMIN, NVME_IOCTL_ADMIN_CMD will carry Sanitize or Format. So every command is
// checked here against an explicit list of non-modifying commands before any ioctl is made.
//
//   ATA (SG_IO, ATA PASS-THROUGH(16))  IDENTIFY DEVICE 0xEC, READ NATIVE MAX ADDRESS EXT 0x27,
//                                      GET NATIVE MAX ADDRESS EXT (0x78 / feature 0x0000),
//                                      DEVICE CONFIGURATION IDENTIFY (0xB1 / feature 0xC2)
//   SCSI (SG_IO)                       SECURITY PROTOCOL IN 0xA2, protocol 0x00 or TCG Level 0
//                                      Discovery (protocol 0x01, ComID 0x0001)
//   NVMe admin                         Identify 0x06 (CNS 0 namespace, CNS 1 controller),
//                                      Security Receive 0x82 (same protocol limits as above)
//   eMMC (MMC_IOC_CMD)                 CMD8 SEND_EXT_CSD only

#include <cstdint>
#include <span>

#include "core/result.hpp"
#include "device/ata_taskfile.hpp"
#include "device/block_device.hpp"

namespace dw {

// ATA output registers, returned by the device when CK_COND=1.
struct AtaRegisters {
    std::uint8_t status = 0;
    std::uint8_t error = 0;
    std::uint16_t count = 0;
    std::uint64_t lba = 0;
    bool lba_valid = false;  // false when the transport only gave fixed-format sense
};

// Decode SCSI sense data carrying ATA registers (SAT: descriptor format 0x72 with the ATA
// Status Return descriptor 0x09, or fixed format 0x70). Pure, for testing.
Result<AtaRegisters> parse_ata_sense(std::span<const std::uint8_t> sense);

class ReadOnlyPassthrough {
public:
    explicit ReadOnlyPassthrough(const IBlockDevice& device) : device_(device) {}

    static Result<void> allow_ata(const AtaTaskfile& tf);
    static Result<void> allow_security_in(std::uint8_t protocol, std::uint16_t sp_specific);
    static Result<void> allow_nvme(const NvmeAdminCmd& cmd);

    // Non-data or PIO data-in ATA command. data_in must be sized count*512 for PIO-in.
    Result<AtaRegisters> ata(const AtaTaskfile& tf, std::span<std::uint8_t> data_in);
    // SCSI SECURITY PROTOCOL IN (libata translates it to ATA TRUSTED RECEIVE for SATA).
    Result<void> security_in(std::uint8_t protocol, std::uint16_t sp_specific, std::span<std::uint8_t> out);
    // NVMe admin command with data from the controller. Returns completion dword 0.
    Result<std::uint32_t> nvme_admin(const NvmeAdminCmd& cmd, std::span<std::uint8_t> data_in);
    // eMMC CMD8 SEND_EXT_CSD through MMC_IOC_CMD: the one MMC command this class sends.
    Result<void> mmc_ext_csd(std::span<std::uint8_t> out512);
    // NVME_IOCTL_ID: namespace id of an NVMe namespace block device.
    Result<std::uint32_t> nvme_namespace_id();

private:
    const IBlockDevice& device_;
};

// DevicePassthrough: the destructive counterpart, used only by PassthroughCommandExecutor.
// No whitelist: which commands may be sent is decided by the plan, its preflight and
// engine/command_support.hpp. It can only be created for a physical device that was opened
// writable, which open_target() allows only with a PhysicalOverride (the operator retyped the
// serial number and path). Timeouts are per command: a firmware erase can take hours.
class DevicePassthrough {
public:
    static Result<DevicePassthrough> create(IBlockDevice& device);

    Result<AtaRegisters> ata(const AtaTaskfile& tf, std::span<std::uint8_t> data_in, unsigned timeout_ms);
    Result<std::uint32_t> nvme_admin(const NvmeAdminCmd& cmd, std::span<std::uint8_t> data, unsigned timeout_ms);
    // BLKDISCARD / BLKSECDISCARD over a byte range.
    Result<void> block_ioctl(unsigned long request, std::uint64_t offset, std::uint64_t length);

private:
    explicit DevicePassthrough(IBlockDevice& d) : device_(d) {}
    IBlockDevice& device_;
};

}  // namespace dw
