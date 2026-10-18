#pragma once
// DeviceCommand: a fully specified storage command, down to the bytes that would go on the wire.
//
// The simulated executor logs and state-checks these; a passthrough executor would send the
// very same objects to the kernel. Building them is therefore identical in both modes, which
// is what makes the simulation a faithful stand-in rather than a mock.

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "device/ata_taskfile.hpp"

namespace dw {

enum class Protocol {
    ATA,         // via SCSI ATA PASS-THROUGH(16), ioctl(SG_IO)
    NVMeAdmin,   // via ioctl(NVME_IOCTL_ADMIN_CMD) on the controller node
    eMMC,        // via ioctl(MMC_IOC_CMD) on /dev/mmcblkN
    BlockIoctl,  // generic Linux block layer ioctl (BLKDISCARD, BLKSECDISCARD)
    TCG,         // TCG Storage (Opal) method call carried by ATA TRUSTED SEND/RECEIVE
};

// Role lets the plan executor treat status queries as "poll until done" without knowing
// protocol details.
enum class CommandRole { Action, StatusPoll, Query };

struct DeviceCommand {
    Protocol protocol = Protocol::ATA;
    CommandRole role = CommandRole::Action;
    std::string name;  // e.g. "SECURITY ERASE UNIT"
    std::vector<std::pair<std::string, std::string>> params;  // human-readable, for logs/certificate

    std::optional<AtaTaskfile> ata;
    std::optional<NvmeAdminCmd> nvme;
    std::uint32_t emmc_opcode = 0;  // CMD index
    std::uint32_t emmc_arg = 0;
    unsigned long ioctl_request = 0;                 // BlockIoctl
    std::uint64_t range_offset = 0, range_length = 0;  // BlockIoctl byte range

    // How Linux would deliver it, e.g. "ioctl(SG_IO) ATA PASS-THROUGH(16) CDB 85 0d 26 ...".
    std::string transport() const;
    // One-line description: name, params, transport.
    std::string describe() const;
};

// ---- Builders. Opcodes/signatures per ACS-3 (ATA), NVMe Base 2.0, JEDEC eMMC 5.1. ----
namespace ata {
// Set only for the erase and cleared by it. Deliberately fixed and documented, not random: if an
// erase is interrupted (power loss, crash, timeout) the drive keeps this password and locks at
// the next power-up, and it must then be recoverable without the journal (`datawipe ata-unlock`).
// The data it guards is being destroyed, so a public password protects nothing.
inline constexpr const char* kTempPassword = "DataWipeTmp";

DeviceCommand security_set_password(const std::string& password);
DeviceCommand security_erase_prepare();
DeviceCommand security_unlock(const std::string& password);            // SEC4 -> SEC5
DeviceCommand security_disable_password(const std::string& password);  // SEC5 -> SEC1
DeviceCommand security_erase_unit(const std::string& password, bool enhanced);
DeviceCommand sanitize_crypto_scramble();
DeviceCommand sanitize_block_erase();
DeviceCommand sanitize_overwrite(std::uint32_t pattern);
DeviceCommand sanitize_status();
DeviceCommand read_native_max_address_ext();
DeviceCommand set_max_address_ext(std::uint64_t max_lba, bool non_volatile);
DeviceCommand dco_restore();
}  // namespace ata

namespace nvme {
enum class SanitizeAction : std::uint8_t { ExitFailureMode = 1, BlockErase = 2, Overwrite = 3, CryptoErase = 4 };
DeviceCommand sanitize(SanitizeAction action, std::uint32_t overwrite_pattern = 0);
DeviceCommand sanitize_status_log();
// ses 1 = user data erase, 2 = cryptographic erase. Targets namespace `nsid` and keeps its
// current LBA format `lbaf` (both from the drive's identity).
DeviceCommand format_nvm(std::uint8_t ses, std::uint32_t nsid, std::uint8_t lbaf);
}  // namespace nvme

namespace emmc {
DeviceCommand sanitize();  // CMD6 SWITCH, EXT_CSD[165] SANITIZE_START := 1
}  // namespace emmc

namespace blk {
DeviceCommand discard(std::uint64_t offset, std::uint64_t length);
// BLKSECDISCARD: on eMMC the kernel issues Secure Erase / Secure Trim (CMD38, secure argument).
DeviceCommand secure_discard(std::uint64_t offset, std::uint64_t length);
}  // namespace blk

namespace tcg {
DeviceCommand opal_genkey_all_ranges();  // regenerate the media encryption key(s)
}  // namespace tcg

}  // namespace dw
