#ifdef __linux__
#include <linux/fs.h>  // BLKSECDISCARD
#endif

#include <format>

#include "core/log.hpp"
#include "engine/command_executor.hpp"

namespace dw {

namespace {

Error aborted(const DeviceCommand& cmd, const std::string& why) {
    return error(std::format("{} ABORTED by device: {}", cmd.name, why));
}

std::string payload_password(const std::vector<std::uint8_t>& payload) {
    std::string pw;
    for (size_t i = 2; i < 34 && i < payload.size() && payload[i] != 0; ++i) pw += static_cast<char>(payload[i]);
    return pw;
}

}  // namespace

SimulatedCommandExecutor::SimulatedCommandExecutor(const DeviceProfile& profile)
    : device_bytes_(profile.geometry.size_bytes) {
    st_.id = profile.identity;
}

Result<void> SimulatedCommandExecutor::preflight(std::span<const DeviceCommand> sequence) {
    SimulatedCommandExecutor dry = *this;  // copy of the drive state; the real one is untouched
    dry.quiet_ = true;
    for (const auto& cmd : sequence) {
        auto r = dry.issue(cmd);
        if (!r) return error("preflight: " + r.error().message);
        // Treat polls as "wait until complete", exactly as the plan executor will.
        for (int i = 0; r->in_progress && i < 1000; ++i) {
            r = dry.issue(cmd);
            if (!r) return error("preflight: " + r.error().message);
        }
    }
    return ok();
}

Result<void> SimulatedCommandExecutor::restore(std::span<const DeviceCommand> already_issued) {
    const bool was_quiet = std::exchange(quiet_, true);
    for (const auto& cmd : already_issued) {
        auto r = issue(cmd);
        for (int i = 0; r && r->in_progress && i < 1000; ++i) r = issue(cmd);
        if (!r) {
            quiet_ = was_quiet;
            return error("replaying " + cmd.name + ": " + r.error().message);
        }
    }
    quiet_ = was_quiet;
    return ok();
}

Result<CommandResult> SimulatedCommandExecutor::issue(const DeviceCommand& cmd) {
    if (!quiet_) log::info("[SIMULATED] -> {}", cmd.describe());
    auto r = dispatch(cmd);
    if (!quiet_) {
        if (!r) log::warn("[SIMULATED] <- {}", r.error().message);
        else if (r->in_progress) log::info("[SIMULATED] <- in progress {}% {}", r->progress_pct, r->detail);
        else log::info("[SIMULATED] <- OK {}", r->detail);
    }
    return r;
}

Result<CommandResult> SimulatedCommandExecutor::dispatch(const DeviceCommand& cmd) {
    // "Immediately preceded by" rules: any command clears the sequencing flags.
    const bool prepared = std::exchange(st_.erase_prepared, false);
    const bool native_read = std::exchange(st_.native_max_read, false);

    // A running sanitize locks the device out of everything but status queries.
    if (st_.sanitize == SimulatedDriveState::SanitizeState::InProgress && cmd.role != CommandRole::StatusPoll)
        return aborted(cmd, "sanitize operation in progress");

    const Transport t = st_.id.transport;
    switch (cmd.protocol) {
        case Protocol::ATA:
            if (t != Transport::SATA) return aborted(cmd, "device does not implement the ATA command set");
            return ata(cmd, prepared, native_read);
        case Protocol::NVMeAdmin:
            if (t != Transport::NVMe) return aborted(cmd, "device is not an NVMe controller");
            return nvme(cmd);
        case Protocol::eMMC:
            if (t != Transport::eMMC) return aborted(cmd, "device is not an eMMC");
            if (cmd.emmc_opcode == 6 && ((cmd.emmc_arg >> 16) & 0xFF) == 165) {
                if (!st_.id.sanitize_supported) return aborted(cmd, "EXT_CSD SEC_FEATURE_SUPPORT lacks SEC_SANITIZE");
                st_.effects.push_back("emmc-sanitize");
                return CommandResult{false, 100, "sanitize complete (DAT0 busy released)"};
            }
            return aborted(cmd, "unsupported eMMC command in simulation");
        case Protocol::BlockIoctl:
            if (cmd.range_offset + cmd.range_length > device_bytes_) return aborted(cmd, "range beyond device end");
            if (cmd.ioctl_request == BLKSECDISCARD) {
                if (!st_.id.emmc_secure_erase) return aborted(cmd, "EXT_CSD SEC_FEATURE_SUPPORT lacks SECURE_ER_EN");
                st_.effects.push_back("secure-discard");
                return CommandResult{false, 100, std::format("{} bytes securely erased", cmd.range_length)};
            }
            st_.effects.push_back("discard");
            return CommandResult{false, 100, std::format("{} bytes unmapped", cmd.range_length)};
        case Protocol::TCG:
            if (!st_.id.self_encrypting) return aborted(cmd, "Level 0 Discovery: no Locking feature");
            st_.effects.push_back("opal-genkey");
            return CommandResult{false, 100, "media encryption key regenerated"};
    }
    return aborted(cmd, "unknown protocol");
}

Result<CommandResult> SimulatedCommandExecutor::ata(const DeviceCommand& cmd, bool prepared, bool native_read) {
    AtaIdentity& id = st_.id;
    const AtaTaskfile& tf = *cmd.ata;

    auto security_common = [&]() -> Result<void> {
        if (!id.security_supported) return aborted(cmd, "Security feature set not supported");
        if (id.security_frozen) return aborted(cmd, "security FROZEN (SEC2/SEC6)");
        return ok();
    };

    switch (tf.command) {
        case 0xF1: {  // SECURITY SET PASSWORD
            if (auto r = security_common(); !r) return r.error();
            if (id.security_locked) return aborted(cmd, "device LOCKED (SEC4)");
            st_.password = payload_password(tf.payload);
            id.security_enabled = true;
            return CommandResult{false, 100, "user password set, security enabled (SEC5)"};
        }
        case 0xF2: {  // SECURITY UNLOCK
            if (!id.security_supported) return aborted(cmd, "Security feature set not supported");
            if (!id.security_enabled) return aborted(cmd, "security not enabled: nothing to unlock");
            // The password is only known here if it was set earlier in this sequence; on a real
            // drive with an unknown password, the drive itself decides.
            if (!st_.password.empty() && payload_password(tf.payload) != st_.password)
                return aborted(cmd, "password mismatch");
            id.security_locked = false;
            return CommandResult{false, 100, "unlocked (SEC5)"};
        }
        case 0xF6: {  // SECURITY DISABLE PASSWORD
            if (auto r = security_common(); !r) return r.error();
            if (!id.security_enabled) return aborted(cmd, "security not enabled: no password to remove");
            if (id.security_locked) return aborted(cmd, "device LOCKED (SEC4): SECURITY UNLOCK first");
            if (!st_.password.empty() && payload_password(tf.payload) != st_.password)
                return aborted(cmd, "password mismatch");
            id.security_enabled = false;
            st_.password.clear();
            return CommandResult{false, 100, "password removed, security disabled (SEC1)"};
        }
        case 0xF3:  // SECURITY ERASE PREPARE
            if (auto r = security_common(); !r) return r.error();
            st_.erase_prepared = true;
            return CommandResult{false, 100, "erase prepared"};
        case 0xF4: {  // SECURITY ERASE UNIT
            if (auto r = security_common(); !r) return r.error();
            if (!prepared) return aborted(cmd, "not immediately preceded by SECURITY ERASE PREPARE");
            const bool enhanced = !tf.payload.empty() && (tf.payload[0] & 0x02);
            if (enhanced && !id.enhanced_erase_supported) return aborted(cmd, "enhanced erase not supported");
            if (!id.security_enabled) return aborted(cmd, "security not enabled (no user password set)");
            if (payload_password(tf.payload) != st_.password) return aborted(cmd, "password mismatch");
            id.security_enabled = false;
            id.security_locked = false;
            st_.password.clear();
            st_.effects.push_back(enhanced ? "ata-se-enhanced" : "ata-se-normal");
            return CommandResult{false, 100, "erase complete, security disabled (SEC1)"};
        }
        case 0xB4: {  // SANITIZE DEVICE
            if (tf.features == 0x0000) return poll_sanitize();
            if (!id.sanitize_supported) return aborted(cmd, "Sanitize feature set not supported");
            if (id.security_locked) return aborted(cmd, "device LOCKED");
            if (tf.features == 0x0011) {
                if (!id.crypto_scramble_supported) return aborted(cmd, "CRYPTO SCRAMBLE not supported");
                if (tf.lba != 0x43727970) return aborted(cmd, "invalid CRYPTO SCRAMBLE signature in LBA");
                return start_sanitize("ata-crypto-scramble");
            }
            if (tf.features == 0x0012) {
                if (!id.block_erase_supported) return aborted(cmd, "BLOCK ERASE not supported");
                if (tf.lba != 0x426B4572) return aborted(cmd, "invalid BLOCK ERASE signature in LBA");
                return start_sanitize("ata-block-erase");
            }
            if (tf.features == 0x0014) {
                if (!id.overwrite_supported) return aborted(cmd, "OVERWRITE not supported");
                if ((tf.lba >> 32) != 0x4F57) return aborted(cmd, "invalid OVERWRITE signature in LBA");
                return start_sanitize("ata-sanitize-overwrite");
            }
            return aborted(cmd, std::format("unknown SANITIZE feature 0x{:04x}", tf.features));
        }
        case 0x27:  // READ NATIVE MAX ADDRESS EXT
            if (!id.hpa_supported) return aborted(cmd, "HPA feature set not supported");
            st_.native_max_read = true;
            return CommandResult{false, 100, std::format("native max LBA {}", id.native_max_sectors - 1)};
        case 0x37: {  // SET MAX ADDRESS EXT
            if (!id.hpa_supported) return aborted(cmd, "HPA feature set not supported");
            if (!native_read) return aborted(cmd, "not immediately preceded by READ NATIVE MAX ADDRESS EXT");
            if (tf.lba + 1 > id.native_max_sectors) return aborted(cmd, "requested max LBA beyond native max");
            id.user_addressable_sectors = tf.lba + 1;
            id.hpa_enabled = id.user_addressable_sectors < id.native_max_sectors;
            return CommandResult{false, 100, std::format("user-addressable now {} sectors ({})",
                                                         id.user_addressable_sectors,
                                                         (tf.count & 1) ? "non-volatile" : "volatile")};
        }
        case 0xB1:  // DEVICE CONFIGURATION
            if (tf.features != 0xC0) return aborted(cmd, "only DCO RESTORE is simulated");
            if (!id.dco_supported) return aborted(cmd, "DCO feature set not supported");
            if (id.user_addressable_sectors < id.native_max_sectors)
                return aborted(cmd, "an HPA is set; DCO RESTORE is refused while an HPA exists");
            id.native_max_sectors = id.dco_max_sectors;
            id.user_addressable_sectors = id.dco_max_sectors;
            return CommandResult{false, 100, std::format("factory configuration restored: {} sectors", id.dco_max_sectors)};
    }
    return aborted(cmd, std::format("opcode 0x{:02x} not simulated", tf.command));
}

Result<CommandResult> SimulatedCommandExecutor::nvme(const DeviceCommand& cmd) {
    const AtaIdentity& id = st_.id;  // SANICAP mapped: CES=crypto_scramble, BES=block_erase, OWS=overwrite
    const NvmeAdminCmd& n = *cmd.nvme;
    switch (n.opcode) {
        case 0x84: {  // Sanitize
            if (st_.sanitize == SimulatedDriveState::SanitizeState::InProgress)
                return aborted(cmd, "Sanitize In Progress");
            const auto sanact = static_cast<nvme::SanitizeAction>(n.cdw10 & 0x7);
            if (!id.sanitize_supported) return aborted(cmd, "Invalid Field (SANICAP = 0)");
            switch (sanact) {
                case nvme::SanitizeAction::CryptoErase:
                    if (!id.crypto_scramble_supported) return aborted(cmd, "Invalid Field (SANICAP.CES = 0)");
                    return start_sanitize("nvme-crypto-erase");
                case nvme::SanitizeAction::BlockErase:
                    if (!id.block_erase_supported) return aborted(cmd, "Invalid Field (SANICAP.BES = 0)");
                    return start_sanitize("nvme-block-erase");
                case nvme::SanitizeAction::Overwrite:
                    if (!id.overwrite_supported) return aborted(cmd, "Invalid Field (SANICAP.OWS = 0)");
                    return start_sanitize("nvme-overwrite");
                default: return aborted(cmd, "Invalid Field (SANACT)");
            }
        }
        case 0x02:  // Get Log Page
            if ((n.cdw10 & 0xFF) == 0x81) return poll_sanitize();
            return aborted(cmd, "log page not simulated");
        case 0x80: {  // Format NVM
            const unsigned ses = (n.cdw10 >> 9) & 0x7;
            if (ses == 2 && !id.self_encrypting) return aborted(cmd, "Invalid Format (FNA: crypto erase not supported)");
            if (ses != 1 && ses != 2) return aborted(cmd, "Invalid Field (SES)");
            st_.effects.push_back(ses == 2 ? "nvme-format-crypto" : "nvme-format-erase");
            return CommandResult{false, 100, "format complete"};
        }
    }
    return aborted(cmd, std::format("admin opcode 0x{:02x} not simulated", n.opcode));
}

Result<CommandResult> SimulatedCommandExecutor::start_sanitize(const std::string& effect) {
    st_.sanitize = SimulatedDriveState::SanitizeState::InProgress;
    st_.sanitize_progress = 0;
    st_.effects.push_back(effect);
    return CommandResult{false, 100, "sanitize operation started"};
}

Result<CommandResult> SimulatedCommandExecutor::poll_sanitize() {
    using S = SimulatedDriveState::SanitizeState;
    if (st_.sanitize == S::InProgress) {
        // Simulated time: each poll advances the operation by a quarter.
        st_.sanitize_progress += 25;
        if (st_.sanitize_progress >= 100) {
            st_.sanitize = S::Completed;
            return CommandResult{false, 100, "sanitize completed without error"};
        }
        return CommandResult{true, st_.sanitize_progress, "sanitize in progress"};
    }
    return CommandResult{false, 100, st_.sanitize == S::Completed ? "sanitize completed without error"
                                                                   : "no sanitize operation has run"};
}

// ---------------------------------------------------------------------------------------------

// Real issuance, when enabled, would map each protocol as follows (fd = device.native_handle()):
//   ATA        sg_io_hdr{ .interface_id='S', .cmdp=ata_pass_through_16(tf), .dxferp=payload,
//              .dxfer_direction=SG_DXFER_TO_DEV/NONE, .timeout=<IDENTIFY words 89/90 x 2 min> };
//              ioctl(fd, SG_IO, &hdr); ATA status/error come back in descriptor sense data
//              (CK_COND=1, sense key RECOVERED ERROR, ASC/ASCQ 00/1D).
//   NVMeAdmin  nvme_admin_cmd{ .opcode, .nsid, .cdw10, .cdw11 }; ioctl(ctrl_fd, NVME_IOCTL_ADMIN_CMD)
//              on /dev/nvmeN (the controller, not the namespace node).
//   eMMC       mmc_ioc_cmd{ .opcode=6, .arg, .flags=MMC_RSP_R1B|MMC_CMD_AC, .write_flag=1 };
//              ioctl(fd, MMC_IOC_CMD) on /dev/mmcblkN.
//   BlockIoctl uint64_t range[2]{offset, length}; ioctl(fd, BLKDISCARD / BLKSECDISCARD, range).
//   TCG        Opal ComPacket built per TCG Core spec, sent with ATA TRUSTED SEND (0x5E) or SCSI
//              SECURITY PROTOCOL OUT through the ATA/SCSI paths above.
// Status polls would sleep between iterations (SANITIZE can take hours on large HDDs).

std::unique_ptr<ICommandExecutor> make_command_executor(const DeviceProfile& profile, IBlockDevice& device,
                                                        PassthroughOptions opts) {
    if (profile.identity_source == IdentitySource::Simulated)
        return std::make_unique<SimulatedCommandExecutor>(profile);
    return std::make_unique<PassthroughCommandExecutor>(device, profile, std::move(opts));
}

}  // namespace dw
