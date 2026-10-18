#include "engine/device_command.hpp"

#ifdef __linux__
#include <linux/fs.h>  // BLKDISCARD
#endif

#include <format>

namespace dw {

std::string DeviceCommand::transport() const {
    switch (protocol) {
        case Protocol::ATA: {
            if (!ata) return "ATA (no taskfile)";
            std::string hex;
            for (auto b : ata_pass_through_16(*ata)) hex += std::format("{:02x} ", b);
            hex.pop_back();
            std::string s = "ioctl(SG_IO) ATA PASS-THROUGH(16) CDB [" + hex + "]";
            if (!ata->payload.empty()) s += std::format(" + {}-byte data-out", ata->payload.size());
            return s;
        }
        case Protocol::NVMeAdmin:
            if (!nvme) return "NVMe (no command)";
            return std::format("ioctl(NVME_IOCTL_ADMIN_CMD) opcode=0x{:02x} nsid=0x{:x} cdw10=0x{:08x} cdw11=0x{:08x}",
                               nvme->opcode, nvme->nsid, nvme->cdw10, nvme->cdw11);
        case Protocol::eMMC:
            return std::format("ioctl(MMC_IOC_CMD) CMD{} arg=0x{:08x}", emmc_opcode, emmc_arg);
        case Protocol::BlockIoctl:
            return std::format("ioctl(0x{:x}, range={{offset={}, length={}}})", ioctl_request, range_offset,
                               range_length);
        case Protocol::TCG:
            return "ATA TRUSTED SEND (0x5E) / SECURITY PROTOCOL OUT, protocol 0x01, ComID from Level 0 Discovery";
    }
    return "?";
}

std::string DeviceCommand::describe() const {
    std::string s = name;
    if (!params.empty()) {
        s += " (";
        for (size_t i = 0; i < params.size(); ++i) s += (i ? ", " : "") + params[i].first + "=" + params[i].second;
        s += ")";
    }
    return s + " via " + transport();
}

namespace {

DeviceCommand ata_cmd(std::string name, std::uint8_t opcode, bool ext, CommandRole role = CommandRole::Action) {
    DeviceCommand c;
    c.protocol = Protocol::ATA;
    c.role = role;
    c.name = std::move(name);
    AtaTaskfile tf;
    tf.command = opcode;
    tf.ext = ext;
    c.ata = tf;
    return c;
}

// 512-byte security data-out block: word 0 = control bits, words 1-16 = 32-byte password.
std::vector<std::uint8_t> password_block(const std::string& password, bool enhanced) {
    std::vector<std::uint8_t> b(512, 0);
    b[0] = enhanced ? 0x02 : 0x00;  // bit 0 identifier: 0 = user password; bit 1: enhanced erase
    for (size_t i = 0; i < password.size() && i < 32; ++i) b[2 + i] = static_cast<std::uint8_t>(password[i]);
    return b;
}

DeviceCommand ata_sanitize(std::string name, std::uint16_t feature, std::uint64_t lba_signature,
                           std::uint16_t count = 0) {
    auto c = ata_cmd(std::move(name), 0xB4, true);
    c.ata->features = feature;
    c.ata->lba = lba_signature;
    c.ata->count = count;
    return c;
}

}  // namespace

namespace ata {

DeviceCommand security_set_password(const std::string& password) {
    auto c = ata_cmd("SECURITY SET PASSWORD", 0xF1, false);
    c.ata->transfer = AtaTaskfile::Transfer::PioOut;
    c.ata->count = 1;
    c.ata->payload = password_block(password, false);
    c.params = {{"identifier", "user"}, {"password", password}};
    return c;
}

DeviceCommand security_erase_prepare() { return ata_cmd("SECURITY ERASE PREPARE", 0xF3, false); }

DeviceCommand security_unlock(const std::string& password) {
    auto c = ata_cmd("SECURITY UNLOCK", 0xF2, false);
    c.ata->transfer = AtaTaskfile::Transfer::PioOut;
    c.ata->count = 1;
    c.ata->payload = password_block(password, false);
    c.params = {{"identifier", "user"}};
    return c;
}

DeviceCommand security_disable_password(const std::string& password) {
    auto c = ata_cmd("SECURITY DISABLE PASSWORD", 0xF6, false);
    c.ata->transfer = AtaTaskfile::Transfer::PioOut;
    c.ata->count = 1;
    c.ata->payload = password_block(password, false);
    c.params = {{"identifier", "user"}};
    return c;
}

DeviceCommand security_erase_unit(const std::string& password, bool enhanced) {
    auto c = ata_cmd("SECURITY ERASE UNIT", 0xF4, false);
    c.ata->transfer = AtaTaskfile::Transfer::PioOut;
    c.ata->count = 1;
    c.ata->payload = password_block(password, enhanced);
    c.params = {{"mode", enhanced ? "enhanced" : "normal"}, {"identifier", "user"}};
    return c;
}

// SANITIZE DEVICE (0xB4). Each destructive sub-command must carry a fixed ASCII signature in
// the LBA field, a guard against a stray command erasing a drive.
DeviceCommand sanitize_crypto_scramble() {
    auto c = ata_sanitize("SANITIZE CRYPTO SCRAMBLE EXT", 0x0011, 0x43727970 /* "Cryp" */);
    c.params = {{"failure_mode", "0"}};
    return c;
}

DeviceCommand sanitize_block_erase() {
    auto c = ata_sanitize("SANITIZE BLOCK ERASE EXT", 0x0012, 0x426B4572 /* "BkEr" */);
    c.params = {{"failure_mode", "0"}};
    return c;
}

DeviceCommand sanitize_overwrite(std::uint32_t pattern) {
    // LBA 47:32 = "OW" signature, LBA 31:0 = pattern; COUNT 3:0 = pass count (1).
    auto c = ata_sanitize("SANITIZE OVERWRITE EXT", 0x0014, (0x4F57ull << 32) | pattern, 0x0001);
    c.params = {{"pattern", std::format("0x{:08x}", pattern)}, {"passes", "1"}, {"invert", "0"}};
    return c;
}

DeviceCommand sanitize_status() {
    auto c = ata_sanitize("SANITIZE STATUS EXT", 0x0000, 0);
    c.role = CommandRole::StatusPoll;
    return c;
}

DeviceCommand read_native_max_address_ext() {
    return ata_cmd("READ NATIVE MAX ADDRESS EXT", 0x27, true, CommandRole::Query);
}

DeviceCommand set_max_address_ext(std::uint64_t max_lba, bool non_volatile) {
    auto c = ata_cmd("SET MAX ADDRESS EXT", 0x37, true);
    c.ata->lba = max_lba;
    c.ata->count = non_volatile ? 1 : 0;  // bit 0: VV (value volatile) - 1 = persists across power cycles
    c.params = {{"max_lba", std::to_string(max_lba)}, {"non_volatile", non_volatile ? "1" : "0"}};
    return c;
}

DeviceCommand dco_restore() {
    auto c = ata_cmd("DEVICE CONFIGURATION RESTORE", 0xB1, false);
    c.ata->features = 0xC0;
    return c;
}

}  // namespace ata

namespace nvme {

DeviceCommand sanitize(SanitizeAction action, std::uint32_t overwrite_pattern) {
    DeviceCommand c;
    c.protocol = Protocol::NVMeAdmin;
    NvmeAdminCmd n;
    n.opcode = 0x84;
    n.nsid = 0;  // Sanitize acts on the whole NVM subsystem; NSID is not used
    n.cdw10 = static_cast<std::uint32_t>(action);  // SANACT bits 2:0; AUSE=0, OWPASS=0, NDAS=0
    switch (action) {
        case SanitizeAction::BlockErase: c.name = "NVMe SANITIZE (Block Erase)"; break;
        case SanitizeAction::CryptoErase: c.name = "NVMe SANITIZE (Crypto Erase)"; break;
        case SanitizeAction::Overwrite:
            c.name = "NVMe SANITIZE (Overwrite)";
            n.cdw10 |= 1u << 4;  // OWPASS = 1 pass
            n.cdw11 = overwrite_pattern;
            c.params = {{"pattern", std::format("0x{:08x}", overwrite_pattern)}, {"passes", "1"}};
            break;
        case SanitizeAction::ExitFailureMode: c.name = "NVMe SANITIZE (Exit Failure Mode)"; break;
    }
    c.nvme = n;
    return c;
}

DeviceCommand sanitize_status_log() {
    DeviceCommand c;
    c.protocol = Protocol::NVMeAdmin;
    c.role = CommandRole::StatusPoll;
    c.name = "NVMe GET LOG PAGE (Sanitize Status, LID 0x81)";
    NvmeAdminCmd n;
    n.opcode = 0x02;
    n.nsid = 0xFFFFFFFF;
    n.cdw10 = 0x81u | ((512u / 4 - 1) << 16);  // LID | NUMDL (dwords - 1)
    c.nvme = n;
    return c;
}

DeviceCommand format_nvm(std::uint8_t ses, std::uint32_t nsid, std::uint8_t lbaf) {
    DeviceCommand c;
    c.protocol = Protocol::NVMeAdmin;
    c.name = ses == 2 ? "NVMe FORMAT NVM (Cryptographic Erase)" : "NVMe FORMAT NVM (User Data Erase)";
    NvmeAdminCmd n;
    n.opcode = 0x80;
    n.nsid = nsid;
    // CDW10: LBAFL bits 3:0, SES bits 11:9, LBAFU bits 13:12 (NVMe 2.0). MSET/PI/PIL = 0.
    n.cdw10 = (lbaf & 0x0Fu) | static_cast<std::uint32_t>(ses & 7) << 9 | ((lbaf >> 4) & 0x03u) << 12;
    c.nvme = n;
    c.params = {{"ses", std::to_string(ses)}, {"nsid", std::to_string(nsid)}, {"lbaf", std::to_string(lbaf)}};
    return c;
}

}  // namespace nvme

namespace emmc {

DeviceCommand sanitize() {
    DeviceCommand c;
    c.protocol = Protocol::eMMC;
    c.name = "eMMC SANITIZE (CMD6 SWITCH EXT_CSD[165] SANITIZE_START=1)";
    c.emmc_opcode = 6;
    // Access=0b11 (write byte) << 24 | index 165 << 16 | value 1 << 8 | cmd set 0
    c.emmc_arg = (0x3u << 24) | (165u << 16) | (1u << 8);
    return c;
}

}  // namespace emmc

namespace blk {

DeviceCommand discard(std::uint64_t offset, std::uint64_t length) {
    DeviceCommand c;
    c.protocol = Protocol::BlockIoctl;
    c.name = "BLKDISCARD (unmap all LBAs)";
    c.ioctl_request = BLKDISCARD;
    c.range_offset = offset;
    c.range_length = length;
    return c;
}

DeviceCommand secure_discard(std::uint64_t offset, std::uint64_t length) {
    DeviceCommand c = discard(offset, length);
    c.name = "BLKSECDISCARD (secure erase of all LBAs)";
    c.ioctl_request = BLKSECDISCARD;
    return c;
}

}  // namespace blk

namespace tcg {

DeviceCommand opal_genkey_all_ranges() {
    DeviceCommand c;
    c.protocol = Protocol::TCG;
    c.name = "TCG Opal GenKey on all Locking Ranges";
    c.params = {{"session", "StartSession(LockingSP, Admin1)"},
                {"method", "GenKey(K_AES_*) per range"},
                {"effect", "media encryption key replaced; old ciphertext undecryptable"}};
    return c;
}

}  // namespace tcg

}  // namespace dw
