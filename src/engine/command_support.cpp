#include "engine/command_support.hpp"

namespace dw {

std::string_view to_string(Support s) {
    switch (s) {
        case Support::Proven: return "proven";
        case Support::Experimental: return "experimental";
        case Support::Unsupported: return "unsupported";
    }
    return "?";
}

namespace {

#ifdef _WIN32
// Windows: commands reach the drive through a different transport (SCSI pass-through). ATA
// commands are validated on Linux but not through it, so none is Proven here; Windows' inbox
// drivers do not pass NVMe Format/Sanitize, eMMC commands or Linux block ioctls through at all.
constexpr bool kWindows = true;
#else
constexpr bool kWindows = false;
#endif

SupportInfo command_support_linux(const DeviceCommand& c, MediaType media);

}  // namespace

SupportInfo command_support(const DeviceCommand& c, MediaType media) {
    SupportInfo s = command_support_linux(c, media);
    if (!kWindows || c.role != CommandRole::Action) return s;
    if (c.protocol == Protocol::NVMeAdmin || c.protocol == Protocol::eMMC || c.protocol == Protocol::BlockIoctl)
        return {Support::Unsupported, c.name + ": cannot be sent from Windows (its inbox drivers do not pass it "
                                               "through); use the bootable DataWipe image"};
    if (c.protocol == Protocol::ATA && s.level == Support::Proven)
        return {Support::Experimental, s.why + "; on Windows it goes through SCSI pass-through, which has not yet run "
                                               "on hardware"};
    return s;
}

namespace {

SupportInfo command_support_linux(const DeviceCommand& c, MediaType media) {
    const std::string untested = "not yet run against a drive that supports it (QEMU does not emulate it)";
    switch (c.protocol) {
        case Protocol::NVMeAdmin:
            if (c.nvme && c.nvme->opcode == 0x80 && ((c.nvme->cdw10 >> 9) & 7) == 1)
                return {Support::Proven, "NVMe Format NVM, user-data erase: exercised on the QEMU bench"};
            if (c.nvme && c.nvme->opcode == 0x80) return {Support::Experimental, "NVMe Format crypto erase: " + untested};
            if (c.nvme && c.nvme->opcode == 0x84) return {Support::Experimental, "NVMe Sanitize: " + untested};
            if (c.role != CommandRole::Action) return {Support::Proven, "read-only query"};
            return {Support::Experimental, "NVMe admin command: " + untested};
        case Protocol::ATA:
            if (c.role == CommandRole::Query) return {Support::Proven, "read-only query"};
            // The enhanced Secure Erase sequence on an HDD: SET PASSWORD, ERASE PREPARE, ERASE
            // UNIT with the enhanced bit. Proven on real hardware (see command_support.hpp).
            if (media == MediaType::HDD && c.ata) {
                const bool enhanced_erase = c.ata->command == 0xF4 && !c.ata->payload.empty() && (c.ata->payload[0] & 0x02);
                if (c.ata->command == 0xF1 || c.ata->command == 0xF3 || enhanced_erase)
                    return {Support::Proven, "ATA enhanced Secure Erase on an HDD: passed on real hardware"};
            }
            return {Support::Experimental, "ATA " + c.name + ": " + (media == MediaType::HDD || !c.ata || c.ata->command < 0xF1 || c.ata->command > 0xF6
                                                                     ? untested
                                                                     : std::string("validated on HDDs only; on SSDs it has a "
                                                                                   "measured silent-failure rate"))};
        case Protocol::BlockIoctl: return {Support::Experimental, c.name + ": " + untested};
        case Protocol::eMMC: return {Support::Experimental, "eMMC SANITIZE: " + untested};
        case Protocol::TCG:
            return {Support::Unsupported, "TCG Opal key operations need an authenticated session protocol, not "
                                          "implemented; use the drive vendor's PSID revert"};
    }
    return {Support::Unsupported, "unknown protocol"};
}

}  // namespace

std::vector<std::string> mask_unvalidated_capabilities(DeviceProfile& p, SelectorOptions& opts, bool experimental) {
    std::vector<std::string> out;
    if (p.identity_source == IdentitySource::Simulated) return out;
    AtaIdentity& id = p.identity;
    const std::string hint = " (not validated on hardware yet; --experimental enables it)";

    // Always: Opal key regeneration is not implemented. A self-encrypting drive then gets the
    // non-cryptographic methods it also supports.
    if (p.encrypted && id.transport == Transport::SATA) {
        p.encrypted = false;
        out.push_back("TCG Opal cryptographic erase is not implemented; the drive is planned as unencrypted");
    }
    // Windows cannot send NVMe or eMMC commands at all, flag or not.
    if (kWindows && (id.transport == Transport::NVMe || id.transport == Transport::eMMC)) {
        if (id.sanitize_supported || id.nvme_format_supported || id.emmc_secure_erase || p.encrypted)
            out.push_back("NVMe/eMMC firmware commands cannot be sent from Windows; host overwrite only");
        id.sanitize_supported = id.crypto_scramble_supported = id.block_erase_supported = id.overwrite_supported = false;
        id.nvme_format_supported = id.emmc_secure_erase = false;
        p.encrypted = false;
    }
    if (experimental) return out;

    // Enhanced Secure Erase on an HDD is proven (Linux); the non-enhanced variant, Secure Erase
    // on flash, and anything through the Windows transport are not.
    if (id.security_supported && (kWindows || !(p.media == MediaType::HDD && id.enhanced_erase_supported))) {
        id.security_supported = id.enhanced_erase_supported = false;
        out.push_back(std::string("ATA SECURITY ERASE disabled") +
                      (kWindows ? " (validated on Linux; not yet through the Windows transport)"
                       : p.media == MediaType::HDD ? " (only the enhanced variant is validated)"
                                                   : "") +
                      hint);
    }
    if (id.sanitize_supported) {
        id.sanitize_supported = id.crypto_scramble_supported = id.block_erase_supported = id.overwrite_supported = false;
        out.push_back(std::string(id.transport == Transport::NVMe ? "NVMe" : "ATA") + " SANITIZE disabled" + hint);
    }
    if (id.emmc_secure_erase) {
        id.emmc_secure_erase = false;
        out.push_back("eMMC secure erase (BLKSECDISCARD) disabled" + hint);
    }
    if (p.encrypted) {  // NVMe: Format with cryptographic erase
        p.encrypted = false;
        out.push_back("NVMe Format cryptographic erase disabled" + hint);
    }
    if (p.hidden_sectors() && opts.remove_hidden_areas) {
        opts.remove_hidden_areas = false;
        out.push_back("HPA/DCO removal disabled" + hint + "; the hidden sectors stay unsanitized and the plan is "
                      "capped at Clear");
    }
    return out;
}

}  // namespace dw
