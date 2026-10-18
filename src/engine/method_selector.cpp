#include "engine/method_selector.hpp"

#include <format>

namespace dw {

namespace {

constexpr const char* kNist = "NIST SP 800-88 Rev. 1, Guidelines for Media Sanitization";
constexpr const char* kIeee2883 = "IEEE 2883-2022, Standard for Sanitizing Storage";
constexpr const char* kAcs = "INCITS ACS-3 (ATA Command Set): Security, Sanitize, HPA, DCO feature sets";
constexpr const char* kNvme = "NVM Express Base Specification 2.0: Sanitize, Format NVM";
constexpr const char* kEmmc = "JEDEC JESD84-B51 (eMMC 5.1): Sanitize";
constexpr const char* kOpal = "TCG Storage Security Subsystem Class: Opal 2.0";

// Plan under construction plus the pieces the helpers share.
struct Builder {
    const DeviceProfile& p;
    const SelectorOptions& opts;
    WipePlan plan;
    std::vector<std::string> keys;  // joined into method_id
    std::uint64_t host_first = 0;
    std::uint64_t host_count = 0;  // host-visible range after (or without) hidden-area removal
    bool hidden_left_behind = false;

    void add(std::string key, WipeStep step) {
        keys.push_back(std::move(key));
        plan.steps.push_back(std::move(step));
    }

    OverwriteSpec host_range(PatternSpec pattern) const { return OverwriteSpec{host_first, host_count, pattern}; }
};

PatternSpec prng(std::uint32_t stream) { return PatternSpec{PatternSpec::Kind::Prng, stream, 0}; }
PatternSpec fixed(std::uint32_t v) { return PatternSpec{PatternSpec::Kind::Fixed32, 0, v}; }

// ---- Shared steps ----

WipeStep host_overwrite_step(const Builder& b, SanitizationLevel level, std::string rationale) {
    WipeStep s;
    s.title = "Host overwrite, single pass, pseudo-random";
    s.execution = Execution::Real;
    s.level = level;
    s.overwrite = b.host_range(prng(1));
    s.rationale = std::move(rationale);
    return s;
}

WipeStep ata_security_erase_step(bool enhanced, Execution exec, const Builder& b) {
    WipeStep s;
    s.title = enhanced ? "ATA SECURITY ERASE UNIT (Enhanced)" : "ATA SECURITY ERASE UNIT (Normal)";
    s.execution = exec;
    s.level = SanitizationLevel::Purge;
    // The erase requires security to be enabled with a known password; the erase itself then
    // returns the drive to security-disabled (SEC1), so the temporary password does not persist.
    s.commands = {ata::security_set_password(ata::kTempPassword), ata::security_erase_prepare(),
                  ata::security_erase_unit(ata::kTempPassword, enhanced)};
    if (exec == Execution::Emulated) {
        // Normal erase writes zeros; enhanced writes a vendor-defined pattern (emulated with an
        // independent PRNG stream, so a sampled read-back can tell it apart from pass 1).
        s.overwrite = b.host_range(enhanced ? prng(2) : fixed(0));
    }
    s.rationale = enhanced ? "Firmware-level erase also reaches reallocated/spare sectors the host cannot address."
                           : "Firmware-level erase of all user data areas (zeros).";
    return s;
}

WipeStep ata_sanitize_step(DeviceCommand op, SanitizationLevel level, Execution exec, std::string rationale) {
    WipeStep s;
    s.title = op.name;
    s.execution = exec;
    s.level = level;
    s.commands = {std::move(op), ata::sanitize_status()};
    s.rationale = std::move(rationale);
    return s;
}

WipeStep nvme_step(DeviceCommand op, bool poll, SanitizationLevel level, std::string rationale) {
    WipeStep s;
    s.title = op.name;
    s.execution = Execution::Simulated;
    s.level = level;
    s.commands = {std::move(op)};
    if (poll) s.commands.push_back(nvme::sanitize_status_log());
    s.rationale = std::move(rationale);
    return s;
}

// HPA/DCO: make the whole medium host-visible before anything else runs.
Result<void> handle_hidden_areas(Builder& b) {
    const DeviceProfile& p = b.p;
    const AtaIdentity& id = p.identity;
    b.host_first = 0;
    // Host writes stop where the kernel's view of the drive ends (see unreachable_sectors()).
    b.host_count = id.user_addressable_sectors - p.unreachable_sectors();
    if (p.hidden_sectors() == 0) return ok();

    if (id.transport != Transport::SATA)
        return error(std::format("{} hidden sectors reported on a {} device; HPA/DCO are ATA-only, profile is inconsistent",
                                 p.hidden_sectors(), to_string(id.transport)));

    if (!b.opts.remove_hidden_areas) {
        b.hidden_left_behind = true;
        b.plan.warnings.push_back(std::format(
            "{} sectors hidden by HPA/DCO will NOT be sanitized (hidden-area removal disabled); plan capped at Clear",
            p.hidden_sectors()));
        return ok();
    }

    WipeStep s;
    s.title = "Remove HPA/DCO (expose full native capacity)";
    s.level = SanitizationLevel::None;
    const bool has_hpa = id.native_max_sectors > id.user_addressable_sectors;
    const bool has_dco = id.dco_max_sectors > id.native_max_sectors;
    if (has_hpa) {
        s.commands.push_back(ata::read_native_max_address_ext());
        // Non-volatile when a DCO restore follows (DCO RESTORE aborts while an HPA is set), and
        // always on a real drive: the kernel may only see the new size after a reboot, which a
        // volatile SET MAX would undo.
        s.commands.push_back(
            ata::set_max_address_ext(id.native_max_sectors - 1, has_dco || is_hardware_identity(p.identity_source)));
    }
    if (has_dco) s.commands.push_back(ata::dco_restore());
    s.rationale = std::format("Original geometry: user-addressable {}, native max {}, DCO max {}. Recorded so the "
                              "configuration can be re-applied after sanitization if required.",
                              id.user_addressable_sectors, id.native_max_sectors, id.dco_max_sectors);
    b.add("unhide", std::move(s));
    b.host_count = p.medium_sectors();
    b.plan.warnings.push_back(std::format("{} hidden sectors will be exposed and sanitized; the HPA/DCO change is "
                                          "persistent on real hardware",
                                          p.hidden_sectors()));
    return ok();
}

// ---- Per-media ladders ----

// Flash without a usable firmware sanitize: two full host passes. Wei et al. (FAST'11, Table 2,
// sequential initialisation) found that after ONE pass 7 of 8 SSDs still held old data, and
// after TWO passes 1 of 8 did ("usually, but not always, sufficient"). Still Clear only.
void add_flash_overwrite(Builder& b, const std::string& rationale) {
    WipeStep first = host_overwrite_step(b, SanitizationLevel::Clear, rationale);
    first.title = "Host overwrite, pass 1 of 2, pseudo-random";
    WipeStep second = host_overwrite_step(b, SanitizationLevel::Clear,
                                          "Second full pass: on flash one pass leaves stale copies on most drives "
                                          "(Wei et al., FAST'11, Table 2).");
    second.title = "Host overwrite, pass 2 of 2, pseudo-random";
    second.overwrite->pattern = prng(2);
    b.add("overwrite-2pass", std::move(first));
    b.plan.steps.push_back(std::move(second));
}

void plan_hdd(Builder& b) {
    const AtaIdentity& id = b.p.identity;
    b.plan.method_name = "HDD: pseudo-random overwrite (Clear) + firmware erase (Purge)";
    b.plan.standards = {kNist, kAcs};

    b.add("overwrite", host_overwrite_step(b, SanitizationLevel::Clear,
                                           "NIST Clear for magnetic media: one pass over every addressable sector. "
                                           "Independent of firmware, and verifiable by read-back."));

    const bool se_usable = id.security_supported && !id.security_frozen;
    if (se_usable && id.enhanced_erase_supported) {
        b.add("ata-se-enhanced", ata_security_erase_step(true, Execution::Emulated, b));
    } else if (id.sanitize_supported && id.overwrite_supported) {
        auto s = ata_sanitize_step(ata::sanitize_overwrite(0), SanitizationLevel::Purge, Execution::Emulated,
                                   "Device-internal overwrite of all user data, including reallocated sectors.");
        s.overwrite = b.host_range(fixed(0));
        b.add("ata-sanitize-overwrite", std::move(s));
    } else if (se_usable) {
        b.add("ata-se-normal", ata_security_erase_step(false, Execution::Emulated, b));
    } else {
        b.plan.method_name = "HDD: pseudo-random overwrite (Clear only)";
        b.plan.warnings.push_back(
            id.security_frozen
                ? "security is FROZEN (BIOS froze it at boot): SECURITY ERASE unavailable; suspend/resume or "
                  "hot-plug the drive to unfreeze, then re-plan. Plan achieves Clear only"
                : "no usable firmware erase command: plan achieves Clear only");
    }
}

void plan_sata_ssd(Builder& b) {
    const AtaIdentity& id = b.p.identity;
    b.plan.standards = {kNist, kIeee2883, kAcs};
    const bool se_usable = id.security_supported && !id.security_frozen;

    if (b.p.encrypted) {
        b.plan.method_name = "SATA SED: cryptographic erase (Purge)";
        b.plan.standards.push_back(kOpal);
        if (id.sanitize_supported && id.crypto_scramble_supported) {
            b.add("crypto-scramble",
                  ata_sanitize_step(ata::sanitize_crypto_scramble(), SanitizationLevel::Purge, Execution::Simulated,
                                    "Replaces the media encryption key; all stored ciphertext becomes unrecoverable."));
        } else {
            WipeStep s;
            s.title = "TCG Opal cryptographic erase";
            s.execution = Execution::Simulated;
            s.level = SanitizationLevel::Purge;
            s.commands = {tcg::opal_genkey_all_ranges()};
            s.rationale = "No SANITIZE CRYPTO SCRAMBLE: fall back to regenerating keys through the Opal Locking SP.";
            b.add("opal-genkey", std::move(s));
        }
        if (b.opts.defense_in_depth) {
            if (id.sanitize_supported && id.block_erase_supported) {
                b.add("block-erase", ata_sanitize_step(ata::sanitize_block_erase(), SanitizationLevel::Purge,
                                                       Execution::Simulated,
                                                       "Defense in depth: SED key management has had real-world "
                                                       "flaws; also erase every NAND block."));
            } else if (se_usable && id.enhanced_erase_supported) {
                b.add("ata-se-enhanced", ata_security_erase_step(true, Execution::Simulated, b));
            }
        }
        return;
    }

    b.plan.method_name = "SATA SSD: firmware sanitize (Purge)";
    if (id.sanitize_supported && id.block_erase_supported) {
        b.add("block-erase", ata_sanitize_step(ata::sanitize_block_erase(), SanitizationLevel::Purge,
                                               Execution::Simulated,
                                               "Erases every NAND block, including over-provisioned and retired "
                                               "blocks the host cannot address."));
    } else if (id.sanitize_supported && id.overwrite_supported) {
        b.add("sanitize-overwrite",
              ata_sanitize_step(ata::sanitize_overwrite(0), SanitizationLevel::Purge, Execution::Simulated,
                                "Device-internal overwrite of all physical user data."));
        b.plan.warnings.push_back("SANITIZE OVERWRITE on flash is slow and adds wear; block erase is preferred");
    } else if (se_usable) {
        b.add(id.enhanced_erase_supported ? "ata-se-enhanced" : "ata-se-normal",
              ata_security_erase_step(id.enhanced_erase_supported, Execution::Simulated, b));
        b.plan.warnings.push_back("ATA SECURITY ERASE on SSDs is implementation-dependent; NIST accepts it as Purge "
                                  "only where the vendor documents that it erases all NAND");
    } else {
        b.plan.method_name = "SATA SSD: host overwrite (Clear only)";
        add_flash_overwrite(b, "No firmware sanitize known to be available. Overwriting LBAs on flash reaches only "
                               "mapped blocks, so this is Clear, never Purge.");
        if (capabilities_queried(b.p.identity_source))
            b.plan.warnings.push_back(id.security_frozen ? "security FROZEN and no SANITIZE: only Clear is possible"
                                                         : "no firmware sanitize support: only Clear is possible");
    }
}

// Simulated identities have no namespace id; namespace 1 is what a single-namespace drive uses.
std::uint32_t nvme_nsid(const Builder& b) { return b.p.identity.nvme_nsid ? b.p.identity.nvme_nsid : 1; }

void plan_nvme(Builder& b) {
    const AtaIdentity& id = b.p.identity;  // SANICAP mapped: crypto_scramble=CES, block_erase=BES, overwrite=OWS
    b.plan.standards = {kNist, kIeee2883, kNvme};

    if (b.p.encrypted) {
        b.plan.method_name = "NVMe SED: cryptographic erase (Purge)";
        if (id.sanitize_supported && id.crypto_scramble_supported) {
            b.add("sanitize-crypto", nvme_step(nvme::sanitize(nvme::SanitizeAction::CryptoErase), true,
                                               SanitizationLevel::Purge,
                                               "Controller discards the media encryption key for all namespaces."));
        } else {
            b.add("format-crypto", nvme_step(nvme::format_nvm(2, nvme_nsid(b), id.nvme_lbaf), false,
                                             SanitizationLevel::Purge,
                                             "Format NVM with SES=2: cryptographic erase of the namespace."));
        }
        if (b.opts.defense_in_depth && id.sanitize_supported && id.block_erase_supported)
            b.add("sanitize-block", nvme_step(nvme::sanitize(nvme::SanitizeAction::BlockErase), true,
                                              SanitizationLevel::Purge, "Defense in depth: also erase every block."));
        return;
    }

    b.plan.method_name = "NVMe SSD: sanitize (Purge)";
    if (id.sanitize_supported && id.block_erase_supported) {
        b.add("sanitize-block", nvme_step(nvme::sanitize(nvme::SanitizeAction::BlockErase), true,
                                          SanitizationLevel::Purge,
                                          "Erases all NAND including over-provisioning; persists across resets "
                                          "until complete."));
    } else if (id.sanitize_supported && id.overwrite_supported) {
        b.add("sanitize-overwrite", nvme_step(nvme::sanitize(nvme::SanitizeAction::Overwrite, 0), true,
                                              SanitizationLevel::Purge, "Controller-internal overwrite."));
    } else if (!id.nvme_format_supported) {
        b.plan.method_name = "NVMe SSD: host overwrite (Clear only)";
        add_flash_overwrite(b, capabilities_queried(b.p.identity_source)
                                   ? "Controller supports neither Sanitize nor Format NVM: host overwrite of every LBA, "
                                     "twice. Clear only."
                                   : "No NVMe command can be sent from here: host overwrite of every LBA, twice. "
                                     "Clear only.");
        if (capabilities_queried(b.p.identity_source))
            b.plan.warnings.push_back("controller supports neither Sanitize nor Format NVM: only Clear is possible");
    } else {
        b.plan.method_name = "NVMe SSD: format user-data erase (Clear only)";
        b.add("format-erase", nvme_step(nvme::format_nvm(1, nvme_nsid(b), id.nvme_lbaf), false, SanitizationLevel::Clear,
                                        "No Sanitize action known to be supported. Format SES=1 erases user data but gives no guarantee "
                                        "for unmapped/over-provisioned blocks: Clear."));
        if (capabilities_queried(b.p.identity_source))
            b.plan.warnings.push_back("controller supports no Sanitize action: only Clear is possible");
    }
}

void plan_emmc(Builder& b) {
    const AtaIdentity& id = b.p.identity;
    b.plan.standards = {kNist, kEmmc};
    if (id.sanitize_supported) {
        b.plan.method_name = "eMMC: discard + sanitize (Purge)";
        WipeStep s;
        s.title = "eMMC discard all + SANITIZE";
        s.execution = Execution::Simulated;
        s.level = SanitizationLevel::Purge;
        s.commands = {blk::discard(0, b.p.geometry.size_bytes), emmc::sanitize()};
        s.rationale = "Discard unmaps every block; SANITIZE then physically erases all unmapped blocks.";
        b.add("discard+sanitize", std::move(s));
    } else if (id.emmc_secure_erase) {
        // Paper III-B: BLKSECDISCARD through the kernel ioctl interface. On eMMC the kernel
        // turns it into Secure Erase (CMD38 with the secure argument), which JEDEC defines as a
        // physical erase of the addressed blocks and of any copies the controller made.
        b.plan.method_name = "eMMC: secure erase via BLKSECDISCARD (Purge)";
        WipeStep s;
        s.title = "eMMC secure erase (BLKSECDISCARD)";
        s.execution = Execution::Simulated;
        s.level = SanitizationLevel::Purge;
        s.commands = {blk::secure_discard(0, b.p.geometry.size_bytes)};
        s.rationale = "Secure Erase physically erases every user-area block and its relocated copies. Obsolete from "
                      "eMMC 4.51 in favour of SANITIZE, which this device does not report.";
        b.add("secure-erase", std::move(s));
    } else {
        b.plan.method_name = "eMMC: host overwrite (Clear only)";
        add_flash_overwrite(b, "No eMMC SANITIZE or secure erase known to be supported: host overwrite reaches mapped "
                               "blocks only.");
        if (capabilities_queried(b.p.identity_source))
            b.plan.warnings.push_back("eMMC without SANITIZE or secure erase: only Clear is possible");
    }
    const std::uint64_t outside = id.emmc_boot_bytes + id.emmc_rpmb_bytes + id.emmc_gp_bytes;
    if (outside)
        b.plan.warnings.push_back(std::format(
            "eMMC hardware partitions outside the user area are NOT covered by this plan: boot {} KiB, RPMB {} KiB, "
            "general-purpose {} KiB (boot areas normally hold firmware, not user data)",
            id.emmc_boot_bytes / 1024, id.emmc_rpmb_bytes / 1024, id.emmc_gp_bytes / 1024));
}

}  // namespace

Result<WipePlan> select_method(const DeviceProfile& p, const SelectorOptions& opts) {
    const AtaIdentity& id = p.identity;
    if (id.security_locked)
        return error("device security is LOCKED: it rejects media access until unlocked with its password");
    if (p.media == MediaType::Unknown)
        return error("media type is unknown; refusing to guess a sanitization method (fix the identity data)");

    Builder b{p, opts, {}, {}, 0, 0, false};
    if (auto r = handle_hidden_areas(b); !r) return r.error();

    std::string prefix;
    switch (p.media) {
        case MediaType::HDD: prefix = "hdd"; plan_hdd(b); break;
        case MediaType::SSD_SATA: prefix = "ssd-sata"; plan_sata_ssd(b); break;
        case MediaType::SSD_NVMe: prefix = "ssd-nvme"; plan_nvme(b); break;
        case MediaType::eMMC: prefix = "emmc"; plan_emmc(b); break;
        case MediaType::Unknown: break;
    }

    WipePlan& plan = b.plan;
    plan.method_id = prefix;
    for (size_t i = 0; i < b.keys.size(); ++i) plan.method_id += (i ? "+" : ".") + b.keys[i];

    const bool hardware = is_hardware_identity(p.identity_source);
    if (hardware) {
        // A real drive performs its firmware commands itself: every command step is REAL, and
        // no host pass "reproduces" a firmware erase (that would re-dirty the disk and misstate
        // what happened).
        for (auto& s : plan.steps) {
            if (s.commands.empty()) continue;
            s.execution = Execution::Real;
            s.overwrite.reset();
        }
    } else if (!plan.steps.empty() && plan.steps.front().level == SanitizationLevel::None &&
               !plan.steps.front().commands.empty()) {
        // Simulated drive: the hidden-area step is only as real as the steps acting on the exposed area.
        plan.steps.front().execution = plan.has_host_io() ? Execution::Emulated : Execution::Simulated;
    }

    plan.level = SanitizationLevel::None;
    for (const auto& s : plan.steps)
        if (s.level > plan.level) plan.level = s.level;
    if (b.hidden_left_behind && plan.level > SanitizationLevel::Clear) plan.level = SanitizationLevel::Clear;

    // Verification follows whatever touches the medium last.
    const WipeStep* last = nullptr;
    for (const auto& s : plan.steps)
        if (s.overwrite || (!s.commands.empty() && s.level != SanitizationLevel::None)) last = &s;
    if (last && last->overwrite) {
        plan.verification.kind = VerificationExpectation::Kind::Pattern;
        plan.verification.expected = last->overwrite;
        plan.verification.reason = "read back sampled sectors and compare with the last pattern written (" +
                                   last->overwrite->pattern.describe() + ")";
    } else if (last && hardware) {
        plan.verification.kind = VerificationExpectation::Kind::Fingerprint;
        plan.verification.expected = b.host_range(PatternSpec{});
        plan.verification.reason = "device-internal erase leaves vendor-defined content: sampled sectors are hashed "
                                   "before the plan and must all differ afterwards";
    } else {
        plan.verification.reason =
            plan.fully_simulated()
                ? "all steps are SIMULATED: the medium is not modified, so read-back verification does not apply"
                : "device-internal erase leaves vendor-defined content; no host-known pattern to compare";
    }
    if (const std::uint64_t un = p.unreachable_sectors()) {
        const bool firmware_last = last && !last->overwrite;
        plan.warnings.push_back(std::format(
            "{} sector(s) at the end of the drive cannot be reached through this connection (the USB bridge reports "
            "a smaller capacity): {}",
            un,
            firmware_last ? "the host pass skips them; the firmware erase still covers the whole drive"
                          : "they are NOT overwritten. Connect the drive directly to a SATA port to sanitize them"));
    }
    if (plan.fully_simulated())
        plan.warnings.push_back("SIMULATED plan: device commands are built and logged but NOT sent; data on the "
                                "target is left intact");
    if (p.identity_source == IdentitySource::Sysfs)
        plan.warnings.push_back("identity came from sysfs only: security/SANITIZE/encryption support was not read, "
                                "so the ladder fell to its most conservative rung; run with sudo for a full plan");
    if (p.identity_source == IdentitySource::WindowsStorage)
        plan.warnings.push_back("identity came from the Windows storage descriptor: firmware erase support, hidden "
                                "areas (HPA/DCO) and encryption were not read and the Windows build sends no drive "
                                "commands, so this is a host overwrite (Clear). Sectors hidden by an HPA or DCO are "
                                "not reached; for Purge, boot the DataWipe live image");
    if (p.backend == BackendKind::PhysicalBlock)
        plan.warnings.push_back(std::format("REAL DEVICE: running this plan destroys all data on {} (serial {})",
                                            p.path, p.identity.serial));
    return plan;
}

}  // namespace dw
