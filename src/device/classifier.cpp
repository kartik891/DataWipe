#include "device/classifier.hpp"

#include <format>

namespace dw {

namespace {

MediaType classify_media(const AtaIdentity& id, std::vector<std::string>& warnings) {
    switch (id.transport) {
        case Transport::NVMe: return MediaType::SSD_NVMe;
        case Transport::eMMC: return MediaType::eMMC;
        case Transport::SATA: break;
    }
    if (id.rotation_rate == 0x0001) return MediaType::SSD_SATA;
    if (id.rotation_rate >= 0x0401 && id.rotation_rate <= 0xFFFE) return MediaType::HDD;
    // Word 217 only exists since ATA8-ACS (2008); older drives, and some bridges, leave it 0.
    // TRIM is the second signal: flash advertises it, magnetic disks do not.
    if (id.trim_supported) {
        warnings.push_back(std::format("rotation rate not reported (0x{:04x}); classified as an SSD because the "
                                       "drive supports TRIM",
                                       id.rotation_rate));
        return MediaType::SSD_SATA;
    }
    warnings.push_back(std::format("rotation rate not reported (0x{:04x}); classified as an HDD because the drive "
                                   "does not support TRIM (a pre-2009 SSD without TRIM would look the same)",
                                   id.rotation_rate));
    return MediaType::HDD;
}

}  // namespace

Result<DeviceProfile> classify(const OpenedTarget& target, const AtaIdentity& id, IdentitySource source,
                               std::string identity_origin) {
    return classify(target.assessment, target.device->geometry(), id, source, std::move(identity_origin));
}

Result<DeviceProfile> classify(const TargetAssessment& target, const DeviceGeometry& geometry, const AtaIdentity& id,
                               IdentitySource source, std::string identity_origin) {
    DeviceProfile p;
    p.path = target.canonical_path;
    p.backend = target.kind;
    p.backing_file = target.backing_file;
    p.geometry = geometry;
    p.identity = id;
    p.identity_source = source;
    p.identity_origin = std::move(identity_origin);

    // A simulated identity must never be attached to real hardware, and vice versa.
    if (source == IdentitySource::Simulated && p.backend == BackendKind::PhysicalBlock)
        return error("simulated identity cannot describe a physical device");
    if (source != IdentitySource::Simulated && p.backend != BackendKind::PhysicalBlock)
        return error("hardware identity source on a non-physical target");

    // --- Capacity invariants: user <= native <= dco_max ---
    if (id.user_addressable_sectors == 0) return error("identity reports zero user-addressable sectors");
    if (id.user_addressable_sectors > id.native_max_sectors)
        return error(std::format("identity inconsistent: user-addressable {} > native max {}",
                                 id.user_addressable_sectors, id.native_max_sectors));
    if (id.dco_max_sectors && id.native_max_sectors > id.dco_max_sectors)
        return error(std::format("identity inconsistent: native max {} > DCO max {}", id.native_max_sectors,
                                 id.dco_max_sectors));

    // --- Cross-check reported capacity against measured geometry ---
    const std::uint64_t measured = p.geometry.sector_count();
    if (p.geometry.size_bytes % p.geometry.logical_sector_size != 0)
        p.warnings.push_back("device size is not a whole number of logical sectors");

    if (source == IdentitySource::Simulated) {
        // The image IS the physical medium: every sector the identity claims must exist in it.
        if (p.medium_sectors() > measured)
            return error(std::format("identity claims {} sectors but the device only has {}", p.medium_sectors(),
                                     measured));
        if (p.medium_sectors() < measured)
            p.warnings.push_back(std::format("{} measured sectors lie beyond anything the identity reports",
                                             measured - p.medium_sectors()));
    } else if (source == IdentitySource::AtaIdentify) {
        // Real SATA drive: the kernel sees the user-addressable area (or native max when booted
        // with libata.ignore_hpa=1). Anything else means the identity doesn't match the disk.
        if (measured < id.user_addressable_sectors)
            p.warnings.push_back(std::format("the kernel reaches {} of the drive's {} sectors through this connection "
                                             "({} short; USB bridges commonly under-report): host writes cannot "
                                             "touch the rest",
                                             measured, id.user_addressable_sectors,
                                             id.user_addressable_sectors - measured));
        else if (measured != id.user_addressable_sectors && measured != id.native_max_sectors)
            p.warnings.push_back(std::format("kernel sees {} sectors; IDENTIFY reports user {} / native {}", measured,
                                             id.user_addressable_sectors, id.native_max_sectors));
    } else if (measured != id.user_addressable_sectors) {
        // NVMe namespace size (or the sysfs size itself) must match what the kernel exposes.
        p.warnings.push_back(std::format("kernel sees {} sectors; device reports {}", measured,
                                         id.user_addressable_sectors));
    }
    for (const auto& n : id.probe_notes) p.warnings.push_back("detection: " + n);

    // --- Classification ---
    p.media = classify_media(id, p.warnings);
    p.encrypted = id.self_encrypting;

    // --- Conditions that constrain later method selection ---
    if (id.hpa_enabled || id.native_max_sectors > id.user_addressable_sectors)
        p.warnings.push_back(std::format("HPA hides {} sectors (native max {} > user-addressable {})",
                                         id.native_max_sectors - id.user_addressable_sectors, id.native_max_sectors,
                                         id.user_addressable_sectors));
    if (id.dco_max_sectors > id.native_max_sectors)
        p.warnings.push_back(std::format("DCO hides {} sectors (DCO max {} > native max {})",
                                         id.dco_max_sectors - id.native_max_sectors, id.dco_max_sectors,
                                         id.native_max_sectors));
    if (id.security_frozen)
        p.warnings.push_back("security is FROZEN: SECURITY ERASE UNIT will be rejected until a power cycle");
    if (id.security_locked) p.warnings.push_back("security is LOCKED: device requires the user password");
    if (capabilities_queried(source) && p.media != MediaType::HDD && p.media != MediaType::Unknown &&
        !id.sanitize_supported && !id.security_supported && !id.emmc_secure_erase && !p.encrypted)
        p.warnings.push_back(id.transport == Transport::eMMC ? "eMMC supports neither SANITIZE nor secure erase; no Purge method available"
                             : id.transport == Transport::NVMe
                                 ? "NVMe controller supports no Sanitize action; no Purge method available"
                                 : "flash device supports neither SANITIZE nor SECURITY ERASE; no Purge method available");

    return p;
}

Json to_json(const DeviceProfile& p) {
    const AtaIdentity& id = p.identity;
    Json j = Json::object();
    j["path"] = p.path;
    j["backend"] = to_string(p.backend);
    if (!p.backing_file.empty()) j["backing_file"] = p.backing_file;

    Json& g = j["geometry"];
    g["size_bytes"] = p.geometry.size_bytes;
    g["logical_sector_size"] = p.geometry.logical_sector_size;
    g["physical_sector_size"] = p.geometry.physical_sector_size;
    g["sector_count"] = p.geometry.sector_count();

    Json& i = j["identity"];
    i["source"] = to_string(p.identity_source);
    i["origin"] = p.identity_origin;
    i["transport"] = to_string(id.transport);
    i["model"] = id.model;
    i["serial"] = id.serial;
    i["firmware"] = id.firmware;
    i["rotation_rate"] = id.rotation_rate;
    i["user_addressable_sectors"] = id.user_addressable_sectors;
    i["native_max_sectors"] = id.native_max_sectors;
    i["dco_max_sectors"] = id.dco_max_sectors;
    i["hpa_supported"] = id.hpa_supported;
    i["hpa_enabled"] = id.hpa_enabled;
    i["dco_supported"] = id.dco_supported;
    Json& sec = i["security"];
    sec["supported"] = id.security_supported;
    sec["enabled"] = id.security_enabled;
    sec["locked"] = id.security_locked;
    sec["frozen"] = id.security_frozen;
    sec["enhanced_erase"] = id.enhanced_erase_supported;
    Json& san = i["sanitize"];
    san["supported"] = id.sanitize_supported;
    san["crypto_scramble"] = id.crypto_scramble_supported;
    san["overwrite"] = id.overwrite_supported;
    san["block_erase"] = id.block_erase_supported;
    i["self_encrypting"] = id.self_encrypting;
    i["tcg_ssc"] = id.tcg_ssc;
    if (id.wear_ratio >= 0) i["wear_ratio"] = id.wear_ratio;

    Json& c = j["classification"];
    c["media"] = to_string(p.media);
    c["encrypted"] = p.encrypted;
    c["hidden_sectors"] = p.hidden_sectors();
    c["capabilities_queried"] = capabilities_queried(p.identity_source);

    Json w = Json::array();
    for (const auto& s : p.warnings) w.push_back(s);
    j["warnings"] = std::move(w);
    return j;
}

}  // namespace dw
