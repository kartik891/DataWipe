#pragma once
// AtaIdentity: the fields of ATA IDENTIFY DEVICE (ACS-3) that sanitization decisions depend on.
//
// Every provider produces exactly this shape: the simulated JSON provider, the real ATA
// provider (IDENTIFY + native max + DCO + TCG), the NVMe provider mapping Identify Controller
// (SANICAP, OACS) onto the same fields, and the sysfs fallback. Downstream code never knows
// which one ran; it only sees IdentitySource.

#include <cstdint>
#include <string>
#include <vector>

#include "device/types.hpp"

namespace dw {

struct AtaIdentity {
    Transport transport = Transport::SATA;

    std::string model;     // words 27-46 (40 ASCII chars)
    std::string serial;    // words 10-19 (20 ASCII chars)
    std::string firmware;  // words 23-26 (8 ASCII chars)

    // Word 217, Nominal Media Rotation Rate: 0x0000 not reported, 0x0001 non-rotating (SSD),
    // 0x0401-0xFFFE nominal RPM. The primary HDD-vs-SSD signal.
    std::uint16_t rotation_rate = 0;
    // Word 169 bit 0: DATA SET MANAGEMENT / TRIM supported. Only flash advertises it, so it
    // classifies drives that predate word 217 and leave the rotation rate unreported.
    bool trim_supported = false;

    // Capacity, in logical sectors. Three nested limits exist on a real ATA drive:
    //   user_addressable <= native_max <= dco_max
    //   user_addressable : words 100-103; what the host can see. Reduced by an HPA.
    //   native_max       : READ NATIVE MAX ADDRESS EXT; the max before HPA. Reduced by a DCO.
    //   dco_max          : DEVICE CONFIGURATION IDENTIFY; the factory maximum.
    // Sectors between user_addressable and dco_max are invisible to a normal overwrite.
    std::uint64_t user_addressable_sectors = 0;
    std::uint64_t native_max_sectors = 0;
    std::uint64_t dco_max_sectors = 0;  // 0 = unknown / DCO not queried

    bool hpa_supported = false;  // word 82 bit 10
    bool hpa_enabled = false;    // word 85 bit 10 (and user_addressable < native_max)
    bool dco_supported = false;  // word 83 bit 11

    // Security feature set, word 128. Needed for SECURITY ERASE UNIT (normal/enhanced).
    bool security_supported = false;        // bit 0
    bool security_enabled = false;          // bit 1  (a user password is set)
    bool security_locked = false;           // bit 2
    bool security_frozen = false;           // bit 3  (erase impossible until power cycle)
    bool enhanced_erase_supported = false;  // bit 5
    // The drive's own estimate for SECURITY ERASE UNIT, words 89 (normal) and 90 (enhanced), in
    // minutes. 0 = not reported; kEraseTimeOver508 = "more than 508 minutes" (short format).
    std::uint32_t ata_erase_minutes = 0;
    std::uint32_t ata_enhanced_erase_minutes = 0;
    static constexpr std::uint32_t kEraseTimeOver508 = 0xFFFFFFFF;

    // SANITIZE feature set, word 59.
    bool sanitize_supported = false;         // bit 12
    bool crypto_scramble_supported = false;  // bit 13
    bool overwrite_supported = false;        // bit 14
    bool block_erase_supported = false;      // bit 15

    // Self-encrypting drive (TCG Opal/Enterprise). Not an IDENTIFY field: on real hardware it
    // comes from TCG Level 0 Discovery (IF-RECV). Decides whether crypto erase is a valid Purge.
    bool self_encrypting = false;
    std::string tcg_ssc;  // e.g. "Opal 2", "Pyrite 2", "Enterprise"; empty if not discovered

    // Flash wear as a fraction of rated endurance, capped at 1 (ARVS factor W). NVMe: SMART /
    // Health log "Percentage Used" / 100. SATA SSD: vendor wear attribute (e.g. 177, 233).
    // Negative = not known. Not an IDENTIFY field.
    double wear_ratio = -1;

    // NVMe addressing (NVMe identities only). Format NVM must target the confirmed namespace
    // with its CURRENT LBA format: LBAF 0 means "format index 0", not "keep", and a broadcast
    // NSID would erase namespaces the operator never confirmed.
    std::uint32_t nvme_nsid = 0;                   // NVME_IOCTL_ID of the target namespace
    std::uint8_t nvme_lbaf = 0;                    // its current LBA format index (FLBAS)
    bool nvme_format_supported = true;             // OACS bit 1
    bool nvme_format_all_namespaces = false;       // FNA bit 0: a Format hits every namespace

    // eMMC (eMMC identities only), from EXT_CSD (JEDEC JESD84-B51). The boot, RPMB and
    // general-purpose partitions are separate hardware partitions: a wipe of the user area
    // (mmcblkN) does not reach them.
    std::uint8_t emmc_ext_csd_rev = 0;  // [192]: 5 = eMMC 4.41, 6 = 4.5, 7 = 5.0, 8 = 5.1
    bool emmc_secure_erase = false;     // SEC_FEATURE_SUPPORT bit 0: secure erase / secure trim
    std::uint64_t emmc_boot_bytes = 0;  // both boot partitions together
    std::uint64_t emmc_rpmb_bytes = 0;
    std::uint64_t emmc_gp_bytes = 0;    // general-purpose partitions together

    // What detection could not determine, and why (e.g. "DCO IDENTIFY aborted by device").
    // Flags left false because of these are "unknown", not "unsupported"; the classifier turns
    // them into warnings so a conservative plan is never mistaken for a complete picture.
    std::vector<std::string> probe_notes;
};

}  // namespace dw
