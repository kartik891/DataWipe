#pragma once
// Real-hardware detection (read-only), for SATA HDDs/SSDs and NVMe SSDs.
//
// Layers, most to least detailed:
//   AtaIdentityProvider / NvmeIdentityProvider  need the device open (root, or the disk group)
//                                              and send only whitelisted query commands.
//   detect_from_sysfs                          never opens the device; works unprivileged.
//                                              Capabilities it cannot see are recorded in
//                                              AtaIdentity::probe_notes.
// detect_physical() picks the best layer available and says which one it used.

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string>

#include "core/result.hpp"
#include "device/ata_identity.hpp"
#include "device/device_factory.hpp"
#include "device/identity.hpp"

namespace dw {

// ---- Pure decoders (unit-tested with synthetic buffers) ----

struct TcgDiscovery {
    bool locking_feature = false;   // Locking feature descriptor (0x0002) present
    bool media_encryption = false;  // ... with MediaEncryption set: a real SED
    bool locking_enabled = false;
    bool locked = false;
    std::string ssc;  // Security Subsystem Class, e.g. "Opal 2"
};
// TCG Storage Level 0 Discovery response (48-byte header + feature descriptors, big-endian).
Result<TcgDiscovery> parse_tcg_level0(std::span<const std::uint8_t> data);

// DEVICE CONFIGURATION IDENTIFY data: words 3-6 = maximum LBA. Returns max LBA + 1 (sectors).
Result<std::uint64_t> decode_dco_identify(const IdentifyWords& words);

// SCSI VPD page 0xB1 (Block Device Characteristics): MEDIUM ROTATION RATE, same encoding as
// ATA IDENTIFY word 217. Readable without root at /sys/block/X/device/vpd_pgb1.
std::optional<std::uint16_t> parse_vpd_b1_rotation(std::span<const std::uint8_t> page);

struct NvmeDecoded {
    AtaIdentity id;
    std::uint32_t lba_bytes = 0;
    bool security_send_receive = false;  // OACS bit 0: TCG discovery is possible
    bool format_crypto_erase = false;    // FNA bit 2
};
// Identify Controller (CNS 1) + Identify Namespace (CNS 0), 4096 bytes each.
Result<NvmeDecoded> decode_nvme_identify(std::span<const std::uint8_t> controller,
                                         std::span<const std::uint8_t> ns);

// eMMC EXT_CSD register, 512 bytes (JEDEC JESD84-B51, section 7.4).
struct EmmcExtCsd {
    std::uint8_t rev = 0;           // [192] EXT_CSD_REV
    std::uint64_t sec_count = 0;    // [215:212] user-area size in 512-byte sectors
    bool sanitize = false;          // [231] SEC_FEATURE_SUPPORT bit 6 (eMMC 4.5+)
    bool secure_erase = false;      // [231] bit 0 SECURE_ER_EN
    std::uint64_t boot_bytes = 0;   // [226] BOOT_SIZE_MULT x 128 KiB, x 2 partitions
    std::uint64_t rpmb_bytes = 0;   // [168] RPMB_SIZE_MULT x 128 KiB
    std::uint64_t gp_bytes = 0;     // [154:143] GP_SIZE_MULT x [221] HC_WP_GRP_SIZE x [224] HC_ERASE_GRP_SIZE x 512 KiB
    double wear_ratio = -1;         // [268]/[269] DEVICE_LIFE_TIME_EST_TYP_A/B (eMMC 5.0+), -1 = not reported
    std::uint8_t pre_eol = 0;       // [267] PRE_EOL_INFO: 1 normal, 2 warning (80% of reserved blocks), 3 urgent
};
Result<EmmcExtCsd> decode_ext_csd(std::span<const std::uint8_t> ext_csd);

// ---- Detection ----

struct SysfsDetection {
    AtaIdentity id;
    DeviceGeometry geometry;
};
Result<SysfsDetection> detect_from_sysfs(const std::string& block_name);

struct PhysicalDetection {
    std::optional<OpenedTarget> target;  // present when the device could be opened read-only
    DeviceGeometry geometry;
    AtaIdentity identity;
    IdentitySource source = IdentitySource::Sysfs;
    std::string origin;  // which commands/files the identity came from
};

// Read-only detection of a physical block device the caller named explicitly.
Result<PhysicalDetection> detect_physical(const TargetAssessment& target);

}  // namespace dw
