#include "device/hw_identity.hpp"

#ifdef __linux__
#include <linux/hdreg.h>
#include <sys/ioctl.h>
#endif

#include <cerrno>
#include <cstring>
#include <filesystem>
#include <format>
#include <fstream>
#include <vector>

#include "core/log.hpp"
#include "device/identity_provider.hpp"
#include "device/passthrough.hpp"
#include "device/sysfs.hpp"

namespace dw {

namespace {

std::uint16_t be16(const std::uint8_t* p) { return static_cast<std::uint16_t>(p[0] << 8 | p[1]); }
std::uint32_t be32(const std::uint8_t* p) {
    return static_cast<std::uint32_t>(p[0]) << 24 | static_cast<std::uint32_t>(p[1]) << 16 |
           static_cast<std::uint32_t>(p[2]) << 8 | p[3];
}
std::uint16_t le16(const std::uint8_t* p) { return static_cast<std::uint16_t>(p[0] | p[1] << 8); }
std::uint32_t le32(const std::uint8_t* p) {
    return static_cast<std::uint32_t>(p[0]) | static_cast<std::uint32_t>(p[1]) << 8 |
           static_cast<std::uint32_t>(p[2]) << 16 | static_cast<std::uint32_t>(p[3]) << 24;
}
std::uint64_t le64(const std::uint8_t* p) { return le32(p) | static_cast<std::uint64_t>(le32(p + 4)) << 32; }

std::string ascii_field(const std::uint8_t* p, size_t n) {
    std::string s(reinterpret_cast<const char*>(p), n);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\0')) s.pop_back();
    size_t b = 0;
    while (b < s.size() && s[b] == ' ') ++b;
    return s.substr(b);
}

std::string ssc_name(std::uint16_t code) {
    switch (code) {
        case 0x0100: return "Enterprise";
        case 0x0200: return "Opal 1";
        case 0x0203: return "Opal 2";
        case 0x0301: return "Opalite";
        case 0x0302: return "Pyrite 1";
        case 0x0303: return "Pyrite 2";
        case 0x0304: return "Ruby";
    }
    return "";
}

// Level 0 Discovery through whatever transport the device speaks, recorded into `id`.
void apply_tcg(AtaIdentity& id, Result<TcgDiscovery> tcg) {
    if (!tcg) {
        id.probe_notes.push_back("TCG Level 0 Discovery unavailable (" + tcg.error().message +
                                 "): self-encryption status unknown");
        return;
    }
    id.tcg_ssc = tcg->ssc;
    id.self_encrypting = tcg->locking_feature && tcg->media_encryption;
    if (tcg->locking_feature && !tcg->media_encryption)
        id.probe_notes.push_back("TCG " + (tcg->ssc.empty() ? std::string("Locking") : tcg->ssc) +
                                 " present without media encryption (e.g. Pyrite): crypto erase is not available");
    if (tcg->locked) id.probe_notes.push_back("TCG locking range is LOCKED");
}

}  // namespace

// ============================================================================ decoders

Result<TcgDiscovery> parse_tcg_level0(std::span<const std::uint8_t> d) {
    if (d.size() < 48) return error("Level 0 response shorter than its 48-byte header");
    const std::uint32_t len = be32(d.data());
    if (len == 0) return error("empty Level 0 response (no TCG support)");
    const size_t end = std::min<size_t>(d.size(), 4u + len);
    TcgDiscovery t;
    for (size_t off = 48; off + 4 <= end;) {
        const std::uint16_t code = be16(&d[off]);
        const std::uint8_t flen = d[off + 3];
        if (off + 4 + flen > end) return error(std::format("truncated feature descriptor 0x{:04x}", code));
        if (code == 0x0002 && flen >= 1) {
            const std::uint8_t f = d[off + 4];
            t.locking_feature = true;
            t.locking_enabled = f & 0x02;
            t.locked = f & 0x04;
            t.media_encryption = f & 0x08;
        } else if (auto name = ssc_name(code); !name.empty() && t.ssc.empty()) {
            t.ssc = name;
        }
        off += 4u + flen;
    }
    return t;
}

Result<std::uint64_t> decode_dco_identify(const IdentifyWords& w) {
    if ((w[255] & 0xFF) == 0xA5) {
        std::uint8_t sum = 0;
        for (auto word : w) sum = static_cast<std::uint8_t>(sum + (word & 0xFF) + (word >> 8));
        if (sum != 0) return error("DCO IDENTIFY checksum mismatch");
    }
    if (w[0] != 0x0001 && w[0] != 0x0002) return error(std::format("unexpected DCO revision 0x{:04x}", w[0]));
    const std::uint64_t max_lba = static_cast<std::uint64_t>(w[3]) | static_cast<std::uint64_t>(w[4]) << 16 |
                                  static_cast<std::uint64_t>(w[5]) << 32 | static_cast<std::uint64_t>(w[6]) << 48;
    if (max_lba == 0) return error("DCO IDENTIFY reports maximum LBA 0");
    return max_lba + 1;
}

std::optional<std::uint16_t> parse_vpd_b1_rotation(std::span<const std::uint8_t> p) {
    if (p.size() < 6 || p[1] != 0xB1) return std::nullopt;
    return be16(&p[4]);
}

Result<EmmcExtCsd> decode_ext_csd(std::span<const std::uint8_t> x) {
    if (x.size() != 512) return error("EXT_CSD must be 512 bytes");
    EmmcExtCsd e;
    e.rev = x[192];
    if (e.rev > 9) return error(std::format("implausible EXT_CSD_REV {}", e.rev));
    e.sec_count = le32(&x[212]);
    if (e.sec_count == 0) return error("EXT_CSD reports a user area of 0 sectors");
    const std::uint8_t sec = x[231];
    e.secure_erase = sec & 0x01;
    e.sanitize = e.rev >= 6 && (sec & 0x40);  // SANITIZE exists from eMMC 4.5 (rev 6)
    constexpr std::uint64_t k128K = 128 * 1024;
    e.boot_bytes = 2 * x[226] * k128K;
    e.rpmb_bytes = x[168] * k128K;
    const std::uint64_t gp_unit = std::uint64_t(x[221]) * x[224] * 512 * 1024;
    for (int i = 0; i < 4; ++i) {
        const std::uint64_t mult = x[143 + 3 * i] | x[144 + 3 * i] << 8 | x[145 + 3 * i] << 16;
        e.gp_bytes += mult * gp_unit;
    }
    if (e.rev >= 7) {  // life-time estimation, eMMC 5.0+: 0x01 = 0-10% used ... 0x0A = 90-100%, 0x0B = exceeded
        const std::uint8_t worst = std::max(x[268], x[269]);
        if (worst >= 1 && worst <= 0x0B) e.wear_ratio = std::min(1.0, worst / 10.0);
        e.pre_eol = x[267];
    }
    return e;
}

Result<NvmeDecoded> decode_nvme_identify(std::span<const std::uint8_t> c, std::span<const std::uint8_t> ns) {
    if (c.size() < 4096 || ns.size() < 4096) return error("NVMe Identify data must be 4096 bytes");
    NvmeDecoded r;
    AtaIdentity& id = r.id;
    id.transport = Transport::NVMe;
    id.serial = ascii_field(&c[4], 20);
    id.model = ascii_field(&c[24], 40);
    id.firmware = ascii_field(&c[64], 8);
    if (id.model.empty()) return error("Identify Controller returned an empty model number");
    id.rotation_rate = 1;  // NVMe is solid state by definition

    const std::uint16_t oacs = le16(&c[256]);
    const std::uint32_t sanicap = le32(&c[328]);
    const std::uint8_t fna = c[524];
    r.security_send_receive = oacs & 0x0001;
    r.format_crypto_erase = fna & 0x04;
    id.nvme_format_supported = oacs & 0x0002;
    id.nvme_format_all_namespaces = fna & 0x01;
    id.crypto_scramble_supported = sanicap & 0x1;  // CES
    id.block_erase_supported = sanicap & 0x2;      // BES
    id.overwrite_supported = sanicap & 0x4;        // OWS
    id.sanitize_supported = sanicap & 0x7;

    const std::uint64_t nsze = le64(&ns[0]);
    const std::uint8_t flbas = ns[26];
    const unsigned fmt = (flbas & 0x0F) | ((flbas >> 5) & 0x03) << 4;
    const std::uint8_t lbads = ns[128 + 4 * fmt + 2];
    if (lbads < 9 || lbads > 16) return error(std::format("implausible LBA data size 2^{}", lbads));
    r.lba_bytes = 1u << lbads;
    id.nvme_lbaf = static_cast<std::uint8_t>(fmt);
    if (nsze == 0) return error("namespace size is 0");
    id.user_addressable_sectors = id.native_max_sectors = nsze;  // no HPA/DCO on NVMe
    return r;
}

// ============================================================================ providers

Result<AtaIdentity> AtaIdentityProvider::identify(IBlockDevice& device) {
    if (device.kind() != BackendKind::PhysicalBlock)
        return error("ATA IDENTIFY is only issued to physical devices; use a simulated profile for " +
                     std::string(to_string(device.kind())) + " targets");
    ReadOnlyPassthrough pt(device);

    // 1. IDENTIFY DEVICE. HDIO_GET_IDENTITY (libata) first; SG_IO for SAT bridges (USB/SAS).
    IdentifyWords words{};
    Result<AtaIdentity> decoded = error("no IDENTIFY data");
#ifdef __linux__
    const bool hdio_ok = ::ioctl(device.native_handle(), HDIO_GET_IDENTITY, words.data()) == 0;
#else
    const bool hdio_ok = false;
    errno = ENOTSUP;
#endif
    if (hdio_ok) {
        decoded = decode_ata_identify(words, AtaStringOrder::AlreadyFixed);
    } else {
        const int hdio_errno = errno;
        AtaTaskfile tf;
        tf.command = 0xEC;
        tf.transfer = AtaTaskfile::Transfer::PioIn;
        tf.count = 1;
        tf.device = 0;
        std::array<std::uint8_t, 512> buf{};
        auto r = pt.ata(tf, buf);
#ifdef _WIN32
        (void)hdio_errno;
        if (!r) return error("IDENTIFY DEVICE failed: " + r.error().message);
#else
        if (!r)
            return error(std::format("IDENTIFY DEVICE failed: HDIO_GET_IDENTITY: {}; SG_IO: {}",
                                     std::strerror(hdio_errno), r.error().message));
#endif
        std::memcpy(words.data(), buf.data(), buf.size());  // little-endian words on the wire
        decoded = decode_ata_identify(words, AtaStringOrder::WireSwapped);
    }
    if (!decoded) return decoded;
    AtaIdentity id = std::move(decoded).value();

    // 2. Native max: reveals an HPA. Legacy READ NATIVE MAX (0x27), else ACS-3 GET NATIVE MAX (0x78/0).
    if (id.hpa_supported) {
        AtaTaskfile rnm;
        rnm.command = 0x27;
        rnm.ext = true;
        auto regs = pt.ata(rnm, {});
        if (!regs) {
            AtaTaskfile gnm;
            gnm.command = 0x78;
            gnm.features = 0x0000;
            gnm.ext = true;
            regs = pt.ata(gnm, {});
        }
        if (regs && regs->lba_valid) {
            id.native_max_sectors = regs->lba + 1;
            id.hpa_enabled = id.native_max_sectors > id.user_addressable_sectors;
        } else {
            id.probe_notes.push_back("native max address not readable (" +
                                     (regs ? std::string("registers not returned") : regs.error().message) +
                                     "): HPA size unknown");
        }
    }

    // 3. DCO IDENTIFY: reveals capacity hidden by a Device Configuration Overlay.
    if (id.dco_supported) {
        AtaTaskfile dco;
        dco.command = 0xB1;
        dco.features = 0xC2;
        dco.transfer = AtaTaskfile::Transfer::PioIn;
        dco.count = 1;
        std::array<std::uint8_t, 512> buf{};
        auto r = pt.ata(dco, buf);
        if (r) {
            IdentifyWords dco_words{};
            std::memcpy(dco_words.data(), buf.data(), buf.size());
            auto max = decode_dco_identify(dco_words);
            if (max && *max >= id.native_max_sectors) id.dco_max_sectors = *max;
            else id.probe_notes.push_back("DCO IDENTIFY unusable: " + (max ? "reports less than native max" : max.error().message));
        } else {
            id.probe_notes.push_back("DCO IDENTIFY failed (" + r.error().message + "): DCO size unknown");
        }
    }

    // 4. TCG Level 0 Discovery (SECURITY PROTOCOL IN -> ATA TRUSTED RECEIVE via libata).
    std::vector<std::uint8_t> l0(2048);
    auto s = pt.security_in(0x01, 0x0001, l0);
    apply_tcg(id, s ? parse_tcg_level0(l0) : Result<TcgDiscovery>(s.error()));
    return id;
}

Result<AtaIdentity> NvmeIdentityProvider::identify(IBlockDevice& device) {
    if (device.kind() != BackendKind::PhysicalBlock) return error("NVMe Identify is only issued to physical devices");
    ReadOnlyPassthrough pt(device);
    auto nsid = pt.nvme_namespace_id();
    if (!nsid) return nsid.error();

    std::vector<std::uint8_t> ctrl(4096), ns(4096);
    if (auto r = pt.nvme_admin(NvmeAdminCmd{0x06, 0, 0x01, 0}, ctrl); !r)
        return error("Identify Controller: " + r.error().message);
    if (auto r = pt.nvme_admin(NvmeAdminCmd{0x06, *nsid, 0x00, 0}, ns); !r)
        return error("Identify Namespace: " + r.error().message);
    auto d = decode_nvme_identify(ctrl, ns);
    if (!d) return d.error();
    AtaIdentity id = d->id;
    id.nvme_nsid = *nsid;

    // Capacity is compared in the kernel's logical sectors; convert if the namespace differs.
    const std::uint32_t lss = device.geometry().logical_sector_size;
    if (d->lba_bytes != lss) {
        id.probe_notes.push_back(std::format("namespace LBA size {} B differs from kernel logical sector {} B",
                                             d->lba_bytes, lss));
        id.user_addressable_sectors = id.native_max_sectors = id.user_addressable_sectors * d->lba_bytes / lss;
    }
    if (d->format_crypto_erase) id.probe_notes.push_back("Format NVM supports cryptographic erase (FNA bit 2)");

    if (d->security_send_receive) {
        std::vector<std::uint8_t> l0(2048);
        const NvmeAdminCmd recv{0x82, 0, (0x01u << 24) | (0x0001u << 8), static_cast<std::uint32_t>(l0.size())};
        auto r = pt.nvme_admin(recv, l0);
        apply_tcg(id, r ? parse_tcg_level0(l0) : Result<TcgDiscovery>(r.error()));
    }
    return id;
}

// ============================================================================ sysfs

Result<AtaIdentity> EmmcIdentityProvider::identify(IBlockDevice& device) {
    if (device.kind() != BackendKind::PhysicalBlock) return error("EXT_CSD is only read from physical devices");
    const std::string name = std::filesystem::path(device.path()).filename().string();
    if (!name.starts_with("mmcblk")) return error(device.path() + " is not an eMMC device");
    std::vector<std::uint8_t> raw(512);
    ReadOnlyPassthrough pt(device);
    if (auto r = pt.mmc_ext_csd(raw); !r) return error("EXT_CSD: " + r.error().message);
    auto x = decode_ext_csd(raw);
    if (!x) return x.error();

    AtaIdentity id;
    id.transport = Transport::eMMC;
    id.rotation_rate = 1;
    const std::string dev = "/sys/block/" + name + "/device/";
    auto attr = [&](const char* a) { auto v = sysfs::read_file(dev + a); return v ? *v : std::string(); };
    id.model = attr("name");      // CID product name
    id.serial = attr("serial");   // CID product serial number
    id.firmware = attr("fwrev");
    if (id.model.empty() || id.serial.empty()) return error("the kernel exposes no eMMC CID for " + name);
    const std::uint32_t lss = device.geometry().logical_sector_size;
    id.user_addressable_sectors = id.native_max_sectors = x->sec_count * 512 / lss;
    id.sanitize_supported = x->sanitize;
    id.emmc_ext_csd_rev = x->rev;
    id.emmc_secure_erase = x->secure_erase;
    id.emmc_boot_bytes = x->boot_bytes;
    id.emmc_rpmb_bytes = x->rpmb_bytes;
    id.emmc_gp_bytes = x->gp_bytes;
    id.wear_ratio = x->wear_ratio;
    if (x->pre_eol >= 2)
        id.probe_notes.push_back(std::format("eMMC PRE_EOL_INFO {}: reserved blocks {}", x->pre_eol,
                                             x->pre_eol == 2 ? "80% consumed" : "urgent, nearly exhausted"));
    return id;
}

Result<SysfsDetection> detect_from_sysfs(const std::string& name) {
    namespace fs = std::filesystem;
    const std::string dir = sysfs::block_dir(name);
    SysfsDetection r;

    auto size = sysfs::read_file(dir + "/size");  // always in 512-byte units
    auto lbs = sysfs::read_file(dir + "/queue/logical_block_size");
    auto pbs = sysfs::read_file(dir + "/queue/physical_block_size");
    if (!size || !lbs) return error("sysfs has no size information for " + name);
    r.geometry.size_bytes = std::stoull(*size) * 512;
    r.geometry.logical_sector_size = static_cast<std::uint32_t>(std::stoul(*lbs));
    r.geometry.physical_sector_size = pbs ? static_cast<std::uint32_t>(std::stoul(*pbs)) : r.geometry.logical_sector_size;

    AtaIdentity& id = r.id;
    const std::string dev = dir + "/device";
    auto attr = [&](const char* a) { auto v = sysfs::read_file(dev + "/" + a); return v ? *v : std::string(); };

    if (name.starts_with("nvme")) {
        id.transport = Transport::NVMe;
        id.model = attr("model");
        id.serial = attr("serial");
        id.firmware = attr("firmware_rev");
        id.rotation_rate = 1;
    } else if (name.starts_with("mmcblk")) {
        id.transport = Transport::eMMC;
        id.model = attr("name");
        id.serial = attr("serial");
        id.firmware = attr("fwrev");
        id.rotation_rate = 1;
    } else {
        id.transport = Transport::SATA;
        const std::string vendor = attr("vendor");
        id.model = (vendor.empty() || vendor == "ATA" ? "" : vendor + " ") + attr("model");
        id.firmware = attr("rev");
        if (auto s = sysfs::device_serial(name)) id.serial = *s;
        std::error_code ec;
        const std::string real = fs::canonical(dev, ec).string();
        if (real.find("/usb") != std::string::npos)
            id.probe_notes.push_back("attached through a USB bridge: ATA commands may not pass through");
        else if (real.find("/ata") == std::string::npos)
            id.probe_notes.push_back("not attached through libata (SCSI/SAS?): ATA feature sets may not apply");

        // Rotation rate from VPD page B1 (world-readable); the rotational flag is only a fallback
        // because the kernel defaults it to 1 when the drive reports nothing.
        std::ifstream in(dev + "/vpd_pgb1", std::ios::binary);
        std::vector<std::uint8_t> page((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        if (auto rot = parse_vpd_b1_rotation(page)) {
            id.rotation_rate = *rot;
        } else if (auto rotational = sysfs::read_file(dir + "/queue/rotational"); rotational && *rotational == "0") {
            id.rotation_rate = 1;
        } else {
            id.probe_notes.push_back("rotation rate not available without IDENTIFY (kernel rotational flag is only a default)");
        }
    }
    if (id.model.empty()) id.model = "(unknown model)";
    id.user_addressable_sectors = id.native_max_sectors = r.geometry.sector_count();
    id.probe_notes.push_back("sysfs only: security, SANITIZE, HPA/DCO and encryption were not queried "
                             "(opening the device needs root); run with sudo for full identification");
    return r;
}

// ============================================================================ orchestration

#ifndef _WIN32  // Windows: platform/win_device.cpp
Result<PhysicalDetection> detect_physical(const TargetAssessment& t) {
    if (t.kind != BackendKind::PhysicalBlock) return error(t.canonical_path + " is not a physical block device");
    PhysicalDetection det;

    auto opened = open_target(t.canonical_path, OpenOptions{.writable = false, .direct_io = false});
    if (!opened) {
        if (opened.error().sys_errno != EACCES && opened.error().sys_errno != EPERM) return opened.error();
        auto s = detect_from_sysfs(t.block_name);
        if (!s) return s.error();
        det.geometry = s->geometry;
        det.identity = std::move(s->id);
        det.source = IdentitySource::Sysfs;
        det.origin = "/sys/class/block/" + t.block_name + " (device not opened: permission denied)";
        return det;
    }

    det.geometry = opened->device->geometry();
    const bool nvme = t.block_name.starts_with("nvme");
    const bool emmc = t.block_name.starts_with("mmcblk");
    std::unique_ptr<IIdentityProvider> provider;
    if (nvme) provider = std::make_unique<NvmeIdentityProvider>();
    else if (emmc) provider = std::make_unique<EmmcIdentityProvider>();
    else provider = std::make_unique<AtaIdentityProvider>();

    Result<AtaIdentity> id = error("no command-level identity provider for " + t.block_name);
    if (provider) id = provider->identify(*opened->device);
    if (id) {
        det.identity = std::move(id).value();
        det.source = provider->source();
        det.origin = nvme ? "NVMe Identify Controller/Namespace" : emmc ? "eMMC EXT_CSD (CMD8) + CID" : "ATA IDENTIFY DEVICE";
    } else {
        // Opened but the drive/bridge did not answer: fall back to sysfs for identity only.
        auto s = detect_from_sysfs(t.block_name);
        if (!s) return s.error();
        det.identity = std::move(s->id);
        det.identity.probe_notes.insert(det.identity.probe_notes.begin(), "command-level identify failed: " + id.error().message);
        det.source = IdentitySource::Sysfs;
        det.origin = "/sys/class/block/" + t.block_name;
    }
    det.target = std::move(opened).value();
    return det;
}
#endif

}  // namespace dw
