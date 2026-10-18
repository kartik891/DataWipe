// Real-hardware detection: decoders, the read-only command whitelist, and a live read-only
// detection of whatever physical disk this machine has (sysfs-only when not root).

#include <cstring>
#include <filesystem>
#include <fstream>

#include "check.hpp"
#include "core/log.hpp"
#include "device/classifier.hpp"
#include "device/hw_identity.hpp"
#include "device/passthrough.hpp"
#include "engine/device_command.hpp"
#include "engine/method_selector.hpp"

using namespace dw;
namespace fs = std::filesystem;

namespace {

void put_ascii(std::vector<std::uint8_t>& b, size_t off, size_t n, const std::string& s) {
    for (size_t i = 0; i < n; ++i) b[off + i] = i < s.size() ? static_cast<std::uint8_t>(s[i]) : ' ';
}
void put_le(std::vector<std::uint8_t>& b, size_t off, std::uint64_t v, int bytes) {
    for (int i = 0; i < bytes; ++i) b[off + static_cast<size_t>(i)] = static_cast<std::uint8_t>(v >> (8 * i));
}

void test_nvme_decode() {
    std::vector<std::uint8_t> ctrl(4096), ns(4096);
    put_ascii(ctrl, 4, 20, "S5GXNG0R123456");
    put_ascii(ctrl, 24, 40, "Samsung SSD 980 PRO 1TB");
    put_ascii(ctrl, 64, 8, "5B2QGXA7");
    put_le(ctrl, 256, 0x0017, 2);  // OACS: Security Send/Receive, Format, FW, NS mgmt
    put_le(ctrl, 328, 0x3, 4);     // SANICAP: CES | BES
    ctrl[524] = 0x04;              // FNA: crypto erase supported
    put_le(ns, 0, 1953525168ull, 8);
    ns[26] = 0x01;         // FLBAS: format index 1
    ns[128 + 2] = 9;       // LBAF0: 512 B
    ns[128 + 4 + 2] = 12;  // LBAF1: 4096 B
    auto d = decode_nvme_identify(ctrl, ns);
    CHECK_OK(d);
    if (d) {
        CHECK(d->id.model == "Samsung SSD 980 PRO 1TB" && d->id.serial == "S5GXNG0R123456" && d->id.firmware == "5B2QGXA7");
        CHECK(d->id.transport == Transport::NVMe && d->id.rotation_rate == 1);
        CHECK(d->id.sanitize_supported && d->id.crypto_scramble_supported && d->id.block_erase_supported);
        CHECK(!d->id.overwrite_supported);
        CHECK(d->security_send_receive && d->format_crypto_erase);
        CHECK(d->lba_bytes == 4096 && d->id.user_addressable_sectors == 1953525168ull);
        CHECK(d->id.dco_max_sectors == 0 && d->id.native_max_sectors == d->id.user_addressable_sectors);
    }
    std::vector<std::uint8_t> blank(4096);
    CHECK_ERR_CONTAINS(decode_nvme_identify(blank, ns), "empty model");
    CHECK_ERR_CONTAINS(decode_nvme_identify(ctrl, blank), "implausible LBA");
    CHECK_ERR_CONTAINS(decode_nvme_identify(std::vector<std::uint8_t>(100), ns), "4096");
}

std::vector<std::uint8_t> level0(std::initializer_list<std::pair<std::uint16_t, std::vector<std::uint8_t>>> feats) {
    std::vector<std::uint8_t> d(48, 0);
    for (const auto& [code, data] : feats) {
        d.push_back(static_cast<std::uint8_t>(code >> 8));
        d.push_back(static_cast<std::uint8_t>(code));
        d.push_back(0x10);  // version
        d.push_back(static_cast<std::uint8_t>(data.size()));
        d.insert(d.end(), data.begin(), data.end());
    }
    const auto len = static_cast<std::uint32_t>(d.size() - 4);
    d[0] = static_cast<std::uint8_t>(len >> 24);
    d[1] = static_cast<std::uint8_t>(len >> 16);
    d[2] = static_cast<std::uint8_t>(len >> 8);
    d[3] = static_cast<std::uint8_t>(len);
    d.resize(2048, 0);
    return d;
}

void test_tcg() {
    auto opal = parse_tcg_level0(level0({{0x0001, std::vector<std::uint8_t>(12, 0x11)},
                                         {0x0002, {0x0B, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
                                         {0x0203, std::vector<std::uint8_t>(16, 0)}}));
    CHECK_OK(opal);
    if (opal) {
        CHECK(opal->locking_feature && opal->media_encryption && opal->locking_enabled && !opal->locked);
        CHECK(opal->ssc == "Opal 2");
    }
    auto pyrite = parse_tcg_level0(level0({{0x0002, {0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
                                           {0x0303, std::vector<std::uint8_t>(16, 0)}}));
    CHECK_OK(pyrite);
    if (pyrite) CHECK(pyrite->locking_feature && !pyrite->media_encryption && pyrite->ssc == "Pyrite 2");

    CHECK_ERR_CONTAINS(parse_tcg_level0(std::vector<std::uint8_t>(2048, 0)), "no TCG support");
    auto bad = level0({{0x0002, {0x0B}}});
    bad[48 + 3] = 200;  // descriptor claims more bytes than the response has
    bad.resize(60);
    CHECK_ERR_CONTAINS(parse_tcg_level0(bad), "truncated");
}

void test_dco_vpd() {
    IdentifyWords w{};
    w[0] = 0x0002;
    const std::uint64_t max_lba = 1953525167ull;
    for (int i = 0; i < 4; ++i) w[static_cast<size_t>(3 + i)] = static_cast<std::uint16_t>(max_lba >> (16 * i));
    w[255] = 0x00A5;
    std::uint8_t sum = 0;
    for (auto word : w) sum = static_cast<std::uint8_t>(sum + (word & 0xFF) + (word >> 8));
    w[255] = static_cast<std::uint16_t>(0x00A5 | (static_cast<std::uint8_t>(-sum) << 8));
    auto r = decode_dco_identify(w);
    CHECK_OK(r);
    if (r) CHECK(*r == max_lba + 1);
    w[4] ^= 1;
    CHECK_ERR_CONTAINS(decode_dco_identify(w), "checksum");

    const std::uint8_t hdd[] = {0x00, 0xB1, 0x00, 0x3C, 0x1C, 0x20};
    const std::uint8_t ssd[] = {0x00, 0xB1, 0x00, 0x3C, 0x00, 0x01};
    const std::uint8_t other[] = {0x00, 0x80, 0x00, 0x3C, 0x00, 0x01};
    CHECK(parse_vpd_b1_rotation(hdd) == std::optional<std::uint16_t>(7200));
    CHECK(parse_vpd_b1_rotation(ssd) == std::optional<std::uint16_t>(1));
    CHECK(!parse_vpd_b1_rotation(other));
}

void test_sense() {
    // Descriptor sense (0x72) with ATA Status Return descriptor, 48-bit LBA 0x123456789ABC.
    std::vector<std::uint8_t> s = {0x72, 0x01, 0x00, 0x1D, 0, 0, 0, 14,
                                   0x09, 0x0C, 0x01, 0x00, 0x00, 0x01, 0x56, 0xBC, 0x34, 0x9A, 0x12, 0x78, 0x40, 0x50};
    auto r = parse_ata_sense(s);
    CHECK_OK(r);
    if (r) {
        CHECK(r->lba_valid && r->lba == 0x123456789ABCull);
        CHECK(r->status == 0x50 && r->error == 0 && r->count == 1);
    }
    std::vector<std::uint8_t> fixed = {0x70, 0, 0x01, 0x04, 0x51, 0x40, 0x00, 10, 0, 0, 0, 0, 0, 0x1D};
    auto f = parse_ata_sense(fixed);
    CHECK_OK(f);
    if (f) CHECK(!f->lba_valid && f->status == 0x51 && f->error == 0x04);
    // A bridge that rejects ATA PASS-THROUGH (ILLEGAL REQUEST, INVALID COMMAND OPERATION CODE):
    // not a register set with status 0, which would read as success.
    std::vector<std::uint8_t> illegal = {0x70, 0, 0x05, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0x20, 0x00};
    CHECK_ERR_CONTAINS(parse_ata_sense(illegal), "ILLEGAL REQUEST ASC/ASCQ 0x20/0x00");
    std::vector<std::uint8_t> attention = {0x70, 0, 0x06, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0x29, 0x00};
    CHECK_ERR_CONTAINS(parse_ata_sense(attention), "UNIT ATTENTION");
    // ABORTED COMMAND still carries the device's registers (its ERR bit is what fails the command).
    std::vector<std::uint8_t> aborted = {0x70, 0, 0x0B, 0x04, 0x51, 0x40, 0x00, 10, 0, 0, 0, 0, 0, 0x1D};
    auto ab = parse_ata_sense(aborted);
    CHECK(ab && ab->status == 0x51 && ab->error == 0x04);
    CHECK_ERR_CONTAINS(parse_ata_sense(std::vector<std::uint8_t>{0x72, 0, 0, 0, 0, 0, 0, 0}), "no ATA Status Return");
    CHECK_ERR_CONTAINS(parse_ata_sense(std::vector<std::uint8_t>{}), "no sense");
}

void test_whitelist() {
    using T = AtaTaskfile::Transfer;
    auto tf = [](std::uint8_t cmd, std::uint16_t feat, T t) {
        AtaTaskfile x;
        x.command = cmd;
        x.features = feat;
        x.transfer = t;
        return x;
    };
    CHECK_OK(ReadOnlyPassthrough::allow_ata(tf(0xEC, 0, T::PioIn)));
    CHECK_OK(ReadOnlyPassthrough::allow_ata(tf(0x27, 0, T::NonData)));
    CHECK_OK(ReadOnlyPassthrough::allow_ata(tf(0x78, 0x0000, T::NonData)));
    CHECK_OK(ReadOnlyPassthrough::allow_ata(tf(0xB1, 0xC2, T::PioIn)));
    CHECK_ERR_CONTAINS(ReadOnlyPassthrough::allow_ata(tf(0x78, 0x0001, T::NonData)), "READ-ONLY GUARD");  // SET ACCESSIBLE MAX
    CHECK_ERR_CONTAINS(ReadOnlyPassthrough::allow_ata(tf(0xEC, 0, T::PioOut)), "data-out");

    // Every destructive command the engine can build must be refused.
    for (const auto& c : {ata::security_set_password("x"), ata::security_erase_prepare(),
                          ata::security_erase_unit("x", true), ata::sanitize_crypto_scramble(),
                          ata::sanitize_block_erase(), ata::sanitize_overwrite(0), ata::sanitize_status(),
                          ata::set_max_address_ext(100, true), ata::dco_restore()}) {
        auto r = ReadOnlyPassthrough::allow_ata(*c.ata);
        if (r) {
            std::fprintf(stderr, "FAIL whitelist let through %s\n", c.name.c_str());
            ++g_failures;
        }
    }
    CHECK_OK(ReadOnlyPassthrough::allow_ata(*ata::read_native_max_address_ext().ata));

    CHECK_OK(ReadOnlyPassthrough::allow_nvme(NvmeAdminCmd{0x06, 0, 0x01, 0}));
    CHECK_OK(ReadOnlyPassthrough::allow_nvme(NvmeAdminCmd{0x06, 1, 0x00, 0}));
    CHECK_OK(ReadOnlyPassthrough::allow_nvme(NvmeAdminCmd{0x82, 0, (0x01u << 24) | (0x0001u << 8), 2048}));
    CHECK(!ReadOnlyPassthrough::allow_nvme(NvmeAdminCmd{0x06, 0, 0x02, 0}));
    CHECK(!ReadOnlyPassthrough::allow_nvme(NvmeAdminCmd{0x82, 0, (0x02u << 24), 2048}));
    CHECK(!ReadOnlyPassthrough::allow_nvme(NvmeAdminCmd{0x81, 0, (0x01u << 24) | (0x0001u << 8), 0}));  // Security Send
    for (const auto& c : {nvme::sanitize(nvme::SanitizeAction::BlockErase), nvme::sanitize(nvme::SanitizeAction::CryptoErase),
                          nvme::format_nvm(1, 1, 0), nvme::format_nvm(2, 1, 0)})
        CHECK(!ReadOnlyPassthrough::allow_nvme(*c.nvme));

    CHECK_OK(ReadOnlyPassthrough::allow_security_in(0x01, 0x0001));
    CHECK_OK(ReadOnlyPassthrough::allow_security_in(0x00, 0x0000));
    CHECK(!ReadOnlyPassthrough::allow_security_in(0x01, 0x0002));
    CHECK(!ReadOnlyPassthrough::allow_security_in(0xEF, 0x0000));

    // The refusal happens before any ioctl: exercised on an ordinary image file.
    fs::path img = fs::temp_directory_path() / "dw_hw_whitelist.img";
    { std::ofstream(img, std::ios::binary) << std::string(4096, '\0'); }
    auto t = open_target(img.string(), OpenOptions{});
    CHECK_OK(t);
    if (t) {
        ReadOnlyPassthrough pt(*t->device);
        CHECK_ERR_CONTAINS(pt.ata(*ata::security_erase_prepare().ata, {}), "READ-ONLY GUARD");
        std::vector<std::uint8_t> buf(4096);
        CHECK_ERR_CONTAINS(pt.nvme_admin(*nvme::format_nvm(2, 1, 0).nvme, buf), "READ-ONLY GUARD");
    }
    fs::remove(img);
}

// Live, read-only: the first physical disk this machine has (the test never opens it writable).
void test_live_detection() {
#ifdef _WIN32
    return;  // Linux device nodes and /sys: not part of the Windows build (Wine would show the host's)
#endif
    std::string name;
    for (const auto& e : fs::directory_iterator("/sys/block")) {
        std::string n = e.path().filename().string();
        if (n.starts_with("nvme") || n.starts_with("sd")) { name = n; break; }
    }
    if (name.empty()) {
        std::fprintf(stderr, "  (no physical disk found, live detection skipped)\n");
        return;
    }
    auto a = assess_target("/dev/" + name);
    CHECK_OK(a);
    if (!a) return;
    CHECK(a->kind == BackendKind::PhysicalBlock);
    CHECK_ERR_CONTAINS(open_target("/dev/" + name, OpenOptions{.writable = true}), "REFUSED");

    auto det = detect_physical(*a);
    CHECK_OK(det);
    if (!det) return;
    CHECK(!det->identity.model.empty() && det->geometry.size_bytes > 0);
    if (det->target) CHECK(!det->target->device->writable());
    auto p = classify(*a, det->geometry, det->identity, det->source, det->origin);
    CHECK_OK(p);
    if (!p) return;
    if (name.starts_with("nvme")) CHECK(p->media == MediaType::SSD_NVMe);
    auto plan = select_method(*p);
    std::fprintf(stderr, "  live: /dev/%s -> %s via %s, %s, %s, plan %s\n", name.c_str(), p->identity.model.c_str(),
                 std::string(to_string(det->source)).c_str(), std::string(to_string(p->media)).c_str(),
                 p->encrypted ? "self-encrypting" : "not reported as self-encrypting",
                 plan ? plan->method_id.c_str() : plan.error().message.c_str());
    if (plan) {
        bool flagged = false;
        for (const auto& w : plan->warnings) flagged |= w.find("REAL DEVICE") != std::string::npos;
        CHECK(flagged);
    }
}

}  // namespace

// EXT_CSD offsets per JEDEC JESD84-B51 section 7.4.
void test_ext_csd() {
    std::vector<std::uint8_t> x(512, 0);
    x[192] = 8;  // eMMC 5.1
    const std::uint32_t sectors = 7634944;  // ~3.6 GiB
    std::memcpy(&x[212], &sectors, 4);
    x[231] = 0x45;  // SEC_SANITIZE | SEC_BD_BLK_EN | SECURE_ER_EN
    x[226] = 32;    // BOOT_SIZE_MULT: 32 x 128 KiB = 4 MiB each
    x[168] = 4;     // RPMB_SIZE_MULT: 512 KiB
    x[221] = 1;     // HC_WP_GRP_SIZE
    x[224] = 2;     // HC_ERASE_GRP_SIZE -> GP unit 1 MiB
    x[143] = 3;     // GP1: 3 units
    x[268] = 0x03;  // life A: 20-30% used
    x[269] = 0x05;  // life B: 40-50% used
    x[267] = 0x02;  // PRE_EOL warning
    auto e = decode_ext_csd(x);
    CHECK_OK(e);
    if (e) {
        CHECK(e->rev == 8 && e->sec_count == sectors && e->sanitize && e->secure_erase);
        CHECK(e->boot_bytes == 8u << 20 && e->rpmb_bytes == 512u << 10 && e->gp_bytes == 3u << 20);
        CHECK(e->wear_ratio == 0.5 && e->pre_eol == 2);  // the worse of A and B, upper bound
    }
    // SANITIZE only exists from eMMC 4.5 (rev 6): the bit means nothing on a 4.41 card.
    x[192] = 5;
    e = decode_ext_csd(x);
    CHECK(e && !e->sanitize && e->secure_erase && e->wear_ratio < 0);  // life time is eMMC 5.0+
    x[192] = 8;
    x[268] = x[269] = 0x0B;  // exceeded
    e = decode_ext_csd(x);
    CHECK(e && e->wear_ratio == 1.0);
    x[192] = 12;
    CHECK_ERR_CONTAINS(decode_ext_csd(x), "implausible");
    x[192] = 8;
    std::memset(&x[212], 0, 4);
    CHECK_ERR_CONTAINS(decode_ext_csd(x), "0 sectors");
    CHECK_ERR_CONTAINS(decode_ext_csd(std::span(x).first(100)), "512 bytes");
}

int main() {
    log::set_level(log::Level::Error);
    test_nvme_decode();
    test_tcg();
    test_dco_vpd();
    test_sense();
    test_ext_csd();
    test_whitelist();
    test_live_detection();
    return finish("test_hardware");
}
