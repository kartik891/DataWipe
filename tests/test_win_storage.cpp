// Windows disk identity decoding (device/win_storage.hpp): runs on every platform with
// synthetic STORAGE_DEVICE_DESCRIPTOR buffers.

#include <array>
#include <cstring>
#include <string>
#include <vector>

#include "check.hpp"
#include "device/classifier.hpp"
#include "device/win_storage.hpp"
#include "engine/method_selector.hpp"

using namespace dw;
using namespace dw::winstorage;

namespace {

void put32(std::vector<std::uint8_t>& b, std::size_t off, std::uint32_t v) {
    for (int i = 0; i < 4; ++i) b[off + static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(v >> (8 * i));
}

// A descriptor laid out as Windows returns it: 36-byte header, then the strings.
std::vector<std::uint8_t> descriptor(const char* vendor, const char* product, const char* rev, const char* serial,
                                     Bus bus, bool removable = false) {
    std::vector<std::uint8_t> b(36, 0);
    auto add = [&](const char* s, std::size_t field) {
        if (!s) return;
        put32(b, field, static_cast<std::uint32_t>(b.size()));
        b.insert(b.end(), s, s + std::strlen(s) + 1);
    };
    add(vendor, 12);
    add(product, 16);
    add(rev, 20);
    add(serial, 24);
    put32(b, 0, 1);
    put32(b, 4, static_cast<std::uint32_t>(b.size()));
    b[8] = 0;  // FILE_DEVICE_DISK type in the descriptor is 0 for direct-access
    b[10] = removable ? 1 : 0;
    put32(b, 28, static_cast<std::uint32_t>(bus));
    return b;
}

void test_descriptor() {
    auto b = descriptor(nullptr, "WDC WD5000AAKX-22ERMA0  ", "18.01H18", "     WD-WCC0TEST0001", Bus::Sata);
    auto d = decode_descriptor(b);
    CHECK_OK(d);
    if (!d) return;
    CHECK(d->vendor.empty() && d->product == "WDC WD5000AAKX-22ERMA0" && d->revision == "18.01H18");
    CHECK(d->serial == "WD-WCC0TEST0001" && d->bus == Bus::Sata && !d->removable);

    CHECK_ERR_CONTAINS(decode_descriptor(std::vector<std::uint8_t>(20, 0)), "too short");
    auto bad = descriptor("ACME", "Disk", "1.0", "S1", Bus::Usb);
    put32(bad, 24, 5000);  // serial offset past the end
    CHECK_ERR_CONTAINS(decode_descriptor(bad), "outside");
    // Unterminated string at the end is cut at the descriptor's size, not read past it.
    auto cut = descriptor("ACME", "Disk", "1.0", "S1", Bus::Usb);
    cut.back() = 'X';
    auto c = decode_descriptor(cut);
    CHECK(c && c->serial == "S1X");
}

void test_owning_layers() {
    // Storage Spaces protective partition, in Windows' in-memory GUID layout.
    const std::array<std::uint8_t, 16> spaces = {0x8F, 0xAF, 0x5C, 0xE7, 0x80, 0xF6, 0xEE, 0x4C,
                                                 0xAF, 0xA3, 0xB0, 0x01, 0xE5, 0x6E, 0xFC, 0x2D};
    CHECK(guid_string(spaces) == "E75CAF8F-F680-4CEE-AFA3-B001E56EFC2D");
    CHECK(owning_layer_gpt(spaces) && owning_layer_gpt(spaces)->find("Storage Spaces") != std::string::npos);
    const std::array<std::uint8_t, 16> ldm_data = {0xA0, 0x60, 0x9B, 0xAF, 0x31, 0x14, 0x62, 0x4F,
                                                   0xBC, 0x68, 0x33, 0x11, 0x71, 0x4A, 0x69, 0xAD};
    CHECK(owning_layer_gpt(ldm_data) && owning_layer_gpt(ldm_data)->find("dynamic disk") != std::string::npos);
    // Basic data partition: an ordinary partition, found as a volume instead.
    const std::array<std::uint8_t, 16> basic = {0xA2, 0xA0, 0xD0, 0xEB, 0xE5, 0xB9, 0x33, 0x44,
                                                0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7};
    CHECK(guid_string(basic) == "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7" && !owning_layer_gpt(basic));
    CHECK(owning_layer_mbr(0x42) && !owning_layer_mbr(0x07) && !owning_layer_mbr(0x0C));
}

void test_paths() {
    CHECK(parse_disk_path("\\\\.\\PhysicalDrive3") == 3u);
    CHECK(parse_disk_path("//./physicaldrive0") == 0u);
    CHECK(parse_disk_path("\\\\?\\PHYSICALDRIVE12") == 12u);
    CHECK(!parse_disk_path("\\\\.\\PhysicalDrive"));
    CHECK(!parse_disk_path("\\\\.\\PhysicalDrive03"));   // one spelling per disk
    CHECK(!parse_disk_path("\\\\.\\PhysicalDrive1a"));
    CHECK(!parse_disk_path("\\\\.\\PhysicalDrive1234"));
    CHECK(!parse_disk_path("\\\\.\\C:"));
    CHECK(!parse_disk_path("PhysicalDrive1"));
    CHECK(!parse_disk_path("C:\\images\\PhysicalDrive1"));
    CHECK(disk_path(7) == "\\\\.\\PhysicalDrive7");
    CHECK(is_device_namespace("\\\\.\\C:") && is_device_namespace("\\\\?\\Volume{1234}") &&
          is_device_namespace("//./CdRom0") && is_device_namespace("\\?" "?\\C:"));
    CHECK(!is_device_namespace("C:\\disk.img") && !is_device_namespace("disk.img"));
}

DeviceProfile profile_of(const AtaIdentity& id, std::uint64_t bytes) {
    TargetAssessment t;
    t.canonical_path = "\\\\.\\PhysicalDrive1";
    t.kind = BackendKind::PhysicalBlock;
    DeviceGeometry g;
    g.size_bytes = bytes;
    auto p = classify(t, g, id, IdentitySource::WindowsStorage, "Windows storage descriptor");
    CHECK_OK(p);
    return p ? *p : DeviceProfile{};
}

void test_identity_and_plans() {
    constexpr std::uint64_t kBytes = 500107862016;
    auto d = decode_descriptor(descriptor(nullptr, "WDC WD5000AAKX-22ERMA0", "18.01H18", "WD-WCC0TEST0001", Bus::Usb));
    CHECK_OK(d);
    if (!d) return;

    // A spinning disk behind USB: seek penalty, no TRIM.
    auto hdd = build_identity({*d, kBytes, 512, true, false});
    CHECK(hdd.model == "WDC WD5000AAKX-22ERMA0" && hdd.serial == "WD-WCC0TEST0001" && hdd.firmware == "18.01H18");
    CHECK(hdd.transport == Transport::SATA && hdd.user_addressable_sectors == kBytes / 512 &&
          hdd.native_max_sectors == hdd.user_addressable_sectors);
    CHECK(!hdd.security_supported && !hdd.sanitize_supported && !hdd.nvme_format_supported);
    auto p = profile_of(hdd, kBytes);
    CHECK(p.media == MediaType::HDD && p.hidden_sectors() == 0);
    CHECK(!capabilities_queried(p.identity_source) && is_hardware_identity(p.identity_source));
    auto plan = select_method(p);
    CHECK_OK(plan);
    if (plan) {
        CHECK(plan->method_id == "hdd.overwrite" && plan->level == SanitizationLevel::Clear);
        CHECK(plan->steps.size() == 1 && plan->steps[0].execution == Execution::Real && plan->steps[0].commands.empty());
        bool said = false;
        for (const auto& w : plan->warnings) said |= w.find("Windows storage descriptor") != std::string::npos;
        CHECK(said);
    }

    // A SATA SSD: no seek penalty -> non-rotating; plan is the two-pass overwrite, no commands.
    auto ssd = build_identity({*d, kBytes, 512, false, true});
    CHECK(ssd.rotation_rate == 1 && ssd.trim_supported);
    auto sp = profile_of(ssd, kBytes);
    CHECK(sp.media == MediaType::SSD_SATA);
    auto splan = select_method(sp);
    CHECK(splan && splan->level == SanitizationLevel::Clear);
    if (splan)
        for (const auto& s : splan->steps) CHECK(s.commands.empty() && s.execution == Execution::Real);

    // NVMe: no Format NVM is planned, because this build cannot send it.
    auto nd = decode_descriptor(descriptor("NVMe", "INTEL SSDPEKKF256G8", "L08P", "BTHH0000000000256B", Bus::Nvme));
    CHECK_OK(nd);
    if (nd) {
        auto nvme = build_identity({*nd, 256060514304, 512, false, true});
        CHECK(nvme.transport == Transport::NVMe && nvme.model == "NVMe INTEL SSDPEKKF256G8");
        auto np = profile_of(nvme, 256060514304);
        auto nplan = select_method(np);
        CHECK(nplan && nplan->level == SanitizationLevel::Clear);
        if (nplan)
            for (const auto& s : nplan->steps) CHECK(s.commands.empty());
    }

    // Unknown rotation and TRIM (common behind USB): HDD by the TRIM rule, with the reason given.
    auto unk = build_identity({*d, kBytes, 512, std::nullopt, std::nullopt});
    bool noted = false;
    for (const auto& n : unk.probe_notes) noted |= n.find("could not report whether the disk rotates") != std::string::npos;
    CHECK(noted && profile_of(unk, kBytes).media == MediaType::HDD);

    // 4Kn disk: sectors counted in 4096-byte units.
    auto k4 = build_identity({*d, 4096ull * 1000, 4096, true, false});
    CHECK(k4.user_addressable_sectors == 1000);
}

}  // namespace

int main() {
    test_descriptor();
    test_owning_layers();
    test_paths();
    test_identity_and_plans();
    return finish("test_win_storage");
}
