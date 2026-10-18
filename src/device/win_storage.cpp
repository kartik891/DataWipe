#include "device/win_storage.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <format>

namespace dw::winstorage {

namespace {

std::uint32_t u32(std::span<const std::uint8_t> b, std::size_t off) {
    std::uint32_t v = 0;
    for (int i = 3; i >= 0; --i) v = (v << 8) | b[off + static_cast<std::size_t>(i)];
    return v;
}

std::string trim(std::string s) {
    auto is_pad = [](unsigned char c) { return c == ' ' || c == '\t' || c == 0; };
    while (!s.empty() && is_pad(static_cast<unsigned char>(s.back()))) s.pop_back();
    std::size_t i = 0;
    while (i < s.size() && is_pad(static_cast<unsigned char>(s[i]))) ++i;
    return s.substr(i);
}

// A NUL-terminated string at `off` inside the descriptor; 0 = absent.
Result<std::string> string_at(std::span<const std::uint8_t> b, std::uint32_t off, std::size_t limit, const char* what) {
    if (off == 0) return std::string();
    if (off >= limit) return error(std::format("storage descriptor: {} offset {} is outside its {} bytes", what, off, limit));
    std::string s;
    for (std::size_t i = off; i < limit && b[i] != 0; ++i) {
        const unsigned char c = b[i];
        s += std::isprint(c) ? static_cast<char>(c) : '?';
    }
    return trim(s);
}

std::string lower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

std::string unify(const std::string& path) {
    std::string s = path;
    std::replace(s.begin(), s.end(), '\\', '/');
    return lower(s);
}

}  // namespace

std::string to_string(Bus b) {
    switch (b) {
        case Bus::Unknown: return "unknown";
        case Bus::Scsi: return "SCSI";
        case Bus::Atapi: return "ATAPI";
        case Bus::Ata: return "ATA";
        case Bus::Ieee1394: return "IEEE 1394";
        case Bus::Ssa: return "SSA";
        case Bus::Fibre: return "Fibre Channel";
        case Bus::Usb: return "USB";
        case Bus::Raid: return "RAID";
        case Bus::IScsi: return "iSCSI";
        case Bus::Sas: return "SAS";
        case Bus::Sata: return "SATA";
        case Bus::Sd: return "SD";
        case Bus::Mmc: return "MMC";
        case Bus::Virtual: return "virtual";
        case Bus::FileBackedVirtual: return "virtual disk (VHD)";
        case Bus::Spaces: return "Storage Spaces";
        case Bus::Nvme: return "NVMe";
        case Bus::Scm: return "SCM";
        case Bus::Ufs: return "UFS";
    }
    return std::format("bus type {}", static_cast<std::uint32_t>(b));
}

Result<Descriptor> decode_descriptor(std::span<const std::uint8_t> b) {
    // Version, Size, DeviceType, DeviceTypeModifier, RemovableMedia, CommandQueueing,
    // VendorIdOffset, ProductIdOffset, ProductRevisionOffset, SerialNumberOffset, BusType,
    // RawPropertiesLength: 36 bytes before the raw properties.
    constexpr std::size_t kHeader = 36;
    if (b.size() < kHeader) return error(std::format("storage descriptor too short ({} bytes)", b.size()));
    const std::size_t limit = std::min<std::size_t>(b.size(), std::max<std::uint32_t>(u32(b, 4), kHeader));
    Descriptor d;
    d.removable = b[10] != 0;
    d.bus = static_cast<Bus>(u32(b, 28));
    auto v = string_at(b, u32(b, 12), limit, "vendor");
    auto p = string_at(b, u32(b, 16), limit, "product");
    auto r = string_at(b, u32(b, 20), limit, "revision");
    auto s = string_at(b, u32(b, 24), limit, "serial number");
    for (auto* x : {&v, &p, &r, &s})
        if (!*x) return x->error();
    d.vendor = *v;
    d.product = *p;
    d.revision = *r;
    d.serial = *s;
    return d;
}

std::optional<unsigned> parse_disk_path(const std::string& path) {
    const std::string s = unify(path);
    std::string_view rest;
    for (std::string_view prefix : {"//./physicaldrive", "//?/physicaldrive"})
        if (s.starts_with(prefix)) rest = std::string_view(s).substr(prefix.size());
    if (rest.empty() || rest.size() > 3 || !std::all_of(rest.begin(), rest.end(), [](char c) { return c >= '0' && c <= '9'; }))
        return std::nullopt;
    if (rest.size() > 1 && rest[0] == '0') return std::nullopt;  // one spelling per disk
    unsigned n = 0;
    for (char c : rest) n = n * 10 + static_cast<unsigned>(c - '0');
    return n;
}

std::string disk_path(unsigned number) { return std::format("\\\\.\\PhysicalDrive{}", number); }

std::string guid_string(std::span<const std::uint8_t, 16> g) {
    auto le = [&](int off, int n) {
        std::uint32_t v = 0;
        for (int i = n - 1; i >= 0; --i) v = (v << 8) | g[static_cast<std::size_t>(off + i)];
        return v;
    };
    return std::format("{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}", le(0, 4), le(4, 2), le(6, 2),
                       g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15]);
}

std::optional<std::string> owning_layer_gpt(std::span<const std::uint8_t, 16> guid) {
    const std::string s = guid_string(guid);
    if (s == "E75CAF8F-F680-4CEE-AFA3-B001E56EFC2D") return "it is a member of a Storage Spaces pool";
    if (s == "5808C8AA-7E8F-42E0-85D2-E1E90434CFB3" || s == "AF9B60A0-1431-4F62-BC68-3311714A69AD")
        return "it is a dynamic disk (its volumes may span other disks)";
    return std::nullopt;
}

std::optional<std::string> owning_layer_mbr(std::uint8_t partition_type) {
    if (partition_type == 0x42) return "it is a dynamic disk (its volumes may span other disks)";
    return std::nullopt;
}

bool is_device_namespace(const std::string& path) {
    const std::string s = unify(path);
    return s.starts_with("//./") || s.starts_with("//?/") || s.starts_with("/?" "?/") || s.starts_with("/device/");
}

AtaIdentity build_identity(const Inputs& in) {
    const Descriptor& d = in.descriptor;
    AtaIdentity id;
    id.model = d.vendor.empty() ? d.product : d.product.starts_with(d.vendor) ? d.product : d.vendor + " " + d.product;
    id.model = trim(id.model);
    id.serial = d.serial;
    id.firmware = d.revision;
    id.transport = d.bus == Bus::Nvme ? Transport::NVMe
                   : d.bus == Bus::Sd || d.bus == Bus::Mmc ? Transport::eMMC
                                                           : Transport::SATA;
    const std::uint32_t ss = in.logical_sector ? in.logical_sector : 512;
    id.user_addressable_sectors = in.disk_bytes / ss;
    id.native_max_sectors = id.user_addressable_sectors;

    // Rotation. A seek penalty is what Windows itself uses to tell spinning disks from flash.
    if (in.seek_penalty == false) id.rotation_rate = 0x0001;
    if (in.trim) id.trim_supported = *in.trim && in.seek_penalty != true;
    if (in.seek_penalty == true) id.probe_notes.push_back("Windows reports a seek penalty: rotating media");
    else if (!in.seek_penalty) id.probe_notes.push_back("Windows could not report whether the disk rotates");

    // These are not limitations of the drive: this build cannot ask.
    id.nvme_format_supported = false;
    id.probe_notes.push_back("Windows build: firmware erase support (Secure Erase, SANITIZE, Format NVM), hidden "
                             "areas (HPA/DCO) and self-encryption were not queried; drive commands cannot be sent");
    if (d.bus == Bus::Usb)
        id.probe_notes.push_back("connected through USB: the bridge may hide sectors or report a smaller capacity");
    return id;
}

}  // namespace dw::winstorage
