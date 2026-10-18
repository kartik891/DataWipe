// Windows device layer.
//
// Physical disks (\\.\PhysicalDriveN) are identified from the storage stack's descriptor and
// geometry, checked for volumes, and opened unbuffered. SATA drives (and USB bridges that
// implement SAT) are then identified with ATA IDENTIFY and sent ATA commands through
// IOCTL_SCSI_PASS_THROUGH_DIRECT, carrying the same ATA PASS-THROUGH(16) command blocks the
// Linux build sends through SG_IO. NVMe and eMMC drives get no commands: Windows' inbox drivers
// do not pass Format NVM, Sanitize or eMMC commands through, so their plans are host overwrites.
//
// Every ATA command that changes the drive is Experimental on Windows (engine/command_support):
// the commands are validated on Linux, this transport has not yet run on hardware.
//
// Writing to a disk needs, as on Linux: the destructive flag, the operator retyping the serial
// number and path, a disk opened by an Administrator, and no volume on the disk (take it offline
// first). The checks themselves are in device/safety_guard.cpp, device_factory.cpp and the CLI.

#include "platform/win_device.hpp"

#include <windows.h>
#include <winioctl.h>
#include <ntddscsi.h>

#include <array>
#include <cstddef>
#include <cstring>
#include <format>
#include <memory>
#include <vector>

#include "core/log.hpp"
#include "core/portable.hpp"
#include "device/ata_taskfile.hpp"
#include "device/identity_provider.hpp"
#include "device/backends.hpp"
#include "device/device_factory.hpp"
#include "device/hw_identity.hpp"
#include "device/passthrough.hpp"
#include "device/sysfs.hpp"

namespace dw {

namespace {

Error not_yet(const std::string& what) {
    return error(what + " cannot be sent from Windows (its inbox drivers do not pass them through; use the "
                        "bootable DataWipe image)");
}

class Handle {
public:
    explicit Handle(HANDLE h) : h_(h) {}
    ~Handle() {
        if (ok()) CloseHandle(h_);
    }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    bool ok() const { return h_ != INVALID_HANDLE_VALUE && h_ != nullptr; }
    HANDLE get() const { return h_; }

private:
    HANDLE h_;
};

std::string win_message(DWORD e) {
    char buf[256] = {};
    const DWORD n = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, e, 0, buf,
                                   sizeof buf, nullptr);
    std::string s(buf, n);
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r' || s.back() == ' ' || s.back() == '.')) s.pop_back();
    return std::format("{} (Windows error {})", s, e);
}

Handle open_query(unsigned number) {
    const std::string path = winstorage::disk_path(number);
    return Handle(CreateFileA(path.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr));
}

bool device_number_of(HANDLE h, STORAGE_DEVICE_NUMBER& out) {
    DWORD got = 0;
    return DeviceIoControl(h, IOCTL_STORAGE_GET_DEVICE_NUMBER, nullptr, 0, &out, sizeof out, &got, nullptr) != 0;
}

// IOCTL_STORAGE_QUERY_PROPERTY into a fixed-size structure. False if the driver does not answer.
template <typename T>
bool query_property(HANDLE h, STORAGE_PROPERTY_ID id, T& out) {
    STORAGE_PROPERTY_QUERY q{};
    q.PropertyId = id;
    q.QueryType = PropertyStandardQuery;
    DWORD got = 0;
    return DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY, &q, sizeof q, &out, sizeof out, &got, nullptr) &&
           got >= sizeof out;
}

Result<std::vector<std::uint8_t>> device_descriptor(HANDLE h) {
    STORAGE_PROPERTY_QUERY q{};
    q.PropertyId = StorageDeviceProperty;
    q.QueryType = PropertyStandardQuery;
    STORAGE_DESCRIPTOR_HEADER head{};
    DWORD got = 0;
    if (!DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY, &q, sizeof q, &head, sizeof head, &got, nullptr))
        return error("storage descriptor query failed: " + win_message(GetLastError()));
    std::vector<std::uint8_t> buf(std::max<DWORD>(head.Size, sizeof(STORAGE_DEVICE_DESCRIPTOR)) + 256, 0);
    if (!DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY, &q, sizeof q, buf.data(), static_cast<DWORD>(buf.size()), &got,
                         nullptr))
        return error("storage descriptor query failed: " + win_message(GetLastError()));
    buf.resize(got);
    return buf;
}

struct Geometry {
    std::uint64_t bytes = 0;
    std::uint32_t logical = 512, physical = 0;
};

Result<Geometry> geometry_of(HANDLE h) {
    std::vector<std::uint8_t> buf(sizeof(DISK_GEOMETRY_EX) + 512, 0);
    DWORD got = 0;
    if (!DeviceIoControl(h, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, nullptr, 0, buf.data(), static_cast<DWORD>(buf.size()), &got,
                         nullptr))
        return error("drive geometry query failed: " + win_message(GetLastError()));
    DISK_GEOMETRY_EX g{};
    std::memcpy(&g, buf.data(), std::min<std::size_t>(sizeof g, got));
    Geometry out;
    out.bytes = static_cast<std::uint64_t>(g.DiskSize.QuadPart);
    out.logical = g.Geometry.BytesPerSector ? g.Geometry.BytesPerSector : 512;
    STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR align{};
    if (query_property(h, StorageAccessAlignmentProperty, align)) out.physical = align.BytesPerPhysicalSector;
    if (out.bytes == 0) return error("the disk reports a size of 0 (no medium?)");
    return out;
}

std::wstring trim_trailing_backslash(std::wstring s) {
    if (!s.empty() && s.back() == L'\\') s.pop_back();
    return s;
}

std::string narrow(const std::wstring& w) {
    if (w.empty()) return {};
    const int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
    std::string s(static_cast<std::size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()), s.data(), n, nullptr, nullptr);
    return s;
}

// Mount points of a volume ("C:\", "D:\mnt\data\"), from its GUID path.
std::vector<std::string> mount_points(const std::wstring& volume) {
    std::vector<wchar_t> buf(1024);
    DWORD need = 0;
    if (!GetVolumePathNamesForVolumeNameW(volume.c_str(), buf.data(), static_cast<DWORD>(buf.size()), &need)) {
        if (GetLastError() != ERROR_MORE_DATA) return {};
        buf.resize(need);
        if (!GetVolumePathNamesForVolumeNameW(volume.c_str(), buf.data(), static_cast<DWORD>(buf.size()), &need)) return {};
    }
    std::vector<std::string> out;
    for (const wchar_t* p = buf.data(); *p; p += std::wcslen(p) + 1) out.push_back(narrow(p));
    return out;
}

// Disk numbers a volume has extents on.
std::vector<unsigned> volume_disks(const std::wstring& volume) {
    const std::wstring dev = trim_trailing_backslash(volume);
    Handle v(CreateFileW(dev.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr));
    if (!v.ok()) return {};
    std::vector<std::uint8_t> buf(sizeof(VOLUME_DISK_EXTENTS) + 64 * sizeof(DISK_EXTENT), 0);
    DWORD got = 0;
    if (!DeviceIoControl(v.get(), IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, nullptr, 0, buf.data(),
                         static_cast<DWORD>(buf.size()), &got, nullptr))
        return {};
    const auto* ext = reinterpret_cast<const VOLUME_DISK_EXTENTS*>(buf.data());
    std::vector<unsigned> out;
    for (DWORD i = 0; i < ext->NumberOfDiskExtents && i < 64; ++i) out.push_back(ext->Extents[i].DiskNumber);
    return out;
}

// ---------------------------------------------------------------- SCSI pass-through

constexpr unsigned kQueryTimeoutMs = 15000;

struct SptdWithSense {
    SCSI_PASS_THROUGH_DIRECT sptd;
    ULONG filler;  // keeps the sense buffer aligned, as Microsoft's samples do
    UCHAR sense[32];
};

struct SptResult {
    std::uint8_t scsi_status = 0;
    std::array<std::uint8_t, 32> sense{};
    std::size_t sense_len = 0;

    bool has_sense() const {
        const std::uint8_t code = sense[0] & 0x7F;
        return sense_len >= 8 && code >= 0x70 && code <= 0x73;
    }
    std::string describe() const { return std::format("SCSI status 0x{:02x}", scsi_status); }
};

enum class Dir : UCHAR { Out = SCSI_IOCTL_DATA_OUT, In = SCSI_IOCTL_DATA_IN, None = SCSI_IOCTL_DATA_UNSPECIFIED };

// One CDB through IOCTL_SCSI_PASS_THROUGH_DIRECT. `data` is copied through a page-aligned
// buffer (adapters require their alignment). Needs a handle with read and write access.
Result<SptResult> scsi_pass_through(int fd, const std::string& path, std::span<const std::uint8_t> cdb, Dir dir,
                                    std::span<std::uint8_t> data, unsigned timeout_ms) {
    const auto h = reinterpret_cast<HANDLE>(_get_osfhandle(fd));
    if (h == INVALID_HANDLE_VALUE) return error("no handle for " + path);
    if (cdb.size() > 16) return error("CDB longer than 16 bytes");
    std::unique_ptr<std::uint8_t, decltype(&dw::aligned_free)> buf(
        data.empty() ? nullptr : static_cast<std::uint8_t*>(dw::aligned_alloc_bytes(4096, (data.size() + 4095) / 4096 * 4096)),
        &dw::aligned_free);
    if (!data.empty() && !buf) return error("cannot allocate a pass-through buffer");
    if (!data.empty()) std::memcpy(buf.get(), data.data(), data.size());

    SptdWithSense s{};
    s.sptd.Length = sizeof(SCSI_PASS_THROUGH_DIRECT);
    s.sptd.CdbLength = static_cast<UCHAR>(cdb.size());
    s.sptd.SenseInfoLength = sizeof s.sense;
    s.sptd.SenseInfoOffset = offsetof(SptdWithSense, sense);
    s.sptd.DataIn = data.empty() ? SCSI_IOCTL_DATA_UNSPECIFIED : static_cast<UCHAR>(dir);
    s.sptd.DataTransferLength = static_cast<ULONG>(data.size());
    s.sptd.DataBuffer = buf.get();
    s.sptd.TimeOutValue = std::max<ULONG>(1, (timeout_ms + 999) / 1000);
    std::memcpy(s.sptd.Cdb, cdb.data(), cdb.size());

    DWORD got = 0;
    if (!DeviceIoControl(h, IOCTL_SCSI_PASS_THROUGH_DIRECT, &s, sizeof s, &s, sizeof s, &got, nullptr)) {
        const DWORD e = GetLastError();
        std::string hint;
        if (e == ERROR_ACCESS_DENIED) hint = " (not an Administrator, or the disk was opened without write access)";
        else if (e == ERROR_INVALID_FUNCTION || e == ERROR_NOT_SUPPORTED || e == ERROR_INVALID_PARAMETER)
            hint = " (the disk's driver does not accept SCSI pass-through)";
        return error("IOCTL_SCSI_PASS_THROUGH_DIRECT on " + path + ": " + win_message(e) + hint);
    }
    SptResult r;
    r.scsi_status = s.sptd.ScsiStatus;
    r.sense_len = std::min<std::size_t>(s.sptd.SenseInfoLength, sizeof s.sense);
    std::memcpy(r.sense.data(), s.sense, sizeof s.sense);
    if (!r.sense_len && (r.sense[0] & 0x7F) >= 0x70) r.sense_len = sizeof s.sense;  // drivers that leave the length
    if (dir == Dir::In && !data.empty()) std::memcpy(data.data(), buf.get(), data.size());
    return r;
}

// One ATA command as ATA PASS-THROUGH(16): the counterpart of sg_ata() in
// device/passthrough_linux.cpp, decoding the same sense data.
Result<AtaRegisters> spt_ata(int fd, const std::string& path, const AtaTaskfile& tf, std::span<std::uint8_t> data_in,
                             unsigned timeout_ms) {
    const bool pio_in = tf.transfer == AtaTaskfile::Transfer::PioIn;
    const bool pio_out = tf.transfer == AtaTaskfile::Transfer::PioOut;
    if (pio_in && data_in.size() != static_cast<std::size_t>(tf.count) * 512)
        return error("data buffer must be count x 512 bytes");
    std::vector<std::uint8_t> out = tf.payload;
    if (pio_out && out.size() != static_cast<std::size_t>(tf.count) * 512)
        return error("PIO-out payload must be count x 512 bytes");

    const auto cdb = ata_pass_through_16(tf);
    auto r = pio_in    ? scsi_pass_through(fd, path, cdb, Dir::In, data_in, timeout_ms)
             : pio_out ? scsi_pass_through(fd, path, cdb, Dir::Out, out, timeout_ms)
                       : scsi_pass_through(fd, path, cdb, Dir::None, {}, timeout_ms);
    if (!r) return r.error();

    AtaRegisters regs;
    if (r->has_sense()) {
        auto parsed = parse_ata_sense(std::span<const std::uint8_t>(r->sense.data(), r->sense_len));
        if (!parsed) return error("ATA PASS-THROUGH: " + parsed.error().message + " (" + r->describe() + ")");
        regs = *parsed;
    } else if (r->scsi_status != 0) {
        return error("ATA PASS-THROUGH failed without sense data: " + r->describe());
    }
    if (regs.status & 0x01)  // ERR
        return error(std::format("device aborted ATA command 0x{:02x} (error register 0x{:02x}{})", tf.command,
                                 regs.error, (regs.error & 0x04) ? ", ABRT" : ""));
    return regs;
}

}  // namespace

// ---------------------------------------------------------------- dw::win

namespace win {

Result<void> disk_exists(unsigned number) {
    Handle h = open_query(number);
    if (!h.ok()) {
        const DWORD e = GetLastError();
        if (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND)
            return error(std::format("no disk {} (Get-Disk in PowerShell lists the disk numbers)", number));
        return error(std::format("cannot open disk {}: {}", number, win_message(e)));
    }
    STORAGE_DEVICE_NUMBER sdn{};
    if (!device_number_of(h.get(), sdn) || sdn.DeviceType != FILE_DEVICE_DISK || sdn.DeviceNumber != number ||
        sdn.PartitionNumber != 0)
        return error(std::format("{} is not a whole disk", winstorage::disk_path(number)));
    return ok();
}

Result<DiskQuery> query_disk(unsigned number) {
    if (auto e = disk_exists(number); !e) return e.error();
    Handle h = open_query(number);
    if (!h.ok()) return error(std::format("cannot open disk {}: {}", number, win_message(GetLastError())));
    auto raw = device_descriptor(h.get());
    if (!raw) return raw.error();
    auto desc = winstorage::decode_descriptor(*raw);
    if (!desc) return desc.error();
    auto g = geometry_of(h.get());
    if (!g) return g.error();

    DiskQuery q;
    q.inputs.descriptor = std::move(desc).value();
    q.inputs.disk_bytes = g->bytes;
    q.inputs.logical_sector = g->logical;
    q.physical_sector = g->physical;
    DEVICE_SEEK_PENALTY_DESCRIPTOR seek{};
    if (query_property(h.get(), StorageDeviceSeekPenaltyProperty, seek)) q.inputs.seek_penalty = seek.IncursSeekPenalty != 0;
    DEVICE_TRIM_DESCRIPTOR trim{};
    if (query_property(h.get(), StorageDeviceTrimProperty, trim)) q.inputs.trim = trim.TrimEnabled != 0;
    return q;
}

std::vector<std::string> disk_usage(unsigned number) {
    std::vector<std::string> out;
    char windir[MAX_PATH] = {};
    const std::string system_drive = GetWindowsDirectoryA(windir, MAX_PATH) >= 3 ? std::string(windir, 3) : "";

    wchar_t name[MAX_PATH];
    HANDLE f = FindFirstVolumeW(name, MAX_PATH);
    if (f == INVALID_HANDLE_VALUE) {
        out.push_back("the volumes on this system could not be listed: " + win_message(GetLastError()));
        return out;
    }
    do {
        const std::wstring volume = name;
        bool here = false;
        for (unsigned d : volume_disks(volume)) here |= d == number;
        if (!here) continue;
        const auto mounts = mount_points(volume);
        std::string where;
        for (const auto& m : mounts) where += (where.empty() ? "" : ", ") + m;
        bool system = false;
        for (const auto& m : mounts) system |= !system_drive.empty() && _stricmp(m.c_str(), system_drive.c_str()) == 0;
        if (system) out.push_back("it holds the running Windows installation (" + system_drive + ")");
        else if (!where.empty()) out.push_back("volume mounted at " + where);
        else out.push_back("volume " + narrow(volume) + " (no drive letter, e.g. EFI or recovery partition)");
    } while (FindNextVolumeW(f, name, MAX_PATH));
    FindVolumeClose(f);

    // Partitions owned by another storage layer. Reading the layout needs read access, i.e. an
    // Administrator; without it nothing can be written either, and the writable open re-runs
    // this check with the rights it needs.
    const std::string path = winstorage::disk_path(number);
    Handle h(CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr));
    if (h.ok()) {
        std::vector<std::uint8_t> buf(sizeof(DRIVE_LAYOUT_INFORMATION_EX) + 256 * sizeof(PARTITION_INFORMATION_EX), 0);
        DWORD got = 0;
        if (DeviceIoControl(h.get(), IOCTL_DISK_GET_DRIVE_LAYOUT_EX, nullptr, 0, buf.data(), static_cast<DWORD>(buf.size()),
                            &got, nullptr)) {
            const auto* layout = reinterpret_cast<const DRIVE_LAYOUT_INFORMATION_EX*>(buf.data());
            for (DWORD i = 0; i < layout->PartitionCount && i < 256; ++i) {
                const PARTITION_INFORMATION_EX& pi = layout->PartitionEntry[i];
                std::optional<std::string> owner;
                if (pi.PartitionStyle == PARTITION_STYLE_GPT) {
                    std::array<std::uint8_t, 16> g{};
                    std::memcpy(g.data(), &pi.Gpt.PartitionType, 16);
                    owner = winstorage::owning_layer_gpt(g);
                } else if (pi.PartitionStyle == PARTITION_STYLE_MBR) {
                    owner = winstorage::owning_layer_mbr(pi.Mbr.PartitionType);
                }
                if (owner) {
                    out.push_back(*owner);
                    break;
                }
            }
        } else {
            out.push_back("its partition table could not be read: " + win_message(GetLastError()));
        }
    }
    return out;
}

std::vector<unsigned> disk_numbers() {
    std::vector<unsigned> out;
    for (unsigned n = 0; n < 128; ++n)
        if (disk_exists(n)) out.push_back(n);
    return out;
}

bool disk_number(int fd, unsigned& number) {
    const auto h = reinterpret_cast<HANDLE>(_get_osfhandle(fd));
    STORAGE_DEVICE_NUMBER sdn{};
    if (h == INVALID_HANDLE_VALUE || !device_number_of(h, sdn) || sdn.DeviceType != FILE_DEVICE_DISK ||
        sdn.PartitionNumber != 0)
        return false;
    number = sdn.DeviceNumber;
    return true;
}

std::string offline_hint(unsigned number) {
    return std::format("for a pool member or dynamic disk, remove it from the pool / convert it to basic first; "
                       "otherwise take the disk offline first (PowerShell as Administrator: Set-Disk -Number {0} -IsOffline "
                       "$true; afterwards Set-Disk -Number {0} -IsOffline $false), or delete its partitions in Disk "
                       "Management",
                       number);
}

}  // namespace win

// ---------------------------------------------------------------- block device

namespace detail {

namespace {
class WindowsDiskDevice final : public FdBlockDevice {
public:
    WindowsDiskDevice(int fd, std::string path, DeviceGeometry g, OpenOptions opts)
        : FdBlockDevice(fd, std::move(path), BackendKind::PhysicalBlock, g, opts) {}
};
}  // namespace

Result<std::unique_ptr<IBlockDevice>> make_block_device(int fd, const TargetAssessment& t, OpenOptions opts) {
    const auto h = reinterpret_cast<HANDLE>(_get_osfhandle(fd));
    auto g = geometry_of(h);
    if (!g) {
        ::close(fd);
        return g.error();
    }
    DeviceGeometry geo;
    geo.size_bytes = g->bytes;
    geo.logical_sector_size = g->logical;
    geo.physical_sector_size = g->physical ? g->physical : g->logical;
    // The handle is unbuffered (sector-aligned I/O only), so the device says so.
    opts.direct_io = true;
    return std::unique_ptr<IBlockDevice>(std::make_unique<WindowsDiskDevice>(fd, t.canonical_path, geo, opts));
}

}  // namespace detail

// ---------------------------------------------------------------- detection

Result<PhysicalDetection> detect_physical(const TargetAssessment& t) {
    if (t.kind != BackendKind::PhysicalBlock) return error(t.canonical_path + " is not a physical disk");
    auto q = win::query_disk(static_cast<unsigned>(t.rdev));
    if (!q) return q.error();
    const auto bus = q->inputs.descriptor.bus;
    if (bus == winstorage::Bus::Spaces)
        return error(t.canonical_path + " is a Storage Spaces virtual disk: wipe the physical disks of the pool "
                                        "instead (after removing them from the pool)");

    PhysicalDetection det;
    det.identity = winstorage::build_identity(q->inputs);
    det.geometry.size_bytes = q->inputs.disk_bytes;
    det.geometry.logical_sector_size = q->inputs.logical_sector;
    det.geometry.physical_sector_size = q->physical_sector ? q->physical_sector : q->inputs.logical_sector;
    det.source = IdentitySource::WindowsStorage;
    det.origin = "Windows storage descriptor and drive geometry (" + winstorage::to_string(bus) + " bus)";

    auto opened = open_target(t.canonical_path, OpenOptions{.writable = false, .direct_io = true});
    if (opened) {
        det.target = std::move(opened).value();
    } else if (opened.error().sys_errno == EACCES) {
        det.identity.probe_notes.push_back("disk not opened for reading (not running as Administrator)");
        return det;
    } else {
        return opened.error();
    }

    // ATA drives (directly attached, or behind a SAT bridge): the full identity, from the drive.
    using winstorage::Bus;
    const bool ata_candidate = bus != Bus::Nvme && bus != Bus::Sd && bus != Bus::Mmc && bus != Bus::Virtual &&
                               bus != Bus::FileBackedVirtual && bus != Bus::Ufs && bus != Bus::Scm;
    if (ata_candidate) {
        AtaIdentityProvider ata;
        auto id = ata.identify(*det.target->device);
        if (id) {
            det.identity = std::move(id).value();
            det.source = IdentitySource::AtaIdentify;
            det.origin = "ATA IDENTIFY DEVICE (SCSI pass-through, " + winstorage::to_string(bus) + " bus)";
        } else {
            det.identity.probe_notes.insert(det.identity.probe_notes.begin(),
                                            "ATA IDENTIFY through SCSI pass-through failed: " + id.error().message);
        }
    }
    return det;
}

// ---------------------------------------------------------------- /sys (none on Windows)

namespace sysfs {

Result<std::string> read_file(const std::string& path) { return error("no such file: " + path); }
Result<std::string> block_name(dev_t) { return error("no /sys on Windows"); }
std::string block_dir(const std::string& name) { return name; }
bool is_partition(const std::string&) { return false; }
std::vector<std::string> partitions(const std::string&) { return {}; }
std::vector<std::string> holders(const std::string&) { return {}; }
std::vector<std::string> mount_points(dev_t) { return {}; }
Result<void> rescan_disk(const std::string& name) {
    const auto n = winstorage::parse_disk_path("\\\\.\\" + name);
    if (!n) return error("not a disk: " + name);
    const std::string path = winstorage::disk_path(*n);
    Handle h(CreateFileA(path.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                         OPEN_EXISTING, 0, nullptr));
    if (!h.ok()) return error("open " + path + ": " + win_message(GetLastError()));
    DWORD got = 0;
    if (!DeviceIoControl(h.get(), IOCTL_DISK_UPDATE_PROPERTIES, nullptr, 0, nullptr, 0, &got, nullptr))
        return error("IOCTL_DISK_UPDATE_PROPERTIES: " + win_message(GetLastError()));
    return ok();
}
std::vector<std::string> swap_areas(dev_t, const std::string&) { return {}; }
std::optional<std::string> loop_backing_file(const std::string&) { return std::nullopt; }
std::vector<std::string> loops_backed_by(dev_t, ino_t) { return {}; }
Result<std::string> device_serial(const std::string& name) {
    const auto n = winstorage::parse_disk_path("\\\\.\\" + name);
    if (!n) return error("not a disk: " + name);
    auto q = win::query_disk(*n);
    if (!q) return q.error();
    return q->inputs.descriptor.serial;
}

}  // namespace sysfs

// ---------------------------------------------------------------- drive commands

// The read-only whitelist is checked first, exactly as on Linux.
Result<AtaRegisters> ReadOnlyPassthrough::ata(const AtaTaskfile& tf, std::span<std::uint8_t> data_in) {
    if (auto r = allow_ata(tf); !r) return r.error();
    log::debug("read-only ATA PASS-THROUGH 0x{:02x} feat 0x{:04x} on {}", tf.command, tf.features, device_.path());
    return spt_ata(device_.native_handle(), device_.path(), tf, data_in, kQueryTimeoutMs);
}

Result<void> ReadOnlyPassthrough::security_in(std::uint8_t protocol, std::uint16_t sp, std::span<std::uint8_t> out) {
    if (auto r = allow_security_in(protocol, sp); !r) return r;
    if (out.size() % 512 != 0) return error("security-in buffer must be a multiple of 512 bytes");
    std::array<std::uint8_t, 12> cdb{};
    cdb[0] = 0xA2;  // SECURITY PROTOCOL IN
    cdb[1] = protocol;
    cdb[2] = static_cast<std::uint8_t>(sp >> 8);
    cdb[3] = static_cast<std::uint8_t>(sp);
    const auto len = static_cast<std::uint32_t>(out.size());
    cdb[6] = static_cast<std::uint8_t>(len >> 24);
    cdb[7] = static_cast<std::uint8_t>(len >> 16);
    cdb[8] = static_cast<std::uint8_t>(len >> 8);
    cdb[9] = static_cast<std::uint8_t>(len);
    auto r = scsi_pass_through(device_.native_handle(), device_.path(), cdb, Dir::In, out, kQueryTimeoutMs);
    if (!r) return r.error();
    if (r->scsi_status != 0) return error("SECURITY PROTOCOL IN not supported: " + r->describe());
    return ok();
}

Result<std::uint32_t> ReadOnlyPassthrough::nvme_admin(const NvmeAdminCmd& cmd, std::span<std::uint8_t>) {
    if (auto r = allow_nvme(cmd); !r) return r.error();
    return not_yet("NVMe admin commands");
}
Result<void> ReadOnlyPassthrough::mmc_ext_csd(std::span<std::uint8_t>) { return not_yet("eMMC commands"); }
Result<std::uint32_t> ReadOnlyPassthrough::nvme_namespace_id() { return not_yet("NVMe admin commands"); }

Result<AtaRegisters> DevicePassthrough::ata(const AtaTaskfile& tf, std::span<std::uint8_t> data_in, unsigned timeout_ms) {
    log::info("ATA PASS-THROUGH 0x{:02x} feat 0x{:04x} count {} on {} (timeout {} s)", tf.command, tf.features, tf.count,
              device_.path(), timeout_ms / 1000);
    return spt_ata(device_.native_handle(), device_.path(), tf, data_in, timeout_ms);
}
Result<std::uint32_t> DevicePassthrough::nvme_admin(const NvmeAdminCmd&, std::span<std::uint8_t>, unsigned) {
    return not_yet("NVMe admin commands");
}
Result<void> DevicePassthrough::block_ioctl(unsigned long, std::uint64_t, std::uint64_t) { return not_yet("discard"); }

}  // namespace dw
