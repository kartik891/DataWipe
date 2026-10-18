// Block-device backend (loop devices, and physical devices once a PhysicalOverride exists).
//
// Geometry comes from the kernel's block layer ioctls, the same calls any real disk answers:
//   BLKGETSIZE64  total bytes (u64)          BLKSSZGET  logical sector size (int)
//   BLKPBSZGET    physical sector size (uint)
// For a loop device the kernel derives these from the backing file (and lo_offset/lo_sizelimit),
// which LOOP_GET_STATUS64 reports and we log for traceability.

#include <linux/fs.h>
#include <linux/loop.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <cstring>

#include "core/log.hpp"
#include "device/backends.hpp"

namespace dw::detail {

namespace {
class KernelBlockDevice final : public FdBlockDevice {
public:
    KernelBlockDevice(int fd, std::string path, BackendKind kind, DeviceGeometry g, OpenOptions opts)
        : FdBlockDevice(fd, std::move(path), kind, g, opts) {}
};

Result<DeviceGeometry> query_geometry(int fd, const std::string& path) {
    DeviceGeometry g;
    std::uint64_t bytes = 0;
    if (::ioctl(fd, BLKGETSIZE64, &bytes) != 0) return sys_error("ioctl(BLKGETSIZE64) " + path);
    int lss = 0;
    if (::ioctl(fd, BLKSSZGET, &lss) != 0) return sys_error("ioctl(BLKSSZGET) " + path);
    unsigned int pss = 0;
    if (::ioctl(fd, BLKPBSZGET, &pss) != 0) return sys_error("ioctl(BLKPBSZGET) " + path);
    if (lss <= 0 || pss == 0) return error("kernel reported invalid sector size for " + path);
    g.size_bytes = bytes;
    g.logical_sector_size = static_cast<std::uint32_t>(lss);
    g.physical_sector_size = pss;
    return g;
}
}  // namespace

Result<std::unique_ptr<IBlockDevice>> make_block_device(int fd, const TargetAssessment& t, OpenOptions opts) {
    auto fail = [fd](Error e) -> Result<std::unique_ptr<IBlockDevice>> {
        ::close(fd);
        return e;
    };

    auto g = query_geometry(fd, t.canonical_path);
    if (!g) return fail(g.error());

    if (t.kind == BackendKind::LoopDevice) {
        loop_info64 info{};
        if (::ioctl(fd, LOOP_GET_STATUS64, &info) != 0)
            return fail(sys_error("ioctl(LOOP_GET_STATUS64) " + t.canonical_path));
        if (opts.writable && (info.lo_flags & LO_FLAGS_READ_ONLY))
            return fail(error("loop device " + t.canonical_path + " is attached read-only"));
        log::debug("loop {}: backing='{}' offset={} sizelimit={} flags=0x{:x}", t.canonical_path, t.backing_file,
                   info.lo_offset, info.lo_sizelimit, info.lo_flags);
    }

    return std::unique_ptr<IBlockDevice>(
        std::make_unique<KernelBlockDevice>(fd, t.canonical_path, t.kind, *g, opts));
}

}  // namespace dw::detail
