// Image-file backend: a regular file standing in for a disk.
//
// Geometry comes from fstat(). A file has no sector size of its own, so we present the
// classic 512-byte logical sector that ATA devices report; the simulated identity profile
// then describes capacity in those 512-byte units, exactly as IDENTIFY words 100-103 would.

#include <sys/stat.h>
#include <unistd.h>

#include "device/backends.hpp"

namespace dw::detail {

namespace {
class ImageFileDevice final : public FdBlockDevice {
public:
    ImageFileDevice(int fd, std::string path, DeviceGeometry g, OpenOptions opts)
        : FdBlockDevice(fd, std::move(path), BackendKind::ImageFile, g, opts) {}
};
}  // namespace

Result<std::unique_ptr<IBlockDevice>> make_image_device(int fd, const TargetAssessment& t, OpenOptions opts) {
    struct stat st{};
    if (::fstat(fd, &st) != 0) {
        auto e = sys_error("fstat " + t.canonical_path);
        ::close(fd);
        return e;
    }
    DeviceGeometry g;
    g.size_bytes = static_cast<std::uint64_t>(st.st_size);
    g.logical_sector_size = 512;
    g.physical_sector_size = 512;
    return std::unique_ptr<IBlockDevice>(std::make_unique<ImageFileDevice>(fd, t.canonical_path, g, opts));
}

}  // namespace dw::detail
