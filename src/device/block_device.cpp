#include "device/block_device.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>

namespace dw {

FdBlockDevice::FdBlockDevice(int fd, std::string path, BackendKind kind, DeviceGeometry geometry,
                             OpenOptions opts)
    : fd_(fd), path_(std::move(path)), kind_(kind), geometry_(geometry), writable_(opts.writable),
      direct_(opts.direct_io) {}

FdBlockDevice::~FdBlockDevice() {
    if (fd_ >= 0) ::close(fd_);
}

Result<void> FdBlockDevice::check_range(std::uint64_t offset, std::size_t len) const {
    if (offset > geometry_.size_bytes || len > geometry_.size_bytes - offset)
        return error("I/O range [" + std::to_string(offset) + ", +" + std::to_string(len) +
                     ") exceeds device size " + std::to_string(geometry_.size_bytes));
    if (direct_) {
        const std::uint64_t align = geometry_.logical_sector_size;
        if (offset % align || len % align)
            return error("O_DIRECT I/O must be aligned to " + std::to_string(align) + " bytes");
    }
    return ok();
}

Result<void> FdBlockDevice::read_at(std::uint64_t offset, std::span<std::byte> buf) {
    if (auto r = check_range(offset, buf.size()); !r) return r;
    std::size_t done = 0;
    while (done < buf.size()) {
        ssize_t n = ::pread(fd_, buf.data() + done, buf.size() - done, static_cast<off_t>(offset + done));
        if (n < 0) {
            if (errno == EINTR) continue;
            return sys_error("pread " + path_ + " @" + std::to_string(offset + done));
        }
        if (n == 0) return error("unexpected EOF reading " + path_ + " @" + std::to_string(offset + done));
        done += static_cast<std::size_t>(n);
    }
    return ok();
}

Result<void> FdBlockDevice::write_at(std::uint64_t offset, std::span<const std::byte> buf) {
    if (!writable_) return error("device " + path_ + " was opened read-only");
    if (auto r = check_range(offset, buf.size()); !r) return r;
    std::size_t done = 0;
    while (done < buf.size()) {
        ssize_t n = ::pwrite(fd_, buf.data() + done, buf.size() - done, static_cast<off_t>(offset + done));
        if (n < 0) {
            if (errno == EINTR) continue;
            return sys_error("pwrite " + path_ + " @" + std::to_string(offset + done));
        }
        if (n == 0) return error("pwrite made no progress on " + path_ + " @" + std::to_string(offset + done));
        done += static_cast<std::size_t>(n);
    }
    return ok();
}

Result<void> FdBlockDevice::flush() {
    // fdatasync, not fsync: we only care that the data blocks are durable, not timestamps.
    // For a block device the kernel also issues a cache FLUSH to the drive's write cache.
    while (::fdatasync(fd_) != 0) {
        if (errno == EINTR) continue;
        return sys_error("fdatasync " + path_);
    }
    return ok();
}

Result<void> FdBlockDevice::drop_cache(std::uint64_t offset, std::uint64_t len) {
    if (direct_) return ok();  // O_DIRECT I/O never populated the cache
    // Only clean pages are dropped, which is why callers flush() first. For a loop device this
    // evicts the loop node's cache; the backing file's own cache is dropped by the loop driver
    // only when it runs in direct-I/O mode (LO_FLAGS_DIRECT_IO).
    const int rc = ::posix_fadvise(fd_, static_cast<off_t>(offset), static_cast<off_t>(len), POSIX_FADV_DONTNEED);
    if (rc != 0) return sys_error("posix_fadvise(DONTNEED) " + path_, rc);
    return ok();
}

}  // namespace dw
