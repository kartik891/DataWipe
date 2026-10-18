#pragma once
// IBlockDevice: the only surface the sanitization engine uses to touch storage.
//
// Instances are created exclusively by open_target() (device_factory.hpp), which runs the
// safety guard first. The concrete classes have no public way to be constructed from a path.

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

#include "core/result.hpp"
#include "device/types.hpp"

namespace dw {

struct OpenOptions {
    bool writable = false;
    // O_DIRECT bypasses the page cache. Requires offset, length and buffer address to be
    // aligned to the logical sector size. Tradeoffs: engine/overwrite_engine.hpp.
    bool direct_io = false;
};

class IBlockDevice {
public:
    virtual ~IBlockDevice() = default;

    virtual const std::string& path() const = 0;
    virtual BackendKind kind() const = 0;
    virtual const DeviceGeometry& geometry() const = 0;
    virtual bool writable() const = 0;
    virtual bool direct_io() const = 0;

    // Full-length positional I/O: loops over short transfers and EINTR, fails on EOF.
    virtual Result<void> read_at(std::uint64_t offset, std::span<std::byte> buf) = 0;
    virtual Result<void> write_at(std::uint64_t offset, std::span<const std::byte> buf) = 0;

    // Durability barrier: data written so far is on the backing store when this returns.
    virtual Result<void> flush() = 0;

    // Evict [offset, offset+len) from the page cache once it has been flushed, so a later
    // read-back is served by the medium rather than by memory holding what we just wrote.
    virtual Result<void> drop_cache(std::uint64_t /*offset*/, std::uint64_t /*len*/) { return ok(); }

    // Raw fd for device-specific ioctls (HDIO_GET_IDENTITY, and later BLKSECDISCARD / NVMe
    // passthrough). Never used for plain data I/O, which must go through read_at/write_at.
    virtual int native_handle() const = 0;
};

// Shared implementation over a POSIX file descriptor. Image files and loop devices differ
// only in how they are opened and how geometry is discovered.
class FdBlockDevice : public IBlockDevice {
public:
    ~FdBlockDevice() override;
    FdBlockDevice(const FdBlockDevice&) = delete;
    FdBlockDevice& operator=(const FdBlockDevice&) = delete;

    const std::string& path() const override { return path_; }
    BackendKind kind() const override { return kind_; }
    const DeviceGeometry& geometry() const override { return geometry_; }
    bool writable() const override { return writable_; }
    bool direct_io() const override { return direct_; }

    Result<void> read_at(std::uint64_t offset, std::span<std::byte> buf) override;
    Result<void> write_at(std::uint64_t offset, std::span<const std::byte> buf) override;
    Result<void> flush() override;
    Result<void> drop_cache(std::uint64_t offset, std::uint64_t len) override;
    int native_handle() const override { return fd_; }

protected:
    FdBlockDevice(int fd, std::string path, BackendKind kind, DeviceGeometry geometry, OpenOptions opts);

private:
    Result<void> check_range(std::uint64_t offset, std::size_t len) const;

    int fd_;
    std::string path_;
    BackendKind kind_;
    DeviceGeometry geometry_;
    bool writable_;
    bool direct_;
};

}  // namespace dw
