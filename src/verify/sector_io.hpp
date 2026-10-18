#pragma once
// Sector-granular reads and writes on top of IBlockDevice for the verifier and the
// fingerprint capture. Honours O_DIRECT alignment by going through an aligned bounce buffer
// that covers the aligned window around each request; with buffered I/O it evicts the range
// from the page cache before reading, so data comes from the medium.

#include <algorithm>
#include <cstdlib>
#include <functional>
#include <memory>
#include <span>
#include <utility>

#include "core/portable.hpp"
#include "core/result.hpp"
#include "device/block_device.hpp"

namespace dw {

inline constexpr std::uint64_t kSectorIoChunkBytes = 1 << 20;

struct SectorIoFree {
    void operator()(std::byte* p) const { dw::aligned_free(p); }
};

class SectorIo {
public:
    explicit SectorIo(IBlockDevice& d)
        : d_(d),
          ss_(d.geometry().logical_sector_size),
          align_(d.direct_io() ? std::max<std::uint64_t>(ss_, 4096) : ss_),
          buf_(static_cast<std::byte*>(dw::aligned_alloc_bytes(4096, kSectorIoChunkBytes + 2 * 4096))) {}

    bool ok() const { return buf_ != nullptr; }
    std::uint64_t sector_size() const { return ss_; }
    // Largest request read()/write() accept, in sectors.
    std::uint64_t max_sectors() const { return kSectorIoChunkBytes / ss_; }

    // Reads sectors [first, first+n) and returns a view of them.
    Result<std::span<const std::byte>> read(std::uint64_t first, std::uint64_t n) {
        auto [start, len] = window(first, n);
        if (!d_.direct_io()) (void)d_.drop_cache(start, len);
        if (auto r = d_.read_at(start, std::span(buf_.get(), len)); !r) return r.error();
        return std::span<const std::byte>(buf_.get() + (first * ss_ - start), n * ss_);
    }

    // Writes `fill(offset, span)` over sectors [first, first+n). Read-modify-write when the
    // aligned window is wider than the request, so neighbouring sectors keep their content.
    Result<void> write(std::uint64_t first, std::uint64_t n,
                       const std::function<void(std::uint64_t, std::span<std::byte>)>& fill) {
        auto [start, len] = window(first, n);
        const std::uint64_t off = first * ss_;
        if (start != off || len != n * ss_)
            if (auto r = d_.read_at(start, std::span(buf_.get(), len)); !r) return r.error();
        fill(off, std::span(buf_.get() + (off - start), n * ss_));
        return d_.write_at(start, std::span<const std::byte>(buf_.get(), len));
    }

private:
    std::pair<std::uint64_t, std::uint64_t> window(std::uint64_t first, std::uint64_t n) const {
        const std::uint64_t start = first * ss_ / align_ * align_;
        const std::uint64_t end = std::min((((first + n) * ss_ + align_ - 1) / align_) * align_, d_.geometry().size_bytes);
        return {start, end - start};
    }

    IBlockDevice& d_;
    std::uint64_t ss_, align_;
    std::unique_ptr<std::byte, SectorIoFree> buf_;
};

}  // namespace dw
