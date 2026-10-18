#include "engine/overwrite_engine.hpp"

#include "core/portable.hpp"

#include <chrono>
#include <cstdlib>
#include <format>
#include <future>
#include <system_error>
#include <memory>

#include "core/log.hpp"

namespace dw {

namespace {

using Clock = std::chrono::steady_clock;

double since(Clock::time_point t0) { return std::chrono::duration<double>(Clock::now() - t0).count(); }

struct FreeDeleter {
    void operator()(std::byte* p) const { dw::aligned_free(p); }
};

}  // namespace

std::size_t OverwriteEngine::io_alignment(const IBlockDevice& device) {
    const std::size_t sector = device.geometry().logical_sector_size;
    return device.direct_io() ? std::max<std::size_t>(sector, 4096) : sector;
}

Result<OverwriteOutcome> OverwriteEngine::run(const OverwriteSpec& spec, IBlockDevice& device,
                                              const OverwriteContext& ctx) {
    const std::uint64_t ss = device.geometry().logical_sector_size;
    const std::uint64_t dev_sectors = device.geometry().sector_count();
    if (spec.sector_count == 0) return error("overwrite pass covers no sectors");
    if (spec.first_sector > dev_sectors || spec.sector_count > dev_sectors - spec.first_sector)
        return error(std::format("overwrite range [{}, +{}) exceeds the device's {} sectors", spec.first_sector,
                                 spec.sector_count, dev_sectors));
    if (ctx.resume_sector > spec.sector_count)
        return error(std::format("resume point {} is past the end of the {}-sector pass", ctx.resume_sector,
                                 spec.sector_count));
    if (!device.writable()) return error("device " + device.path() + " is not open for writing");

    const std::size_t align = io_alignment(device);
    const std::size_t buf_bytes = cfg_.buffer_bytes / align * align;
    if (buf_bytes == 0)
        return error(std::format("buffer size {} is smaller than the required I/O alignment {}", cfg_.buffer_bytes,
                                 align));
    // Two buffers: the next chunk is generated on a helper thread while this one is written,
    // so a pass runs at min(generator, device) speed instead of the harmonic sum of both.
    std::unique_ptr<std::byte, FreeDeleter> bufs[2];
    for (auto& b : bufs) {
        b.reset(static_cast<std::byte*>(dw::aligned_alloc_bytes(align, buf_bytes)));
        if (!b) return error(std::format("cannot allocate a {}-byte aligned I/O buffer", buf_bytes));
    }

    const std::uint64_t base = spec.first_sector * ss;
    const std::uint64_t total = spec.sector_count * ss;
    const std::uint64_t resumed = ctx.resume_sector * ss;
    std::uint64_t done = resumed;     // handed to write_at
    std::uint64_t durable = resumed;  // flushed

    const PatternGenerator gen(spec.pattern, key_);
    OverwriteOutcome out;
    const auto t0 = Clock::now();
    auto last_sync = t0;
    auto last_progress = t0;

    if (resumed)
        log::info("resuming pass at sector {} of {} ({:.1f}% already durable)", spec.first_sector + ctx.resume_sector,
                  spec.first_sector + spec.sector_count, 100.0 * double(resumed) / double(total));
    log::debug("overwrite: {} bytes from byte {} with {}, {}-byte chunks, {} I/O", total - resumed, base + resumed,
               spec.pattern.describe(), buf_bytes, device.direct_io() ? "O_DIRECT" : "buffered");

    auto report = [&](bool final) {
        if (!ctx.on_progress) return;
        const double secs = since(t0);
        ctx.on_progress(OverwriteProgress{total, done, durable, resumed, secs,
                                          secs > 0 ? double(done - resumed) / secs : 0, final});
    };

    // flush -> evict -> checkpoint. The checkpoint only ever names data that fdatasync
    // confirmed, so the journal can lag the medium but never overstate it.
    auto checkpoint = [&]() -> Result<void> {
        if (done == durable) return ok();
        if (auto r = device.flush(); !r)
            return error(std::format("flush failed; sectors [{}, {}) may not have reached the medium "
                                     "(not retried: after a failed fdatasync the kernel may already have "
                                     "discarded the dirty pages): {}",
                                     (base + durable) / ss, (base + done) / ss, r.error().describe()));
        if (auto r = device.drop_cache(base + durable, done - durable); !r)
            log::debug("drop_cache: {}", r.error().describe());  // performance only, not correctness
        durable = done;
        ++out.flushes;
        last_sync = Clock::now();
        if (ctx.on_durable) ctx.on_durable(durable / ss);
        return ok();
    };

    auto finish = [&](bool aborted) {
        out.aborted = aborted;
        out.sectors_durable = durable / ss;
        out.bytes_written_this_run = done - resumed;
        out.seconds = since(t0);
        report(true);
        return out;
    };

    auto chunk_at = [&](std::uint64_t pos, int which) {
        const auto n = static_cast<std::size_t>(std::min<std::uint64_t>(buf_bytes, total - pos));
        return std::span<std::byte>(bufs[which].get(), n);
    };
    if (ctx.cancel && ctx.cancel->requested()) return finish(true);
    int cur = 0;
    gen.fill(base + done, chunk_at(done, cur));
    // Declared after bufs so it is destroyed (joined) before they are freed on every return path.
    std::future<void> next;

    while (done < total) {
        const std::span<std::byte> chunk = chunk_at(done, cur);
        const std::uint64_t after = done + chunk.size();
        if (after < total) {
            const std::span<std::byte> ahead = chunk_at(after, 1 - cur);
            try {
                next = std::async(std::launch::async, [&gen, ahead, off = base + after] { gen.fill(off, ahead); });
            } catch (const std::system_error&) {  // no thread available: generate inline instead
                gen.fill(base + after, ahead);
            }
        }

        if (auto r = device.write_at(base + done, chunk); !r) {
            const std::string where = std::format("write failed at sector {} ({:.1f}% of pass)", (base + done) / ss,
                                                  100.0 * double(done) / double(total));
            // Save what did land, so a resume after fixing the cause (e.g. ENOSPC under a
            // sparse image) doesn't redo it. If this flush fails too, nothing new is claimed.
            if (auto c = checkpoint(); !c) log::warn("{}", c.error().message);
            std::string hint;
            if (r.error().sys_errno == ENOSPC)
                hint = " (the image is sparse and its filesystem is full: the wipe must allocate every block)";
            return error(where + ": " + r.error().describe() + hint);
        }
        done = after;

        if (done - durable >= cfg_.sync_interval_bytes || since(last_sync) >= cfg_.sync_interval_seconds)
            if (auto r = checkpoint(); !r) return r.error();
        if (since(last_progress) >= cfg_.progress_interval_seconds) {
            report(false);
            last_progress = Clock::now();
        }
        if (next.valid()) next.get();
        cur = 1 - cur;

        if (ctx.cancel && ctx.cancel->requested() && done < total) {
            if (auto r = checkpoint(); !r) return r.error();
            log::warn("pass interrupted at sector {} ({:.1f}%); progress up to there is saved",
                      (base + durable) / ss, 100.0 * double(durable) / double(total));
            return finish(true);
        }
    }
    if (auto r = checkpoint(); !r) return r.error();
    return finish(false);
}

}  // namespace dw
