#pragma once
// The host overwrite engine: the one path in this build that really destroys data.
//
// Loop, per pass:
//      pwrite chunk k at its offset  ||  generate chunk k+1 on a helper thread (double buffer;
//                                        the pattern is position-derived, see pattern.hpp)
//      every sync_interval: fdatasync -> drop cached pages -> checkpoint "durable up to X"
//      between chunks: poll the cancel token
//
// ---- Getting writes onto the medium: buffered + fdatasync vs O_DIRECT ----------------------
//
// Default (buffered): pwrite() copies into the page cache and returns; the kernel writes back
// later. Alone that is wrong for a wipe in three ways:
//   1. Progress lies: the first GBs "complete" at memory speed, then the process stalls.
//   2. Durability is unknown: a crash loses whatever was still dirty, so "done" means nothing.
//   3. Errors are deferred: a failed writeback surfaces only at the next fsync/fdatasync, and
//      Linux then marks those pages clean anyway ("fsyncgate", 2018): a later fsync succeeds
//      even though the data never arrived. An fsync error must therefore be treated as final
//      for everything written since the previous successful one: we never retry-and-trust it.
// So the engine calls fdatasync every `sync_interval_bytes` / `sync_interval_seconds`. That
// bounds dirty memory, keeps progress honest (to within one interval), surfaces I/O errors
// close to where they happened, and on a block device makes the kernel send FLUSH CACHE so
// the drive's volatile write cache is emptied too. Only after it succeeds is the checkpoint
// advanced. Then POSIX_FADV_DONTNEED evicts the now-clean pages: the wipe does not evict
// everything else from RAM, and a later read-back comes from the medium, not from memory.
//
// --direct (O_DIRECT): DMA straight from our buffer to the device, no page cache.
//   + no double copy, no cache pollution, no deferred errors: pwrite fails where the write fails
//   + progress is accurate per chunk
//   - buffer address, offset and length must be aligned to the logical sector size (we align
//     to max(sector, 4096)); some filesystems (tmpfs) refuse O_DIRECT outright
//   - each pwrite waits for the device, so throughput depends on large chunks (queue depth 1;
//     io_uring or AIO would restore concurrency, deliberately not used to keep the core simple)
//   - it still does not empty the drive's own write cache: fdatasync at checkpoints is still
//     required for that.
//   - on a loop device, O_DIRECT on /dev/loopN only bypasses the loop node's cache; the loop
//     driver writes the backing file through its page cache unless the loop was attached
//     with --direct-io=on.
//
// ---- Interruption --------------------------------------------------------------------------
// A cancel request (SIGINT/SIGTERM via core/cancel.hpp) is honoured at the next chunk
// boundary: flush, checkpoint, return {aborted}. The checkpoint callback persists progress
// (engine/run_journal.hpp). Because the pattern depends only on (key, stream, offset), a
// resumed pass restarts at the last durable checkpoint and rewrites the gap with exactly the
// bytes that were there: the result is indistinguishable from an uninterrupted pass.

#include <cstddef>
#include <cstdint>
#include <functional>

#include "core/cancel.hpp"
#include "core/result.hpp"
#include "device/block_device.hpp"
#include "engine/pattern.hpp"
#include "engine/wipe_plan.hpp"

namespace dw {

struct OverwriteProgress {
    std::uint64_t bytes_total = 0;    // whole pass
    std::uint64_t bytes_written = 0;  // handed to the device so far (includes a resumed prefix)
    std::uint64_t bytes_durable = 0;  // flushed and checkpointed
    std::uint64_t bytes_resumed = 0;  // prefix completed by an earlier run
    double seconds = 0;               // this run
    double bytes_per_second = 0;      // this run's write throughput
    bool final = false;
};

struct OverwriteContext {
    std::uint64_t resume_sector = 0;  // sectors of this pass already durable (from the journal)
    const CancelToken* cancel = nullptr;
    // Called after each successful flush with the pass's durable sector count.
    std::function<void(std::uint64_t sectors_durable)> on_durable;
    std::function<void(const OverwriteProgress&)> on_progress;
};

struct OverwriteOutcome {
    bool aborted = false;
    std::uint64_t sectors_durable = 0;  // of the whole pass, including a resumed prefix
    std::uint64_t bytes_written_this_run = 0;
    unsigned flushes = 0;
    double seconds = 0;
};

class IOverwriteRunner {
public:
    virtual ~IOverwriteRunner() = default;
    virtual Result<OverwriteOutcome> run(const OverwriteSpec& spec, IBlockDevice& device,
                                         const OverwriteContext& ctx) = 0;
};

struct OverwriteConfig {
    std::size_t buffer_bytes = 4u << 20;               // one chunk; rounded down to the I/O alignment
    std::uint64_t sync_interval_bytes = 256ull << 20;  // flush + checkpoint at least this often...
    double sync_interval_seconds = 10;                 // ...and at least this often
    double progress_interval_seconds = 0.25;
};

class OverwriteEngine final : public IOverwriteRunner {
public:
    OverwriteEngine(const PatternKey& key, OverwriteConfig config) : key_(key), cfg_(config) {}

    // Alignment every chunk respects on `device`: the logical sector size, raised to 4096 for
    // O_DIRECT so the buffer is also page-aligned.
    static std::size_t io_alignment(const IBlockDevice& device);

    Result<OverwriteOutcome> run(const OverwriteSpec& spec, IBlockDevice& device,
                                 const OverwriteContext& ctx) override;

    const PatternKey& key() const { return key_; }
    const OverwriteConfig& config() const { return cfg_; }

private:
    PatternKey key_;
    OverwriteConfig cfg_;
};

}  // namespace dw
