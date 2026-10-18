#pragma once
// Cooperative cancellation for long-running passes.
//
// The overwrite engine polls the token between chunks, so an interrupt stops at a chunk
// boundary, flushes, and records durable progress in the journal instead of dying mid-write
// with an unknown amount of data still in the page cache.

#include <atomic>

namespace dw {

class CancelToken {
public:
    void request() { flag_.store(true, std::memory_order_relaxed); }
    bool requested() const { return flag_.load(std::memory_order_relaxed); }

private:
    std::atomic<bool> flag_{false};
    static_assert(std::atomic<bool>::is_always_lock_free, "must be async-signal-safe");
};

// SIGINT, SIGTERM and SIGHUP request cancellation on `token` (which must outlive the process's
// use of it). Handlers are one-shot (SA_RESETHAND): a second Ctrl-C gets the default action and
// kills the process immediately. That is still safe, because the journal only ever records
// progress that was already flushed, so it can lag reality but never overstate it.
void install_cancel_signal_handlers(CancelToken& token);
// Back to the default disposition, and forget the token (which is about to go out of scope in
// a process that keeps running, such as the guided mode's menu).
void clear_cancel_signal_handlers();

}  // namespace dw
