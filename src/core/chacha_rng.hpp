#pragma once
// Deterministic random numbers from the ChaCha20 keystream.
//
// Used where a choice must be reproducible from a recorded seed (verification samples) and
// identical on every platform: std::uniform_int_distribution and friends are not specified
// bit-exactly across standard libraries.

#include <cmath>
#include <cstdint>
#include <span>

#include "core/chacha20.hpp"

namespace dw {

class ChaChaRng {
public:
    ChaChaRng(const chacha20::Key& key, std::uint64_t stream) : key_(key), stream_(stream) {}

    std::uint64_t next() {
        if (pos_ == kWords) {
            chacha20::keystream(key_, stream_, counter_, std::as_writable_bytes(std::span(buf_)));
            counter_ += sizeof buf_ / chacha20::kBlockBytes;
            pos_ = 0;
        }
        return buf_[pos_++];
    }

    // Uniform in [0, bound). Rejection keeps it unbiased: plain `next() % bound` favours small
    // values whenever bound does not divide 2^64.
    std::uint64_t below(std::uint64_t bound) {
        const std::uint64_t threshold = (0 - bound) % bound;  // 2^64 mod bound
        for (;;)
            if (const std::uint64_t r = next(); r >= threshold) return r % bound;
    }

    // Uniform in (0, 1): 53 random bits, never exactly 0 (safe for log()).
    double open01() { return (double(next() >> 11) + 0.5) * 0x1.0p-53; }

private:
    static constexpr std::size_t kWords = 32;
    chacha20::Key key_;
    std::uint64_t stream_;
    std::uint64_t counter_ = 0;
    std::uint64_t buf_[kWords]{};
    std::size_t pos_ = kWords;
};

}  // namespace dw
