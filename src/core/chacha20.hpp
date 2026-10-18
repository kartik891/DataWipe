#pragma once
// ChaCha20 keystream (D. J. Bernstein, 2008; block function as in RFC 8439 Section 2.3).
//
// Used as the pseudo-random overwrite pattern. Why ChaCha20 and not a statistical PRNG
// (xoshiro, PCG, mt19937):
//
//  * Counter mode = random access. Block i of the stream is a pure function of (key, nonce, i),
//    so the bytes destined for any sector can be computed without generating everything before
//    it. The overwrite engine derives the counter from the absolute byte offset on the device,
//    which makes the pattern independent of buffer size and chunking, makes a resumed pass
//    byte-identical to an uninterrupted one, and lets the read-back verifier regenerate the
//    expected contents of a randomly sampled sector in O(1).
//  * Unpredictable without the key. A statistical PRNG's state can be recovered from a few
//    outputs (xoshiro256 from 4 words, mt19937 from 624). Nothing about sanitization strictly
//    requires secrecy of the pattern, but storage that compresses or deduplicates (some SSD
//    controllers, thin-provisioned or deduplicating backends behind a loop device) must not be
//    able to find structure in it and store it in fewer physical blocks than it claims to.
//  * It is a well-specified cipher with published test vectors, so correctness is checkable
//    (tests/test_overwrite.cpp) and the choice is defensible in review.
//  * Throughput: ~700 MiB/s on one core with the SSE2 lane-parallel code (x86-64 baseline, no
//    -march flags), several times HDD speed; the engine generates on a second thread, so it
//    only becomes the limit on fast SSDs.
//
// Layout: the original 64-bit counter / 64-bit nonce variant (state words 12-13 = counter,
// 14-15 = nonce), not RFC 8439's 32/96 split, whose 32-bit counter would wrap after 256 GiB,
// smaller than a modern disk.

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace dw::chacha20 {

using Key = std::array<std::uint8_t, 32>;
constexpr std::size_t kBlockBytes = 64;

// One raw block from a caller-built 16-word input state (for test vectors).
void block(const std::array<std::uint32_t, 16>& input, std::span<std::uint8_t, kBlockBytes> out);

// Keystream bytes [counter*64, counter*64 + out.size()) of stream (key, nonce).
// out.size() need not be a multiple of 64.
void keystream(const Key& key, std::uint64_t nonce, std::uint64_t counter, std::span<std::byte> out);

}  // namespace dw::chacha20
