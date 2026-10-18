#pragma once
// Overwrite pattern generation.
//
// A pattern is a pure function  (PatternSpec, key, absolute device byte offset) -> bytes.
// Nothing depends on how the pass is chunked, where it started, or whether it was resumed, so
//   * a resumed pass writes exactly the bytes an uninterrupted pass would have written;
//   * the verifier can regenerate the expected contents of any single sector on its own.
//
// Kinds:
//   Prng    ChaCha20 keystream (see core/chacha20.hpp for why), nonce = PatternSpec::stream,
//           block counter = offset / 64. Different passes use different streams, so pass 2 is
//           never a copy of pass 1.
//   Fixed32 a 32-bit value repeated little-endian (0x00000000 models ATA SE normal / zeros).

#include <cstdint>
#include <span>
#include <string>

#include "core/chacha20.hpp"
#include "core/result.hpp"
#include "engine/wipe_plan.hpp"

namespace dw {

using PatternKey = chacha20::Key;

// 256 bits from the kernel CSPRNG (getrandom(2)). One key per wipe run, shared by its passes.
Result<PatternKey> random_pattern_key();
std::string to_hex(const PatternKey& key);
Result<PatternKey> pattern_key_from_hex(std::string_view hex);
// Short, non-reversible identifier for logs and certificates: first 16 hex of SHA-256(key).
std::string key_fingerprint(const PatternKey& key);

class PatternGenerator {
public:
    PatternGenerator(const PatternSpec& spec, const PatternKey& key) : spec_(spec), key_(key) {}

    // Writes into `out` the bytes this pattern places at device bytes [offset, offset+out.size()).
    void fill(std::uint64_t offset, std::span<std::byte> out) const;

    const PatternSpec& spec() const { return spec_; }

private:
    PatternSpec spec_;
    PatternKey key_;
};

}  // namespace dw
