#include "engine/pattern.hpp"

#ifndef _WIN32
#include <sys/random.h>
#endif

#include <cerrno>
#include <cstring>

#include "core/sha256.hpp"

namespace dw {

Result<PatternKey> random_pattern_key() {
    PatternKey key{};
    std::size_t got = 0;
    while (got < key.size()) {
        ssize_t n = ::getrandom(key.data() + got, key.size() - got, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return sys_error("getrandom");
        }
        got += static_cast<std::size_t>(n);
    }
    return key;
}

std::string to_hex(const PatternKey& key) { return dw::to_hex(std::span<const std::uint8_t>(key)); }

Result<PatternKey> pattern_key_from_hex(std::string_view hex) {
    if (hex.size() != 64) return error("pattern key must be 64 hex digits");
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        return -1;
    };
    PatternKey key{};
    for (std::size_t i = 0; i < key.size(); ++i) {
        const int hi = nibble(hex[2 * i]), lo = nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return error("pattern key has a non-hex (or upper-case) digit");
        key[i] = static_cast<std::uint8_t>(hi << 4 | lo);
    }
    return key;
}

std::string key_fingerprint(const PatternKey& key) {
    Sha256 h;
    h.update(std::as_bytes(std::span(key)));
    return to_hex(std::span<const std::uint8_t>(h.finish())).substr(0, 16);
}

void PatternGenerator::fill(std::uint64_t offset, std::span<std::byte> out) const {
    if (out.empty()) return;
    if (spec_.kind == PatternSpec::Kind::Fixed32) {
        std::byte word[4];
        for (int i = 0; i < 4; ++i) word[i] = std::byte(spec_.value >> (8 * i));
        for (std::size_t i = 0; i < out.size(); ++i) out[i] = word[(offset + i) % 4];
        return;
    }

    // Prng. Sector-aligned requests (the only kind the engine makes) are 64-byte aligned and go
    // straight to the keystream; an unaligned head is served from one scratch block.
    std::uint64_t counter = offset / chacha20::kBlockBytes;
    std::size_t skip = static_cast<std::size_t>(offset % chacha20::kBlockBytes);
    std::size_t pos = 0;
    if (skip) {
        std::byte head[chacha20::kBlockBytes];
        chacha20::keystream(key_, spec_.stream, counter, head);
        const std::size_t n = std::min(out.size(), chacha20::kBlockBytes - skip);
        std::memcpy(out.data(), head + skip, n);
        pos = n;
        ++counter;
    }
    if (pos < out.size()) chacha20::keystream(key_, spec_.stream, counter, out.subspan(pos));
}

}  // namespace dw
