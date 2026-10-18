#include "core/chacha20.hpp"

#include <bit>
#include <cstring>

namespace dw::chacha20 {

namespace {

constexpr std::uint32_t rotl(std::uint32_t v, int n) { return (v << n) | (v >> (32 - n)); }

std::uint32_t load_le32(const std::uint8_t* p) {
    return std::uint32_t(p[0]) | std::uint32_t(p[1]) << 8 | std::uint32_t(p[2]) << 16 | std::uint32_t(p[3]) << 24;
}

void store_le32(std::uint8_t* p, std::uint32_t v) {
    if constexpr (std::endian::native == std::endian::little) {
        std::memcpy(p, &v, 4);
        return;
    }
    p[0] = std::uint8_t(v);
    p[1] = std::uint8_t(v >> 8);
    p[2] = std::uint8_t(v >> 16);
    p[3] = std::uint8_t(v >> 24);
}

// Computes kLanes consecutive blocks at once. Each quarter-round is written as a loop over
// lanes with no cross-lane dependency, which the compiler turns into SIMD (SSE2/AVX2) code;
// this file is built with -O3 for that reason (see CMakeLists.txt).
constexpr int kLanes = 8;

void blocks(const std::uint32_t in[16], std::uint64_t counter, std::uint8_t* out /* kLanes*64 */) {
    std::uint32_t x[16][kLanes];
    std::uint32_t s[16][kLanes];
    for (int w = 0; w < 16; ++w)
        for (int l = 0; l < kLanes; ++l) s[w][l] = in[w];
    for (int l = 0; l < kLanes; ++l) {
        const std::uint64_t c = counter + std::uint64_t(l);
        s[12][l] = std::uint32_t(c);
        s[13][l] = std::uint32_t(c >> 32);
    }
    std::memcpy(x, s, sizeof x);

    auto qr = [&x](int a, int b, int c, int d) {
        for (int l = 0; l < kLanes; ++l) {
            x[a][l] += x[b][l]; x[d][l] = rotl(x[d][l] ^ x[a][l], 16);
            x[c][l] += x[d][l]; x[b][l] = rotl(x[b][l] ^ x[c][l], 12);
            x[a][l] += x[b][l]; x[d][l] = rotl(x[d][l] ^ x[a][l], 8);
            x[c][l] += x[d][l]; x[b][l] = rotl(x[b][l] ^ x[c][l], 7);
        }
    };
    for (int round = 0; round < 10; ++round) {  // 10 double rounds = ChaCha20
        qr(0, 4, 8, 12); qr(1, 5, 9, 13); qr(2, 6, 10, 14); qr(3, 7, 11, 15);   // columns
        qr(0, 5, 10, 15); qr(1, 6, 11, 12); qr(2, 7, 8, 13); qr(3, 4, 9, 14);   // diagonals
    }
    for (int l = 0; l < kLanes; ++l)
        for (int w = 0; w < 16; ++w) store_le32(out + l * 64 + w * 4, x[w][l] + s[w][l]);
}

void init_state(std::uint32_t st[16], const Key& key, std::uint64_t nonce) {
    st[0] = 0x61707865; st[1] = 0x3320646e; st[2] = 0x79622d32; st[3] = 0x6b206574;  // "expand 32-byte k"
    for (int i = 0; i < 8; ++i) st[4 + i] = load_le32(key.data() + 4 * i);
    st[12] = st[13] = 0;
    st[14] = std::uint32_t(nonce);
    st[15] = std::uint32_t(nonce >> 32);
}

}  // namespace

void block(const std::array<std::uint32_t, 16>& input, std::span<std::uint8_t, kBlockBytes> out) {
    std::uint8_t tmp[kLanes * 64];
    const std::uint64_t counter = std::uint64_t(input[12]) | std::uint64_t(input[13]) << 32;
    blocks(input.data(), counter, tmp);
    std::memcpy(out.data(), tmp, kBlockBytes);
}

void keystream(const Key& key, std::uint64_t nonce, std::uint64_t counter, std::span<std::byte> out) {
    std::uint32_t st[16];
    init_state(st, key, nonce);
    auto* p = reinterpret_cast<std::uint8_t*>(out.data());
    std::size_t left = out.size();
    constexpr std::size_t kBatch = kLanes * kBlockBytes;
    while (left >= kBatch) {
        blocks(st, counter, p);
        counter += kLanes;
        p += kBatch;
        left -= kBatch;
    }
    if (left) {
        std::uint8_t tmp[kBatch];
        blocks(st, counter, tmp);
        std::memcpy(p, tmp, left);
    }
}

}  // namespace dw::chacha20
