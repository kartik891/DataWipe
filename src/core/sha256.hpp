#pragma once
// SHA-256 (FIPS 180-4). Binds a resume journal to the exact plan it was written for, and is
// the hash the Phase 4 certificate stub uses.

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace dw {

class Sha256 {
public:
    using Digest = std::array<std::uint8_t, 32>;

    Sha256();
    void update(std::span<const std::byte> data);
    void update(std::string_view s) { update(std::as_bytes(std::span(s.data(), s.size()))); }
    Digest finish();

    static std::string hex(std::string_view s);

private:
    void compress(const std::uint8_t* block);

    std::array<std::uint32_t, 8> h_;
    std::array<std::uint8_t, 64> buf_{};
    std::size_t buf_len_ = 0;
    std::uint64_t total_ = 0;
};

std::string to_hex(std::span<const std::uint8_t> bytes);

}  // namespace dw
