// ATA IDENTIFY DEVICE decoder (pure). The provider that fetches the words from a real drive,
// plus READ NATIVE MAX / DCO IDENTIFY / TCG discovery, lives in hw_identity.cpp.
//   hdparm equivalents: `hdparm -I` (IDENTIFY), `hdparm -N` (native max / HPA),
//   `hdparm --dco-identify` (DCO).

#include "device/ata_identity.hpp"

#include <cstring>

namespace dw {

namespace {

bool bit(std::uint16_t word, int n) { return (word >> n) & 1u; }

std::string ata_string(const IdentifyWords& w, int first_word, int word_count, AtaStringOrder order) {
    std::string s;
    s.reserve(static_cast<size_t>(word_count) * 2);
    for (int i = 0; i < word_count; ++i) {
        std::uint16_t v = w[static_cast<size_t>(first_word + i)];
        char hi = static_cast<char>(v >> 8), lo = static_cast<char>(v & 0xFF);
        if (order == AtaStringOrder::WireSwapped) {
            s += hi;  // first character lives in the high byte of the word
            s += lo;
        } else {
            // Already byte-ordered in memory; read the word's bytes in address order.
            unsigned char bytes[2];
            std::memcpy(bytes, &v, 2);
            s += static_cast<char>(bytes[0]);
            s += static_cast<char>(bytes[1]);
        }
    }
    // Space-padded (and occasionally NUL-padded) on both ends.
    auto not_pad = [](char c) { return c != ' ' && c != '\0'; };
    size_t b = 0, e = s.size();
    while (b < e && !not_pad(s[b])) ++b;
    while (e > b && !not_pad(s[e - 1])) --e;
    return s.substr(b, e - b);
}

}  // namespace

Result<AtaIdentity> decode_ata_identify(const IdentifyWords& w, AtaStringOrder order) {
    // Word 255: bits 7:0 = 0xA5 signature, bits 15:8 = checksum making the byte sum of all
    // 512 bytes == 0 mod 256. Detects a corrupted or fabricated IDENTIFY block.
    if ((w[255] & 0xFF) == 0xA5) {
        std::uint8_t sum = 0;
        for (auto word : w) sum = static_cast<std::uint8_t>(sum + (word & 0xFF) + (word >> 8));
        if (sum != 0) return error("IDENTIFY DEVICE integrity checksum (word 255) mismatch");
    }
    // Word 0 bit 15 = 1 means ATAPI (optical etc.), not an ATA disk.
    if (bit(w[0], 15)) return error("IDENTIFY data describes an ATAPI device, not an ATA disk");

    AtaIdentity id;
    id.transport = Transport::SATA;
    // String order only matters for the three string fields; numeric words are host-endian
    // either way (the kernel converts from little-endian on read).
    id.serial = ata_string(w, 10, 10, order);
    id.firmware = ata_string(w, 23, 4, order);
    id.model = ata_string(w, 27, 20, order);
    id.rotation_rate = w[217];

    // Capacity: 48-bit LBA (words 100-103) if word 83 bit 10 says the feature set exists,
    // else the legacy 28-bit count in words 60-61.
    if (bit(w[83], 10)) {
        id.user_addressable_sectors = static_cast<std::uint64_t>(w[100]) | static_cast<std::uint64_t>(w[101]) << 16 |
                                      static_cast<std::uint64_t>(w[102]) << 32 |
                                      static_cast<std::uint64_t>(w[103]) << 48;
    } else {
        id.user_addressable_sectors = static_cast<std::uint64_t>(w[60]) | static_cast<std::uint64_t>(w[61]) << 16;
    }
    id.native_max_sectors = id.user_addressable_sectors;  // refined by READ NATIVE MAX (hw_identity.cpp)
    id.dco_max_sectors = 0;

    id.hpa_supported = bit(w[82], 10);
    id.hpa_enabled = bit(w[85], 10);
    id.dco_supported = bit(w[83], 11);

    id.trim_supported = bit(w[169], 0);

    const std::uint16_t sec = w[128];
    id.security_supported = bit(sec, 0);
    id.security_enabled = bit(sec, 1);
    id.security_locked = bit(sec, 2);
    id.security_frozen = bit(sec, 3);
    id.enhanced_erase_supported = bit(sec, 5);
    // Words 89/90 (ACS-3 7.12.7.40/41): bit 15 set = extended format, bits 14:0 in 2-minute
    // units; clear = bits 7:0 in 2-minute units, where 255 means "more than 508 minutes".
    auto erase_minutes = [](std::uint16_t v) -> std::uint32_t {
        if (v & 0x8000) return (v & 0x7FFFu) * 2;
        const std::uint32_t t = v & 0xFFu;
        return t == 255 ? AtaIdentity::kEraseTimeOver508 : t * 2;
    };
    id.ata_erase_minutes = erase_minutes(w[89]);
    id.ata_enhanced_erase_minutes = erase_minutes(w[90]);

    const std::uint16_t san = w[59];
    id.sanitize_supported = bit(san, 12);
    id.crypto_scramble_supported = bit(san, 13);
    id.overwrite_supported = bit(san, 14);
    id.block_erase_supported = bit(san, 15);

    id.self_encrypting = false;  // refined by TCG Level 0 Discovery (hw_identity.cpp)
    return id;
}

}  // namespace dw
