// Decoder tests against synthetic IDENTIFY DEVICE blocks.

#include <cstring>

#include "check.hpp"
#include "device/ata_identity.hpp"

using namespace dw;

namespace {

// Store an ATA string the way the drive sends it: first char in the high byte of each word.
void put_wire_string(IdentifyWords& w, int first, int count, const std::string& s) {
    std::string padded = s;
    padded.resize(static_cast<size_t>(count) * 2, ' ');
    for (int i = 0; i < count; ++i)
        w[static_cast<size_t>(first + i)] = static_cast<std::uint16_t>(
            (static_cast<unsigned char>(padded[2 * static_cast<size_t>(i)]) << 8) |
            static_cast<unsigned char>(padded[2 * static_cast<size_t>(i) + 1]));
}

// Store it the way HDIO_GET_IDENTITY returns it: plain byte order in memory.
void put_fixed_string(IdentifyWords& w, int first, int count, const std::string& s) {
    std::string padded = s;
    padded.resize(static_cast<size_t>(count) * 2, ' ');
    std::memcpy(&w[static_cast<size_t>(first)], padded.data(), padded.size());
}

void seal_checksum(IdentifyWords& w) {
    w[255] = 0x00A5;
    std::uint8_t sum = 0;
    for (auto word : w) sum = static_cast<std::uint8_t>(sum + (word & 0xFF) + (word >> 8));
    w[255] = static_cast<std::uint16_t>(0x00A5 | (static_cast<std::uint8_t>(-sum) << 8));
}

IdentifyWords make_hdd() {
    IdentifyWords w{};
    w[0] = 0x0040;  // ATA device, fixed
    put_wire_string(w, 10, 10, "WD-WCC4E1234567");
    put_wire_string(w, 23, 4, "82.00A82");
    put_wire_string(w, 27, 20, "WDC WD10EZEX-08WN4A0");
    w[59] = 0;                        // no SANITIZE
    w[82] = 1u << 10;                 // HPA supported
    w[83] = (1u << 10) | (1u << 11);  // 48-bit LBA, DCO supported
    w[85] = 1u << 10;                 // HPA enabled
    const std::uint64_t lba = 1953525168ull;  // 1 TB
    w[100] = static_cast<std::uint16_t>(lba);
    w[101] = static_cast<std::uint16_t>(lba >> 16);
    w[102] = static_cast<std::uint16_t>(lba >> 32);
    w[103] = static_cast<std::uint16_t>(lba >> 48);
    w[128] = (1u << 0) | (1u << 3) | (1u << 5);  // supported, frozen, enhanced erase
    w[217] = 7200;
    return w;
}

}  // namespace

int main() {
    {
        auto w = make_hdd();
        seal_checksum(w);
        auto id = decode_ata_identify(w, AtaStringOrder::WireSwapped);
        CHECK_OK(id);
        if (id) {
            CHECK(id->model == "WDC WD10EZEX-08WN4A0");
            CHECK(id->serial == "WD-WCC4E1234567");
            CHECK(id->firmware == "82.00A82");
            CHECK(id->user_addressable_sectors == 1953525168ull);
            CHECK(id->native_max_sectors == id->user_addressable_sectors);
            CHECK(id->rotation_rate == 7200);
            CHECK(id->hpa_supported && id->hpa_enabled && id->dco_supported);
            CHECK(id->security_supported && id->security_frozen && id->enhanced_erase_supported);
            CHECK(!id->security_enabled && !id->security_locked);
            CHECK(!id->sanitize_supported);
        }
    }
    {
        // HDIO_GET_IDENTITY layout: strings already fixed by libata. Same numeric result.
        auto w = make_hdd();
        put_fixed_string(w, 10, 10, "WD-WCC4E1234567");
        put_fixed_string(w, 27, 20, "WDC WD10EZEX-08WN4A0");
        auto id = decode_ata_identify(w, AtaStringOrder::AlreadyFixed);
        CHECK_OK(id);
        if (id) {
            CHECK(id->model == "WDC WD10EZEX-08WN4A0");
            CHECK(id->serial == "WD-WCC4E1234567");
        }
        // Decoding fixed strings as wire-swapped scrambles them: proves the order flag matters.
        auto wrong = decode_ata_identify(w, AtaStringOrder::WireSwapped);
        if (wrong) CHECK(wrong->model != "WDC WD10EZEX-08WN4A0");
    }
    {
        // Corrupted block with a valid-looking signature is rejected.
        auto w = make_hdd();
        seal_checksum(w);
        w[217] = 1;  // flip HDD -> "SSD" after sealing
        CHECK_ERR_CONTAINS(decode_ata_identify(w, AtaStringOrder::WireSwapped), "checksum");
    }
    {
        // No 48-bit support: falls back to 28-bit capacity in words 60-61. SSD with SANITIZE.
        IdentifyWords w{};
        put_wire_string(w, 27, 20, "OLD SSD");
        put_wire_string(w, 10, 10, "S1");
        w[60] = 0x5678;
        w[61] = 0x0123;
        w[59] = (1u << 12) | (1u << 13) | (1u << 15);
        w[217] = 1;
        auto id = decode_ata_identify(w, AtaStringOrder::WireSwapped);
        CHECK_OK(id);
        if (id) {
            CHECK(id->user_addressable_sectors == 0x01235678ull);
            CHECK(id->sanitize_supported && id->crypto_scramble_supported && id->block_erase_supported);
            CHECK(!id->overwrite_supported);
            CHECK(id->rotation_rate == 1);
        }
    }
    {
        IdentifyWords w{};
        w[0] = 0x8580;  // ATAPI
        CHECK_ERR_CONTAINS(decode_ata_identify(w, AtaStringOrder::WireSwapped), "ATAPI");
    }
    {  // Word 169 bit 0: TRIM, the fallback signal when the rotation rate is not reported.
        auto w = make_hdd();
        w[217] = 0;
        seal_checksum(w);
        auto hdd = decode_ata_identify(w, AtaStringOrder::WireSwapped);
        CHECK(hdd && hdd->rotation_rate == 0 && !hdd->trim_supported);
        w = make_hdd();
        w[217] = 0;
        w[169] = 1;
        seal_checksum(w);
        auto ssd = decode_ata_identify(w, AtaStringOrder::WireSwapped);
        CHECK(ssd && ssd->trim_supported);
    }
    {  // Erase-time estimates, words 89 (normal) / 90 (enhanced), both formats.
        auto w = make_hdd();
        w[89] = 20;                 // short format: 20 x 2 minutes
        w[90] = 0x8000 | 200;       // extended format: 200 x 2 minutes
        seal_checksum(w);
        auto id = decode_ata_identify(w, AtaStringOrder::WireSwapped);
        CHECK_OK(id);
        if (id) CHECK(id->ata_erase_minutes == 40 && id->ata_enhanced_erase_minutes == 400);
        w = make_hdd();
        w[89] = 255;  // "more than 508 minutes"
        w[90] = 0;    // not reported
        seal_checksum(w);
        id = decode_ata_identify(w, AtaStringOrder::WireSwapped);
        CHECK_OK(id);
        if (id) CHECK(id->ata_erase_minutes == AtaIdentity::kEraseTimeOver508 && id->ata_enhanced_erase_minutes == 0);
    }
    return finish("test_ata_identity");
}
