#pragma once
// Decoder for the 512-byte (256-word) ATA IDENTIFY DEVICE response.

#include <array>
#include <cstdint>

#include "core/result.hpp"
#include "device/identity.hpp"

namespace dw {

using IdentifyWords = std::array<std::uint16_t, 256>;

// ATA strings are stored two chars per word with the bytes swapped ("IBM " arrives as "BI M").
// Raw data from SG_IO ATA PASS-THROUGH is in that on-wire order. HDIO_GET_IDENTITY is not:
// libata's ata_get_identity() rewrites model/firmware/serial into normal byte order before
// copying to userspace, while leaving every numeric word untouched.
enum class AtaStringOrder { WireSwapped, AlreadyFixed };

// Pure function (no I/O) so it can be tested with synthetic IDENTIFY blocks.
// Validates the word-255 integrity checksum when its 0xA5 signature is present.
Result<AtaIdentity> decode_ata_identify(const IdentifyWords& words, AtaStringOrder order);

}  // namespace dw
