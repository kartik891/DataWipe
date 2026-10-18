#include "device/ata_taskfile.hpp"

namespace dw {

std::array<std::uint8_t, 16> ata_pass_through_16(const AtaTaskfile& tf) {
    // SAT-4 ATA PASS-THROUGH(16). Register interleave matches hdparm's sgio.c:
    // each pair is (HOB "previous" byte, current byte).
    std::uint8_t protocol = 3;  // non-data
    std::uint8_t byte2 = 0x20;  // CK_COND: return the ATA registers (needed for READ NATIVE MAX)
    switch (tf.transfer) {
        case AtaTaskfile::Transfer::NonData: break;
        case AtaTaskfile::Transfer::PioIn:
            protocol = 4;
            byte2 |= 0x08 | 0x04 | 0x02;  // T_DIR=from device, BYTE_BLOCK=blocks, T_LENGTH=in COUNT
            break;
        case AtaTaskfile::Transfer::PioOut:
            protocol = 5;
            byte2 |= 0x04 | 0x02;  // T_DIR=to device
            break;
    }
    std::array<std::uint8_t, 16> cdb{};
    cdb[0] = 0x85;
    cdb[1] = static_cast<std::uint8_t>((protocol << 1) | (tf.ext ? 1 : 0));
    cdb[2] = byte2;
    cdb[3] = static_cast<std::uint8_t>(tf.features >> 8);
    cdb[4] = static_cast<std::uint8_t>(tf.features);
    cdb[5] = static_cast<std::uint8_t>(tf.count >> 8);
    cdb[6] = static_cast<std::uint8_t>(tf.count);
    cdb[7] = static_cast<std::uint8_t>(tf.lba >> 24);
    cdb[8] = static_cast<std::uint8_t>(tf.lba);
    cdb[9] = static_cast<std::uint8_t>(tf.lba >> 32);
    cdb[10] = static_cast<std::uint8_t>(tf.lba >> 8);
    cdb[11] = static_cast<std::uint8_t>(tf.lba >> 40);
    cdb[12] = static_cast<std::uint8_t>(tf.lba >> 16);
    cdb[13] = tf.device;
    cdb[14] = tf.command;
    cdb[15] = 0;
    return cdb;
}

}  // namespace dw
