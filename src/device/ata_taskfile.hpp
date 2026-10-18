#pragma once
// Register-level command structures shared by the device layer (read-only detection
// passthrough) and the engine (command builders / executors).

#include <array>
#include <cstdint>
#include <vector>

namespace dw {

// ATA taskfile, the register-level view of an ATA command (48-bit form).
struct AtaTaskfile {
    std::uint8_t command = 0;
    std::uint16_t features = 0;
    std::uint16_t count = 0;
    std::uint64_t lba = 0;  // 48 bits
    std::uint8_t device = 0x40;  // LBA mode bit
    bool ext = false;            // 48-bit "EXT" command (uses the HOB registers)
    enum class Transfer { NonData, PioIn, PioOut } transfer = Transfer::NonData;
    std::vector<std::uint8_t> payload;  // 512-byte data-out block (e.g. password block)
};

struct NvmeAdminCmd {
    std::uint8_t opcode = 0;
    std::uint32_t nsid = 0;
    std::uint32_t cdw10 = 0;
    std::uint32_t cdw11 = 0;
};

// SCSI ATA PASS-THROUGH(16) CDB (SAT-4, opcode 0x85) for an ATA taskfile.
std::array<std::uint8_t, 16> ata_pass_through_16(const AtaTaskfile& tf);

}  // namespace dw
