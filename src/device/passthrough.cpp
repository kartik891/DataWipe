#include "device/passthrough.hpp"

// The read-only command policy and sense decoding; how commands reach the drive is per
// platform (passthrough_linux.cpp, platform/win_device.cpp).

#include <array>
#include <vector>
#include <cstring>
#include <format>

#include "core/log.hpp"

namespace dw {

namespace {

constexpr std::uint8_t kSenseDescriptorFormat = 0x72;
constexpr std::uint8_t kAtaStatusReturnDescriptor = 0x09;

bool tcg_query_allowed(std::uint8_t protocol, std::uint16_t sp) {
    // Protocol 0x00: list of supported security protocols. 0x01/ComID 0x0001: Level 0 Discovery.
    return (protocol == 0x00 && sp == 0x0000) || (protocol == 0x01 && sp == 0x0001);
}

Error refused(const std::string& what) { return error("READ-ONLY GUARD refused " + what); }

}  // namespace

Result<AtaRegisters> parse_ata_sense(std::span<const std::uint8_t> s) {
    if (s.size() < 8) return error("no sense data returned");
    const std::uint8_t code = s[0] & 0x7F;
    AtaRegisters r;
    if (code == kSenseDescriptorFormat) {
        const size_t len = std::min<size_t>(s.size(), 8u + s[7]);
        for (size_t i = 8; i + 1 < len;) {
            const std::uint8_t type = s[i], dlen = s[i + 1];
            if (type == kAtaStatusReturnDescriptor && dlen >= 12 && i + 14 <= len) {
                const std::uint8_t* d = &s[i];
                const bool ext = d[2] & 1;
                r.error = d[3];
                r.count = static_cast<std::uint16_t>((ext ? d[4] << 8 : 0) | d[5]);
                // Same HOB/current interleave as the CDB: (31:24,7:0) (39:32,15:8) (47:40,23:16)
                r.lba = static_cast<std::uint64_t>(d[7]) | static_cast<std::uint64_t>(d[9]) << 8 |
                        static_cast<std::uint64_t>(d[11]) << 16;
                if (ext)
                    r.lba |= static_cast<std::uint64_t>(d[6]) << 24 | static_cast<std::uint64_t>(d[8]) << 32 |
                             static_cast<std::uint64_t>(d[10]) << 40;
                r.status = d[13];
                r.lba_valid = true;
                return r;
            }
            i += 2u + dlen;
        }
        return error("sense data has no ATA Status Return descriptor");
    }
    if (code == 0x70 || code == 0x71) {
        // ILLEGAL REQUEST or UNIT ATTENTION: the command was not executed (a bridge or driver that
        // does not take ATA PASS-THROUGH, or a reset). Its information bytes are not registers.
        const std::uint8_t key = s[2] & 0x0F;
        if (key == 0x05 || key == 0x06)
            return error(std::format("command not executed: sense key {} ASC/ASCQ 0x{:02x}/0x{:02x}",
                                     key == 0x05 ? "ILLEGAL REQUEST" : "UNIT ATTENTION", s.size() > 12 ? s[12] : 0,
                                     s.size() > 13 ? s[13] : 0));
        // SAT fixed format: INFORMATION bytes 3..6 = ERROR, STATUS, DEVICE, COUNT(7:0).
        r.error = s[3];
        r.status = s[4];
        r.count = s[6];
        r.lba_valid = false;
        return r;
    }
    return error(std::format("unrecognised sense format 0x{:02x}", code));
}

// ---------------------------------------------------------------- whitelist

Result<void> ReadOnlyPassthrough::allow_ata(const AtaTaskfile& tf) {
    using T = AtaTaskfile::Transfer;
    if (tf.transfer == T::PioOut || !tf.payload.empty())
        return refused(std::format("ATA command 0x{:02x}: data-out commands are never sent", tf.command));
    switch (tf.command) {
        case 0xEC:  // IDENTIFY DEVICE
            if (tf.transfer == T::PioIn) return ok();
            break;
        case 0x27:  // READ NATIVE MAX ADDRESS EXT
            if (tf.transfer == T::NonData) return ok();
            break;
        case 0x78:  // ACCESSIBLE MAX ADDRESS CONFIGURATION: only GET NATIVE MAX ADDRESS EXT
            if (tf.transfer == T::NonData && tf.features == 0x0000) return ok();
            break;
        case 0xB1:  // DEVICE CONFIGURATION OVERLAY: only DCO IDENTIFY
            if (tf.transfer == T::PioIn && tf.features == 0xC2) return ok();
            break;
    }
    return refused(std::format("ATA command 0x{:02x} features 0x{:04x}: not a read-only query", tf.command, tf.features));
}

Result<void> ReadOnlyPassthrough::allow_security_in(std::uint8_t protocol, std::uint16_t sp) {
    if (tcg_query_allowed(protocol, sp)) return ok();
    return refused(std::format("SECURITY PROTOCOL IN protocol 0x{:02x} / 0x{:04x}", protocol, sp));
}

Result<void> ReadOnlyPassthrough::allow_nvme(const NvmeAdminCmd& c) {
    if (c.opcode == 0x06) {  // Identify
        const std::uint32_t cns = c.cdw10 & 0xFF;
        if (cns == 0x00 || cns == 0x01) return ok();
        return refused(std::format("NVMe Identify CNS 0x{:02x}", cns));
    }
    if (c.opcode == 0x82) {  // Security Receive: SECP bits 31:24, SPSP bits 23:8
        const auto secp = static_cast<std::uint8_t>(c.cdw10 >> 24);
        const auto spsp = static_cast<std::uint16_t>((c.cdw10 >> 8) & 0xFFFF);
        if (tcg_query_allowed(secp, spsp)) return ok();
        return refused(std::format("NVMe Security Receive SECP 0x{:02x} SPSP 0x{:04x}", secp, spsp));
    }
    return refused(std::format("NVMe admin opcode 0x{:02x}: not a read-only query", c.opcode));
}

// The gate every destructive transport sits behind, on every platform.
Result<DevicePassthrough> DevicePassthrough::create(IBlockDevice& device) {
    if (device.kind() != BackendKind::PhysicalBlock) return error("device commands are only sent to physical devices");
    if (!device.writable())
        return error("device commands need the device opened writable, which requires the physical-device confirmation");
    return DevicePassthrough(device);
}

}  // namespace dw
