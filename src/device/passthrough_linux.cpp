// Linux transports for device/passthrough.hpp: SG_IO (ATA PASS-THROUGH, SECURITY PROTOCOL IN),
// the NVMe admin ioctl, MMC_IOC_CMD and the block-layer discard ioctls.

#include "device/passthrough.hpp"

#include <linux/mmc/ioctl.h>
#include <linux/nvme_ioctl.h>
#include <scsi/sg.h>
#include <sys/ioctl.h>

#include <array>
#include <cstring>
#include <format>
#include <vector>

#include "core/log.hpp"

namespace dw {

namespace {

constexpr unsigned kTimeoutMs = 15000;

std::string sg_status(const sg_io_hdr_t& h) {
    return std::format("scsi status 0x{:02x}, host 0x{:x}, driver 0x{:x}", h.status, h.host_status, h.driver_status);
}

}  // namespace

// ---------------------------------------------------------------- transports

namespace {

// One ATA command through SG_IO / ATA PASS-THROUGH(16). PIO-in fills `data`; PIO-out sends
// tf.payload. The device's ERR bit becomes an error naming the abort.
Result<AtaRegisters> sg_ata(int fd, const std::string& path, const AtaTaskfile& tf, std::span<std::uint8_t> data_in,
                            unsigned timeout_ms) {
    const bool pio_in = tf.transfer == AtaTaskfile::Transfer::PioIn;
    const bool pio_out = tf.transfer == AtaTaskfile::Transfer::PioOut;
    if (pio_in && data_in.size() != static_cast<size_t>(tf.count) * 512)
        return error("data buffer must be count x 512 bytes");
    std::vector<std::uint8_t> out = tf.payload;
    if (pio_out && out.size() != static_cast<size_t>(tf.count) * 512)
        return error("PIO-out payload must be count x 512 bytes");

    auto cdb = ata_pass_through_16(tf);
    std::array<std::uint8_t, 64> sense{};
    sg_io_hdr_t h{};
    h.interface_id = 'S';
    h.cmd_len = static_cast<unsigned char>(cdb.size());
    h.cmdp = cdb.data();
    h.mx_sb_len = static_cast<unsigned char>(sense.size());
    h.sbp = sense.data();
    h.dxfer_direction = pio_in ? SG_DXFER_FROM_DEV : pio_out ? SG_DXFER_TO_DEV : SG_DXFER_NONE;
    h.dxferp = pio_in ? data_in.data() : pio_out ? out.data() : nullptr;
    h.dxfer_len = pio_in ? static_cast<unsigned>(data_in.size()) : pio_out ? static_cast<unsigned>(out.size()) : 0;
    h.timeout = timeout_ms;

    if (::ioctl(fd, SG_IO, &h) != 0) return sys_error("ioctl(SG_IO) " + path);
    if (h.host_status != 0) return error("SG_IO transport error: " + sg_status(h));

    AtaRegisters regs;
    if (h.sb_len_wr > 0) {
        auto parsed = parse_ata_sense(std::span<const std::uint8_t>(sense.data(), h.sb_len_wr));
        if (!parsed) return error("SG_IO: " + parsed.error().message + " (" + sg_status(h) + ")");
        regs = *parsed;
    } else if (h.status != 0) {
        return error("SG_IO failed without sense data: " + sg_status(h));
    }
    if (regs.status & 0x01)  // ERR
        return error(std::format("device aborted ATA command 0x{:02x} (error register 0x{:02x}{})", tf.command,
                                 regs.error, (regs.error & 0x04) ? ", ABRT" : ""));
    return regs;
}

Result<std::uint32_t> nvme_admin_raw(int fd, const std::string& path, const NvmeAdminCmd& c, std::span<std::uint8_t> data,
                                     unsigned timeout_ms) {
    nvme_admin_cmd cmd{};
    cmd.opcode = c.opcode;
    cmd.nsid = c.nsid;
    cmd.cdw10 = c.cdw10;
    cmd.cdw11 = c.cdw11;
    cmd.addr = reinterpret_cast<std::uintptr_t>(data.data());
    cmd.data_len = static_cast<std::uint32_t>(data.size());
    cmd.timeout_ms = timeout_ms;
    const int rc = ::ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd);
    if (rc < 0) return sys_error("ioctl(NVME_IOCTL_ADMIN_CMD) " + path);
    if (rc > 0) return error(std::format("NVMe admin 0x{:02x} failed with status 0x{:x}", c.opcode, rc));
    return cmd.result;
}

}  // namespace

Result<AtaRegisters> ReadOnlyPassthrough::ata(const AtaTaskfile& tf, std::span<std::uint8_t> data_in) {
    if (auto r = allow_ata(tf); !r) return r.error();
    log::debug("read-only SG_IO ATA 0x{:02x} feat 0x{:04x} on {}", tf.command, tf.features, device_.path());
    return sg_ata(device_.native_handle(), device_.path(), tf, data_in, kTimeoutMs);
}

Result<void> ReadOnlyPassthrough::security_in(std::uint8_t protocol, std::uint16_t sp, std::span<std::uint8_t> out) {
    if (auto r = allow_security_in(protocol, sp); !r) return r;
    if (out.size() % 512 != 0) return error("security-in buffer must be a multiple of 512 bytes");
    std::array<std::uint8_t, 12> cdb{};
    cdb[0] = 0xA2;  // SECURITY PROTOCOL IN
    cdb[1] = protocol;
    cdb[2] = static_cast<std::uint8_t>(sp >> 8);
    cdb[3] = static_cast<std::uint8_t>(sp);
    const auto len = static_cast<std::uint32_t>(out.size());
    cdb[6] = static_cast<std::uint8_t>(len >> 24);
    cdb[7] = static_cast<std::uint8_t>(len >> 16);
    cdb[8] = static_cast<std::uint8_t>(len >> 8);
    cdb[9] = static_cast<std::uint8_t>(len);

    std::array<std::uint8_t, 64> sense{};
    sg_io_hdr_t h{};
    h.interface_id = 'S';
    h.cmd_len = static_cast<unsigned char>(cdb.size());
    h.cmdp = cdb.data();
    h.mx_sb_len = static_cast<unsigned char>(sense.size());
    h.sbp = sense.data();
    h.dxfer_direction = SG_DXFER_FROM_DEV;
    h.dxferp = out.data();
    h.dxfer_len = len;
    h.timeout = kTimeoutMs;
    if (::ioctl(device_.native_handle(), SG_IO, &h) != 0) return sys_error("ioctl(SG_IO) " + device_.path());
    if (h.status != 0 || h.host_status != 0 || (h.info & SG_INFO_OK_MASK) != SG_INFO_OK)
        return error("SECURITY PROTOCOL IN not supported: " + sg_status(h));
    return ok();
}

Result<std::uint32_t> ReadOnlyPassthrough::nvme_admin(const NvmeAdminCmd& c, std::span<std::uint8_t> data_in) {
    if (auto r = allow_nvme(c); !r) return r.error();
    log::debug("read-only NVMe admin 0x{:02x} cdw10 0x{:08x} on {}", c.opcode, c.cdw10, device_.path());
    return nvme_admin_raw(device_.native_handle(), device_.path(), c, data_in, kTimeoutMs);
}

Result<void> ReadOnlyPassthrough::mmc_ext_csd(std::span<std::uint8_t> out) {
    if (out.size() != 512) return error("EXT_CSD buffer must be 512 bytes");
    // Response/command flags from the kernel's mmc core (not in the uapi header): R1 response
    // (present, CRC, opcode) on an addressed data-transfer command, as mmc-utils sends it.
    constexpr unsigned kRspPresent = 1 << 0, kRspCrc = 1 << 2, kRspOpcode = 1 << 4, kCmdAdtc = 1 << 5,
                       kRspSpiS1 = 1 << 7;
    mmc_ioc_cmd ic{};
    ic.opcode = 8;  // SEND_EXT_CSD
    ic.arg = 0;
    ic.flags = kRspSpiS1 | kRspPresent | kRspCrc | kRspOpcode | kCmdAdtc;
    ic.blksz = 512;
    ic.blocks = 1;
    ic.write_flag = 0;
    mmc_ioc_cmd_set_data(ic, out.data());
    log::debug("read-only MMC CMD8 SEND_EXT_CSD on {}", device_.path());
    if (::ioctl(device_.native_handle(), MMC_IOC_CMD, &ic) != 0) return sys_error("ioctl(MMC_IOC_CMD CMD8) " + device_.path());
    return ok();
}

Result<std::uint32_t> ReadOnlyPassthrough::nvme_namespace_id() {
    const int id = ::ioctl(device_.native_handle(), NVME_IOCTL_ID);
    if (id < 0) return sys_error("ioctl(NVME_IOCTL_ID) " + device_.path());
    return static_cast<std::uint32_t>(id);
}

// ---------------------------------------------------------------- destructive transport

Result<AtaRegisters> DevicePassthrough::ata(const AtaTaskfile& tf, std::span<std::uint8_t> data_in, unsigned timeout_ms) {
    log::info("SG_IO ATA 0x{:02x} feat 0x{:04x} count {} on {} (timeout {} s)", tf.command, tf.features, tf.count,
              device_.path(), timeout_ms / 1000);
    return sg_ata(device_.native_handle(), device_.path(), tf, data_in, timeout_ms);
}

Result<std::uint32_t> DevicePassthrough::nvme_admin(const NvmeAdminCmd& c, std::span<std::uint8_t> data,
                                                    unsigned timeout_ms) {
    log::info("NVMe admin 0x{:02x} nsid 0x{:x} cdw10 0x{:08x} on {} (timeout {} s)", c.opcode, c.nsid, c.cdw10,
              device_.path(), timeout_ms / 1000);
    return nvme_admin_raw(device_.native_handle(), device_.path(), c, data, timeout_ms);
}

Result<void> DevicePassthrough::block_ioctl(unsigned long request, std::uint64_t offset, std::uint64_t length) {
    std::uint64_t range[2] = {offset, length};
    log::info("block ioctl 0x{:x} [{}, +{}) on {}", request, offset, length, device_.path());
    if (::ioctl(device_.native_handle(), request, range) != 0) return sys_error("block ioctl on " + device_.path());
    return ok();
}

}  // namespace dw
