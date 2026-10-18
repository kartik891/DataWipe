// PassthroughCommandExecutor: sends a plan's device commands to real hardware.
//
// Reached only through the physical-device gate: the CLI opens the device writable with a
// PhysicalOverride (flag + retyped serial + retyped path + device not in use), and
// DevicePassthrough refuses any device that was not opened that way.

#ifdef __linux__
#include <linux/fs.h>
#include <linux/mmc/ioctl.h>
#include <sys/ioctl.h>
#endif
#include <unistd.h>

#include <chrono>
#include <filesystem>
#include <format>
#include <regex>
#include <thread>

#include "core/log.hpp"
#include "device/passthrough.hpp"
#include "engine/command_executor.hpp"
#include "engine/command_support.hpp"

namespace dw {

namespace {

constexpr unsigned kShortTimeoutMs = 60000;

std::uint16_t le16(const std::uint8_t* p) { return static_cast<std::uint16_t>(p[0] | p[1] << 8); }

bool controller_wide(const DeviceCommand& c, const AtaIdentity& id) {
    if (c.protocol != Protocol::NVMeAdmin || !c.nvme || c.role != CommandRole::Action) return false;
    if (c.nvme->opcode == 0x84) return true;                                  // Sanitize: whole NVM subsystem
    if (c.nvme->opcode == 0x80) return id.nvme_format_all_namespaces;        // FNA bit 0
    return false;
}

// Namespaces of the controller behind block device `name` (e.g. nvme0n1), from sysfs.
std::vector<std::string> sibling_namespaces(const std::string& sysfs_root, const std::string& name) {
    std::vector<std::string> out;
    static const std::regex ns(R"(nvme\d+(c\d+)?n\d+)");
    std::error_code ec;
    for (const auto& e : std::filesystem::directory_iterator(sysfs_root + "/block/" + name + "/device", ec)) {
        const std::string n = e.path().filename().string();
        if (std::regex_match(n, ns)) out.push_back(n);
    }
    return out;
}

void wait_ms(unsigned ms) { std::this_thread::sleep_for(std::chrono::milliseconds(ms)); }

}  // namespace

unsigned ata_erase_timeout_ms(const AtaIdentity& id, bool enhanced) {
    const std::uint32_t m = enhanced ? id.ata_enhanced_erase_minutes : id.ata_erase_minutes;
    std::uint64_t minutes = 72 * 60;
    if (m != 0 && m != AtaIdentity::kEraseTimeOver508) minutes = std::max<std::uint64_t>(2 * std::uint64_t(m) + 30, 120);
    return static_cast<unsigned>(std::min<std::uint64_t>(minutes * 60000, 0xFFFFFFFFu));
}

Result<void> PassthroughCommandExecutor::preflight(std::span<const DeviceCommand> seq) {
    if (auto pt = DevicePassthrough::create(device_); !pt) return pt.error();
    for (const auto& c : seq) {
        if (c.role != CommandRole::Action) continue;
        const SupportInfo s = command_support(c, profile_.media);
        if (s.level == Support::Unsupported) return error("refusing " + c.name + ": " + s.why);
        if (s.level == Support::Experimental && !opts_.experimental)
            return error("refusing " + c.name + " without --experimental: " + s.why);
        if (controller_wide(c, profile_.identity)) {
            const std::string name = std::filesystem::path(device_.path()).filename().string();
            auto nss = sibling_namespaces(opts_.sysfs_root, name);
            if (nss.size() > 1) {
                std::string list;
                for (const auto& n : nss) list += (list.empty() ? "" : ", ") + n;
                return error(std::format("refusing {}: it acts on every namespace of the controller ({}), but only {} "
                                         "was confirmed",
                                         c.name, list, device_.path()));
            }
        }
    }
    // The drive's own rules (security state, frozen/locked, "immediately preceded by", SANITIZE
    // signatures), checked against the identity read moments ago, before anything is sent.
    SimulatedCommandExecutor rules(profile_);
    if (auto r = rules.preflight(seq); !r) return error("the drive would reject this sequence: " + r.error().message);
    preflighted_ = true;
    return ok();
}

Result<CommandResult> PassthroughCommandExecutor::issue(const DeviceCommand& cmd) {
    if (!preflighted_) return error("internal: device command issued without a preflight");
    const SupportInfo s = command_support(cmd, profile_.media);
    if (cmd.role == CommandRole::Action &&
        (s.level == Support::Unsupported || (s.level == Support::Experimental && !opts_.experimental)))
        return error("refusing " + cmd.name + ": " + s.why);  // belt and braces: preflight already checked
    switch (cmd.protocol) {
        case Protocol::ATA: return ata(cmd);
        case Protocol::NVMeAdmin: return nvme(cmd);
        case Protocol::eMMC: return emmc(cmd);
        case Protocol::BlockIoctl: {
            auto pt = DevicePassthrough::create(device_);
            if (!pt) return pt.error();
            if (auto r = pt->block_ioctl(cmd.ioctl_request, cmd.range_offset, cmd.range_length); !r) return r.error();
            return CommandResult{false, 100, "accepted"};
        }
        case Protocol::TCG: return error("TCG Opal commands are not implemented");
    }
    return error("unknown protocol");
}

Result<CommandResult> PassthroughCommandExecutor::ata(const DeviceCommand& cmd) {
    if (!cmd.ata) return error("ATA command without a taskfile");
    auto pt = DevicePassthrough::create(device_);
    if (!pt) return pt.error();
    const AtaTaskfile& tf = *cmd.ata;
    if (cmd.role == CommandRole::StatusPoll) wait_ms(opts_.poll_interval_ms);
    const bool enhanced = !tf.payload.empty() && (tf.payload[0] & 0x02);
    const unsigned timeout =
        tf.command == 0xF4 ? ata_erase_timeout_ms(profile_.identity, enhanced) : kShortTimeoutMs;  // SECURITY ERASE UNIT
    auto regs = pt->ata(tf, {}, timeout);
    if (!regs) return regs.error();
    if (cmd.role == CommandRole::StatusPoll && tf.command == 0xB4) {
        // SANITIZE STATUS EXT (ACS-3 7.34.4): COUNT bit 15 completed without error, bit 14 in
        // progress; LBA 15:0 progress in 1/65536.
        const bool running = regs->count & 0x4000;
        const bool done = regs->count & 0x8000;
        const unsigned pct = regs->lba_valid ? static_cast<unsigned>((regs->lba & 0xFFFF) * 100 / 65536) : 0;
        if (running) return CommandResult{true, pct, "sanitize in progress"};
        if (!done) return error("SANITIZE STATUS reports the operation neither running nor completed without error");
        return CommandResult{false, 100, "sanitize completed without error"};
    }
    if (cmd.role == CommandRole::Query)
        return CommandResult{false, 100, std::format("status 0x{:02x}, lba {}", regs->status, regs->lba)};
    return CommandResult{false, 100, "accepted"};
}

Result<CommandResult> PassthroughCommandExecutor::nvme(const DeviceCommand& cmd) {
    if (!cmd.nvme) return error("NVMe command without a command block");
    auto pt = DevicePassthrough::create(device_);
    if (!pt) return pt.error();
    const NvmeAdminCmd& n = *cmd.nvme;
    if (n.opcode == 0x02 && (n.cdw10 & 0xFF) == 0x81) {  // Get Log Page: Sanitize Status
        wait_ms(opts_.poll_interval_ms);
        std::vector<std::uint8_t> log(512);
        if (auto r = pt->nvme_admin(n, log, kShortTimeoutMs); !r) return r.error();
        const unsigned pct = le16(&log[0]) * 100u / 65536u;  // SPROG
        switch (le16(&log[2]) & 0x7) {                        // SSTAT
            case 2: return CommandResult{true, pct, "sanitize in progress"};
            case 1:
            case 4: return CommandResult{false, 100, "sanitize completed successfully"};
            case 3: return error("the controller reports the most recent sanitize FAILED");
            default: return error("the controller reports no sanitize operation");
        }
    }
    const unsigned timeout = n.opcode == 0x80 ? opts_.format_timeout_ms : kShortTimeoutMs;
    auto r = pt->nvme_admin(n, {}, timeout);
    if (!r) return r.error();
    return CommandResult{false, 100, std::format("completed (dword 0 = 0x{:x})", *r)};
}

Result<CommandResult> PassthroughCommandExecutor::emmc(const DeviceCommand& cmd) {
    // CMD6 SWITCH with an R1b response (busy until the sanitize finishes).
#ifndef __linux__
    return error(std::format("eMMC CMD{} cannot be sent on this platform", cmd.emmc_opcode));
#else
    constexpr unsigned kRspPresent = 1 << 0, kRspCrc = 1 << 2, kRspBusy = 1 << 3, kRspOpcode = 1 << 4, kCmdAc = 0 << 5;
    mmc_ioc_cmd ic{};
    ic.opcode = cmd.emmc_opcode;
    ic.arg = cmd.emmc_arg;
    ic.flags = kRspPresent | kRspCrc | kRspOpcode | kRspBusy | kCmdAc;
    ic.write_flag = 1;
    ic.cmd_timeout_ms = opts_.erase_timeout_ms;
    if (::ioctl(device_.native_handle(), MMC_IOC_CMD, &ic) != 0) return sys_error("ioctl(MMC_IOC_CMD) " + device_.path());
    return CommandResult{false, 100, std::format("response 0x{:08x}", ic.response[0])};
#endif
}

}  // namespace dw
