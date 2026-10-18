#pragma once
// ICommandExecutor: where DeviceCommands go.
//
//   SimulatedCommandExecutor   - a state machine of the drive described by a simulated identity.
//                                Commands are validated against the same rules real firmware
//                                enforces (ATA security states, "immediately preceded by"
//                                sequencing, SANITIZE LBA signatures, in-progress lockout) and
//                                logged with their exact wire encoding. No bytes reach the medium.
//   PassthroughCommandExecutor - real issuance (SG_IO / NVME_IOCTL_ADMIN_CMD / MMC_IOC_CMD /
//                                BLKDISCARD) to a physical device opened under a
//                                PhysicalOverride. engine/passthrough_executor.cpp.

#include <memory>
#include <span>
#include <string>
#include <vector>

#include "core/result.hpp"
#include "device/classifier.hpp"
#include "engine/device_command.hpp"

namespace dw {

struct CommandResult {
    bool in_progress = false;   // StatusPoll: operation still running
    unsigned progress_pct = 100;
    std::string detail;
};

class ICommandExecutor {
public:
    virtual ~ICommandExecutor() = default;
    virtual std::string_view name() const = 0;
    // Check the whole sequence would be accepted, without side effects. Run before the first
    // destructive command so a plan never stops halfway on a predictable rejection.
    virtual Result<void> preflight(std::span<const DeviceCommand> sequence) = 0;
    // Error = the device aborted the command (or transport failure).
    virtual Result<CommandResult> issue(const DeviceCommand& cmd) = 0;
    // Resume support: bring this executor's view of the device to the state it reached after
    // `already_issued` completed in an earlier, interrupted run. A real drive kept that state
    // itself, so by default there is nothing to do.
    virtual Result<void> restore(std::span<const DeviceCommand> /*already_issued*/) { return ok(); }
};

// Mutable view of the simulated drive. Public so tests can assert on transitions.
struct SimulatedDriveState {
    AtaIdentity id;  // capacity + security fields change as commands execute
    bool erase_prepared = false;   // last command was SECURITY ERASE PREPARE
    bool native_max_read = false;  // last command was READ NATIVE MAX ADDRESS EXT
    std::string password;          // user password while security is enabled
    enum class SanitizeState { Idle, InProgress, Completed } sanitize = SanitizeState::Idle;
    unsigned sanitize_progress = 0;
    std::vector<std::string> effects;  // destructive operations "performed", in order
};

class SimulatedCommandExecutor final : public ICommandExecutor {
public:
    explicit SimulatedCommandExecutor(const DeviceProfile& profile);

    std::string_view name() const override { return "simulated"; }
    Result<void> preflight(std::span<const DeviceCommand> sequence) override;
    Result<CommandResult> issue(const DeviceCommand& cmd) override;
    // The simulated drive's state lives only in this process, so replay the commands silently.
    Result<void> restore(std::span<const DeviceCommand> already_issued) override;

    const SimulatedDriveState& state() const { return st_; }

private:
    Result<CommandResult> dispatch(const DeviceCommand& cmd);
    Result<CommandResult> ata(const DeviceCommand& cmd, bool prepared, bool native_read);
    Result<CommandResult> nvme(const DeviceCommand& cmd);
    Result<CommandResult> poll_sanitize();
    Result<CommandResult> start_sanitize(const std::string& effect);

    SimulatedDriveState st_;
    std::uint64_t device_bytes_;
    bool quiet_ = false;
};

struct PassthroughOptions {
    bool experimental = false;                  // allow Support::Experimental commands
    unsigned poll_interval_ms = 2000;           // between status polls of a running erase
    unsigned erase_timeout_ms = 72u * 3600000;  // eMMC SANITIZE (R1b busy); ATA erase: see below
    unsigned format_timeout_ms = 3600000;       // NVMe Format NVM runs synchronously
    std::string sysfs_root = "/sys";            // for tests
};

class PassthroughCommandExecutor final : public ICommandExecutor {
public:
    PassthroughCommandExecutor(IBlockDevice& device, DeviceProfile profile, PassthroughOptions opts)
        : device_(device), profile_(std::move(profile)), opts_(std::move(opts)) {}
    std::string_view name() const override { return "passthrough"; }
    // Support level of every command, controller-wide NVMe operations against other
    // namespaces, then the drive's own sequencing rules checked against its live identity.
    Result<void> preflight(std::span<const DeviceCommand> sequence) override;
    Result<CommandResult> issue(const DeviceCommand& cmd) override;

private:
    Result<CommandResult> ata(const DeviceCommand& cmd);
    Result<CommandResult> nvme(const DeviceCommand& cmd);
    Result<CommandResult> emmc(const DeviceCommand& cmd);

    IBlockDevice& device_;
    DeviceProfile profile_;
    PassthroughOptions opts_;
    bool preflighted_ = false;
};

// SG_IO timeout for SECURITY ERASE UNIT: twice the drive's own estimate (IDENTIFY word 89/90)
// plus 30 minutes, at least 2 hours; 72 hours when the drive reports none or only "over 508
// minutes". Too short is the dangerous direction: the kernel then aborts and resets the drive
// mid-erase, which leaves it with the temporary password set.
unsigned ata_erase_timeout_ms(const AtaIdentity& id, bool enhanced);

// Simulated identity -> simulated executor; hardware identity -> passthrough.
std::unique_ptr<ICommandExecutor> make_command_executor(const DeviceProfile& profile, IBlockDevice& device,
                                                        PassthroughOptions opts = {});

}  // namespace dw
