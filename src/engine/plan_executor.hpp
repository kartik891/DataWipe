#pragma once
// Runs a WipePlan: preflight every device command, then execute steps in order.
//
// Failure is reported as data (PlanRunResult), not only as an error: a plan that stops after
// a completed Clear pass has still achieved Clear, and the certificate must say exactly that.

#include <cstdint>
#include <string>
#include <vector>

#include "core/cancel.hpp"
#include "core/json.hpp"
#include "core/result.hpp"
#include "device/block_device.hpp"
#include "engine/command_executor.hpp"
#include "engine/overwrite_engine.hpp"
#include "engine/wipe_plan.hpp"

namespace dw {

// Where a run stands, in terms that survive a crash: steps before `step` are complete; if
// `commands_done`, step `step`'s device commands were all accepted; `sectors_done` sectors of
// its overwrite pass are durable. {0, false, 0} is a fresh start.
struct ResumePoint {
    std::size_t step = 0;
    bool commands_done = false;
    std::uint64_t sectors_done = 0;
    bool operator==(const ResumePoint&) const = default;
};

// Persists ResumePoints (engine/run_journal.hpp). Implementations handle their own failures:
// a store that falls behind is safe, since a resume then just redoes more work.
class IProgressStore {
public:
    virtual ~IProgressStore() = default;
    virtual void save(const ResumePoint& point) = 0;
};

struct StepRecord {
    std::string title;
    Execution execution = Execution::Simulated;
    SanitizationLevel level = SanitizationLevel::None;
    enum class Status { Completed, Failed, Aborted, NotRun } status = Status::NotRun;
    std::vector<std::string> log;  // commands issued and device responses
    std::string error;
    double seconds = 0;
    std::uint64_t bytes_written = 0;  // host overwrite, this run
};

struct PlanRunResult {
    std::vector<StepRecord> steps;
    bool success = false;
    bool aborted = false;  // stopped on request; `resume_at` says where to continue
    SanitizationLevel achieved = SanitizationLevel::None;
    ResumePoint resumed_from;
    ResumePoint resume_at;  // meaningful when !success
};

// Optional hooks for progress display (CLI, later a GUI).
class PlanObserver {
public:
    virtual ~PlanObserver() = default;
    virtual void preflight_passed(std::size_t /*command_count*/) {}
    virtual void step_started(std::size_t /*index*/, const WipeStep& /*step*/) {}
    virtual void overwrite_progress(std::size_t /*index*/, const OverwriteProgress& /*progress*/) {}
    virtual void step_finished(std::size_t /*index*/, const StepRecord& /*record*/) {}
};

struct ExecutionOptions {
    IOverwriteRunner* runner = nullptr;  // required iff plan.has_host_io()
    PlanObserver* observer = nullptr;
    const CancelToken* cancel = nullptr;
    IProgressStore* progress = nullptr;
    ResumePoint resume;
};

// device may be null only for plans without host I/O (has_host_io() == false).
//
// Resuming: steps before resume.step are not re-run; their device commands are handed to
// ICommandExecutor::restore() so a simulated drive reaches the state the real one kept.
Result<PlanRunResult> execute_plan(const WipePlan& plan, ICommandExecutor& executor, IBlockDevice* device,
                                   const ExecutionOptions& options);

inline Result<PlanRunResult> execute_plan(const WipePlan& plan, ICommandExecutor& executor, IBlockDevice* device,
                                          IOverwriteRunner* runner, PlanObserver* observer = nullptr) {
    return execute_plan(plan, executor, device, ExecutionOptions{runner, observer, nullptr, nullptr, {}});
}

Json to_json(const PlanRunResult& result);

}  // namespace dw
