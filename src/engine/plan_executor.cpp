#include "engine/plan_executor.hpp"

#include <chrono>
#include <format>

#include "core/log.hpp"

namespace dw {

namespace {
constexpr int kMaxPolls = 100000;

std::string_view to_string(StepRecord::Status s) {
    switch (s) {
        case StepRecord::Status::Completed: return "completed";
        case StepRecord::Status::Failed: return "failed";
        case StepRecord::Status::Aborted: return "aborted";
        case StepRecord::Status::NotRun: return "not-run";
    }
    return "?";
}

Result<void> check_resume(const WipePlan& plan, const ResumePoint& r) {
    if (r.step > plan.steps.size())
        return error(std::format("resume point names step {} but the plan has {}", r.step + 1, plan.steps.size()));
    if (r.step == plan.steps.size()) {
        if (r.commands_done || r.sectors_done) return error("resume point is past the last step");
        return ok();
    }
    const WipeStep& s = plan.steps[r.step];
    if (r.sectors_done && !(r.commands_done && s.overwrite && r.sectors_done <= s.overwrite->sector_count))
        return error(std::format("resume point ({} sectors into step {}) does not fit that step", r.sectors_done,
                                 r.step + 1));
    return ok();
}
}  // namespace

Result<PlanRunResult> execute_plan(const WipePlan& plan, ICommandExecutor& executor, IBlockDevice* device,
                                   const ExecutionOptions& opt) {
    if (plan.has_host_io() && (!device || !opt.runner))
        return error("plan '" + plan.method_id + "' contains host overwrite passes but no overwrite engine is "
                     "attached");
    if (plan.has_host_io() && !device->writable()) return error("plan requires a writable device");
    if (auto r = check_resume(plan, opt.resume); !r) return r.error();
    const ResumePoint& resume = opt.resume;

    // Bring the command executor to where the interrupted run left the drive, then preflight
    // everything still to be issued before issuing anything.
    std::vector<DeviceCommand> done_cmds, todo_cmds;
    for (size_t i = 0; i < plan.steps.size(); ++i) {
        const bool done = i < resume.step || (i == resume.step && resume.commands_done);
        auto& dst = done ? done_cmds : todo_cmds;
        dst.insert(dst.end(), plan.steps[i].commands.begin(), plan.steps[i].commands.end());
    }
    if (!done_cmds.empty()) {
        if (auto r = executor.restore(done_cmds); !r) return error("cannot restore drive state: " + r.error().message);
        log::info("resume: {} device command(s) from the interrupted run restored on {}", done_cmds.size(),
                  executor.name());
    }
    if (!todo_cmds.empty()) {
        if (auto r = executor.preflight(todo_cmds); !r) return r.error();
        log::info("preflight: all {} device commands would be accepted by {}", todo_cmds.size(), executor.name());
        if (opt.observer) opt.observer->preflight_passed(todo_cmds.size());
    }

    PlanRunResult result;
    result.resumed_from = resume;
    for (const auto& s : plan.steps) result.steps.push_back(StepRecord{s.title, s.execution, s.level, StepRecord::Status::NotRun, {}, {}, 0, 0});
    for (size_t i = 0; i < resume.step; ++i) {
        result.steps[i].status = StepRecord::Status::Completed;
        result.steps[i].log.push_back("completed by an earlier, interrupted run");
        if (result.steps[i].level > result.achieved) result.achieved = result.steps[i].level;
    }
    auto save = [&](ResumePoint p) {
        result.resume_at = p;
        if (opt.progress) opt.progress->save(p);
    };

    for (size_t i = resume.step; i < plan.steps.size(); ++i) {
        const WipeStep& step = plan.steps[i];
        StepRecord& rec = result.steps[i];
        const bool resuming_here = i == resume.step && resume != ResumePoint{};

        if (opt.cancel && opt.cancel->requested() && !resuming_here) {
            log::warn("interrupted before step {}", i + 1);
            result.aborted = true;
            save({i, false, 0});
            break;
        }

        log::info("step {}/{} [{}] {}{}", i + 1, plan.steps.size(), to_string(step.execution), step.title,
                  resuming_here ? " (resuming)" : "");
        if (opt.observer) opt.observer->step_started(i, step);
        const auto t0 = std::chrono::steady_clock::now();

        auto fail = [&](const std::string& why) {
            rec.status = StepRecord::Status::Failed;
            rec.error = why;
            log::error("step {} failed: {}", i + 1, why);
        };

        // Device commands are never interrupted: a firmware erase in progress cannot be
        // cancelled by the host, and abandoning its status polls would only hide the outcome.
        if (i == resume.step && resume.commands_done) {
            if (!step.commands.empty()) rec.log.push_back("device commands completed by the interrupted run");
        } else {
            for (const auto& cmd : step.commands) {
                rec.log.push_back("-> " + cmd.describe());
                auto r = executor.issue(cmd);
                int polls = 0;
                unsigned logged_pct = 101;  // log progress changes only: a real erase polls for hours
                while (r && r->in_progress && cmd.role == CommandRole::StatusPoll && ++polls < kMaxPolls) {
                    if (r->progress_pct != logged_pct)
                        rec.log.push_back(std::format("<- in progress {}%", logged_pct = r->progress_pct));
                    r = executor.issue(cmd);  // a real executor sleeps inside issue() between polls
                }
                if (!r) {
                    fail(r.error().message);
                    break;
                }
                if (r->in_progress) {
                    fail("operation did not complete within the polling limit");
                    break;
                }
                rec.log.push_back("<- " + r->detail);
            }
            if (rec.status != StepRecord::Status::Failed && step.overwrite && !step.commands.empty())
                save({i, true, 0});
        }

        if (rec.status != StepRecord::Status::Failed && step.overwrite) {
            if (step.execution == Execution::Emulated)
                log::info("[EMULATED] reproducing the effect of '{}' with a host pass: {}", step.title,
                          step.overwrite->pattern.describe());
            OverwriteContext ctx;
            ctx.resume_sector = i == resume.step ? resume.sectors_done : 0;
            ctx.cancel = opt.cancel;
            ctx.on_durable = [&, i](std::uint64_t sectors) { save({i, true, sectors}); };
            if (opt.observer) ctx.on_progress = [&, i](const OverwriteProgress& p) { opt.observer->overwrite_progress(i, p); };

            auto r = opt.runner->run(*step.overwrite, *device, ctx);
            if (!r) {
                fail(r.error().describe());
            } else {
                rec.bytes_written = r->bytes_written_this_run;
                const auto& o = *step.overwrite;
                rec.log.push_back(std::format("host overwrite of sectors [{}, {}) with {}: {} bytes this run in {:.1f}s, "
                                              "{} flush(es){}",
                                              o.first_sector, o.first_sector + o.sector_count, o.pattern.describe(),
                                              r->bytes_written_this_run, r->seconds, r->flushes,
                                              ctx.resume_sector ? std::format(", resumed at +{}", ctx.resume_sector)
                                                                : ""));
                if (r->aborted) {
                    rec.status = StepRecord::Status::Aborted;
                    rec.error = std::format("interrupted; {} of {} sectors durable", r->sectors_durable, o.sector_count);
                    result.aborted = true;
                    result.resume_at = {i, true, r->sectors_durable};
                }
            }
        }

        rec.seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
        if (rec.status == StepRecord::Status::NotRun) {
            rec.status = StepRecord::Status::Completed;
            if (rec.level > result.achieved) result.achieved = rec.level;
            save({i + 1, false, 0});
        }
        if (opt.observer) opt.observer->step_finished(i, rec);
        if (rec.status != StepRecord::Status::Completed) break;
    }

    result.success = !result.steps.empty() && result.steps.back().status == StepRecord::Status::Completed;
    if (result.achieved > plan.level) result.achieved = plan.level;  // e.g. capped by un-removed HPA
    return result;
}

Json to_json(const PlanRunResult& r) {
    Json j = Json::object();
    j["success"] = r.success;
    j["aborted"] = r.aborted;
    j["achieved_level"] = to_string(r.achieved);
    if (r.resumed_from != ResumePoint{}) {
        j["resumed_from"]["step"] = r.resumed_from.step + 1;
        j["resumed_from"]["sectors_done"] = r.resumed_from.sectors_done;
    }
    if (!r.success) {
        j["resume_at"]["step"] = r.resume_at.step + 1;
        j["resume_at"]["commands_done"] = r.resume_at.commands_done;
        j["resume_at"]["sectors_done"] = r.resume_at.sectors_done;
    }
    Json steps = Json::array();
    for (const auto& s : r.steps) {
        Json sj = Json::object();
        sj["title"] = s.title;
        sj["execution"] = to_string(s.execution);
        sj["status"] = to_string(s.status);
        sj["seconds"] = s.seconds;
        if (s.bytes_written) sj["bytes_written"] = s.bytes_written;
        Json log = Json::array();
        for (const auto& l : s.log) log.push_back(l);
        sj["log"] = std::move(log);
        if (!s.error.empty()) sj["error"] = s.error;
        steps.push_back(std::move(sj));
    }
    j["steps"] = std::move(steps);
    return j;
}

}  // namespace dw
