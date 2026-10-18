#include "engine/wipe_plan.hpp"

#include <format>

namespace dw {

std::string PatternSpec::describe() const {
    if (kind == Kind::Prng) return std::format("pseudo-random stream #{}", stream);
    return std::format("fixed 0x{:08x}", value);
}

bool WipePlan::has_host_io() const {
    for (const auto& s : steps)
        if (s.overwrite) return true;
    return false;
}

bool WipePlan::fully_simulated() const {
    for (const auto& s : steps)
        if (s.execution != Execution::Simulated) return false;
    return true;
}

std::string_view to_string(SanitizationLevel l) {
    switch (l) {
        case SanitizationLevel::None: return "none";
        case SanitizationLevel::Clear: return "Clear";
        case SanitizationLevel::Purge: return "Purge";
    }
    return "?";
}

std::string_view to_string(Execution e) {
    switch (e) {
        case Execution::Real: return "REAL";
        case Execution::Emulated: return "EMULATED";
        case Execution::Simulated: return "SIMULATED";
    }
    return "?";
}

namespace {
Json to_json(const OverwriteSpec& o) {
    Json j = Json::object();
    j["first_sector"] = o.first_sector;
    j["sector_count"] = o.sector_count;
    j["pattern"] = o.pattern.describe();
    return j;
}
}  // namespace

Json to_json(const WipePlan& plan) {
    Json j = Json::object();
    j["method_id"] = plan.method_id;
    j["method_name"] = plan.method_name;
    j["level"] = to_string(plan.level);
    Json stds = Json::array();
    for (const auto& s : plan.standards) stds.push_back(s);
    j["standards"] = std::move(stds);

    Json steps = Json::array();
    for (const auto& s : plan.steps) {
        Json st = Json::object();
        st["title"] = s.title;
        st["execution"] = to_string(s.execution);
        st["level"] = to_string(s.level);
        Json cmds = Json::array();
        for (const auto& c : s.commands) {
            Json cj = Json::object();
            cj["name"] = c.name;
            cj["transport"] = c.transport();
            for (const auto& [k, v] : c.params) cj["params"][k] = v;
            cmds.push_back(std::move(cj));
        }
        st["commands"] = std::move(cmds);
        if (s.overwrite) st["overwrite"] = to_json(*s.overwrite);
        st["rationale"] = s.rationale;
        steps.push_back(std::move(st));
    }
    j["steps"] = std::move(steps);

    Json& v = j["verification"];
    v["kind"] = plan.verification.kind == VerificationExpectation::Kind::Pattern       ? "pattern"
                : plan.verification.kind == VerificationExpectation::Kind::Fingerprint ? "fingerprint"
                                                                                        : "not-applicable";
    if (plan.verification.expected) v["expected"] = to_json(*plan.verification.expected);
    v["reason"] = plan.verification.reason;

    Json w = Json::array();
    for (const auto& s : plan.warnings) w.push_back(s);
    j["warnings"] = std::move(w);
    return j;
}

}  // namespace dw
