#pragma once
// WipePlan: the output of method selection (paper Section III-E), consumed by the plan executor
// and, later, recorded verbatim in the certificate.

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "core/json.hpp"
#include "engine/device_command.hpp"

namespace dw {

// NIST SP 800-88 sanitization categories. Destroy is out of scope for software.
enum class SanitizationLevel { None, Clear, Purge };

// How honestly a step's effect is produced in this environment.
enum class Execution {
    Real,       // genuine host-side writes to the target; exactly what would run on hardware
    Emulated,   // a device-internal command (logged like Simulated) whose effect on the medium is
                // reproduced with real host writes, so read-back verification is meaningful
    Simulated,  // command is built, state-checked and logged; the medium is NOT modified
};

struct PatternSpec {
    enum class Kind { Prng, Fixed32 } kind = Kind::Prng;
    std::uint32_t stream = 0;  // Prng: independent stream id (seed chosen at execution time)
    std::uint32_t value = 0;   // Fixed32: repeating 32-bit little-endian pattern
    std::string describe() const;
};

// A host-visible write pass over a sector range.
struct OverwriteSpec {
    std::uint64_t first_sector = 0;
    std::uint64_t sector_count = 0;
    PatternSpec pattern;
};

struct WipeStep {
    std::string title;
    Execution execution = Execution::Simulated;
    SanitizationLevel level = SanitizationLevel::None;  // None = preparatory step
    std::vector<DeviceCommand> commands;                 // issued in order via ICommandExecutor
    std::optional<OverwriteSpec> overwrite;              // Real / Emulated steps: host writes
    std::string rationale;
};

// What the medium should look like after the plan, for the read-back verifier.
//   Pattern      the last thing to touch the medium is a host overwrite: read back and compare
//   Fingerprint  the last thing is a REAL device-internal erase with vendor-defined output:
//                hash sampled sectors before the plan, require them to differ afterwards
//                (verify/fingerprint.hpp)
//   NotApplicable  the medium is not changed (simulated plan)
struct VerificationExpectation {
    enum class Kind { Pattern, Fingerprint, NotApplicable } kind = Kind::NotApplicable;
    std::optional<OverwriteSpec> expected;  // Pattern: range + final pattern; Fingerprint: range only
    std::string reason;
};

struct WipePlan {
    std::string method_id;  // stable identifier, e.g. "hdd.overwrite+ata-se-enhanced"
    std::string method_name;
    SanitizationLevel level = SanitizationLevel::None;  // achieved if every step succeeds
    std::vector<std::string> standards;
    std::vector<WipeStep> steps;
    VerificationExpectation verification;
    std::vector<std::string> warnings;

    bool has_host_io() const;
    bool fully_simulated() const;
};

std::string_view to_string(SanitizationLevel l);
std::string_view to_string(Execution e);
Json to_json(const WipePlan& plan);

}  // namespace dw
