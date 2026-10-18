#pragma once
// Resume journal: a small JSON file that makes an interrupted wipe a well-defined state.
//
// Without it, a wipe killed at 60% leaves a medium that is part pattern, part old data, and
// nothing that says which part. With it:
//   * the journal is written BEFORE the first destructive action, and names the medium, the
//     drive identity, the exact plan (SHA-256 of its JSON) and the pattern key;
//   * it is advanced only after fdatasync confirms the data (overwrite_engine.hpp), so it may
//     lag the medium but never overstates it;
//   * each update is atomic: write temp file, fdatasync, rename over, fsync the directory. A
//     crash leaves either the old or the new journal, never a torn one;
//   * a resume is refused unless medium, size, sector size, serial and plan digest all match,
//     so a journal can never steer a wipe of the wrong disk or with a different plan;
//   * while a journal exists, a plain `run` refuses to start over it: the operator must choose
//     --resume or --restart explicitly;
//   * it is deleted when the plan completes.
//
// Location: <medium>.dwjournal next to the image file (for a loop device, next to its backing
// file), so the same interrupted wipe is found whether it is continued through the image or
// through a different loop device attached to it. Override with --journal.
//
// The pattern key is stored in the clear. It is not a secret: it only determines the
// overwrite pattern, and the verifier needs it.

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "core/json.hpp"
#include "core/result.hpp"
#include "device/classifier.hpp"
#include "engine/pattern.hpp"
#include "engine/plan_executor.hpp"
#include "engine/wipe_plan.hpp"

namespace dw {

struct JournalRecord {
    std::string medium;  // image file wiped (the loop's backing file for a loop device)
    std::string target;  // path the most recent run used
    std::uint64_t size_bytes = 0;
    std::uint32_t logical_sector_size = 0;
    std::string model;
    std::string serial;
    std::string identity_source;
    std::string method_id;
    std::string plan_sha256;
    PatternKey key{};
    ResumePoint position;
    std::string started_at;
    std::string updated_at;
    unsigned runs = 1;  // 1 + number of resumes
    // Where each resumed run picked up: (step index, absolute sector). The seams between runs
    // are boundaries the ARVS risk model samples preferentially (verify/risk_model.hpp).
    std::vector<std::pair<std::size_t, std::uint64_t>> resumes;
    // TECC session (tecc/session_chain.hpp): the log continues across resumes, and the journal
    // remembers how far it had got, so a log truncated or edited in between is refused.
    std::string session_id;
    std::string log_path;
    std::string cert_path;
    std::uint64_t chain_entries = 0;
    std::string chain_last;  // hex
    // Pre-wipe fingerprints (plans verified by fingerprint): taken before the first destructive
    // command, so a resume must reuse them rather than hash the half-erased medium again.
    std::string fingerprint_path;

    static JournalRecord start(const DeviceProfile& profile, const WipePlan& plan, const PatternKey& key);
};

Json to_json(const JournalRecord& record);
Result<JournalRecord> journal_from_json(const Json& j);

// SHA-256 over the plan's canonical JSON: any change to method, ranges, patterns or commands
// changes the digest.
std::string plan_digest(const WipePlan& plan);

// The medium a profile's wipe writes to (see JournalRecord::medium).
std::string journal_medium(const DeviceProfile& profile);

// Where a session's files (journal, fingerprints, certificate, log) are named from: the image
// path for image files and loop devices; for a physical disk, $DATAWIPE_STATE_DIR (default:
// the current directory) + "datawipe-<model>-<serial>", so they follow the drive, not /dev/sdX.
std::string session_file_base(const DeviceProfile& profile);

// Refuses to resume `record` against anything but the exact medium, drive and plan it recorded.
Result<void> check_journal_matches(const JournalRecord& record, const DeviceProfile& profile, const WipePlan& plan);

class RunJournal final : public IProgressStore {
public:
    explicit RunJournal(std::string path) : path_(std::move(path)) {}
    static Result<std::string> default_path(const DeviceProfile& profile);

    const std::string& path() const { return path_; }

    // nullopt if no journal exists. A file that exists but does not parse is an error, never
    // silently treated as "no journal".
    Result<std::optional<JournalRecord>> load() const;

    // Writes `record` and makes it the one save() advances. Call before the first write.
    Result<void> begin(JournalRecord record);
    // IProgressStore: record the new position. A failed write is logged, not fatal (see top).
    void save(const ResumePoint& point) override;
    // Records the session chain's new length and last hash (after each chain append).
    void set_chain(std::uint64_t entries, const std::string& last_hex);
    Result<void> remove();

    const JournalRecord& record() const { return rec_; }

private:
    Result<void> write_atomic(const std::string& text) const;

    std::string path_;
    JournalRecord rec_;
    bool warned_ = false;
};

}  // namespace dw
