#include "engine/run_journal.hpp"

#include "core/portable.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <cctype>
#include <format>
#include <fstream>
#include <sstream>

#include "core/log.hpp"
#include "core/sha256.hpp"

namespace dw {

namespace {

constexpr std::string_view kSchema = "datawipe.journal.v1";

std::string now_utc() {
    return std::format("{:%FT%TZ}", std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now()));
}

[[maybe_unused]] std::string parent_dir(const std::string& path) {
    const auto slash = dw::last_separator(path);
    if (slash == std::string::npos) return ".";
    return slash == 0 ? "/" : path.substr(0, slash);
}

// Under sudo, hand the journal to the invoking user like the image it sits next to.
void chown_to_sudo_user([[maybe_unused]] int fd) {
#ifndef _WIN32
    if (::geteuid() != 0) return;
    const char* uid = std::getenv("SUDO_UID");
    const char* gid = std::getenv("SUDO_GID");
    if (!uid || !gid) return;
    if (::fchown(fd, static_cast<uid_t>(std::strtoul(uid, nullptr, 10)),
                 static_cast<gid_t>(std::strtoul(gid, nullptr, 10))) != 0)
        log::debug("fchown journal: {}", std::strerror(errno));
#endif
}

Result<void> write_all(int fd, std::string_view text) {
    std::size_t done = 0;
    while (done < text.size()) {
        ssize_t n = ::write(fd, text.data() + done, text.size() - done);
        if (n < 0) {
            if (errno == EINTR) continue;
            return sys_error("write");
        }
        done += static_cast<std::size_t>(n);
    }
    return ok();
}

template <typename T>
Result<T> field(const Json& j, std::string_view key, Result<T> (Json::*get)() const) {
    const Json* v = j.find(key);
    if (!v) return error(std::format("journal: missing '{}'", key));
    auto r = (v->*get)();
    if (!r) return error(std::format("journal: '{}': {}", key, r.error().message));
    return r;
}

}  // namespace

JournalRecord JournalRecord::start(const DeviceProfile& p, const WipePlan& plan, const PatternKey& key) {
    JournalRecord r;
    r.medium = journal_medium(p);
    r.target = p.path;
    r.size_bytes = p.geometry.size_bytes;
    r.logical_sector_size = p.geometry.logical_sector_size;
    r.model = p.identity.model;
    r.serial = p.identity.serial;
    r.identity_source = std::string(to_string(p.identity_source));
    r.method_id = plan.method_id;
    r.plan_sha256 = plan_digest(plan);
    r.key = key;
    r.started_at = r.updated_at = now_utc();
    return r;
}

Json to_json(const JournalRecord& r) {
    Json j = Json::object();
    j["schema"] = kSchema;
    j["medium"] = r.medium;
    j["target"] = r.target;
    j["size_bytes"] = r.size_bytes;
    j["logical_sector_size"] = r.logical_sector_size;
    j["model"] = r.model;
    j["serial"] = r.serial;
    j["identity_source"] = r.identity_source;
    j["method_id"] = r.method_id;
    j["plan_sha256"] = r.plan_sha256;
    j["pattern_key"] = to_hex(r.key);
    j["step"] = r.position.step;
    j["commands_done"] = r.position.commands_done;
    j["sectors_done"] = r.position.sectors_done;
    j["started_at"] = r.started_at;
    j["updated_at"] = r.updated_at;
    j["runs"] = r.runs;
    Json resumes = Json::array();
    for (const auto& [step, sector] : r.resumes) {
        Json e = Json::object();
        e["step"] = step;
        e["sector"] = sector;
        resumes.push_back(std::move(e));
    }
    j["resumes"] = std::move(resumes);
    j["session_id"] = r.session_id;
    j["log_path"] = r.log_path;
    j["cert_path"] = r.cert_path;
    j["chain_entries"] = r.chain_entries;
    j["chain_last"] = r.chain_last;
    if (!r.fingerprint_path.empty()) j["fingerprint_path"] = r.fingerprint_path;
    return j;
}

Result<JournalRecord> journal_from_json(const Json& j) {
    if (!j.is_object()) return error("journal: not a JSON object");
    auto schema = field(j, "schema", &Json::as_string);
    if (!schema) return schema.error();
    if (*schema != kSchema) return error("journal: unsupported schema '" + *schema + "'");

    JournalRecord r;
    auto str = [&](std::string_view k, std::string& out) -> Result<void> {
        auto v = field(j, k, &Json::as_string);
        if (!v) return v.error();
        out = std::move(v).value();
        return ok();
    };
    auto u64 = [&](std::string_view k, std::uint64_t& out) -> Result<void> {
        auto v = field(j, k, &Json::as_u64);
        if (!v) return v.error();
        out = *v;
        return ok();
    };
    std::string key_hex;
    std::uint64_t sector_size = 0, step = 0, runs = 0;
    bool commands_done = false;
    for (auto res : {str("medium", r.medium), str("target", r.target), u64("size_bytes", r.size_bytes),
                     u64("logical_sector_size", sector_size), str("model", r.model), str("serial", r.serial),
                     str("identity_source", r.identity_source), str("method_id", r.method_id),
                     str("plan_sha256", r.plan_sha256), str("pattern_key", key_hex), u64("step", step),
                     u64("sectors_done", r.position.sectors_done), str("started_at", r.started_at),
                     str("updated_at", r.updated_at), u64("runs", runs), str("session_id", r.session_id),
                     str("log_path", r.log_path), str("cert_path", r.cert_path),
                     u64("chain_entries", r.chain_entries), str("chain_last", r.chain_last)})
        if (!res) return res.error();
    auto cd = field(j, "commands_done", &Json::as_bool);
    if (!cd) return cd.error();
    commands_done = *cd;
    auto key = pattern_key_from_hex(key_hex);
    if (!key) return error("journal: " + key.error().message);
    if (sector_size == 0 || sector_size > 65536) return error("journal: implausible logical_sector_size");

    r.key = *key;
    r.logical_sector_size = static_cast<std::uint32_t>(sector_size);
    r.position = {static_cast<std::size_t>(step), commands_done, r.position.sectors_done};
    r.runs = static_cast<unsigned>(runs);
    if (const Json* res = j.find("resumes"))  // absent in journals from before ARVS
        for (const auto& e : res->items()) {
            auto st = e.find("step") ? e.find("step")->as_u64() : Result<std::uint64_t>(error("missing step"));
            auto se = e.find("sector") ? e.find("sector")->as_u64() : Result<std::uint64_t>(error("missing sector"));
            if (!st || !se) return error("journal: malformed 'resumes' entry");
            r.resumes.emplace_back(static_cast<std::size_t>(*st), *se);
        }
    if (const Json* fp = j.find("fingerprint_path")) {
        auto v = fp->as_string();
        if (!v) return error("journal: 'fingerprint_path': " + v.error().message);
        r.fingerprint_path = *v;
    }
    return r;
}

std::string plan_digest(const WipePlan& plan) { return Sha256::hex(to_json(plan).dump()); }

std::string journal_medium(const DeviceProfile& p) {
    // A physical disk is named by what it IS, not where it is: /dev/sdb can be /dev/sdc after
    // a reboot, but the drive's serial number does not change.
    if (p.backend == BackendKind::PhysicalBlock)
        return std::format("{}:{}", to_string(p.identity.transport), p.identity.serial);
    return p.backing_file.empty() ? p.path : p.backing_file;
}

std::string session_file_base(const DeviceProfile& p) {
    if (p.backend != BackendKind::PhysicalBlock) return journal_medium(p);
    const char* dir = std::getenv("DATAWIPE_STATE_DIR");
    std::string name = "datawipe-" + p.identity.model + "-" + p.identity.serial;
    for (char& c : name)
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '-' && c != '_' && c != '.') c = '_';
    return std::string(dir && *dir ? dir : ".") + "/" + name;
}

Result<void> check_journal_matches(const JournalRecord& r, const DeviceProfile& p, const WipePlan& plan) {
    auto mismatch = [](std::string_view what, const auto& journal, const auto& now) {
        return error(std::format("journal does not match this target: {} is '{}' in the journal but '{}' now", what,
                                 journal, now));
    };
    if (r.medium != journal_medium(p)) return mismatch("medium", r.medium, journal_medium(p));
    if (r.size_bytes != p.geometry.size_bytes) return mismatch("size_bytes", r.size_bytes, p.geometry.size_bytes);
    if (r.logical_sector_size != p.geometry.logical_sector_size)
        return mismatch("logical_sector_size", r.logical_sector_size, p.geometry.logical_sector_size);
    if (r.serial != p.identity.serial) return mismatch("serial", r.serial, p.identity.serial);
    if (r.model != p.identity.model) return mismatch("model", r.model, p.identity.model);
    if (r.method_id != plan.method_id) return mismatch("method", r.method_id, plan.method_id);
    if (r.plan_sha256 != plan_digest(plan))
        return error("journal does not match this target: the plan changed since the interrupted run (same method '" +
                     plan.method_id + "' but different steps, ranges or options, e.g. --keep-hidden)");
    return ok();
}

Result<std::string> RunJournal::default_path(const DeviceProfile& p) {
    if (p.backend == BackendKind::PhysicalBlock && p.identity.serial.empty())
        return error("the drive reports no serial number; pass --journal <path>");
    return session_file_base(p) + ".dwjournal";
}

Result<std::optional<JournalRecord>> RunJournal::load() const {
    std::ifstream in(path_);
    if (!in) {
        if (errno == ENOENT) return std::optional<JournalRecord>{};
        return sys_error("open journal " + path_);
    }
    std::stringstream ss;
    ss << in.rdbuf();
    auto j = Json::parse(ss.str());
    if (!j) return error("journal " + path_ + " is corrupt: " + j.error().message);
    auto r = journal_from_json(*j);
    if (!r) return error(path_ + ": " + r.error().message);
    return std::optional<JournalRecord>(std::move(r).value());
}

Result<void> RunJournal::begin(JournalRecord record) {
    rec_ = std::move(record);
    rec_.updated_at = now_utc();
    return write_atomic(to_json(rec_).dump(2) + "\n");
}

void RunJournal::set_chain(std::uint64_t entries, const std::string& last_hex) {
    rec_.chain_entries = entries;
    rec_.chain_last = last_hex;
    rec_.updated_at = now_utc();
    if (auto r = write_atomic(to_json(rec_).dump(2) + "\n"); !r)
        log::warn("could not record the session chain in journal {} ({}); a resume will refuse this log", path_,
                  r.error().describe());
}

void RunJournal::save(const ResumePoint& point) {
    rec_.position = point;
    rec_.updated_at = now_utc();
    if (auto r = write_atomic(to_json(rec_).dump(2) + "\n"); !r && !std::exchange(warned_, true))
        log::warn("could not update journal {} ({}); an interruption now resumes from an earlier point",
                  path_, r.error().describe());
}

Result<void> RunJournal::remove() {
    if (::unlink(path_.c_str()) != 0 && errno != ENOENT) return sys_error("unlink " + path_);
    return ok();
}

Result<void> RunJournal::write_atomic(const std::string& text) const {
    const std::string tmp = path_ + ".tmp";
    int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return sys_error("create " + tmp);
    chown_to_sudo_user(fd);
    auto w = write_all(fd, text);
    if (w && ::fdatasync(fd) != 0) w = sys_error("fdatasync " + tmp);
    ::close(fd);
    if (!w) {
        ::unlink(tmp.c_str());
        return w;
    }
    if (dw::replace_file(tmp.c_str(), path_.c_str()) != 0) return sys_error("rename " + tmp + " -> " + path_);
#ifdef _WIN32
    return ok();  // replace_file() wrote through; a directory cannot be opened for syncing here
#else
    // The rename itself lives in the directory: make it durable too.
    const std::string dir = parent_dir(path_);
    int dfd = ::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dfd < 0) return sys_error("open directory " + dir);
    const bool synced = ::fsync(dfd) == 0;
    const int err = errno;
    ::close(dfd);
    if (!synced) return sys_error("fsync directory " + dir, err);
    return ok();
#endif
}

}  // namespace dw
