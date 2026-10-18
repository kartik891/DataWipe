#include "tecc/session_chain.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <chrono>
#include <cstring>
#include <format>
#include <fstream>

#include "core/sha256.hpp"

namespace dw::tecc {

namespace {

constexpr std::string_view kSchema = "datawipe.session.v1";
constexpr std::string_view kGenesisTag = "DataWipe-TECC-genesis-v1";

Result<void> append_line(const std::string& path, const std::string& line, bool create) {
    const int flags = O_WRONLY | O_APPEND | O_CLOEXEC | O_NOFOLLOW | (create ? O_CREAT | O_EXCL : 0);
    int fd = ::open(path.c_str(), flags, 0644);
    if (fd < 0) return sys_error((create ? "create " : "open ") + path);
    const std::string text = line + "\n";
    for (std::size_t done = 0; done < text.size();) {
        ssize_t n = ::write(fd, text.data() + done, text.size() - done);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) {
            const int err = errno;
            ::close(fd);
            return sys_error("write " + path, err);
        }
        done += static_cast<std::size_t>(n);
    }
    const bool synced = ::fdatasync(fd) == 0;
    ::close(fd);
    if (!synced) return sys_error("fdatasync " + path);
    return ok();
}

}  // namespace

std::string utc_now() {
    return std::format("{:%FT%TZ}", std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now()));
}

std::string hex(const Hash& h) { return to_hex(std::span<const std::uint8_t>(h)); }

Result<Hash> hash_from_hex(std::string_view s) {
    if (s.size() != 64) return error("hash must be 64 hex digits");
    Hash h{};
    for (std::size_t i = 0; i < 32; ++i) {
        auto nib = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            return -1;
        };
        const int a = nib(s[2 * i]), b = nib(s[2 * i + 1]);
        if (a < 0 || b < 0) return error("hash has a non-hex (or upper-case) digit");
        h[i] = static_cast<std::uint8_t>(a << 4 | b);
    }
    return h;
}

Hash genesis_hash(const std::string& session_id) {
    Sha256 s;
    s.update(kGenesisTag);
    s.update(std::string_view("\0", 1));
    s.update(session_id);
    return s.finish();
}

Json entry_object(std::uint64_t index, const std::string& stage, const std::string& time, const Json& data) {
    Json e = Json::object();
    e["i"] = index;
    e["stage"] = stage;
    e["time"] = time;
    e["data"] = data;
    return e;
}

Hash entry_hash(const Hash& prev, const Json& entry) {
    Sha256 s;
    s.update(std::as_bytes(std::span(prev)));
    s.update(entry.dump());
    return s.finish();
}

Result<VerifiedLog> read_and_verify_log(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return sys_error("open " + path);
    VerifiedLog log;
    std::string line;
    std::uint64_t lineno = 0;
    Hash prev{};
    while (std::getline(in, line)) {
        ++lineno;
        if (line.empty()) continue;
        auto j = Json::parse(line);
        if (!j) return error(std::format("{} line {}: {}", path, lineno, j.error().message));
        auto str = [&](const Json& o, std::string_view k) -> Result<std::string> {
            const Json* v = o.find(k);
            if (!v) return error(std::format("{} line {}: missing '{}'", path, lineno, k));
            return v->as_string();
        };
        if (lineno == 1) {
            auto schema = str(*j, "schema");
            auto sid = str(*j, "session_id");
            auto gen = str(*j, "genesis");
            if (!schema || *schema != kSchema) return error(path + ": not a datawipe session log");
            if (!sid || !gen) return error(path + ": malformed header");
            log.session_id = *sid;
            log.genesis = genesis_hash(*sid);
            if (*gen != hex(log.genesis)) return error(path + ": header genesis hash does not match the session id");
            prev = log.genesis;
            continue;
        }
        ChainEntry e;
        const Json* i = j->find("i");
        const Json* data = j->find("data");
        auto stage = str(*j, "stage");
        auto time = str(*j, "time");
        auto prev_hex = str(*j, "prev");
        auto hash_hex = str(*j, "hash");
        if (!i || !data || !stage || !time || !prev_hex || !hash_hex)
            return error(std::format("{} line {}: malformed entry", path, lineno));
        auto idx = i->as_u64();
        if (!idx || *idx != log.entries.size() + 1)
            return error(std::format("{} line {}: entry number {} out of sequence (expected {})", path, lineno,
                                     idx ? *idx : 0, log.entries.size() + 1));
        if (*prev_hex != hex(prev))
            return error(std::format("{} line {}: 'prev' does not link to entry {}", path, lineno, *idx - 1));
        e.index = *idx;
        e.stage = *stage;
        e.time = *time;
        e.data = *data;
        e.prev = prev;
        e.hash = entry_hash(prev, entry_object(e.index, e.stage, e.time, e.data));
        if (hex(e.hash) != *hash_hex)
            return error(std::format("{} line {} (entry {}, '{}'): content does not match its hash; the log was "
                                     "modified",
                                     path, lineno, e.index, e.stage));
        prev = e.hash;
        log.entries.push_back(std::move(e));
    }
    if (lineno == 0) return error(path + ": empty session log");
    return log;
}

Result<SessionChain> SessionChain::create(const std::string& path, const std::string& session_id) {
    SessionChain c;
    c.path_ = path;
    c.session_id_ = session_id;
    c.genesis_ = c.last_ = genesis_hash(session_id);
    Json h = Json::object();
    h["schema"] = kSchema;
    h["session_id"] = session_id;
    h["genesis"] = hex(c.genesis_);
    if (auto r = append_line(path, h.dump(), true); !r) return r.error();
    return c;
}

Result<SessionChain> SessionChain::resume(const std::string& path, std::uint64_t expect_count, const Hash& expect_last) {
    auto log = read_and_verify_log(path);
    if (!log) return log.error();
    const Hash at = expect_count == 0 ? log->genesis
                    : expect_count <= log->entries.size() ? log->entries[expect_count - 1].hash
                                                          : Hash{};
    if (expect_count > log->entries.size() || at != expect_last)
        return error(std::format("{} does not contain the {} entries the journal recorded (last hash {}): the log was "
                                 "truncated or replaced",
                                 path, expect_count, hex(expect_last)));
    SessionChain c;
    c.path_ = path;
    c.session_id_ = log->session_id;
    c.genesis_ = log->genesis;
    c.last_ = log->terminal();
    c.count_ = log->entries.size();
    return c;
}

Result<Hash> SessionChain::append(const std::string& stage, Json data, std::string time) {
    if (time.empty()) time = utc_now();
    const Json e = entry_object(count_ + 1, stage, time, data);
    const Hash h = entry_hash(last_, e);
    Json line = e;
    line["prev"] = hex(last_);
    line["hash"] = hex(h);
    if (auto r = append_line(path_, line.dump(), false); !r) return r.error();
    last_ = h;
    ++count_;
    return h;
}

}  // namespace dw::tecc
