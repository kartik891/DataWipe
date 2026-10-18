#pragma once
// TECC session chain (paper Section III-D, Fig. 2): a hash-linked log of one sanitization session.
//
//   H0 = SHA-256("DataWipe-TECC-genesis-v1" 0x00 || session_id)
//   Hi = SHA-256(H(i-1) || canonical(entry_i)),  entry_i = {"i", "stage", "time", "data"}
//
// canonical() is the compact serialization of core/json.hpp (insertion-ordered keys, numbers
// kept as their literal text), so a hash computed at write time is recomputed exactly from
// the file. Changing, removing, reordering or inserting any entry changes every later hash.
//
// Stages written by `datawipe run`: detection, plan, execution (or interrupted, then resume,
// ..., execution), verification, certificate. The certificate is the last entry, so its hash
// is the terminal hash that the certificate's signature covers (cert/certificate.hpp).
//
// File (<base>.dwlog.jsonl): one JSON object per line. Line 1 is the header
//   {"schema": "datawipe.session.v1", "session_id": ..., "genesis": hex(H0)}
// then one line per entry: {"i", "stage", "time", "data", "prev": hex, "hash": hex}.
// Every append is fsynced before it counts. An interrupted wipe keeps (entries, last hash) in
// its journal; on resume the whole file is re-verified and must still contain that hash at
// that position, so a log edited or truncated while the wipe was paused is refused.

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "core/json.hpp"
#include "core/result.hpp"

namespace dw::tecc {

using Hash = std::array<std::uint8_t, 32>;

std::string hex(const Hash& h);
Result<Hash> hash_from_hex(std::string_view s);

Hash genesis_hash(const std::string& session_id);
Json entry_object(std::uint64_t index, const std::string& stage, const std::string& time, const Json& data);
Hash entry_hash(const Hash& prev, const Json& entry_object);

struct ChainEntry {
    std::uint64_t index = 0;  // 1-based
    std::string stage;
    std::string time;
    Json data;
    Hash prev{}, hash{};
};

struct VerifiedLog {
    std::string session_id;
    Hash genesis{};
    std::vector<ChainEntry> entries;
    Hash terminal() const { return entries.empty() ? genesis : entries.back().hash; }
};

// Reads a log file and recomputes every hash; any mismatch is an error naming the line.
Result<VerifiedLog> read_and_verify_log(const std::string& path);

class SessionChain {
public:
    // New log file (never overwrites).
    static Result<SessionChain> create(const std::string& path, const std::string& session_id);
    // Existing log: verified in full, and entry `expect_count` must have hash `expect_last`
    // (what the journal recorded). Entries after it (written just before a crash, before the
    // journal caught up) are accepted: they are chained, so they cannot have been forged.
    static Result<SessionChain> resume(const std::string& path, std::uint64_t expect_count, const Hash& expect_last);

    // Appends and fsyncs one entry; returns its hash.
    Result<Hash> append(const std::string& stage, Json data, std::string time = {});

    const std::string& path() const { return path_; }
    const std::string& session_id() const { return session_id_; }
    const Hash& genesis() const { return genesis_; }
    const Hash& last() const { return last_; }
    std::uint64_t count() const { return count_; }

private:
    std::string path_, session_id_;
    Hash genesis_{}, last_{};
    std::uint64_t count_ = 0;
};

std::string utc_now();

}  // namespace dw::tecc
