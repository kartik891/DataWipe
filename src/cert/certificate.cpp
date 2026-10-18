#include "cert/certificate.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <chrono>
#include <format>

#include "core/sha256.hpp"
#include "engine/pattern.hpp"
#include "engine/run_journal.hpp"

#ifndef DW_VERSION
#define DW_VERSION "dev"
#endif

namespace dw {

namespace {

constexpr std::string_view kSchema = "datawipe.certificate.v2";
constexpr std::string_view kSignatureTag = "DataWipe-TECC-v1";

// What the signature covers: a domain tag, a zero byte, then the 32-byte terminal hash.
std::vector<std::uint8_t> signed_message(const tecc::Hash& terminal) {
    std::vector<std::uint8_t> m(kSignatureTag.begin(), kSignatureTag.end());
    m.push_back(0);
    m.insert(m.end(), terminal.begin(), terminal.end());
    return m;
}

Result<std::vector<std::uint8_t>> bytes_from_hex(std::string_view s, std::size_t n) {
    if (s.size() != 2 * n) return error(std::format("expected {} hex digits", 2 * n));
    std::vector<std::uint8_t> out(n);
    for (std::size_t i = 0; i < n; ++i) {
        auto nib = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            return -1;
        };
        const int a = nib(s[2 * i]), b = nib(s[2 * i + 1]);
        if (a < 0 || b < 0) return error("non-hex digit");
        out[i] = static_cast<std::uint8_t>(a << 4 | b);
    }
    return out;
}


}  // namespace

// RFC 4122 version-4 UUID from the kernel CSPRNG.
std::string random_uuid() {
    auto r = random_pattern_key();
    if (!r) return "00000000-0000-4000-8000-000000000000";
    auto b = *r;
    b[6] = static_cast<std::uint8_t>((b[6] & 0x0F) | 0x40);
    b[8] = static_cast<std::uint8_t>((b[8] & 0x3F) | 0x80);
    const std::string h = to_hex(std::span<const std::uint8_t>(b.data(), 16));
    return h.substr(0, 8) + "-" + h.substr(8, 4) + "-" + h.substr(12, 4) + "-" + h.substr(16, 4) + "-" + h.substr(20);
}

std::string_view step_status(StepRecord::Status s) {
    switch (s) {
        case StepRecord::Status::Completed: return "completed";
        case StepRecord::Status::Failed: return "failed";
        case StepRecord::Status::Aborted: return "aborted";
        case StepRecord::Status::NotRun: return "not-run";
    }
    return "?";
}

namespace {

// The signed body: every top-level member except the `tecc` seal.
Json body_of(const Json& cert) {
    Json body = Json::object();
    for (const auto& [k, v] : cert.members())
        if (k != "tecc") body[k] = v;
    return body;
}

}  // namespace

std::string_view certificate_outcome(const CertificateInput& in) {
    if (!in.result.success) return "incomplete";
    if (in.plan.fully_simulated()) return "simulated";
    switch (in.verification.status) {
        case VerificationResult::Status::Passed: return "sanitized";
        case VerificationResult::Status::Repaired: return "sanitized-with-repairs";
        case VerificationResult::Status::Failed: return "verification-failed";
        case VerificationResult::Status::Inconclusive:
        case VerificationResult::Status::NotApplicable:
        case VerificationResult::Status::Interrupted:  // no certificate is issued in this state
        case VerificationResult::Status::Skipped: return "sanitized-unverified";
    }
    return "incomplete";
}

Json certificate_body(const CertificateInput& in, const std::string& certificate_id, const std::string& issued_at,
                      const std::string& session_id) {
    Json c = Json::object();
    c["schema"] = kSchema;
    c["certificate_id"] = certificate_id;
    c["session_id"] = session_id;
    c["issued_at"] = issued_at;
    c["tool"]["name"] = "datawipe";
    c["tool"]["version"] = DW_VERSION;

    c["outcome"] = certificate_outcome(in);
    if (in.verification.sci.defined) c["sci_score"] = in.verification.sci.sci;
    else c["sci_score"] = nullptr;
    c["device"] = to_json(in.profile);

    Json& s = c["sanitization"];
    s["method_id"] = in.plan.method_id;
    s["method_name"] = in.plan.method_name;
    Json standards = Json::array();
    for (const auto& st : in.plan.standards) standards.push_back(st);
    s["standards"] = std::move(standards);
    s["nist_level_planned"] = to_string(in.plan.level);
    s["nist_level_achieved"] = to_string(in.result.achieved);
    s["plan_sha256"] = plan_digest(in.plan);
    if (in.pattern_key) {
        s["pattern_key"] = to_hex(*in.pattern_key);
        s["pattern_key_fingerprint"] = key_fingerprint(*in.pattern_key);
    }
    if (in.plan.verification.kind == VerificationExpectation::Kind::Pattern && in.plan.verification.expected) {
        const OverwriteSpec& o = *in.plan.verification.expected;
        Json& f = s["final_overwrite"];
        f["first_sector"] = o.first_sector;
        f["sector_count"] = o.sector_count;
        f["kind"] = o.pattern.kind == PatternSpec::Kind::Prng ? "prng" : "fixed32";
        f["stream"] = o.pattern.stream;
        f["value"] = o.pattern.value;
    }
    if (!in.started_at.empty()) s["started_at"] = in.started_at;
    s["runs"] = in.runs;

    // Honesty about each step: which effects are genuine in this environment.
    Json steps = Json::array();
    Json caveats = Json::array();
    for (std::size_t i = 0; i < in.plan.steps.size(); ++i) {
        const WipeStep& ps = in.plan.steps[i];
        Json sj = Json::object();
        sj["title"] = ps.title;
        sj["execution"] = to_string(ps.execution);
        sj["level"] = to_string(ps.level);
        if (i < in.result.steps.size()) {
            const StepRecord& rs = in.result.steps[i];
            sj["status"] = step_status(rs.status);
            if (rs.bytes_written) sj["bytes_written_last_run"] = rs.bytes_written;
            if (!rs.error.empty()) sj["error"] = rs.error;
        } else {
            sj["status"] = "not-run";
        }
        if (ps.overwrite) {
            sj["overwrite"]["first_sector"] = ps.overwrite->first_sector;
            sj["overwrite"]["sector_count"] = ps.overwrite->sector_count;
            sj["overwrite"]["pattern"] = ps.overwrite->pattern.describe();
        }
        Json cmds = Json::array();
        for (const auto& cmd : ps.commands) cmds.push_back(cmd.describe());
        if (!ps.commands.empty()) sj["device_commands"] = std::move(cmds);
        steps.push_back(std::move(sj));

        if (ps.execution == Execution::Emulated && !ps.commands.empty())
            caveats.push_back(std::format("step {} ({}): the device command was logged, not sent; its effect on "
                                          "the medium was reproduced with real host writes",
                                          i + 1, ps.title));
        else if (ps.execution == Execution::Simulated)
            caveats.push_back(std::format("step {} ({}): SIMULATED, the command was logged, not sent; the medium "
                                          "was not modified by it",
                                          i + 1, ps.title));
    }
    s["steps"] = std::move(steps);
    for (const auto& w : in.plan.warnings)
        if (!w.starts_with("REAL DEVICE:")) caveats.push_back(w);  // a pre-run warning, not a caveat of the result
    c["verification"] = to_json(in.verification);
    c["caveats"] = std::move(caveats);
    return c;
}

Result<Json> seal_certificate(Json body, tecc::SessionChain& chain, const ed25519::PrivateKey* key,
                              const std::string& log_name) {
    const Json* issued = body.find("issued_at");
    if (!issued || !issued->is_string()) return error("certificate body lacks issued_at");
    const std::string time = issued->as_string().value();
    const tecc::Hash prev = chain.last();
    auto terminal = chain.append("certificate", body, time);
    if (!terminal) return terminal.error();

    Json& t = body["tecc"];
    t["scheme"] = "TECC v1: H0 = SHA-256('DataWipe-TECC-genesis-v1' 0x00 || session_id); Hi = SHA-256(H(i-1) || "
                  "compact JSON of {i, stage, time, data}); the certificate body (all members but 'tecc') is the last "
                  "entry; Ed25519 signs 'DataWipe-TECC-v1' 0x00 || H(k)";
    t["session_id"] = chain.session_id();
    t["genesis_hash"] = tecc::hex(chain.genesis());
    t["log_file"] = log_name;
    t["entries"] = chain.count();
    t["certificate_entry"]["i"] = chain.count();
    t["certificate_entry"]["prev_hash"] = tecc::hex(prev);
    t["terminal_hash"] = tecc::hex(*terminal);
    if (key) {
        auto sig = key->sign(signed_message(*terminal));
        if (!sig) return sig.error();
        const auto pub = key->public_key();
        Json& g = t["signature"];
        g["algorithm"] = "Ed25519";
        g["key_id"] = ed25519::key_id(pub);
        g["public_key"] = to_hex(std::span<const std::uint8_t>(pub));
        g["value"] = to_hex(std::span<const std::uint8_t>(*sig));
    } else {
        t["signature"] = nullptr;
        t["unsigned_reason"] = "no signing key was given (--sign-key); the chain proves integrity, not origin";
    }
    return body;
}

Result<CertificateCheck> check_certificate(const Json& cert, const std::optional<ed25519::PublicKey>& trusted) {
    if (!cert.is_object()) return error("certificate is not a JSON object");
    const Json* schema = cert.find("schema");
    if (!schema || !schema->is_string() || schema->as_string().value() != kSchema)
        return error(std::format("not a {} document", kSchema));
    const Json* t = cert.find("tecc");
    if (!t || !t->is_object()) return error("certificate has no TECC seal");
    auto str = [&](const Json* o, std::string_view k) -> Result<std::string> {
        const Json* v = o ? o->find(k) : nullptr;
        if (!v || !v->is_string()) return error(std::format("TECC seal lacks '{}'", k));
        return v->as_string().value();
    };
    CertificateCheck r;
    auto session = str(t, "session_id");
    auto genesis = str(t, "genesis_hash");
    auto terminal = str(t, "terminal_hash");
    auto prev = str(t->find("certificate_entry"), "prev_hash");
    auto issued = str(&cert, "issued_at");
    auto body_session = str(&cert, "session_id");
    for (const Result<std::string>* x : {&session, &genesis, &terminal, &prev, &issued, &body_session})
        if (!*x) return x->error();
    const Json* idx = t->find("certificate_entry")->find("i");
    auto k = idx ? idx->as_u64() : Result<std::uint64_t>(error("TECC seal lacks certificate_entry.i"));
    if (!k) return k.error();
    if (*session != *body_session) return error("the seal's session id differs from the certificate's");
    if (*genesis != tecc::hex(tecc::genesis_hash(*session))) return error("the genesis hash does not match the session id");
    auto prev_hash = tecc::hash_from_hex(*prev);
    if (!prev_hash) return error("certificate_entry.prev_hash: " + prev_hash.error().message);

    // Recompute the terminal hash from the body as it stands now.
    const tecc::Hash h = tecc::entry_hash(*prev_hash, tecc::entry_object(*k, "certificate", *issued, body_of(cert)));
    if (tecc::hex(h) != *terminal)
        return error(std::format("TECC check FAILED: the certificate hashes to {} but its seal says {}; it was "
                                 "modified after issue",
                                 tecc::hex(h), *terminal));
    r.session_id = *session;
    r.terminal_hash = *terminal;
    r.entries = *k;

    const Json* sig = t->find("signature");
    if (sig && sig->is_object()) {
        auto pub_hex = str(sig, "public_key");
        auto val_hex = str(sig, "value");
        if (!pub_hex || !val_hex) return error("malformed signature");
        auto pub = bytes_from_hex(*pub_hex, 32);
        auto val = bytes_from_hex(*val_hex, 64);
        if (!pub || !val) return error("malformed signature");
        ed25519::PublicKey pk{};
        ed25519::Signature sv{};
        std::copy(pub->begin(), pub->end(), pk.begin());
        std::copy(val->begin(), val->end(), sv.begin());
        if (!ed25519::verify(pk, signed_message(h), sv))
            return error("signature INVALID: the seal was not produced by the key it names (forged or altered)");
        r.signed_by = pk;
        r.key_id = ed25519::key_id(pk);
        if (trusted) {
            if (*trusted != pk)
                return error(std::format("signed by key {}, which is NOT the trusted key {}", r.key_id,
                                         ed25519::key_id(*trusted)));
            r.trusted = true;
        }
    } else if (trusted) {
        return error("certificate is UNSIGNED, but a trusted key was required");
    }
    return r;
}

Result<void> audit_session_log(const Json& cert, const tecc::VerifiedLog& log) {
    auto check = check_certificate(cert, std::nullopt);
    if (!check) return check.error();
    if (log.session_id != check->session_id)
        return error(std::format("the log belongs to session {}, the certificate to {}", log.session_id,
                                 check->session_id));
    if (log.entries.size() != check->entries)
        return error(std::format("the log has {} entries, the certificate seals {}", log.entries.size(), check->entries));
    const auto& last = log.entries.back();
    if (last.stage != "certificate" || tecc::hex(last.hash) != check->terminal_hash)
        return error("the log's last entry is not this certificate");
    return ok();
}

Result<CertifiedContent> certified_content(const Json& cert) {
    auto at = [&](std::initializer_list<std::string_view> path) -> const Json* {
        const Json* j = &cert;
        for (auto k : path) j = j ? j->find(k) : nullptr;
        return j;
    };
    auto str = [&](std::initializer_list<std::string_view> path) -> Result<std::string> {
        const Json* j = at(path);
        if (!j) return error("certificate lacks " + std::string(*(path.end() - 1)));
        return j->as_string();
    };
    auto num = [&](std::initializer_list<std::string_view> path) -> Result<std::uint64_t> {
        const Json* j = at(path);
        if (!j) return error("certificate lacks " + std::string(*(path.end() - 1)));
        return j->as_u64();
    };

    CertifiedContent c;
    if (auto o = str({"outcome"})) c.outcome = *o;
    const Json* f = at({"sanitization", "final_overwrite"});
    if (!f)
        return error(std::format("this certificate records no host-written pattern (outcome '{}'): there is "
                                 "nothing to read back",
                                 c.outcome));
    auto key_hex = str({"sanitization", "pattern_key"});
    if (!key_hex) return key_hex.error();
    auto key = pattern_key_from_hex(*key_hex);
    if (!key) return key.error();
    c.key = *key;

    auto first = num({"sanitization", "final_overwrite", "first_sector"});
    auto count = num({"sanitization", "final_overwrite", "sector_count"});
    auto stream = num({"sanitization", "final_overwrite", "stream"});
    auto value = num({"sanitization", "final_overwrite", "value"});
    auto kind = str({"sanitization", "final_overwrite", "kind"});
    auto size = num({"device", "geometry", "size_bytes"});
    auto lss = num({"device", "geometry", "logical_sector_size"});
    auto path = str({"device", "path"});
    for (const Result<std::uint64_t>* r : {&first, &count, &stream, &value, &size, &lss})
        if (!*r) return r->error();
    if (!kind) return kind.error();
    if (!path) return path.error();
    if (*kind != "prng" && *kind != "fixed32") return error("unknown final_overwrite.kind '" + *kind + "'");
    if (*stream > UINT32_MAX || *value > UINT32_MAX || *lss > UINT32_MAX) return error("final_overwrite out of range");

    c.expected.first_sector = *first;
    c.expected.sector_count = *count;
    c.expected.pattern.kind = *kind == "prng" ? PatternSpec::Kind::Prng : PatternSpec::Kind::Fixed32;
    c.expected.pattern.stream = static_cast<std::uint32_t>(*stream);
    c.expected.pattern.value = static_cast<std::uint32_t>(*value);
    c.size_bytes = *size;
    c.logical_sector_size = static_cast<std::uint32_t>(*lss);
    c.device_path = *path;
    auto backing = str({"device", "backing_file"});
    c.medium = backing ? *backing : c.device_path;
    if (const Json* s = at({"verification", "sampler"}); s && s->find("name") && s->find("name")->is_string() &&
                                                         s->find("name")->as_string().value() == "arvs") {
        const Json* rc = s->find("risk_context");
        if (!rc) return error("certificate: ARVS sampler without risk_context");
        auto ctx = risk_context_from_json(*rc);
        if (!ctx) return error("certificate: " + ctx.error().message);
        c.risk = *ctx;
        if (const Json* m = s->find("ahp") ? s->find("ahp")->find("pairwise") : nullptr) {
            PairwiseMatrix pm{};
            if (m->items().size() != kFactors) return error("certificate: AHP matrix is not 5x5");
            for (int i = 0; i < kFactors; ++i) {
                const auto& row = m->items()[i].items();
                if (row.size() != kFactors) return error("certificate: AHP matrix is not 5x5");
                for (int k = 0; k < kFactors; ++k) {
                    auto v = row[k].as_double();
                    if (!v) return error("certificate: AHP entry: " + v.error().message);
                    pm[i][k] = *v;
                }
            }
            c.judgments = pm;
        }
    }
    return c;
}

Result<void> write_certificate(const Json& cert, const std::string& path) { return write_new_file(path, cert.dump(2) + "\n"); }

Result<void> write_new_file(const std::string& path, std::string_view text) {
    int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0644);
    if (fd < 0) return sys_error("create " + path);
    std::size_t done = 0;
    while (done < text.size()) {
        ssize_t n = ::write(fd, text.data() + done, text.size() - done);
        if (n < 0) {
            if (errno == EINTR) continue;
            const int err = errno;
            ::close(fd);
            return sys_error("write " + path, err);
        }
        done += static_cast<std::size_t>(n);
    }
    const bool synced = ::fsync(fd) == 0;
    const int err = errno;
    ::close(fd);
    if (!synced) return sys_error("fsync " + path, err);
    return ok();
}

CertificatePaths certificate_paths(const DeviceProfile& profile) {
    const auto now = std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now());
    const std::string base = std::format("{}.{:%Y%m%dT%H%M%SZ}", session_file_base(profile), now);
    return {base + ".dwcert.json", base + ".dwlog.jsonl", base + ".dwcert.pdf"};
}

CertificatePaths certificate_paths(const std::string& json_path) {
    std::string base = json_path;
    if (base.ends_with(".json")) base.resize(base.size() - 5);
    return {json_path, base + ".dwlog.jsonl", base + ".pdf"};
}

}  // namespace dw
