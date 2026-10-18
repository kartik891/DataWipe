#pragma once
// Destruction certificate with TECC seal (paper Sections III-D and VI).
//
// Body: device identity, method, standards, what each step really did (Real / Emulated /
// Simulated), the achieved NIST level, SCI and verification detail, session id, timestamp.
//
// Seal (`tecc`): the body is appended to the session's hash chain (tecc/session_chain.hpp) as
// its last entry, so the terminal hash commits to the whole session history AND to the
// certificate. The seal carries that hash, the previous hash (so the certificate can be
// checked on its own) and an Ed25519 signature over the terminal hash.
//
// What each check proves (threats of paper Table IV):
//   certificate alone        not modified since issue; signed by the key it names
//   + trusted public key     signed by THAT organisation (forgery); the key embedded in the
//                            certificate is a convenience, never a trust anchor
//   + session log            the whole history (detection, plan, execution, interruptions,
//                            verification) is exactly what was hashed (log tampering)
//   device serial + session id in the signed body: a certificate replayed for another device
//   or session does not match it (replay).
// Limits (paper Section VI): only as good as private-key custody, and the auditor must get
// the public key through a trusted channel.
//
// Re-verification: for plans that end in a host-written pattern the certificate carries the
// pattern key and the final pattern's range, so `datawipe verify --cert` can re-read the
// medium later with nothing but the certificate. The key is not a secret (it only decides the
// overwrite pattern; see engine/run_journal.hpp); knowing it lets anyone predict the wiped
// content, which is the point of an auditable wipe.

#include <optional>
#include <string>

#include "core/json.hpp"
#include "core/result.hpp"
#include "device/classifier.hpp"
#include "engine/pattern.hpp"
#include "engine/plan_executor.hpp"
#include "engine/wipe_plan.hpp"
#include "tecc/ed25519.hpp"
#include "tecc/session_chain.hpp"
#include "verify/readback_verifier.hpp"
#include "verify/risk_model.hpp"

namespace dw {

struct CertificateInput {
    const DeviceProfile& profile;
    const WipePlan& plan;
    const PlanRunResult& result;
    const VerificationResult& verification;
    std::optional<PatternKey> pattern_key;  // plans with host writes
    unsigned runs = 1;                      // 1 + resumes
    std::string started_at;                 // UTC, ISO 8601; empty = unknown
};

// Overall verdict written into the certificate, from most to least favourable.
//   sanitized            plan completed, medium changed, read-back passed
//   sanitized-with-repairs  read-back found failures in the sample; they passed after re-wipe,
//                        but unsampled areas may share the defect (SCI < 100 says how much)
//   sanitized-unverified plan completed, medium changed, nothing (informative) to read back
//   simulated            plan completed but every step was SIMULATED: the medium is unchanged
//   verification-failed  plan completed, read-back found sectors without the pattern
//   incomplete           plan did not complete
std::string_view certificate_outcome(const CertificateInput& in);

std::string random_uuid();

// The signed body (everything but the seal).
Json certificate_body(const CertificateInput& in, const std::string& certificate_id, const std::string& issued_at,
                      const std::string& session_id);
// Appends the body to `chain` as the "certificate" entry and adds the `tecc` seal; signs when
// `key` is given. `log_name` is how the seal refers to the chain's file (a basename).
Result<Json> seal_certificate(Json body, tecc::SessionChain& chain, const ed25519::PrivateKey* key,
                              const std::string& log_name);

struct CertificateCheck {
    std::string session_id;
    std::string terminal_hash;
    std::uint64_t entries = 0;
    std::optional<ed25519::PublicKey> signed_by;  // absent: unsigned
    std::string key_id;
    bool trusted = false;  // signed by the key the caller trusts
};
// Recomputes the terminal hash from the body and verifies the signature. With `trusted`, also
// requires the signature to be by that key.
Result<CertificateCheck> check_certificate(const Json& certificate,
                                           const std::optional<ed25519::PublicKey>& trusted = std::nullopt);
// Full audit: the (already verified) session log ends in exactly this certificate.
Result<void> audit_session_log(const Json& certificate, const tecc::VerifiedLog& log);

// What a certificate says the medium must hold, for re-verification.
struct CertifiedContent {
    OverwriteSpec expected;  // final pattern and its sector range
    PatternKey key{};
    std::uint64_t size_bytes = 0;
    std::uint32_t logical_sector_size = 0;
    std::string device_path;  // as wiped (an image, or a loop device)
    std::string medium;       // image file behind it
    std::string outcome;
    std::optional<RiskContext> risk;         // ARVS context the run verified with, if any
    std::optional<PairwiseMatrix> judgments;  // its AHP matrix
};
// Fails if the certificate has no host-known final pattern (e.g. a simulated SSD plan).
Result<CertifiedContent> certified_content(const Json& certificate);

// Writes the certificate to a new file (never overwrites) and fsyncs it.
Result<void> write_certificate(const Json& certificate, const std::string& path);
Result<void> write_new_file(const std::string& path, std::string_view data);
// Where a session's files go: <medium>.<UTC time>.{dwcert.json, dwlog.jsonl, dwcert.pdf} next
// to the wiped image, or, for --cert X.json, X.json / X.dwlog.jsonl / X.pdf.
struct CertificatePaths {
    std::string json, log, pdf;
};
CertificatePaths certificate_paths(const DeviceProfile& profile);
CertificatePaths certificate_paths(const std::string& json_path);

}  // namespace dw
