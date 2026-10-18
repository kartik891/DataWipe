// TECC: Ed25519 keys, the session hash chain, certificate seal and checks, PDF rendering.

#include <sys/stat.h>
#include <unistd.h>

#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>

#include "cert/certificate.hpp"
#include "cert/pdf.hpp"
#include "check.hpp"
#include "core/log.hpp"
#include "core/sha256.hpp"
#include "tecc/ed25519.hpp"
#include "tecc/session_chain.hpp"

using namespace dw;
namespace fs = std::filesystem;

namespace {

fs::path g_dir;

std::string path(const std::string& name) { return (g_dir / name).string(); }

std::vector<std::uint8_t> unhex(std::string_view s) {
    std::vector<std::uint8_t> v;
    for (std::size_t i = 0; i + 1 < s.size(); i += 2) v.push_back(static_cast<std::uint8_t>(std::stoi(std::string(s.substr(i, 2)), nullptr, 16)));
    return v;
}

std::string slurp(const std::string& p) {
    std::ifstream in(p, std::ios::binary);
    std::stringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

std::vector<std::string> lines_of(const std::string& p) {
    std::vector<std::string> v;
    std::ifstream in(p);
    for (std::string l; std::getline(in, l);) v.push_back(l);
    return v;
}

void write_lines(const std::string& p, const std::vector<std::string>& v) {
    std::ofstream out(p, std::ios::trunc);
    for (const auto& l : v) out << l << "\n";
}

// ---- Ed25519 ----

void test_rfc8032_vectors() {
    // RFC 8032 Section 7.1, TEST 1 (empty message) and TEST 2 (one byte 0x72).
    struct V {
        const char *pub, *msg, *sig;
    } vs[] = {
        {"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
         "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe"
         "24655141438e7a100b"},
        {"3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
         "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302a"
         "eeb00d291612bb0c00"},
    };
    for (const auto& v : vs) {
        ed25519::PublicKey pub{};
        ed25519::Signature sig{};
        auto p = unhex(v.pub), s = unhex(v.sig), m = unhex(v.msg);
        std::copy(p.begin(), p.end(), pub.begin());
        std::copy(s.begin(), s.end(), sig.begin());
        CHECK(ed25519::verify(pub, m, sig));
        m.push_back(0);  // any change to the message breaks it
        CHECK(!ed25519::verify(pub, m, sig));
    }
}

void test_keys() {
    auto k = ed25519::PrivateKey::generate();
    CHECK_OK(k);
    if (!k) return;
    const std::uint8_t msg[] = {1, 2, 3};
    auto sig = k->sign(msg);
    CHECK_OK(sig);
    if (!sig) return;
    CHECK(ed25519::verify(k->public_key(), msg, *sig));
    auto other = ed25519::PrivateKey::generate().value();
    CHECK(!ed25519::verify(other.public_key(), msg, *sig));
    CHECK(ed25519::key_id(k->public_key()).size() == 16);

    // Encrypted private key: 0600, never overwritten, needs the passphrase.
    const std::string priv = path("org.key.pem"), pub = path("org.pub.pem");
    CHECK_OK(k->save(priv, "a long passphrase"));
#ifndef _WIN32  // Windows files have ACLs inherited from the directory, not mode bits
    struct stat st{};
    CHECK(::stat(priv.c_str(), &st) == 0 && (st.st_mode & 0777) == 0600);
#endif
    CHECK(slurp(priv).starts_with("-----BEGIN ENCRYPTED PRIVATE KEY-----"));
    CHECK_ERR_CONTAINS(k->save(priv, "x"), "create");
    auto back = ed25519::PrivateKey::load(priv, [] { return std::string("a long passphrase"); });
    CHECK_OK(back);
    if (back) CHECK(back->public_key() == k->public_key());
    CHECK_ERR_CONTAINS(ed25519::PrivateKey::load(priv, [] { return std::string("wrong passphrase!"); }), "wrong passphrase");
    CHECK(!ed25519::PrivateKey::load(priv, nullptr));

    // Unencrypted only on request; asks nothing.
    const std::string plain = path("plain.key.pem");
    CHECK_OK(k->save(plain, ""));
    CHECK(slurp(plain).starts_with("-----BEGIN PRIVATE KEY-----"));
    bool asked = false;
    CHECK_OK(ed25519::PrivateKey::load(plain, [&] { asked = true; return std::string(); }));
    CHECK(!asked);

    CHECK_OK(ed25519::save_public_key(k->public_key(), pub));
    auto pk = ed25519::load_public_key(pub);
    CHECK_OK(pk);
    if (pk) CHECK(*pk == k->public_key());
    CHECK_ERR_CONTAINS(ed25519::load_public_key(priv), "cannot read public key");
}

// ---- Chain ----

void test_chain() {
    const std::string log = path("s.dwlog.jsonl");
    auto c = tecc::SessionChain::create(log, "session-1");
    CHECK_OK(c);
    if (!c) return;
    CHECK(c->last() == tecc::genesis_hash("session-1") && c->count() == 0);
    Json d = Json::object();
    d["x"] = 1.25;
    d["s"] = "quote \" and (parens) and \\ backslash";
    std::vector<tecc::Hash> hashes;
    for (const char* stage : {"detection", "plan", "execution"}) {
        auto h = c->append(stage, d, "2026-09-27T00:00:00Z");
        CHECK_OK(h);
        if (h) hashes.push_back(*h);
    }
    CHECK(c->count() == 3);
    CHECK_ERR_CONTAINS(tecc::SessionChain::create(log, "again"), "create");  // never overwritten

    auto v = tecc::read_and_verify_log(log);
    CHECK_OK(v);
    if (v) {
        CHECK(v->session_id == "session-1" && v->entries.size() == 3 && v->terminal() == hashes.back());
        // Hi = SHA-256(H(i-1) || canonical entry), recomputed independently.
        CHECK(v->entries[1].hash == tecc::entry_hash(hashes[0], tecc::entry_object(2, "plan", "2026-09-27T00:00:00Z", d)));
    }

    const auto orig = lines_of(log);
    auto tampered = [&](std::vector<std::string> l, const char* needle) {
        const std::string p = path("t.dwlog.jsonl");
        write_lines(p, l);
        CHECK_ERR_CONTAINS(tecc::read_and_verify_log(p), needle);
    };
    auto edited = orig;
    edited[2].replace(edited[2].find("1.25"), 4, "1.26");
    tampered(edited, "does not match its hash");
    auto swapped = orig;
    std::swap(swapped[1], swapped[2]);
    tampered(swapped, "out of sequence");
    auto removed = orig;
    removed.erase(removed.begin() + 2);
    tampered(removed, "out of sequence");
    auto renumbered = removed;  // drop an entry and renumber: the links no longer match
    renumbered[2].replace(renumbered[2].find("\"i\":3"), 5, "\"i\":2");
    tampered(renumbered, "does not link");
    auto header = orig;
    header[0].replace(header[0].find("session-1"), 9, "session-2");
    tampered(header, "genesis");

    // Resume: the journal's (count, last hash) must still be in the log.
    auto r = tecc::SessionChain::resume(log, 3, hashes[2]);
    CHECK_OK(r);
    if (r) {
        CHECK_OK(r->append("resume", d));
        CHECK(r->count() == 4);
    }
    // A crash after an append but before the journal caught up: accepted (the extra entry is chained).
    CHECK_OK(tecc::SessionChain::resume(log, 3, hashes[2]));
    // The log lost entries while the wipe was paused: refused.
    write_lines(path("short.dwlog.jsonl"), {orig[0], orig[1], orig[2]});
    CHECK_ERR_CONTAINS(tecc::SessionChain::resume(path("short.dwlog.jsonl"), 3, hashes[2]), "truncated or replaced");
    // A different log (same length, other content): refused.
    CHECK_ERR_CONTAINS(tecc::SessionChain::resume(log, 3, hashes[0]), "truncated or replaced");
}

// ---- Certificate seal ----

struct Fixture {
    DeviceProfile profile;
    WipePlan plan;
    PlanRunResult result;
    VerificationResult verification;
    Fixture() {
        profile.identity.serial = "SER-1";
        profile.identity.model = "Model (X)";
        plan.method_id = "hdd.overwrite";
        plan.method_name = "HDD: overwrite";
        plan.standards = {"NIST SP 800-88 Rev. 1"};
        result.success = true;
        verification = verification_not_performed(VerificationResult::Status::NotApplicable, "test");
    }
    CertificateInput input() const { return {profile, plan, result, verification, std::nullopt, 1, {}}; }
};

Result<Json> issue(const std::string& name, const Fixture& f, const ed25519::PrivateKey* key,
                   void (*edit)(Json&) = nullptr) {
    auto chain = tecc::SessionChain::create(path(name + ".dwlog.jsonl"), random_uuid());
    if (!chain) return chain.error();
    if (auto h = chain->append("detection", to_json(f.profile)); !h) return h.error();
    Json body = certificate_body(f.input(), random_uuid(), tecc::utc_now(), chain->session_id());
    if (edit) edit(body);
    return seal_certificate(std::move(body), *chain, key, name + ".dwlog.jsonl");
}

void test_certificate_seal() {
    Fixture f;
    auto org = ed25519::PrivateKey::generate().value();
    auto evil = ed25519::PrivateKey::generate().value();

    auto cert = issue("genuine", f, &org);
    CHECK_OK(cert);
    if (!cert) return;
    auto chk = check_certificate(*cert);
    CHECK_OK(chk);
    if (chk) CHECK(chk->signed_by && *chk->signed_by == org.public_key() && !chk->trusted && chk->entries == 2);
    auto trusted = check_certificate(*cert, org.public_key());
    CHECK_OK(trusted);
    if (trusted) CHECK(trusted->trusted);
    CHECK_ERR_CONTAINS(check_certificate(*cert, evil.public_key()), "NOT the trusted key");

    // Re-indenting keeps it valid; any value change breaks it.
    auto pretty = Json::parse(cert->dump(2));
    CHECK_OK(pretty);
    if (pretty) CHECK_OK(check_certificate(*pretty, org.public_key()));
    Json tampered = *cert;
    tampered["outcome"] = "sanitized-but-edited";
    CHECK_ERR_CONTAINS(check_certificate(tampered), "modified after issue");
    Json sci = *cert;
    sci["sci_score"] = 99.0;  // a substituted SCI score (paper Table IV)
    CHECK_ERR_CONTAINS(check_certificate(sci), "modified after issue");

    // Forgery: the attacker edits the body, rebuilds a chain and signs with their own key. The
    // result is self-consistent, so only the trusted public key exposes it (paper Table IV).
    auto forged = issue("forged", f, &evil, [](Json& b) { b["device"]["identity"]["serial"] = "OTHER-DRIVE"; });
    CHECK_OK(forged);
    if (forged) {
        CHECK_OK(check_certificate(*forged));
        CHECK_ERR_CONTAINS(check_certificate(*forged, org.public_key()), "NOT the trusted key");
    }
    // Swapping in the organisation's public key without its private key: the signature fails.
    if (forged) {
        Json swap = *forged;
        swap["tecc"]["signature"]["public_key"] = to_hex(std::span<const std::uint8_t>(org.public_key()));
        CHECK_ERR_CONTAINS(check_certificate(swap, org.public_key()), "signature INVALID");
    }

    // Unsigned: integrity only, and refused when a trusted key is required.
    auto unsigned_cert = issue("unsigned", f, nullptr);
    CHECK_OK(unsigned_cert);
    if (unsigned_cert) {
        auto u = check_certificate(*unsigned_cert);
        CHECK_OK(u);
        if (u) CHECK(!u->signed_by);
        CHECK_ERR_CONTAINS(check_certificate(*unsigned_cert, org.public_key()), "UNSIGNED");
    }

    // Full audit with the session log; the wrong log is rejected.
    auto log = tecc::read_and_verify_log(path("genuine.dwlog.jsonl"));
    CHECK_OK(log);
    if (log) {
        CHECK_OK(audit_session_log(*cert, *log));
        CHECK(log->entries.back().stage == "certificate");
    }
    auto other_log = tecc::read_and_verify_log(path("unsigned.dwlog.jsonl"));
    if (other_log) CHECK_ERR_CONTAINS(audit_session_log(*cert, *other_log), "belongs to session");
}

// ---- PDF ----

void test_pdf() {
    Fixture f;
    for (int i = 0; i < 80; ++i) f.plan.warnings.push_back("caveat line (with parentheses) number " + std::to_string(i));
    auto key = ed25519::PrivateKey::generate().value();
    auto cert = issue("pdf", f, &key);
    CHECK_OK(cert);
    if (!cert) return;
    const std::string pdf = render_certificate_pdf(*cert, "pdf.dwcert.json");
    CHECK(pdf.starts_with("%PDF-1.4\n") && pdf.ends_with("%%EOF\n"));

    // Every xref offset points at the object it names.
    const auto xref = pdf.rfind("\nxref\n");
    CHECK(xref != std::string::npos);
    std::istringstream in(pdf.substr(xref + 6));
    int zero = 0, count = 0;
    in >> zero >> count;
    std::string off, gen, kind;
    in >> off >> gen >> kind;  // free entry 0
    for (int i = 1; i < count; ++i) {
        in >> off >> gen >> kind;
        CHECK(pdf.compare(std::stoul(off), std::to_string(i).size() + 6, std::to_string(i) + " 0 obj") == 0);
    }
    CHECK(pdf.find("startxref\n" + std::to_string(xref + 1)) != std::string::npos);
    // Many caveats spill onto further pages.
    CHECK(pdf.find("/Count 1 ") == std::string::npos);
    // Parentheses in text are escaped.
    CHECK(pdf.find("\\(with parentheses\\)") != std::string::npos);

    // The attached JSON is exactly the signed certificate.
    const std::string mark = "/Subtype /application#2Fjson /Length ";
    const auto m = pdf.find(mark);
    CHECK(m != std::string::npos);
    const std::size_t len = std::stoul(pdf.substr(m + mark.size()));
    const auto st = pdf.find("stream\n", m) + 7;
    auto attached = Json::parse(pdf.substr(st, len));
    CHECK_OK(attached);
    if (attached) CHECK_OK(check_certificate(*attached, key.public_key()));
}

}  // namespace

int main() {
    log::set_level(log::Level::Error);
    std::string tmpl = (fs::current_path() / "dw_tecc_XXXXXX").string();
    if (!::mkdtemp(tmpl.data())) {
        std::perror("mkdtemp");
        return 1;
    }
    g_dir = tmpl;

    test_rfc8032_vectors();
    test_keys();
    test_chain();
    test_certificate_seal();
    test_pdf();

    fs::remove_all(g_dir);
    return finish("test_tecc");
}
