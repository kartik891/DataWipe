// Phase 4: sector sampling, read-back verification and the certificate stub.
//
// Images live in a private directory under the current working directory (the build tree when
// run by ctest), as in test_overwrite.

#include <fcntl.h>
#include <unistd.h>

#include <cmath>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <vector>

#include "cert/certificate.hpp"
#include <format>
#include "check.hpp"
#include "core/log.hpp"
#include "device/classifier.hpp"
#include "device/device_factory.hpp"
#include "device/identity_provider.hpp"
#include "engine/command_executor.hpp"
#include "engine/method_selector.hpp"
#include "engine/overwrite_engine.hpp"
#include "engine/plan_executor.hpp"
#include "verify/readback_verifier.hpp"
#include "verify/sector_sampler.hpp"

using namespace dw;
namespace fs = std::filesystem;

namespace {

fs::path g_dir;
constexpr std::uint64_t kSs = 512;

UniformSampler::Seed seed(std::uint8_t s) {
    UniformSampler::Seed k{};
    for (std::size_t i = 0; i < k.size(); ++i) k[i] = static_cast<std::uint8_t>(s * 31 + i);
    return k;
}

PatternKey test_key(std::uint8_t s) {
    PatternKey k{};
    for (std::size_t i = 0; i < k.size(); ++i) k[i] = static_cast<std::uint8_t>(s + i * 5);
    return k;
}

std::string make_image(const std::string& name, std::uint64_t size, std::uint8_t fill = 0xAB) {
    fs::path p = g_dir / name;
    fs::remove(p);
    std::ofstream out(p, std::ios::binary);
    std::string chunk(65536, static_cast<char>(fill));
    for (std::uint64_t left = size; left > 0;) {
        auto n = std::min<std::uint64_t>(left, chunk.size());
        out.write(chunk.data(), static_cast<std::streamsize>(n));
        left -= n;
    }
    return p.string();
}

std::unique_ptr<IBlockDevice> open_dev(const std::string& path, bool writable, bool direct = false) {
    auto t = open_target(path, OpenOptions{.writable = writable, .direct_io = direct});
    if (!t) return nullptr;
    return std::move(t->device);
}

void fill_sectors(IBlockDevice& d, std::uint64_t first, std::uint64_t count, std::uint8_t v) {
    std::vector<std::byte> buf(count * kSs, std::byte(v));
    CHECK_OK(d.write_at(first * kSs, buf));
    CHECK_OK(d.flush());
}

VerificationExpectation expect(const OverwriteSpec& spec) {
    VerificationExpectation e;
    e.kind = VerificationExpectation::Kind::Pattern;
    e.expected = spec;
    return e;
}

// Wipes a fresh image with `spec` and returns its path.
std::string wiped_image(const std::string& name, std::uint64_t size, const OverwriteSpec& spec, const PatternKey& key) {
    const auto img = make_image(name, size);
    auto d = open_dev(img, true);
    CHECK(d != nullptr);
    if (d) CHECK_OK(OverwriteEngine(key, {}).run(spec, *d, {}));
    return img;
}

class FixedSampler final : public ISectorSampler {
public:
    explicit FixedSampler(std::vector<std::uint64_t> s) : s_(std::move(s)) {}
    int calls = 0;
    std::vector<SampleUnit> sample(const SampleDomain&) override {
        ++calls;
        std::vector<SampleUnit> u;
        for (auto x : s_) u.push_back({x, 1, 0, false});
        return u;
    }
    std::string name() const override { return "fixed"; }
    Json describe() const override { return Json::object(); }

private:
    std::vector<std::uint64_t> s_;
};

class FailingReads final : public IBlockDevice {
public:
    FailingReads(IBlockDevice& d, std::uint64_t bad_sector) : d_(d), bad_(bad_sector * kSs) {}
    const std::string& path() const override { return d_.path(); }
    BackendKind kind() const override { return d_.kind(); }
    const DeviceGeometry& geometry() const override { return d_.geometry(); }
    bool writable() const override { return d_.writable(); }
    bool direct_io() const override { return d_.direct_io(); }
    Result<void> read_at(std::uint64_t o, std::span<std::byte> b) override {
        if (o <= bad_ && bad_ < o + b.size()) return sys_error("pread (injected)", EIO);
        return d_.read_at(o, b);
    }
    Result<void> write_at(std::uint64_t o, std::span<const std::byte> b) override { return d_.write_at(o, b); }
    Result<void> flush() override { return d_.flush(); }
    int native_handle() const override { return d_.native_handle(); }

private:
    IBlockDevice& d_;
    std::uint64_t bad_;
};

// ---- Sampling ----

std::vector<std::uint64_t> firsts(const std::vector<SampleUnit>& units) {
    std::vector<std::uint64_t> v;
    for (const auto& u : units) v.push_back(u.first_sector);
    return v;
}

void test_sample_size_math() {
    CHECK(sample_size_for(0.001, 0.99) == UniformSampler::kDefaultSamples);
    CHECK(sample_size_for(0.01, 0.95) == 299);
    CHECK(sample_size_for(0, 0.99) == 0 && sample_size_for(0.5, 1) == 0);
    const double f = detectable_fraction(UniformSampler::kDefaultSamples, 1ull << 40, 0.99);
    CHECK(f <= 0.001 && f > 0.00099);
    CHECK(detectable_fraction(100, 100, 0.99) == 0.01);  // exhaustive: any one sector
    CHECK(detectable_fraction(0, 100, 0.99) == 1);
}

void test_uniform_sampler_shape() {
    const SampleDomain d{100, 1'000'000};
    UniformSampler a(seed(1), 1000), a2(seed(1), 1000), b(seed(2), 1000);
    const auto s = firsts(a.sample(d));
    CHECK(s.size() >= 1000 && s.size() <= 1002);
    CHECK(std::is_sorted(s.begin(), s.end()));
    CHECK(std::adjacent_find(s.begin(), s.end()) == s.end());
    CHECK(!s.empty() && s.front() == 100 && s.back() == 100 + 1'000'000 - 1);  // edges included
    CHECK(firsts(a2.sample(d)) == s);  // reproducible from the seed
    CHECK(firsts(b.sample(d)) != s);
    CHECK(firsts(a.sample(d)) == s);  // sampling twice from one sampler gives the same set

    // A sample as large as the range reads every sector.
    auto all = firsts(UniformSampler(seed(3), 50).sample({7, 40}));
    CHECK(all.size() == 40 && all.front() == 7 && all.back() == 46);
    CHECK(firsts(UniformSampler(seed(3), 5).sample({9, 1})) == std::vector<std::uint64_t>{9});
    CHECK(firsts(UniformSampler(seed(3), 5).sample({9, 0})).empty());
    // Huge ranges need no O(n) memory.
    auto huge = firsts(UniformSampler(seed(4), 100).sample({0, 1ull << 50}));
    CHECK(huge.size() >= 100 && huge.back() == (1ull << 50) - 1);

    Json j = a.describe();
    CHECK(j.find("seed") && j.find("seed")->as_string().value().size() == 64);
}

void test_uniform_sampler_is_uniform() {
    // Chi-square over 10 equal buckets, 20000 draws from 10^6 sectors. df = 9; the 0.999 quantile
    // is 27.9, so a correct sampler fails this with probability 1e-3 for a given seed (fixed here).
    const auto s = firsts(UniformSampler(seed(5), 20000).sample({0, 1'000'000}));
    std::array<double, 10> buckets{};
    for (auto x : s) buckets[x / 100'000] += 1;
    const double e = double(s.size()) / 10;
    double chi2 = 0;
    for (double o : buckets) chi2 += (o - e) * (o - e) / e;
    CHECK(chi2 < 27.9);

    // Floyd's algorithm on a small range, 3000 seeds: each of the 8 sectors is drawn with
    // probability 3/8 (expected 1125 hits, sd 27); the two edges are then added every time.
    std::array<int, 8> hits{};
    for (int i = 0; i < 3000; ++i) {
        UniformSampler::Seed k{};
        std::memcpy(k.data(), &i, sizeof i);
        for (auto x : firsts(UniformSampler(k, 3).sample({0, 8}))) ++hits[x];
    }
    CHECK(hits[0] == 3000 && hits[7] == 3000);
    for (int i = 1; i <= 6; ++i) CHECK(hits[i] > 1000 && hits[i] < 1250);
}

// ---- Read-back ----

void test_verify_passes_after_wipe() {
    constexpr std::uint64_t kSize = 4 << 20;
    const OverwriteSpec spec{0, kSize / kSs, PatternSpec{PatternSpec::Kind::Prng, 2, 0}};
    const auto img = wiped_image("pass.img", kSize, spec, test_key(1));
    for (bool direct : {false, true}) {
        auto d = open_dev(img, false, direct);
        if (!d) {
            CHECK(direct);  // only O_DIRECT may be refused (e.g. tmpfs)
            continue;
        }
        UniformSampler sampler(seed(1), UniformSampler::kDefaultSamples);
        auto r = verify_readback(expect(spec), *d, test_key(1), sampler);
        CHECK(r.passed());
        CHECK(r.sectors_sampled >= UniformSampler::kDefaultSamples && r.sectors_sampled == r.sectors_matched);
        CHECK(r.sectors_mismatched == 0 && r.sectors_unreadable == 0 && r.mismatched.empty());
        CHECK(std::abs(r.coverage_percent - 100.0 * double(r.sectors_sampled) / 8192) < 1e-9);
        CHECK(r.read_mode == (direct ? "O_DIRECT" : "buffered + page-cache eviction"));
        Json j = to_json(r);
        CHECK(j.find("status")->as_string().value() == "passed");
        CHECK(j.find("sampler")->find("name")->as_string().value() == "uniform");
    }
}

void test_verify_fixed_pattern_and_subrange() {
    // A sub-range (hidden area kept, say) with a fixed pattern: only that range is sampled.
    constexpr std::uint64_t kSize = 1 << 20;
    const OverwriteSpec spec{64, 1024, PatternSpec{PatternSpec::Kind::Fixed32, 0, 0}};
    const auto img = wiped_image("fixed.img", kSize, spec, test_key(2));
    auto d = open_dev(img, false);
    UniformSampler sampler(seed(2), 200);
    auto r = verify_readback(expect(spec), *d, test_key(2), sampler);
    CHECK(r.passed() && r.first_sector == 64 && r.sectors_in_range == 1024);
    // Outside the range the old fill is still there: a verifier that strayed would fail.
    CHECK(r.sectors_matched == r.sectors_sampled);
}

void test_verify_detects_leftover_data() {
    constexpr std::uint64_t kSize = 4 << 20;
    const std::uint64_t n = kSize / kSs;
    const OverwriteSpec spec{0, n, PatternSpec{PatternSpec::Kind::Prng, 2, 0}};
    const auto img = wiped_image("leftover.img", kSize, spec, test_key(3));

    // A quarter of the range reverts to old data (a skipped region).
    {
        auto w = open_dev(img, true);
        fill_sectors(*w, 2000, 2048, 0xAB);
    }
    auto d = open_dev(img, false);
    UniformSampler sampler(seed(3), 500);
    auto r = verify_readback(expect(spec), *d, test_key(3), sampler);
    CHECK(r.status == VerificationResult::Status::Failed);
    CHECK(r.sectors_mismatched > 60 && r.sectors_mismatched < 200);  // ~25% of ~500
    CHECK(!r.mismatched.empty() && r.mismatched.size() <= 16);
    for (auto s : r.mismatched) CHECK(s >= 2000 && s < 4048);
    CHECK(r.reason.find("do not hold the expected content") != std::string::npos);

    // An exhaustive sample finds a single bad sector, and names it.
    {
        auto w = open_dev(img, true);
        CHECK_OK(OverwriteEngine(test_key(3), {}).run(spec, *w, {}));  // re-wipe
        fill_sectors(*w, 5000, 1, 0x00);
    }
    d = open_dev(img, false);
    UniformSampler all(seed(4), n);
    r = verify_readback(expect(spec), *d, test_key(3), all);
    CHECK(r.status == VerificationResult::Status::Failed && r.sectors_mismatched == 1);
    CHECK(r.mismatched == std::vector<std::uint64_t>{5000});
    CHECK(r.coverage_percent == 100 && r.sectors_sampled == n);
}

void test_verify_wrong_key_or_unwiped() {
    constexpr std::uint64_t kSize = 1 << 20;
    const OverwriteSpec spec{0, kSize / kSs, PatternSpec{PatternSpec::Kind::Prng, 1, 0}};
    const auto img = wiped_image("wrongkey.img", kSize, spec, test_key(4));
    auto d = open_dev(img, false);
    UniformSampler s1(seed(5), 100);
    auto r = verify_readback(expect(spec), *d, test_key(99), s1);
    CHECK(!r.passed() && r.sectors_matched == 0);
    // Same key, different stream (e.g. pass 1 instead of pass 2): also a failure.
    OverwriteSpec other = spec;
    other.pattern.stream = 2;
    UniformSampler s2(seed(5), 100);
    CHECK(!verify_readback(expect(other), *d, test_key(4), s2).passed());

    const auto fresh = make_image("unwiped.img", kSize);
    auto f = open_dev(fresh, false);
    UniformSampler s3(seed(6), 100);
    r = verify_readback(expect(spec), *f, test_key(4), s3);
    CHECK(!r.passed() && r.sectors_matched == 0);
}

void test_verify_unreadable_and_bad_input() {
    constexpr std::uint64_t kSize = 1 << 20;
    const OverwriteSpec spec{0, kSize / kSs, PatternSpec{PatternSpec::Kind::Prng, 1, 0}};
    const auto img = wiped_image("unreadable.img", kSize, spec, test_key(5));
    auto d = open_dev(img, false);
    FailingReads faulty(*d, 700);
    FixedSampler fixed({10, 700, 1500});
    auto r = verify_readback(expect(spec), faulty, test_key(5), fixed);
    CHECK(r.status == VerificationResult::Status::Failed);
    CHECK(r.sectors_unreadable == 1 && r.unreadable == std::vector<std::uint64_t>{700});
    CHECK(r.sectors_matched == 2 && r.sectors_sampled == 3);
    CHECK(r.reason.find("could not be read") != std::string::npos);

    // Nothing to compare against: no reads, no sampler call.
    VerificationExpectation na;
    na.reason = "all steps are SIMULATED";
    FixedSampler untouched({1});
    r = verify_readback(na, *d, test_key(5), untouched);
    CHECK(r.status == VerificationResult::Status::NotApplicable && untouched.calls == 0 && r.reason == na.reason);
    CHECK(to_json(r).find("sectors_sampled") == nullptr);

    // An expectation that does not fit the device is a failure, not a pass over nothing.
    OverwriteSpec big = spec;
    big.sector_count += 1;
    r = verify_readback(expect(big), *d, test_key(5), fixed);
    CHECK(r.status == VerificationResult::Status::Failed && r.sectors_sampled == 0);

    FixedSampler empty({});
    r = verify_readback(expect(spec), *d, test_key(5), empty);
    CHECK(r.status == VerificationResult::Status::Failed);
}

// ---- Certificate ----

// Seals `in` through a fresh session chain, unsigned (tests/test_tecc.cpp covers signing).
Json make_cert(const CertificateInput& in) {
    static int n = 0;
    const std::string log = (g_dir / std::format("session{}.dwlog.jsonl", n++)).string();
    auto chain = tecc::SessionChain::create(log, random_uuid());
    if (!chain) return Json();
    auto sealed = seal_certificate(certificate_body(in, random_uuid(), tecc::utc_now(), chain->session_id()), *chain,
                                   nullptr, "session.dwlog.jsonl");
    return sealed ? *sealed : Json();
}

std::string profiles_dir() {
    const char* d = std::getenv("DW_PROFILES_DIR");
    return d ? d : "profiles";
}

struct Run {
    DeviceProfile profile;
    WipePlan plan;
    PlanRunResult result;
    VerificationResult verification;
};

// probe -> plan -> execute -> verify, the same sequence `datawipe run` performs.
std::optional<Run> full_run(const std::string& img, const std::string& profile_name, const PatternKey& key) {
    auto sim = SimulatedIdentityProvider::load(profiles_dir() + "/" + profile_name);
    auto t = open_target(img, OpenOptions{.writable = true, .direct_io = false});
    if (!sim || !t) return std::nullopt;
    auto id = sim->identify(*t->device);
    if (!id) return std::nullopt;
    auto p = classify(*t, *id, sim->source(), sim->origin());
    if (!p) return std::nullopt;
    auto plan = select_method(*p);
    if (!plan) return std::nullopt;
    OverwriteEngine eng(key, {});
    auto ex = make_command_executor(*p, *t->device);
    auto r = execute_plan(*plan, *ex, t->device.get(), plan->has_host_io() ? &eng : nullptr);
    if (!r) return std::nullopt;
    UniformSampler sampler(seed(9), 300);
    auto v = verify_readback(plan->verification, *t->device, key, sampler);
    return Run{*p, *plan, *r, v};
}

void test_certificate_real_wipe() {
    const auto img = make_image("cert_hdd.img", 2 << 20);
    auto run = full_run(img, "hdd_basic.json", test_key(7));
    CHECK(run.has_value());
    if (!run) return;
    CHECK(run->verification.passed());
    CertificateInput in{run->profile, run->plan, run->result, run->verification, test_key(7), 2,
                        "2026-09-27T10:00:00Z"};
    CHECK(certificate_outcome(in) == "sanitized");
    const Json c = make_cert(in);
    CHECK_OK(check_certificate(c));

    auto str = [&](std::initializer_list<std::string_view> path) {
        const Json* j = &c;
        for (auto k : path) {
            j = j ? j->find(k) : nullptr;
        }
        return j && j->is_string() ? j->as_string().value() : std::string("<missing>");
    };
    CHECK(str({"schema"}) == "datawipe.certificate.v2");
    CHECK(str({"outcome"}) == "sanitized");
    CHECK(str({"device", "identity", "serial"}) == "SIMHDD-0001");
    CHECK(str({"sanitization", "method_id"}) == "hdd.overwrite+ata-se-enhanced");
    CHECK(str({"sanitization", "nist_level_achieved"}) == "Purge");
    CHECK(str({"sanitization", "pattern_key_fingerprint"}) == key_fingerprint(test_key(7)));
    CHECK(str({"sanitization", "started_at"}) == "2026-09-27T10:00:00Z");
    CHECK(str({"verification", "status"}) == "passed");
    CHECK(str({"tecc", "terminal_hash"}).size() == 64 && str({"tecc", "unsigned_reason"}) != "<missing>");
    CHECK(str({"certificate_id"}).size() == 36 && str({"certificate_id"})[14] == '4');
    CHECK(!c.find("sanitization")->find("standards")->items().empty());
    // The emulated Secure Erase is disclosed, not passed off as a real drive command.
    bool emulated_disclosed = false;
    for (const auto& cv : c.find("caveats")->items())
        if (cv.as_string().value().find("logged, not sent") != std::string::npos) emulated_disclosed = true;
    CHECK(emulated_disclosed);
    const auto& steps = c.find("sanitization")->find("steps")->items();
    CHECK(steps.size() == run->plan.steps.size());
    CHECK(steps.back().find("execution")->as_string().value() == to_string(Execution::Emulated));

    // Formatting does not matter; content does.
    auto pretty = Json::parse(c.dump(2));
    CHECK_OK(pretty);
    if (pretty) CHECK_OK(check_certificate(*pretty));
    std::string text = c.dump(2);
    const auto pos = text.find("SIMHDD-0001");
    CHECK(pos != std::string::npos);
    text.replace(pos, 11, "SIMHDD-0002");
    auto tampered = Json::parse(text);
    CHECK_OK(tampered);
    if (tampered) CHECK_ERR_CONTAINS(check_certificate(*tampered), "modified after issue");

    // Editing the claimed digest, dropping it, or a foreign document all fail.
    Json bad = c;
    bad["tecc"]["terminal_hash"] = std::string(64, '0');
    CHECK_ERR_CONTAINS(check_certificate(bad), "TECC check FAILED");
    Json stripped = Json::object();
    for (const auto& [k, v] : c.members())
        if (k != "tecc") stripped[k] = v;
    CHECK_ERR_CONTAINS(check_certificate(stripped), "no TECC seal");
    Json foreign = c;
    foreign["schema"] = "something.else";
    CHECK_ERR_CONTAINS(check_certificate(foreign), "not a datawipe.certificate.v2");

    // Everything needed to re-verify later comes back out of the certificate.
    auto content = certified_content(c);
    CHECK_OK(content);
    if (content) {
        const OverwriteSpec& want = *run->plan.verification.expected;
        CHECK(content->expected.first_sector == want.first_sector && content->expected.sector_count == want.sector_count);
        CHECK(content->expected.pattern.kind == want.pattern.kind && content->expected.pattern.stream == want.pattern.stream);
        CHECK(content->key == test_key(7));
        CHECK(content->size_bytes == run->profile.geometry.size_bytes && content->logical_sector_size == kSs);
        CHECK(content->medium == img && content->outcome == "sanitized");
        // ...and it is enough to verify the medium again.
        auto d = open_dev(img, false);
        VerificationExpectation e;
        e.kind = VerificationExpectation::Kind::Pattern;
        e.expected = content->expected;
        UniformSampler again(seed(11), 200);
        CHECK(verify_readback(e, *d, content->key, again).passed());
    }

    // Every certificate is unique.
    CHECK(str({"certificate_id"}) != make_cert(in).find("certificate_id")->as_string().value());

    // Written once, never overwritten.
    const std::string path = (g_dir / "cert.json").string();
    CHECK_OK(write_certificate(c, path));
    CHECK_ERR_CONTAINS(write_certificate(c, path), "create");
    std::ifstream f(path);
    std::stringstream ss;
    ss << f.rdbuf();
    auto back = Json::parse(ss.str());
    CHECK_OK(back);
    if (back) CHECK_OK(check_certificate(*back));

    const auto paths = certificate_paths(run->profile);
    CHECK(paths.json.starts_with(img + ".") && paths.json.ends_with(".dwcert.json"));
    CHECK(paths.log.ends_with(".dwlog.jsonl") && paths.pdf.ends_with(".dwcert.pdf"));
    const auto custom = certificate_paths(std::string("/x/y.json"));
    CHECK(custom.json == "/x/y.json" && custom.log == "/x/y.dwlog.jsonl" && custom.pdf == "/x/y.pdf");
}

void test_certificate_outcomes() {
    // A fully simulated plan leaves the medium alone and must say so.
    const auto img = make_image("cert_ssd.img", 1 << 20);
    auto run = full_run(img, "ssd_nvme_plain.json", test_key(8));
    CHECK(run.has_value());
    if (!run) return;
    CHECK(run->plan.fully_simulated() && run->result.success);
    CHECK(run->verification.status == VerificationResult::Status::NotApplicable);
    CertificateInput in{run->profile, run->plan, run->result, run->verification, std::nullopt, 1, {}};
    CHECK(certificate_outcome(in) == "simulated");
    const Json c = make_cert(in);
    CHECK_OK(check_certificate(c));
    CHECK(c.find("sanitization")->find("pattern_key_fingerprint") == nullptr);
    CHECK_ERR_CONTAINS(certified_content(c), "nothing to read back");
    bool simulated_disclosed = false;
    for (const auto& cv : c.find("caveats")->items())
        if (cv.as_string().value().find("SIMULATED") != std::string::npos) simulated_disclosed = true;
    CHECK(simulated_disclosed);

    // The remaining verdicts, from the same inputs with one field changed.
    const auto hdd = make_image("cert_hdd2.img", 1 << 20);
    auto h = full_run(hdd, "hdd_basic.json", test_key(9));
    CHECK(h.has_value());
    if (!h) return;
    VerificationResult failed = h->verification;
    failed.status = VerificationResult::Status::Failed;
    CHECK(certificate_outcome({h->profile, h->plan, h->result, failed, std::nullopt, 1, {}}) == "verification-failed");
    VerificationResult skipped = verification_not_performed(VerificationResult::Status::Skipped, "--no-verify");
    CHECK(certificate_outcome({h->profile, h->plan, h->result, skipped, std::nullopt, 1, {}}) ==
          "sanitized-unverified");
    PlanRunResult unfinished = h->result;
    unfinished.success = false;
    CHECK(certificate_outcome({h->profile, h->plan, unfinished, h->verification, std::nullopt, 1, {}}) ==
          "incomplete");
}

}  // namespace

int main() {
    log::set_level(log::Level::Error);
    std::string tmpl = (fs::current_path() / "dw_verify_XXXXXX").string();
    if (!::mkdtemp(tmpl.data())) {
        std::perror("mkdtemp");
        return 1;
    }
    g_dir = tmpl;

    test_sample_size_math();
    test_uniform_sampler_shape();
    test_uniform_sampler_is_uniform();
    test_verify_passes_after_wipe();
    test_verify_fixed_pattern_and_subrange();
    test_verify_detects_leftover_data();
    test_verify_wrong_key_or_unwiped();
    test_verify_unreadable_and_bad_input();
    test_certificate_real_wipe();
    test_certificate_outcomes();

    fs::remove_all(g_dir);
    return finish("test_verify");
}
