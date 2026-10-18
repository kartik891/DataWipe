// ARVS risk model and sampler, SCI, Stage 6 re-wipe, pre-wipe fingerprints, and a Monte Carlo
// comparison of ARVS with uniform sampling at an equal budget (the shape of paper Table VI).

#include <unistd.h>

#include <cmath>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>

#include "check.hpp"
#include "core/chacha_rng.hpp"
#include "core/log.hpp"
#include "device/device_factory.hpp"
#include "engine/device_command.hpp"
#include "engine/overwrite_engine.hpp"
#include "engine/run_journal.hpp"
#include "verify/arvs_sampler.hpp"
#include "verify/fingerprint.hpp"
#include "verify/readback_verifier.hpp"
#include "verify/risk_model.hpp"
#include "verify/sci.hpp"

using namespace dw;
namespace fs = std::filesystem;

namespace {

fs::path g_dir;
constexpr std::uint32_t kSs = 512;

chacha20::Key key_of(std::uint8_t s) {
    chacha20::Key k{};
    for (std::size_t i = 0; i < k.size(); ++i) k[i] = static_cast<std::uint8_t>(s * 13 + i);
    return k;
}

// A disk in memory. `drop_writes` models firmware that acknowledges writes it never performs.
class MemDevice final : public IBlockDevice {
public:
    explicit MemDevice(std::uint64_t sectors) : data_(sectors * kSs), geo_{sectors * kSs, kSs, kSs} {}
    bool drop_writes = false;
    std::vector<std::byte>& data() { return data_; }
    const std::string& path() const override { return path_; }
    BackendKind kind() const override { return BackendKind::ImageFile; }
    const DeviceGeometry& geometry() const override { return geo_; }
    bool writable() const override { return true; }
    bool direct_io() const override { return false; }
    Result<void> read_at(std::uint64_t o, std::span<std::byte> b) override {
        if (o + b.size() > data_.size()) return error("read past end");
        std::memcpy(b.data(), data_.data() + o, b.size());
        return ok();
    }
    Result<void> write_at(std::uint64_t o, std::span<const std::byte> b) override {
        if (o + b.size() > data_.size()) return error("write past end");
        if (!drop_writes) std::memcpy(data_.data() + o, b.data(), b.size());
        return ok();
    }
    Result<void> flush() override { return ok(); }
    int native_handle() const override { return -1; }

private:
    std::vector<std::byte> data_;
    DeviceGeometry geo_;
    std::string path_ = "mem";
};

void fill_pattern(MemDevice& d, const PatternSpec& p, const PatternKey& k) {
    PatternGenerator(p, k).fill(0, d.data());
}

RiskContext ctx_for(std::uint64_t sectors, std::vector<SectorRange> hidden = {}, std::vector<std::uint64_t> seams = {},
                    EraseMethod m = EraseMethod::HostOverwrite, MediaType media = MediaType::HDD) {
    RiskContext c;
    c.domain = {0, sectors};
    c.sector_size = kSs;
    c.cluster_sectors = choose_cluster_sectors(sectors, kSs);
    c.hidden = std::move(hidden);
    c.boundaries = std::move(seams);
    c.boundary_reach = std::max<std::uint64_t>(c.cluster_sectors, sectors / 100);
    c.method = m;
    c.media = media;
    return c;
}

ArvsSampler arvs(const RiskContext& c, std::uint8_t seed, ArvsConfig cfg = {}) {
    auto s = ArvsSampler::create(key_of(seed), c, default_pairwise(), cfg);
    if (!s) std::fprintf(stderr, "ArvsSampler::create: %s\n", s.error().describe().c_str());
    return std::move(s).value();
}

// ---- AHP ----

void test_ahp() {
    auto a = ahp_weights(default_pairwise());
    CHECK_OK(a);
    if (!a) return;
    double sum = 0;
    for (double w : a->weights) sum += w;
    CHECK(std::abs(sum - 1) < 1e-12);  // equation (2)
    CHECK(a->consistency_ratio < 0.1);
    const auto& w = a->weights;
    CHECK(w[kF] > w[kH] && w[kH] > w[kW] && w[kH] > w[kE] && w[kW] > w[kB] && w[kE] > w[kB]);

    // A perfectly consistent matrix a_ij = v_i / v_j returns v exactly, with CR = 0.
    const RiskWeights v{0.3, 0.1, 0.4, 0.05, 0.15};
    PairwiseMatrix m{};
    for (int i = 0; i < kFactors; ++i)
        for (int j = 0; j < kFactors; ++j) m[i][j] = v[i] / v[j];
    auto c = ahp_weights(m);
    CHECK_OK(c);
    if (c) {
        for (int i = 0; i < kFactors; ++i) CHECK(std::abs(c->weights[i] - v[i]) < 1e-9);
        CHECK(std::abs(c->lambda_max - 5) < 1e-9 && std::abs(c->consistency_ratio) < 1e-9);
    }

    // Contradictory judgments (H >> F, F >> W, W >> H) are rejected.
    PairwiseMatrix bad = default_pairwise();
    bad[kH][kF] = 9, bad[kF][kH] = 1.0 / 9;
    bad[kW][kH] = 9, bad[kH][kW] = 1.0 / 9;
    CHECK_ERR_CONTAINS(ahp_weights(bad), "inconsistent");
    PairwiseMatrix nonrecip = default_pairwise();
    nonrecip[kH][kW] = 7;
    CHECK_ERR_CONTAINS(ahp_weights(nonrecip), "not reciprocal");
    PairwiseMatrix zero = default_pairwise();
    zero[kB][kE] = 0;
    CHECK_ERR_CONTAINS(ahp_weights(zero), "positive");
}

// ---- Methods ----

void test_method_classification() {
    auto step = [](std::vector<DeviceCommand> cmds, bool overwrite) {
        WipeStep s;
        s.commands = std::move(cmds);
        if (overwrite) s.overwrite = OverwriteSpec{0, 8, {}};
        return s;
    };
    CHECK(classify_step(step({}, true)) == EraseMethod::HostOverwrite);
    CHECK(classify_step(step({ata::security_set_password("x"), ata::security_erase_prepare(),
                              ata::security_erase_unit("x", true)}, true)) == EraseMethod::AtaSecureEraseEnhanced);
    CHECK(classify_step(step({ata::security_erase_unit("x", false)}, false)) == EraseMethod::AtaSecureErase);
    CHECK(classify_step(step({ata::sanitize_crypto_scramble(), ata::sanitize_status()}, false)) ==
          EraseMethod::AtaSanitizeCrypto);
    CHECK(classify_step(step({ata::sanitize_block_erase()}, false)) == EraseMethod::AtaSanitizeBlock);
    CHECK(classify_step(step({nvme::sanitize(nvme::SanitizeAction::CryptoErase), nvme::sanitize_status_log()}, false)) ==
          EraseMethod::NvmeSanitizeCrypto);
    CHECK(classify_step(step({nvme::format_nvm(2, 1, 0)}, false)) == EraseMethod::NvmeFormatCrypto);
    CHECK(classify_step(step({nvme::format_nvm(1, 1, 0)}, false)) == EraseMethod::NvmeFormatUserData);
    CHECK(classify_step(step({emmc::sanitize()}, false)) == EraseMethod::EmmcSanitize);
    CHECK(classify_step(step({tcg::opal_genkey_all_ranges()}, false)) == EraseMethod::OpalGenKey);
    CHECK(classify_step(step({blk::discard(0, 4096)}, false)) == EraseMethod::Discard);

    // The final method is the last step that changes the medium; an HPA step does not count.
    WipePlan plan;
    plan.steps.push_back(step({ata::read_native_max_address_ext(), ata::set_max_address_ext(99, false)}, false));
    plan.steps.push_back(step({}, true));
    plan.steps.push_back(step({nvme::sanitize_status_log()}, false));
    CHECK(final_method(plan) == EraseMethod::HostOverwrite);

    // Priors derived from Wei et al. (FAST'11) counts: Jeffreys mean (x + 1/2) / (n + 1).
    auto se = method_prior(EraseMethod::AtaSecureErase, MediaType::SSD_SATA);
    CHECK(se.measured && se.failures == 1 && se.trials == 5 && std::abs(se.failure_rate - 0.25) < 1e-12);
    CHECK(se.ci_low < se.failure_rate && se.failure_rate < se.ci_high);
    auto enh = method_prior(EraseMethod::AtaSecureEraseEnhanced, MediaType::SSD_SATA);
    CHECK(enh.measured && enh.failures == 0 && enh.trials == 4 && std::abs(enh.failure_rate - 0.1) < 1e-12);
    auto one = method_prior(EraseMethod::HostOverwrite, MediaType::SSD_NVMe, 1);
    auto two = method_prior(EraseMethod::HostOverwrite, MediaType::SSD_NVMe, 2);
    CHECK(one.measured && one.failures == 7 && one.trials == 8 && std::abs(one.failure_rate - 7.5 / 9) < 1e-12);
    CHECK(two.measured && two.failures == 1 && two.trials == 8 && std::abs(two.failure_rate - 1.5 / 9) < 1e-12);
    // No published rate: labelled as an assumption, never as measured.
    for (auto m : {EraseMethod::NvmeSanitizeCrypto, EraseMethod::NvmeFormatCrypto, EraseMethod::OpalGenKey,
                   EraseMethod::EmmcSanitize, EraseMethod::Discard}) {
        auto p = method_prior(m, MediaType::SSD_NVMe);
        CHECK(!p.measured && p.basis.starts_with("ASSUMPTION"));
    }
    for (auto m : {EraseMethod::HostOverwrite, EraseMethod::AtaSecureErase, EraseMethod::AtaSecureEraseEnhanced})
        CHECK(!method_prior(m, MediaType::HDD).measured);  // Wei et al. tested SSDs only
    CHECK(method_prior(EraseMethod::HostOverwrite, MediaType::HDD).confidence == 0.9);

    // The risk context counts the plan's host passes, so a two-pass flash plan gets the
    // two-pass rate and an HDD plan's firmware erase step is not counted as a host pass.
    DeviceProfile ssd;
    ssd.geometry = {1 << 20, kSs, kSs};
    ssd.media = MediaType::SSD_SATA;
    ssd.identity.user_addressable_sectors = ssd.identity.native_max_sectors = 2048;
    WipePlan two_pass;
    two_pass.steps = {step({}, true), step({}, true)};
    auto rc = make_risk_context(ssd, two_pass, {0, 2048}, {});
    CHECK(rc.host_passes == 2 && rc.method == EraseMethod::HostOverwrite);
    WipePlan hdd_plan;
    hdd_plan.steps = {step({}, true), step({ata::security_erase_unit("x", true)}, true)};
    DeviceProfile hdd = ssd;
    hdd.media = MediaType::HDD;
    rc = make_risk_context(hdd, hdd_plan, {0, 2048}, {});
    CHECK(rc.host_passes == 1 && rc.method == EraseMethod::AtaSecureEraseEnhanced);
    CHECK(method_prior(EraseMethod::NvmeSanitizeCrypto, MediaType::SSD_NVMe).confidence == 0.2);
}

// ---- Clusters ----

void test_clusters() {
    constexpr std::uint64_t n = 1 << 16;  // 32 MiB
    auto w = ahp_weights(default_pairwise()).value().weights;
    const auto ctx = ctx_for(n, {{n - 4096, n}}, {n / 2}, EraseMethod::AtaSecureEraseEnhanced, MediaType::SSD_SATA);
    const auto cl = score_clusters(ctx, w);
    CHECK(!cl.empty() && cl.front().range.first == 0 && cl.back().range.end == n);
    for (std::size_t i = 1; i < cl.size(); ++i) CHECK(cl[i].range.first == cl[i - 1].range.end);
    for (const auto& c : cl) CHECK(c.range.first % ctx.cluster_sectors == 0);

    auto at = [&](std::uint64_t lba) -> const Cluster& {
        for (const auto& c : cl)
            if (lba >= c.range.first && lba < c.range.end) return c;
        return cl.front();
    };
    const Cluster& hidden = at(n - 100);
    const Cluster& middle = at(n / 4);
    const Cluster& seam = at(n / 2);
    const Cluster& edge = at(0);
    CHECK(hidden.factors.h == 1 && hidden.high_risk);
    CHECK(middle.factors.h == 0 && middle.factors.b == 0 && !middle.high_risk);
    CHECK(seam.factors.b == 1 && seam.high_risk);
    CHECK(edge.factors.b == 1 && edge.high_risk);
    CHECK(std::abs(middle.factors.f - 0.1) < 1e-12 && std::abs(middle.factors.e - 0.8) < 1e-12);
    // Equation (1) exactly.
    const double want = w[kH] * 0 + w[kW] * ctx.wear_ratio + w[kF] * 0.1 + w[kB] * 0 + w[kE] * 0.8;
    CHECK(std::abs(middle.risk - want) < 1e-12);
    CHECK(hidden.risk > middle.risk && seam.risk > middle.risk);
    // B falls off linearly with distance, reaching 0 at the reach.
    const Cluster& near = at(n / 2 + ctx.boundary_reach / 2 + ctx.cluster_sectors);
    CHECK(near.factors.b > 0 && near.factors.b < 0.5);

    CHECK(choose_cluster_sectors(1 << 16, 512) == 8);                  // 4 KiB clusters
    CHECK(choose_cluster_sectors(2'000'000'000'000ull / 512, 512) == 65536);  // 2 TB: 32 MiB clusters
    CHECK(choose_cluster_sectors(1 << 16, 4096) == 1);

    auto round = risk_context_from_json(to_json(ctx));
    CHECK_OK(round);
    if (round) {
        CHECK(round->domain.end == n && round->hidden.size() == 1 && round->boundaries == ctx.boundaries);
        CHECK(round->method == ctx.method && round->media == ctx.media && round->cluster_sectors == ctx.cluster_sectors);
        CHECK(round->host_passes == ctx.host_passes);
    }
    Json cj = to_json(ctx);
    CHECK(cj.find("method_prior")->find("calibration")->as_string().value() == "measured");
    CHECK(cj.find("method_prior")->find("evidence")->find("trials")->as_u64().value() == 4);
}

// ---- Sampler ----

void test_arvs_sampler() {
    constexpr std::uint64_t n = 1 << 18;  // 128 MiB, 32768 clusters of 4 KiB
    const auto ctx = ctx_for(n, {{n - n / 50, n}}, {n / 3});
    ArvsSampler s = arvs(ctx, 1);
    const auto units = s.sample({0, n});
    std::uint64_t sectors = 0, high = 0;
    for (std::size_t i = 0; i < units.size(); ++i) {
        sectors += units[i].sector_count;
        high += units[i].high_risk;
        if (i) CHECK(units[i].first_sector >= units[i - 1].first_sector + units[i - 1].sector_count);
        CHECK(units[i].first_sector + units[i].sector_count <= n);
    }
    Json d = s.describe();
    // Budget: base 5% scaled by the device risk D, in whole clusters.
    const double D = d.find("device_risk_D")->as_double().value();
    CHECK(D > 0 && D < 1);
    CHECK(sectors >= std::uint64_t(std::ceil(0.05 * (1 + D) * n)) &&
          sectors <= std::uint64_t(std::ceil(0.05 * (1 + D) * n)) + ctx.cluster_sectors);
    // The high-risk region gets several times its share of the disk, but not everything.
    const double region_share = double(d.find("clusters_high_risk")->as_u64().value()) / double(d.find("clusters_total")->as_u64().value());
    CHECK(double(high) / double(units.size()) > 4 * region_share && high < units.size());
    CHECK(d.find("clusters_sampled")->as_u64().value() == units.size());
    CHECK(d.find("risk_context") && d.find("weights")->find("gamma_F"));
    // Reproducible from the seed, different for another seed.
    CHECK(arvs(ctx, 1).sample({0, n}) == units);
    CHECK(arvs(ctx, 2).sample({0, n}) != units);
    // Wrong domain: nothing (the context defines the domain).
    CHECK(arvs(ctx, 1).sample({0, n - 1}).empty());

    // A small hidden area is read far more often than an ordinary cluster (L = 1 vs 0: weight
    // 1.02 vs 0.02). Over 40 seeds its clusters are read almost always, a mid-disk one rarely.
    const auto small = ctx_for(n, {{n - 64, n}});
    int hidden_reads = 0, mid_reads = 0;
    for (std::uint8_t seed = 0; seed < 40; ++seed)
        for (const auto& u : arvs(small, seed).sample({0, n})) {
            if (u.first_sector >= n - 64) ++hidden_reads;
            if (u.first_sector == n / 2 - 4096) ++mid_reads;
        }
    CHECK(hidden_reads > 8 * 40 * 9 / 10);  // 8 clusters x 40 seeds, >90% of the time
    CHECK(mid_reads < 10);

    // The floor keeps every cluster reachable: over many seeds, baseline clusters all get read.
    const auto tiny = ctx_for(4096);  // 512 clusters, budget 26
    std::map<std::uint64_t, int> seen;
    for (std::uint8_t i = 0; i < 200; ++i)
        for (const auto& u : arvs(tiny, i).sample({0, 4096})) ++seen[u.first_sector];
    CHECK(seen.size() == 512);

    ArvsConfig bad;
    bad.budget_fraction = 0;
    CHECK_ERR_CONTAINS(ArvsSampler::create(key_of(1), ctx, default_pairwise(), bad), "budget");
    bad = {};
    bad.device_risk_gain = -1;
    CHECK_ERR_CONTAINS(ArvsSampler::create(key_of(1), ctx, default_pairwise(), bad), "gain");
}

// ---- Every weight changes the outcome ----

PairwiseMatrix consistent(RiskWeights w) {
    PairwiseMatrix m{};
    for (int i = 0; i < kFactors; ++i)
        for (int j = 0; j < kFactors; ++j) m[i][j] = w[i] / w[j];
    return m;
}

void test_weights_matter() {
    constexpr std::uint64_t n = 1 << 17;
    const SectorRange hpa{n - n / 50, n};
    const std::uint64_t seam = n / 2;
    // WHERE: alpha vs delta decides whether hidden-area or seam clusters win the budget.
    auto reads = [&](const PairwiseMatrix& m) {
        const auto ctx = ctx_for(n, {hpa}, {seam});
        auto s = ArvsSampler::create(key_of(9), ctx, m).value();
        std::pair<int, int> hidden_seam{0, 0};
        for (const auto& u : s.sample({0, n})) {
            if (u.first_sector >= hpa.first) ++hidden_seam.first;
            if (u.first_sector + ctx.boundary_reach / 2 >= seam && u.first_sector < seam + ctx.boundary_reach / 2)
                ++hidden_seam.second;
        }
        return hidden_seam;
    };
    const auto h_heavy = reads(consistent({0.6, 0.1, 0.1, 0.1, 0.1}));
    const auto b_heavy = reads(consistent({0.1, 0.1, 0.1, 0.6, 0.1}));
    CHECK(h_heavy.first > b_heavy.first && b_heavy.second > h_heavy.second);

    // HOW MUCH: W, F, E scale the budget; a risky method on a worn SSD is read more than an
    // HDD overwrite, and the more weight on F, the larger that gap.
    auto budget = [&](const PairwiseMatrix& m, EraseMethod meth, MediaType media, double wear, double gain) {
        auto ctx = ctx_for(n, {}, {}, meth, media);
        ctx.wear_ratio = wear;
        ArvsConfig cfg;
        cfg.device_risk_gain = gain;
        auto s = ArvsSampler::create(key_of(1), ctx, m, cfg).value();
        (void)s.sample({0, n});
        return s.describe().find("budget_sectors")->as_u64().value();
    };
    const auto hdd = budget(default_pairwise(), EraseMethod::HostOverwrite, MediaType::HDD, 0, 1);
    const auto ssd = budget(default_pairwise(), EraseMethod::HostOverwrite, MediaType::SSD_SATA, 0.5, 1);
    CHECK(hdd >= n / 20 && ssd > hdd && ssd <= n / 10);
    const auto f_heavy = budget(consistent({0.1, 0.05, 0.7, 0.1, 0.05}), EraseMethod::HostOverwrite, MediaType::SSD_SATA, 0.5, 1);
    const auto f_light = budget(consistent({0.1, 0.35, 0.05, 0.1, 0.4}), EraseMethod::HostOverwrite, MediaType::SSD_SATA, 0.5, 1);
    CHECK(f_heavy > f_light);  // F (0.83 for one flash pass) dominates D only when gamma is large
    // gain 0: a fixed budget whatever the device, for like-for-like comparisons.
    CHECK(budget(default_pairwise(), EraseMethod::HostOverwrite, MediaType::SSD_SATA, 0.5, 0) ==
          budget(default_pairwise(), EraseMethod::HostOverwrite, MediaType::HDD, 0, 0));
}

// ---- SCI ----

void test_sci() {
    auto r = compute_sci({10, 10, 4, 2, 3});  // V = 1, R = 0.5, lambda 3
    CHECK(r.defined && std::abs(r.wc - 0.25) < 1e-12 && std::abs(r.wr - 0.75) < 1e-12);
    CHECK(std::abs(r.sci - 62.5) < 1e-9);
    // A high-risk failure costs lambda times a baseline one.
    auto base_fail = compute_sci({10, 9, 10, 10, 3}), high_fail = compute_sci({10, 10, 10, 9, 3});
    CHECK(std::abs((100 - high_fail.sci) - 3 * (100 - base_fail.sci)) < 1e-9);
    CHECK(compute_sci({5, 5, 5, 5, 3}).sci == 100 && compute_sci({5, 0, 5, 0, 3}).sci == 0);
    auto only_base = compute_sci({8, 6, 0, 0, 3});
    CHECK(only_base.defined && std::abs(only_base.sci - 75) < 1e-9 && !only_base.note.empty());
    CHECK(!compute_sci({0, 0, 0, 0, 3}).defined);
    Json j = to_json(SciInput{10, 10, 4, 2, 3}, r);
    CHECK(j.find("score") && j.find("lambda") && j.find("formula"));
}

// ---- Verification with ARVS, Stage 6 re-wipe ----

void test_verify_arvs_and_rewipe() {
    constexpr std::uint64_t n = 1 << 16;
    const PatternSpec pat{PatternSpec::Kind::Prng, 2, 0};
    const PatternKey key = key_of(7);
    const auto ctx = ctx_for(n, {{n - 2048, n}});
    MemDevice dev(n);
    fill_pattern(dev, pat, key);

    PatternOracle oracle(pat, key);
    VerifyConfig cfg;
    ArvsSampler s1 = arvs(ctx, 4);
    auto r = verify_sampled(dev, {0, n}, s1, oracle, cfg);
    CHECK(r.passed() && r.sci.defined && r.sci.sci == 100);
    CHECK(r.sci_input.high_total > 0 && r.sci_input.baseline_total > 0);
    CHECK(to_json(r).find("sci")->find("score")->as_double().value() == 100);

    // Firmware skipped part of the hidden area (the classic HPA miss): old data remains there.
    std::memset(dev.data().data() + (n - 1024) * kSs, 0x5A, 1024 * kSs);
    ArvsSampler s2 = arvs(ctx, 4);
    r = verify_sampled(dev, {0, n}, s2, oracle, cfg);  // no re-wipe device: report only
    CHECK(r.status == VerificationResult::Status::Failed && r.sci.sci < 100);
    CHECK(r.sci_input.high_pass < r.sci_input.high_total && r.sci_input.baseline_pass == r.sci_input.baseline_total);
    for (auto x : r.mismatched) CHECK(x >= n - 1024);
    const double failed_sci = r.sci.sci;

    // Stage 6: with a writable device the failing clusters are re-wiped and read again.
    cfg.rewipe_device = &dev;
    cfg.rewipe_pattern = pat;
    cfg.rewipe_key = key;
    ArvsSampler s3 = arvs(ctx, 4);
    r = verify_sampled(dev, {0, n}, s3, oracle, cfg);
    CHECK(r.status == VerificationResult::Status::Repaired && r.units_repaired > 0 && r.sectors_not_verified == 0);
    CHECK(r.sci.sci == failed_sci);  // the SCI measures the wipe, not the repair
    CHECK(r.reason.find("unsampled areas may have failed") != std::string::npos);

    // Firmware that acknowledges writes it drops: re-wipes never take, sectors are NOT VERIFIED.
    MemDevice liar(n);
    fill_pattern(liar, pat, key);
    std::memset(liar.data().data() + (n - 1024) * kSs, 0x5A, 1024 * kSs);
    liar.drop_writes = true;
    cfg.rewipe_device = &liar;
    ArvsSampler s4 = arvs(ctx, 4);
    r = verify_sampled(liar, {0, n}, s4, oracle, cfg);
    CHECK(r.status == VerificationResult::Status::Failed && r.sectors_not_verified > 0);
    CHECK(!r.not_verified.empty() && r.reason.find("NOT VERIFIED") != std::string::npos);
    CHECK(to_json(r).find("not_verified_sectors_first") != nullptr);
}

// ---- Interrupting and watching a verification ----

void test_verify_cancel_and_progress() {
    constexpr std::uint64_t n = 1 << 16;
    const PatternSpec pat{PatternSpec::Kind::Prng, 2, 0};
    const PatternKey key = key_of(7);
    MemDevice dev(n);
    fill_pattern(dev, pat, key);
    PatternOracle oracle(pat, key);
    ArvsSampler s = arvs(ctx_for(n), 4);
    const auto units = s.sample({0, n});

    // Progress runs from 0 to the unit count and never goes backwards.
    std::vector<std::uint64_t> seen;
    VerifyConfig cfg;
    cfg.on_progress = [&](std::uint64_t done, std::uint64_t total, std::uint64_t) {
        CHECK(total == units.size());
        seen.push_back(done);
    };
    auto r = verify_units(dev, {0, n}, units, oracle, s.describe(), cfg);
    CHECK(r.passed() && !seen.empty() && seen.front() == 0 && seen.back() == units.size());
    CHECK(std::is_sorted(seen.begin(), seen.end()));

    // A cancel request stops between units: status Interrupted, no pass/fail claimed.
    CancelToken cancel;
    VerifyConfig stop;
    stop.cancel = &cancel;
    stop.on_progress = [&](std::uint64_t done, std::uint64_t, std::uint64_t) {
        if (done == 5) cancel.request();
    };
    r = verify_units(dev, {0, n}, units, oracle, s.describe(), stop);
    CHECK(r.status == VerificationResult::Status::Interrupted && r.units_sampled == 6 && units.size() > 6);
    CHECK(!r.passed() && to_json(r).find("status")->as_string().value() == "interrupted");

    // Pre-wipe fingerprinting stops the same way, as an error: nothing was changed yet.
    CancelToken c2;
    c2.request();
    CHECK_ERR_CONTAINS(capture_fingerprints(dev, units, s.describe(), &c2), "interrupted");
}

// ---- Fingerprints (device-internal erases) ----

void test_fingerprints() {
    constexpr std::uint64_t n = 1 << 15;
    const auto ctx = ctx_for(n, {}, {}, EraseMethod::NvmeSanitizeCrypto, MediaType::SSD_NVMe);
    MemDevice dev(n);
    fill_pattern(dev, {PatternSpec::Kind::Prng, 9, 0}, key_of(1));  // "user data"
    std::memset(dev.data().data(), 0, 64 * kSs);                      // a never-written area

    ArvsSampler s = arvs(ctx, 5);
    auto units = s.sample({0, n});
    auto set = capture_fingerprints(dev, units, s.describe());
    CHECK_OK(set);
    if (!set) return;
    std::uint64_t total = 0;
    for (const auto& u : set->units) total += u.sector_count;
    CHECK(set->sector_total() == total && set->constant.size() == total);

    const std::string path = (g_dir / "fp.dwfp").string();
    CHECK_OK(save_fingerprints(*set, path));
    auto loaded = load_fingerprints(path);
    CHECK_OK(loaded);
    if (!loaded) return;
    CHECK(loaded->units == set->units && loaded->hashes == set->hashes && loaded->constant == set->constant);

    // The erase: ciphertext under a discarded key looks like fresh random data.
    fill_pattern(dev, {PatternSpec::Kind::Prng, 77, 0}, key_of(2));
    FingerprintOracle oracle(*loaded);
    auto r = verify_units(dev, {0, n}, loaded->units, oracle, loaded->sampler, {});
    CHECK(r.passed());

    // A controller that skipped a block: those sectors still hold the user data.
    MemDevice partial(n);
    fill_pattern(partial, {PatternSpec::Kind::Prng, 9, 0}, key_of(1));
    std::memset(partial.data().data(), 0, 64 * kSs);
    auto set2 = capture_fingerprints(partial, units, s.describe());
    CHECK_OK(set2);
    if (!set2) return;
    const SampleUnit victim = set2->units[set2->units.size() / 2];
    std::vector<std::byte> keep(partial.data().begin() + victim.first_sector * kSs,
                                partial.data().begin() + (victim.first_sector + victim.sector_count) * kSs);
    fill_pattern(partial, {PatternSpec::Kind::Prng, 77, 0}, key_of(2));
    std::memcpy(partial.data().data() + victim.first_sector * kSs, keep.data(), keep.size());
    FingerprintOracle o2(*set2);
    r = verify_units(partial, {0, n}, set2->units, o2, {}, {});
    CHECK(r.status == VerificationResult::Status::Failed && r.sectors_mismatched == victim.sector_count);
    CHECK(!r.mismatched.empty() && r.mismatched.front() == victim.first_sector);

    // A blank disk: nothing to tell an erase from no change.
    MemDevice blank(n);
    auto set3 = capture_fingerprints(blank, units, s.describe());
    CHECK_OK(set3);
    if (!set3) return;
    FingerprintOracle o3(*set3);
    r = verify_units(blank, {0, n}, set3->units, o3, {}, {});
    CHECK(r.status == VerificationResult::Status::Inconclusive && r.units_uninformative == r.units_sampled);

    // A damaged fingerprint file is refused, not trusted.
    {
        std::fstream f(path, std::ios::in | std::ios::out | std::ios::binary);
        f.seekp(200);
        f.put('\x7f');
    }
    CHECK_ERR_CONTAINS(load_fingerprints(path), "checksum");
}

// ---- Journal seams ----

void test_journal_resumes() {
    JournalRecord rec;
    rec.medium = rec.target = "/x.img";
    rec.size_bytes = 1 << 20;
    rec.logical_sector_size = 512;
    rec.model = rec.serial = rec.identity_source = rec.method_id = rec.plan_sha256 = rec.started_at = rec.updated_at = "x";
    rec.resumes = {{0, 100}, {1, 2048}};
    auto back = journal_from_json(to_json(rec));
    CHECK_OK(back);
    if (back) CHECK(back->resumes == rec.resumes);
    Json old = to_json(rec);
    Json stripped = Json::object();
    for (const auto& [k, v] : old.members())
        if (k != "resumes") stripped[k] = v;
    auto legacy = journal_from_json(stripped);
    CHECK_OK(legacy);
    if (legacy) CHECK(legacy->resumes.empty());
}

// ---- Monte Carlo: ARVS vs uniform at equal budget ----
//
// Each trial: a 64 MiB disk wiped with the pattern, then one silent firmware failure left
// behind: a run of 4-16 clusters still holding old data. The paper's model says failures are
// "weighted toward hidden and over-provisioned regions" without giving a split; the 60% inside
// a 2% HPA at the end / 40% at the seam where an interrupted pass was resumed used here is this
// test's own assumption. Every trial contains a failure, so the rates are detection rates
// given a failure, as in the paper's Table VI. Both samplers read 5% of the disk
// in the same 4 KiB clusters; the uniform one is ARVS with no risk information (no hidden
// area, no seam, no high-risk share), i.e. a uniform draw of clusters.
void test_monte_carlo() {
    constexpr std::uint64_t n = 1 << 17;
    constexpr int kTrials = 300;
    const PatternSpec pat{PatternSpec::Kind::Prng, 2, 0};
    const PatternKey key = key_of(3);
    MemDevice dev(n);
    fill_pattern(dev, pat, key);
    const SectorRange hpa{n - n / 50, n};
    ChaChaRng rng(key_of(42), 0x4d43);  // fixed seed 42, as in the paper

    int detected_arvs = 0, detected_uniform = 0;
    double sci_arvs = 0, sci_uniform = 0;
    for (int t = 0; t < kTrials; ++t) {
        const std::uint64_t seam = n / 4 + rng.below(n / 2);
        const std::uint64_t run = (4 + rng.below(13)) * 8;  // 4-16 clusters of 8 sectors
        std::uint64_t start;
        if (rng.below(100) < 60) start = hpa.first + rng.below(hpa.end - hpa.first - run);
        else start = seam > run / 2 ? seam - run / 2 : 0;

        std::vector<std::byte> saved(dev.data().begin() + start * kSs, dev.data().begin() + (start + run) * kSs);
        std::memset(dev.data().data() + start * kSs, 0xA5, run * kSs);

        PatternOracle oracle(pat, key);
        const auto with_risk = ctx_for(n, {hpa}, {seam});
        ArvsConfig fixed;
        fixed.device_risk_gain = 0;  // equal budgets, as in the paper's Table VI
        ArvsSampler a = arvs(with_risk, static_cast<std::uint8_t>(t), fixed);
        auto ra = verify_sampled(dev, {0, n}, a, oracle, {});
        ArvsConfig flat;
        flat.device_risk_gain = 0;
        ArvsSampler u = arvs(ctx_for(n), static_cast<std::uint8_t>(t), flat);
        auto ru = verify_sampled(dev, {0, n}, u, oracle, {});
        detected_arvs += ra.status == VerificationResult::Status::Failed;
        detected_uniform += ru.status == VerificationResult::Status::Failed;
        sci_arvs += ra.sci.sci;
        sci_uniform += ru.sci.sci;
        std::memcpy(dev.data().data() + start * kSs, saved.data(), saved.size());
    }
    const double pa = double(detected_arvs) / kTrials, pu = double(detected_uniform) / kTrials;
    std::fprintf(stderr,
                 "  Monte Carlo (%d trials, 5%% budget): detection ARVS %.1f%%, uniform %.1f%%; "
                 "mean SCI ARVS %.1f, uniform %.1f\n",
                 kTrials, 100 * pa, 100 * pu, sci_arvs / kTrials, sci_uniform / kTrials);
    CHECK(pa > 0.9);
    CHECK(pa > pu + 0.3);
    // Uniform sampling misses most failures, so it reports a higher (over-confident) SCI.
    CHECK(sci_uniform / kTrials > sci_arvs / kTrials);
}

}  // namespace

int main() {
    log::set_level(log::Level::Error);
    std::string tmpl = (fs::current_path() / "dw_arvs_XXXXXX").string();
    if (!::mkdtemp(tmpl.data())) {
        std::perror("mkdtemp");
        return 1;
    }
    g_dir = tmpl;

    test_ahp();
    test_method_classification();
    test_clusters();
    test_arvs_sampler();
    test_weights_matter();
    test_sci();
    test_verify_arvs_and_rewipe();
    test_verify_cancel_and_progress();
    test_fingerprints();
    test_journal_resumes();
    test_monte_carlo();

    fs::remove_all(g_dir);
    return finish("test_arvs");
}
