#include "verify/arvs_sampler.hpp"

#include <algorithm>
#include <cmath>
#include <format>

#include "core/chacha_rng.hpp"
#include "core/sha256.hpp"

namespace dw {

namespace {

constexpr std::uint64_t kArvsStream = 0x4152565300000000;  // "ARVS"

// Indices of the k items with the largest Efraimidis-Spirakis keys log(u)/w.
std::vector<std::size_t> weighted_draw(ChaChaRng& rng, const std::vector<std::size_t>& items,
                                       const std::vector<double>& weight, std::size_t k) {
    if (k >= items.size()) return items;
    std::vector<std::pair<double, std::size_t>> keyed;
    keyed.reserve(items.size());
    for (std::size_t i : items) keyed.push_back({std::log(rng.open01()) / weight[i], i});
    std::nth_element(keyed.begin(), keyed.begin() + static_cast<std::ptrdiff_t>(k), keyed.end(),
                     [](const auto& a, const auto& b) { return a.first > b.first; });
    std::vector<std::size_t> out;
    out.reserve(k);
    for (std::size_t i = 0; i < k; ++i) out.push_back(keyed[i].second);
    return out;
}

}  // namespace

Result<ArvsSampler> ArvsSampler::create(const Seed& seed, RiskContext ctx, const PairwiseMatrix& judgments,
                                        ArvsConfig cfg) {
    if (!(cfg.budget_fraction > 0 && cfg.budget_fraction <= 1)) return error("ARVS budget must be in (0, 100%]");
    if (!(cfg.device_risk_gain >= 0 && cfg.device_risk_gain <= 10)) return error("ARVS device-risk gain must be in [0, 10]");
    if (!(cfg.floor_weight > 0)) return error("ARVS floor weight must be positive");
    if (ctx.domain.end <= ctx.domain.first) return error("ARVS domain is empty");
    if (ctx.cluster_sectors == 0) ctx.cluster_sectors = choose_cluster_sectors(ctx.domain.end - ctx.domain.first, ctx.sector_size);
    auto a = ahp_weights(judgments);
    if (!a) return a.error();
    return ArvsSampler(seed, std::move(ctx), judgments, *a, cfg);
}

std::vector<SampleUnit> ArvsSampler::sample(const SampleDomain& d) {
    std::vector<SampleUnit> out;
    if (d.first_sector != ctx_.domain.first || d.first_sector + d.sector_count != ctx_.domain.end) return out;

    const std::vector<Cluster> clusters = score_clusters(ctx_, ahp_.weights);
    const std::uint64_t domain_sectors = ctx_.domain.end - ctx_.domain.first;

    // How much: W, F, E scale the budget.
    device_risk_ = device_risk(ctx_, ahp_.weights);
    effective_fraction_ = std::min(1.0, cfg_.budget_fraction * (1 + cfg_.device_risk_gain * device_risk_));
    std::uint64_t budget = static_cast<std::uint64_t>(std::ceil(effective_fraction_ * double(domain_sectors)));
    if (cfg_.max_budget_sectors) budget = std::min(budget, cfg_.max_budget_sectors);
    budget = std::max(budget, ctx_.cluster_sectors);
    const std::size_t k = std::min<std::size_t>(
        clusters.size(), static_cast<std::size_t>((budget + ctx_.cluster_sectors - 1) / ctx_.cluster_sectors));

    // Where: H and B, through L(c).
    std::vector<double> weight(clusters.size());
    std::vector<std::size_t> all(clusters.size());
    std::size_t high = 0;
    double sum = 0;
    max_risk_ = 0;
    for (std::size_t i = 0; i < clusters.size(); ++i) {
        weight[i] = cfg_.floor_weight + clusters[i].location;
        all[i] = i;
        sum += clusters[i].risk;
        max_risk_ = std::max(max_risk_, clusters[i].risk);
        high += clusters[i].high_risk;
    }
    ChaChaRng rng(seed_, kArvsStream);
    std::vector<std::size_t> chosen = weighted_draw(rng, all, weight, k);
    std::sort(chosen.begin(), chosen.end());

    chosen_high_ = 0;
    for (std::size_t i : chosen) {
        const Cluster& c = clusters[i];
        out.push_back({c.range.first, c.range.end - c.range.first, c.risk, c.high_risk});
        chosen_high_ += c.high_risk;
    }
    clusters_ = clusters.size();
    high_risk_clusters_ = high;
    chosen_ = chosen.size();
    budget_sectors_ = budget;
    mean_risk_ = clusters.empty() ? 0 : sum / double(clusters.size());
    return out;
}

Json ArvsSampler::describe() const {
    Json j = Json::object();
    j["name"] = name();
    j["seed"] = to_hex(std::span<const std::uint8_t>(seed_));
    j["rng"] = "ChaCha20 keystream, nonce 0x4152565300000000; Efraimidis-Spirakis weighted draw without replacement";
    j["budget_base_fraction"] = cfg_.budget_fraction;
    j["device_risk_gain"] = cfg_.device_risk_gain;
    j["device_risk_D"] = device_risk_;
    j["budget_fraction"] = effective_fraction_;
    j["budget_rule"] = "base * (1 + gain * D), D = (beta*W + gamma*F + epsilon*E)/(beta + gamma + epsilon)";
    j["budget_sectors"] = budget_sectors_;
    if (cfg_.max_budget_sectors) j["max_budget_sectors"] = cfg_.max_budget_sectors;
    j["floor_weight"] = cfg_.floor_weight;
    j["allocation_rule"] = "weighted draw, weight = floor + (alpha*H + delta*B)/(alpha + delta)";
    j["high_risk_rule"] = std::format("H = 1 or B >= {}", kHighRiskBoundary);
    Json& w = j["weights"];
    w["alpha_H"] = ahp_.weights[kH];
    w["beta_W"] = ahp_.weights[kW];
    w["gamma_F"] = ahp_.weights[kF];
    w["delta_B"] = ahp_.weights[kB];
    w["epsilon_E"] = ahp_.weights[kE];
    Json& a = j["ahp"];
    a["factor_order"] = "H, W, F, B, E";
    a["pairwise"] = to_json(matrix_);
    a["lambda_max"] = ahp_.lambda_max;
    a["consistency_ratio"] = ahp_.consistency_ratio;
    j["risk_context"] = to_json(ctx_);
    j["clusters_total"] = clusters_;
    j["clusters_high_risk"] = high_risk_clusters_;
    j["clusters_sampled"] = chosen_;
    j["clusters_sampled_high_risk"] = chosen_high_;
    j["mean_risk"] = mean_risk_;
    j["max_risk"] = max_risk_;
    return j;
}

}  // namespace dw
