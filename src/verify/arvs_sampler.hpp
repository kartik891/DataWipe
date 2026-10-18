#pragma once
// ARVS: Adaptive Risk-Based Verification Sampling (paper Section III-C).
//
// Every factor of equation (1) has a job, so every weight changes the outcome:
//
//   HOW MUCH (W, F, E: drive and method, equal for all clusters of a session)
//     budget = base * (1 + gain * D),  D = (beta*W + gamma*F + epsilon*E) / (beta + gamma + epsilon)
//     base defaults to 5% of the domain's sectors (the paper's budget), gain to 1, so the
//     budget runs from 5% (a drive and method with no device-level risk) to 10%. gain = 0 gives
//     a fixed budget, for like-for-like comparison with uniform sampling (paper Table VI).
//
//   WHERE (H, B: vary from cluster to cluster)
//     One weighted draw without replacement over all clusters, weight = floor + L(c),
//     L(c) = (alpha*H + delta*B) / (alpha + delta). A hidden-area cluster (H = 1) and a cluster
//     on a resume seam (B = 1) compete according to alpha versus delta. The floor keeps every
//     cluster reachable, so the baseline pass rate V still estimates the whole disk.
//
//   An earlier version sent a fixed half of the budget to the high-risk region by rule; an
//   ablation showed the weights then had no measurable effect, so that rule was removed.
//   The high-risk REGION (H = 1 or B >= 0.5) is still what the SCI's R term counts.
//
//   The draw uses Efraimidis-Spirakis keys, log(u)/w, top-k.
//
// Each chosen cluster is read in full (contiguous I/O, efficient on HDDs) and becomes one
// SampleUnit carrying its risk and region for the SCI (verify/sci.hpp).
//
// Deterministic: the draw is a function of the seed (recorded in the certificate), the risk
// context and the weights, so an auditor can regenerate exactly which clusters were read.

#include <cstdint>

#include "core/chacha20.hpp"
#include "core/result.hpp"
#include "verify/risk_model.hpp"
#include "verify/sector_sampler.hpp"

namespace dw {

struct ArvsConfig {
    double budget_fraction = 0.05;         // base budget, share of the domain's sectors (paper: ~5%)
    double device_risk_gain = 1.0;         // budget = base * (1 + gain * D); 0 = fixed budget
    std::uint64_t max_budget_sectors = 0;  // cap on sectors read; 0 = none
    double floor_weight = 0.02;            // draw weight of a cluster with L(c) = 0
};

class ArvsSampler final : public ISectorSampler {
public:
    using Seed = chacha20::Key;

    // Fails if the AHP judgments are inconsistent or the configuration is out of range.
    static Result<ArvsSampler> create(const Seed& seed, RiskContext ctx, const PairwiseMatrix& judgments = default_pairwise(),
                                      ArvsConfig config = {});

    // `domain` must be the risk context's domain.
    std::vector<SampleUnit> sample(const SampleDomain& domain) override;
    std::string name() const override { return "arvs"; }
    Json describe() const override;

    const AhpResult& ahp() const { return ahp_; }
    const RiskContext& context() const { return ctx_; }

private:
    ArvsSampler(const Seed& seed, RiskContext ctx, const PairwiseMatrix& m, AhpResult ahp, ArvsConfig cfg)
        : seed_(seed), ctx_(std::move(ctx)), matrix_(m), ahp_(ahp), cfg_(cfg) {}

    Seed seed_;
    RiskContext ctx_;
    PairwiseMatrix matrix_;
    AhpResult ahp_;
    ArvsConfig cfg_;
    // From the last sample(), for describe().
    std::uint64_t clusters_ = 0, high_risk_clusters_ = 0, chosen_ = 0, chosen_high_ = 0, budget_sectors_ = 0;
    double mean_risk_ = 0, max_risk_ = 0, device_risk_ = 0, effective_fraction_ = 0;
};

}  // namespace dw
