#pragma once
// ARVS risk model (paper Section III-C, equation 1 and Table II).
//
//   Risk(c) = alpha*H + beta*W + gamma*F + delta*B + epsilon*E        for each cluster c
//
//   H  hidden area      1 if the cluster lies in a region an HPA/DCO hid before the wipe, else 0
//   W  wear levelling   drive wear ratio / max wear ratio (NVMe "Percentage Used"/100, SMART
//                       wear attributes on SATA SSDs); 0 for HDDs, which do not remap on wear
//   F  firmware         probability that the method which produced the cluster's final
//                       content left data behind although it reported success (see
//                       method_prior() for the source or assumption behind each value)
//   B  boundary         1 - distance to the nearest boundary / max boundary offset, clamped at 0.
//                       Boundaries: the range edges, hidden-area edges, and every point where
//                       an interrupted pass was resumed
//   E  erase method     1 - host-visible assurance of the method. DEVIATION FROM THE PAPER'S
//                       TABLE II: the paper lists E as a confidence (host overwrite 0.9, native
//                       Sanitize/Crypto Erase 0.2) but adds it to the risk sum, which would make
//                       the most verifiable method the riskiest. The paper's own explanation
//                       ("lower host-visible assurance") says native methods deserve MORE
//                       verification, so the risk term uses 1 - confidence.
//
// Weights come from the Analytic Hierarchy Process: a 5x5 pairwise comparison matrix of the
// factors (Saaty 1-9 scale), whose normalized principal eigenvector gives alpha..epsilon with
// alpha+...+epsilon = 1 (equation 2). The consistency ratio CR = CI / RI must be below 0.1 or
// the judgments contradict each other and are rejected.
//
// Calibration status of the defaults, stated per value in method_prior():
//   MEASURED   derived from counts in Wei et al., "Reliably Erasing Data from Flash-Based Solid
//              State Drives", USENIX FAST 2011 (Tables 1 and 2). Samples are 4-8 drives, so the
//              estimate is the Jeffreys posterior mean (x + 1/2) / (n + 1), with its 95% interval
//              recorded; it never reports 0 from "0 failures in 4".
//   ASSUMED    no published failure rate exists; the value is a stated assumption.
// The AHP judgments are the author's; SCI's lambda is illustrative (paper Section III-C).
// Every certificate records matrix, weights and priors so sessions can be re-scored later.

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "core/json.hpp"
#include "core/result.hpp"
#include "device/classifier.hpp"
#include "engine/wipe_plan.hpp"

namespace dw {

// ---- Methods ----

enum class EraseMethod {
    HostOverwrite,
    AtaSecureErase,
    AtaSecureEraseEnhanced,
    AtaSanitizeCrypto,
    AtaSanitizeBlock,
    AtaSanitizeOverwrite,
    NvmeSanitizeCrypto,
    NvmeSanitizeBlock,
    NvmeSanitizeOverwrite,
    NvmeFormatCrypto,
    NvmeFormatUserData,
    OpalGenKey,
    EmmcSanitize,
    Discard,
};
std::string_view to_string(EraseMethod m);

// The method whose effect a step leaves on the medium: its last action command (by opcode),
// or a plain host overwrite for a step with no device commands.
EraseMethod classify_step(const WipeStep& step);
// The method behind the medium's final content: the last step that changes it.
EraseMethod final_method(const WipePlan& plan);

struct MethodPrior {
    double failure_rate = 1;  // F
    double confidence = 0;    // host-visible assurance; E = 1 - confidence
    std::string basis;        // where the numbers come from
    bool measured = false;    // F derived from published counts (else an assumption)
    int failures = -1, trials = -1;  // the counts, when measured
    double ci_low = 0, ci_high = 1;  // 95% Jeffreys interval, when measured
};
// `host_passes`: full host overwrite passes in the plan (matters for flash, Wei et al. Table 2).
MethodPrior method_prior(EraseMethod method, MediaType media, unsigned host_passes = 1);

// ---- AHP ----

enum Factor { kH, kW, kF, kB, kE, kFactors };
using PairwiseMatrix = std::array<std::array<double, kFactors>, kFactors>;
using RiskWeights = std::array<double, kFactors>;  // alpha, beta, gamma, delta, epsilon

PairwiseMatrix default_pairwise();

struct AhpResult {
    RiskWeights weights{};
    double lambda_max = 0;
    double consistency_index = 0;
    double consistency_ratio = 0;
};
// Principal eigenvector by power iteration. Fails on a matrix that is not positive and
// reciprocal, or whose consistency ratio is >= 0.1.
Result<AhpResult> ahp_weights(const PairwiseMatrix& m);

// ---- Clusters ----

struct SectorRange {
    std::uint64_t first = 0;
    std::uint64_t end = 0;  // exclusive
};

struct RiskContext {
    SectorRange domain;                 // what verification covers
    std::uint32_t sector_size = 512;
    std::uint64_t cluster_sectors = 0;  // 0 = choose_cluster_sectors()
    std::vector<SectorRange> hidden;    // regions an HPA/DCO hid before the wipe
    std::vector<std::uint64_t> boundaries;  // besides domain and hidden edges: resume points
    std::uint64_t boundary_reach = 0;   // "max boundary offset", in sectors; 0 = 1% of domain
    double wear_ratio = 0;              // W, already in [0, 1]
    EraseMethod method = EraseMethod::HostOverwrite;
    MediaType media = MediaType::HDD;
    unsigned host_passes = 1;  // full host overwrite passes in the plan
};

// Cluster size: a power-of-two multiple of 4 KiB giving at most 65536 clusters (and at least
// 4 KiB), so scoring stays O(65536) and each sampled cluster is one contiguous read.
std::uint64_t choose_cluster_sectors(std::uint64_t domain_sectors, std::uint32_t sector_size);

// Everything the risk model needs, from the detected profile, the plan, and the absolute
// sectors where interrupted passes of the final-content step resumed.
RiskContext make_risk_context(const DeviceProfile& profile, const WipePlan& plan, SectorRange domain,
                              const std::vector<std::uint64_t>& resume_points);

struct RiskFactors {
    double h = 0, w = 0, f = 0, b = 0, e = 0;
};

struct Cluster {
    SectorRange range;
    RiskFactors factors;
    double risk = 0;          // equation (1), all five factors
    double location = 0;      // (alpha*H + delta*B) / (alpha + delta): steers WHERE ARVS reads
    bool high_risk = false;   // in the high-risk region (HRR): hidden area or near a boundary
};

// The two roles of the factors (arvs_sampler.hpp):
//   H and B vary from cluster to cluster: they decide where the budget goes (Cluster::location).
//   W, F and E are properties of the drive and the method, equal for every cluster of a
//   session: they decide how much to read. device_risk() is their weighted mean, in [0, 1].
double device_risk(const RiskContext& ctx, const RiskWeights& w);

// A cluster is in the high-risk region when it is hidden (H = 1) or B >= this.
inline constexpr double kHighRiskBoundary = 0.5;

std::vector<Cluster> score_clusters(const RiskContext& ctx, const RiskWeights& w);

Json to_json(const RiskContext& ctx);
Result<RiskContext> risk_context_from_json(const Json& j);
Json to_json(const PairwiseMatrix& m);

}  // namespace dw
