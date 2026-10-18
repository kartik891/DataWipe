#pragma once
// Sanitization Confidence Index (paper Section III-C, equations 3 and 4).
//
//   SCI = ( Wc * Vpass/Vtotal + Wr * Rhigh/Rtotal ) / (Wc + Wr) * 100
//   Wc = 1 / (1 + lambda),  Wr = lambda / (1 + lambda)
//
// V counts sampled units in the baseline region, R those in the high-risk region; "pass" is
// the FIRST read-back, before any re-wipe, so the index measures how well the sanitization
// itself worked. lambda > 1 makes a high-risk failure cost lambda times a baseline failure.
// With Wc + Wr = 1 the SCI is a convex combination in [0, 100].
//
// If one region was not sampled at all its term is undefined; the SCI is then the other
// region's pass rate, and `note` says so. The paper leaves lambda to a failure-impact analysis;
// the default here (3) is illustrative, and every certificate records the value used.

#include <cstdint>
#include <string>

#include "core/json.hpp"

namespace dw {

inline constexpr double kDefaultSciLambda = 3.0;

struct SciInput {
    std::uint64_t baseline_total = 0, baseline_pass = 0;
    std::uint64_t high_total = 0, high_pass = 0;
    double lambda = kDefaultSciLambda;
};

struct SciResult {
    double sci = 0;  // [0, 100]
    double wc = 0, wr = 0;
    double v = 0, r = 0;  // pass rates; meaningful when the region was sampled
    bool defined = false;
    std::string note;
};

SciResult compute_sci(const SciInput& in);
Json to_json(const SciInput& in, const SciResult& r);

}  // namespace dw
