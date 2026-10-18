#pragma once
// Which sectors the read-back verifier inspects.
//
// ISectorSampler returns sample units: contiguous sector ranges, each with the risk score and
// region (high-risk or baseline) the Sanitization Confidence Index needs. Two samplers:
//   ArvsSampler (verify/arvs_sampler.hpp): the default, risk-weighted clusters (paper III-C).
//   UniformSampler (below): single sectors drawn uniformly, the paper's baseline comparison.
//
// UniformSampler: k distinct sectors drawn uniformly without replacement, plus the
// first and last sector of the range.
//   * Uniform sampling answers "what fraction of the range could still be unwritten?": if a
//     fraction p of sectors is wrong, k samples all miss it with probability about (1-p)^k.
//     The default k = 4603 detects p >= 0.1% with 99% confidence, independent of disk size.
//   * It does NOT find small concentrated defects: a skipped 1 MiB extent on a 1 TB disk is
//     p = 1e-6 and is almost never sampled. That gap is exactly what ARVS is for.
//   * The two edge sectors are the cheapest check against off-by-one range errors, which a
//     uniform sample almost never hits.
//   * The random source is ChaCha20 keyed with a 256-bit seed recorded in the certificate, so
//     the exact sample is reproducible (by anyone holding the seed) and platform-independent;
//     std::uniform_int_distribution is not specified bit-exactly across standard libraries.

#include <cstdint>
#include <string>
#include <vector>

#include "core/chacha20.hpp"
#include "core/json.hpp"

namespace dw {

struct SampleDomain {
    std::uint64_t first_sector = 0;
    std::uint64_t sector_count = 0;
};

struct SampleUnit {
    std::uint64_t first_sector = 0;
    std::uint64_t sector_count = 1;
    double risk = 0;         // ARVS Risk(c); 0 for samplers without a risk model
    bool high_risk = false;  // counts toward R (high-risk region) instead of V in the SCI
    bool operator==(const SampleUnit&) const = default;
};

class ISectorSampler {
public:
    virtual ~ISectorSampler() = default;
    // Units inside `domain`, sorted by first sector (so reads sweep forward), non-overlapping.
    virtual std::vector<SampleUnit> sample(const SampleDomain& domain) = 0;
    virtual std::string name() const = 0;
    // Parameters needed to reproduce the sample; recorded in the certificate.
    virtual Json describe() const = 0;
};

// Sample size for "a bad fraction >= p is found with probability >= confidence":
// smallest k with (1-p)^k <= 1-confidence.
std::uint64_t sample_size_for(double p, double confidence);
// The converse, for a sample actually taken: smallest bad fraction detected with `confidence`.
double detectable_fraction(std::uint64_t samples, std::uint64_t population, double confidence);

class UniformSampler final : public ISectorSampler {
public:
    static constexpr std::uint64_t kDefaultSamples = 4603;  // sample_size_for(0.001, 0.99)
    using Seed = chacha20::Key;

    UniformSampler(const Seed& seed, std::uint64_t samples) : seed_(seed), samples_(samples) {}

    std::vector<SampleUnit> sample(const SampleDomain& domain) override;
    std::string name() const override { return "uniform"; }
    Json describe() const override;

private:
    Seed seed_;
    std::uint64_t samples_;
};

}  // namespace dw
