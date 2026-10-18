#include "verify/sector_sampler.hpp"

#include <cmath>
#include <cstring>
#include <set>

#include "core/chacha_rng.hpp"
#include "core/sha256.hpp"

namespace dw {

namespace {
constexpr std::uint64_t kSampleStream = 0x5645524946590000;  // "VERIFY": no overwrite pass uses it
}  // namespace

std::uint64_t sample_size_for(double p, double confidence) {
    if (p <= 0 || p >= 1 || confidence <= 0 || confidence >= 1) return 0;
    return static_cast<std::uint64_t>(std::ceil(std::log1p(-confidence) / std::log1p(-p)));
}

double detectable_fraction(std::uint64_t samples, std::uint64_t population, double confidence) {
    if (samples == 0 || population == 0) return 1;
    if (samples >= population) return 1.0 / double(population);  // exhaustive: any single sector
    return 1 - std::pow(1 - confidence, 1.0 / double(samples));
}

std::vector<SampleUnit> UniformSampler::sample(const SampleDomain& d) {
    std::vector<SampleUnit> out;
    if (d.sector_count == 0) return out;
    const std::uint64_t n = d.sector_count;
    if (samples_ >= n) {  // the sample would be the whole range: read all of it
        out.resize(n);
        for (std::uint64_t i = 0; i < n; ++i) out[i].first_sector = d.first_sector + i;
        return out;
    }
    // Floyd's algorithm: k distinct values from [0, n) in k draws, with no O(n) memory.
    // The edges are added afterwards: Floyd's uniformity argument needs an empty start set.
    ChaChaRng rng(seed_, kSampleStream);
    std::set<std::uint64_t> picked;
    for (std::uint64_t j = n - samples_; j < n; ++j) {
        const std::uint64_t t = rng.below(j + 1);
        picked.insert(picked.contains(t) ? j : t);
    }
    picked.insert(0);
    picked.insert(n - 1);
    out.reserve(picked.size());
    for (std::uint64_t s : picked) out.push_back({d.first_sector + s, 1, 0, false});
    return out;
}

Json UniformSampler::describe() const {
    Json j = Json::object();
    j["name"] = name();
    j["requested_samples"] = samples_;
    j["includes_range_edges"] = true;
    j["rng"] = "ChaCha20 keystream, nonce 0x5645524946590000, rejection-sampled, Floyd's algorithm";
    j["seed"] = to_hex(std::span<const std::uint8_t>(seed_));
    return j;
}

}  // namespace dw
