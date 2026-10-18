#pragma once
// Read-back verification (paper Section III-C and workflow Stage 6).
//
// For every unit an ISectorSampler chooses (ARVS clusters, or uniform single sectors), read
// the sectors from the medium and ask an IContentOracle whether each one is acceptable:
//   PatternOracle      the plan ended in a host-known pattern (HDD overwrite): the sector must
//                      equal the pattern regenerated from key, stream and offset.
//   FingerprintOracle  the plan ended in a device-internal erase (SSD crypto/block erase,
//                      sanitize) whose output is vendor-defined: the sector must NO LONGER
//                      match the hash taken of it before the wipe (verify/fingerprint.hpp).
//                      Sectors that held one repeated byte before the wipe (never-written,
//                      zero-filled) are uninformative: an erase and no change look the same.
//
// A unit passes its first read if none of its informative sectors is bad or unreadable. The
// SCI (verify/sci.hpp) is computed from these first reads.
//
// Stage 6, re-wipe: a unit that fails is overwritten in full with a known pattern (the
// expected pattern, or a dedicated re-wipe stream after an internal erase), flushed, evicted
// from the cache and read again, up to `rewipe_attempts` times. Sectors that still fail are
// reported as NOT VERIFIED. A repaired unit does not make the result "passed": a failure in
// the sample means unsampled areas may have failed the same way (status Repaired).
//
// Reading from the medium, not from memory: the CLI verifies through a separate read-only
// handle opened with O_DIRECT where the filesystem allows it; otherwise each read is preceded
// by a page-cache eviction of that range. On a loop device this reaches the loop node's
// backing file; attach with --direct-io=on for the read to reach the disk under it.

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "core/cancel.hpp"
#include "core/json.hpp"
#include "core/result.hpp"
#include "device/block_device.hpp"
#include "engine/pattern.hpp"
#include "engine/wipe_plan.hpp"
#include "verify/sci.hpp"
#include "verify/sector_sampler.hpp"

namespace dw {

class IContentOracle {
public:
    enum class Verdict { Ok, Bad, Uninformative };
    virtual ~IContentOracle() = default;
    virtual Verdict check(std::uint64_t lba, std::span<const std::byte> sector) = 0;
    virtual std::string describe() const = 0;
};

class PatternOracle final : public IContentOracle {
public:
    PatternOracle(const PatternSpec& pattern, const PatternKey& key) : gen_(pattern, key) {}
    Verdict check(std::uint64_t lba, std::span<const std::byte> sector) override;
    std::string describe() const override { return gen_.spec().describe(); }

private:
    PatternGenerator gen_;
    std::vector<std::byte> want_;
};

// Pattern used to re-wipe after a device-internal erase: independent of every plan stream.
inline constexpr std::uint32_t kRewipeStream = 0x52455750;  // "REWP"

struct VerifyConfig {
    std::size_t max_listed = 16;  // sector numbers kept per list
    double sci_lambda = kDefaultSciLambda;
    // Stage 6 re-wipe. Null device = verification only (e.g. `datawipe verify`).
    IBlockDevice* rewipe_device = nullptr;
    unsigned rewipe_attempts = 3;
    PatternSpec rewipe_pattern;  // what a re-wipe writes (and the re-read then expects)
    PatternKey rewipe_key{};
    // Verification of a large drive takes as long as a good part of a pass: it can be
    // interrupted between units (status Interrupted, nothing changed) and reports progress.
    const CancelToken* cancel = nullptr;
    std::function<void(std::uint64_t units_done, std::uint64_t units_total, std::uint64_t sectors_read)> on_progress;
};

struct VerificationResult {
    enum class Status { Passed, Repaired, Failed, Inconclusive, NotApplicable, Skipped, Interrupted } status =
        Status::NotApplicable;
    std::string reason;

    std::string expected;  // IContentOracle::describe()
    std::uint64_t first_sector = 0;
    std::uint64_t sectors_in_range = 0;

    std::uint64_t units_sampled = 0;
    std::uint64_t units_uninformative = 0;  // no informative sector: excluded from the SCI
    std::uint64_t units_passed_first = 0;
    std::uint64_t units_repaired = 0;
    std::uint64_t sectors_sampled = 0;  // read
    std::uint64_t sectors_matched = 0;
    std::uint64_t sectors_mismatched = 0;  // first read
    std::uint64_t sectors_unreadable = 0;  // first read
    std::uint64_t sectors_uninformative = 0;
    std::uint64_t sectors_not_verified = 0;  // still bad after every re-wipe attempt
    std::vector<std::uint64_t> mismatched;    // first few, absolute sector numbers
    std::vector<std::uint64_t> unreadable;    // first few
    std::vector<std::uint64_t> not_verified;  // first few
    double coverage_percent = 0;              // sectors read / sectors in range
    double detectable_fraction = 0;           // uniform single-sector samples only; else 0
    std::string read_mode;
    Json sampler;  // ISectorSampler::describe()
    SciInput sci_input;
    SciResult sci;
    double seconds = 0;

    bool passed() const { return status == Status::Passed; }
};

// Verify `units` (already drawn) against `oracle`.
VerificationResult verify_units(IBlockDevice& device, SampleDomain domain, const std::vector<SampleUnit>& units,
                                IContentOracle& oracle, const Json& sampler_description, const VerifyConfig& config);

// Draw from `sampler`, then verify_units().
VerificationResult verify_sampled(IBlockDevice& device, SampleDomain domain, ISectorSampler& sampler,
                                  IContentOracle& oracle, const VerifyConfig& config);

// Plans ending in a host-known pattern: the expectation names range and pattern.
VerificationResult verify_readback(const VerificationExpectation& expectation, IBlockDevice& device,
                                   const PatternKey& key, ISectorSampler& sampler, const VerifyConfig& config = {});

VerificationResult verification_not_performed(VerificationResult::Status status, std::string reason);

std::string_view to_string(VerificationResult::Status s);
Json to_json(const VerificationResult& r);

}  // namespace dw
