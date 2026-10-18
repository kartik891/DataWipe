#include "verify/readback_verifier.hpp"

#include <chrono>
#include <cstdlib>
#include <cstring>
#include <format>
#include <functional>

#include "core/log.hpp"
#include "verify/sector_io.hpp"

namespace dw {

namespace {

constexpr double kConfidence = 0.99;
void note(std::vector<std::uint64_t>& list, std::uint64_t lba, std::size_t max) {
    if (list.size() < max) list.push_back(lba);
}

}  // namespace

IContentOracle::Verdict PatternOracle::check(std::uint64_t lba, std::span<const std::byte> sector) {
    want_.resize(sector.size());
    gen_.fill(lba * sector.size(), want_);
    return std::memcmp(want_.data(), sector.data(), sector.size()) == 0 ? Verdict::Ok : Verdict::Bad;
}

VerificationResult verification_not_performed(VerificationResult::Status status, std::string reason) {
    VerificationResult r;
    r.status = status;
    r.reason = std::move(reason);
    return r;
}

VerificationResult verify_units(IBlockDevice& device, SampleDomain domain, const std::vector<SampleUnit>& units,
                                IContentOracle& oracle, const Json& sampler_description, const VerifyConfig& cfg) {
    using V = IContentOracle::Verdict;
    const auto t0 = std::chrono::steady_clock::now();
    VerificationResult r;
    r.expected = oracle.describe();
    r.first_sector = domain.first_sector;
    r.sectors_in_range = domain.sector_count;
    r.sampler = sampler_description;
    r.read_mode = device.direct_io() ? "O_DIRECT" : "buffered + page-cache eviction";
    r.sci_input.lambda = cfg.sci_lambda;
    auto fail = [&](std::string why) {
        r.status = VerificationResult::Status::Failed;
        r.reason = std::move(why);
        return r;
    };
    if (domain.sector_count == 0 || domain.first_sector + domain.sector_count > device.geometry().sector_count())
        return fail(std::format("expected range [{}, +{}) does not fit the device's {} sectors", domain.first_sector,
                                domain.sector_count, device.geometry().sector_count()));
    SectorIo io(device);
    if (!io.ok()) return fail("cannot allocate the read buffer");
    std::unique_ptr<SectorIo> wio;
    if (cfg.rewipe_device) wio = std::make_unique<SectorIo>(*cfg.rewipe_device);
    const std::uint64_t ss = io.sector_size();
    const std::uint64_t domain_end = domain.first_sector + domain.sector_count;

    // Check sectors [first, first+n) with `judge`; collects bad/unreadable sector numbers.
    struct Scan {
        std::vector<std::uint64_t> bad, unreadable;
        std::uint64_t ok = 0, uninformative = 0, read = 0;
    };
    auto scan = [&](std::uint64_t first, std::uint64_t n, const std::function<V(std::uint64_t, std::span<const std::byte>)>& judge) {
        Scan s;
        for (std::uint64_t pos = first; pos < first + n;) {
            const std::uint64_t k = std::min(io.max_sectors(), first + n - pos);
            auto chunk = io.read(pos, k);
            for (std::uint64_t i = 0; i < k; ++i) {
                const std::uint64_t lba = pos + i;
                ++s.read;
                std::span<const std::byte> sector;
                if (chunk) {
                    sector = chunk->subspan(i * ss, ss);
                } else {  // isolate the unreadable sector(s) of a failed chunk
                    auto one = io.read(lba, 1);
                    if (!one) {
                        log::debug("verify: sector {} unreadable: {}", lba, one.error().describe());
                        s.unreadable.push_back(lba);
                        continue;
                    }
                    sector = *one;
                }
                switch (judge(lba, sector)) {
                    case V::Ok: ++s.ok; break;
                    case V::Bad: s.bad.push_back(lba); break;
                    case V::Uninformative: ++s.uninformative; break;
                }
            }
            pos += k;
        }
        return s;
    };

    bool interrupted = false;
    for (const SampleUnit& u : units) {
        if (cfg.cancel && cfg.cancel->requested()) {
            interrupted = true;
            break;
        }
        if (cfg.on_progress) cfg.on_progress(r.units_sampled, units.size(), r.sectors_sampled);
        if (u.sector_count == 0 || u.first_sector < domain.first_sector || u.first_sector + u.sector_count > domain_end)
            return fail(std::format("sampler returned unit [{}, +{}) outside the range", u.first_sector, u.sector_count));
        ++r.units_sampled;
        Scan s = scan(u.first_sector, u.sector_count,
                      [&](std::uint64_t lba, std::span<const std::byte> d) { return oracle.check(lba, d); });
        r.sectors_sampled += s.read;
        r.sectors_matched += s.ok;
        r.sectors_uninformative += s.uninformative;
        r.sectors_mismatched += s.bad.size();
        r.sectors_unreadable += s.unreadable.size();
        for (auto x : s.bad) note(r.mismatched, x, cfg.max_listed);
        for (auto x : s.unreadable) note(r.unreadable, x, cfg.max_listed);

        const bool informative = s.ok + s.bad.size() + s.unreadable.size() > 0;
        const bool first_pass = s.bad.empty() && s.unreadable.empty();
        if (!informative) {
            ++r.units_uninformative;
            continue;
        }
        (u.high_risk ? r.sci_input.high_total : r.sci_input.baseline_total)++;
        if (first_pass) {
            ++r.units_passed_first;
            (u.high_risk ? r.sci_input.high_pass : r.sci_input.baseline_pass)++;
            continue;
        }

        // Stage 6: re-wipe the whole unit, flush, read back against the re-wipe pattern.
        std::vector<std::uint64_t> still = s.bad;
        still.insert(still.end(), s.unreadable.begin(), s.unreadable.end());
        if (wio && wio->ok()) {
            PatternGenerator gen(cfg.rewipe_pattern, cfg.rewipe_key);
            PatternOracle after(cfg.rewipe_pattern, cfg.rewipe_key);
            for (unsigned attempt = 1; attempt <= cfg.rewipe_attempts && !still.empty(); ++attempt) {
                bool wrote = true;
                for (std::uint64_t pos = u.first_sector; pos < u.first_sector + u.sector_count && wrote;) {
                    const std::uint64_t k = std::min(wio->max_sectors(), u.first_sector + u.sector_count - pos);
                    if (auto w = wio->write(pos, k, [&](std::uint64_t off, std::span<std::byte> b) { gen.fill(off, b); }); !w) {
                        log::warn("re-wipe of sectors [{}, +{}) failed: {}", pos, k, w.error().describe());
                        wrote = false;
                    }
                    pos += k;
                }
                if (wrote) {
                    if (auto f = cfg.rewipe_device->flush(); !f) {
                        log::warn("flush after re-wipe failed: {}", f.error().describe());
                        wrote = false;
                    }
                    (void)cfg.rewipe_device->drop_cache(u.first_sector * ss, u.sector_count * ss);
                }
                if (!wrote) continue;
                Scan again = scan(u.first_sector, u.sector_count,
                                  [&](std::uint64_t lba, std::span<const std::byte> d) { return after.check(lba, d); });
                still = again.bad;
                still.insert(still.end(), again.unreadable.begin(), again.unreadable.end());
                log::info("re-wipe attempt {} of sectors [{}, +{}): {} sector(s) still failing", attempt, u.first_sector,
                          u.sector_count, still.size());
            }
        }
        if (still.empty()) {
            ++r.units_repaired;
        } else {
            r.sectors_not_verified += still.size();
            for (auto x : still) note(r.not_verified, x, cfg.max_listed);
        }
    }

    r.coverage_percent = 100.0 * double(r.sectors_sampled) / double(domain.sector_count);
    bool single = true;
    for (const auto& u : units) single &= u.sector_count == 1;
    if (single) r.detectable_fraction = detectable_fraction(r.sectors_sampled, domain.sector_count, kConfidence);
    r.sci = compute_sci(r.sci_input);
    r.seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();

    if (cfg.on_progress) cfg.on_progress(r.units_sampled, units.size(), r.sectors_sampled);
    if (interrupted) {
        r.status = VerificationResult::Status::Interrupted;
        r.reason = std::format("interrupted after {} of {} units; verification changes nothing, so it can simply be "
                               "repeated",
                               r.units_sampled, units.size());
        return r;
    }
    if (r.units_sampled == 0) return fail("the sampler chose no sectors");
    const std::uint64_t failed_units = r.units_sampled - r.units_uninformative - r.units_passed_first;
    if (r.sectors_not_verified && cfg.rewipe_device && cfg.rewipe_attempts)
        return fail(std::format("{} of {} sampled sectors failed; after {} re-wipe attempt(s) {} still fail: NOT "
                                "VERIFIED",
                                r.sectors_mismatched + r.sectors_unreadable, r.sectors_sampled, cfg.rewipe_attempts,
                                r.sectors_not_verified));
    if (failed_units && r.units_repaired == failed_units) {
        r.status = VerificationResult::Status::Repaired;
        r.reason = std::format("{} of {} sampled units failed the first read ({} sectors bad, {} unreadable) and "
                               "passed after re-wipe; unsampled areas may have failed the same way",
                               failed_units, r.units_sampled - r.units_uninformative, r.sectors_mismatched,
                               r.sectors_unreadable);
        return r;
    }
    if (failed_units)
        return fail(std::format("{} of {} sampled sectors do not hold the expected content{}", r.sectors_mismatched,
                                r.sectors_sampled,
                                r.sectors_unreadable ? std::format(", {} could not be read", r.sectors_unreadable)
                                                     : std::string()));
    if (r.units_uninformative == r.units_sampled) {
        r.status = VerificationResult::Status::Inconclusive;
        r.reason = "every sampled sector held a constant fill before the wipe: an erase and no change look the same";
        return r;
    }
    r.status = VerificationResult::Status::Passed;
    r.reason = std::format("all {} sampled units ({} sectors) hold the expected content", r.units_sampled - r.units_uninformative,
                           r.sectors_matched);
    return r;
}

VerificationResult verify_sampled(IBlockDevice& device, SampleDomain domain, ISectorSampler& sampler,
                                  IContentOracle& oracle, const VerifyConfig& config) {
    const auto units = sampler.sample(domain);
    return verify_units(device, domain, units, oracle, sampler.describe(), config);
}

VerificationResult verify_readback(const VerificationExpectation& expectation, IBlockDevice& device,
                                   const PatternKey& key, ISectorSampler& sampler, const VerifyConfig& config) {
    if (expectation.kind != VerificationExpectation::Kind::Pattern || !expectation.expected)
        return verification_not_performed(VerificationResult::Status::NotApplicable, expectation.reason);
    const OverwriteSpec& spec = *expectation.expected;
    PatternOracle oracle(spec.pattern, key);
    VerifyConfig cfg = config;
    cfg.rewipe_pattern = spec.pattern;  // re-wiping restores exactly the expected content
    cfg.rewipe_key = key;
    return verify_sampled(device, {spec.first_sector, spec.sector_count}, sampler, oracle, cfg);
}

std::string_view to_string(VerificationResult::Status s) {
    switch (s) {
        case VerificationResult::Status::Passed: return "passed";
        case VerificationResult::Status::Repaired: return "repaired";
        case VerificationResult::Status::Failed: return "failed";
        case VerificationResult::Status::Inconclusive: return "inconclusive";
        case VerificationResult::Status::NotApplicable: return "not-applicable";
        case VerificationResult::Status::Skipped: return "skipped";
        case VerificationResult::Status::Interrupted: return "interrupted";
    }
    return "?";
}

Json to_json(const VerificationResult& r) {
    Json j = Json::object();
    j["status"] = to_string(r.status);
    j["reason"] = r.reason;
    if (r.status == VerificationResult::Status::NotApplicable || r.status == VerificationResult::Status::Skipped)
        return j;
    j["expected_content"] = r.expected;
    j["range"]["first_sector"] = r.first_sector;
    j["range"]["sector_count"] = r.sectors_in_range;
    j["sampler"] = r.sampler;
    j["read_mode"] = r.read_mode;
    j["units"]["sampled"] = r.units_sampled;
    j["units"]["uninformative"] = r.units_uninformative;
    j["units"]["passed_first_read"] = r.units_passed_first;
    j["units"]["repaired_by_rewipe"] = r.units_repaired;
    j["sectors"]["read"] = r.sectors_sampled;
    j["sectors"]["matched"] = r.sectors_matched;
    j["sectors"]["mismatched_first_read"] = r.sectors_mismatched;
    j["sectors"]["unreadable_first_read"] = r.sectors_unreadable;
    j["sectors"]["uninformative"] = r.sectors_uninformative;
    j["sectors"]["not_verified"] = r.sectors_not_verified;
    auto list = [](const std::vector<std::uint64_t>& v) {
        Json a = Json::array();
        for (auto s : v) a.push_back(s);
        return a;
    };
    if (!r.mismatched.empty()) j["mismatched_sectors_first"] = list(r.mismatched);
    if (!r.unreadable.empty()) j["unreadable_sectors_first"] = list(r.unreadable);
    if (!r.not_verified.empty()) j["not_verified_sectors_first"] = list(r.not_verified);
    j["coverage_percent"] = r.coverage_percent;
    j["sci"] = to_json(r.sci_input, r.sci);
    if (r.detectable_fraction > 0) {
        j["confidence"]["level"] = kConfidence;
        j["confidence"]["min_detectable_bad_fraction"] = r.detectable_fraction;
    }
    j["seconds"] = r.seconds;
    return j;
}

}  // namespace dw
