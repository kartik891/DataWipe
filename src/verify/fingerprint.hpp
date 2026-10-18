#pragma once
// Pre-wipe fingerprints: read-back verification for device-internal erases.
//
// After an SSD crypto erase, block erase or SANITIZE the medium holds vendor-defined content
// (zeros, ones, or ciphertext under a discarded key), so there is no pattern to compare with.
// What CAN be checked is that the old data is gone: before the erase, the verifier's sample
// units are drawn and every sector in them is hashed; after the erase, the same sectors are
// read again and each must hash differently.
//
//   * Only a 64-bit truncated SHA-256 per sector is kept, never the data. 5% of a 1 TB disk is
//     ~100 M sectors = ~800 MB of hashes, so the set lives in a file next to the journal
//     (<medium>.dwfp), which also lets verification survive a power cycle mid-erase.
//   * A sector that held one repeated byte (never written, zero-filled) is uninformative: after
//     an erase to zeros it is unchanged either way, so it is excluded from pass/fail and SCI.
//   * The unit list is stored with the hashes, so the post-erase read covers exactly the
//     sectors that were fingerprinted.
//
// File format (little-endian): "DWFP0001", u32 sector size, u64 unit count, u64 sector count,
// u32 sampler-description length + JSON text, then per unit {u64 first, u64 count, f64 risk,
// u8 high_risk}, then per sector {u64 hash, u8 constant}, then SHA-256 of everything before.

#include <cstdint>
#include <string>
#include <vector>

#include "core/json.hpp"
#include "core/result.hpp"
#include "device/block_device.hpp"
#include "verify/readback_verifier.hpp"
#include "verify/sector_sampler.hpp"

namespace dw {

struct FingerprintSet {
    std::uint32_t sector_size = 0;
    std::vector<SampleUnit> units;
    std::vector<std::uint64_t> hashes;   // one per sector, units in order
    std::vector<std::uint8_t> constant;  // 1 = the sector held one repeated byte
    Json sampler;                        // ISectorSampler::describe() at capture time

    std::uint64_t sector_total() const { return hashes.size(); }
};

// 64-bit truncated SHA-256 of one sector.
std::uint64_t sector_fingerprint(std::span<const std::byte> sector);

// `cancel` aborts between units with an error (nothing has been changed at that point).
Result<FingerprintSet> capture_fingerprints(IBlockDevice& device, std::vector<SampleUnit> units, Json sampler_description,
                                            const CancelToken* cancel = nullptr,
                                            const std::function<void(std::uint64_t, std::uint64_t, std::uint64_t)>& on_progress = {});
Result<void> save_fingerprints(const FingerprintSet& set, const std::string& path);
Result<FingerprintSet> load_fingerprints(const std::string& path);

class FingerprintOracle final : public IContentOracle {
public:
    explicit FingerprintOracle(const FingerprintSet& set);
    Verdict check(std::uint64_t lba, std::span<const std::byte> sector) override;
    std::string describe() const override { return "differs from its pre-wipe fingerprint"; }

private:
    const FingerprintSet& set_;
    std::vector<std::uint64_t> offsets_;  // index of each unit's first sector in set_.hashes
};

}  // namespace dw
