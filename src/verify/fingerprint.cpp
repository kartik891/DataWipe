#include "verify/fingerprint.hpp"

#include <fcntl.h>
#include <openssl/sha.h>
#include <unistd.h>

#include <algorithm>
#include <bit>
#include <cstring>
#include <format>
#include <fstream>

#include "core/portable.hpp"
#include "core/sha256.hpp"
#include "verify/sector_io.hpp"

namespace dw {

namespace {

constexpr char kMagic[8] = {'D', 'W', 'F', 'P', '0', '0', '0', '1'};

static_assert(std::endian::native == std::endian::little, "fingerprint files are written little-endian");

template <typename T>
void put(std::string& out, T v) {
    out.append(reinterpret_cast<const char*>(&v), sizeof v);
}

class Reader {
public:
    explicit Reader(std::string_view d) : d_(d) {}
    template <typename T>
    bool get(T& v) {
        if (pos_ + sizeof v > d_.size()) return false;
        std::memcpy(&v, d_.data() + pos_, sizeof v);
        pos_ += sizeof v;
        return true;
    }
    bool get(std::string& s, std::size_t n) {
        if (pos_ + n > d_.size()) return false;
        s.assign(d_.substr(pos_, n));
        pos_ += n;
        return true;
    }
    std::size_t pos() const { return pos_; }

private:
    std::string_view d_;
    std::size_t pos_ = 0;
};

bool is_constant(std::span<const std::byte> s) {
    for (std::byte b : s)
        if (b != s[0]) return false;
    return true;
}

}  // namespace

std::uint64_t sector_fingerprint(std::span<const std::byte> sector) {
    // OpenSSL's SHA-256 (assembly, SHA-NI where the CPU has it): this runs once per sampled
    // sector, tens of millions of times on a large drive.
    unsigned char d[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(sector.data()), sector.size(), d);
    std::uint64_t v = 0;
    std::memcpy(&v, d, sizeof v);
    return v;
}

Result<FingerprintSet> capture_fingerprints(IBlockDevice& device, std::vector<SampleUnit> units, Json sampler,
                                            const CancelToken* cancel,
                                            const std::function<void(std::uint64_t, std::uint64_t, std::uint64_t)>& on_progress) {
    FingerprintSet set;
    set.sector_size = device.geometry().logical_sector_size;
    set.sampler = std::move(sampler);
    std::sort(units.begin(), units.end(), [](const auto& a, const auto& b) { return a.first_sector < b.first_sector; });
    SectorIo io(device);
    if (!io.ok()) return error("cannot allocate the read buffer");
    std::uint64_t done = 0;
    for (const auto& u : units) {
        if (cancel && cancel->requested()) return error("interrupted while taking pre-wipe fingerprints");
        if (on_progress) on_progress(done++, units.size(), set.hashes.size());
        for (std::uint64_t pos = u.first_sector; pos < u.first_sector + u.sector_count;) {
            const std::uint64_t k = std::min(io.max_sectors(), u.first_sector + u.sector_count - pos);
            auto chunk = io.read(pos, k);
            if (!chunk)
                return error(std::format("pre-wipe fingerprint: cannot read sectors [{}, +{}): {}", pos, k,
                                         chunk.error().describe()));
            for (std::uint64_t i = 0; i < k; ++i) {
                auto s = chunk->subspan(i * set.sector_size, set.sector_size);
                set.hashes.push_back(sector_fingerprint(s));
                set.constant.push_back(is_constant(s) ? 1 : 0);
            }
            pos += k;
        }
    }
    set.units = std::move(units);
    return set;
}

Result<void> save_fingerprints(const FingerprintSet& set, const std::string& path) {
    std::string out(kMagic, sizeof kMagic);
    put<std::uint32_t>(out, set.sector_size);
    put<std::uint64_t>(out, set.units.size());
    put<std::uint64_t>(out, set.hashes.size());
    const std::string desc = set.sampler.dump();
    put<std::uint32_t>(out, static_cast<std::uint32_t>(desc.size()));
    out += desc;
    for (const auto& u : set.units) {
        put<std::uint64_t>(out, u.first_sector);
        put<std::uint64_t>(out, u.sector_count);
        put<double>(out, u.risk);
        put<std::uint8_t>(out, u.high_risk ? 1 : 0);
    }
    for (std::size_t i = 0; i < set.hashes.size(); ++i) {
        put<std::uint64_t>(out, set.hashes[i]);
        put<std::uint8_t>(out, set.constant[i]);
    }
    Sha256 h;
    h.update(out);
    const auto d = h.finish();
    out.append(reinterpret_cast<const char*>(d.data()), d.size());

    const std::string tmp = path + ".tmp";
    int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return sys_error("create " + tmp);
    for (std::size_t done = 0; done < out.size();) {
        ssize_t n = ::write(fd, out.data() + done, out.size() - done);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) {
            const int err = errno;
            ::close(fd);
            return sys_error("write " + tmp, err);
        }
        done += static_cast<std::size_t>(n);
    }
    const bool synced = ::fdatasync(fd) == 0;
    ::close(fd);
    if (!synced) return sys_error("fdatasync " + tmp);
    if (dw::replace_file(tmp.c_str(), path.c_str()) != 0) return sys_error("rename " + tmp + " -> " + path);
    return ok();
}

Result<FingerprintSet> load_fingerprints(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return sys_error("open " + path);
    std::string data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    if (data.size() < sizeof kMagic + 32 || std::memcmp(data.data(), kMagic, sizeof kMagic) != 0)
        return error(path + ": not a datawipe fingerprint file");
    Sha256 h;
    h.update(std::string_view(data).substr(0, data.size() - 32));
    const auto d = h.finish();
    if (std::memcmp(d.data(), data.data() + data.size() - 32, 32) != 0)
        return error(path + ": checksum mismatch (truncated or modified)");

    Reader r(std::string_view(data).substr(sizeof kMagic, data.size() - sizeof kMagic - 32));
    FingerprintSet set;
    std::uint64_t units = 0, sectors = 0;
    std::uint32_t desc_len = 0;
    std::string desc;
    if (!r.get(set.sector_size) || !r.get(units) || !r.get(sectors) || !r.get(desc_len) || !r.get(desc, desc_len))
        return error(path + ": truncated header");
    auto j = Json::parse(desc);
    if (!j) return error(path + ": " + j.error().message);
    set.sampler = *j;
    std::uint64_t expect_sectors = 0;
    for (std::uint64_t i = 0; i < units; ++i) {
        SampleUnit u;
        std::uint8_t hr = 0;
        if (!r.get(u.first_sector) || !r.get(u.sector_count) || !r.get(u.risk) || !r.get(hr))
            return error(path + ": truncated unit list");
        u.high_risk = hr != 0;
        expect_sectors += u.sector_count;
        set.units.push_back(u);
    }
    if (expect_sectors != sectors) return error(path + ": unit list and sector count disagree");
    set.hashes.resize(sectors);
    set.constant.resize(sectors);
    for (std::uint64_t i = 0; i < sectors; ++i)
        if (!r.get(set.hashes[i]) || !r.get(set.constant[i])) return error(path + ": truncated fingerprints");
    return set;
}

FingerprintOracle::FingerprintOracle(const FingerprintSet& set) : set_(set) {
    std::uint64_t off = 0;
    for (const auto& u : set.units) {
        offsets_.push_back(off);
        off += u.sector_count;
    }
}

IContentOracle::Verdict FingerprintOracle::check(std::uint64_t lba, std::span<const std::byte> sector) {
    // The unit containing lba: the last one starting at or before it.
    auto it = std::upper_bound(set_.units.begin(), set_.units.end(), lba,
                               [](std::uint64_t x, const SampleUnit& u) { return x < u.first_sector; });
    if (it == set_.units.begin()) return Verdict::Uninformative;
    --it;
    if (lba >= it->first_sector + it->sector_count) return Verdict::Uninformative;  // never fingerprinted
    const std::uint64_t i = offsets_[static_cast<std::size_t>(it - set_.units.begin())] + (lba - it->first_sector);
    if (set_.constant[i]) return Verdict::Uninformative;
    return sector_fingerprint(sector) == set_.hashes[i] ? Verdict::Bad : Verdict::Ok;
}

}  // namespace dw
