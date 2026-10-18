// Phase 3: pattern generation, the real overwrite engine, interruption, resume and the journal.
//
// Every write goes to image files in a private directory created under the current working
// directory (the build tree when run by ctest; not /tmp, whose tmpfs refuses O_DIRECT).

#include <fcntl.h>
#include <unistd.h>

#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <vector>

#include "check.hpp"
#include "core/chacha20.hpp"
#include "core/log.hpp"
#include "core/sha256.hpp"
#include "device/classifier.hpp"
#include "device/device_factory.hpp"
#include "device/identity_provider.hpp"
#include "engine/method_selector.hpp"
#include "engine/overwrite_engine.hpp"
#include "engine/pattern.hpp"
#include "engine/plan_executor.hpp"
#include "engine/run_journal.hpp"

using namespace dw;
namespace fs = std::filesystem;

namespace {

fs::path g_dir;

std::string hex(std::span<const std::byte> b) {
    return to_hex(std::span(reinterpret_cast<const std::uint8_t*>(b.data()), b.size()));
}

PatternKey test_key(std::uint8_t seed) {
    PatternKey k{};
    for (std::size_t i = 0; i < k.size(); ++i) k[i] = static_cast<std::uint8_t>(seed + i * 7);
    return k;
}

std::string make_image(const std::string& name, std::uint64_t size, std::uint8_t fill = 0xAB) {
    fs::path p = g_dir / name;
    fs::remove(p);
    std::ofstream out(p, std::ios::binary);
    std::string chunk(65536, static_cast<char>(fill));
    for (std::uint64_t left = size; left > 0;) {
        auto n = std::min<std::uint64_t>(left, chunk.size());
        out.write(chunk.data(), static_cast<std::streamsize>(n));
        left -= n;
    }
    return p.string();
}

std::vector<std::byte> read_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    std::vector<char> c((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    std::vector<std::byte> out(c.size());
    std::memcpy(out.data(), c.data(), c.size());
    return out;
}

std::unique_ptr<IBlockDevice> open_rw(const std::string& path, bool direct = false) {
    auto t = open_target(path, OpenOptions{.writable = true, .direct_io = direct});
    if (!t) {
        std::fprintf(stderr, "open %s: %s\n", path.c_str(), t.error().describe().c_str());
        return nullptr;
    }
    return std::move(t->device);
}

std::vector<std::byte> expected(const PatternSpec& spec, const PatternKey& key, std::uint64_t off, std::size_t n) {
    std::vector<std::byte> v(n);
    PatternGenerator(spec, key).fill(off, v);
    return v;
}

bool range_is(const std::vector<std::byte>& img, std::uint64_t off, std::uint64_t n, const std::vector<std::byte>& want) {
    return want.size() == n && off + n <= img.size() && std::memcmp(img.data() + off, want.data(), n) == 0;
}

bool range_filled(const std::vector<std::byte>& img, std::uint64_t off, std::uint64_t n, std::uint8_t fill) {
    for (std::uint64_t i = off; i < off + n; ++i)
        if (img[i] != std::byte(fill)) return false;
    return true;
}

// Wraps a real device and injects failures.
class FaultyDevice final : public IBlockDevice {
public:
    explicit FaultyDevice(IBlockDevice& d) : d_(d) {}
    std::uint64_t fail_write_at = UINT64_MAX;  // byte offset
    int fail_flush_number = -1;                // 0-based
    int flushes = 0;
    const std::string& path() const override { return d_.path(); }
    BackendKind kind() const override { return d_.kind(); }
    const DeviceGeometry& geometry() const override { return d_.geometry(); }
    bool writable() const override { return d_.writable(); }
    bool direct_io() const override { return d_.direct_io(); }
    Result<void> read_at(std::uint64_t o, std::span<std::byte> b) override { return d_.read_at(o, b); }
    Result<void> write_at(std::uint64_t o, std::span<const std::byte> b) override {
        if (o <= fail_write_at && fail_write_at < o + b.size()) return sys_error("pwrite (injected)", EIO);
        return d_.write_at(o, b);
    }
    Result<void> flush() override {
        if (flushes++ == fail_flush_number) return sys_error("fdatasync (injected)", EIO);
        return d_.flush();
    }
    int native_handle() const override { return d_.native_handle(); }

private:
    IBlockDevice& d_;
};

// ---- Primitives ----

void test_chacha20() {
    // RFC 8439 Section 2.3.2 block function test vector.
    std::array<std::uint32_t, 16> st{0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, 0x03020100, 0x07060504,
                                     0x0b0a0908, 0x0f0e0d0c, 0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
                                     0x00000001, 0x09000000, 0x4a000000, 0x00000000};
    std::array<std::uint8_t, 64> out{};
    chacha20::block(st, out);
    CHECK(to_hex(out) ==
          "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
          "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e");

    // RFC 8439 Appendix A.1 test vector #1: all-zero key, nonce and counter.
    std::vector<std::byte> ks(64);
    chacha20::keystream(PatternKey{}, 0, 0, ks);
    CHECK(hex(ks) ==
          "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7"
          "da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586");

    // Random access: any window equals the same window cut from one long sequential stream,
    // including windows that start mid-block and straddle the 8-lane batch boundary.
    const PatternKey key = test_key(3);
    std::vector<std::byte> whole(64 * 40);
    chacha20::keystream(key, 9, 0, whole);
    const PatternSpec prng{PatternSpec::Kind::Prng, 9, 0};
    for (std::uint64_t off : {0ull, 1ull, 63ull, 64ull, 500ull, 511ull, 512ull, 1000ull}) {
        for (std::size_t len : {1u, 17u, 64u, 513u, 1200u}) {
            auto w = expected(prng, key, off, len);
            CHECK(std::memcmp(w.data(), whole.data() + off, len) == 0);
        }
    }
    // Streams (passes) and keys (runs) are independent.
    CHECK(expected(prng, key, 0, 64) != expected(PatternSpec{PatternSpec::Kind::Prng, 10, 0}, key, 0, 64));
    CHECK(expected(prng, key, 0, 64) != expected(prng, test_key(4), 0, 64));
    // Fixed32 is little-endian and phase-correct at any offset.
    CHECK(hex(expected(PatternSpec{PatternSpec::Kind::Fixed32, 0, 0x11223344}, key, 1, 6)) == "332211443322");
}

void test_sha256() {
    CHECK(Sha256::hex("") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    CHECK(Sha256::hex("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    CHECK(Sha256::hex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") ==
          "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    Sha256 h;  // one million 'a', fed in uneven pieces to exercise buffering
    std::string piece(997, 'a');
    std::size_t left = 1000000;
    while (left) {
        const std::size_t n = std::min(left, piece.size());
        h.update(std::string_view(piece.data(), n));
        left -= n;
    }
    CHECK(to_hex(h.finish()) == "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
}

void test_key_helpers() {
    auto k = random_pattern_key();
    CHECK_OK(k);
    if (!k) return;
    auto k2 = random_pattern_key();
    CHECK(k2 && *k2 != *k);
    auto back = pattern_key_from_hex(to_hex(*k));
    CHECK(back && *back == *k);
    CHECK_ERR_CONTAINS(pattern_key_from_hex("abc"), "64 hex");
    CHECK_ERR_CONTAINS(pattern_key_from_hex(std::string(64, 'G')), "non-hex");
    CHECK(key_fingerprint(*k).size() == 16 && to_hex(*k).find(key_fingerprint(*k)) == std::string::npos);
}

// ---- Engine ----

void test_engine_writes_exact_range() {
    constexpr std::uint64_t kSize = 2 << 20;
    const auto img = make_image("range.img", kSize);
    const PatternKey key = test_key(1);
    const OverwriteSpec spec{7, 3000, PatternSpec{PatternSpec::Kind::Prng, 1, 0}};  // odd start, odd length
    {
        auto dev = open_rw(img);
        CHECK(dev != nullptr);
        if (!dev) return;
        OverwriteConfig cfg;
        cfg.buffer_bytes = 12345;  // not a sector multiple: rounded down to 12288
        cfg.sync_interval_bytes = 100000;
        std::vector<std::uint64_t> durable;
        std::vector<OverwriteProgress> progress;
        cfg.progress_interval_seconds = 0;
        OverwriteContext ctx;
        ctx.on_durable = [&](std::uint64_t s) { durable.push_back(s); };
        ctx.on_progress = [&](const OverwriteProgress& p) { progress.push_back(p); };
        auto r = OverwriteEngine(key, cfg).run(spec, *dev, ctx);
        CHECK_OK(r);
        if (!r) return;
        CHECK(!r->aborted && r->sectors_durable == 3000 && r->bytes_written_this_run == 3000 * 512);
        CHECK(r->flushes == 14 && durable.size() == r->flushes);  // 13 x 9 chunks (>= 100000 B), then the tail
        CHECK(!durable.empty() && durable.back() == 3000);
        for (std::size_t i = 1; i < durable.size(); ++i) CHECK(durable[i] > durable[i - 1]);
        CHECK(!progress.empty() && progress.back().final && progress.back().bytes_durable == 3000 * 512);
    }
    auto data = read_file(img);
    CHECK(range_filled(data, 0, 7 * 512, 0xAB));
    CHECK(range_is(data, 7 * 512, 3000 * 512, expected(spec.pattern, key, 7 * 512, 3000 * 512)));
    CHECK(range_filled(data, 3007 * 512, kSize - 3007 * 512, 0xAB));
}

void test_engine_chunking_invariance() {
    constexpr std::uint64_t kSize = 1 << 20;
    const PatternKey key = test_key(2);
    const OverwriteSpec spec{0, kSize / 512, PatternSpec{PatternSpec::Kind::Prng, 2, 0}};
    std::vector<std::vector<std::byte>> results;
    for (std::size_t buf : {512u, 4096u, 1u << 20, 64u << 20}) {
        const auto img = make_image("chunk.img", kSize);
        {
            auto dev = open_rw(img);
            OverwriteConfig cfg;
            cfg.buffer_bytes = buf;
            CHECK(dev && OverwriteEngine(key, cfg).run(spec, *dev, {}).ok());
        }
        results.push_back(read_file(img));
    }
    for (const auto& r : results) CHECK(r == results.front());

    const auto img = make_image("fixed.img", kSize);
    {
        auto dev = open_rw(img);
        const OverwriteSpec zeros{0, kSize / 512, PatternSpec{PatternSpec::Kind::Fixed32, 0, 0}};
        CHECK(dev && OverwriteEngine(key, {}).run(zeros, *dev, {}).ok());
    }
    CHECK(range_filled(read_file(img), 0, kSize, 0x00));
}

void test_engine_rejects_bad_input() {
    const auto img = make_image("bad.img", 64 * 512);
    auto dev = open_rw(img);
    if (!dev) return;
    OverwriteEngine eng(test_key(1), {});
    const PatternSpec p{};
    CHECK_ERR_CONTAINS(eng.run({60, 5, p}, *dev, {}), "exceeds");
    CHECK_ERR_CONTAINS(eng.run({0, 0, p}, *dev, {}), "no sectors");
    OverwriteContext past;
    past.resume_sector = 11;
    CHECK_ERR_CONTAINS(eng.run({0, 10, p}, *dev, past), "past the end");
    OverwriteConfig tiny;
    tiny.buffer_bytes = 100;
    CHECK_ERR_CONTAINS(OverwriteEngine(test_key(1), tiny).run({0, 10, p}, *dev, {}), "alignment");
    auto ro = open_target(img, OpenOptions{});
    CHECK(ro && !OverwriteEngine(test_key(1), {}).run({0, 10, p}, *ro->device, {}).ok());
}

void test_engine_abort_and_resume() {
    constexpr std::uint64_t kSize = 4 << 20;
    const PatternKey key = test_key(5);
    const OverwriteSpec spec{16, kSize / 512 - 16, PatternSpec{PatternSpec::Kind::Prng, 1, 0}};
    OverwriteConfig cfg;
    cfg.buffer_bytes = 64 << 10;
    cfg.sync_interval_bytes = 256 << 10;

    // Reference: uninterrupted.
    const auto ref_img = make_image("ref.img", kSize);
    {
        auto dev = open_rw(ref_img);
        CHECK(dev && OverwriteEngine(key, cfg).run(spec, *dev, {}).ok());
    }
    const auto reference = read_file(ref_img);

    // Interrupted after the third checkpoint, as a signal handler would.
    const auto img = make_image("abort.img", kSize);
    std::uint64_t durable = 0;
    {
        auto dev = open_rw(img);
        if (!dev) return;
        CancelToken cancel;
        OverwriteContext ctx;
        ctx.cancel = &cancel;
        int n = 0;
        ctx.on_durable = [&](std::uint64_t s) {
            durable = s;
            if (++n == 3) cancel.request();
        };
        auto r = OverwriteEngine(key, cfg).run(spec, *dev, ctx);
        CHECK_OK(r);
        if (!r) return;
        CHECK(r->aborted);
        CHECK(r->sectors_durable == durable && durable == 3 * 512);  // 3 x 256 KiB in sectors
    }
    auto partial = read_file(img);
    const std::uint64_t cut = (16 + durable) * 512;
    CHECK(range_is(partial, 16 * 512, durable * 512, expected(spec.pattern, key, 16 * 512, durable * 512)));
    CHECK(range_filled(partial, cut, kSize - cut, 0xAB));  // stopped at the chunk boundary, nothing beyond

    // Resume from an OLDER checkpoint than the real one (a lagging journal): the overlap is
    // rewritten with identical bytes and the result equals the uninterrupted reference.
    {
        auto dev = open_rw(img);
        if (!dev) return;
        OverwriteContext ctx;
        ctx.resume_sector = durable - 512;
        OverwriteConfig other = cfg;
        other.buffer_bytes = 1 << 20;  // a different chunk size on resume must not matter
        auto r = OverwriteEngine(key, other).run(spec, *dev, ctx);
        CHECK(r && !r->aborted && r->bytes_written_this_run == (spec.sector_count - durable + 512) * 512);
    }
    CHECK(read_file(img) == reference);
}

void test_engine_io_errors() {
    constexpr std::uint64_t kSize = 1 << 20;
    const OverwriteSpec spec{0, kSize / 512, PatternSpec{}};
    OverwriteConfig cfg;
    cfg.buffer_bytes = 32 << 10;
    cfg.sync_interval_bytes = 128 << 10;
    {  // Write error: stops with the sector number; checkpoints never pass the failed chunk.
        const auto img = make_image("eio.img", kSize);
        auto dev = open_rw(img);
        if (!dev) return;
        FaultyDevice f(*dev);
        f.fail_write_at = 300 * 1024 + 5;
        std::uint64_t durable = 0;
        OverwriteContext ctx;
        ctx.on_durable = [&](std::uint64_t s) { durable = s; };
        auto r = OverwriteEngine(test_key(1), cfg).run(spec, f, ctx);
        CHECK_ERR_CONTAINS(r, "write failed at sector 576");  // chunk 9 starts at byte 294912
        CHECK_ERR_CONTAINS(r, "Input/output error");
        CHECK(durable == 576);  // the work before the bad chunk was saved for a resume
    }
    {  // Flush error: fatal, and the durable mark does not move past the last good flush.
        const auto img = make_image("fsync.img", kSize);
        auto dev = open_rw(img);
        if (!dev) return;
        FaultyDevice f(*dev);
        f.fail_flush_number = 2;
        std::uint64_t durable = 0;
        OverwriteContext ctx;
        ctx.on_durable = [&](std::uint64_t s) { durable = s; };
        auto r = OverwriteEngine(test_key(1), cfg).run(spec, f, ctx);
        CHECK_ERR_CONTAINS(r, "not retried");
        CHECK(durable == 2 * 256);  // two good 128 KiB checkpoints
    }
}

void test_engine_direct_io() {
    constexpr std::uint64_t kSize = 1 << 20;
    const auto img = make_image("direct.img", kSize);
    auto t = open_target(img, OpenOptions{.writable = true, .direct_io = true});
    if (!t && t.error().sys_errno == EINVAL) {
        std::fprintf(stderr, "test_overwrite: O_DIRECT unsupported on this filesystem, skipping\n");
        return;
    }
    CHECK_OK(t);
    if (!t) return;
    CHECK(OverwriteEngine::io_alignment(*t->device) == 4096);
    OverwriteConfig cfg;
    cfg.buffer_bytes = 3 * 4096 + 100;  // rounds to 12288, a 4 KiB multiple for O_DIRECT
    const OverwriteSpec spec{8, kSize / 512 - 8, PatternSpec{PatternSpec::Kind::Prng, 1, 0}};
    auto r = OverwriteEngine(test_key(8), cfg).run(spec, *t->device, {});
    CHECK_OK(r);
    t->device.reset();
    CHECK(range_is(read_file(img), 8 * 512, kSize - 8 * 512, expected(spec.pattern, test_key(8), 8 * 512, kSize - 8 * 512)));
}

// ---- Plans end to end ----

std::string profiles_dir() {
    const char* d = std::getenv("DW_PROFILES_DIR");
    return d ? d : "profiles";
}

struct Target {
    std::unique_ptr<IBlockDevice> dev;
    DeviceProfile profile;
};

std::optional<Target> probe_rw(const std::string& img, const std::string& profile_name) {
    auto sim = SimulatedIdentityProvider::load(profiles_dir() + "/" + profile_name);
    auto t = open_target(img, OpenOptions{.writable = true, .direct_io = false});
    if (!sim || !t) return std::nullopt;
    auto id = sim->identify(*t->device);
    if (!id) return std::nullopt;
    auto p = classify(*t, *id, sim->source(), sim->origin());
    if (!p) return std::nullopt;
    return Target{std::move(t->device), std::move(p).value()};
}

class Recorder final : public IProgressStore {
public:
    std::vector<ResumePoint> saved;
    void save(const ResumePoint& p) override { saved.push_back(p); }
};

class CancelInStep final : public PlanObserver {
public:
    CancelInStep(CancelToken& c, std::size_t step, double at) : c_(c), step_(step), at_(at) {}
    void overwrite_progress(std::size_t i, const OverwriteProgress& p) override {
        if (i == step_ && double(p.bytes_durable) >= at_ * double(p.bytes_total)) c_.request();
    }

private:
    CancelToken& c_;
    std::size_t step_;
    double at_;
};

void test_plan_real_overwrite() {
    constexpr std::uint64_t kSize = 2 << 20;
    const auto img = make_image("hdd.img", kSize);
    auto t = probe_rw(img, "hdd_basic.json");
    CHECK(t.has_value());
    if (!t) return;
    auto plan = select_method(t->profile);
    CHECK_OK(plan);
    if (!plan) return;
    CHECK(plan->method_id == "hdd.overwrite+ata-se-enhanced");
    const PatternKey key = test_key(9);
    OverwriteEngine eng(key, {});
    auto ex = make_command_executor(t->profile, *t->dev);
    Recorder rec;
    auto r = execute_plan(*plan, *ex, t->dev.get(), ExecutionOptions{&eng, nullptr, nullptr, &rec, {}});
    CHECK_OK(r);
    if (!r) return;
    CHECK(r->success && r->achieved == SanitizationLevel::Purge && !r->aborted);
    CHECK(r->steps[0].bytes_written == kSize && r->steps[1].bytes_written == kSize);
    CHECK(!rec.saved.empty() && rec.saved.back() == (ResumePoint{2, false, 0}));
    // A resume point past the last step (only verification was pending): nothing runs again.
    {
        const auto before = read_file(img);
        Recorder rec2;
        auto again = execute_plan(*plan, *ex, t->dev.get(),
                                  ExecutionOptions{&eng, nullptr, nullptr, &rec2, ResumePoint{plan->steps.size(), false, 0}});
        CHECK_OK(again);
        if (again) {
            CHECK(again->success && again->achieved == SanitizationLevel::Purge);
            CHECK(again->steps[0].bytes_written == 0 && again->steps[1].bytes_written == 0);
        }
        CHECK(rec2.saved.empty() && read_file(img) == before);
    }
    t->dev.reset();
    // The medium holds the LAST pass (stream 2), which is what the verifier will expect.
    CHECK(plan->verification.expected && plan->verification.expected->pattern.stream == 2);
    CHECK(read_file(img) == expected(plan->verification.expected->pattern, key, 0, kSize));
}

void test_plan_interrupt_and_resume() {
    constexpr std::uint64_t kSize = 8 << 20;  // hdd_with_hpa hides the last 5 MiB
    const PatternKey key = test_key(11);
    OverwriteConfig cfg;
    cfg.buffer_bytes = 128 << 10;
    cfg.sync_interval_bytes = 512 << 10;
    cfg.progress_interval_seconds = 0;

    // Uninterrupted reference.
    const auto ref_img = make_image("plan_ref.img", kSize);
    {
        auto t = probe_rw(ref_img, "hdd_with_hpa.json");
        if (!t) { CHECK(false); return; }
        auto plan = select_method(t->profile);
        OverwriteEngine eng(key, cfg);
        auto ex = make_command_executor(t->profile, *t->dev);
        CHECK(plan && execute_plan(*plan, *ex, t->dev.get(), &eng).ok());
    }
    const auto reference = read_file(ref_img);

    const auto img = make_image("plan.img", kSize);
    ResumePoint at;
    std::string digest;
    {  // Run 1: interrupted halfway through the emulated Secure Erase pass (step 3).
        auto t = probe_rw(img, "hdd_with_hpa.json");
        if (!t) { CHECK(false); return; }
        auto plan = select_method(t->profile);
        if (!plan) { CHECK(false); return; }
        CHECK(plan->steps.size() == 3 && plan->steps[0].commands.size() > 0 && plan->steps[2].commands.size() > 0);
        digest = plan_digest(*plan);
        CancelToken cancel;
        CancelInStep obs(cancel, 2, 0.5);
        Recorder rec;
        OverwriteEngine eng(key, cfg);
        SimulatedCommandExecutor ex(t->profile);
        auto r = execute_plan(*plan, ex, t->dev.get(), ExecutionOptions{&eng, &obs, &cancel, &rec, {}});
        CHECK_OK(r);
        if (!r) return;
        CHECK(!r->success && r->aborted);
        CHECK(r->achieved == SanitizationLevel::Clear);  // pass 1 finished; Purge pending
        CHECK(r->steps[2].status == StepRecord::Status::Aborted);
        CHECK(r->resume_at.step == 2 && r->resume_at.commands_done);
        CHECK(r->resume_at.sectors_done >= kSize / 512 / 2 && r->resume_at.sectors_done < kSize / 512);
        CHECK(!rec.saved.empty() && rec.saved.back() == r->resume_at);
        // Journal checkpoints are monotonic.
        for (std::size_t i = 1; i < rec.saved.size(); ++i) {
            const auto &a = rec.saved[i - 1], &b = rec.saved[i];
            CHECK(a.step < b.step || (a.step == b.step && a.sectors_done <= b.sectors_done));
        }
        at = r->resume_at;
    }
    CHECK(read_file(img) != reference);
    {  // Run 2: a fresh process would re-probe, re-plan (same digest) and resume.
        auto t = probe_rw(img, "hdd_with_hpa.json");
        if (!t) { CHECK(false); return; }
        auto plan = select_method(t->profile);
        if (!plan) { CHECK(false); return; }
        CHECK(plan_digest(*plan) == digest);
        OverwriteEngine eng(key, cfg);
        SimulatedCommandExecutor ex(t->profile);
        auto r = execute_plan(*plan, ex, t->dev.get(), ExecutionOptions{&eng, nullptr, nullptr, nullptr, at});
        CHECK_OK(r);
        if (!r) return;
        CHECK(r->success && r->achieved == SanitizationLevel::Purge);
        CHECK(r->steps[0].status == StepRecord::Status::Completed && r->steps[0].log.front().find("earlier") != std::string::npos);
        CHECK(r->steps[2].bytes_written == (kSize / 512 - at.sectors_done) * 512);
        // Restored drive state: HPA/DCO removed and the Secure Erase counted once.
        CHECK(ex.state().id.user_addressable_sectors == kSize / 512);
        CHECK(ex.state().effects.size() == 1 && ex.state().effects.front() == "ata-se-enhanced");
    }
    CHECK(read_file(img) == reference);

    {  // Resume points that don't fit the plan are rejected before anything runs.
        auto t = probe_rw(img, "hdd_with_hpa.json");
        if (!t) { CHECK(false); return; }
        auto plan = select_method(t->profile);
        OverwriteEngine eng(key, cfg);
        SimulatedCommandExecutor ex(t->profile);
        CHECK_ERR_CONTAINS(execute_plan(*plan, ex, t->dev.get(), ExecutionOptions{&eng, nullptr, nullptr, nullptr, {7, false, 0}}),
                           "has 3");
        CHECK_ERR_CONTAINS(execute_plan(*plan, ex, t->dev.get(), ExecutionOptions{&eng, nullptr, nullptr, nullptr, {0, true, 5}}),
                           "does not fit");
    }
}

// ---- Journal ----

void test_journal() {
    constexpr std::uint64_t kSize = 8 << 20;
    const auto img = make_image("journal.img", kSize);
    auto t = probe_rw(img, "hdd_with_hpa.json");
    if (!t) { CHECK(false); return; }
    auto plan = select_method(t->profile);
    if (!plan) { CHECK(false); return; }

    auto path = RunJournal::default_path(t->profile);
    CHECK(path && *path == img + ".dwjournal");
    RunJournal j(*path);
    auto none = j.load();
    CHECK(none && !none->has_value());

    auto rec = JournalRecord::start(t->profile, *plan, test_key(4));
    CHECK(rec.medium == img && rec.serial == "SIMHDD-HPA-0002" && rec.plan_sha256.size() == 64);
    CHECK_OK(j.begin(rec));
    j.save({2, true, 1234});
    CHECK(!fs::exists(*path + ".tmp"));
#ifndef _WIN32  // Windows files have ACLs inherited from the directory, not mode bits
    CHECK((fs::status(*path).permissions() & fs::perms::all) == (fs::perms::owner_read | fs::perms::owner_write));
#endif

    auto loaded = j.load();
    CHECK(loaded && loaded->has_value());
    if (!loaded || !loaded->has_value()) return;
    const JournalRecord& l = **loaded;
    CHECK(l.key == test_key(4) && (l.position == ResumePoint{2, true, 1234}) && l.runs == 1);
    CHECK(to_json(l).dump() == to_json(j.record()).dump());
    CHECK_OK(check_journal_matches(l, t->profile, *plan));

    {  // Binding: every identity mismatch is refused.
        DeviceProfile p = t->profile;
        p.identity.serial = "OTHER";
        CHECK_ERR_CONTAINS(check_journal_matches(l, p, *plan), "serial");
        p = t->profile;
        p.geometry.size_bytes += 512;
        CHECK_ERR_CONTAINS(check_journal_matches(l, p, *plan), "size_bytes");
        p = t->profile;
        p.path = p.backing_file = "/elsewhere.img";
        CHECK_ERR_CONTAINS(check_journal_matches(l, p, *plan), "medium");
        auto kept = select_method(t->profile, SelectorOptions{.remove_hidden_areas = false});
        CHECK(kept && !check_journal_matches(l, t->profile, *kept).ok());
    }
    {  // Corruption is an error, never "no journal".
        std::ofstream(*path) << "{\"schema\":\"datawipe.journal.v1\",\"medium\":";
        CHECK_ERR_CONTAINS(j.load(), "corrupt");
        std::ofstream(*path) << "{\"schema\":\"datawipe.journal.v9\"}";
        CHECK_ERR_CONTAINS(j.load(), "unsupported schema");
    }
    CHECK_OK(j.remove());
    CHECK(!fs::exists(*path));
    CHECK_OK(j.remove());  // idempotent
}

}  // namespace

int main() {
    log::set_level(log::Level::Error);
    std::string tmpl = (fs::current_path() / "dw_overwrite_XXXXXX").string();
    if (!::mkdtemp(tmpl.data())) {
        std::perror("mkdtemp");
        return 1;
    }
    g_dir = tmpl;

    test_chacha20();
    test_sha256();
    test_key_helpers();
    test_engine_writes_exact_range();
    test_engine_chunking_invariance();
    test_engine_rejects_bad_input();
    test_engine_abort_and_resume();
    test_engine_io_errors();
    test_engine_direct_io();
    test_plan_real_overwrite();
    test_plan_interrupt_and_resume();
    test_journal();

    fs::remove_all(g_dir);
    return finish("test_overwrite");
}
