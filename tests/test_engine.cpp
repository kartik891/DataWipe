// Method selection matrix, command encoding, simulated drive state machine, plan execution.
// Pure logic: no files or devices are touched (fake device/runner stand in for Phase 3).

#include <format>

#ifdef __linux__
#include <linux/fs.h>
#endif

#include <cstring>

#include "check.hpp"
#include "core/log.hpp"
#include "engine/command_executor.hpp"
#include "engine/command_support.hpp"
#include "engine/method_selector.hpp"
#include "engine/plan_executor.hpp"

using namespace dw;

namespace {

constexpr std::uint64_t kSectors = 32768;  // 16 MiB

std::string hex(const std::array<std::uint8_t, 16>& cdb) {
    std::string s;
    for (auto b : cdb) s += std::format("{:02x}", b);
    return s;
}

// Minimal DeviceProfile builder: the selector never looks at the device itself.
struct P {
    DeviceProfile p;
    P(Transport t, MediaType m) {
        p.geometry.size_bytes = kSectors * 512;
        p.identity.transport = t;
        p.identity.rotation_rate = m == MediaType::HDD ? 7200 : 1;
        p.identity.user_addressable_sectors = p.identity.native_max_sectors = kSectors;
        p.media = m;
    }
    P& security(bool enhanced) { p.identity.security_supported = true; p.identity.enhanced_erase_supported = enhanced; return *this; }
    P& frozen() { p.identity.security_frozen = true; return *this; }
    P& locked() { p.identity.security_locked = true; return *this; }
    P& sanitize(bool crypto, bool block, bool overwrite) {
        p.identity.sanitize_supported = true;
        p.identity.crypto_scramble_supported = crypto;
        p.identity.block_erase_supported = block;
        p.identity.overwrite_supported = overwrite;
        return *this;
    }
    P& sed() { p.identity.self_encrypting = true; p.encrypted = true; return *this; }
    P& hidden(std::uint64_t dco, std::uint64_t hpa) {
        auto& id = p.identity;
        id.dco_supported = dco > 0;
        id.hpa_supported = id.hpa_enabled = hpa > 0;
        id.dco_max_sectors = dco ? kSectors : 0;
        id.native_max_sectors = kSectors - dco;
        id.user_addressable_sectors = id.native_max_sectors - hpa;
        return *this;
    }
    operator const DeviceProfile&() const { return p; }
};

bool has_warning(const WipePlan& plan, const std::string& needle) {
    for (const auto& w : plan.warnings)
        if (w.find(needle) != std::string::npos) return true;
    return false;
}

// ---- Fakes for plan execution ----

class FakeDevice final : public IBlockDevice {
public:
    std::string p = "/fake";
    DeviceGeometry g{kSectors * 512, 512, 512};
    const std::string& path() const override { return p; }
    BackendKind kind() const override { return BackendKind::ImageFile; }
    const DeviceGeometry& geometry() const override { return g; }
    bool writable() const override { return true; }
    bool direct_io() const override { return false; }
    Result<void> read_at(std::uint64_t, std::span<std::byte>) override { return ok(); }
    Result<void> write_at(std::uint64_t, std::span<const std::byte>) override { return ok(); }
    Result<void> flush() override { return ok(); }
    int native_handle() const override { return -1; }
};

class RecordingRunner final : public IOverwriteRunner {
public:
    std::vector<OverwriteSpec> calls;
    int fail_on_call = -1;
    Result<OverwriteOutcome> run(const OverwriteSpec& spec, IBlockDevice&, const OverwriteContext&) override {
        calls.push_back(spec);
        if (static_cast<int>(calls.size()) - 1 == fail_on_call) return error("injected I/O error");
        return OverwriteOutcome{false, spec.sector_count, spec.sector_count * 512, 1, 0};
    }
};

// ---- Tests ----

void test_cdb_encoding() {
    // Values checked against SAT-4 field layout (and hdparm's sgio.c register interleave).
    CHECK(hex(ata_pass_through_16(*ata::security_erase_unit("x", true).ata)) == "850a2600000001000000000000"
                                                                                 "40f400");
    CHECK(hex(ata_pass_through_16(*ata::sanitize_crypto_scramble().ata)) == "85072000110000437000790072"
                                                                            "40b400");
    CHECK(hex(ata_pass_through_16(*ata::set_max_address_ext(0x123456789Aull, true).ata)) ==
          "8507200000000134" "9a12780056" "403700");
    CHECK(hex(ata_pass_through_16(*ata::read_native_max_address_ext().ata)) == "85072000000000000000000000"
                                                                               "402700");

    auto se = ata::security_erase_unit("pw", true);
    CHECK(se.ata->payload.size() == 512 && se.ata->payload[0] == 0x02 && se.ata->payload[2] == 'p');
    CHECK(ata::sanitize_overwrite(0xAABBCCDD).ata->lba == 0x4F57AABBCCDDull);

    auto ns = nvme::sanitize(nvme::SanitizeAction::CryptoErase);
    CHECK(ns.nvme->opcode == 0x84 && ns.nvme->cdw10 == 4);
    CHECK(nvme::format_nvm(2, 1, 0).nvme->cdw10 == (2u << 9));
    // Targets the confirmed namespace and keeps its LBA format: never broadcast, never LBAF 0 by default.
    const auto f = nvme::format_nvm(1, 3, 0x13);
    CHECK(f.nvme->nsid == 3 && f.nvme->nsid != 0xFFFFFFFF);
    CHECK(f.nvme->cdw10 == (0x3u | 1u << 9 | 1u << 12));  // LBAFL 3, SES 1, LBAFU 1
    CHECK(nvme::sanitize_status_log().nvme->cdw10 == (0x81u | (127u << 16)));
    CHECK(emmc::sanitize().emmc_arg == 0x03A50100);
    CHECK(se.describe().find("ioctl(SG_IO) ATA PASS-THROUGH(16) CDB [85 0a 26") != std::string::npos);
}

void test_matrix() {
    struct Case {
        const char* name;
        DeviceProfile profile;
        const char* method_id;
        SanitizationLevel level;
        bool fully_simulated;
    };
    using M = MediaType;
    using T = Transport;
    using L = SanitizationLevel;
    const Case cases[] = {
        {"hdd enhanced", P(T::SATA, M::HDD).security(true), "hdd.overwrite+ata-se-enhanced", L::Purge, false},
        {"hdd normal SE", P(T::SATA, M::HDD).security(false), "hdd.overwrite+ata-se-normal", L::Purge, false},
        {"hdd sanitize ow", P(T::SATA, M::HDD).sanitize(false, false, true), "hdd.overwrite+ata-sanitize-overwrite", L::Purge, false},
        {"hdd frozen, ow", P(T::SATA, M::HDD).security(true).frozen().sanitize(false, false, true),
         "hdd.overwrite+ata-sanitize-overwrite", L::Purge, false},
        {"hdd frozen", P(T::SATA, M::HDD).security(true).frozen(), "hdd.overwrite", L::Clear, false},
        {"hdd bare", P(T::SATA, M::HDD), "hdd.overwrite", L::Clear, false},
        {"hdd hpa+dco", P(T::SATA, M::HDD).security(true).hidden(2048, 8192), "hdd.unhide+overwrite+ata-se-enhanced", L::Purge, false},
        {"sata sed full", P(T::SATA, M::SSD_SATA).sed().sanitize(true, true, false).security(true),
         "ssd-sata.crypto-scramble+block-erase", L::Purge, true},
        {"sata sed opal+se", P(T::SATA, M::SSD_SATA).sed().security(true), "ssd-sata.opal-genkey+ata-se-enhanced", L::Purge, true},
        {"sata sed opal", P(T::SATA, M::SSD_SATA).sed(), "ssd-sata.opal-genkey", L::Purge, true},
        {"sata plain block", P(T::SATA, M::SSD_SATA).sanitize(false, true, true), "ssd-sata.block-erase", L::Purge, true},
        {"sata plain ow", P(T::SATA, M::SSD_SATA).sanitize(false, false, true), "ssd-sata.sanitize-overwrite", L::Purge, true},
        {"sata plain se", P(T::SATA, M::SSD_SATA).security(false), "ssd-sata.ata-se-normal", L::Purge, true},
        {"sata plain frozen", P(T::SATA, M::SSD_SATA).security(true).frozen(), "ssd-sata.overwrite-2pass", L::Clear, false},
        {"sata sed hpa", P(T::SATA, M::SSD_SATA).sed().sanitize(true, false, false).hidden(0, 100),
         "ssd-sata.unhide+crypto-scramble", L::Purge, true},
        {"nvme sed", P(T::NVMe, M::SSD_NVMe).sed().sanitize(true, true, false), "ssd-nvme.sanitize-crypto+sanitize-block", L::Purge, true},
        {"nvme sed fmt", P(T::NVMe, M::SSD_NVMe).sed(), "ssd-nvme.format-crypto", L::Purge, true},
        {"nvme plain", P(T::NVMe, M::SSD_NVMe).sanitize(false, true, false), "ssd-nvme.sanitize-block", L::Purge, true},
        {"nvme plain ow", P(T::NVMe, M::SSD_NVMe).sanitize(false, false, true), "ssd-nvme.sanitize-overwrite", L::Purge, true},
        {"nvme none", P(T::NVMe, M::SSD_NVMe), "ssd-nvme.format-erase", L::Clear, true},
        {"emmc", P(T::eMMC, M::eMMC).sanitize(false, false, false), "emmc.discard+sanitize", L::Purge, true},
        {"emmc none", P(T::eMMC, M::eMMC), "emmc.overwrite-2pass", L::Clear, false},
    };
    for (const auto& c : cases) {
        auto plan = select_method(c.profile);
        if (!plan) {
            std::fprintf(stderr, "FAIL matrix[%s]: %s\n", c.name, plan.error().describe().c_str());
            ++g_failures;
            continue;
        }
        if (plan->method_id != c.method_id || plan->level != c.level || plan->fully_simulated() != c.fully_simulated) {
            std::fprintf(stderr, "FAIL matrix[%s]: got %s/%s/sim=%d, want %s/%s/sim=%d\n", c.name,
                         plan->method_id.c_str(), std::string(to_string(plan->level)).c_str(), plan->fully_simulated(),
                         c.method_id, std::string(to_string(c.level)).c_str(), c.fully_simulated);
            ++g_failures;
        }
        // Every plan's device commands must be accepted by a drive matching the profile.
        SimulatedCommandExecutor ex(c.profile);
        std::vector<DeviceCommand> all;
        for (const auto& s : plan->steps) all.insert(all.end(), s.commands.begin(), s.commands.end());
        auto pf = ex.preflight(all);
        if (!pf) {
            std::fprintf(stderr, "FAIL matrix[%s] preflight: %s\n", c.name, pf.error().describe().c_str());
            ++g_failures;
        }
    }

    // Detail checks on the headline HDD plan.
    auto hdd = select_method(P(T::SATA, M::HDD).security(true));
    if (hdd) {
        CHECK(hdd->steps.size() == 2);
        CHECK(hdd->steps[0].execution == Execution::Real && hdd->steps[0].overwrite->pattern.stream == 1);
        CHECK(hdd->steps[1].execution == Execution::Emulated && hdd->steps[1].overwrite->pattern.stream == 2);
        CHECK(hdd->steps[1].commands.size() == 3);
        CHECK(hdd->verification.kind == VerificationExpectation::Kind::Pattern);
        CHECK(hdd->verification.expected->pattern.stream == 2);
        CHECK(hdd->verification.expected->sector_count == kSectors);
    }

    // Hidden areas: removed -> full medium; kept -> host range only and capped at Clear.
    auto hpa = select_method(P(T::SATA, M::HDD).security(true).hidden(2048, 8192));
    if (hpa) {
        CHECK(hpa->steps[0].execution == Execution::Emulated);
        CHECK(hpa->steps[0].commands.size() == 3);  // READ NATIVE MAX, SET MAX (non-volatile), DCO RESTORE
        CHECK(hpa->steps[0].commands[1].ata->count == 1);
        CHECK(hpa->steps[1].overwrite->sector_count == kSectors);
    }
    auto keep = select_method(P(T::SATA, M::HDD).security(true).hidden(2048, 8192), SelectorOptions{false, true});
    CHECK_OK(keep);
    if (keep) {
        CHECK(keep->method_id == "hdd.overwrite+ata-se-enhanced");
        CHECK(keep->level == SanitizationLevel::Clear);
        CHECK(keep->steps[0].overwrite->sector_count == kSectors - 2048 - 8192);
        CHECK(has_warning(*keep, "will NOT be sanitized"));
    }
    auto hpa_only = select_method(P(T::SATA, M::HDD).hidden(0, 100));
    if (hpa_only) CHECK(hpa_only->steps[0].commands.size() == 2 && hpa_only->steps[0].commands[1].ata->count == 0);

    auto frozen = select_method(P(T::SATA, M::HDD).security(true).frozen());
    if (frozen) CHECK(has_warning(*frozen, "FROZEN"));

    auto sed = select_method(P(T::SATA, M::SSD_SATA).sed().sanitize(true, true, false));
    if (sed) {
        CHECK(sed->verification.kind == VerificationExpectation::Kind::NotApplicable);
        CHECK(has_warning(*sed, "SIMULATED plan"));
        CHECK(to_json(*sed).dump().find("\"execution\":\"SIMULATED\"") != std::string::npos);
    }
    auto no_did = select_method(P(T::SATA, M::SSD_SATA).sed().sanitize(true, true, false), SelectorOptions{true, false});
    if (no_did) CHECK(no_did->method_id == "ssd-sata.crypto-scramble");

    CHECK_ERR_CONTAINS(select_method(P(T::SATA, M::HDD).security(true).locked()), "LOCKED");
    CHECK_ERR_CONTAINS(select_method(P(T::SATA, M::Unknown)), "unknown");
    CHECK_ERR_CONTAINS(select_method(P(T::NVMe, M::SSD_NVMe).hidden(0, 10)), "ATA-only");
}

void test_state_machine() {
    DeviceProfile hdd = P(Transport::SATA, MediaType::HDD).security(true).hidden(2048, 8192);

    {  // SECURITY ERASE UNIT must be immediately preceded by PREPARE, with the right password.
        SimulatedCommandExecutor ex(hdd);
        CHECK_ERR_CONTAINS(ex.issue(ata::security_erase_unit("pw", true)), "not immediately preceded");
        CHECK_OK(ex.issue(ata::security_erase_prepare()));
        CHECK_ERR_CONTAINS(ex.issue(ata::security_erase_unit("pw", true)), "security not enabled");
        CHECK_OK(ex.issue(ata::security_set_password("pw")));
        CHECK(ex.state().id.security_enabled);
        CHECK_OK(ex.issue(ata::security_erase_prepare()));
        CHECK_OK(ex.issue(ata::read_native_max_address_ext()));  // anything in between breaks the sequence
        CHECK_ERR_CONTAINS(ex.issue(ata::security_erase_unit("pw", true)), "not immediately preceded");
        CHECK_OK(ex.issue(ata::security_erase_prepare()));
        CHECK_ERR_CONTAINS(ex.issue(ata::security_erase_unit("wrong", true)), "password mismatch");
        CHECK_OK(ex.issue(ata::security_erase_prepare()));
        CHECK_OK(ex.issue(ata::security_erase_unit("pw", true)));
        CHECK(!ex.state().id.security_enabled);  // back to SEC1, temp password gone
        CHECK(ex.state().effects == std::vector<std::string>{"ata-se-enhanced"});
    }
    {  // Frozen drives reject the whole security feature set.
        SimulatedCommandExecutor ex(P(Transport::SATA, MediaType::HDD).security(true).frozen());
        CHECK_ERR_CONTAINS(ex.issue(ata::security_set_password("pw")), "FROZEN");
    }
    {  // HPA/DCO sequencing.
        SimulatedCommandExecutor ex(hdd);
        CHECK_ERR_CONTAINS(ex.issue(ata::set_max_address_ext(kSectors - 2048 - 1, true)), "READ NATIVE MAX");
        CHECK_ERR_CONTAINS(ex.issue(ata::dco_restore()), "HPA is set");
        CHECK_OK(ex.issue(ata::read_native_max_address_ext()));
        CHECK_ERR_CONTAINS(ex.issue(ata::set_max_address_ext(kSectors, true)), "beyond native max");
        CHECK_OK(ex.issue(ata::read_native_max_address_ext()));
        CHECK_OK(ex.issue(ata::set_max_address_ext(kSectors - 2048 - 1, true)));
        CHECK_OK(ex.issue(ata::dco_restore()));
        CHECK(ex.state().id.user_addressable_sectors == kSectors);
        CHECK(ex.state().id.native_max_sectors == kSectors);
    }
    {  // SANITIZE signatures, in-progress lockout, status polling.
        SimulatedCommandExecutor ex(P(Transport::SATA, MediaType::SSD_SATA).sanitize(true, true, false).security(true));
        auto bad = ata::sanitize_block_erase();
        bad.ata->lba = 0;
        CHECK_ERR_CONTAINS(ex.issue(bad), "signature");
        CHECK_ERR_CONTAINS(ex.issue(ata::sanitize_overwrite(0)), "OVERWRITE not supported");
        CHECK_OK(ex.issue(ata::sanitize_block_erase()));
        CHECK_ERR_CONTAINS(ex.issue(ata::security_set_password("pw")), "sanitize operation in progress");
        int polls = 0;
        Result<CommandResult> r = CommandResult{};
        do { r = ex.issue(ata::sanitize_status()); ++polls; } while (r && r->in_progress && polls < 10);
        CHECK_OK(r);
        CHECK(polls == 4);
        CHECK_OK(ex.issue(ata::security_set_password("pw")));  // lockout released
    }
    {  // Protocol mismatch and NVMe capability checks.
        SimulatedCommandExecutor ex(P(Transport::NVMe, MediaType::SSD_NVMe).sanitize(false, true, false));
        CHECK_ERR_CONTAINS(ex.issue(ata::security_erase_prepare()), "does not implement the ATA");
        CHECK_ERR_CONTAINS(ex.issue(nvme::sanitize(nvme::SanitizeAction::CryptoErase)), "SANICAP.CES");
        CHECK_ERR_CONTAINS(ex.issue(nvme::format_nvm(2, 1, 0)), "FNA");
        CHECK_OK(ex.issue(nvme::sanitize(nvme::SanitizeAction::BlockErase)));
        CHECK_ERR_CONTAINS(ex.issue(nvme::sanitize(nvme::SanitizeAction::BlockErase)), "in progress");
    }
    {  // Preflight must not mutate the real state.
        SimulatedCommandExecutor ex(hdd);
        std::vector<DeviceCommand> seq = {ata::security_set_password("pw"), ata::security_erase_prepare(),
                                          ata::security_erase_unit("pw", true)};
        CHECK_OK(ex.preflight(seq));
        CHECK(ex.state().effects.empty() && !ex.state().id.security_enabled);
        seq.erase(seq.begin() + 1);
        CHECK_ERR_CONTAINS(ex.preflight(seq), "preflight");
    }
}

void test_plan_execution() {
    FakeDevice dev;

    {  // Full HDD plan with emulated SE: commands go to the executor, both passes to the runner.
        DeviceProfile hdd = P(Transport::SATA, MediaType::HDD).security(true).hidden(2048, 8192);
        auto plan = select_method(hdd);
        SimulatedCommandExecutor ex(hdd);
        RecordingRunner runner;
        auto r = execute_plan(*plan, ex, &dev, &runner);
        CHECK_OK(r);
        if (r) {
            CHECK(r->success && r->achieved == SanitizationLevel::Purge);
            CHECK(runner.calls.size() == 2);
            CHECK(runner.calls[0].pattern.stream == 1 && runner.calls[1].pattern.stream == 2);
            CHECK(ex.state().effects == std::vector<std::string>{"ata-se-enhanced"});
            CHECK(ex.state().id.user_addressable_sectors == kSectors);
        }
    }
    {  // Host-I/O plan without a runner is refused before any command is issued.
        DeviceProfile hdd = P(Transport::SATA, MediaType::HDD).security(true);
        auto plan = select_method(hdd);
        SimulatedCommandExecutor ex(hdd);
        CHECK_ERR_CONTAINS(execute_plan(*plan, ex, &dev, nullptr), "no overwrite engine");
        CHECK(ex.state().effects.empty());
    }
    {  // Failure in the Purge pass leaves an honest record: Clear achieved, Purge failed.
        DeviceProfile hdd = P(Transport::SATA, MediaType::HDD).security(true);
        auto plan = select_method(hdd);
        SimulatedCommandExecutor ex(hdd);
        RecordingRunner runner;
        runner.fail_on_call = 1;
        auto r = execute_plan(*plan, ex, &dev, &runner);
        CHECK_OK(r);
        if (r) {
            CHECK(!r->success);
            CHECK(r->achieved == SanitizationLevel::Clear);
            CHECK(r->steps[0].status == StepRecord::Status::Completed);
            CHECK(r->steps[1].status == StepRecord::Status::Failed);
            CHECK(r->steps[1].error.find("injected") != std::string::npos);
        }
    }
    {  // Fully simulated SSD plan runs without a device writer at all.
        DeviceProfile sed = P(Transport::NVMe, MediaType::SSD_NVMe).sed().sanitize(true, true, false);
        auto plan = select_method(sed);
        SimulatedCommandExecutor ex(sed);
        auto r = execute_plan(*plan, ex, nullptr, nullptr);
        CHECK_OK(r);
        if (r) {
            CHECK(r->success && r->achieved == SanitizationLevel::Purge);
            CHECK((ex.state().effects == std::vector<std::string>{"nvme-crypto-erase", "nvme-block-erase"}));
            CHECK(to_json(*r).dump().find("\"status\":\"completed\"") != std::string::npos);
        }
    }
    {  // The real executor: only physical devices opened through the gate, and never without a preflight.
        DeviceProfile hw = P(Transport::SATA, MediaType::HDD).security(true);
        hw.identity_source = IdentitySource::AtaIdentify;
        PassthroughCommandExecutor pt(dev, hw, {});
        CHECK_ERR_CONTAINS(pt.issue(ata::security_erase_prepare()), "without a preflight");
        const DeviceCommand seq[] = {ata::security_erase_prepare()};
        CHECK_ERR_CONTAINS(pt.preflight(seq), "only sent to physical devices");
    }
}

// Hardware plans: what may be sent, and what the plan becomes when it may not.
DeviceProfile hardware(DeviceProfile p) {
    p.identity_source = p.identity.transport == Transport::NVMe ? IdentitySource::NvmeIdentify : IdentitySource::AtaIdentify;
    return p;
}

WipePlan hw_plan(DeviceProfile p, bool experimental, std::vector<std::string>* masked = nullptr) {
    SelectorOptions opts;
    auto m = mask_unvalidated_capabilities(p, opts, experimental);
    if (masked) *masked = m;
    auto plan = select_method(p, opts);
    CHECK_OK(plan);
    return plan ? *plan : WipePlan{};
}

void test_hardware_plans() {
#ifdef _WIN32
    // Windows: the same commands through SCSI pass-through, which has not run on hardware, so no
    // firmware command is Proven; NVMe, eMMC and block ioctls cannot be sent at all.
    CHECK(command_support(nvme::format_nvm(1, 1, 0)).level == Support::Unsupported);
    CHECK(command_support(nvme::sanitize(nvme::SanitizeAction::BlockErase)).level == Support::Unsupported);
    CHECK(command_support(emmc::sanitize()).level == Support::Unsupported);
    CHECK(command_support(blk::discard(0, 4096)).level == Support::Unsupported);
    const auto se = command_support(ata::security_erase_unit("x", true), MediaType::HDD);
    CHECK(se.level == Support::Experimental && se.why.find("SCSI pass-through") != std::string::npos);
    CHECK(command_support(ata::security_set_password("x"), MediaType::HDD).level == Support::Experimental);
    CHECK(command_support(ata::sanitize_overwrite(0), MediaType::HDD).level == Support::Experimental);
    CHECK(command_support(ata::read_native_max_address_ext()).level == Support::Proven);  // a read-only query
    CHECK(command_support(tcg::opal_genkey_all_ranges()).level == Support::Unsupported);

    std::vector<std::string> masked;
    auto clear = hw_plan(hardware(P(Transport::SATA, MediaType::HDD).security(true)), false, &masked);
    CHECK(clear.method_id == "hdd.overwrite" && clear.level == SanitizationLevel::Clear);
    CHECK(masked.size() == 1 && masked[0].find("Windows transport") != std::string::npos);
    auto purge = hw_plan(hardware(P(Transport::SATA, MediaType::HDD).security(true)), true, &masked);
    CHECK(masked.empty());
    CHECK(purge.method_id == "hdd.overwrite+ata-se-enhanced" && purge.level == SanitizationLevel::Purge);
    CHECK(purge.steps.size() == 2 && purge.steps[1].execution == Execution::Real && !purge.steps[1].overwrite);
    CHECK(purge.verification.kind == VerificationExpectation::Kind::Fingerprint);

    // NVMe: host overwrite even with --experimental, and the plan says why.
    auto nsan = hardware(P(Transport::NVMe, MediaType::SSD_NVMe).sanitize(false, true, false));
    auto nplan = hw_plan(nsan, true, &masked);
    CHECK(nplan.method_id == "ssd-nvme.overwrite-2pass" && nplan.level == SanitizationLevel::Clear);
    CHECK(!masked.empty() && masked.back().find("cannot be sent from Windows") != std::string::npos);
    for (const auto& st : nplan.steps) CHECK(st.commands.empty());

    // HPA/DCO removal needs --experimental here as on Linux.
    auto hpa = hw_plan(hardware(P(Transport::SATA, MediaType::HDD).hidden(0, 4096)), false, &masked);
    CHECK(hpa.level == SanitizationLevel::Clear && has_warning(hpa, "NOT be sanitized"));
#else
    CHECK(command_support(nvme::format_nvm(1, 1, 0)).level == Support::Proven);
    CHECK(command_support(nvme::format_nvm(2, 1, 0)).level == Support::Experimental);
    CHECK(command_support(nvme::sanitize(nvme::SanitizeAction::BlockErase)).level == Support::Experimental);
    CHECK(command_support(nvme::sanitize_status_log()).level == Support::Proven);  // a read-only poll
    // ATA Secure Erase: proven for the enhanced variant on HDDs only (hardware test, 2026-10-10).
    CHECK(command_support(ata::security_erase_unit("x", true), MediaType::HDD).level == Support::Proven);
    CHECK(command_support(ata::security_set_password("x"), MediaType::HDD).level == Support::Proven);
    CHECK(command_support(ata::security_erase_prepare(), MediaType::HDD).level == Support::Proven);
    CHECK(command_support(ata::security_erase_unit("x", false), MediaType::HDD).level == Support::Experimental);
    CHECK(command_support(ata::security_erase_unit("x", true), MediaType::SSD_SATA).level == Support::Experimental);
    CHECK(command_support(ata::security_erase_unit("x", true)).level == Support::Experimental);  // media unknown
    CHECK(command_support(ata::sanitize_overwrite(0), MediaType::HDD).level == Support::Experimental);
    CHECK(command_support(ata::set_max_address_ext(100, false)).level == Support::Experimental);
    CHECK(command_support(ata::read_native_max_address_ext()).level == Support::Proven);
    CHECK(command_support(blk::discard(0, 4096)).level == Support::Experimental);
    CHECK(command_support(emmc::sanitize()).level == Support::Experimental);
    CHECK(command_support(tcg::opal_genkey_all_ranges()).level == Support::Unsupported);

    // HDD that only has the non-enhanced Secure Erase (never exercised on hardware): without
    // --experimental the firmware step is masked out -> Clear.
    std::vector<std::string> masked;
    auto clear = hw_plan(hardware(P(Transport::SATA, MediaType::HDD).security(false)), false, &masked);
    CHECK(clear.method_id == "hdd.overwrite" && clear.level == SanitizationLevel::Clear);
    CHECK(clear.method_name == "HDD: pseudo-random overwrite (Clear only)");  // never claims a Purge it won't do
    CHECK(masked.size() == 1 && masked[0].find("ATA SECURITY ERASE disabled") != std::string::npos);
    CHECK(clear.verification.kind == VerificationExpectation::Kind::Pattern);
    CHECK(hw_plan(hardware(P(Transport::SATA, MediaType::HDD).security(false)), true).method_id == "hdd.overwrite+ata-se-normal");
    // HDD with ENHANCED Secure Erase: proven, so the default plan reaches Purge with no flag.
    // The erase is REAL (sent to the drive), carries no emulation pass, and the plan is
    // verified by pre-wipe fingerprints because the firmware writes last.
    auto purge = hw_plan(hardware(P(Transport::SATA, MediaType::HDD).security(true)), false, &masked);
    CHECK(masked.empty());
    // A SATA SSD with the same capability stays masked: Secure Erase on flash is not validated.
    std::vector<std::string> ssd_masked;
    auto ssd_clear = hw_plan(hardware(P(Transport::SATA, MediaType::SSD_SATA).security(true)), false, &ssd_masked);
    CHECK(ssd_clear.method_id == "ssd-sata.overwrite-2pass" && ssd_clear.level == SanitizationLevel::Clear);
    CHECK(ssd_masked.size() == 1 && ssd_masked[0].find("ATA SECURITY ERASE disabled") != std::string::npos);
    CHECK(purge.method_id == "hdd.overwrite+ata-se-enhanced" && purge.level == SanitizationLevel::Purge);
    CHECK(purge.steps.size() == 2 && purge.steps[1].execution == Execution::Real && !purge.steps[1].overwrite);
    CHECK(purge.steps[0].execution == Execution::Real && purge.steps[0].overwrite);
    CHECK(purge.verification.kind == VerificationExpectation::Kind::Fingerprint);
    CHECK(!purge.fully_simulated());

    // NVMe without Sanitize: Format NVM user-data erase (proven), for the confirmed namespace
    // and its current LBA format.
    DeviceProfile nv = hardware(P(Transport::NVMe, MediaType::SSD_NVMe));
    nv.identity.nvme_nsid = 2;
    nv.identity.nvme_lbaf = 1;
    auto fmt = hw_plan(nv, false);
    CHECK(fmt.method_id == "ssd-nvme.format-erase" && fmt.steps.size() == 1);
    CHECK(fmt.steps[0].commands[0].nvme->nsid == 2 && (fmt.steps[0].commands[0].nvme->cdw10 & 0xF) == 1);
    CHECK(fmt.steps[0].execution == Execution::Real);
    CHECK(fmt.verification.kind == VerificationExpectation::Kind::Fingerprint);
    CHECK(fmt.verification.expected && fmt.verification.expected->sector_count == kSectors);
    // No Format support either: two host passes, verified by pattern.
    nv.identity.nvme_format_supported = false;
    auto ow = hw_plan(nv, false);
    CHECK(ow.method_id == "ssd-nvme.overwrite-2pass" && ow.steps.size() == 2);
    CHECK(ow.verification.kind == VerificationExpectation::Kind::Pattern);

    // NVMe with Sanitize: masked without --experimental, used with it.
    auto nsan = hardware(P(Transport::NVMe, MediaType::SSD_NVMe).sanitize(false, true, false));
    CHECK(hw_plan(nsan, false).method_id == "ssd-nvme.format-erase");
    CHECK(hw_plan(nsan, true).method_id == "ssd-nvme.sanitize-block");

    // Opal is never sent, even with --experimental.
    std::vector<std::string> m2;
    auto sed = hw_plan(hardware(P(Transport::SATA, MediaType::SSD_SATA).sed().security(true)), true, &m2);
    for (const auto& st : sed.steps)
        for (const auto& c : st.commands) CHECK(c.protocol != Protocol::TCG);
    CHECK(!m2.empty() && m2[0].find("Opal") != std::string::npos);

    // HPA/DCO changes are experimental: without the flag the hidden area is left and the plan
    // says so and is capped at Clear.
    auto hpa = hw_plan(hardware(P(Transport::SATA, MediaType::HDD).hidden(0, 4096)), false, &masked);
    CHECK(hpa.level == SanitizationLevel::Clear && has_warning(hpa, "NOT be sanitized"));
    CHECK(!masked.empty() && masked.back().find("HPA/DCO removal disabled") != std::string::npos);

#endif

    // Secure Erase recovery commands: UNLOCK (0xF2) and DISABLE PASSWORD (0xF6), password block out.
    const auto unlock = ata::security_unlock(ata::kTempPassword), disable = ata::security_disable_password(ata::kTempPassword);
    CHECK(unlock.ata->command == 0xF2 && disable.ata->command == 0xF6);
    CHECK(unlock.ata->transfer == AtaTaskfile::Transfer::PioOut && unlock.ata->payload.size() == 512);
    CHECK(unlock.ata->payload[0] == 0 && std::memcmp(&unlock.ata->payload[2], "DataWipeTmp", 11) == 0);
    CHECK(command_support(unlock).level == Support::Experimental && command_support(disable).level == Support::Experimental);
    {  // A drive left locked by an interrupted erase: unlock, then disable, in that order.
        DeviceProfile locked = P(Transport::SATA, MediaType::HDD).security(true);
        locked.identity.security_enabled = locked.identity.security_locked = true;
        SimulatedCommandExecutor rules(locked);
        const DeviceCommand good[] = {unlock, disable};
        CHECK_OK(rules.preflight(good));
        const DeviceCommand wrong_order[] = {disable};
        CHECK_ERR_CONTAINS(rules.preflight(wrong_order), "UNLOCK first");
        DeviceProfile clean = P(Transport::SATA, MediaType::HDD).security(true);
        SimulatedCommandExecutor rules2(clean);
        const DeviceCommand nothing[] = {unlock};
        CHECK_ERR_CONTAINS(rules2.preflight(nothing), "nothing to unlock");
        // Known password (set earlier in the sequence) is checked; a wrong one is refused.
        const DeviceCommand mismatch[] = {ata::security_set_password("pw1"), ata::security_disable_password("pw2")};
        CHECK_ERR_CONTAINS(rules2.preflight(mismatch), "password mismatch");
    }

    // Erase timeout from the drive's own estimate: never too short.
    AtaIdentity est;
    est.ata_erase_minutes = 40;
    est.ata_enhanced_erase_minutes = 400;
    CHECK(ata_erase_timeout_ms(est, false) == 120u * 60000);        // 2 x 40 + 30 < 120: the 2 h floor
    CHECK(ata_erase_timeout_ms(est, true) == 830u * 60000);         // 2 x 400 + 30
    est.ata_erase_minutes = 0;
    CHECK(ata_erase_timeout_ms(est, false) == 72u * 3600000);       // not reported
    est.ata_erase_minutes = AtaIdentity::kEraseTimeOver508;
    CHECK(ata_erase_timeout_ms(est, false) == 72u * 3600000);       // "over 508 minutes"
    est.ata_enhanced_erase_minutes = 0x7FFF * 2;
    CHECK(ata_erase_timeout_ms(est, true) == 0xFFFFFFFFu);          // capped at SG_IO's limit

    // On a real drive the HPA removal is non-volatile (a needed reboot must not undo it).
    auto hpa_hw = hw_plan(hardware(P(Transport::SATA, MediaType::HDD).hidden(0, 4096)), true);
    CHECK(!hpa_hw.steps.empty() && hpa_hw.steps[0].level == SanitizationLevel::None);
    CHECK(hpa_hw.steps[0].commands.size() == 2 && (hpa_hw.steps[0].commands[1].ata->count & 1) == 1);
    auto hpa_sim = select_method(P(Transport::SATA, MediaType::HDD).hidden(0, 4096));
    CHECK(hpa_sim && (hpa_sim->steps[0].commands[1].ata->count & 1) == 0);  // simulated: volatile, as before

    // A USB bridge that reports one sector fewer than the drive: the host pass covers what the
    // kernel can reach, and the plan says what happens to the rest.
    DeviceProfile bridged = hardware(P(Transport::SATA, MediaType::HDD).security(true));
    bridged.geometry.size_bytes = (kSectors - 1) * 512;  // the kernel's view
    CHECK(bridged.unreachable_sectors() == 1);
    DeviceProfile bridged_plain = hardware(P(Transport::SATA, MediaType::HDD));  // no firmware erase at all
    bridged_plain.geometry.size_bytes = bridged.geometry.size_bytes;
    auto short_clear = hw_plan(bridged_plain, false);
    CHECK(short_clear.steps[0].overwrite->sector_count == kSectors - 1);
    CHECK(has_warning(short_clear, "1 sector(s) at the end of the drive cannot be reached") &&
          has_warning(short_clear, "NOT overwritten"));
#ifdef _WIN32
    auto short_purge = hw_plan(bridged, true);  // Windows: Secure Erase needs --experimental
#else
    auto short_purge = hw_plan(bridged, false);  // Secure Erase last: the firmware covers them
#endif
    CHECK(short_purge.steps[0].overwrite->sector_count == kSectors - 1);
    CHECK(has_warning(short_purge, "the firmware erase still covers the whole drive"));
    CHECK(short_purge.verification.expected->sector_count == kSectors - 1);  // read back what is reachable
    DeviceProfile sim_same = P(Transport::SATA, MediaType::HDD);
    CHECK(sim_same.unreachable_sectors() == 0);

    // eMMC (paper III-B): SANITIZE if supported, else BLKSECDISCARD secure erase, else two
    // host passes; boot/RPMB/GP areas are always reported as not covered.
    DeviceProfile em = P(Transport::eMMC, MediaType::eMMC);
    em.identity_source = IdentitySource::EmmcExtCsd;
    em.identity.emmc_secure_erase = true;
    em.identity.emmc_boot_bytes = 8u << 20;
#ifdef _WIN32
    // Windows cannot send eMMC commands: two host passes even with --experimental.
    auto em_win = hw_plan(em, true, &masked);
    CHECK(em_win.method_id == "emmc.overwrite-2pass" && em_win.level == SanitizationLevel::Clear);
    CHECK(has_warning(em_win, "boot 8192 KiB"));
    for (const auto& st : em_win.steps) CHECK(st.commands.empty());
#else
    auto em_proven = hw_plan(em, false, &masked);
    CHECK(em_proven.method_id == "emmc.overwrite-2pass" && em_proven.level == SanitizationLevel::Clear);
    CHECK(!masked.empty() && masked[0].find("BLKSECDISCARD") != std::string::npos);
    CHECK(has_warning(em_proven, "boot 8192 KiB"));
    auto em_secure = hw_plan(em, true);
    CHECK(em_secure.method_id == "emmc.secure-erase" && em_secure.level == SanitizationLevel::Purge);
    CHECK(em_secure.steps.size() == 1 && em_secure.steps[0].execution == Execution::Real);
    CHECK(em_secure.steps[0].commands[0].ioctl_request == BLKSECDISCARD);
    CHECK(em_secure.verification.kind == VerificationExpectation::Kind::Fingerprint);
    CHECK(command_support(em_secure.steps[0].commands[0]).level == Support::Experimental);
    em.identity.sanitize_supported = true;
    CHECK(hw_plan(em, true).method_id == "emmc.discard+sanitize");
#endif

    // Simulated drives are never masked: nothing reaches a device.
    DeviceProfile sim = P(Transport::SATA, MediaType::HDD).security(true);
    SelectorOptions so;
    CHECK(mask_unvalidated_capabilities(sim, so, false).empty() && sim.identity.security_supported);
}

}  // namespace

int main() {
    log::set_level(log::Level::Error);  // keep test output readable
    test_cdb_encoding();
    test_matrix();
    test_hardware_plans();
    test_state_machine();
    test_plan_execution();
    return finish("test_engine");
}
