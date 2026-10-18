// datawipe CLI.
//   probe  detection & classification (III-D), read-only
//   plan   probe + method selection (III-E), prints the plan, touches nothing
//   run    plan + execution: simulated device commands, real host overwrite passes
//          (engine/overwrite_engine.hpp), resumable through a journal (engine/run_journal.hpp),
//          then sampled read-back verification (verify/) and a JSON certificate (cert/).
//   verify       re-read a wiped medium later and check it against its certificate.
//   verify-cert  recompute a certificate's SHA-256.

#include <fcntl.h>
#ifndef _WIN32
#include <termios.h>
#endif
#include <unistd.h>

#include <cerrno>
#include <charconv>
#include <chrono>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <format>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <variant>
#include <vector>

#include "cert/certificate.hpp"
#include "cli/cli.hpp"
#ifdef _WIN32
#include "platform/win_device.hpp"
#endif
#include "cert/pdf.hpp"
#include "core/cancel.hpp"
#include "core/log.hpp"
#include "core/portable.hpp"
#include "device/classifier.hpp"
#include "device/device_factory.hpp"
#include "device/hw_identity.hpp"
#include "device/sysfs.hpp"
#include "device/identity_provider.hpp"
#include "engine/command_executor.hpp"
#include "engine/command_support.hpp"
#include "engine/method_selector.hpp"
#include "engine/overwrite_engine.hpp"
#include "engine/plan_executor.hpp"
#include "engine/run_journal.hpp"
#include "tecc/ed25519.hpp"
#include "tecc/session_chain.hpp"
#include "verify/arvs_sampler.hpp"
#include "verify/fingerprint.hpp"
#include "verify/readback_verifier.hpp"
#include "verify/risk_model.hpp"
#include "verify/sector_sampler.hpp"

namespace dwcli {

void usage() {
    std::cerr << "usage:\n"
                 "  datawipe [interactive] [--i-understand-this-is-destructive] [--experimental] [--state-dir <dir>]\n"
                 "                 guided mode: pick a drive from a list, review the plan, wipe, get the\n"
                 "                 certificate. Physical disks are listed only with the destructive flag.\n"
                 "  datawipe probe <target> --identity <profile.json> [--json] [-v]\n"
                 "  datawipe plan  <target> --identity <profile.json> [--keep-hidden] [--no-defense-in-depth] [--json]\n"
                 "  datawipe run   <target> --identity <profile.json> [--keep-hidden] [--no-defense-in-depth] [--json]\n"
                 "                [--buffer-size 4M] [--sync-every 256M] [--direct] [--journal <path>]\n"
                 "                [--resume | --restart] [--cert <path>] [--sign-key <org.key.pem>]\n"
                 "                [verification options]\n"
                 "  datawipe verify <target> --cert <certificate.json> [verification options] [--json]\n"
                 "  datawipe verify-cert <certificate.json|.pdf> [--pubkey <issuer.pub.pem>] [--log <session.dwlog.jsonl>]\n"
                 "  datawipe keygen <prefix> [--no-passphrase]        writes <prefix>.key.pem, <prefix>.pub.pem\n"
                 "  datawipe ata-unlock /dev/sdX --i-understand-this-is-destructive --experimental [--password P]\n"
                 "                   remove the ATA password an interrupted Secure Erase left (default: DataWipeTmp)\n"
                 "  datawipe --version\n"
                 "\n"
                 "  datawipe probe /dev/sdX|/dev/nvmeXnY [--json]      real disk, read-only detection\n"
                 "\n"
                 "Wipe targets: disk image files, loop devices backed by an image you own, and physical\n"
                 "disks. probe/plan are read-only (identify commands only; full detail needs sudo).\n"
                 "Wiping a physical disk (as root) requires " << kDestructiveFlag << ", an interactive\n"
                 "terminal on which you retype the drive's serial number and device path, and the disk not\n"
                 "being in use (mounted, swap, LVM/RAID/dm member). Its journal and certificate go to\n"
                 "--state-dir <dir> (or $DATAWIPE_STATE_DIR; default: current directory), named by model\n"
                 "and serial. Under sudo, prefer --state-dir and --sign-key: many sudo setups drop\n"
                 "environment variables.\n"
                 "  --experimental   also send firmware commands not yet validated on hardware (ATA\n"
                 "                   Secure Erase, SANITIZE, HPA/DCO removal, crypto erase); without it,\n"
                 "                   plans fall back to proven methods and say what was left out\n"
                 "\n"
                 "run: host overwrite passes really write the target. Ctrl-C stops at the next chunk,\n"
                 "flushes, and records durable progress in <image>.dwjournal; continue with --resume\n"
                 "or discard with --restart. Sizes take K/M/G suffixes (binary).\n"
                 "\n"
                 "Verification (ARVS + SCI): after a completed plan, 5-10% of the wiped range is read back\n"
                 "(more for riskier drives and methods), concentrated on hidden areas and on range and\n"
                 "resume boundaries. Failed\n"
                 "clusters are re-wiped and re-read; the certificate carries the Sanitization Confidence\n"
                 "Index. It is written to <image>.<UTC time>.dwcert.json (or --cert).\n"
                 "  --sampler arvs|uniform   risk-weighted clusters (default) or uniform single sectors\n"
                 "  --verify-budget 5%       ARVS base budget, percent of the range's sectors; scaled up to\n"
                 "                           2x by the drive/method risk (W, F, E)\n"
                 "  --fixed-budget           no risk scaling: read exactly the base budget\n"
                 "  --verify-samples N       uniform sampler: sector count (default 4603)\n"
                 "  --sci-lambda 3           weight of a high-risk failure relative to a baseline one\n"
                 "  --rewipe-attempts 3      re-wipes of a failing cluster before NOT VERIFIED (run only)\n"
                 "  --no-verify\n"
                 "exit: 0 done, 1 usage, 2 refused, 3 detection, 4 not supported, 5 error,\n"
                 "      6 plan failed (journal kept), 7 interrupted (resumable),\n"
                 "      8 verification failed / certificate check failed,\n"
                 "      10 hidden area (HPA/DCO) removed: run again to wipe the full native capacity\n"
                 "\n"
                 "Certificates (TECC): every session is a hash chain in <cert>.dwlog.jsonl (detection, plan,\n"
                 "execution, interruptions, verification, certificate); the certificate seals the chain's\n"
                 "terminal hash and is signed with --sign-key (or $DATAWIPE_SIGN_KEY; passphrase from\n"
                 "$DATAWIPE_KEY_PASSPHRASE or the terminal). A PDF copy embeds the signed JSON.\n";
}

// "4M" -> 4194304. Binary suffixes K, M, G; a bare number is bytes.
std::optional<std::uint64_t> parse_size(std::string_view s) {
    std::uint64_t v = 0;
    auto [p, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
    if (ec != std::errc() || p == s.data()) return std::nullopt;
    std::string_view rest(p, static_cast<std::size_t>(s.data() + s.size() - p));
    int shift = 0;
    if (rest == "K" || rest == "k") shift = 10;
    else if (rest == "M" || rest == "m") shift = 20;
    else if (rest == "G" || rest == "g") shift = 30;
    else if (!rest.empty()) return std::nullopt;
    if (v > (UINT64_MAX >> shift)) return std::nullopt;
    return v << shift;
}

std::optional<Args> parse_args(int argc, char** argv) {
    Args a;
    std::vector<std::string> pos;
    for (int i = 1; i < argc; ++i) {
        std::string s = argv[i];
        if (s == "--identity" && i + 1 < argc) a.identity = argv[++i];
        else if (s == "--json") a.json = true;
        else if (s == "-v" || s == "--verbose") a.verbose = true;
        else if (s == kDestructiveFlag) a.destructive = true;
        else if (s == "--keep-hidden") a.selector.remove_hidden_areas = false;
        else if (s == "--no-defense-in-depth") a.selector.defense_in_depth = false;
        else if (s == "--direct") a.direct = true;
        else if (s == "--resume") a.resume = true;
        else if (s == "--restart") a.restart = true;
        else if (s == "--journal" && i + 1 < argc) a.journal = argv[++i];
        else if (s == "--no-verify") a.verify = false;
        else if (s == "--fixed-budget") a.fixed_budget = true;
        else if (s == "--cert" && i + 1 < argc) a.cert = argv[++i];
        else if (s == "--sign-key" && i + 1 < argc) a.sign_key = argv[++i];
        else if (s == "--pubkey" && i + 1 < argc) a.pubkey = argv[++i];
        else if (s == "--log" && i + 1 < argc) a.log = argv[++i];
        else if (s == "--password" && i + 1 < argc) a.ata_password = argv[++i];
        else if (s == "--state-dir" && i + 1 < argc) ::setenv("DATAWIPE_STATE_DIR", argv[++i], 1);
        else if (s == "--no-passphrase") a.no_passphrase = true;
        else if (s == "--experimental") a.experimental = true;
        else if (s == "--sampler" && i + 1 < argc) {
            a.sampler = argv[++i];
            if (a.sampler != "arvs" && a.sampler != "uniform") {
                std::cerr << "--sampler must be arvs or uniform\n";
                return std::nullopt;
            }
        }
        else if ((s == "--verify-budget" || s == "--sci-lambda") && i + 1 < argc) {
            std::string v = argv[++i];
            const bool pct = s == "--verify-budget";
            if (pct && v.ends_with("%")) v.pop_back();
            char* end = nullptr;
            const double d = std::strtod(v.c_str(), &end);
            if (v.empty() || *end || !(d > 0) || (pct && d > 100) || (!pct && d > 1000)) {
                std::cerr << "bad value for " << s << ": " << argv[i] << "\n";
                return std::nullopt;
            }
            if (pct) a.verify_budget = d / 100;
            else a.sci_lambda = d;
        }
        else if (s == "--rewipe-attempts" && i + 1 < argc) {
            std::string_view v = argv[++i];
            auto [p, ec] = std::from_chars(v.data(), v.data() + v.size(), a.rewipe_attempts);
            if (ec != std::errc() || p != v.data() + v.size() || a.rewipe_attempts > 10) {
                std::cerr << "--rewipe-attempts takes 0..10\n";
                return std::nullopt;
            }
        }
        else if (s == "--verify-samples" && i + 1 < argc) {
            std::string_view v = argv[++i];
            auto [p, ec] = std::from_chars(v.data(), v.data() + v.size(), a.verify_samples);
            if (ec != std::errc() || p != v.data() + v.size() || a.verify_samples == 0) {
                std::cerr << "bad count for --verify-samples: " << v << "\n";
                return std::nullopt;
            }
        }
        else if ((s == "--buffer-size" || s == "--sync-every") && i + 1 < argc) {
            auto v = parse_size(argv[++i]);
            if (!v || *v == 0 || (s == "--buffer-size" && *v > (1ull << 30))) {
                std::cerr << "bad size for " << s << ": " << argv[i] << "\n";
                return std::nullopt;
            }
            if (s == "--buffer-size") a.overwrite.buffer_bytes = static_cast<std::size_t>(*v);
            else a.overwrite.sync_interval_bytes = *v;
        }
        else if (s.starts_with("-")) { std::cerr << "unknown option " << s << "\n"; return std::nullopt; }
        else pos.push_back(s);
    }
    if (pos.size() == 1 && pos[0] == "interactive") pos.emplace_back();
    // No command at all on a terminal: the guided mode. Anything else incomplete is a usage error.
    if (pos.empty() && argc >= 1 && ::isatty(STDIN_FILENO) && ::isatty(STDOUT_FILENO)) pos = {"interactive", ""};
    if (pos.size() != 2) return std::nullopt;
    if (a.resume && a.restart) {
        std::cerr << "--resume and --restart are mutually exclusive\n";
        return std::nullopt;
    }
    a.command = pos[0];
    a.target = pos[1];
    return a;
}

// Physical disk: read-only detection. Only whitelisted query commands reach the drive, so no
// confirmation is needed here; anything that writes goes through the destructive gate.
std::variant<Probed, int> probe_physical(const Args& a, const dw::TargetAssessment& assessed) {
    if (a.identity) {
        dw::log::error("--identity (simulated profile) cannot be used with a physical device");
        return 2;
    }
    std::cerr << "READ-ONLY detection of physical device " << assessed.canonical_path
              << ": only identify/query commands are sent\n";
    for (const auto& u : assessed.in_use) std::cerr << "  in use: " << u << " (fine for detection; blocks wiping)\n";
    auto det = dw::detect_physical(assessed);
    if (!det) {
        dw::log::error("{}", det.error().describe());
        return 3;
    }
    auto profile = dw::classify(assessed, det->geometry, det->identity, det->source, det->origin);
    if (!profile) {
        dw::log::error("classification failed: {}", profile.error().describe());
        return 3;
    }
    return Probed{std::move(det->target), std::move(profile).value()};
}

// Guard -> open -> identify -> classify. Exit code on failure.
std::variant<Probed, int> probe_target(const Args& a, bool writable) {
    auto assessed = dw::assess_target(a.target);
    if (!assessed) {
        dw::log::error("{}", assessed.error().describe());
        return 2;
    }
    if (assessed->kind == dw::BackendKind::PhysicalBlock) return probe_physical(a, *assessed);

    if (!a.identity) {
        dw::log::error("{} [{}] needs --identity <profile.json> to say what drive it simulates", a.target,
                       dw::to_string(assessed->kind));
        return 2;
    }
    auto sim = dw::SimulatedIdentityProvider::load(*a.identity);
    if (!sim) {
        dw::log::error("{}", sim.error().describe());
        return 2;
    }
    auto target = dw::open_target(a.target, dw::OpenOptions{.writable = writable, .direct_io = writable && a.direct});
    if (!target) {
        dw::log::error("{}", target.error().describe());
        return 2;
    }
    auto identity = sim->identify(*target->device);
    if (!identity) {
        dw::log::error("{}", identity.error().describe());
        return 3;
    }
    auto profile = dw::classify(*target, *identity, sim->source(), sim->origin());
    if (!profile) {
        dw::log::error("classification failed: {}", profile.error().describe());
        return 3;
    }
    return Probed{std::move(target).value(), std::move(profile).value()};
}

// After confirmation: identify the drive again from scratch, check it is still the one the
// operator confirmed, then open it writable and exclusively (O_EXCL) under the override.
std::variant<Probed, int> reopen_physical(const Args& a, const dw::PhysicalOverride& override) {
    auto assessed = dw::assess_target(a.target);
    if (!assessed) {
        dw::log::error("{}", assessed.error().describe());
        return 2;
    }
    auto det = dw::detect_physical(*assessed);
    if (!det) {
        dw::log::error("{}", det.error().describe());
        return 3;
    }
    if (det->identity.serial != override.serial()) {
        dw::log::error("REFUSED {}: the drive now reports serial '{}', but '{}' was confirmed", a.target,
                       det->identity.serial, override.serial());
        return 2;
    }
    det->target.reset();  // release the read-only identify handle
    auto target = dw::open_target(a.target, dw::OpenOptions{.writable = true, .direct_io = a.direct}, &override);
    if (!target) {
        dw::log::error("{}", target.error().describe());
        return 2;
    }
    auto profile = dw::classify(*target, det->identity, det->source, det->origin);
    if (!profile) {
        dw::log::error("classification failed: {}", profile.error().describe());
        return 3;
    }
    return Probed{std::move(target).value(), std::move(profile).value()};
}

void print_profile(const dw::DeviceProfile& p) {
    const auto& id = p.identity;
    std::cout << "Target            " << p.path << "  [" << dw::to_string(p.backend) << "]\n";
    if (!p.backing_file.empty()) std::cout << "Backing file      " << p.backing_file << "\n";
    std::cout << "Size              " << p.geometry.size_bytes << " bytes, " << p.geometry.sector_count() << " x "
              << p.geometry.logical_sector_size << "B sectors (physical " << p.geometry.physical_sector_size << "B)\n"
              << "Identity source   " << dw::to_string(p.identity_source) << " (" << p.identity_origin << ")\n"
              << "Model / serial    " << id.model << " / " << id.serial << "  fw " << id.firmware << "\n"
              << "Transport         " << dw::to_string(id.transport) << ", rotation_rate " << id.rotation_rate << "\n"
              << "Capacity          user " << id.user_addressable_sectors << " / native " << id.native_max_sectors
              << " / dco " << id.dco_max_sectors << " sectors  -> hidden " << p.hidden_sectors() << "\n"
              ;
    if (!dw::capabilities_queried(p.identity_source)) {
        const char* why = p.identity_source == dw::IdentitySource::Sysfs ? "sysfs only" : "Windows build";
        std::cout << "Security          not queried (" << why << ")\n"
                  << "Sanitize          not queried (" << why << ")\n"
                  << "Encryption        not queried (" << why << ")\n";
    } else {
        std::cout << "Security          supported=" << id.security_supported << " enhanced=" << id.enhanced_erase_supported
                  << " password_set=" << id.security_enabled << " frozen=" << id.security_frozen
                  << " locked=" << id.security_locked << "\n";
        if (id.security_supported && p.identity_source == dw::IdentitySource::AtaIdentify) {
            auto minutes = [](std::uint32_t m) {
                return m == 0 ? std::string("not reported")
                       : m == dw::AtaIdentity::kEraseTimeOver508 ? std::string("over 508 min")
                                                                 : std::format("{} min", m);
            };
            std::cout << "Erase estimate    normal " << minutes(id.ata_erase_minutes) << ", enhanced "
                      << minutes(id.ata_enhanced_erase_minutes) << " (the drive's own figures for SECURITY ERASE)\n";
        }
        std::cout
                  << "Sanitize          supported=" << id.sanitize_supported << " crypto=" << id.crypto_scramble_supported
                  << " block=" << id.block_erase_supported << " overwrite=" << id.overwrite_supported << "\n";
        if (p.identity_source != dw::IdentitySource::Simulated)
            std::cout << "TCG               " << (id.tcg_ssc.empty() ? "none reported" : id.tcg_ssc)
                      << (id.self_encrypting ? " (self-encrypting)" : "") << "\n";
    }
    std::cout
              << "Classification    " << dw::to_string(p.media) << (p.encrypted ? ", self-encrypting" : "") << "\n";
    for (const auto& w : p.warnings) std::cout << "WARNING           " << w << "\n";
}

void print_plan(const dw::WipePlan& plan) {
    std::cout << "\nMethod            " << plan.method_name << "\n"
              << "Method id         " << plan.method_id << "\n"
              << "NIST level        " << dw::to_string(plan.level) << "\n";
    for (const auto& s : plan.standards) std::cout << "Standard          " << s << "\n";
    for (size_t i = 0; i < plan.steps.size(); ++i) {
        const auto& s = plan.steps[i];
        std::cout << "\n  Step " << i + 1 << " [" << dw::to_string(s.execution) << "] " << s.title << "  ("
                  << dw::to_string(s.level) << ")\n";
        for (const auto& c : s.commands) std::cout << "      cmd  " << c.describe() << "\n";
        if (s.overwrite)
            std::cout << "      I/O  host write sectors [" << s.overwrite->first_sector << ", "
                      << s.overwrite->first_sector + s.overwrite->sector_count << ") with "
                      << s.overwrite->pattern.describe() << "\n";
        std::cout << "      why  " << s.rationale << "\n";
    }
    std::cout << "\nVerification      " << plan.verification.reason << "\n";
    for (const auto& w : plan.warnings) std::cout << "WARNING           " << w << "\n";
}

int cmd_probe(const Args& a) {
    auto r = probe_target(a, false);
    if (auto* code = std::get_if<int>(&r)) return *code;
    const auto& p = std::get<Probed>(r).profile;
    if (a.json) std::cout << dw::to_json(p).dump(2) << "\n";
    else print_profile(p);
    return 0;
}

// Real drives are planned from a copy of their identity with the capabilities this build may
// not use masked out (engine/command_support.hpp), so the plan falls back to proven methods.
std::optional<dw::WipePlan> make_plan(const Args& a, const dw::DeviceProfile& p) {
    dw::DeviceProfile planning = p;
    dw::SelectorOptions opts = a.selector;
    const auto masked = dw::mask_unvalidated_capabilities(planning, opts, a.experimental);
    auto plan = dw::select_method(planning, opts);
    if (!plan) {
        dw::log::error("method selection failed: {}", plan.error().describe());
        if (p.identity.security_locked && p.identity_source == dw::IdentitySource::AtaIdentify)
            dw::log::error("if an interrupted datawipe Secure Erase left it locked, recover it with: datawipe "
                           "ata-unlock {} --i-understand-this-is-destructive --experimental, then run again",
                           p.path);
        return std::nullopt;
    }
    for (const auto& m : masked) plan->warnings.push_back(m);
    return std::move(plan).value();
}

int cmd_plan(const Args& a) {
    auto r = probe_target(a, false);
    if (auto* code = std::get_if<int>(&r)) return *code;
    const auto& p = std::get<Probed>(r).profile;
    auto plan = make_plan(a, p);
    if (!plan) return 3;
    if (a.json) {
        dw::Json j = dw::Json::object();
        j["device"] = dw::to_json(p);
        j["plan"] = dw::to_json(*plan);
        std::cout << j.dump(2) << "\n";
    } else {
        print_profile(p);
        print_plan(*plan);
    }
    return 0;
}

// Progress on stderr: an in-place bar on a terminal, a line per 10% otherwise.
class ProgressPrinter final : public dw::PlanObserver {
public:
    explicit ProgressPrinter(std::size_t steps) : steps_(steps), tty_(::isatty(STDERR_FILENO)) {}

    void step_started(std::size_t i, const dw::WipeStep& step) override {
        std::cerr << std::format("\n== Step {}/{} [{}] {}\n", i + 1, steps_, dw::to_string(step.execution), step.title);
        last_decile_ = -1;
    }

    void overwrite_progress(std::size_t, const dw::OverwriteProgress& p) override {
        const double frac = p.bytes_total ? double(p.bytes_written) / double(p.bytes_total) : 1.0;
        constexpr double kMiB = 1024.0 * 1024.0;
        // Speed and ETA from data confirmed on the medium: until the first flush, "written"
        // only means "in the page cache", which runs at memory speed and predicts nothing.
        const double bps = p.bytes_durable > p.bytes_resumed && p.seconds > 0
                               ? double(p.bytes_durable - p.bytes_resumed) / p.seconds
                               : 0;
        const double rate = bps / kMiB;
        std::string eta = "--:--:--";
        if (bps > 0) {
            const auto secs = static_cast<long>(double(p.bytes_total - p.bytes_durable) / bps);
            eta = std::format("{}:{:02}:{:02}", secs / 3600, secs / 60 % 60, secs % 60);
        }
        const std::string stats =
            std::format("{:5.1f}%  {:.1f}/{:.1f} MiB  {:.1f} MiB/s  ETA {}  durable {:.1f}%", 100 * frac,
                        double(p.bytes_written) / kMiB, double(p.bytes_total) / kMiB, rate, eta,
                        p.bytes_total ? 100.0 * double(p.bytes_durable) / double(p.bytes_total) : 100.0);
        if (tty_) {
            constexpr int kWidth = 30;
            const int fill = static_cast<int>(frac * kWidth);
            std::cerr << "\r  [" << std::string(fill, '#') << std::string(kWidth - fill, '.') << "] " << stats
                      << "\x1b[K" << (p.final ? "\n" : "") << std::flush;
        } else {
            // Not a terminal (piped to tee, a log file): a line per 10%, and at least one a
            // minute, so a multi-hour pass never looks hung.
            const int decile = static_cast<int>(std::floor(frac * 10));
            const auto now = std::chrono::steady_clock::now();
            if (decile != last_decile_ || p.final || now - last_line_ >= std::chrono::seconds(60)) {
                std::cerr << "  " << stats << "\n";
                last_line_ = now;
            }
            last_decile_ = decile;
        }
    }

private:
    std::size_t steps_;
    bool tty_;
    int last_decile_ = -1;
    std::chrono::steady_clock::time_point last_line_ = std::chrono::steady_clock::now();
};

std::string_view status_word(dw::StepRecord::Status s) {
    switch (s) {
        case dw::StepRecord::Status::Completed: return "completed";
        case dw::StepRecord::Status::Failed: return "FAILED";
        case dw::StepRecord::Status::Aborted: return "INTERRUPTED";
        case dw::StepRecord::Status::NotRun: return "not run";
    }
    return "?";
}

// Read-only handle for the read-back. O_DIRECT, so sectors come from the medium rather than
// from pages the wipe just wrote, unless the filesystem refuses it (tmpfs) or the size is not
// 4 KiB-aligned (the verifier reads aligned 4 KiB windows). Then buffered reads with per-read
// page-cache eviction (verify/readback_verifier.hpp).
dw::Result<dw::OpenedTarget> open_for_verify(const std::string& path) {
    if (auto t = dw::open_target(path, dw::OpenOptions{.writable = false, .direct_io = true});
        t && t->device->geometry().size_bytes % 4096 == 0) {
        std::unique_ptr<std::byte, decltype(&dw::aligned_free)> probe(
            static_cast<std::byte*>(dw::aligned_alloc_bytes(4096, 4096)), &dw::aligned_free);
        if (probe && t->device->read_at(0, std::span(probe.get(), 4096))) return std::move(t).value();
        dw::log::debug("O_DIRECT read refused on {}; verifying with buffered reads", path);
    }
    return dw::open_target(path, dw::OpenOptions{.writable = false, .direct_io = false});
}

// ARVS over `ctx` (default), or uniform single sectors with --sampler uniform.
dw::Result<std::unique_ptr<dw::ISectorSampler>> make_sampler(const Args& a, const dw::RiskContext& ctx,
                                                             const dw::PairwiseMatrix& judgments) {
    auto seed = dw::random_pattern_key();
    if (!seed) return seed.error();
    if (a.sampler == "uniform") return std::unique_ptr<dw::ISectorSampler>(new dw::UniformSampler(*seed, a.verify_samples));
    dw::ArvsConfig cfg;
    cfg.budget_fraction = a.verify_budget;
    if (a.fixed_budget) cfg.device_risk_gain = 0;
    auto s = dw::ArvsSampler::create(*seed, ctx, judgments, cfg);
    if (!s) return s.error();
    return std::unique_ptr<dw::ISectorSampler>(new dw::ArvsSampler(std::move(s).value()));
}

std::string sampler_banner(const Args& a) {
    return a.sampler == "uniform" ? std::format("{} uniformly sampled sectors", a.verify_samples)
                                  : std::format("ARVS, {:g}% base budget{}, placed by risk", a.verify_budget * 100,
                                                a.fixed_budget ? " (fixed)" : " scaled by drive/method risk");
}

// ---- TECC: signing key and session chain ----

// Passphrase for an encrypted key: $DATAWIPE_KEY_PASSPHRASE, else asked on the terminal with
// echo off. Never taken from the command line, where it would land in shell history and ps.
std::string ask_passphrase(const std::string& prompt) {
    if (const char* env = std::getenv("DATAWIPE_KEY_PASSPHRASE")) return env;
#ifdef _WIN32
    char secret[512];
    return dw::win::read_console_secret(prompt.c_str(), secret, sizeof secret) ? std::string(secret) : std::string();
#else
    int fd = ::open("/dev/tty", O_RDWR | O_CLOEXEC);
    if (fd < 0) return {};
    termios old{};
    const bool tty = ::tcgetattr(fd, &old) == 0;
    if (tty) {
        termios quiet = old;
        quiet.c_lflag &= ~static_cast<tcflag_t>(ECHO);
        ::tcsetattr(fd, TCSAFLUSH, &quiet);
    }
    (void)!::write(fd, prompt.data(), prompt.size());
    std::string line;
    char c;
    while (::read(fd, &c, 1) == 1 && c != '\n') line += c;
    if (tty) ::tcsetattr(fd, TCSAFLUSH, &old);
    (void)!::write(fd, "\n", 1);
    ::close(fd);
    return line;
#endif
}

// The run's signing key: --sign-key, else $DATAWIPE_SIGN_KEY; none means unsigned certificates.
// Loaded before anything is written, so a wrong passphrase stops the run, not the certificate.
std::variant<std::optional<dw::ed25519::PrivateKey>, int> load_signing_key(const Args& a) {
    std::string path;
    if (a.sign_key) path = *a.sign_key;
    else if (const char* env = std::getenv("DATAWIPE_SIGN_KEY")) path = env;
    if (path.empty()) {
        dw::log::warn("no signing key (--sign-key or DATAWIPE_SIGN_KEY): the certificate will be UNSIGNED; its hash "
                      "chain proves integrity but not who issued it");
        return std::optional<dw::ed25519::PrivateKey>();
    }
    auto key = dw::ed25519::PrivateKey::load(path, [&] { return ask_passphrase("Passphrase for " + path + ": "); });
    if (!key) {
        dw::log::error("{}", key.error().describe());
        return 2;
    }
    dw::log::info("certificates will be signed with key {} ({})", dw::ed25519::key_id(key->public_key()), path);
    return std::optional<dw::ed25519::PrivateKey>(std::move(key).value());
}

std::string basename_of(const std::string& path) {
    const auto slash = dw::last_separator(path);
    return slash == std::string::npos ? path : path.substr(slash + 1);
}

std::string dirname_of(const std::string& path) {
    const auto slash = dw::last_separator(path);
    return slash == std::string::npos ? "." : path.substr(0, slash);
}

// Appends to the session chain and, during a resumable wipe, records the new end in the journal.
bool chain_append(dw::tecc::SessionChain& chain, dw::RunJournal* journal, const std::string& stage, dw::Json data) {
    auto h = chain.append(stage, std::move(data));
    if (!h) {
        dw::log::error("cannot append '{}' to the session log {}: {}", stage, chain.path(), h.error().describe());
        return false;
    }
    if (journal) journal->set_chain(chain.count(), dw::tecc::hex(*h));
    return true;
}

dw::Json plan_entry(const dw::WipePlan& plan, const dw::PatternKey* key) {
    dw::Json j = dw::Json::object();
    j["plan"] = dw::to_json(plan);
    j["plan_sha256"] = dw::plan_digest(plan);
    if (key) j["pattern_key_fingerprint"] = dw::key_fingerprint(*key);
    return j;
}

// Progress of a read phase (verification, pre-wipe fingerprints) on stderr: in place on a
// terminal; when piped, a line per 10% and at least one a minute.
class PhaseProgress {
public:
    PhaseProgress(std::string label, bool quiet) : label_(std::move(label)), quiet_(quiet), tty_(::isatty(STDERR_FILENO)) {}
    void operator()(std::uint64_t done, std::uint64_t total, std::uint64_t sectors) {
        if (quiet_ || total == 0) return;
        const auto now = std::chrono::steady_clock::now();
        const int decile = static_cast<int>(done * 10 / total);
        const bool last = done == total;
        if (tty_ ? (now - last_ < std::chrono::milliseconds(250) && !last)
                 : (decile == decile_ && now - last_ < std::chrono::seconds(60) && !last))
            return;
        const std::string line = std::format("  {}: {} of {} units ({:.1f}%), {} sectors read", label_, done, total,
                                             100.0 * double(done) / double(total), sectors);
        if (tty_) std::cerr << "\r" << line << "\x1b[K" << (last ? "\n" : "") << std::flush;
        else std::cerr << line << "\n";
        last_ = now;
        decile_ = decile;
    }

private:
    std::string label_;
    bool quiet_, tty_;
    int decile_ = -1;
    std::chrono::steady_clock::time_point last_ = std::chrono::steady_clock::now() - std::chrono::hours(1);
};

struct Completion {
    dw::VerificationResult verification;
    dw::CertificatePaths paths;
    bool written = false;  // certificate JSON written
    bool pdf_written = false;
    std::string terminal_hash;
    std::string key_id;  // empty: unsigned
    std::string outcome;
    bool cert_failed = false;
    bool interrupted = false;  // verification stopped on request: no certificate yet, --resume repeats it
};

// After a completed plan: read back a sample (plans whose result is a host-known pattern),
// append it to the session chain, then seal and write the certificate (JSON + PDF). An
// unfinished plan gets neither; its journal and session log are the record.
Completion verify_and_certify(const Args& a, const dw::DeviceProfile& profile, const dw::WipePlan& plan,
                              const dw::PlanRunResult& result, const dw::JournalRecord* record,
                              dw::IBlockDevice* writable, dw::tecc::SessionChain& chain,
                              const dw::ed25519::PrivateKey* key, const dw::CertificatePaths& paths,
                              const dw::FingerprintSet* fingerprints, const dw::CancelToken* cancel = nullptr) {
    using Status = dw::VerificationResult::Status;
    Completion c;
    c.paths = paths;
    if (!result.success) {
        c.verification = dw::verification_not_performed(Status::Skipped, "plan did not complete");
        return c;
    }
    using Kind = dw::VerificationExpectation::Kind;
    if (plan.verification.kind == Kind::NotApplicable || !record) {
        c.verification = dw::verification_not_performed(Status::NotApplicable, plan.verification.reason);
    } else if (!a.verify) {
        c.verification = dw::verification_not_performed(Status::Skipped, "disabled with --no-verify");
    } else if (plan.verification.kind == Kind::Fingerprint) {
        auto dev = open_for_verify(profile.path);
        if (!fingerprints || !dev) {
            c.verification = dw::verification_not_performed(
                Status::Failed, "cannot start read-back: " +
                                    (!fingerprints ? std::string("no pre-wipe fingerprints") : dev.error().describe()));
        } else {
            if (!a.json)
                std::cerr << std::format("\n== Verify: {} fingerprinted sectors must no longer hold their pre-wipe "
                                         "content ({})\n",
                                         fingerprints->sector_total(), dev->device->direct_io() ? "O_DIRECT" : "buffered");
            const dw::OverwriteSpec& range = *plan.verification.expected;
            dw::FingerprintOracle oracle(*fingerprints);
            dw::VerifyConfig cfg;
            cfg.cancel = cancel;
            cfg.on_progress = PhaseProgress("verify", a.json);
            cfg.sci_lambda = a.sci_lambda;
            cfg.rewipe_device = writable;
            cfg.rewipe_attempts = a.rewipe_attempts;
            cfg.rewipe_pattern = dw::PatternSpec{dw::PatternSpec::Kind::Prng, dw::kRewipeStream, 0};
            cfg.rewipe_key = record->key;
            c.verification = dw::verify_units(*dev->device, {range.first_sector, range.sector_count}, fingerprints->units,
                                              oracle, fingerprints->sampler, cfg);
        }
    } else {
        // Risk context: the final pattern's range, and the seams where its pass was resumed.
        const dw::OverwriteSpec& spec = *plan.verification.expected;
        std::size_t final_step = 0;
        for (std::size_t i = 0; i < plan.steps.size(); ++i)
            if (plan.steps[i].overwrite) final_step = i;
        std::vector<std::uint64_t> seams;
        for (const auto& [step, sector] : record->resumes)
            if (step == final_step) seams.push_back(sector);
        const auto ctx = dw::make_risk_context(profile, plan, {spec.first_sector, spec.first_sector + spec.sector_count}, seams);
        auto sampler = make_sampler(a, ctx, dw::default_pairwise());
        auto dev = open_for_verify(profile.path);
        if (!sampler || !dev) {
            c.verification = dw::verification_not_performed(
                Status::Failed, "cannot start read-back: " + (!sampler ? sampler.error() : dev.error()).describe());
        } else {
            if (!a.json)
                std::cerr << std::format("\n== Verify: {} ({})\n", sampler_banner(a),
                                         dev->device->direct_io() ? "O_DIRECT" : "buffered");
            dw::VerifyConfig cfg;
            cfg.cancel = cancel;
            cfg.on_progress = PhaseProgress("verify", a.json);
            cfg.sci_lambda = a.sci_lambda;
            cfg.rewipe_device = writable;
            cfg.rewipe_attempts = a.rewipe_attempts;
            c.verification = dw::verify_readback(plan.verification, *dev->device, record->key, **sampler, cfg);
        }
    }
    if (c.verification.status == Status::Interrupted) {
        // No certificate: the journal is kept, and --resume repeats only the verification.
        c.interrupted = true;
        chain_append(chain, nullptr, "verification-interrupted", dw::to_json(c.verification));
        return c;
    }
    c.cert_failed = true;  // until the certificate is on disk
    if (!chain_append(chain, nullptr, "verification", dw::to_json(c.verification))) return c;

    dw::CertificateInput in{profile, plan, result, c.verification, std::nullopt, 1, {}};
    if (record) {
        in.pattern_key = record->key;
        in.runs = record->runs;
        in.started_at = record->started_at;
    }
    c.outcome = std::string(dw::certificate_outcome(in));
    auto sealed = dw::seal_certificate(dw::certificate_body(in, dw::random_uuid(), dw::tecc::utc_now(), chain.session_id()),
                                       chain, key, basename_of(paths.log));
    if (!sealed) {
        dw::log::error("certificate not sealed: {}", sealed.error().describe());
        return c;
    }
    if (auto w = dw::write_certificate(*sealed, paths.json); !w) {
        dw::log::error("certificate not written: {}", w.error().describe());
        return c;
    }
    c.written = true;
    c.cert_failed = false;
    c.terminal_hash = sealed->find("tecc")->find("terminal_hash")->as_string().value();
    if (key) c.key_id = dw::ed25519::key_id(key->public_key());
    if (auto w = dw::write_new_file(paths.pdf, dw::render_certificate_pdf(*sealed, basename_of(paths.json))); !w)
        dw::log::warn("PDF certificate not written: {} (the JSON certificate is the signed record)",
                      w.error().describe());
    else
        c.pdf_written = true;
    return c;
}

void print_verification(const dw::VerificationResult& v) {
    using S = dw::VerificationResult::Status;
    std::string word(dw::to_string(v.status));
    for (auto& ch : word) ch = static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
    std::cout << std::format("Verification      {}: {}\n", word, v.reason);
    if (v.status == S::NotApplicable || v.status == S::Skipped) return;
    if (v.sectors_sampled) {
        const dw::Json* name = v.sampler.find("name");
        const std::string sampler = name && name->is_string() ? name->as_string().value() : "?";
        std::cout << std::format("                  {} {} unit(s), {} of {} sectors read ({:.3f}%), {}, {:.2f}s\n",
                                 sampler, v.units_sampled, v.sectors_sampled, v.sectors_in_range, v.coverage_percent,
                                 v.read_mode, v.seconds);
        if (const dw::Json* hr = v.sampler.find("clusters_sampled_high_risk"))
            std::cout << std::format("                  {} of those in the high-risk region ({} high-risk clusters "
                                     "of {})\n",
                                     hr->as_u64().value(), v.sampler.find("clusters_high_risk")->as_u64().value(),
                                     v.sampler.find("clusters_total")->as_u64().value());
        if (v.detectable_fraction > 0)
            std::cout << std::format("                  a sample this size finds >= {:.3f}% left unwritten with 99% "
                                     "confidence\n",
                                     100 * v.detectable_fraction);
    }
    if (v.sci.defined)
        std::cout << std::format("SCI               {:.2f} / 100  (baseline {}/{} passed, high-risk {}/{}, lambda {:g})\n",
                                 v.sci.sci, v.sci_input.baseline_pass, v.sci_input.baseline_total,
                                 v.sci_input.high_pass, v.sci_input.high_total, v.sci_input.lambda);
    auto list = [](const std::vector<std::uint64_t>& s) {
        std::string out;
        for (auto x : s) out += (out.empty() ? "" : ", ") + std::to_string(x);
        return out;
    };
    if (!v.mismatched.empty()) std::cout << "                  mismatched sectors: " << list(v.mismatched) << "\n";
    if (!v.unreadable.empty()) std::cout << "                  unreadable sectors: " << list(v.unreadable) << "\n";
    if (v.units_repaired) std::cout << "                  re-wiped and then verified: " << v.units_repaired << " unit(s)\n";
    if (!v.not_verified.empty())
        std::cout << "                  NOT VERIFIED sectors: " << list(v.not_verified)
                  << (v.sectors_not_verified > v.not_verified.size() ? ", ..." : "") << "\n";
}

int report(const Args& a, const dw::DeviceProfile& profile, const dw::WipePlan& plan, const dw::PlanRunResult& result,
           const dw::OverwriteEngine* engine, const dw::RunJournal* journal, const Completion& done) {
    int code = result.success ? 0 : result.aborted ? 7 : 6;
    if (code == 0 && done.interrupted) code = 7;
    else if (code == 0 && done.verification.status == dw::VerificationResult::Status::Failed) code = 8;
    else if (code == 0 && done.cert_failed) code = 5;
    if (a.json) {
        dw::Json j = dw::Json::object();
        j["device"] = dw::to_json(profile);
        j["plan"] = dw::to_json(plan);
        j["result"] = dw::to_json(result);
        if (engine) j["result"]["pattern_key_fingerprint"] = dw::key_fingerprint(engine->key());
        if (journal && !result.success) j["result"]["journal"] = journal->path();
        j["verification"] = dw::to_json(done.verification);
        if (done.written) {
            j["certificate"]["path"] = done.paths.json;
            if (done.pdf_written) j["certificate"]["pdf"] = done.paths.pdf;
            j["certificate"]["session_log"] = done.paths.log;
            j["certificate"]["outcome"] = done.outcome;
            j["certificate"]["terminal_hash"] = done.terminal_hash;
            if (!done.key_id.empty()) j["certificate"]["signed_by_key"] = done.key_id;
            else j["certificate"]["signed_by_key"] = nullptr;
        }
        std::cout << j.dump(2) << "\n";
        return code;
    }
    std::cout << "\nSummary\n";
    for (std::size_t i = 0; i < result.steps.size(); ++i) {
        const auto& s = result.steps[i];
        const bool earlier = !s.log.empty() && s.log.front().starts_with("completed by an earlier");
        std::cout << std::format("  Step {} {:<11} {}", i + 1, status_word(s.status),
                                 earlier ? "(earlier run)" : std::format("{:.2f}s", s.seconds));
        if (s.bytes_written && s.seconds > 0)
            std::cout << std::format("  {} bytes written, {:.1f} MiB/s", s.bytes_written,
                                     double(s.bytes_written) / s.seconds / (1024.0 * 1024.0));
        std::cout << "  " << s.title << "\n";
        if (!s.error.empty()) std::cout << "         " << s.error << "\n";
    }
    if (engine) std::cout << "Pattern key       sha256 fingerprint " << dw::key_fingerprint(engine->key()) << "\n";
    std::cout << "Result            " << (result.success ? "SUCCESS" : result.aborted ? "INTERRUPTED" : "FAILED")
              << ", achieved " << dw::to_string(result.achieved)
              << (plan.fully_simulated() ? " (SIMULATED: medium unchanged)" : "") << "\n";
    const auto& v = done.verification;
    if (result.success) print_verification(v);
    if (done.written) {
        std::cout << "Certificate       " << done.paths.json << (done.pdf_written ? "  (+ " + done.paths.pdf + ")" : "")
                  << "\n"
                  << "                  outcome " << done.outcome << "\n"
                  << "TECC              terminal hash " << done.terminal_hash << "\n"
                  << "                  session log " << done.paths.log << "\n"
                  << "                  "
                  << (done.key_id.empty() ? "UNSIGNED (no --sign-key): integrity only, origin not provable"
                                          : "signed with Ed25519 key " + done.key_id)
                  << "\n";
    }
    if (journal && done.interrupted)
        std::cout << "Resume            the wipe itself is complete; the same command plus --resume repeats only the "
                  << "verification and issues the certificate\n";
    if (journal && result.aborted)
        std::cout << "Resume            progress saved in " << journal->path() << "; continue with the same "
                  << "command plus --resume (or --restart to begin again)\n";
    else if (journal && !result.success)
        std::cout << "Journal           kept at " << journal->path() << " (fix the cause, then --resume or --restart)\n";
    return code;
}

// The physical-disk gate, shared by every command that changes a real drive. Refusals that
// need no human come first, so nobody is asked to type a serial number for a disk that would be
// refused anyway. Releases the read-only handle: the writable reopen claims the device exclusively.
std::variant<dw::PhysicalOverride, int> physical_gate(const Args& a, Probed& probed) {
    if (!dw::is_hardware_identity(probed.profile.identity_source) || !probed.target) {
#ifdef _WIN32
        dw::log::error("REFUSED {}: the disk could not be opened for reading (run from an Administrator terminal); "
                       "its descriptor alone is not enough to act on it",
#else
        dw::log::error("REFUSED {}: the drive could not be identified with its own commands (run as root); "
                       "sysfs detection is not enough to act on it",
#endif
                       probed.profile.path);
        return 2;
    }
    const auto& assessment = probed.target->assessment;
    if (!assessment.in_use.empty()) {
#ifdef _WIN32
        dw::log::error("REFUSED {}: in use ({}); {}", assessment.canonical_path, assessment.in_use.front(),
                       dw::win::offline_hint(static_cast<unsigned>(assessment.rdev)));
        return 2;
#endif
        dw::log::error("REFUSED {}: in use ({}); unmount it, deactivate swap and stacked devices first",
                       assessment.canonical_path, assessment.in_use.front());
        return 2;
    }
    auto ov = dw::confirm_physical_target(assessment, a.destructive, probed.profile.identity.serial,
                                          dw::ConfirmIO{std::cin, std::cerr, ::isatty(STDIN_FILENO) != 0});
    if (!ov) {
        dw::log::error("{}", ov.error().describe());
        return 2;
    }
    probed.target.reset();
    return *ov;
}

// Recovery for a drive left with an ATA user password by an interrupted SECURITY ERASE (it
// locks at the next power-up): SECURITY UNLOCK if locked, then SECURITY DISABLE PASSWORD, with
// datawipe's documented temporary password unless --password names another.
int cmd_ata_unlock(const Args& a) {
    auto r = probe_target(a, false);
    if (auto* code = std::get_if<int>(&r)) return *code;
    auto& probed = std::get<Probed>(r);
    const dw::AtaIdentity& id = probed.profile.identity;
    if (probed.profile.identity_source != dw::IdentitySource::AtaIdentify) {
        dw::log::error("ata-unlock is for SATA drives identified with ATA IDENTIFY (run as root)");
        return 4;
    }
    std::cout << std::format("Security          supported={} enabled={} locked={} frozen={}\n", id.security_supported,
                             id.security_enabled, id.security_locked, id.security_frozen);
    if (!id.security_enabled) {
        std::cout << "No ATA password is set: nothing to do.\n";
        return 0;
    }
    if (id.security_frozen) {
        dw::log::error("security is FROZEN: the drive refuses security commands until it is power-cycled or "
                       "hot-plugged (suspend/resume the machine, or re-plug the drive), then try again");
        return 2;
    }
    auto g = physical_gate(a, probed);
    if (auto* code = std::get_if<int>(&g)) return *code;
    const auto override = std::get<dw::PhysicalOverride>(g);
    auto rw = reopen_physical(a, override);
    if (auto* code = std::get_if<int>(&rw)) return *code;
    auto& target = std::get<Probed>(rw);

    const std::string password = a.ata_password.value_or(dw::ata::kTempPassword);
    std::vector<dw::DeviceCommand> cmds;
    if (target.profile.identity.security_locked) cmds.push_back(dw::ata::security_unlock(password));
    cmds.push_back(dw::ata::security_disable_password(password));
    dw::PassthroughOptions opts;
    opts.experimental = a.experimental;
    auto ex = dw::make_command_executor(target.profile, *target.target->device, opts);
    if (auto p = ex->preflight(cmds); !p) {
        dw::log::error("{}", p.error().describe());
        return 5;
    }
    for (const auto& c : cmds) {
        auto res = ex->issue(c);
        if (!res) {
            dw::log::error("{} failed: {} (a wrong password counts toward the drive's limit of 5 attempts per "
                           "power cycle)",
                           c.name, res.error().describe());
            return 6;
        }
        std::cout << c.name << ": " << res->detail << "\n";
    }
    std::cout << "The ATA password is removed; the drive is usable again.\n";
    return 0;
}

// Real drive with an HPA/DCO: stage 1 of 2. Remove the hidden area, then stop. The kernel still
// believes the disk has its old size until it re-reads the capacity (a rescan, or a reboot /
// re-plug on drives and drivers that ignore the rescan), so no overwrite may run in this
// process. The next run sees a plain disk of full native size and wipes all of it. The
// removal is recorded in its own session log.
int run_hidden_area_stage(const Args& a, Probed& target, const dw::WipePlan& plan, const dw::ed25519::PrivateKey*) {
    if (a.resume) {
        dw::log::error("--resume: hidden-area removal is a separate first run; run without --resume");
        return 1;
    }
    const dw::WipeStep& step = plan.steps.front();
    const auto paths = a.cert ? dw::certificate_paths(*a.cert) : dw::certificate_paths(target.profile);
    auto chain = dw::tecc::SessionChain::create(paths.log, dw::random_uuid());
    if (!chain) {
        dw::log::error("cannot create the session log: {}", chain.error().describe());
        return 5;
    }
    if (!chain_append(*chain, nullptr, "detection", dw::to_json(target.profile)) ||
        !chain_append(*chain, nullptr, "plan", plan_entry(plan, nullptr)))
        return 5;

    dw::PassthroughOptions pt_opts;
    pt_opts.experimental = a.experimental;
    auto executor = dw::make_command_executor(target.profile, *target.target->device, pt_opts);
    if (auto r = executor->preflight(step.commands); !r) {
        dw::log::error("{}", r.error().describe());
        return 5;
    }
    if (!a.json) std::cerr << "\n== Stage 1 of 2: " << step.title << "\n";
    dw::Json log = dw::Json::array();
    for (const auto& cmd : step.commands) {
        auto r = executor->issue(cmd);
        dw::Json e = dw::Json::object();
        e["command"] = cmd.describe();
        e["result"] = r ? r->detail : "FAILED: " + r.error().describe();
        log.push_back(std::move(e));
        if (!r) {
            chain_append(*chain, nullptr, "hidden-area-removal", std::move(log));
            dw::log::error("{} failed: {}", cmd.name, r.error().describe());
            return 6;
        }
        std::cerr << "  " << cmd.name << ": " << r->detail << "\n";
    }

    const std::string name = std::filesystem::path(target.profile.path).filename().string();
    const std::uint64_t want = target.profile.medium_sectors() * target.profile.geometry.logical_sector_size;
    target.target.reset();  // release the device before the kernel re-reads it
    if (auto r = dw::sysfs::rescan_disk(name); !r) dw::log::warn("capacity rescan: {}", r.error().describe());
    ::sleep(2);
    std::uint64_t now = 0;
    if (auto t = dw::open_target(target.profile.path, dw::OpenOptions{.writable = false, .direct_io = false}))
        now = t->device->geometry().size_bytes;
    dw::Json done = dw::Json::object();
    done["commands"] = std::move(log);
    done["native_bytes"] = want;
    done["kernel_bytes_after_rescan"] = now;
    chain_append(*chain, nullptr, "hidden-area-removal", std::move(done));

    std::cout << "\nHidden area removed (" << target.profile.hidden_sectors() << " sectors, non-volatile).\n";
    if (now == want)
        std::cout << "The kernel now sees the full " << want << " bytes. Run the same command again (without\n"
                  << "--resume) to wipe the whole native capacity.\n";
    else
        std::cout << "The kernel still reports " << now << " bytes instead of " << want << ": reboot or re-plug\n"
                  << "the drive, then run the same command again to wipe the whole native capacity.\n";
    std::cout << "Session log       " << paths.log << "\n";
    return 10;
}

int cmd_run(const Args& a) {
    // Select the plan from a read-only probe first; only reopen writable if the plan writes.
    auto r = probe_target(a, false);
    if (auto* code = std::get_if<int>(&r)) return *code;
    auto& probed = std::get<Probed>(r);
    auto plan = make_plan(a, probed.profile);
    if (!plan) return 3;
    if (!a.json && !a.brief) print_plan(*plan);

    // ---- Physical disk: the gate. Refusals that need no human come first, so nobody is asked
    // to type a serial number for a disk that would be refused anyway.
    std::optional<dw::PhysicalOverride> override;
    if (probed.profile.backend == dw::BackendKind::PhysicalBlock) {
        auto g = physical_gate(a, probed);
        if (auto* code = std::get_if<int>(&g)) return *code;
        override.emplace(std::get<dw::PhysicalOverride>(g));
    }

    auto signing = load_signing_key(a);
    if (auto* code = std::get_if<int>(&signing)) return *code;
    const auto& key_opt = std::get<std::optional<dw::ed25519::PrivateKey>>(signing);
    const dw::ed25519::PrivateKey* sign_key = key_opt ? &*key_opt : nullptr;

    if (plan->fully_simulated()) {
        if (a.resume || a.restart) dw::log::warn("--resume/--restart ignored: this plan writes nothing to the medium");
        const auto paths = a.cert ? dw::certificate_paths(*a.cert) : dw::certificate_paths(probed.profile);
        auto chain = dw::tecc::SessionChain::create(paths.log, dw::random_uuid());
        if (!chain) {
            dw::log::error("cannot create the session log: {}", chain.error().describe());
            return 5;
        }
        if (!chain_append(*chain, nullptr, "detection", dw::to_json(probed.profile)) ||
            !chain_append(*chain, nullptr, "plan", plan_entry(*plan, nullptr)))
            return 5;
        auto executor = dw::make_command_executor(probed.profile, *probed.target->device);
        auto result = dw::execute_plan(*plan, *executor, probed.target ? probed.target->device.get() : nullptr, nullptr);
        if (!result) {
            dw::log::error("{}", result.error().describe());
            return 5;
        }
        if (!chain_append(*chain, nullptr, result->success ? "execution" : "failed", dw::to_json(*result))) return 5;
        const auto done = verify_and_certify(a, probed.profile, *plan, *result, nullptr, nullptr, *chain, sign_key, paths,
                                             nullptr);
        return report(a, probed.profile, *plan, *result, nullptr, nullptr, done);
    }

    // ---- Journal: decide between fresh start, resume and restart before anything is written.
    std::string journal_path;
    if (a.journal) journal_path = *a.journal;
    else if (auto d = dw::RunJournal::default_path(probed.profile)) journal_path = *d;
    else {
        dw::log::error("{}", d.error().describe());
        return 2;
    }
    dw::RunJournal journal(journal_path);
    auto existing = journal.load();
    if (!existing && !a.restart) {
        dw::log::error("{} (inspect it, then use --restart to discard it)", existing.error().describe());
        return 2;
    }
    const bool have_journal = existing && existing->has_value();

    dw::JournalRecord record;
    dw::ResumePoint resume;
    if (a.resume) {
        if (!have_journal) {
            dw::log::error("--resume: no interrupted wipe recorded at {}", journal_path);
            return 2;
        }
        record = **existing;
        if (auto m = dw::check_journal_matches(record, probed.profile, *plan); !m) {
            dw::log::error("{} ({})", m.error().describe(), journal_path);
            return 2;
        }
        resume = record.position;
        record.target = probed.profile.path;
        ++record.runs;
        if (resume.step < plan->steps.size() && plan->steps[resume.step].overwrite && resume.sectors_done)
            record.resumes.emplace_back(resume.step,
                                        plan->steps[resume.step].overwrite->first_sector + resume.sectors_done);
        if (resume.step == plan->steps.size())
            dw::log::info("the wipe started {} is complete; repeating only its verification (run {})",
                          record.started_at, record.runs);
        else
            dw::log::info("resuming the wipe started {} (run {}): step {}, {} sectors of its pass durable",
                          record.started_at, record.runs, resume.step + 1, resume.sectors_done);
        // Step back before continuing. "Durable" means fdatasync succeeded, but some USB bridges
        // hide the drive's write cache from the kernel ("No Caching mode page found"), which
        // then never sends the drive a cache flush: the last writes before a power loss may not
        // be on the medium. The pattern is position-derived, so rewriting is exact.
        const std::uint64_t margin = 2 * a.overwrite.sync_interval_bytes / probed.profile.geometry.logical_sector_size;
        if (const std::uint64_t back = std::min(resume.sectors_done, margin)) {
            resume.sectors_done -= back;
            dw::log::info("rewriting the last {} MiB before that point as a safety margin",
                          back * probed.profile.geometry.logical_sector_size >> 20);
        }
    } else {
        if (have_journal && !a.restart) {
            const auto& e = **existing;
            dw::log::error("an interrupted wipe of {} is recorded in {} (started {}, at step {}, {} sectors into its "
                           "pass). Continue it with --resume, or discard it with --restart.",
                           e.medium, journal_path, e.started_at, e.position.step + 1, e.position.sectors_done);
            return 2;
        }
        if (a.restart && (have_journal || !existing)) {
            if (auto rm = journal.remove(); !rm) {
                dw::log::error("{}", rm.error().describe());
                return 5;
            }
            dw::log::warn("discarded journal {}; starting over", journal_path);
        }
        auto key = dw::random_pattern_key();
        if (!key) {
            dw::log::error("{}", key.error().describe());
            return 5;
        }
        record = dw::JournalRecord::start(probed.profile, *plan, *key);
    }

    // ---- Reopen writable. The guard runs again, and the plan must come out identical: if the
    // target changed between the read-only probe and now, stop.
    auto rw = override ? reopen_physical(a, *override) : probe_target(a, true);
    if (auto* code = std::get_if<int>(&rw)) return *code;
    auto& target = std::get<Probed>(rw);
    auto plan_rw = make_plan(a, target.profile);
    if (!plan_rw) return 3;
    if (dw::plan_digest(*plan_rw) != dw::plan_digest(*plan)) {
        dw::log::error("REFUSED: {} changed between the read-only probe and the writable open", a.target);
        return 2;
    }
    dw::IBlockDevice& device = *target.target->device;
    if (override && !plan->steps.empty() && plan->steps.front().level == dw::SanitizationLevel::None &&
        !plan->steps.front().commands.empty())
        return run_hidden_area_stage(a, target, *plan, sign_key);
    if (a.overwrite.buffer_bytes < dw::OverwriteEngine::io_alignment(device)) {
        dw::log::error("--buffer-size must be at least {} bytes for this target{}",
                       dw::OverwriteEngine::io_alignment(device), a.direct ? " with --direct" : "");
        return 1;
    }

    // ---- TECC session: a new chain, or the interrupted one, re-verified in full. Created only
    // now, after every refusal, so a refused run leaves no log behind.
    dw::CertificatePaths paths;
    std::optional<dw::tecc::SessionChain> chain;
    if (a.resume) {
        auto last = dw::tecc::hash_from_hex(record.chain_last);
        auto c = last ? dw::tecc::SessionChain::resume(record.log_path, record.chain_entries, *last)
                      : dw::Result<dw::tecc::SessionChain>(dw::error("journal: bad chain_last: " + last.error().message));
        if (!c) {
            dw::log::error("REFUSED: {}", c.error().describe());
            return 2;
        }
        chain = std::move(c).value();
        paths = dw::certificate_paths(a.cert ? *a.cert : record.cert_path);
        paths.log = record.log_path;
        dw::Json entry = dw::Json::object();
        entry["run"] = record.runs;
        entry["resume_step"] = resume.step + 1;
        entry["resume_sectors_done"] = resume.sectors_done;
        entry["detection"] = dw::to_json(target.profile);
        if (!chain_append(*chain, nullptr, "resume", std::move(entry))) return 5;
    } else {
        paths = a.cert ? dw::certificate_paths(*a.cert) : dw::certificate_paths(target.profile);
        auto c = dw::tecc::SessionChain::create(paths.log, dw::random_uuid());
        if (!c) {
            dw::log::error("cannot create the session log: {}", c.error().describe());
            return 5;
        }
        chain = std::move(c).value();
        if (!chain_append(*chain, nullptr, "detection", dw::to_json(target.profile)) ||
            !chain_append(*chain, nullptr, "plan", plan_entry(*plan, &record.key)))
            return 5;
        record.session_id = chain->session_id();
        record.log_path = paths.log;
        record.cert_path = paths.json;
    }
    dw::CancelToken cancel;
    dw::install_cancel_signal_handlers(cancel);

    // ---- Pre-wipe fingerprints, for plans whose final content is a device-internal erase.
    std::optional<dw::FingerprintSet> fingerprints;
    if (plan->verification.kind == dw::VerificationExpectation::Kind::Fingerprint) {
        if (a.resume) {
            auto fp = dw::load_fingerprints(record.fingerprint_path);
            if (!fp) {
                dw::log::error("REFUSED: cannot reuse the pre-wipe fingerprints: {}", fp.error().describe());
                return 2;
            }
            fingerprints = std::move(fp).value();
        } else {
            const dw::OverwriteSpec& range = *plan->verification.expected;
            const auto ctx = dw::make_risk_context(target.profile, *plan,
                                                   {range.first_sector, range.first_sector + range.sector_count}, {});
            auto sampler = make_sampler(a, ctx, dw::default_pairwise());
            auto reader = open_for_verify(target.profile.path);
            if (!sampler || !reader) {
                dw::log::error("cannot take pre-wipe fingerprints: {}",
                               (!sampler ? sampler.error() : reader.error()).describe());
                return 5;
            }
            if (!a.json) std::cerr << "\n== Pre-wipe fingerprints: hashing the sectors verification will re-read\n";
            const auto units = (*sampler)->sample({range.first_sector, range.sector_count});
            auto fp = dw::capture_fingerprints(*reader->device, units, (*sampler)->describe(), &cancel,
                                               PhaseProgress("fingerprints", a.json));
            if (!fp) {
                dw::log::error("{}{}", fp.error().describe(), cancel.requested() ? "; nothing on the drive was changed" : "");
                return cancel.requested() ? 7 : 5;
            }
            record.fingerprint_path = dw::session_file_base(target.profile) + ".dwfp";
            if (auto w = dw::save_fingerprints(*fp, record.fingerprint_path); !w) {
                dw::log::error("{}", w.error().describe());
                return 5;
            }
            std::uint64_t constant = 0;
            for (auto c : fp->constant) constant += c;
            dw::Json e = dw::Json::object();
            e["file"] = basename_of(record.fingerprint_path);
            e["units"] = fp->units.size();
            e["sectors"] = fp->sector_total();
            e["uninformative_sectors"] = constant;
            e["sampler"] = fp->sampler;
            if (!chain_append(*chain, nullptr, "fingerprints", std::move(e))) return 5;
            fingerprints = std::move(fp).value();
        }
    }

    record.chain_entries = chain->count();
    record.chain_last = dw::tecc::hex(chain->last());

    if (auto b = journal.begin(record); !b) {
        dw::log::error("cannot write journal {}: {}; refusing to start an unrecoverable wipe", journal_path,
                       b.error().describe());
        return 5;
    }
    dw::OverwriteEngine engine(record.key, a.overwrite);
    ProgressPrinter printer(plan->steps.size());
    dw::PassthroughOptions pt_opts;
    pt_opts.experimental = a.experimental;
    auto executor = dw::make_command_executor(target.profile, device, pt_opts);
    dw::ExecutionOptions opts{&engine, a.json ? nullptr : &printer, &cancel, &journal, resume};
    auto result = dw::execute_plan(*plan, *executor, &device, opts);
    if (!result) {
        dw::log::error("{}", result.error().describe());
        return 5;
    }
    // A resume of a run whose steps had all finished (only verification was pending) executes
    // nothing: its "execution" entry is already in the chain.
    const bool verify_only = a.resume && resume.step == plan->steps.size();
    const char* stage = result->success ? "execution" : result->aborted ? "interrupted" : "failed";
    if (!verify_only && !chain_append(*chain, &journal, stage, dw::to_json(*result))) return 5;
    // Read back through a separate read-only handle, not the one that did the writing.
    const auto done = verify_and_certify(a, target.profile, *plan, *result, &journal.record(), &device, *chain, sign_key,
                                         paths, fingerprints ? &*fingerprints : nullptr, &cancel);
    // The journal holds the pattern key, without which nothing can be verified or certified:
    // it goes only once the certificate (which carries the key) is safely written.
    if (result->success && done.written) {
        if (auto rm = journal.remove(); !rm) dw::log::warn("certificate written but {}", rm.error().describe());
        // The pre-wipe fingerprints (9 bytes per sampled sector: hundreds of MB on a large
        // drive) have served their purpose once the verified certificate exists.
        const std::string& fp = journal.record().fingerprint_path;
        if (!fp.empty() && ::unlink(fp.c_str()) != 0 && errno != ENOENT)
            dw::log::warn("could not remove {}: {}", fp, std::strerror(errno));
    }
    return report(a, target.profile, *plan, *result, &engine, &journal, done);
}

// A certificate from its JSON file, or from the JSON attached to a PDF issued by datawipe.
std::variant<dw::Json, int> read_certificate_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        dw::log::error("cannot open {}", path);
        return 5;
    }
    std::stringstream ss;
    ss << in.rdbuf();
    std::string text = ss.str();
    if (text.starts_with("%PDF")) {
        constexpr std::string_view kMark = "/Subtype /application#2Fjson /Length ";
        const auto m = text.find(kMark);
        const auto st = m == std::string::npos ? m : text.find("stream\n", m);
        if (st == std::string::npos) {
            dw::log::error("{}: no attached certificate (not a PDF issued by datawipe)", path);
            return 5;
        }
        const std::size_t len = std::strtoull(text.c_str() + m + kMark.size(), nullptr, 10);
        if (st + 7 + len > text.size()) {
            dw::log::error("{}: truncated attachment", path);
            return 5;
        }
        text = text.substr(st + 7, len);
    }
    auto cert = dw::Json::parse(text);
    if (!cert) {
        dw::log::error("{}: {}", path, cert.error().describe());
        return 5;
    }
    return std::move(cert).value();
}

std::variant<std::optional<dw::ed25519::PublicKey>, int> trusted_key(const Args& a) {
    if (!a.pubkey) return std::optional<dw::ed25519::PublicKey>();
    auto k = dw::ed25519::load_public_key(*a.pubkey);
    if (!k) {
        dw::log::error("{}", k.error().describe());
        return 5;
    }
    return std::optional<dw::ed25519::PublicKey>(*k);
}

// Parse, then check the TECC seal (and the signer, with --pubkey). Exit code on failure.
std::variant<dw::Json, int> load_certificate(const Args& a, const std::string& path) {
    auto cert = read_certificate_file(path);
    if (auto* code = std::get_if<int>(&cert)) return *code;
    auto trusted = trusted_key(a);
    if (auto* code = std::get_if<int>(&trusted)) return *code;
    if (auto r = dw::check_certificate(std::get<dw::Json>(cert), std::get<std::optional<dw::ed25519::PublicKey>>(trusted));
        !r) {
        dw::log::error("{}: {}", path, r.error().describe());
        return 8;
    }
    return std::move(std::get<dw::Json>(cert));
}

// Auditor's check (paper Section III-D): certificate + published public key + session log.
int cmd_verify_cert(const Args& a) {
    auto loaded = read_certificate_file(a.target);
    if (auto* code = std::get_if<int>(&loaded)) return *code;
    const dw::Json& cert = std::get<dw::Json>(loaded);
    auto trusted = trusted_key(a);
    if (auto* code = std::get_if<int>(&trusted)) return *code;
    auto check = dw::check_certificate(cert, std::get<std::optional<dw::ed25519::PublicKey>>(trusted));
    if (!check) {
        dw::log::error("{}: {}", a.target, check.error().describe());
        return 8;
    }
    const dw::Json* outcome = cert.find("outcome");
    std::cout << "Certificate       " << a.target << "\n"
              << "Outcome           " << (outcome && outcome->is_string() ? outcome->as_string().value() : "?") << "\n"
              << "TECC seal         intact: body hashes to terminal hash " << check->terminal_hash << " (entry "
              << check->entries << " of session " << check->session_id << ")\n";
    if (!check->signed_by)
        std::cout << "Signature         NONE: this certificate is unsigned; it proves integrity, not who issued it\n";
    else if (check->trusted)
        std::cout << "Signature         VALID, by the trusted key " << check->key_id << "\n";
    else
        std::cout << "Signature         valid for the key it names (" << check->key_id
                  << "), but that key was NOT checked against a trusted one: pass --pubkey <issuer's published key>\n";

    std::string log_path;
    if (a.log) log_path = *a.log;
    else if (const dw::Json* lf = cert.find("tecc")->find("log_file"); lf && lf->is_string())
        log_path = dirname_of(a.target) + "/" + lf->as_string().value();
    if (log_path.empty() || (!a.log && !std::ifstream(log_path))) {
        std::cout << "Session log       not found" << (log_path.empty() ? "" : " (" + log_path + ")")
                  << ": the history before the certificate was not audited (pass --log)\n";
        return 0;
    }
    auto log = dw::tecc::read_and_verify_log(log_path);
    if (!log) {
        dw::log::error("{}", log.error().describe());
        return 8;
    }
    if (auto r = dw::audit_session_log(cert, *log); !r) {
        dw::log::error("{}: {}", log_path, r.error().describe());
        return 8;
    }
    std::string stages;
    for (const auto& e : log->entries) stages += (stages.empty() ? "" : " -> ") + e.stage;
    std::cout << "Session log       " << log_path << ": all " << log->entries.size()
              << " entries recomputed and chained to the certificate\n"
              << "                  " << stages << "\n";
    return 0;
}

// New organisation signing key pair (paper Section VI: publish the public key; guard the
// private one).
int cmd_keygen(const Args& a) {
    const std::string priv = a.target + ".key.pem", pub = a.target + ".pub.pem";
    std::string pass;
    if (!a.no_passphrase) {
        pass = ask_passphrase("New passphrase for " + priv + ": ");
        if (!std::getenv("DATAWIPE_KEY_PASSPHRASE") && ask_passphrase("Repeat it: ") != pass) {
            dw::log::error("passphrases differ");
            return 1;
        }
        if (pass.size() < 12) {
            dw::log::error("passphrase must be at least 12 characters (or use --no-passphrase to store the key "
                           "unencrypted, e.g. inside an HSM-backed or offline environment)");
            return 1;
        }
    }
    auto key = dw::ed25519::PrivateKey::generate();
    if (!key) {
        dw::log::error("{}", key.error().describe());
        return 5;
    }
    if (auto r = key->save(priv, pass); !r) {
        dw::log::error("{}", r.error().describe());
        return 5;
    }
    if (auto r = dw::ed25519::save_public_key(key->public_key(), pub); !r) {
        dw::log::error("{}", r.error().describe());
        return 5;
    }
    std::cout << "Key id            " << dw::ed25519::key_id(key->public_key()) << "\n"
              << "Private key       " << priv << (pass.empty() ? "  (UNENCRYPTED)" : "  (AES-256 encrypted)")
              
#ifdef _WIN32
              << ": keep it offline or in an HSM, in a folder only you can read; anyone holding it can issue certificates\n"
#else
              << ", mode 0600: keep it offline or in an HSM; anyone holding it can issue certificates\n"
#endif

              << "Public key        " << pub << ": publish it where auditors can fetch it through a channel they "
              << "trust\n";
    return 0;
}

// Re-read a certified medium: same verifier as `run`, with a fresh random sample, the pattern
// key and range taken from the (integrity-checked) certificate.
int cmd_verify(const Args& a) {
    if (!a.cert) {
        dw::log::error("verify needs --cert <certificate.json> (written by `datawipe run`)");
        return 1;
    }
    auto loaded = load_certificate(a, *a.cert);
    if (auto* code = std::get_if<int>(&loaded)) return *code;
    auto content = dw::certified_content(std::get<dw::Json>(loaded));
    if (!content) {
        dw::log::error("{}: {}", *a.cert, content.error().describe());
        return 4;
    }

    auto assessed = dw::assess_target(a.target);
    if (!assessed) {
        dw::log::error("{}", assessed.error().describe());
        return 2;
    }
    if (assessed->kind == dw::BackendKind::PhysicalBlock) {
        // A physical disk is matched by serial number, not by /dev name.
        const dw::Json* serial = std::get<dw::Json>(loaded).find("device");
        serial = serial && serial->find("identity") ? serial->find("identity")->find("serial") : nullptr;
        auto det = dw::detect_physical(*assessed);
        if (!det || !serial || !serial->is_string() || det->identity.serial != serial->as_string().value()) {
            dw::log::error("REFUSED: {} is not the drive the certificate describes (serial '{}' vs '{}')", a.target,
                           det ? det->identity.serial : std::string("?"),
                           serial && serial->is_string() ? serial->as_string().value() : std::string("?"));
            return 2;
        }
    }
    auto opened = open_for_verify(a.target);
    if (!opened) {
        dw::log::error("{}", opened.error().describe());
        return 2;
    }
    dw::IBlockDevice& dev = *opened->device;
    const auto& g = dev.geometry();
    if (g.size_bytes != content->size_bytes || g.logical_sector_size != content->logical_sector_size) {
        dw::log::error("REFUSED: {} is {} bytes in {}B sectors, but the certificate describes {} bytes in {}B sectors; "
                       "it is not the medium that was wiped",
                       a.target, g.size_bytes, g.logical_sector_size, content->size_bytes,
                       content->logical_sector_size);
        return 2;
    }
    const std::string& here = opened->assessment.backing_file.empty() ? opened->assessment.canonical_path
                                                                      : opened->assessment.backing_file;
    if (here != content->medium)
        dw::log::warn("{} is backed by {}, but the certificate was issued for {} (copied or moved?); checking "
                      "its contents anyway",
                      a.target, here, content->medium);

    dw::VerificationExpectation expect;
    expect.kind = dw::VerificationExpectation::Kind::Pattern;
    expect.expected = content->expected;
    // ARVS with the risk context and judgments the certificate recorded; a fresh seed.
    Args opts = a;
    dw::RiskContext ctx;
    if (content->risk) ctx = *content->risk;
    else if (opts.sampler == "arvs") {
        dw::log::warn("the certificate records no ARVS risk context; verifying with the uniform sampler");
        opts.sampler = "uniform";
    }
    auto sampler = make_sampler(opts, ctx, content->judgments.value_or(dw::default_pairwise()));
    if (!sampler) {
        dw::log::error("{}", sampler.error().describe());
        return 5;
    }
    dw::CancelToken cancel;
    dw::install_cancel_signal_handlers(cancel);
    dw::VerifyConfig cfg;
    cfg.sci_lambda = a.sci_lambda;
    cfg.cancel = &cancel;
    cfg.on_progress = PhaseProgress("verify", a.json);
    const auto v = dw::verify_readback(expect, dev, content->key, **sampler, cfg);
    if (v.status == dw::VerificationResult::Status::Interrupted) {
        std::cout << "Verification      INTERRUPTED: " << v.reason << "\n";
        return 7;
    }
    if (a.json) {
        dw::Json j = dw::Json::object();
        j["target"] = a.target;
        j["certificate"] = *a.cert;
        j["verification"] = dw::to_json(v);
        std::cout << j.dump(2) << "\n";
    } else {
        std::cout << "Target            " << a.target << (here != a.target ? " (" + here + ")" : "") << "\n"
                  << "Certificate       " << *a.cert << " (TECC seal intact, outcome " << content->outcome << ")\n"
                  << "Expected          " << content->expected.pattern.describe() << " over sectors ["
                  << content->expected.first_sector << ", "
                  << content->expected.first_sector + content->expected.sector_count << ")\n";
        print_verification(v);
    }
    return v.passed() ? 0 : 8;
}

}  // namespace dwcli

using namespace dwcli;

int main(int argc, char** argv) {
#ifdef _WIN32
    // Colour and the in-place progress line need ANSI processing switched on; without it, say so
    // to the code that would emit colour.
    if (!dw::win::enable_ansi_console()) ::setenv("NO_COLOR", "1", 0);
#endif
    if (argc == 2 && (std::string_view(argv[1]) == "--version" || std::string_view(argv[1]) == "version")) {
        std::cout << "datawipe " << DW_VERSION << "\n";
        return 0;
    }
    auto args = parse_args(argc, argv);
    if (!args) {
        usage();
        return 1;
    }
    if (args->verbose) dw::log::set_level(dw::log::Level::Debug);
    if (args->command == "interactive") return cmd_interactive(*args);
    if (args->command == "probe") return cmd_probe(*args);
    if (args->command == "plan") return cmd_plan(*args);
    if (args->command == "run") return cmd_run(*args);
    if (args->command == "verify-cert") return cmd_verify_cert(*args);
    if (args->command == "verify") return cmd_verify(*args);
    if (args->command == "keygen") return cmd_keygen(*args);
    if (args->command == "ata-unlock") return cmd_ata_unlock(*args);
    std::cerr << "unknown command '" << args->command << "'\n";
    usage();
    return 1;
}
