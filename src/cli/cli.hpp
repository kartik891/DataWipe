#pragma once
// Shared between the command implementations (main.cpp) and the guided mode (interactive.cpp).

#include <cstdint>
#include <optional>
#include <string>
#include <variant>

#include "device/classifier.hpp"
#include "device/device_factory.hpp"
#include "engine/method_selector.hpp"
#include "engine/overwrite_engine.hpp"
#include "engine/wipe_plan.hpp"
#include "verify/sci.hpp"
#include "verify/sector_sampler.hpp"

namespace dwcli {

inline constexpr const char* kDestructiveFlag = "--i-understand-this-is-destructive";

struct Args {
    std::string command;
    std::string target;
    std::optional<std::string> identity;
    bool json = false;
    bool verbose = false;
    bool destructive = false;
    dw::SelectorOptions selector;
    dw::OverwriteConfig overwrite;
    bool direct = false;
    bool resume = false;
    bool restart = false;
    std::optional<std::string> journal;
    bool verify = true;
    std::uint64_t verify_samples = dw::UniformSampler::kDefaultSamples;
    std::string sampler = "arvs";
    double verify_budget = 0.05;
    bool fixed_budget = false;
    double sci_lambda = dw::kDefaultSciLambda;
    unsigned rewipe_attempts = 3;
    std::optional<std::string> cert;
    std::optional<std::string> sign_key;
    std::optional<std::string> pubkey;
    std::optional<std::string> log;
    std::optional<std::string> ata_password;
    bool no_passphrase = false;
    bool experimental = false;
    bool brief = false;  // run: skip the technical plan listing (the guided mode showed its own)
};

struct Probed {
    std::optional<dw::OpenedTarget> target;  // absent for sysfs-only detection of a physical disk
    dw::DeviceProfile profile;
};

// Guard -> open -> identify -> classify. Exit code on failure.
std::variant<Probed, int> probe_target(const Args& a, bool writable);
std::optional<dw::WipePlan> make_plan(const Args& a, const dw::DeviceProfile& p);
void print_profile(const dw::DeviceProfile& p);
void print_plan(const dw::WipePlan& plan);

int cmd_run(const Args& a);
int cmd_verify_cert(const Args& a);
int cmd_keygen(const Args& a);
int cmd_interactive(const Args& a);  // interactive.cpp

}  // namespace dwcli
