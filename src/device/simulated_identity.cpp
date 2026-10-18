#include <fstream>
#include <initializer_list>
#include <sstream>

#include "core/json.hpp"
#include "device/identity_provider.hpp"

namespace dw {

namespace {

constexpr std::string_view kSchema = "datawipe.identity.v1";

// Strict schema: unknown keys are errors, so a typo like "self_encripting" cannot silently
// turn an encrypted-SSD profile into an unencrypted one.
Result<void> only_keys(const Json& obj, std::string_view where, std::initializer_list<std::string_view> allowed) {
    if (!obj.is_object()) return error(std::string(where) + ": expected object");
    for (const auto& [k, v] : obj.members()) {
        bool known = false;
        for (auto a : allowed) known |= (k == a);
        if (!known) return error(std::string(where) + ": unknown key \"" + k + "\"");
    }
    return ok();
}

Result<void> read_bool(const Json& obj, std::string_view key, bool& out) {
    const Json* v = obj.find(key);
    if (!v) return ok();  // optional, default false
    auto b = v->as_bool();
    if (!b) return error(std::string(key) + ": " + b.error().message);
    out = *b;
    return ok();
}

Result<std::string> read_string(const Json& obj, std::string_view key, bool required) {
    const Json* v = obj.find(key);
    if (!v) {
        if (required) return error("missing required key \"" + std::string(key) + "\"");
        return std::string();
    }
    auto s = v->as_string();
    if (!s) return error(std::string(key) + ": " + s.error().message);
    return s;
}

Result<std::uint64_t> read_u64(const Json& obj, std::string_view key) {
    const Json* v = obj.find(key);
    if (!v) return std::uint64_t{0};
    auto n = v->as_u64();
    if (!n) return error(std::string(key) + ": " + n.error().message);
    return n;
}

#define DW_TRY(expr)                        \
    do {                                    \
        if (auto _r = (expr); !_r) return _r.error(); \
    } while (0)

}  // namespace

Result<SimulatedIdentityProvider> SimulatedIdentityProvider::load(const std::string& json_path) {
    std::ifstream in(json_path);
    if (!in) return sys_error("open identity profile " + json_path);
    std::ostringstream ss;
    ss << in.rdbuf();
    return from_json_text(ss.str(), json_path);
}

Result<SimulatedIdentityProvider> SimulatedIdentityProvider::from_json_text(const std::string& text,
                                                                            std::string origin) {
    auto prefix = [&](const Error& e) { return error("identity profile " + origin + ": " + e.message); };

    auto parsed = Json::parse(text);
    if (!parsed) return prefix(parsed.error());
    const Json& root = *parsed;

    if (auto r = only_keys(root, "root", {"schema", "description", "transport", "model", "serial", "firmware",
                                          "rotation_rate", "capacity", "security", "sanitize", "self_encrypting",
                                          "wear_ratio"});
        !r)
        return prefix(r.error());

    SimulatedIdentityProvider p;
    p.origin_ = std::move(origin);
    AtaIdentity& id = p.base_;

    auto body = [&]() -> Result<void> {
        auto schema = read_string(root, "schema", true);
        if (!schema) return schema.error();
        if (*schema != kSchema) return error("schema must be \"" + std::string(kSchema) + "\", got \"" + *schema + "\"");

        auto transport = read_string(root, "transport", true);
        if (!transport) return transport.error();
        if (*transport == "sata") id.transport = Transport::SATA;
        else if (*transport == "nvme") id.transport = Transport::NVMe;
        else if (*transport == "emmc") id.transport = Transport::eMMC;
        else return error("transport must be sata|nvme|emmc, got \"" + *transport + "\"");

        auto model = read_string(root, "model", true);
        if (!model) return model.error();
        auto serial = read_string(root, "serial", true);
        if (!serial) return serial.error();
        if (serial->empty()) return error("serial must be non-empty");
        auto fw = read_string(root, "firmware", false);
        if (!fw) return fw.error();
        id.model = *model;
        id.serial = *serial;
        id.firmware = *fw;

        auto rpm = read_u64(root, "rotation_rate");
        if (!rpm) return rpm.error();
        if (*rpm > 0xFFFF) return error("rotation_rate must fit in 16 bits (IDENTIFY word 217)");
        id.rotation_rate = static_cast<std::uint16_t>(*rpm);

        DW_TRY(read_bool(root, "self_encrypting", id.self_encrypting));
        if (const Json* w = root.find("wear_ratio")) {
            auto v = w->as_double();
            if (!v) return error("wear_ratio: " + v.error().message);
            if (*v < 0 || *v > 1) return error("wear_ratio must be in [0, 1]");
            id.wear_ratio = *v;
        }

        if (const Json* cap = root.find("capacity")) {
            DW_TRY(only_keys(*cap, "capacity", {"total_sectors", "dco_hidden_sectors", "hpa_hidden_sectors"}));
            if (const Json* total = cap->find("total_sectors"); total && !total->is_string()) {
                auto n = total->as_u64();
                if (!n) return error("capacity.total_sectors: " + n.error().message);
                p.total_ = *n;
            } else if (total && total->as_string().value() != "auto") {
                return error("capacity.total_sectors must be a number or \"auto\"");
            }
            auto dco = read_u64(*cap, "dco_hidden_sectors");
            if (!dco) return dco.error();
            auto hpa = read_u64(*cap, "hpa_hidden_sectors");
            if (!hpa) return hpa.error();
            p.dco_hidden_ = *dco;
            p.hpa_hidden_ = *hpa;
        }

        if (const Json* sec = root.find("security")) {
            DW_TRY(only_keys(*sec, "security", {"supported", "enabled", "locked", "frozen", "enhanced_erase"}));
            DW_TRY(read_bool(*sec, "supported", id.security_supported));
            DW_TRY(read_bool(*sec, "enabled", id.security_enabled));
            DW_TRY(read_bool(*sec, "locked", id.security_locked));
            DW_TRY(read_bool(*sec, "frozen", id.security_frozen));
            DW_TRY(read_bool(*sec, "enhanced_erase", id.enhanced_erase_supported));
            if (!id.security_supported && (id.security_enabled || id.enhanced_erase_supported))
                return error("security: flags set but security.supported is false");
        }

        if (const Json* san = root.find("sanitize")) {
            DW_TRY(only_keys(*san, "sanitize", {"supported", "crypto_scramble", "overwrite", "block_erase"}));
            DW_TRY(read_bool(*san, "supported", id.sanitize_supported));
            DW_TRY(read_bool(*san, "crypto_scramble", id.crypto_scramble_supported));
            DW_TRY(read_bool(*san, "overwrite", id.overwrite_supported));
            DW_TRY(read_bool(*san, "block_erase", id.block_erase_supported));
            if (!id.sanitize_supported &&
                (id.crypto_scramble_supported || id.overwrite_supported || id.block_erase_supported))
                return error("sanitize: operations listed but sanitize.supported is false");
        }

        // Hidden regions imply the corresponding feature set is present.
        id.hpa_supported = p.hpa_hidden_ > 0;
        id.hpa_enabled = p.hpa_hidden_ > 0;
        id.dco_supported = p.dco_hidden_ > 0;
        return ok();
    };

    if (auto r = body(); !r) return prefix(r.error());
    return p;
}

Result<AtaIdentity> SimulatedIdentityProvider::identify(IBlockDevice& device) {
    AtaIdentity id = base_;
    const std::uint64_t total = total_.value_or(device.geometry().sector_count());

    if (dco_hidden_ + hpa_hidden_ >= total)
        return error("identity profile " + origin_ + ": hidden sectors (" + std::to_string(dco_hidden_ + hpa_hidden_) +
                     ") leave no user-addressable space out of " + std::to_string(total));

    // Build the nested limits the way a drive would report them: DCO trims the native max,
    // HPA trims the user-addressable max below that.
    id.dco_max_sectors = id.dco_supported ? total : 0;
    id.native_max_sectors = total - dco_hidden_;
    id.user_addressable_sectors = id.native_max_sectors - hpa_hidden_;
    return id;
}

}  // namespace dw
