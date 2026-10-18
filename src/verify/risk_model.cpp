#include "verify/risk_model.hpp"

#include <algorithm>
#include <cmath>
#include <format>

namespace dw {

std::string_view to_string(EraseMethod m) {
    switch (m) {
        case EraseMethod::HostOverwrite: return "host-overwrite";
        case EraseMethod::AtaSecureErase: return "ata-secure-erase";
        case EraseMethod::AtaSecureEraseEnhanced: return "ata-secure-erase-enhanced";
        case EraseMethod::AtaSanitizeCrypto: return "ata-sanitize-crypto";
        case EraseMethod::AtaSanitizeBlock: return "ata-sanitize-block";
        case EraseMethod::AtaSanitizeOverwrite: return "ata-sanitize-overwrite";
        case EraseMethod::NvmeSanitizeCrypto: return "nvme-sanitize-crypto";
        case EraseMethod::NvmeSanitizeBlock: return "nvme-sanitize-block";
        case EraseMethod::NvmeSanitizeOverwrite: return "nvme-sanitize-overwrite";
        case EraseMethod::NvmeFormatCrypto: return "nvme-format-crypto";
        case EraseMethod::NvmeFormatUserData: return "nvme-format-user-data";
        case EraseMethod::OpalGenKey: return "opal-genkey";
        case EraseMethod::EmmcSanitize: return "emmc-sanitize";
        case EraseMethod::Discard: return "discard";
    }
    return "?";
}

namespace {

std::optional<EraseMethod> classify_command(const DeviceCommand& c) {
    if (c.role != CommandRole::Action) return std::nullopt;
    switch (c.protocol) {
        case Protocol::ATA:
            if (!c.ata) return std::nullopt;
            if (c.ata->command == 0xF4)  // SECURITY ERASE UNIT; password block word 0 bit 1 = enhanced
                return !c.ata->payload.empty() && (c.ata->payload[0] & 0x02) ? EraseMethod::AtaSecureEraseEnhanced
                                                                              : EraseMethod::AtaSecureErase;
            if (c.ata->command == 0xB4) {  // SANITIZE DEVICE, sub-command in FEATURE
                switch (c.ata->features) {
                    case 0x0011: return EraseMethod::AtaSanitizeCrypto;
                    case 0x0012: return EraseMethod::AtaSanitizeBlock;
                    case 0x0014: return EraseMethod::AtaSanitizeOverwrite;
                    default: return std::nullopt;
                }
            }
            return std::nullopt;
        case Protocol::NVMeAdmin:
            if (!c.nvme) return std::nullopt;
            if (c.nvme->opcode == 0x84) {  // Sanitize, SANACT = CDW10 bits 2:0
                switch (c.nvme->cdw10 & 7) {
                    case 2: return EraseMethod::NvmeSanitizeBlock;
                    case 3: return EraseMethod::NvmeSanitizeOverwrite;
                    case 4: return EraseMethod::NvmeSanitizeCrypto;
                    default: return std::nullopt;
                }
            }
            if (c.nvme->opcode == 0x80)  // Format NVM, SES = CDW10 bits 11:9
                return ((c.nvme->cdw10 >> 9) & 7) == 2 ? EraseMethod::NvmeFormatCrypto : EraseMethod::NvmeFormatUserData;
            return std::nullopt;
        case Protocol::eMMC: return EraseMethod::EmmcSanitize;
        case Protocol::BlockIoctl: return EraseMethod::Discard;
        case Protocol::TCG: return EraseMethod::OpalGenKey;
    }
    return std::nullopt;
}

bool changes_medium(const WipeStep& s) {
    if (s.overwrite) return true;
    for (const auto& c : s.commands)
        if (classify_command(c)) return true;
    return false;
}

}  // namespace

EraseMethod classify_step(const WipeStep& step) {
    for (auto it = step.commands.rbegin(); it != step.commands.rend(); ++it)
        if (auto m = classify_command(*it)) return *m;
    return EraseMethod::HostOverwrite;
}

EraseMethod final_method(const WipePlan& plan) {
    for (auto it = plan.steps.rbegin(); it != plan.steps.rend(); ++it)
        if (changes_medium(*it)) return classify_step(*it);
    return EraseMethod::HostOverwrite;
}

namespace {

// Wei et al. FAST'11 counts, estimated as the Jeffreys posterior mean (x + 1/2) / (n + 1); the
// 95% interval is the Beta(x + 1/2, n - x + 1/2) 2.5% / 97.5% quantiles.
MethodPrior measured(int x, int n, double lo, double hi, double confidence, std::string basis) {
    MethodPrior p;
    p.failure_rate = (x + 0.5) / (n + 1.0);
    p.confidence = confidence;
    p.basis = std::move(basis);
    p.measured = true;
    p.failures = x;
    p.trials = n;
    p.ci_low = lo;
    p.ci_high = hi;
    return p;
}

MethodPrior assumed(double f, double confidence, std::string basis) {
    MethodPrior p;
    p.failure_rate = f;
    p.confidence = confidence;
    p.basis = "ASSUMPTION: " + std::move(basis);
    return p;
}

constexpr const char* kWei = "Wei et al., Reliably Erasing Data from Flash-Based Solid State Drives, USENIX FAST 2011";

}  // namespace

// Confidence (E = 1 - confidence): 0.9 for host overwrite and 0.2 for native commands are the
// DataWipe paper's Table II values; 0.1 for discard is an assumption (weaker than any command).
MethodPrior method_prior(EraseMethod m, MediaType media, unsigned host_passes) {
    const bool flash = media != MediaType::HDD;
    switch (m) {
        case EraseMethod::HostOverwrite:
            if (flash && host_passes >= 2)
                return measured(1, 8, 0.014, 0.454, 0.9,
                                std::format("{}, Table 2 (sequential initialisation): after two full overwrite "
                                            "passes 1 of 8 SSDs (drive A) still held old data",
                                            kWei));
            if (flash)
                return measured(7, 8, 0.546, 0.986, 0.9,
                                std::format("{}, Table 2 (sequential initialisation): after one full overwrite "
                                            "pass 7 of 8 SSDs still held old data; only drive B was clean",
                                            kWei));
            return assumed(0.02, 0.9, "no published failure rate for full host overwrite of magnetic media; only "
                                      "reallocated (grown-defect) sectors escape it, assumed 2%");
        case EraseMethod::AtaSecureErase:
            if (flash)
                return measured(1, 5, 0.023, 0.629, 0.2,
                                std::format("{}, Table 1, SECURITY ERASE UNIT: of the 5 verifiable drives that "
                                            "REPORTED success, 1 (drive B) kept all data. (Drives C and D also "
                                            "failed but reported the failure; drive E could not be verified.)",
                                            kWei));
            return assumed(0.05, 0.2, "no published failure rate for ATA Secure Erase on HDDs (Wei et al. tested "
                                      "SSDs only); assumed 5%");
        case EraseMethod::AtaSecureEraseEnhanced:
            if (flash)
                return measured(0, 4, 0.000, 0.461, 0.2,
                                std::format("{}, Table 1, SECURITY ERASE UNIT ENH: 0 failures on the 4 verifiable "
                                            "drives that supported it (F, G, H, I); the estimate stays above 0 "
                                            "because 4 drives cannot show a low rate",
                                            kWei));
            return assumed(0.05, 0.2, "no published failure rate for enhanced ATA Secure Erase on HDDs (Wei et al. "
                                      "tested SSDs only); assumed 5%");
        case EraseMethod::AtaSanitizeCrypto:
        case EraseMethod::AtaSanitizeBlock:
        case EraseMethod::AtaSanitizeOverwrite:
        case EraseMethod::NvmeSanitizeCrypto:
        case EraseMethod::NvmeSanitizeBlock:
        case EraseMethod::NvmeSanitizeOverwrite:
            return assumed(0.10, 0.2, "no published failure rate for SANITIZE (none of the 12 drives in Wei et al. "
                                      "2011 supported it); assumed 10%, below the measured ATA Secure Erase rate "
                                      "because SANITIZE must cover over-provisioned space and report completion "
                                      "through a status log");
        case EraseMethod::NvmeFormatCrypto:
        case EraseMethod::NvmeFormatUserData:
            return assumed(0.20, 0.2, "no published failure rate for NVMe Format with secure erase; its scope "
                                      "(namespace vs. all) is vendor-specific; assumed 20%");
        case EraseMethod::OpalGenKey:
            return assumed(0.20, 0.2, "no published failure rate for key regeneration. Meijer & van Gastel "
                                      "(Self-Encrypting Deception, IEEE S&P 2019) found key-handling flaws in "
                                      "self-encrypting SSDs from three vendors, including key material left in "
                                      "wear-levelled storage, and Wei et al. (Sec. 3.2.4) call trusting vendors to "
                                      "sanitize the key store 'unduly optimistic'; assumed 20%");
        case EraseMethod::EmmcSanitize:
            return assumed(0.20, 0.2, "no published failure rate for eMMC SANITIZE; assumed 20%");
        case EraseMethod::Discard:
            return assumed(0.80, 0.1, "discard/TRIM is advisory and a device may keep the data; assumed 80%");
    }
    return assumed(1.0, 0.0, "unknown method");
}

// ---- AHP ----

PairwiseMatrix default_pairwise() {
    // Saaty scale, row factor versus column factor. Order H, W, F, B, E.
    // These are the author's judgments, not measurements:
    //   F: the only factor with published failure counts (Wei et al. 2011): 2x H, 4x W, 5x B, 3x E.
    //   H: a tool that ignores HPA/DCO misses those sectors entirely: 2x W, 3x B, 2x E.
    //   W and E: moderate, equal: 2x B.
    //   B: the DataWipe paper notes boundary effects are the least quantified: least weight.
    constexpr double h = 1.0 / 2, t = 1.0 / 3, q = 1.0 / 4, f = 1.0 / 5;
    return {{
        {1, 2, h, 3, 2},  // H
        {h, 1, q, 2, 1},  // W
        {2, 4, 1, 5, 3},  // F
        {t, h, f, 1, h},  // B
        {h, 1, t, 2, 1},  // E
    }};
}

Result<AhpResult> ahp_weights(const PairwiseMatrix& m) {
    constexpr int n = kFactors;
    for (int i = 0; i < n; ++i)
        for (int j = 0; j < n; ++j) {
            if (!(m[i][j] > 0)) return error(std::format("AHP matrix entry [{}][{}] must be positive", i, j));
            if (std::abs(m[i][j] * m[j][i] - 1) > 1e-9)
                return error(std::format("AHP matrix is not reciprocal at [{}][{}]", i, j));
        }
    // Power iteration: a positive matrix has a unique positive principal eigenvector (Perron).
    RiskWeights v;
    v.fill(1.0 / n);
    double lambda = 0;
    for (int iter = 0; iter < 1000; ++iter) {
        RiskWeights next{};
        for (int i = 0; i < n; ++i)
            for (int j = 0; j < n; ++j) next[i] += m[i][j] * v[j];
        double sum = 0;
        for (double x : next) sum += x;
        double delta = 0;
        for (int i = 0; i < n; ++i) {
            next[i] /= sum;
            delta = std::max(delta, std::abs(next[i] - v[i]));
        }
        v = next;
        lambda = sum;  // v had sum 1, so sum(Mv) -> lambda_max
        if (delta < 1e-12) break;
    }
    AhpResult r;
    r.weights = v;
    r.lambda_max = lambda;
    r.consistency_index = (lambda - n) / (n - 1);
    constexpr double kRandomIndex5 = 1.12;  // Saaty's random index for n = 5
    r.consistency_ratio = r.consistency_index / kRandomIndex5;
    if (r.consistency_ratio >= 0.1)
        return error(std::format("AHP judgments are inconsistent: consistency ratio {:.3f} >= 0.10", r.consistency_ratio));
    return r;
}

// ---- Clusters ----

std::uint64_t choose_cluster_sectors(std::uint64_t domain_sectors, std::uint32_t sector_size) {
    const std::uint64_t base = std::max<std::uint64_t>(1, 4096 / sector_size);
    std::uint64_t c = base;
    while (domain_sectors / c > 65536) c *= 2;
    return c;
}

RiskContext make_risk_context(const DeviceProfile& p, const WipePlan& plan, SectorRange domain,
                              const std::vector<std::uint64_t>& resume_points) {
    RiskContext ctx;
    ctx.domain = domain;
    ctx.sector_size = p.geometry.logical_sector_size;
    ctx.cluster_sectors = choose_cluster_sectors(domain.end - domain.first, ctx.sector_size);
    const AtaIdentity& id = p.identity;
    if (id.native_max_sectors > id.user_addressable_sectors)
        ctx.hidden.push_back({id.user_addressable_sectors, id.native_max_sectors});
    if (id.dco_max_sectors > id.native_max_sectors) ctx.hidden.push_back({id.native_max_sectors, id.dco_max_sectors});
    ctx.boundaries = resume_points;
    ctx.boundary_reach = std::max<std::uint64_t>(ctx.cluster_sectors, (domain.end - domain.first) / 100);
    ctx.wear_ratio = p.media == MediaType::HDD ? 0 : std::clamp(id.wear_ratio < 0 ? 0.5 : id.wear_ratio, 0.0, 1.0);
    ctx.method = final_method(plan);
    ctx.media = p.media;
    ctx.host_passes = 0;
    for (const auto& s : plan.steps)
        if (s.overwrite && classify_step(s) == EraseMethod::HostOverwrite) ++ctx.host_passes;
    ctx.host_passes = std::max(1u, ctx.host_passes);
    return ctx;
}

std::vector<Cluster> score_clusters(const RiskContext& ctx, const RiskWeights& w) {
    std::vector<Cluster> out;
    if (ctx.domain.end <= ctx.domain.first) return out;
    const std::uint64_t cs = ctx.cluster_sectors ? ctx.cluster_sectors
                                                 : choose_cluster_sectors(ctx.domain.end - ctx.domain.first,
                                                                          ctx.sector_size);
    const std::uint64_t reach = ctx.boundary_reach ? ctx.boundary_reach : std::max<std::uint64_t>(cs, (ctx.domain.end - ctx.domain.first) / 100);

    std::vector<std::uint64_t> edges{ctx.domain.first, ctx.domain.end};
    for (const auto& h : ctx.hidden) {
        edges.push_back(h.first);
        edges.push_back(h.end);
    }
    for (auto b : ctx.boundaries) edges.push_back(b);
    std::sort(edges.begin(), edges.end());

    const MethodPrior prior = method_prior(ctx.method, ctx.media, ctx.host_passes);
    // Clusters start at multiples of the cluster size (absolute), so they stay I/O-aligned; the
    // first and last may be partial.
    std::uint64_t pos = ctx.domain.first;
    out.reserve((ctx.domain.end - ctx.domain.first) / cs + 2);
    while (pos < ctx.domain.end) {
        const std::uint64_t end = std::min(ctx.domain.end, (pos / cs + 1) * cs);
        Cluster c;
        c.range = {pos, end};
        for (const auto& h : ctx.hidden)
            if (pos < h.end && h.first < end) c.factors.h = 1;
        // Distance from the cluster to the nearest edge (0 if an edge falls inside it).
        std::uint64_t dist = UINT64_MAX;
        auto it = std::lower_bound(edges.begin(), edges.end(), pos);
        if (it != edges.end()) dist = *it <= end ? 0 : *it - end;
        if (it != edges.begin()) dist = std::min(dist, pos - *(it - 1));
        c.factors.b = dist >= reach ? 0 : 1 - double(dist) / double(reach);
        c.factors.w = ctx.wear_ratio;
        c.factors.f = prior.failure_rate;
        c.factors.e = 1 - prior.confidence;
        c.risk = w[kH] * c.factors.h + w[kW] * c.factors.w + w[kF] * c.factors.f + w[kB] * c.factors.b +
                 w[kE] * c.factors.e;
        c.location = (w[kH] * c.factors.h + w[kB] * c.factors.b) / (w[kH] + w[kB]);
        c.high_risk = c.factors.h > 0 || c.factors.b >= kHighRiskBoundary;
        out.push_back(c);
        pos = end;
    }
    return out;
}

double device_risk(const RiskContext& ctx, const RiskWeights& w) {
    const MethodPrior p = method_prior(ctx.method, ctx.media, ctx.host_passes);
    return (w[kW] * ctx.wear_ratio + w[kF] * p.failure_rate + w[kE] * (1 - p.confidence)) / (w[kW] + w[kF] + w[kE]);
}

Json to_json(const RiskContext& ctx) {
    Json j = Json::object();
    j["domain"]["first_sector"] = ctx.domain.first;
    j["domain"]["end_sector"] = ctx.domain.end;
    j["sector_size"] = ctx.sector_size;
    j["cluster_sectors"] = ctx.cluster_sectors;
    Json hidden = Json::array();
    for (const auto& h : ctx.hidden) {
        Json r = Json::object();
        r["first_sector"] = h.first;
        r["end_sector"] = h.end;
        hidden.push_back(std::move(r));
    }
    j["hidden_regions"] = std::move(hidden);
    Json b = Json::array();
    for (auto x : ctx.boundaries) b.push_back(x);
    j["resume_boundaries"] = std::move(b);
    j["boundary_reach_sectors"] = ctx.boundary_reach;
    j["wear_ratio"] = ctx.wear_ratio;
    j["method"] = to_string(ctx.method);
    j["media"] = to_string(ctx.media);
    j["host_passes"] = ctx.host_passes;
    const MethodPrior p = method_prior(ctx.method, ctx.media, ctx.host_passes);
    Json& mp = j["method_prior"];
    mp["failure_rate_F"] = p.failure_rate;
    mp["confidence"] = p.confidence;
    mp["calibration"] = p.measured ? "measured" : "assumed";
    if (p.measured) {
        mp["evidence"]["failures"] = p.failures;
        mp["evidence"]["trials"] = p.trials;
        mp["evidence"]["estimator"] = "Jeffreys posterior mean (x + 1/2) / (n + 1)";
        mp["evidence"]["ci95"] = Json::array();
        mp["evidence"]["ci95"].push_back(p.ci_low);
        mp["evidence"]["ci95"].push_back(p.ci_high);
    }
    mp["basis"] = p.basis;
    return j;
}

Result<RiskContext> risk_context_from_json(const Json& j) {
    auto u64 = [&](const Json* v, std::string_view what) -> Result<std::uint64_t> {
        if (!v) return error("risk context lacks " + std::string(what));
        return v->as_u64();
    };
    RiskContext c;
    const Json* d = j.find("domain");
    auto first = u64(d ? d->find("first_sector") : nullptr, "domain.first_sector");
    auto end = u64(d ? d->find("end_sector") : nullptr, "domain.end_sector");
    auto ss = u64(j.find("sector_size"), "sector_size");
    auto cs = u64(j.find("cluster_sectors"), "cluster_sectors");
    auto reach = u64(j.find("boundary_reach_sectors"), "boundary_reach_sectors");
    for (const Result<std::uint64_t>* r : {&first, &end, &ss, &cs, &reach})
        if (!*r) return r->error();
    if (*ss == 0 || *ss > 65536 || *end <= *first) return error("risk context: bad geometry");
    c.domain = {*first, *end};
    c.sector_size = static_cast<std::uint32_t>(*ss);
    c.cluster_sectors = *cs;
    c.boundary_reach = *reach;
    if (const Json* h = j.find("hidden_regions"))
        for (const auto& r : h->items()) {
            auto a = u64(r.find("first_sector"), "hidden first_sector");
            auto b = u64(r.find("end_sector"), "hidden end_sector");
            if (!a || !b) return error("risk context: bad hidden region");
            c.hidden.push_back({*a, *b});
        }
    if (const Json* b = j.find("resume_boundaries"))
        for (const auto& x : b->items()) {
            auto v = x.as_u64();
            if (!v) return v.error();
            c.boundaries.push_back(*v);
        }
    if (const Json* hp = j.find("host_passes")) {  // absent in certificates from before calibration
        auto v = hp->as_u64();
        if (!v || *v == 0 || *v > 100) return error("risk context: bad host_passes");
        c.host_passes = static_cast<unsigned>(*v);
    }
    if (const Json* w = j.find("wear_ratio")) {
        auto v = w->as_double();
        if (!v) return v.error();
        c.wear_ratio = *v;
    }
    auto method = j.find("method") ? j.find("method")->as_string() : Result<std::string>(error("no method"));
    auto media = j.find("media") ? j.find("media")->as_string() : Result<std::string>(error("no media"));
    if (!method || !media) return error("risk context lacks method/media");
    bool found = false;
    for (int m = 0; m <= int(EraseMethod::Discard); ++m)
        if (to_string(EraseMethod(m)) == *method) {
            c.method = EraseMethod(m);
            found = true;
        }
    if (!found) return error("risk context: unknown method '" + *method + "'");
    found = false;
    for (MediaType mt : {MediaType::HDD, MediaType::SSD_SATA, MediaType::SSD_NVMe, MediaType::eMMC})
        if (to_string(mt) == *media) {
            c.media = mt;
            found = true;
        }
    if (!found) return error("risk context: unknown media '" + *media + "'");
    return c;
}

Json to_json(const PairwiseMatrix& m) {
    Json rows = Json::array();
    for (const auto& r : m) {
        Json row = Json::array();
        for (double x : r) row.push_back(x);
        rows.push_back(std::move(row));
    }
    return rows;
}

}  // namespace dw
