#include "verify/sci.hpp"

namespace dw {

SciResult compute_sci(const SciInput& in) {
    SciResult r;
    const double lambda = in.lambda > 0 ? in.lambda : kDefaultSciLambda;
    r.wc = 1 / (1 + lambda);
    r.wr = lambda / (1 + lambda);
    if (in.baseline_total) r.v = double(in.baseline_pass) / double(in.baseline_total);
    if (in.high_total) r.r = double(in.high_pass) / double(in.high_total);
    if (in.baseline_total && in.high_total) {
        r.sci = (r.wc * r.v + r.wr * r.r) / (r.wc + r.wr) * 100;
        r.defined = true;
    } else if (in.baseline_total) {
        r.sci = r.v * 100;
        r.defined = true;
        r.note = "no high-risk units were sampled; SCI is the baseline pass rate";
    } else if (in.high_total) {
        r.sci = r.r * 100;
        r.defined = true;
        r.note = "no baseline units were sampled; SCI is the high-risk pass rate";
    } else {
        r.note = "nothing was sampled; SCI undefined";
    }
    return r;
}

Json to_json(const SciInput& in, const SciResult& r) {
    Json j = Json::object();
    if (r.defined) j["score"] = r.sci;
    else j["score"] = nullptr;
    j["lambda"] = in.lambda;
    j["wc"] = r.wc;
    j["wr"] = r.wr;
    j["baseline"]["units"] = in.baseline_total;
    j["baseline"]["passed"] = in.baseline_pass;
    j["high_risk"]["units"] = in.high_total;
    j["high_risk"]["passed"] = in.high_pass;
    j["formula"] = "SCI = (Wc*Vpass/Vtotal + Wr*Rhigh/Rtotal)/(Wc+Wr)*100, Wc = 1/(1+lambda), Wr = lambda/(1+lambda); "
                   "first read-back, before re-wipes";
    if (!r.note.empty()) j["note"] = r.note;
    return j;
}

}  // namespace dw
