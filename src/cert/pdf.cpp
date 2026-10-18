#include "cert/pdf.hpp"

#include <format>
#include <vector>

namespace dw {

namespace {

constexpr int kPageW = 595, kPageH = 842;  // A4 in points
constexpr int kMargin = 50;

struct Line {
    std::string text;
    char font = 'R';  // R regular, B bold, M monospace
    int size = 9;
    int gap = 12;  // leading after the line
};

std::string pdf_escape(std::string_view s) {
    std::string out;
    for (unsigned char c : s) {
        if (c == '(' || c == ')' || c == '\\') {
            out += '\\';
            out += static_cast<char>(c);
        } else if (c < 32 || c > 126) {
            out += '?';
        } else {
            out += static_cast<char>(c);
        }
    }
    return out;
}

// Greedy word wrap at `width` characters; long words (hashes) are split.
std::vector<std::string> wrap(std::string_view s, std::size_t width) {
    std::vector<std::string> out;
    std::string cur;
    std::size_t i = 0;
    while (i < s.size()) {
        std::size_t j = s.find(' ', i);
        if (j == std::string_view::npos) j = s.size();
        std::string_view word = s.substr(i, j - i);
        while (word.size() > width) {
            if (!cur.empty()) out.push_back(std::move(cur)), cur.clear();
            out.emplace_back(word.substr(0, width));
            word.remove_prefix(width);
        }
        if (!cur.empty() && cur.size() + 1 + word.size() > width) out.push_back(std::move(cur)), cur.clear();
        if (!cur.empty()) cur += ' ';
        cur += word;
        i = j + 1;
    }
    if (!cur.empty()) out.push_back(std::move(cur));
    if (out.empty()) out.emplace_back();
    return out;
}

std::string str(const Json& j, std::initializer_list<std::string_view> path, std::string fallback = "-") {
    const Json* v = &j;
    for (auto k : path) v = v ? v->find(k) : nullptr;
    if (!v || v->is_null()) return fallback;
    if (v->is_string()) return v->as_string().value();
    if (v->is_bool()) return v->as_bool().value() ? "yes" : "no";
    return v->dump();
}

std::vector<Line> layout(const Json& c) {
    std::vector<Line> L;
    auto h1 = [&](std::string t) { L.push_back({std::move(t), 'B', 16, 22}); };
    auto h2 = [&](std::string t) {
        L.push_back({"", 'R', 9, 6});
        L.push_back({std::move(t), 'B', 11, 15});
    };
    auto field = [&](std::string label, const std::string& value) {
        bool first = true;
        for (auto& part : wrap(value, 78)) {
            L.push_back({std::format("{:<20}{}", first ? label : "", part), 'R', 9, 12});
            first = false;
        }
    };
    auto mono = [&](const std::string& value) {
        for (auto& part : wrap(value, 88)) L.push_back({part, 'M', 8, 11});
    };
    auto para = [&](const std::string& value) {
        for (auto& part : wrap(value, 100)) L.push_back({part, 'R', 9, 12});
    };

    h1("Certificate of Data Sanitization");
    L.push_back({"Issued by DataWipe " + str(c, {"tool", "version"}) + " under NIST SP 800-88 Rev. 1", 'R', 9, 18});
    field("Certificate ID", str(c, {"certificate_id"}));
    field("Session ID", str(c, {"session_id"}));
    field("Issued (UTC)", str(c, {"issued_at"}));
    field("Outcome", str(c, {"outcome"}));
    const Json* sci = c.find("sci_score");
    field("SCI", sci && sci->is_number() ? std::format("{:.2f} / 100", sci->as_double().value()) : "not applicable");

    h2("Device");
    field("Model", str(c, {"device", "identity", "model"}));
    field("Serial number", str(c, {"device", "identity", "serial"}));
    field("Firmware", str(c, {"device", "identity", "firmware"}));
    field("Interface", str(c, {"device", "identity", "transport"}));
    field("Media type", str(c, {"device", "classification", "media"}));
    field("Capacity", str(c, {"device", "geometry", "size_bytes"}) + " bytes (" +
                          str(c, {"device", "geometry", "sector_count"}) + " x " +
                          str(c, {"device", "geometry", "logical_sector_size"}) + " B)");
    field("Identity source", str(c, {"device", "identity", "source"}));

    h2("Sanitization");
    field("Method", str(c, {"sanitization", "method_name"}));
    field("NIST level", str(c, {"sanitization", "nist_level_achieved"}) + " achieved (planned " +
                            str(c, {"sanitization", "nist_level_planned"}) + ")");
    if (const Json* st = c.find("sanitization") ? c.find("sanitization")->find("standards") : nullptr)
        for (const auto& s : st->items()) field("Standard", (s.is_string() ? s.as_string().value() : std::string()));
    field("Started (UTC)", str(c, {"sanitization", "started_at"}));
    field("Runs", str(c, {"sanitization", "runs"}));
    if (const Json* steps = c.find("sanitization") ? c.find("sanitization")->find("steps") : nullptr) {
        int n = 1;
        for (const auto& s : steps->items())
            field(std::format("Step {}", n++), std::format("[{}] {} - {}", str(s, {"execution"}), str(s, {"title"}),
                                                           str(s, {"status"})));
    }

    h2("Verification (ARVS / SCI)");
    field("Result", str(c, {"verification", "status"}));
    para(str(c, {"verification", "reason"}, ""));
    if (c.find("verification") && c.find("verification")->find("units")) {
        field("Sampler", str(c, {"verification", "sampler", "name"}));
        field("Sectors read", str(c, {"verification", "sectors", "read"}) + " of " +
                                  str(c, {"verification", "range", "sector_count"}) + " (" +
                                  str(c, {"verification", "coverage_percent"}) + " %)");
        field("Not verified", str(c, {"verification", "sectors", "not_verified"}) + " sector(s)");
    }

    if (const Json* cv = c.find("caveats"); cv && !cv->items().empty()) {
        h2("Caveats");
        for (const auto& x : cv->items()) para("- " + (x.is_string() ? x.as_string().value() : std::string()));
    }

    h2("TECC seal");
    field("Log entries", str(c, {"tecc", "entries"}));
    field("Terminal hash", "");
    mono(str(c, {"tecc", "terminal_hash"}));
    const Json* sig = c.find("tecc") ? c.find("tecc")->find("signature") : nullptr;
    if (sig && sig->is_object()) {
        field("Signature", "Ed25519, key id " + str(*sig, {"key_id"}));
        mono(str(*sig, {"value"}));
        field("Signer public key", "");
        mono(str(*sig, {"public_key"}));
    } else {
        field("Signature", "UNSIGNED - " + str(c, {"tecc", "unsigned_reason"}, ""));
    }
    L.push_back({"", 'R', 9, 6});
    para("The signed record is the JSON file attached to this PDF. To verify it, extract the attachment and run: "
         "datawipe verify-cert <file.json> --pubkey <the issuer's published public key> [--log <session log>]. "
         "Trust the issuer's key only if it was obtained from the issuer through a trusted channel, never from this "
         "document.");
    return L;
}

}  // namespace

std::string render_certificate_pdf(const Json& certificate, const std::string& json_name) {
    const std::vector<Line> lines = layout(certificate);

    // Split into pages.
    std::vector<std::string> pages;
    std::string content;
    int y = kPageH - kMargin;
    for (const auto& l : lines) {
        if (y - l.gap < kMargin) {
            pages.push_back(std::move(content));
            content.clear();
            y = kPageH - kMargin;
        }
        const char* font = l.font == 'B' ? "/F2" : l.font == 'M' ? "/F3" : "/F1";
        if (!l.text.empty())
            content += std::format("BT {} {} Tf {} {} Td ({}) Tj ET\n", font, l.size, kMargin, y, pdf_escape(l.text));
        y -= l.gap;
    }
    pages.push_back(std::move(content));

    // Objects: 1 catalog, 2 pages, 3-5 fonts, 6 embedded file, 7 filespec, then page/content pairs.
    std::vector<std::string> objs;
    const std::string json = certificate.dump(2) + "\n";
    const int first_page = 8;
    std::string kids;
    for (std::size_t i = 0; i < pages.size(); ++i) kids += std::format("{} 0 R ", first_page + 2 * int(i));
    objs.push_back(std::format("<< /Type /Catalog /Pages 2 0 R /Names << /EmbeddedFiles << /Names [({}) 7 0 R] >> >> "
                               "/PageMode /UseAttachments >>",
                               pdf_escape(json_name)));
    objs.push_back(std::format("<< /Type /Pages /Kids [{}] /Count {} >>", kids, pages.size()));
    objs.push_back("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>");
    objs.push_back("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>");
    objs.push_back("<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>");
    objs.push_back(std::format("<< /Type /EmbeddedFile /Subtype /application#2Fjson /Length {} >>\nstream\n{}\nendstream",
                               json.size(), json));
    objs.push_back(std::format("<< /Type /Filespec /F ({0}) /UF ({0}) /EF << /F 6 0 R >> /Desc (Signed DataWipe "
                               "certificate) >>",
                               pdf_escape(json_name)));
    for (const auto& c : pages) {
        objs.push_back(std::format("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {} {}] /Resources << /Font << /F1 3 0 "
                                   "R /F2 4 0 R /F3 5 0 R >> >> /Contents {} 0 R >>",
                                   kPageW, kPageH, first_page + 1 + 2 * int(&c - &pages[0])));
        objs.push_back(std::format("<< /Length {} >>\nstream\n{}\nendstream", c.size(), c));
    }

    std::string out = "%PDF-1.4\n%\xE2\xE3\xCF\xD3\n";
    std::vector<std::size_t> offsets;
    for (std::size_t i = 0; i < objs.size(); ++i) {
        offsets.push_back(out.size());
        out += std::format("{} 0 obj\n{}\nendobj\n", i + 1, objs[i]);
    }
    const std::size_t xref = out.size();
    out += std::format("xref\n0 {}\n0000000000 65535 f \n", objs.size() + 1);
    for (auto o : offsets) out += std::format("{:010} 00000 n \n", o);
    out += std::format("trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{}\n%%EOF\n", objs.size() + 1, xref);
    return out;
}

}  // namespace dw
