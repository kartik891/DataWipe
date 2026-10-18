#pragma once
// PDF rendering of a destruction certificate (paper Section III-D: "PDF and JSON format").
//
// The PDF is for people: it prints the certificate's key facts, the TECC terminal hash and
// signature, and how to check them. The signed record is the JSON, which is embedded in the
// PDF as an attached file (/EmbeddedFiles), so the PDF alone is enough to verify: extract the
// attachment and run `datawipe verify-cert`. The PDF itself carries no PDF-level signature
// (PAdES); editing its visible text does not change the attached, signed JSON.
//
// Hand-written PDF 1.4: base-14 Helvetica / Courier (no font embedding), text only, A4 pages,
// correct xref offsets. Non-ASCII characters are printed as '?'.

#include <string>

#include "core/json.hpp"

namespace dw {

// `json_name`: file name the attachment gets, e.g. "disk.img.20260927T063452Z.dwcert.json".
std::string render_certificate_pdf(const Json& certificate, const std::string& json_name);

}  // namespace dw
