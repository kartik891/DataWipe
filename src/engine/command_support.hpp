#pragma once
// Which device commands this build may send to real hardware.
//
//   Proven        exercised end to end, with the result verified by read-back, either on the
//                 QEMU bench (scripts/qemu_bench.py: real kernel interface, emulated drive) or
//                 on real hardware (scripts/hardware_test.sh). Sent without further flags
//                 (behind the physical-device gate).
//                   2026-10-10  ATA SECURITY ERASE UNIT, enhanced, on HDDs: WDC WD5000AAKX
//                               (500 GB) through an Initio INIC-1618L USB bridge; 79 min against
//                               the drive's estimate of 82; pre-wipe fingerprints all changed.
//                               Promoted for HDDs only: on SSDs Wei et al. (FAST'11) found 1 of 5
//                               drives that reported success had kept its data.
//   Experimental  implemented to the specification but not yet run against a drive that
//                 supports it: QEMU emulates neither the ATA Security / SANITIZE feature sets,
//                 HPA/DCO changes, NVMe Sanitize nor crypto erase. Sent only with
//                 --experimental, until the spare-drive hardware tests promote them.
//   Unsupported   not implemented (TCG Opal needs an authenticated session protocol). Never sent.
//
// Read-only queries and status polls follow the command they belong to and are not listed.
//
// A hardware plan built without --experimental never contains an Experimental command: the
// selector sees a copy of the drive's identity with those capabilities masked
// (mask_unvalidated_capabilities), so it falls back to methods that are Proven and says so.

#include <string>
#include <vector>

#include "device/classifier.hpp"
#include "engine/device_command.hpp"
#include "engine/method_selector.hpp"

namespace dw {

enum class Support { Proven, Experimental, Unsupported };

struct SupportInfo {
    Support level = Support::Unsupported;
    std::string why;
};

// `media`: the drive class the command would go to; some commands are proven for one class only.
SupportInfo command_support(const DeviceCommand& cmd, MediaType media = MediaType::Unknown);
std::string_view to_string(Support s);

// Masks, in a planning copy of a hardware identity, the capabilities whose commands may not be
// sent: Unsupported always, Experimental unless `experimental`. Hidden-area removal (SET MAX /
// DCO RESTORE) is switched off through `opts` instead, which caps the plan at Clear. Returns
// one line per masked capability for the plan's warnings. Simulated drives are never masked:
// nothing reaches a device.
std::vector<std::string> mask_unvalidated_capabilities(DeviceProfile& profile, SelectorOptions& opts, bool experimental);

}  // namespace dw
