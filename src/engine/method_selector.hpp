#pragma once
// DeviceProfile -> WipePlan (paper Section III-E). A pure function: no I/O, fully table-testable.
//
// Matrix (first available rung of each ladder wins):
//
//  HDD            Clear : host PRNG overwrite (REAL)
//                 Purge : ATA SECURITY ERASE UNIT enhanced  > SANITIZE OVERWRITE EXT > SE normal
//                         (device command EMULATED: logged, and its effect reproduced by a real
//                          host pass so read-back verification remains meaningful)
//  SSD, encrypted Purge : crypto erase  [SATA: SANITIZE CRYPTO SCRAMBLE > TCG Opal GenKey]
//                                       [NVMe: SANITIZE Crypto Erase  > FORMAT NVM SES=2]
//                         + block erase afterwards if supported (defense in depth: a buggy SED
//                           key hierarchy must not be the only barrier)
//  SSD, plain     Purge : [SATA: SANITIZE BLOCK ERASE > SANITIZE OVERWRITE > SE enhanced > SE normal]
//                         [NVMe: SANITIZE Block Erase > SANITIZE Overwrite]
//                 Clear : NVMe FORMAT SES=1, else host overwrite (flash over-provisioning means
//                         a host overwrite can never be Purge)
//  eMMC           Purge : BLKDISCARD all + eMMC SANITIZE;  else Clear via host overwrite
//  All SSD/eMMC device commands are SIMULATED in this build.
//
//  SATA HPA/DCO   Prepended step removes them so every rung covers the whole medium. If the
//                 caller opts out, the plan is capped at Clear and says why.
//  Security LOCKED -> no plan (the drive rejects I/O until unlocked).

#include "core/result.hpp"
#include "device/classifier.hpp"
#include "engine/wipe_plan.hpp"

namespace dw {

struct SelectorOptions {
    bool remove_hidden_areas = true;
    bool defense_in_depth = true;
};

Result<WipePlan> select_method(const DeviceProfile& profile, const SelectorOptions& opts = {});

}  // namespace dw
