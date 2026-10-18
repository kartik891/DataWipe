#pragma once
// Device detection & classification (paper Section III-D).
//
// Combines what the kernel measured (DeviceGeometry) with what the device reports about
// itself (AtaIdentity) into the DeviceProfile the method selector consumes. The two are kept
// separate and cross-checked: identity data can be wrong or tampered with, and an HPA/DCO
// exists precisely to make the reported capacity differ from the physical one.

#include <string>
#include <vector>

#include "core/json.hpp"
#include "core/result.hpp"
#include "device/device_factory.hpp"
#include "device/identity.hpp"

namespace dw {

struct DeviceProfile {
    std::string path;
    BackendKind backend = BackendKind::ImageFile;
    std::string backing_file;  // loop devices only
    DeviceGeometry geometry;   // measured
    AtaIdentity identity;      // reported
    IdentitySource identity_source = IdentitySource::Simulated;
    std::string identity_origin;  // profile file path, or which commands/files were used
    MediaType media = MediaType::Unknown;
    bool encrypted = false;
    std::vector<std::string> warnings;

    // Largest capacity the identity admits to: DCO max if known, else native max.
    std::uint64_t medium_sectors() const {
        return identity.dco_max_sectors ? identity.dco_max_sectors : identity.native_max_sectors;
    }
    // Sectors a plain host-side overwrite of the user-addressable area would miss.
    std::uint64_t hidden_sectors() const { return medium_sectors() - identity.user_addressable_sectors; }
    // User-addressable sectors the kernel cannot reach through this connection. USB-to-SATA
    // bridges commonly report one sector fewer than the drive does; host writes stop where the
    // kernel's view ends, while a firmware erase still covers the whole drive.
    std::uint64_t unreachable_sectors() const {
        const std::uint64_t seen = geometry.sector_count();
        return identity_source != IdentitySource::Simulated && seen < identity.user_addressable_sectors
                   ? identity.user_addressable_sectors - seen
                   : 0;
    }
};

Result<DeviceProfile> classify(const OpenedTarget& target, const AtaIdentity& identity, IdentitySource source,
                               std::string identity_origin);

// Same, from an assessment and geometry, for detection that never opened the device (sysfs).
Result<DeviceProfile> classify(const TargetAssessment& target, const DeviceGeometry& geometry,
                               const AtaIdentity& identity, IdentitySource source, std::string identity_origin);

Json to_json(const DeviceProfile& profile);

}  // namespace dw
