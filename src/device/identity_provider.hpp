#pragma once

#include <cstdint>
#include <optional>
#include <string>

#include "core/result.hpp"
#include "device/block_device.hpp"
#include "device/identity.hpp"

namespace dw {

class IIdentityProvider {
public:
    virtual ~IIdentityProvider() = default;
    virtual IdentitySource source() const = 0;
    virtual Result<AtaIdentity> identify(IBlockDevice& device) = 0;
};

// Reads a profiles/*.json file describing the drive the image/loop device pretends to be.
// "auto" capacity values resolve against the device's measured geometry, so one profile
// works for any image size. See profiles/README.md for the schema.
class SimulatedIdentityProvider final : public IIdentityProvider {
public:
    static Result<SimulatedIdentityProvider> load(const std::string& json_path);
    static Result<SimulatedIdentityProvider> from_json_text(const std::string& text, std::string origin);

    IdentitySource source() const override { return IdentitySource::Simulated; }
    Result<AtaIdentity> identify(IBlockDevice& device) override;
    const std::string& origin() const { return origin_; }

private:
    SimulatedIdentityProvider() = default;

    AtaIdentity base_;                   // everything except capacity
    std::optional<std::uint64_t> total_;  // nullopt = "auto" (use measured sector count)
    std::uint64_t dco_hidden_ = 0;
    std::uint64_t hpa_hidden_ = 0;
    std::string origin_;
};

// Real SATA drive (HDD or SSD). Read-only: IDENTIFY DEVICE (HDIO_GET_IDENTITY, falling back to
// SG_IO), READ/GET NATIVE MAX for the HPA, DCO IDENTIFY, and TCG Level 0 Discovery. Every raw
// command goes through ReadOnlyPassthrough's whitelist. See hw_identity.cpp.
class AtaIdentityProvider final : public IIdentityProvider {
public:
    IdentitySource source() const override { return IdentitySource::AtaIdentify; }
    Result<AtaIdentity> identify(IBlockDevice& device) override;
};

// Real NVMe drive. Read-only: Identify Controller + Identify Namespace, and TCG Level 0
// Discovery through Security Receive when the controller supports it (OACS bit 0).
class NvmeIdentityProvider final : public IIdentityProvider {
public:
    IdentitySource source() const override { return IdentitySource::NvmeIdentify; }
    Result<AtaIdentity> identify(IBlockDevice& device) override;
};

// Real eMMC device (mmcblkN). Read-only: EXT_CSD through MMC_IOC_CMD CMD8 (SEND_EXT_CSD);
// model, serial and firmware from the CID the kernel exposes in sysfs.
class EmmcIdentityProvider final : public IIdentityProvider {
public:
    IdentitySource source() const override { return IdentitySource::EmmcExtCsd; }
    Result<AtaIdentity> identify(IBlockDevice& device) override;
};

}  // namespace dw
