#pragma once
// The single entry point for obtaining an IBlockDevice.

#include <memory>

#include "device/block_device.hpp"
#include "device/safety_guard.hpp"

namespace dw {

struct OpenedTarget {
    std::unique_ptr<IBlockDevice> device;
    TargetAssessment assessment;
};

// Assess -> open -> verify the opened inode is the one assessed -> build backend.
// Physical block devices additionally require an override minted for that exact device.
Result<OpenedTarget> open_target(const std::string& path, OpenOptions opts,
                                 const PhysicalOverride* override = nullptr);

}  // namespace dw
