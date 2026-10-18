#pragma once
// Internal: concrete backend construction. Only device_factory.cpp may include this; everything
// else gets devices from open_target(), which runs the safety guard first.

#include <memory>

#include "device/block_device.hpp"
#include "device/safety_guard.hpp"

namespace dw::detail {

// Both take ownership of `fd` (closed on failure).
Result<std::unique_ptr<IBlockDevice>> make_image_device(int fd, const TargetAssessment& t, OpenOptions opts);
Result<std::unique_ptr<IBlockDevice>> make_block_device(int fd, const TargetAssessment& t, OpenOptions opts);

}  // namespace dw::detail
