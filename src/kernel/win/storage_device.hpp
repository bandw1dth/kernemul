#pragma once
#include "builtin_device.hpp"
#include <memory>
#include <string_view>

std::shared_ptr<builtin_device> make_storage_device();
bool reserved_raw_device_path(std::string_view normalized) noexcept;
