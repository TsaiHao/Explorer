#pragma once

#include <string>
#include <string_view>
#include <utility>

// if c++ standard >= c++20 use std::format
#if __cplusplus >= 202002L
#include <format>
#else
#include "spdlog/fmt/fmt.h"
#endif

namespace utils {

// Unified formatting helper.
// Users should call utils::Format(...) without caring whether
// it is implemented via std::format or fmt::format.
template <typename... Args>
std::string Format(std::string_view fmt_str, Args &&...args) {
#if __cplusplus >= 202002L
  return std::format(fmt_str, std::forward<Args>(args)...);
#else
  return fmt::format(fmt_str, std::forward<Args>(args)...);
#endif
}

} // namespace utils
