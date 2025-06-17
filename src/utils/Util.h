#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace utils {
std::vector<std::string> SplitString(std::string_view str,
                                     std::string_view delimiter = " ");

std::string JoinStrings(const std::vector<std::string> &strings,
                        std::string_view delimiter);
} // namespace utils