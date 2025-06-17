//
// Created by Hao, Zaijun on 2025/6/17.
//

#include "utils/Util.h"

namespace utils {
std::vector<std::string> SplitString(std::string_view str,
                                     std::string_view delimiter) {
  std::vector<std::string> result;
  size_t start = 0;
  size_t end = str.find(delimiter);

  while (end != std::string_view::npos) {
    result.emplace_back(str.substr(start, end - start));
    start = end + delimiter.length();
    end = str.find(delimiter, start);
  }

  result.emplace_back(str.substr(start));
  return result;
}

std::string JoinStrings(const std::vector<std::string> &strings,
                        std::string_view delimiter) {
  std::string result;
  for (const auto &str : strings) {
    if (!result.empty()) {
      result += delimiter;
    }
    result += str;
  }
  return result;
}
} // namespace utils