#pragma once

#include <string>
#include <vector>
#include <optional>

struct TaskConfig {
  std::optional<int> pid;
  std::optional<std::string> pName;
  std::vector<std::string> scripts;
};

TaskConfig ParseFromJson(std::string_view json_str);
TaskConfig ParseFromJsonFile(const std::string& file_path);
