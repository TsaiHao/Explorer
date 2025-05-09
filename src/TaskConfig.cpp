//
// Created by Hao, Zaijun on 2025/4/27.
//

#include <string>
#include <string_view>
#include <vector>

#include "TaskConfig.h"
#include "nlohmann/json.hpp"
#include "utils/System.h"
using json = nlohmann::json;

TaskConfig ParseFromJson(std::string_view json_str) {
  json obj = json::parse(json_str);
  TaskConfig config;

  if (obj.contains("pid")) {
    config.pid = obj["pid"].get<int>();
  }
  if (obj.contains("pName")) {
    config.pName = obj["pName"].get<std::string>();
  }
  if (obj.contains("scripts")) {
    config.scripts = obj["scripts"].get<std::vector<std::string>>();
  }

  return config;
}

TaskConfig ParseFromJsonFile(const std::string& file_path) {
  return ParseFromJson(utils::ReadFileToBuffer(file_path));
}