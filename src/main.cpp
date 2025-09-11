//
// Created by Hao, Zaijun on 2025/4/27.
//

#include <iostream>

#include "Application.h"
#include "utils/Log.h"
#include "utils/System.h"

constexpr std::string_view kConfilFilePathRelative = "config.json";
constexpr std::string_view kConfigFilePathAbsolute =
    "/data/local/tmp/config.json";

int main() {
  std::string config;

  if (utils::FileExists(kConfilFilePathRelative)) {
    config = utils::ReadFileToBuffer(kConfilFilePathRelative);
  } else if (utils::FileExists(kConfigFilePathAbsolute)) {
    config = utils::ReadFileToBuffer(kConfigFilePathAbsolute);
  } else {
    std::cerr << "Config file not found in either location: " << kConfilFilePathRelative << " or " << kConfigFilePathAbsolute << '\n';
    return 1;
  }

  const Application app(config);

  LOGI("Starting application");
  app.Run();

  return 0;
}