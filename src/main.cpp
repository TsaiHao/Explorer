//
// Created by Hao, Zaijun on 2025/4/27.
//

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
    LOG(INFO) << "Using relative config file: " << kConfilFilePathRelative;
  } else if (utils::FileExists(kConfigFilePathAbsolute)) {
    config = utils::ReadFileToBuffer(kConfigFilePathAbsolute);
    LOG(INFO) << "Using absolute config file: " << kConfigFilePathAbsolute;
  } else {
    LOG(ERROR) << "Config file not found in either location: "
               << kConfilFilePathRelative << " or " << kConfigFilePathAbsolute;
    return 1;
  }

  LOG(INFO) << "Starting application";

  const Application app(config);
  app.Run();

  return 0;
}