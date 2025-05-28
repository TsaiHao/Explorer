//
// Created by Hao, Zaijun on 2025/4/27.
//

#include "Application.h"
#include "utils/Log.h"
#include "utils/System.h"

constexpr std::string_view kConfigFilePath = "/data/local/tmp/config.json";

int main() {
  if (!utils::FileExists(kConfigFilePath)) {
    LOG(ERROR) << "Config file not found: " << kConfigFilePath;
    return 1;
  }
  std::string config = utils::ReadFileToBuffer(kConfigFilePath);

  LOG(INFO) << "Starting application";

  const Application app(config);
  app.Run();

  return 0;
}