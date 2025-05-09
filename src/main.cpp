//
// Created by Hao, Zaijun on 2025/4/27.
//

#include <fstream>
#include <iostream>
#include <string>

#include "utils/Log.h"
#include "Application.h"

int main(int argc, const char *argv[]) {
  if (argc < 2) {
    std::cerr << "Usage: " << argv[0] << " <file>\n";
    return EXIT_FAILURE;
  }

  TaskConfig config;
  config.pid = atoi(argv[1]);
  config.scripts.emplace_back("debug.js");

  LOG(INFO) << "Starting application, targeting pid " << *config.pid;

  const Application app(config);
  app.Run();

  return 0;
}