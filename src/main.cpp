//
// Created by Hao, Zaijun on 2025/4/27.
//

#include <iostream>
#include <signal.h>

#include "Application.h"
#include "utils/Log.h"
#include "utils/System.h"

// Global pointer to application instance for signal handler
static Application* g_app_instance = nullptr;

// Signal handler for graceful shutdown
void sigint_handler(int signal) {
  if (signal == SIGINT) {
    LOGI("Received SIGINT (Ctrl+C), initiating graceful shutdown...");
    if (g_app_instance) {
      g_app_instance->Shutdown();
    }
  }
}

int main(int argc, char *argv[]) {
  Application app({argv, argv + argc});

  // Set global instance for signal handler
  g_app_instance = &app;

  // Register signal handler for SIGINT
  if (signal(SIGINT, sigint_handler) == SIG_ERR) {
    LOGE("Failed to register SIGINT handler");
    return 1;
  }

  LOGI("Starting application (Press Ctrl+C for graceful shutdown)");
  app.Run();

  // Clear global pointer
  g_app_instance = nullptr;

  LOGI("Application exited gracefully");
  return 0;
}