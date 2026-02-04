/**
 * Main entry point for Explorer daemon integration tests.
 *
 * This program runs comprehensive integration tests for the Explorer daemon,
 * verifying all major functionality including HTTP API, session management,
 * error handling, state persistence, and performance characteristics.
 */

#include "DaemonIntegrationTest.h"
#include "utils/Log.h"

#include <iostream>
#include <cstdlib>

int main() {
  std::cout << "Explorer Daemon Integration Test Suite\n";
  std::cout << "======================================\n";

  // Logging is already initialized via spdlog

  LOGI("🚀 Starting Explorer daemon integration tests");
  LOGI("   Test suite will validate:");
  LOGI("   • Daemon startup and shutdown procedures");
  LOGI("   • HTTP API endpoint functionality");
  LOGI("   • Session lifecycle management");
  LOGI("   • Concurrent request handling");
  LOGI("   • Error handling and validation");
  LOGI("   • State persistence and recovery");
  LOGI("   • Health monitoring and metrics");
  LOGI("   • Rate limiting and security");
  LOGI("   • Performance under load");

  try {
    // Run the comprehensive integration test suite
    int result = RunDaemonIntegrationTestSuite();

    if (result == 0) {
      std::cout << '\n';
      std::cout << "🎉 Integration Test Result: SUCCESS" << '\n';
      std::cout << "   All daemon functionality validated successfully!" << '\n';
      std::cout << "   The Explorer daemon is ready for production use." << '\n';
    } else {
      std::cout << '\n';
      std::cout << "❌ Integration Test Result: FAILURE" << '\n';
      std::cout << "   Some tests failed - check the logs above for details." << '\n';
      std::cout << "   Please fix the issues before deploying the daemon." << '\n';
    }

    return result;

  } catch (const std::exception& e) {
    LOGE("💥 Fatal error during integration tests: {}", e.what());
    std::cout << '\n';
    std::cout << "💥 Integration Test Result: FATAL ERROR" << '\n';
    std::cout << "   Exception: " << e.what() << '\n';
    return 1;
  } catch (...) {
    LOGE("💥 Unknown fatal error during integration tests");
    std::cout << '\n';
    std::cout << "💥 Integration Test Result: UNKNOWN ERROR" << '\n';
    return 1;
  }
}