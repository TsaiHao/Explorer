#pragma once

#include "ApplicationDaemon.h"
#include "utils/Log.h"
#include "nlohmann/json.hpp"

#include <memory>
#include <string>
#include <thread>
#include <chrono>
#include <vector>
#include <future>

using json = nlohmann::json;

/**
 * Comprehensive integration test suite for Explorer daemon.
 * Tests all major components and their interactions.
 */
class DaemonIntegrationTest {
public:
  explicit DaemonIntegrationTest(int test_port = 8084);
  ~DaemonIntegrationTest();

  /**
   * Run all integration tests.
   * @return True if all tests pass
   */
  bool RunAllTests();

  /**
   * Individual test categories.
   */
  bool TestDaemonStartupShutdown();
  bool TestHttpApiEndpoints();
  bool TestSessionLifecycle();
  bool TestConcurrentRequests();
  bool TestErrorHandling();
  bool TestStatePersistence();
  bool TestHealthMonitoring();
  bool TestMetricsCollection();
  bool TestRateLimiting();
  bool TestEdgeCases();

private:
  /**
   * HTTP client for testing API endpoints.
   */
  struct HttpResponse {
    int status_code;
    json response_data;
    std::string error_message;
    double response_time_ms;
  };

  /**
   * Make HTTP request to daemon API.
   */
  HttpResponse MakeHttpRequest(const std::string& method,
                               const std::string& endpoint,
                               const json& request_data = json::object());

  /**
   * Start daemon instance for testing.
   */
  bool StartDaemon();

  /**
   * Stop daemon instance.
   */
  void StopDaemon();

  /**
   * Wait for daemon to be ready.
   */
  bool WaitForDaemonReady(int timeout_seconds = 10);

  /**
   * Create test session configuration.
   */
  json CreateTestSessionConfig(const std::string& app_name = "com.test.app");

  /**
   * Mock FRIDA session for testing.
   */
  struct MockSession {
    std::string session_id;
    std::string app_name;
    std::string status;
    json config;
  };

  /**
   * Validate API response format.
   */
  bool ValidateApiResponse(const HttpResponse& response, bool expect_success = true);

  /**
   * Test helper: run multiple concurrent requests.
   */
  std::vector<HttpResponse> RunConcurrentRequests(
      const std::string& method,
      const std::string& endpoint,
      const json& request_data,
      int num_requests);

  /**
   * Performance test: measure response time under load.
   */
  bool TestPerformanceUnderLoad(int num_requests = 100);

  /**
   * Test state file operations.
   */
  bool TestStateFileOperations();

  /**
   * Logging helpers.
   */
  void LogTestStart(const std::string& test_name);
  void LogTestResult(const std::string& test_name, bool passed, const std::string& details = "");
  void LogTestSummary();

  // Test configuration
  int test_port_;
  std::string test_host_;
  std::string daemon_state_file_;

  // Daemon instance
  std::unique_ptr<ApplicationDaemon> daemon_;
  std::unique_ptr<std::thread> daemon_thread_;
  std::atomic<bool> daemon_running_;

  // Test results tracking
  int total_tests_;
  int passed_tests_;
  int failed_tests_;
  std::vector<std::string> test_failures_;

  // Test timeouts
  static constexpr int kDefaultTimeoutMs = 5000;
  static constexpr int kDaemonStartupTimeoutMs = 10000;
};

/**
 * Test runner utility functions.
 */
class TestRunner {
public:
  /**
   * Run integration tests with proper setup/teardown.
   */
  static int RunDaemonIntegrationTests();

  /**
   * Create isolated test environment.
   */
  static bool SetupTestEnvironment();

  /**
   * Clean up test environment.
   */
  static void CleanupTestEnvironment();

private:
  static std::string test_data_dir_;
  static std::vector<std::string> cleanup_files_;
};

/**
 * HTTP client utilities for testing.
 */
class TestHttpClient {
public:
  explicit TestHttpClient(const std::string& base_url);

  struct Response {
    int status;
    std::string body;
    std::map<std::string, std::string> headers;
    double duration_ms;
    bool success;
    std::string error;
  };

  Response Get(const std::string& path);
  Response Post(const std::string& path, const json& data);
  Response Put(const std::string& path, const json& data);
  Response Delete(const std::string& path);

  // Test utilities
  bool IsServerRunning();
  Response WaitForServer(int timeout_seconds = 10);

private:
  std::string base_url_;
  int timeout_ms_;
};

/**
 * Mock FRIDA environment for testing.
 */
class MockFridaEnvironment {
public:
  MockFridaEnvironment();
  ~MockFridaEnvironment();

  /**
   * Initialize mock FRIDA environment.
   */
  bool Initialize();

  /**
   * Create mock session.
   */
  std::string CreateMockSession(const std::string& app_name, const json& config);

  /**
   * Remove mock session.
   */
  bool RemoveMockSession(const std::string& session_id);

  /**
   * Get mock session info.
   */
  json GetMockSessionInfo(const std::string& session_id);

  /**
   * List all mock sessions.
   */
  std::vector<json> ListMockSessions();

  /**
   * Simulate session operations.
   */
  void SimulateSessionActivity(const std::string& session_id);

private:
  std::map<std::string, json> mock_sessions_;
  std::mutex sessions_mutex_;
  std::atomic<int> session_counter_;
};

/**
 * Performance testing utilities.
 */
class PerformanceTestUtils {
public:
  struct PerformanceMetrics {
    double min_response_time_ms;
    double max_response_time_ms;
    double avg_response_time_ms;
    double percentile_95_ms;
    double percentile_99_ms;
    int total_requests;
    int successful_requests;
    int failed_requests;
    double requests_per_second;
  };

  /**
   * Run concurrent load test.
   */
  static PerformanceMetrics RunLoadTest(
      TestHttpClient& client,
      const std::string& endpoint,
      const json& request_data,
      int num_requests,
      int num_threads = 4);

  /**
   * Analyze response time distribution.
   */
  static PerformanceMetrics AnalyzeResponseTimes(const std::vector<double>& response_times);
};

/**
 * Test data generators.
 */
class TestDataGenerator {
public:
  /**
   * Generate test session configurations.
   */
  static std::vector<json> GenerateSessionConfigs(int count = 10);

  /**
   * Generate concurrent request scenarios.
   */
  static std::vector<std::pair<std::string, json>> GenerateConcurrentScenarios();

  /**
   * Generate error test cases.
   */
  static std::vector<std::pair<json, int>> GenerateErrorTestCases();

  /**
   * Generate performance test data.
   */
  static std::vector<json> GeneratePerformanceTestData(int size);
};

/**
 * Test assertions and validation.
 */
class TestAssertions {
public:
  static bool AssertEquals(const json& expected, const json& actual, const std::string& message = "");
  static bool AssertTrue(bool condition, const std::string& message = "");
  static bool AssertFalse(bool condition, const std::string& message = "");
  static bool AssertContains(const json& container, const std::string& key, const std::string& message = "");
  static bool AssertResponseCode(int expected, int actual, const std::string& message = "");
  static bool AssertResponseTime(double actual_ms, double max_expected_ms, const std::string& message = "");

private:
  static void LogAssertion(bool passed, const std::string& message);
};

/**
 * Integration test main entry point.
 */
int RunDaemonIntegrationTestSuite();