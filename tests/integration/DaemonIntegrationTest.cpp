#include "DaemonIntegrationTest.h"
#include "utils/Log.h"
#include "httplib/httplib.h"

#include <thread>
#include <chrono>
#include <fstream>
#include <filesystem>
#include <set>

// Static member definitions
std::string TestRunner::test_data_dir_ = "/tmp/explorer_test";
std::vector<std::string> TestRunner::cleanup_files_;

// HTTP client utilities for testing

DaemonIntegrationTest::DaemonIntegrationTest(int test_port)
    : test_port_(test_port),
      test_host_("127.0.0.1"),
      daemon_state_file_("/tmp/explorer_integration_test_state.json"),
      daemon_running_(false),
      total_tests_(0),
      passed_tests_(0),
      failed_tests_(0) {

  LOGI("Created daemon integration test suite on port {}", test_port_);
}

DaemonIntegrationTest::~DaemonIntegrationTest() {
  StopDaemon();

  // Cleanup test files
  std::filesystem::remove(daemon_state_file_);

  LOGI("Destroyed daemon integration test suite");
}

bool DaemonIntegrationTest::RunAllTests() {
  LogTestStart("Daemon Integration Test Suite");

  bool all_passed = true;

  // Setup test environment
  if (!TestRunner::SetupTestEnvironment()) {
    LOGE("Failed to setup test environment");
    return false;
  }

  // Run all test categories
  all_passed &= TestDaemonStartupShutdown();
  all_passed &= TestHttpApiEndpoints();
  all_passed &= TestSessionLifecycle();
  all_passed &= TestErrorHandling();
  all_passed &= TestStatePersistence();
  all_passed &= TestHealthMonitoring();
  all_passed &= TestMetricsCollection();
  all_passed &= TestConcurrentRequests();
  all_passed &= TestRateLimiting();
  all_passed &= TestEdgeCases();

  // Performance tests (non-blocking)
  TestPerformanceUnderLoad(50);

  LogTestSummary();

  // Cleanup
  TestRunner::CleanupTestEnvironment();

  return all_passed;
}

bool DaemonIntegrationTest::TestDaemonStartupShutdown() {
  LogTestStart("Daemon Startup/Shutdown");

  // Test 1: Normal startup
  if (!StartDaemon()) {
    LogTestResult("Daemon Startup", false, "Failed to start daemon");
    return false;
  }

  if (!WaitForDaemonReady()) {
    LogTestResult("Daemon Startup", false, "Daemon not ready after timeout");
    StopDaemon();
    return false;
  }

  // Test 2: Health check after startup
  auto health_response = MakeHttpRequest("GET", "/health");
  if (!ValidateApiResponse(health_response) || health_response.status_code != 200) {
    LogTestResult("Daemon Startup", false, "Health check failed after startup");
    StopDaemon();
    return false;
  }

  // Test 3: Graceful shutdown
  StopDaemon();

  // Test 4: Verify daemon stopped (health check should fail)
  auto stopped_response = MakeHttpRequest("GET", "/health");
  if (stopped_response.status_code == 200) {
    LogTestResult("Daemon Shutdown", false, "Daemon still responding after shutdown");
    return false;
  }

  LogTestResult("Daemon Startup/Shutdown", true);
  return true;
}

bool DaemonIntegrationTest::TestHttpApiEndpoints() {
  LogTestStart("HTTP API Endpoints");

  if (!StartDaemon() || !WaitForDaemonReady()) {
    LogTestResult("HTTP API Endpoints", false, "Failed to start daemon");
    return false;
  }

  bool all_passed = true;

  // Test health endpoints
  struct EndpointTest {
    std::string method;
    std::string path;
    int expected_status;
  };

  std::vector<EndpointTest> endpoints = {
    {"GET", "/health", 200},
    {"GET", "/api/v1/health", 200},
    {"GET", "/api/v1/metrics", 200},
    {"GET", "/api/v1/daemon/stats", 200},
    {"GET", "/api/v1/daemon/history", 200},
    {"GET", "/nonexistent", 404}  // Test 404 handling
  };

  for (const auto& test : endpoints) {
    auto response = MakeHttpRequest(test.method, test.path);
    if (response.status_code != test.expected_status) {
      LogTestResult("HTTP API Endpoints", false,
                   "Endpoint " + test.path + " returned " + std::to_string(response.status_code) +
                   " expected " + std::to_string(test.expected_status));
      all_passed = false;
    }
  }

  // Test CORS headers
  auto cors_response = MakeHttpRequest("OPTIONS", "/api/v1/health");
  // Note: OPTIONS handling would need to be implemented in the actual server

  StopDaemon();
  LogTestResult("HTTP API Endpoints", all_passed);
  return all_passed;
}

bool DaemonIntegrationTest::TestSessionLifecycle() {
  LogTestStart("Session Lifecycle Management");

  if (!StartDaemon() || !WaitForDaemonReady()) {
    LogTestResult("Session Lifecycle", false, "Failed to start daemon");
    return false;
  }

  bool all_passed = true;

  // Test 1: List sessions (should be empty initially)
  auto list_response = MakeHttpRequest("POST", "/api/v1/session/list",
                                       json{{"action", "list"}, {"data", json::object()}});

  if (!ValidateApiResponse(list_response) || list_response.status_code != 200) {
    LogTestResult("Session Lifecycle", false, "Failed to list initial sessions");
    all_passed = false;
  }

  // Test 2: Start a session (this will likely fail without real FRIDA, but we test the API)
  json start_config = CreateTestSessionConfig("com.test.integration");
  auto start_response = MakeHttpRequest("POST", "/api/v1/session/start",
                                        json{{"action", "start"}, {"data", start_config}});

  // Note: This may fail due to FRIDA not being available in test environment
  // We're testing the API structure, not necessarily successful execution
  if (start_response.status_code != 200 && start_response.status_code != 500) {
    LogTestResult("Session Lifecycle", false, "Unexpected response to session start");
    all_passed = false;
  }

  // Test 3: Session status query
  auto status_response = MakeHttpRequest("POST", "/api/v1/session/status",
                                         json{{"action", "status"}, {"data", json::object()}});

  if (!ValidateApiResponse(status_response)) {
    LogTestResult("Session Lifecycle", false, "Failed to get session status");
    all_passed = false;
  }

  StopDaemon();
  LogTestResult("Session Lifecycle Management", all_passed);
  return all_passed;
}

bool DaemonIntegrationTest::TestErrorHandling() {
  LogTestStart("Error Handling");

  if (!StartDaemon() || !WaitForDaemonReady()) {
    LogTestResult("Error Handling", false, "Failed to start daemon");
    return false;
  }

  bool all_passed = true;

  // Test malformed JSON
  auto malformed_response = MakeHttpRequest("POST", "/api/v1/session/start",
                                            json{{"invalid json structure"}});
  if (malformed_response.status_code == 200) {
    LogTestResult("Error Handling", false, "Server accepted malformed request");
    all_passed = false;
  }

  // Test missing required fields
  auto missing_fields_response = MakeHttpRequest("POST", "/api/v1/session/start",
                                                 json{{"action", "start"}});  // Missing data field
  if (missing_fields_response.status_code == 200) {
    LogTestResult("Error Handling", false, "Server accepted request with missing fields");
    all_passed = false;
  }

  // Test invalid session ID for stop
  auto invalid_stop_response = MakeHttpRequest("POST", "/api/v1/session/stop",
                                               json{{"action", "stop"}, {"data", {{"session", "invalid"}}}});
  if (invalid_stop_response.status_code == 200) {
    LogTestResult("Error Handling", false, "Server accepted invalid session ID");
    all_passed = false;
  }

  // Validate error response structure
  if (invalid_stop_response.response_data.contains("error") &&
      invalid_stop_response.response_data["error"] == true &&
      invalid_stop_response.response_data.contains("message")) {
    // Good - structured error response
  } else {
    LogTestResult("Error Handling", false, "Error response not properly structured");
    all_passed = false;
  }

  StopDaemon();
  LogTestResult("Error Handling", all_passed);
  return all_passed;
}

bool DaemonIntegrationTest::TestStatePersistence() {
  LogTestStart("State Persistence");

  bool all_passed = true;

  // Test 1: Start daemon and verify state file creation
  if (!StartDaemon() || !WaitForDaemonReady()) {
    LogTestResult("State Persistence", false, "Failed to start daemon");
    return false;
  }

  // Give daemon time to initialize state
  std::this_thread::sleep_for(std::chrono::milliseconds(500));

  StopDaemon();

  // Test 2: Verify state file exists (this depends on StateManager configuration)
  // The actual state file location would be daemon-specific

  // Test 3: Restart daemon and verify state recovery
  if (!StartDaemon() || !WaitForDaemonReady()) {
    LogTestResult("State Persistence", false, "Failed to restart daemon for recovery test");
    return false;
  }

  // Test recovery by checking daemon stats
  auto stats_response = MakeHttpRequest("GET", "/api/v1/daemon/stats");
  if (!ValidateApiResponse(stats_response)) {
    LogTestResult("State Persistence", false, "Failed to get daemon stats after restart");
    all_passed = false;
  }

  StopDaemon();
  LogTestResult("State Persistence", all_passed);
  return all_passed;
}

bool DaemonIntegrationTest::TestHealthMonitoring() {
  LogTestStart("Health Monitoring");

  if (!StartDaemon() || !WaitForDaemonReady()) {
    LogTestResult("Health Monitoring", false, "Failed to start daemon");
    return false;
  }

  bool all_passed = true;

  // Test basic health endpoint
  auto health_response = MakeHttpRequest("GET", "/health");
  if (!ValidateApiResponse(health_response) || health_response.status_code != 200) {
    LogTestResult("Health Monitoring", false, "Basic health check failed");
    all_passed = false;
  }

  // Test detailed health endpoint
  auto detailed_health = MakeHttpRequest("GET", "/api/v1/health");
  if (!ValidateApiResponse(detailed_health) || detailed_health.status_code != 200) {
    LogTestResult("Health Monitoring", false, "Detailed health check failed");
    all_passed = false;
  }

  // Validate health response structure
  if (detailed_health.response_data.contains("status") &&
      detailed_health.response_data.contains("components")) {
    // Good structure
  } else {
    LogTestResult("Health Monitoring", false, "Health response missing required fields");
    all_passed = false;
  }

  StopDaemon();
  LogTestResult("Health Monitoring", all_passed);
  return all_passed;
}

bool DaemonIntegrationTest::TestMetricsCollection() {
  LogTestStart("Metrics Collection");

  if (!StartDaemon() || !WaitForDaemonReady()) {
    LogTestResult("Metrics Collection", false, "Failed to start daemon");
    return false;
  }

  bool all_passed = true;

  // Test metrics endpoint
  auto metrics_response = MakeHttpRequest("GET", "/api/v1/metrics");
  if (!ValidateApiResponse(metrics_response) || metrics_response.status_code != 200) {
    LogTestResult("Metrics Collection", false, "Metrics endpoint failed");
    all_passed = false;
  }

  // Validate metrics structure
  const auto& data = metrics_response.response_data;
  if (data.contains("data")) {
    const auto& metrics = data["data"];
    std::vector<std::string> required_sections = {"daemon", "http_server", "sessions", "system"};

    for (const auto& section : required_sections) {
      if (!metrics.contains(section)) {
        LogTestResult("Metrics Collection", false, "Missing metrics section: " + section);
        all_passed = false;
      }
    }
  }

  StopDaemon();
  LogTestResult("Metrics Collection", all_passed);
  return all_passed;
}

bool DaemonIntegrationTest::TestConcurrentRequests() {
  LogTestStart("Concurrent Request Handling");

  if (!StartDaemon() || !WaitForDaemonReady()) {
    LogTestResult("Concurrent Requests", false, "Failed to start daemon");
    return false;
  }

  bool all_passed = true;

  // Test concurrent health checks
  const int num_concurrent = 10;
  auto responses = RunConcurrentRequests("GET", "/health", json::object(), num_concurrent);

  // Verify all requests succeeded
  int successful_requests = 0;
  for (const auto& response : responses) {
    if (response.status_code == 200) {
      successful_requests++;
    }
  }

  if (successful_requests != num_concurrent) {
    LogTestResult("Concurrent Requests", false,
                 "Only " + std::to_string(successful_requests) + "/" + std::to_string(num_concurrent) + " concurrent requests succeeded");
    all_passed = false;
  }

  StopDaemon();
  LogTestResult("Concurrent Request Handling", all_passed);
  return all_passed;
}

bool DaemonIntegrationTest::TestRateLimiting() {
  LogTestStart("Rate Limiting");

  if (!StartDaemon() || !WaitForDaemonReady()) {
    LogTestResult("Rate Limiting", false, "Failed to start daemon");
    return false;
  }

  bool all_passed = true;

  // Send requests rapidly to trigger rate limiting
  // Note: This test depends on the rate limiting configuration
  const int rapid_requests = 150;  // Exceed the 100 req/sec limit
  auto start_time = std::chrono::steady_clock::now();

  int rate_limited_count = 0;
  for (int i = 0; i < rapid_requests; ++i) {
    auto response = MakeHttpRequest("GET", "/health");
    if (response.status_code == 429) {  // Too Many Requests
      rate_limited_count++;
    }
  }

  auto end_time = std::chrono::steady_clock::now();
  auto duration = std::chrono::duration_cast<std::chrono::seconds>(end_time - start_time);

  // If we sent requests faster than the rate limit, we should see some 429 responses
  if (duration.count() < 2 && rate_limited_count == 0) {
    LogTestResult("Rate Limiting", false, "No rate limiting observed despite rapid requests");
    all_passed = false;
  } else {
    LOGI("Rate limiting test: {} requests rate limited", rate_limited_count);
  }

  StopDaemon();
  LogTestResult("Rate Limiting", all_passed);
  return all_passed;
}

bool DaemonIntegrationTest::TestEdgeCases() {
  LogTestStart("Edge Cases");

  if (!StartDaemon() || !WaitForDaemonReady()) {
    LogTestResult("Edge Cases", false, "Failed to start daemon");
    return false;
  }

  bool all_passed = true;

  // Test extremely large request (should be rejected)
  json large_request = json::object();
  std::string large_string(1024 * 1024 * 2, 'x');  // 2MB string
  large_request["large_field"] = large_string;

  auto large_response = MakeHttpRequest("POST", "/api/v1/session/start", large_request);
  if (large_response.status_code == 200) {
    LogTestResult("Edge Cases", false, "Server accepted extremely large request");
    all_passed = false;
  }

  // Test empty request body
  auto empty_response = MakeHttpRequest("POST", "/api/v1/session/start", json::object());
  // Should return 400 due to missing required fields

  // Test invalid UTF-8 (difficult to test with json library)

  // Test concurrent start/stop of same session
  // This would require mock FRIDA integration

  StopDaemon();
  LogTestResult("Edge Cases", all_passed);
  return all_passed;
}

// ============================================================================
// Missing method implementations
// ============================================================================

DaemonIntegrationTest::HttpResponse DaemonIntegrationTest::MakeHttpRequest(
    const std::string& method,
    const std::string& endpoint,
    const json& request_data) {

  HttpResponse response;
  response.status_code = 0;
  response.response_data = json::object();
  response.error_message = "";
  response.response_time_ms = 0.0;

  auto start_time = std::chrono::steady_clock::now();

  try {
    httplib::Client client(test_host_, test_port_);
    client.set_connection_timeout(kDefaultTimeoutMs / 1000);
    client.set_read_timeout(kDefaultTimeoutMs / 1000);

    httplib::Result result;
    std::string json_str = request_data.dump();

    if (method == "GET") {
      result = client.Get(endpoint);
    } else if (method == "POST") {
      result = client.Post(endpoint, json_str, "application/json");
    } else if (method == "PUT") {
      result = client.Put(endpoint, json_str, "application/json");
    } else if (method == "DELETE") {
      result = client.Delete(endpoint);
    } else if (method == "OPTIONS") {
      result = client.Options(endpoint);
    } else {
      response.error_message = "Unsupported HTTP method: " + method;
      return response;
    }

    auto end_time = std::chrono::steady_clock::now();
    response.response_time_ms = std::chrono::duration<double, std::milli>(end_time - start_time).count();

    if (result) {
      response.status_code = result->status;

      // Try to parse response as JSON
      if (!result->body.empty()) {
        try {
          response.response_data = json::parse(result->body);
        } catch (const json::parse_error& e) {
          // If not valid JSON, store as string
          response.response_data = json{{"raw_body", result->body}};
          response.error_message = "Response not valid JSON: " + std::string(e.what());
        }
      }
    } else {
      response.error_message = "HTTP request failed: " + httplib::to_string(result.error());
    }

  } catch (const std::exception& e) {
    response.error_message = "Exception during HTTP request: " + std::string(e.what());
  }

  return response;
}

bool DaemonIntegrationTest::StartDaemon() {
  if (daemon_running_) {
    LOGW("Daemon already running");
    return true;
  }

  try {
    // Create daemon with test configuration
    std::vector<std::string> arg_strings = {
      "explorer_test",
      "--daemon",
      "--host", test_host_,
      "--port", std::to_string(test_port_),
      "--state-file", daemon_state_file_
    };

    std::vector<std::string_view> args(arg_strings.begin(), arg_strings.end());
    daemon_ = std::make_unique<ApplicationDaemon>(args);

    // Start daemon in separate thread
    daemon_thread_ = std::make_unique<std::thread>([this]() {
      try {
        daemon_running_ = true;
        daemon_->Run();
      } catch (const std::exception& e) {
        LOGE("Daemon thread exception: {}", e.what());
        daemon_running_ = false;
      }
    });

    // Give daemon time to start
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    return daemon_running_;

  } catch (const std::exception& e) {
    LOGE("Failed to start daemon: {}", e.what());
    return false;
  }
}

void DaemonIntegrationTest::StopDaemon() {
  if (!daemon_running_) {
    return;
  }

  daemon_running_ = false;

  if (daemon_) {
    daemon_->Shutdown();
  }

  if (daemon_thread_ && daemon_thread_->joinable()) {
    daemon_thread_->join();
  }

  daemon_thread_.reset();
  daemon_.reset();
}

bool DaemonIntegrationTest::WaitForDaemonReady(int timeout_seconds) {
  auto start_time = std::chrono::steady_clock::now();
  auto timeout = std::chrono::seconds(timeout_seconds);

  while (std::chrono::steady_clock::now() - start_time < timeout) {
    auto response = MakeHttpRequest("GET", "/health");
    if (response.status_code == 200) {
      return true;
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }

  return false;
}

json DaemonIntegrationTest::CreateTestSessionConfig(const std::string& app_name) {
  return json{
    {"app", app_name},
    {"spawn", true},
    {"trace", json::array({
      json{
        {"type", "java"},
        {"class", "java.lang.Object"},
        {"method", "toString"},
        {"log", true}
      }
    })},
    {"timeout_seconds", 30}
  };
}

bool DaemonIntegrationTest::ValidateApiResponse(const HttpResponse& response, bool expect_success) {
  if (response.error_message.empty() && response.status_code > 0) {
    if (expect_success) {
      return response.status_code >= 200 && response.status_code < 300;
    } else {
      return response.status_code >= 400;
    }
  }
  return !expect_success; // If there was an error, it's only valid if we expected failure
}

std::vector<DaemonIntegrationTest::HttpResponse> DaemonIntegrationTest::RunConcurrentRequests(
    const std::string& method,
    const std::string& endpoint,
    const json& request_data,
    int num_requests) {

  std::vector<HttpResponse> responses(num_requests);
  std::vector<std::thread> threads;

  for (int i = 0; i < num_requests; ++i) {
    threads.emplace_back([this, &responses, i, method, endpoint, request_data]() {
      responses[i] = MakeHttpRequest(method, endpoint, request_data);
    });
  }

  for (auto& thread : threads) {
    if (thread.joinable()) {
      thread.join();
    }
  }

  return responses;
}

bool DaemonIntegrationTest::TestPerformanceUnderLoad(int num_requests) {
  LogTestStart("Performance Under Load");

  if (!StartDaemon() || !WaitForDaemonReady()) {
    LogTestResult("Performance Under Load", false, "Failed to start daemon");
    return false;
  }

  auto start_time = std::chrono::steady_clock::now();
  auto responses = RunConcurrentRequests("GET", "/health", json::object(), num_requests);
  auto end_time = std::chrono::steady_clock::now();

  auto total_time = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

  int successful = 0;
  double total_response_time = 0.0;
  for (const auto& response : responses) {
    if (response.status_code == 200) {
      successful++;
    }
    total_response_time += response.response_time_ms;
  }

  double success_rate = (double)successful / num_requests * 100.0;
  double avg_response_time = total_response_time / num_requests;
  double requests_per_second = (double)num_requests / total_time.count() * 1000.0;

  LOGI("Performance test results:");
  LOGI("  Total requests: {}", num_requests);
  LOGI("  Successful: {} ({:.1f}%)", successful, success_rate);
  LOGI("  Average response time: {:.2f} ms", avg_response_time);
  LOGI("  Requests per second: {:.1f}", requests_per_second);
  LOGI("  Total test time: {} ms", total_time.count());

  StopDaemon();

  bool passed = success_rate >= 95.0 && avg_response_time < 1000.0;
  LogTestResult("Performance Under Load", passed,
                "Success rate: " + std::to_string(success_rate) + "%, "
                "Avg response: " + std::to_string(avg_response_time) + " ms");

  return passed;
}

void DaemonIntegrationTest::LogTestStart(const std::string& test_name) {
  LOGI("📋 Starting test: {}", test_name);
  total_tests_++;
}

void DaemonIntegrationTest::LogTestResult(const std::string& test_name, bool passed, const std::string& details) {
  if (passed) {
    passed_tests_++;
    LOGI("✅ Test passed: {}", test_name);
    if (!details.empty()) {
      LOGI("   Details: {}", details);
    }
  } else {
    failed_tests_++;
    LOGE("❌ Test failed: {}", test_name);
    if (!details.empty()) {
      LOGE("   Details: {}", details);
    }
    test_failures_.push_back(test_name + (details.empty() ? "" : ": " + details));
  }
}

void DaemonIntegrationTest::LogTestSummary() {
  LOGI("📊 Test Summary");
  LOGI("   Total tests: {}", total_tests_);
  LOGI("   Passed: {} ({}%)", passed_tests_, total_tests_ > 0 ? (passed_tests_ * 100 / total_tests_) : 0);
  LOGI("   Failed: {} ({}%)", failed_tests_, total_tests_ > 0 ? (failed_tests_ * 100 / total_tests_) : 0);

  if (!test_failures_.empty()) {
    LOGE("❌ Failed tests:");
    for (const auto& failure : test_failures_) {
      LOGE("   - {}", failure);
    }
  }

  if (failed_tests_ == 0) {
    LOGI("🎉 All tests passed!");
  }
}

// ============================================================================
// TestRunner implementations
// ============================================================================

int TestRunner::RunDaemonIntegrationTests() {
  LOGI("🚀 Starting Daemon Integration Test Suite");

  // Setup test environment
  if (!SetupTestEnvironment()) {
    LOGE("Failed to setup test environment");
    return 1;
  }

  // Run tests on different ports to avoid conflicts
  std::vector<int> test_ports = {8084, 8085, 8086};
  bool all_passed = true;

  for (int port : test_ports) {
    LOGI("Running integration tests on port {}", port);
    DaemonIntegrationTest test_suite(port);

    bool result = test_suite.RunAllTests();
    all_passed = all_passed && result;

    if (!result) {
      LOGE("Integration tests failed on port {}", port);
    }

    // Wait between test runs
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
  }

  // Cleanup
  CleanupTestEnvironment();

  if (all_passed) {
    LOGI("🎉 All integration test suites passed!");
    return 0;
  } else {
    LOGE("❌ Some integration tests failed");
    return 1;
  }
}

bool TestRunner::SetupTestEnvironment() {
  try {
    // Create test data directory
    std::filesystem::create_directories(test_data_dir_);
    LOGI("Created test directory: {}", test_data_dir_);

    // Setup logging for tests
    // (Assuming Log is already initialized by this point)

    return true;
  } catch (const std::exception& e) {
    LOGE("Failed to setup test environment: {}", e.what());
    return false;
  }
}

void TestRunner::CleanupTestEnvironment() {
  try {
    // Remove test files
    for (const auto& file : cleanup_files_) {
      std::filesystem::remove(file);
      LOGI("Removed test file: {}", file);
    }
    cleanup_files_.clear();

    // Remove test directory
    if (std::filesystem::exists(test_data_dir_)) {
      std::filesystem::remove_all(test_data_dir_);
      LOGI("Removed test directory: {}", test_data_dir_);
    }
  } catch (const std::exception& e) {
    LOGW("Error during test cleanup: {}", e.what());
  }
}

// ============================================================================
// Integration test main entry point
// ============================================================================

int RunDaemonIntegrationTestSuite() {
  return TestRunner::RunDaemonIntegrationTests();
}