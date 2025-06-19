//
// Created by Hao, Zaijun on 2025/6/16.
//

#include "utils/Subprocess.h"
#include <cassert>
#include <chrono>
#include <iomanip>
#include <iostream>
#include <thread>

using utils::Subprocess;

namespace {
const char *kGreen = "\033[32m";
const char *kRed = "\033[31m";
const char *kYellow = "\033[33m";
const char *kBlue = "\033[34m";
const char *kReset = "\033[0m";

struct TestResult {
  int passed = 0;
  int failed = 0;

  void RecordPass(const std::string &testName) {
    passed++;
    std::cout << kGreen << "[PASS] " << kReset << testName << '\n';
  }

  void RecordFail(const std::string &testName, const std::string &reason) {
    failed++;
    std::cout << kRed << "[FAIL] " << kReset << testName << " - " << reason
              << '\n';
  }

  void PrintSummary() const {
    std::cout << "\n" << kBlue << "===== Test Summary =====" << kReset << '\n';
    std::cout << "Total tests: " << (passed + failed) << '\n';
    std::cout << kGreen << "Passed: " << passed << kReset << '\n';
    std::cout << kRed << "Failed: " << failed << kReset << '\n';
  }
};

TestResult g_results;

void DebugLog(const std::string &message) {
  auto now = std::chrono::system_clock::now();
  auto time_t = std::chrono::system_clock::to_time_t(now);
  auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                now.time_since_epoch()) %
            1000;

  std::cout << kYellow << "["
            << std::put_time(std::localtime(&time_t), "%H:%M:%S");
  std::cout << "." << std::setfill('0') << std::setw(3) << ms.count() << "] "
            << kReset << message << '\n';
}

void TestBasicEcho() {
  std::cout << "\n"
            << kBlue << "=== Test 1: Basic Echo Command ===" << kReset << '\n';

  try {
    Subprocess proc(DebugLog);

    Status spawn_result =
        proc.Spawn("echo", {"Hello", "World", "from", "test!"});
    if (!spawn_result.Ok()) {
      g_results.RecordFail("TestBasicEcho", "Failed to spawn process");
      return;
    }

    std::cout << "Process spawned with PID: " << proc.GetPid() << '\n';

    auto result = proc.Wait();

    std::cout << "Exit status: " << result.exitStatus << '\n';
    std::cout << "Stdout: [" << result.stdout << "]" << '\n';
    std::cout << "Stderr: [" << result.stderr << "]" << '\n';

    if (result.exitStatus == 0 && result.stdout == "Hello World from test!\n" &&
        result.stderr.empty()) {
      g_results.RecordPass("TestBasicEcho");
    } else {
      g_results.RecordFail("TestBasicEcho", "Unexpected output or exit status");
    }

  } catch (const std::exception &e) {
    g_results.RecordFail("TestBasicEcho",
                         std::string("Exception: ") + e.what());
  }
}

void TestStderrCapture() {
  std::cout << "\n"
            << kBlue << "=== Test 2: Stderr Capture ===" << kReset << '\n';

  try {
    Subprocess proc(DebugLog);

    Status spawn_result = proc.Spawn(
        "sh",
        {"-c", "echo 'This goes to stdout'; echo 'This goes to stderr' >&2"});

    if (!spawn_result.Ok()) {
      g_results.RecordFail("TestStderrCapture", "Failed to spawn process");
      return;
    }

    auto result = proc.Wait();

    std::cout << "Exit status: " << result.exitStatus << '\n';
    std::cout << "Stdout: [" << result.stdout << "]" << '\n';
    std::cout << "Stderr: [" << result.stderr << "]" << '\n';

    if (result.exitStatus == 0 &&
        result.stdout.find("stdout") != std::string::npos &&
        result.stderr.find("stderr") != std::string::npos) {
      g_results.RecordPass("TestStderrCapture");
    } else {
      g_results.RecordFail("TestStderrCapture",
                           "Failed to capture both streams");
    }

  } catch (const std::exception &e) {
    g_results.RecordFail("TestStderrCapture",
                         std::string("Exception: ") + e.what());
  }
}

void TestTimeout() {
  std::cout << "\n"
            << kBlue << "=== Test 3: Process Timeout ===" << kReset << '\n';

  try {
    Subprocess proc(DebugLog);

    Status spawn_result =
        proc.Spawn("sh", {"-c", "sleep 5; echo 'Should not see this'"});

    if (!spawn_result.Ok()) {
      g_results.RecordFail("TestTimeout", "Failed to spawn process");
      return;
    }

    std::cout << "Starting process that sleeps for 5 seconds..." << '\n';
    std::cout << "Will timeout after 1 second..." << '\n';

    auto result = proc.Wait(1000);

    std::cout << "Timed out: " << (result.timedOut ? "YES" : "NO") << '\n';
    std::cout << "Exit status: " << result.exitStatus << '\n';

    if (result.timedOut && result.stdout.empty()) {
      g_results.RecordPass("TestTimeout");
    } else {
      g_results.RecordFail("TestTimeout",
                           "Process did not timeout as expected");
    }

  } catch (const std::exception &e) {
    g_results.RecordFail("TestTimeout", std::string("Exception: ") + e.what());
  }
}

void TestAsyncExecution() {
  std::cout << "\n"
            << kBlue << "=== Test 4: Async Execution ===" << kReset << '\n';

  try {
    Subprocess proc(DebugLog);

    Status spawn_result = proc.Spawn(
        "sh", {"-c", "for i in 1 2 3; do echo \"Line $i\"; sleep 0.5; done"});

    if (!spawn_result.Ok()) {
      g_results.RecordFail("TestAsyncExecution", "Failed to spawn process");
      return;
    }

    std::cout << "Process started, checking status..." << '\n';

    int checks = 0;
    while (proc.IsRunning() && checks < 10) {
      std::cout << "Check " << (checks + 1)
                << ": Process is running (PID: " << proc.GetPid() << ")"
                << '\n';

      std::string partial_out = proc.GetStdoutBuffer();
      if (!partial_out.empty()) {
        std::cout << "Partial stdout so far: [" << partial_out << "]" << '\n';
      }

      std::this_thread::sleep_for(std::chrono::milliseconds(400));
      checks++;
    }

    auto result = proc.Wait();
    std::cout << "Final stdout: [" << result.stdout << "]" << '\n';

    if (result.exitStatus == 0 &&
        result.stdout.find("Line 1") != std::string::npos &&
        result.stdout.find("Line 3") != std::string::npos) {
      g_results.RecordPass("TestAsyncExecution");
    } else {
      std::cout << "Exit status: " << result.exitStatus << '\n';
      std::cout << "Stderr: [" << result.stderr << "]" << '\n';
      std::cout << "Full stdout: [" << result.stdout << "]" << '\n';
      std::cout << "find(\"Line 1\") result: "
                << (result.stdout.find("Line 1") != std::string::npos) << '\n';
      std::cout << "find(\"Line 3\") result: "
                << (result.stdout.find("Line 3") != std::string::npos) << '\n';
      g_results.RecordFail("TestAsyncExecution", "Unexpected output");
    }

  } catch (const std::exception &e) {
    g_results.RecordFail("TestAsyncExecution",
                         std::string("Exception: ") + e.what());
  }
}

void TestTermination() {
  std::cout << "\n"
            << kBlue << "=== Test 5: Process Termination ===" << kReset << '\n';

  try {
    Subprocess proc(DebugLog);

    Status spawn_result = proc.Spawn(
        "sh", {"-c", "trap 'echo Got SIGTERM' TERM; echo Started; sleep 30"});

    if (!spawn_result.Ok()) {
      g_results.RecordFail("TestTermination", "Failed to spawn process");
      return;
    }

    std::cout << "Process started, waiting 1 second..." << '\n';
    std::this_thread::sleep_for(std::chrono::seconds(1));

    if (!proc.IsRunning()) {
      g_results.RecordFail("TestTermination",
                           "Process not running after spawn");
      return;
    }

    std::cout << "Sending SIGTERM to process..." << '\n';
    bool term_result = proc.Terminate(15); // SIGTERM

    if (!term_result) {
      g_results.RecordFail("TestTermination", "Failed to send signal");
      return;
    }

    auto result = proc.Wait(2000);

    std::cout << "Exit status: " << result.exitStatus << '\n';
    std::cout << "Stdout: [" << result.stdout << "]" << '\n';

    if (result.exitStatus < 0 &&
        result.stdout.find("Started") != std::string::npos) {
      g_results.RecordPass("TestTermination");
    } else {
      g_results.RecordFail("TestTermination",
                           "Process not terminated properly");
    }

  } catch (const std::exception &e) {
    g_results.RecordFail("TestTermination",
                         std::string("Exception: ") + e.what());
  }
}

void TestInvalidCommand() {
  std::cout << "\n"
            << kBlue << "=== Test 6: Invalid Command ===" << kReset << '\n';

  try {
    Subprocess proc(DebugLog);

    Status spawn_result = proc.Spawn("/this/does/not/exist", {"arg1", "arg2"});

    if (!spawn_result.Ok()) {
      g_results.RecordPass("TestInvalidCommand");
      return;
    }

    auto result = proc.Wait();

    std::cout << "Exit status: " << result.exitStatus << '\n';
    std::cout << "Stderr: [" << result.stderr << "]" << '\n';

    if (result.exitStatus != 0 || !result.stderr.empty()) {
      g_results.RecordPass("TestInvalidCommand");
    } else {
      g_results.RecordFail("TestInvalidCommand",
                           "No error for invalid command");
    }

  } catch (const std::exception &e) {
    g_results.RecordFail("TestInvalidCommand",
                         std::string("Exception: ") + e.what());
  }
}

void TestMultipleProcesses() {
  std::cout << "\n"
            << kBlue
            << "=== Test 7: Multiple Sequential Processes ===" << kReset
            << '\n';

  try {
    Subprocess proc1(DebugLog);
    Subprocess proc2(DebugLog);

    if (!proc1.Spawn("echo", {"First process"}).Ok()) {
      g_results.RecordFail("TestMultipleProcesses",
                           "Failed to spawn first process");
      return;
    }

    auto result1 = proc1.Wait();
    std::cout << "Process 1 output: [" << result1.stdout << "]" << '\n';

    if (!proc2.Spawn("echo", {"Second process"}).Ok()) {
      g_results.RecordFail("TestMultipleProcesses",
                           "Failed to spawn second process");
      return;
    }

    auto result2 = proc2.Wait();
    std::cout << "Process 2 output: [" << result2.stdout << "]" << '\n';

    if (result1.exitStatus == 0 && result2.exitStatus == 0 &&
        result1.stdout.find("First") != std::string::npos &&
        result2.stdout.find("Second") != std::string::npos) {
      g_results.RecordPass("TestMultipleProcesses");
    } else {
      g_results.RecordFail("TestMultipleProcesses", "Unexpected outputs");
    }

  } catch (const std::exception &e) {
    g_results.RecordFail("TestMultipleProcesses",
                         std::string("Exception: ") + e.what());
  }
}

} // namespace

int main() {
  std::cout << kBlue << "========================================" << kReset
            << '\n';
  std::cout << kBlue << "   Subprocess Class Debug Test Suite    " << kReset
            << '\n';
  std::cout << kBlue << "========================================" << kReset
            << '\n';
  std::cout << "Running on: " << (sizeof(void *) == 4 ? "32-bit" : "64-bit")
            << " system" << '\n';
  std::cout << '\n';

  TestBasicEcho();
  TestStderrCapture();
  TestTimeout();
  TestAsyncExecution();
  TestTermination();
  TestInvalidCommand();
  TestMultipleProcesses();

  g_results.PrintSummary();

  return (g_results.failed > 0) ? 1 : 0;
}