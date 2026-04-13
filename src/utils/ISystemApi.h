#pragma once

#include "utils/System.h"

#include <csignal>
#include <optional>
#include <string>
#include <string_view>

namespace utils {

/**
 * Abstract interface for OS/system operations.
 * Enables dependency injection and mocking for unit tests.
 */
class ISystemApi {
public:
  virtual ~ISystemApi() = default;

  virtual std::optional<ProcessInfo> FindProcessByPid(pid_t pid) = 0;
  virtual std::optional<ProcessInfo>
  FindProcessByName(std::string_view name) = 0;
  virtual int KillProcess(pid_t pid, int signal) = 0;
  virtual std::string ReadFileToBuffer(std::string_view path) = 0;
  virtual void SleepForMilliseconds(int ms) = 0;
};

} // namespace utils
