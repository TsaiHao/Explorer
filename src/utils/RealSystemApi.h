#pragma once

#include "ISystemApi.h"

namespace utils {

/**
 * Concrete ISystemApi that forwards to the real system functions.
 */
class RealSystemApi : public ISystemApi {
public:
  std::optional<ProcessInfo> FindProcessByPid(pid_t pid) override {
    return utils::FindProcessByPid(pid);
  }

  std::optional<ProcessInfo>
  FindProcessByName(std::string_view name) override {
    return utils::FindProcessByName(name);
  }

  int KillProcess(pid_t pid, int signal) override {
    return kill(pid, signal);
  }

  std::string ReadFileToBuffer(std::string_view path) override {
    return utils::ReadFileToBuffer(path);
  }

  void SleepForMilliseconds(int ms) override {
    utils::SleepForMilliseconds(ms);
  }
};

} // namespace utils
