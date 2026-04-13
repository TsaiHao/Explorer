#pragma once

#include <gmock/gmock.h>

#include "utils/ISystemApi.h"

namespace utils {

class MockSystemApi : public ISystemApi {
public:
  MOCK_METHOD(std::optional<ProcessInfo>, FindProcessByPid, (pid_t),
              (override));
  MOCK_METHOD(std::optional<ProcessInfo>, FindProcessByName,
              (std::string_view), (override));
  MOCK_METHOD(int, KillProcess, (pid_t, int), (override));
  MOCK_METHOD(std::string, ReadFileToBuffer, (std::string_view), (override));
  MOCK_METHOD(void, SleepForMilliseconds, (int), (override));
};

} // namespace utils
