#pragma once

#include <array>
#include <atomic>
#include <functional>
#include <string>
#include <vector>

#include "utils/Status.h"

namespace utils {

class Subprocess {
public:
  struct Result {
    int exitStatus;
    std::string stdout;
    std::string stderr;
    bool timedOut;
  };

  using LogCallback = std::function<void(const std::string &)>;

  explicit Subprocess(LogCallback logCallback = nullptr);

  ~Subprocess();

  Status Spawn(const std::string &command, const std::vector<std::string> &args,
               const std::vector<std::string> &env = {});

  Result Wait(int timeoutMs = -1);

  bool IsRunning();

  bool Terminate(int signal = 15);

  pid_t GetPid() const { return mPid; }

  std::string GetStdoutBuffer();

  std::string GetStderrBuffer();

  Subprocess(const Subprocess &) = delete;
  Subprocess &operator=(const Subprocess &) = delete;

private:
  void ClosePipes();
  bool CreatePipes();

  void ChildProcess(const std::string &command,
                    const std::vector<std::string> &args,
                    const std::vector<std::string> &env);

  void Log(const std::string &message) const;

  bool CheckRunningAndUpdateStatus();

  pid_t mPid;
  std::atomic<bool> mIsRunning;

  std::array<int, 2> mStdoutPipe;
  std::array<int, 2> mStderrPipe;

  mutable std::string mStdoutBuffer;
  mutable std::string mStderrBuffer;

  LogCallback mLogCallback;

  int mExitStatus;
};

} // namespace utils