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
    int exit_status;
    std::string stdout;
    std::string stderr;
    bool timed_out;
  };

  using LogCallback = std::function<void(const std::string &)>;

  explicit Subprocess(LogCallback logCallback = nullptr);

  ~Subprocess();

  Status Spawn(const std::string &command, const std::vector<std::string> &args,
               const std::vector<std::string> &env = {});

  Result Wait(int timeoutMs = -1);

  bool IsRunning();

  bool Terminate(int signal = 15);

  pid_t GetPid() const { return m_pid; }

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

  pid_t m_pid;
  std::atomic<bool> m_is_running;

  std::array<int, 2> m_stdout_pipe;
  std::array<int, 2> m_stderr_pipe;

  mutable std::string m_stdout_buffer;
  mutable std::string m_stderr_buffer;

  LogCallback m_log_callback;

  int m_exit_status;
};

} // namespace utils