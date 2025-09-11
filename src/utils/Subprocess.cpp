//
// Created by Hao, Zaijun on 2025/6/16.
//

#include "utils/Subprocess.h"
#include "utils/Log.h"
#include "utils/Status.h"

#include <cstring>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <unistd.h>

namespace utils {

namespace {
std::vector<char *> VectorToCharArray(const std::vector<std::string> &vec) {
  std::vector<char *> array(vec.size() + 1, nullptr);
  for (size_t i = 0; i < vec.size(); ++i) {
    array[i] = const_cast<char *>(vec[i].c_str());
  }
  return array;
}

bool MakeNonBlocking(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags == -1) {
    return false;
  }
  return fcntl(fd, F_SETFL, flags | O_NONBLOCK) != -1;
}

void ReadFromPipe(int fd, std::string &buffer) {
  if (fd == -1) {
    return;
  }

  std::array<char, 4096> read_buffer;
  ssize_t bytes_read;

  while ((bytes_read = read(fd, read_buffer.data(), read_buffer.size())) > 0) {
    buffer.append(read_buffer.data(), bytes_read);
  }
}
} // namespace

Subprocess::Subprocess(LogCallback logCallback)
    : m_pid(-1), m_is_running(false), m_stdout_pipe{-1, -1},
      m_stderr_pipe{-1, -1}, m_log_callback(std::move(logCallback)),
      m_exit_status(-1) {
  LOGD("Subprocess instance created @ {}", (void *)this);
}

Subprocess::~Subprocess() {
  if (m_is_running) {
    LOGD("Destructor called with running process, terminating...");
    Terminate(SIGKILL);
    Wait(1000);
  }

  ClosePipes();
  LOGD("Subprocess instance destroyed @ {}", (void *)this);
}

Status Subprocess::Spawn(const std::string &command,
                         const std::vector<std::string> &args,
                         const std::vector<std::string> &env) {
  if (m_is_running) {
    LOGE("Error: Cannot spawn - process already running");
    return InvalidOperation("Repeated spawn attempt");
  }

  m_stdout_buffer.clear();
  m_stderr_buffer.clear();
  m_exit_status = -1;

  if (!CreatePipes()) {
    LOGE("Error: Failed to create pipes");
    return InvalidOperation("Failed to create pipes");
  }

  m_pid = fork();
  if (m_pid == -1) {
    LOGE("Error: fork() failed - {}", strerror(errno));
    ClosePipes();
    return InvalidState("Fork failed: " + std::string(strerror(errno)));
  }

  if (m_pid == 0) {
    ChildProcess(command, args, env);
    _exit(127);
  }

  close(m_stdout_pipe[1]);
  close(m_stderr_pipe[1]);
  m_stdout_pipe[1] = -1;
  m_stderr_pipe[1] = -1;

  MakeNonBlocking(m_stdout_pipe[0]);
  MakeNonBlocking(m_stderr_pipe[0]);

  m_is_running = true;

  std::ostringstream oss;
  oss << "Spawned process with PID " << m_pid << " - Command: " << command;
  LOGD(oss.str());

  return Ok();
}

Subprocess::Result Subprocess::Wait(int timeoutMs) {
  Result result = {
      .exit_status = -1, .stdout = "", .stderr = "", .timed_out = false};

  if (!m_is_running) {
    LOGW("Warning: Wait() called but process not running");
    result.exit_status = m_exit_status;
    result.stdout = m_stdout_buffer;
    result.stderr = m_stderr_buffer;
    return result;
  }

  auto start_time = std::chrono::steady_clock::now();

  while (m_is_running) {
    if (timeoutMs >= 0) {
      auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                         std::chrono::steady_clock::now() - start_time)
                         .count();
      if (elapsed >= timeoutMs) {
        LOGW("Process timed out after {}ms", timeoutMs);
        result.timed_out = true;
        Terminate(SIGTERM);
        break;
      }
    }

    fd_set read_fds;
    FD_ZERO(&read_fds);
    int max_fd = -1;

    if (m_stdout_pipe[0] != -1) {
      FD_SET(m_stdout_pipe[0], &read_fds);
      max_fd = std::max(max_fd, m_stdout_pipe[0]);
    }
    if (m_stderr_pipe[0] != -1) {
      FD_SET(m_stderr_pipe[0], &read_fds);
      max_fd = std::max(max_fd, m_stderr_pipe[0]);
    }

    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 100000;

    int select_result = select(max_fd + 1, &read_fds, nullptr, nullptr, &tv);

    if (select_result > 0) {
      if (m_stdout_pipe[0] != -1 && FD_ISSET(m_stdout_pipe[0], &read_fds)) {
        ReadFromPipe(m_stdout_pipe[0], m_stdout_buffer);
      }
      if (m_stderr_pipe[0] != -1 && FD_ISSET(m_stderr_pipe[0], &read_fds)) {
        ReadFromPipe(m_stderr_pipe[0], m_stderr_buffer);
      }
    }

    if (!CheckRunningAndUpdateStatus()) {
      break;
    }
  }

  result.exit_status = m_exit_status;
  result.stdout = m_stdout_buffer;
  result.stderr = m_stderr_buffer;

  return result;
}

bool Subprocess::IsRunning() {
  if (!m_is_running) {
    return false;
  }

  if (!CheckRunningAndUpdateStatus()) {
    return false;
  }

  return true;
}

bool Subprocess::Terminate(int signal) {
  if (!m_is_running) {
    LOGW("Warning: Terminate() called but process not running");
    return false;
  }

  LOGI("Sending signal {} to PID {}", signal, m_pid);

  if (kill(m_pid, signal) == -1) {
    LOGE("Error: Failed to send signal - {}", strerror(errno));
    return false;
  }

  return true;
}

std::string Subprocess::GetStdoutBuffer() {
  if (m_stdout_pipe[0] != -1) {
    ReadFromPipe(m_stdout_pipe[0], m_stdout_buffer);
  }
  return m_stdout_buffer;
}

std::string Subprocess::GetStderrBuffer() {
  if (m_stderr_pipe[0] != -1) {
    ReadFromPipe(m_stderr_pipe[0], m_stderr_buffer);
  }
  return m_stderr_buffer;
}

void Subprocess::ClosePipes() {
  for (int fd : {m_stdout_pipe[0], m_stdout_pipe[1], m_stderr_pipe[0],
                 m_stderr_pipe[1]}) {
    if (fd != -1) {
      close(fd);
    }
  }
  m_stdout_pipe[0] = m_stdout_pipe[1] = -1;
  m_stderr_pipe[0] = m_stderr_pipe[1] = -1;
}

bool Subprocess::CreatePipes() {
  if (pipe(m_stdout_pipe.data()) == -1) {
    LOGE("Error: Failed to create stdout pipe - {}", strerror(errno));
    return false;
  }

  if (pipe(m_stderr_pipe.data()) == -1) {
    LOGE("Error: Failed to create stderr pipe - {}", strerror(errno));
    close(m_stdout_pipe[0]);
    close(m_stdout_pipe[1]);
    return false;
  }

  return true;
}

void Subprocess::ChildProcess(const std::string &command,
                              const std::vector<std::string> &args,
                              const std::vector<std::string> &env) {
  dup2(m_stdout_pipe[1], STDOUT_FILENO);
  dup2(m_stderr_pipe[1], STDERR_FILENO);

  close(m_stdout_pipe[0]);
  close(m_stdout_pipe[1]);
  close(m_stderr_pipe[0]);
  close(m_stderr_pipe[1]);

  std::vector<std::string> full_args;
  full_args.push_back(command);
  full_args.insert(full_args.end(), args.begin(), args.end());

  auto argv = VectorToCharArray(full_args);

  if (!env.empty()) {
    auto envp = VectorToCharArray(env);
    execve(command.c_str(), argv.data(), envp.data());
  } else {
    execvp(command.c_str(), argv.data());
  }

  const char *error = strerror(errno);
  write(STDERR_FILENO, "exec failed: ", 13);
  write(STDERR_FILENO, error, strlen(error));
  write(STDERR_FILENO, "\n", 1);
}

void Subprocess::Log(const std::string &message) const {
  if (m_log_callback) {
    m_log_callback("[Subprocess] " + message);
  }
}

bool Subprocess::CheckRunningAndUpdateStatus() {
  int status;

  pid_t result = waitpid(m_pid, &status, WNOHANG);

  if (result == m_pid) {
    m_is_running = false;

    if (WIFEXITED(status)) {
      m_exit_status = WEXITSTATUS(status);
      LOGI("Process exited with status {}", m_exit_status);
    } else if (WIFSIGNALED(status)) {
      m_exit_status = -WTERMSIG(status);
      LOGI("Process terminated by signal {}", WTERMSIG(status));
    }

    ReadFromPipe(m_stdout_pipe[0], m_stdout_buffer);
    ReadFromPipe(m_stderr_pipe[0], m_stderr_buffer);

    ClosePipes();
    return false;
  }

  return true;
}

} // namespace utils