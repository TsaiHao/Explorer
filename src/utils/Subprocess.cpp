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
    : mPid(-1), mIsRunning(false), mStdoutPipe{-1, -1},
      mStderrPipe{-1, -1}, mLogCallback(std::move(logCallback)), mExitStatus(-1) {
  LOG(DEBUG) << "Subprocess instance created @ " << this;
}

Subprocess::~Subprocess() {
  if (mIsRunning) {
    LOG(DEBUG) << "Destructor called with running process, terminating...";
    Terminate(SIGKILL);
    Wait(1000);
  }

  ClosePipes();
  LOG(DEBUG) << "Subprocess instance destroyed @ " << this;
}

Status Subprocess::Spawn(const std::string &command,
                         const std::vector<std::string> &args,
                         const std::vector<std::string> &env) {
  if (mIsRunning) {
    LOG(ERROR) << "Error: Cannot spawn - process already running";
    return InvalidOperation("Repeated spawn attempt");
  }

  mStdoutBuffer.clear();
  mStderrBuffer.clear();
  mExitStatus = -1;

  if (!CreatePipes()) {
    LOG(ERROR) << "Error: Failed to create pipes";
    return InvalidOperation("Failed to create pipes");
  }

  mPid = fork();
  if (mPid == -1) {
    LOG(ERROR) << "Error: fork() failed - " << strerror(errno);
    ClosePipes();
    return InvalidState("Fork failed: " + std::string(strerror(errno)));
  }

  if (mPid == 0) {
    ChildProcess(command, args, env);
    _exit(127);
  }

  close(mStdoutPipe[1]);
  close(mStderrPipe[1]);
  mStdoutPipe[1] = -1;
  mStderrPipe[1] = -1;

  MakeNonBlocking(mStdoutPipe[0]);
  MakeNonBlocking(mStderrPipe[0]);

  mIsRunning = true;

  std::ostringstream oss;
  oss << "Spawned process with PID " << mPid << " - Command: " << command;
  LOG(DEBUG) << oss.str();

  return Ok();
}

Subprocess::Result Subprocess::Wait(int timeoutMs) {
  Result result = {
      .exitStatus = -1, .stdout = "", .stderr = "", .timedOut = false};

  if (!mIsRunning) {
    LOG(WARNING) << "Warning: Wait() called but process not running";
    result.exitStatus = mExitStatus;
    result.stdout = mStdoutBuffer;
    result.stderr = mStderrBuffer;
    return result;
  }

  auto start_time = std::chrono::steady_clock::now();

  while (mIsRunning) {
    if (timeoutMs >= 0) {
      auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                         std::chrono::steady_clock::now() - start_time)
                         .count();
      if (elapsed >= timeoutMs) {
        LOG(WARNING) << "Process timed out after " << timeoutMs << "ms";
        result.timedOut = true;
        Terminate(SIGTERM);
        break;
      }
    }

    fd_set read_fds;
    FD_ZERO(&read_fds);
    int max_fd = -1;

    if (mStdoutPipe[0] != -1) {
      FD_SET(mStdoutPipe[0], &read_fds);
      max_fd = std::max(max_fd, mStdoutPipe[0]);
    }
    if (mStderrPipe[0] != -1) {
      FD_SET(mStderrPipe[0], &read_fds);
      max_fd = std::max(max_fd, mStderrPipe[0]);
    }

    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 100000;

    int select_result = select(max_fd + 1, &read_fds, nullptr, nullptr, &tv);

    if (select_result > 0) {
      if (mStdoutPipe[0] != -1 && FD_ISSET(mStdoutPipe[0], &read_fds)) {
        ReadFromPipe(mStdoutPipe[0], mStdoutBuffer);
      }
      if (mStderrPipe[0] != -1 && FD_ISSET(mStderrPipe[0], &read_fds)) {
        ReadFromPipe(mStderrPipe[0], mStderrBuffer);
      }
    }

    if (!CheckRunningAndUpdateStatus()) {
      break;
    }
  }

  result.exitStatus = mExitStatus;
  result.stdout = mStdoutBuffer;
  result.stderr = mStderrBuffer;

  return result;
}

bool Subprocess::IsRunning() {
  if (!mIsRunning) {
    return false;
  }

  if (!CheckRunningAndUpdateStatus()) {
    return false;
  }

  return true;
}

bool Subprocess::Terminate(int signal) {
  if (!mIsRunning) {
    LOG(WARNING) << "Warning: Terminate() called but process not running";
    return false;
  }

  LOG(INFO) << "Sending signal " << signal << " to PID " << mPid;

  if (kill(mPid, signal) == -1) {
    LOG(ERROR) << "Error: Failed to send signal - " << strerror(errno);
    return false;
  }

  return true;
}

std::string Subprocess::GetStdoutBuffer() {
  if (mStdoutPipe[0] != -1) {
    ReadFromPipe(mStdoutPipe[0], mStdoutBuffer);
  }
  return mStdoutBuffer;
}

std::string Subprocess::GetStderrBuffer() {
  if (mStderrPipe[0] != -1) {
    ReadFromPipe(mStderrPipe[0], mStderrBuffer);
  }
  return mStderrBuffer;
}

void Subprocess::ClosePipes() {
  for (int fd :
       {mStdoutPipe[0], mStdoutPipe[1], mStderrPipe[0], mStderrPipe[1]}) {
    if (fd != -1) {
      close(fd);
    }
  }
  mStdoutPipe[0] = mStdoutPipe[1] = -1;
  mStderrPipe[0] = mStderrPipe[1] = -1;
}

bool Subprocess::CreatePipes() {
  if (pipe(mStdoutPipe.data()) == -1) {
    LOG(ERROR) << "Error: Failed to create stdout pipe - " << strerror(errno);
    return false;
  }

  if (pipe(mStderrPipe.data()) == -1) {
    LOG(ERROR) << "Error: Failed to create stderr pipe - " << strerror(errno);
    close(mStdoutPipe[0]);
    close(mStdoutPipe[1]);
    return false;
  }

  return true;
}

void Subprocess::ChildProcess(const std::string &command,
                              const std::vector<std::string> &args,
                              const std::vector<std::string> &env) {
  dup2(mStdoutPipe[1], STDOUT_FILENO);
  dup2(mStderrPipe[1], STDERR_FILENO);

  close(mStdoutPipe[0]);
  close(mStdoutPipe[1]);
  close(mStderrPipe[0]);
  close(mStderrPipe[1]);

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
  if (mLogCallback) {
    mLogCallback("[Subprocess] " + message);
  }
}

bool Subprocess::CheckRunningAndUpdateStatus() {
  int status;

  pid_t result = waitpid(mPid, &status, WNOHANG);

  if (result == mPid) {
    mIsRunning = false;

    if (WIFEXITED(status)) {
      mExitStatus = WEXITSTATUS(status);
      LOG(INFO) << "Process exited with status " << mExitStatus;
    } else if (WIFSIGNALED(status)) {
      mExitStatus = -WTERMSIG(status);
      LOG(INFO) << "Process terminated by signal " << WTERMSIG(status);
    }

    ReadFromPipe(mStdoutPipe[0], mStdoutBuffer);
    ReadFromPipe(mStderrPipe[0], mStderrBuffer);

    ClosePipes();
    return false;
  }

  return true;
}

} // namespace utils