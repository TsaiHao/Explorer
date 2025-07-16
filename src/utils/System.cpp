//
// Created by Hao, Zaijun on 2025/4/28.
//

#include "System.h"
#include "Log.h"

#include <algorithm>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <vector>

#include <cxxabi.h>

static bool IsNumeric(std::string_view str) {
  return !str.empty() && std::ranges::all_of(str, ::isdigit);
}

static std::string_view GetBaseName(std::string_view cmdline) {
  cmdline.remove_suffix(std::count(cmdline.rbegin(), cmdline.rend(), '\0'));
  auto last = cmdline.find_last_of('/');
  if (last == std::string_view::npos) {
    return cmdline;
  }
  return cmdline.substr(last + 1);
}

namespace utils {
bool FileExists(std::string_view file_path) {
  return access(file_path.data(), F_OK) != -1;
}

std::string ReadFileToBuffer(std::string_view file_path, bool is_virtual_file) {
  CHECK(!file_path.empty());

  const int fd = open(file_path.data(), O_RDONLY | O_CLOEXEC);
  if (fd == -1) {
    perror("Opening file failed");
    if (errno == ENOENT) {
      LOG(ERROR) << "File " << file_path << " does not exist";
    } else if (errno == EACCES) {
      LOG(ERROR) << "File " << file_path << " access denied";
    } else {
      LOG(ERROR) << "Opening " << file_path
                 << " failed, error = " << strerror(errno);
    }
    exit(1);
  }

  std::string file_content;
  ssize_t bytes_read;
  if (is_virtual_file) {
    std::vector<char> buf(1024);
    while ((bytes_read = read(fd, buf.data(), buf.size())) > 0) {
      file_content.append(buf.data(), bytes_read);
    }
    return file_content;
  }

  auto file_size = lseek(fd, 0, SEEK_END);
  if (file_size == 0) {
    return {};
  }
  if (file_size < 0) {
    LOG(ERROR) << "Reading file " << file_path
               << " failed, error = " << strerror(errno)
               << " file size= " << file_size;
    return {};
  }

  CHECK(lseek(fd, 0, SEEK_SET) != -1);

  file_content.resize(file_size);
  bytes_read = read(fd, file_content.data(), file_size);
  CHECK(bytes_read == file_size);
  close(fd);

  return file_content;
}

bool EnumerateProcesses(const EnumerateProcessCallback &callback) {
  DIR *proc_dir = opendir("/proc");
  CHECK(proc_dir != nullptr);

  dirent *entry;
  while ((entry = readdir(proc_dir)) != nullptr) {
    if (entry->d_type != DT_DIR) {
      continue;
    }

    auto filepath = std::string(entry->d_name);
    if (filepath.empty() || !IsNumeric(filepath)) {
      continue;
    }

    ProcessInfo info;
    info.pid = std::stoi(entry->d_name);
    std::string const proc_dir_name = "/proc/" + filepath;

    info.command = ReadFileToBuffer(proc_dir_name + "/comm", true);
    info.cmd_line = ReadFileToBuffer(proc_dir_name + "/cmdline", true);
    if (!info.command.empty() && info.command.back() == '\n') {
      info.command.pop_back();
    }

    if (callback(info)) {
      return true;
    }
  }
  return false;
}

std::vector<ProcessInfo> ListAllRunningProcesses() {
  std::vector<ProcessInfo> processes;

  EnumerateProcesses([&processes](const ProcessInfo &info) {
    processes.push_back(info);
    return false;
  });

  return processes;
}

std::optional<ProcessInfo> FindProcessByPid(pid_t pid) {
  if (ProcessInfo process;
      EnumerateProcesses([&process, pid](const ProcessInfo &info) {
        if (info.pid == pid) {
          process = info;
          return true;
        }
        return false;
      })) {
    return process;
  }
  return std::nullopt;
}

std::optional<ProcessInfo> FindProcessByName(std::string_view name) {
  if (ProcessInfo process;
      EnumerateProcesses([&process, name](const ProcessInfo &info) {
        if (info.command == name || info.cmd_line == name ||
            GetBaseName(info.cmd_line) == name) {
          process = info;
          return true;
        }
        return false;
      })) {
    return process;
  }
  return std::nullopt;
}

std::string DemangleSymbol(std::string_view symbol) {
  int status = 0;
  std::unique_ptr<char, void (*)(void *)> result{
      abi::__cxa_demangle(symbol.data(), nullptr, nullptr, &status), std::free};

  return status == 0 ? std::string(result.get()) : std::string(symbol);
}
} // namespace utils