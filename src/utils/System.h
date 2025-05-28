#pragma once

#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace utils {
bool FileExists(std::string_view file_path);
std::string ReadFileToBuffer(std::string_view file_path,
                             bool is_virtual_file = false);

struct ProcessInfo {
  std::string Command;
  std::string CmdLine;
  pid_t Pid;
};

using EnumerateProcessCallback = std::function<bool(const ProcessInfo &)>;
bool EnumerateProcesses(const EnumerateProcessCallback &callback);

std::vector<ProcessInfo> ListAllRunningProcesses();

std::optional<ProcessInfo> FindProcessByPid(pid_t pid);

std::optional<ProcessInfo> FindProcessByName(std::string_view name);
} // namespace utils
