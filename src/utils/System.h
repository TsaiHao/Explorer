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
  std::string command;
  std::string cmd_line;
  pid_t pid;
};
inline bool operator==(const ProcessInfo &lhs, const ProcessInfo &rhs) {
  return lhs.pid == rhs.pid && lhs.command == rhs.command &&
         lhs.cmd_line == rhs.cmd_line;
}

using EnumerateProcessCallback = std::function<bool(const ProcessInfo &)>;
bool EnumerateProcesses(const EnumerateProcessCallback &callback);

std::vector<ProcessInfo> ListAllRunningProcesses();

std::optional<ProcessInfo> FindProcessByPid(pid_t pid);

std::optional<ProcessInfo> FindProcessByName(std::string_view name);

std::string DemangleSymbol(std::string_view symbol);
} // namespace utils
