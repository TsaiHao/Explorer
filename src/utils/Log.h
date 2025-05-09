#pragma once
#include <iosfwd>
#include <sstream>
#include <string_view>
#include "Macros.h"

// NOLINTBEGIN(*-identifier-naming)
enum class LogLevel : int8_t {
  DEBUG,
  INFO,
  WARNING,
  ERROR,
  FATAL
};
// NOLINTEND(*-identifier-naming)

// todo: multithreading safety
class Logger {
public:
  Logger(LogLevel level, const char *file, int lineno);
  ~Logger();

  template <typename T> Logger &operator<<(T &&value) {
    mStream << value;
    return *this;
  }

  Logger &operator<<(std::string_view msg) {
    mStream << msg;
    return *this;
  }

private:
  LogLevel mLevel;
  std::ostringstream mStream;
};

constexpr const char* GetBaseFilename(const char* path) {
  const char* last_slash = path;
  while (*last_slash != '\0') {
    if (*last_slash == '/') {
      path = last_slash + 1;
    }
    last_slash++;
  }

  const char* last_backslash = path;
  while (*last_backslash != '\0') {
    if (*last_backslash == '\\') {
      path = last_backslash + 1;
    }
    last_backslash++;
  }

  return path;
}

#define LOG(level) Logger(LogLevel::level, GetBaseFilename(__FILE__), __LINE__)

#define CHECK(condition)                                                       \
  if (!(condition)) [[unlikely]]                                               \
  LOG(FATAL) << "condition " << #condition << " check failed. msg: "
