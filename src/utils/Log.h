#pragma once
#include "Macros.h"
#include <iosfwd>
#include <sstream>

// NOLINTBEGIN(*-identifier-naming)
enum class LogLevel : int8_t { DEBUG, INFO, WARNING, ERROR, FATAL };
// NOLINTEND(*-identifier-naming)

// todo: multithreading safety
class Logger {
public:
  Logger(LogLevel level, const char *file, int lineno);
  ~Logger();

  template <typename T> Logger &operator<<(T &&value) {
    mStream << std::forward<T>(value);
    return *this;
  }

private:
  LogLevel mLevel;
  std::ostringstream mStream;
};

constexpr const char *GetBaseFilename(const char *path) {
  const char *result = path;
  for (const char *p = path; *p != '\0'; ++p) {
    if (*p == '/' || *p == '\\') {
      result = p + 1;
    }
  }
  return result;
}

#define LOG(level) Logger(LogLevel::level, GetBaseFilename(__FILE__), __LINE__)

#define CHECK(condition)                                                       \
  do {                                                                         \
    if (auto _check_result = (condition); !_check_result) [[unlikely]] {       \
      LOG(FATAL) << "condition " << #condition << " check failed. msg: ";      \
    }                                                                          \
  } while (0)

#define CHECK_STATUS(status)                                                   \
  if (!(status).Ok()) [[unlikely]]                                             \
    LOG(FATAL) << "Status check failed: " << (status);