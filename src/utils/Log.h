#pragma once

#include "spdlog/spdlog.h"

#define LOGV(...) SPDLOG_TRACE(__VA_ARGS__)

#define LOGD(...) SPDLOG_DEBUG(__VA_ARGS__)

#define LOGI(...) SPDLOG_INFO(__VA_ARGS__)

#define LOGW(...) SPDLOG_WARN(__VA_ARGS__)

#define LOGE(...) SPDLOG_ERROR(__VA_ARGS__)

#define LOGF(...)                                                              \
  {                                                                            \
    SPDLOG_CRITICAL(__VA_ARGS__);                                              \
    std::terminate();                                                          \
  }

#define CHECK(condition, ...)                                                  \
  if (!(condition)) {                                                          \
    LOGE("Check failed: {}", #condition);                                      \
    std::terminate();                                                          \
  }

#define CHECK_STATUS(status_expr)                                              \
  if (const Status s = (status_expr); !s.Ok()) {                               \
    LOGE("Status check failed: {}, status {}", #status_expr, s.DebugString()); \
    std::terminate();                                                          \
  }
