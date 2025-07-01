//
// Created by Hao, Zaijun on 2025/4/29.
//

#include "Log.h"
#include "utils/Macros.h"
#ifdef TARGET_ANDROID
#include "android/log.h"
#include <sys/syscall.h>
#include <unistd.h>
#endif
#ifdef EXP_DEBUG
#include <iostream>
#endif

#include <thread>

constexpr std::string_view kTag = "Explorer";
thread_local static std::string thread_id_str = []() {
  std::ostringstream oss;
#ifdef TARGET_ANDROID
  // Get the actual Linux thread ID (always positive)
  oss << syscall(SYS_gettid);
#else
  oss << std::this_thread::get_id();
#endif
  return oss.str();
}();

Logger::Logger(const LogLevel level, const char *file, const int lineno)
    : mLevel(level) {
  mStream << "(" << thread_id_str << ")[" << file << ":" << lineno << "] ";
}

Logger::~Logger() {
  // todo: set log level
#ifdef TARGET_ANDROID
  // see https://developer.android.com/ndk/reference/group/logging
  int log_level = static_cast<int>(mLevel) + 3;
  __android_log_write(log_level, kTag.data(), mStream.str().c_str());
#endif

#ifdef EXP_DEBUG
  std::cout << mStream.str() << '\n';
  std::cout.flush();
#endif

  if (UNLIKELY(mLevel == LogLevel::FATAL)) {
    abort();
  }
}
