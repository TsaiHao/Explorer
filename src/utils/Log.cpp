#ifdef TARGET_ANDROID
#include "android/log.h"
#endif

#include "Log.h"
#ifdef EXP_DEBUG
#include <iostream>
#endif
#include <array>

constexpr std::string_view TAG = "Explorer";
Logger::Logger(const LogLevel level, const char *file, const int lineno)
    : mLevel(level) {
  mStream << "[" << file << ":" << lineno << "] ";
}

Logger::~Logger() {
  // todo: set log level
#ifdef TARGET_ANDROID
  // see https://developer.android.com/ndk/reference/group/logging
  int log_level = mLevel + 3;
  __android_log_write(log_level, TAG.data(), mStream.str().c_str());
#endif

#ifdef EXP_DEBUG
  std::cout << mStream.str() << '\n';
#endif
}
