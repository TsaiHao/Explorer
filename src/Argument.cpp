//
// Created by Hao, Zaijun on 2025/4/27.
//
#include "Argument.h"

#include <cassert>

Argument::Argument(std::string_view name, ArgType type)
    : mName(name), mType(type) {}

Argument& Argument::alias(std::string_view alias) {
  mAlias = alias;
  return *this;
}

Argument& Argument::desc(std::string_view desc) {
  mDesc = desc;
  return *this;
}

ArgManager::ArgManager() = default;

static bool startsWith(std::string_view s, std::string_view prefix) {
  return s.substr(0, prefix.size()) == prefix;
}

static bool endsWith(std::string_view s, std::string_view suffix) {
  return s.substr(s.size() - suffix.size()) == suffix;
}

bool ArgManager::parse(int argc, const char* argv[]) {
  assert(argc >= 1);
  mProgramName = argv[0];

  for (int i = 1; i < argc; i++) {
    std::string_view arg = argv[i];
    if (arg == "--help" || arg == "-h") {}
    else if (arg == "--version" || arg == "-v") {}

    std::string_view argName;
    if (startsWith(arg, "--")) {
      argName = arg.substr(2);
    } else if (startsWith(arg, "-")) {
      argName = arg.substr(1);
    } else {
      return false;
    }

  }

  return true;
}

 std::string_view ArgManager::programName() const {
  return mProgramName;
}

bool ArgManager::exists(std::string_view name) const {
  return std::find(mArguments.begin(), mArguments.end(), [&](const Argument& arg) {
    return arg.mName == name;
  }) != mArguments.end();
}

Argument& ArgManager::addArg(Argument&& arg) {
  mArguments.push_back(std::move(arg));
  return mArguments.back();
}

Argument& ArgManager::find(std::string_view name) {
  auto iter = std::find(mArguments.begin(), mArguments.end(), [&](const Argument& arg) {
    return arg.mName == name;
  });
  if (iter == mArguments.end()) {
    throw std::invalid_argument("No such argument");
  }
  return *iter;
}