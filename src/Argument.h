#pragma once

#include <string>
#include <vector>
#include <optional>

enum class ArgType {
  kInt,
  kString,
  kDouble,
  kBool,
};

template <typename T>
struct Arg {
  const std::string name;
  std::optional<T> value;
  bool required {false};
  ArgType type {ArgType::kInt};
};

#define DECL_ARG_DEFAULT(NAME, TYPE, DEFAULT) \
