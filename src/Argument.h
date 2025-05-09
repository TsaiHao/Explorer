#pragma once

#include <optional>
#include <string>
#include <unordered_map>
#include <variant>
#include <vector>

enum class ArgType {
  kInt,
  kString,
  kDouble,
  kBool,
  kStringArray,
};

class Argument {
  friend class ArgManager;
 public:
  Argument& alias(std::string_view alias);
  Argument& desc(std::string_view desc);
  template <typename T>
  Argument& defaultValue(T&& value) {
    mValue.emplace(std::forward<T>(value));
    return *this;
  }

 private:
  Argument(std::string_view name, ArgType type);

  using ValueType =
      std::variant<int, std::string, double, bool, std::vector<std::string>>;

  std::string mName;
  ArgType mType;
  std::string mDesc;
  std::string mAlias;
  ValueType mValue;
};

class ArgManager {
public:
  ArgManager();

  template <typename T>
  Argument& newArgument(std::string_view name) {
    if (exists(name)) {
      throw std::invalid_argument("duplicate argument");
    }
    ArgType type;
    if constexpr (std::is_same_v<T, int>) {
      type = ArgType::kBool;
    } else if constexpr (std::is_same_v<T, std::string>) {
      type = ArgType::kString;
    } else if constexpr (std::is_same_v<T, double>) {
      type = ArgType::kDouble;
    } else if constexpr (std::is_same_v<T, bool>) {
      type = ArgType::kBool;
    } else if constexpr (std::is_same_v<T, std::vector<std::string>>) {
      type = ArgType::kStringArray;
    } else {
      throw std::invalid_argument("unknown argument type");
    }

    auto& ret = addArg(Argument(name, type));
    return ret;
  }

  template <typename T>
  T& getValue(std::string_view name) {
    if (exists(name)) {
      throw std::invalid_argument("unknown argument name");
    }
    auto value = find(name).mValue;
    return std::get<T>(value);
  }

  bool parse(int argc, const char* argv[]);

  std::string_view programName() const;
private:
  bool exists(std::string_view name) const;
  Argument& addArg(Argument&& arg);
  Argument& find(std::string_view name);

  std::string_view mProgramName;
  std::vector<Argument> mArguments;
  std::vector<std::string> mPositionals;
};