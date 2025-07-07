#pragma once

#include <string>
#include <variant>
#include <vector>

namespace plugin {
class ScriptBuilder {
public:
  using Self = ScriptBuilder;

  enum class ArgType : int8_t { kInt64, kString, kFloat, kDouble };
  using NewValueType = std::variant<std::string, int64_t, double, float>;
  struct Transform {
    int index;              // argument index
    ArgType arg_type;       // argument type
    NewValueType new_value; // new value to set
  };

  ScriptBuilder() = default;
  ~ScriptBuilder() = default;

  std::string Build() const;

  Self &EnableBacktrace(bool enable) {
    mEnableBacktrace = enable;
    return *this;
  }

  Self &EnableArguments(bool enable) {
    mEnableArguments = enable;
    return *this;
  }

  Self &EnableAtrace(bool enable) {
    mEnableAtrace = enable;
    return *this;
  }

  Self &EnableLogcat(bool enable) {
    mEnableLogcat = enable;
    return *this;
  }

  Self &SetArgumentTransform(std::vector<Transform> transforms) {
    mTransform = std::move(transforms);
    return *this;
  }

private:
  bool mEnableBacktrace = false;
  bool mEnableArguments = false;
  bool mEnableAtrace = false;
  bool mEnableLogcat = false;

  std::vector<Transform> mTransform;
};
} // namespace plugin