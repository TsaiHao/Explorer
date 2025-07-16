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
    m_enable_backtrace = enable;
    return *this;
  }

  Self &EnableArguments(bool enable) {
    m_enable_arguments = enable;
    return *this;
  }

  Self &EnableAtrace(bool enable) {
    m_enable_atrace = enable;
    return *this;
  }

  Self &EnableLogcat(bool enable) {
    m_enable_logcat = enable;
    return *this;
  }

  Self &SetArgumentTransform(std::vector<Transform> transforms) {
    m_transform = std::move(transforms);
    return *this;
  }

private:
  bool m_enable_backtrace = false;
  bool m_enable_arguments = false;
  bool m_enable_atrace = false;
  bool m_enable_logcat = false;

  std::vector<Transform> m_transform;
};
} // namespace plugin