#pragma once

#include "../Plugin.h"
#include "frida/Script.h"

namespace plugin {
class FunctionTracer : public Plugin {
public:
  FunctionTracer();

  ~FunctionTracer() override;

  Status Init(frida::Session *session, const nlohmann::json &config) override;

  Status Activate() override;

  Status Deactivate() override;

  static constexpr std::string_view Identifier() { return "trace"; }

  class Impl;

private:
  std::unique_ptr<Impl> m_impl;
};
} // namespace plugin