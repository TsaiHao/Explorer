#pragma once

#include "../Plugin.h"
#include "frida/Script.h"

class FunctionTracer: public Plugin {
public:
  FunctionTracer();

  ~FunctionTracer() override;

  Status Init(frida::Session* session, const nlohmann::json &config) override;

  Status Activate() override;

  Status Deactivate() override;

private:
  Status LoadScript(frida::Session* session);

  frida::Script* mScript {nullptr};
};
