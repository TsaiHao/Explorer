#pragma once
#include "nlohmann/json.hpp"
#include "utils/Status.h"
#include "frida/Session.h"

#include <expected>
#include <memory>

class Plugin {
public:
  virtual ~Plugin() = default;

  virtual Status Init(frida::Session* session, const nlohmann::json &config) = 0;

  virtual Status Activate() = 0;

  virtual Status Deactivate() = 0;
};

std::expected<std::unique_ptr<Plugin>, Status>
MakePlugin(const nlohmann::json &json);