#pragma once
#include "nlohmann/json.hpp"
#include "utils/Status.h"

#include <expected>
#include <memory>

namespace frida {
class Session;
}

namespace plugin {
class Plugin {
public:
  virtual ~Plugin() = default;

  virtual Status Init(frida::Session* session, const nlohmann::json &config) = 0;

  virtual Status Activate() = 0;

  virtual Status Deactivate() = 0;
};

std::vector<std::unique_ptr<Plugin>> MakePlugin(frida::Session *session,
                                   const nlohmann::json &json);

} // namespace plugin