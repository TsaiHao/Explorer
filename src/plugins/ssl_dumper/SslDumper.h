#pragma once

#include "../Plugin.h"
#include "frida/Script.h"

namespace plugin {
class SslDumper : public Plugin {
public:
  SslDumper();

  ~SslDumper() override;

  Status Init(frida::Session *session, const nlohmann::json &config) override;

  Status Activate() override;

  Status Deactivate() override;

  static constexpr std::string_view Identifier() { return "ssl_dumper"; }

  class Impl;

private:
  std::unique_ptr<Impl> mImpl;
};
} // namespace plugin