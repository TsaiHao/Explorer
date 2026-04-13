#include "plugins/Plugin.h"

namespace plugin {

std::vector<std::unique_ptr<Plugin>> MakePlugin(frida::Session *,
                                                const nlohmann::json &) {
  return {};
}

} // namespace plugin
