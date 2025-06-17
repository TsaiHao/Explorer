//
// Created by Hao, Zaijun on 2025/5/26.
//

#include "Plugin.h"

#include "frida/Session.h"
#include "function_tracer/FunctionTracer.h"
#include "utils/Log.h"

namespace plugin {
template <typename PluginType>
static std::unique_ptr<Plugin> MakePluginInternal(frida::Session *session,
                                                  const nlohmann::json &json) {
  auto tracer_plugin = std::make_unique<PluginType>();

  CHECK_STATUS(tracer_plugin->Init(session, json));
  CHECK_STATUS(tracer_plugin->Activate());

  return tracer_plugin;
}

std::vector<std::unique_ptr<Plugin>> MakePlugin(frida::Session *session,
                                                const nlohmann::json &json) {
  std::vector<std::unique_ptr<Plugin>> plugins;
  if (json.contains(FunctionTracer::Identifier())) {
    for (const auto &plugin_config :
         json[FunctionTracer::Identifier()].items()) {
      auto plugin =
          MakePluginInternal<FunctionTracer>(session, plugin_config.value());
      if (plugin != nullptr) {
        plugins.push_back(std::move(plugin));
      } else {
        LOG(ERROR) << "Failed to create plugin: " << plugin_config.key();
      }
    }
  }

  return plugins;
}

} // namespace plugin