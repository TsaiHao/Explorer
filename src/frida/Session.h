#pragma once

#include "Script.h"
#include "plugins/Plugin.h"
#include "utils/MessageCache.h"
#include "utils/SmallMap.h"

#include "nlohmann/json.hpp"

#include <atomic>

namespace frida {

class Device;

class Session {
public:
  friend class Device;
  Status CreateScript(std::string_view name, std::string_view source);

  Session(pid_t pid, FridaSession *session);
  ~Session();

  DISABLE_COPY_AND_MOVE(Session);

  bool IsAttaching() const;

  void Resume();
  void Detach();

  Status LoadInlineScriptsFromConfig(const nlohmann::json &config);
  Status LoadScriptFilesFromConfig(const nlohmann::json &config);
  Status LoadPlugins(const nlohmann::json &config);

  Script *GetScript(std::string_view name) const;
  Status RemoveScript(std::string_view name);

  pid_t GetPid() const { return m_pid; }

  utils::MessageCache &GetMessageCache() { return m_message_cache; }

private:
  void RegisterCacheCallback(Script *script);
  FridaSession *m_session{nullptr};
  std::atomic<bool> m_attaching{false};

  pid_t m_pid{0};
  SmallMap<std::string, std::unique_ptr<Script>> m_scripts;
  std::vector<std::unique_ptr<plugin::Plugin>> m_plugins;
  utils::MessageCache m_message_cache;
};

} // namespace frida