#pragma once

#include "Script.h"
#include "frida/include/frida-core.h"
#include "plugins/Plugin.h"
#include "utils/SmallMap.h"

#include "nlohmann/json.hpp"

#include <atomic>

namespace frida {

class Device;

class Session {
public:
  friend class Device;
  Status CreateScript(std::string_view name, std::string_view source);

  explicit Session(pid_t pid, FridaSession *session);
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

  pid_t GetPid() const { return mPid; }

private:
  FridaSession *mSession{nullptr};
  std::atomic<bool> mAttaching{false};

  pid_t mPid{0};
  SmallMap<std::string, std::unique_ptr<Script>> mScripts;
  std::vector<std::unique_ptr<plugin::Plugin>> mPlugins;
};

} // namespace frida