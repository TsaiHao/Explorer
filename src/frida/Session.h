#pragma once

#include "Script.h"
#include "frida/include/frida-core.h"
#include "nlohmann/json.hpp"
#include "utils/SmallMap.h"

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

  Status LoadTracerFromConfig(const nlohmann::json &config);

  Script *GetScript(std::string_view name) const;
  pid_t GetPid() const { return mPid; }

private:
  FridaSession *mSession{nullptr};
  std::atomic<bool> mAttaching{false};
  pid_t mPid{0};
  SmallMap<std::string, std::unique_ptr<Script>> mScripts;
};

} // namespace frida