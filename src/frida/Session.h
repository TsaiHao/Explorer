#pragma once

#include "Script.h"
#include "frida/include/frida-core.h"
#include "utils/SmallMap.h"

#include <atomic>

namespace frida {

class Device;

class Session {
public:
  friend class Device;
  Status CreateScript(std::string_view name, std::string_view source);

  explicit Session(FridaSession *session);
  ~Session();

  DISABLE_COPY_AND_MOVE(Session);

  bool IsAttaching() const;

  void Resume();
  void Detach();

  Script *GetScript(std::string_view name);

private:
  FridaSession *mSession{nullptr};
  std::atomic<bool> mAttaching{false};
  SmallMap<std::string, std::unique_ptr<Script>> mScripts;
};

} // namespace frida