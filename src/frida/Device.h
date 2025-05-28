//
// Created by Hao, Zaijun on 2025/4/27.
//
#pragma once

#include "Session.h"
#include "frida/include/frida-core.h"
#include "utils/Log.h"
#include "utils/SmallMap.h"

#include <string>

namespace frida {
class Device {
public:
  using EnumerateSessionCallback = std::function<bool(Session *session)>;

  Device();
  ~Device();

  DISABLE_COPY_AND_MOVE(Device);

  Status Attach(pid_t target_pid);
  Status Detach(pid_t target_pid);

  Session *GetSession(pid_t target_pid) const;

  bool EnumerateSessions(const EnumerateSessionCallback &callback) const;

private:
  std::string mName;
  FridaDevice *mDevice{nullptr};
  FridaDeviceManager *mManager{nullptr};

  SmallMap<pid_t, std::unique_ptr<Session>> mSessions;
};
} // namespace frida
