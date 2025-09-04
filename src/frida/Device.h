//
// Created by Hao, Zaijun on 2025/4/27.
//
#pragma once

#include "Session.h"
#include "nlohmann/json.hpp"
#include "utils/SmallMap.h"
#include "utils/System.h"

#include <string>

namespace frida {
class Device {
public:
  using EnumerateSessionCallback = std::function<bool(Session *session)>;

  Device();
  ~Device();

  DISABLE_COPY_AND_MOVE(Device);

  Status BuildSessionsFromConfig(const nlohmann::json &config);
  Status Resume();

  Status Attach(const utils::ProcessInfo &proc_info);
  Status Detach(const utils::ProcessInfo &proc_info);

  Status SpawnAppAndAttach(std::string_view exec_name,
                           const std::vector<std::string> &args = {});
  Status LaunchAppAndAttach(std::string_view am_command_args);

  Session *GetSession(pid_t target_pid) const;

  bool EnumerateSessions(const EnumerateSessionCallback &callback) const;

private:
  Status BuildOneSessionFromConfig(const nlohmann::json &session_config);

  Status AttachToAppFromConfig(const nlohmann::json &session_config);

  std::string m_name;
  FridaDevice *m_device{nullptr};
  FridaDeviceManager *m_manager{nullptr};

  std::vector<pid_t> m_pending_spawns;

  const nlohmann::json *m_config = nullptr;

  SmallMap<utils::ProcessInfo, std::unique_ptr<Session>> m_sessions;
};
} // namespace frida
