//
// Created by Hao, Zaijun on 2025/4/27.
//
#pragma once

#include "FridaHelper.h"
#include "nlohmann/json.hpp"
#include "utils/Macros.h"
#include "utils/SmallMap.h"

#include <atomic>
#include <condition_variable>
#include <expected>
#include <functional>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>

namespace frida {
class Session;
using RpcResult = std::expected<nlohmann::json, nlohmann::json>;

class Script {
public:
  using OnMessageCallback = std::function<void(
      Script *, const nlohmann::json &, const uint8_t *data, size_t data_size)>;

  Script(std::string_view name, std::string_view source, FridaSession *session);
  ~Script();

  DISABLE_COPY_AND_MOVE(Script);

  void Load();
  void Unload();

  // todo: do we need data copy here
  void AddMessageCallback(std::string_view name, OnMessageCallback callback);
  void RemoveCallback(std::string_view name);

  RpcResult RpcCallSync(std::string_view method, std::string_view param_json);

  int SendRpcCall(std::string_view method, std::string_view param_json);
  RpcResult WaitForRpcCallResult(int call_id);

private:
  static void OnMessage(const FridaScript *script, const char *message,
                        GBytes *data, gpointer user_data);

  bool MaybeProcessSystemMessage(nlohmann::json &msg);

  void OnRpcReturn(nlohmann::json &msg);

  void ProcessMessage(const FridaScript *script, std::string_view message,
                      GBytes *data);
  std::mutex m_mutex;

  std::string m_name;
  std::string m_source;
  bool m_loaded{false};

  FridaScript *m_script{nullptr};
  std::unordered_map<std::string, OnMessageCallback> m_callbacks;
  FridaSession *m_session{nullptr};

  std::atomic<int> m_rpc_call_id{0};
  SmallMap<int, RpcResult> m_rpc_call_results;
  std::condition_variable m_rpc_call_cond_var;
  std::mutex m_rpc_call_mutex;
};
} // namespace frida