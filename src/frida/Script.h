//
// Created by Hao, Zaijun on 2025/4/27.
//
#pragma once

#include "frida-core.h"
#include "nlohmann/json.hpp"
#include "utils/Macros.h"
#include "utils/SmallMap.h"
#include "utils/Status.h"

#include <atomic>
#include <condition_variable>
#include <expected>
#include <functional>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace frida {
class Session;
using RpcResult = std::expected<nlohmann::json, nlohmann::json>;

class Script {
public:
  using OnMessageCallback =
      std::function<void(Script *, std::string_view, std::vector<uint8_t>)>;

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
  static void OnMessage(const FridaScript *script, const gchar *message,
                        GBytes *data, gpointer user_data);

  bool MaybeProcessSystemMessage(nlohmann::json &msg);

  void OnRpcReturn(nlohmann::json &msg);

  void ProcessMessage(const FridaScript *script, std::string_view message,
                      GBytes *data);
  std::mutex mMutex;

  std::string mName;
  std::string mSource;
  bool mLoaded{false};

  FridaScript *mScript{nullptr};
  std::unordered_map<std::string, OnMessageCallback> mCallbacks;
  FridaSession *mSession{nullptr};

  std::atomic<int> mRpcCallID{0};
  SmallMap<int, RpcResult> mRpcCallResults;
  std::condition_variable mRpcCallCondVar;
  std::mutex mRpcCallMutex;
};
} // namespace frida