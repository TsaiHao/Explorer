//
// Created by Hao, Zaijun on 2025/4/27.
//
#pragma once

#include "frida/include/frida-core.h"
#include "utils/Log.h"
#include "utils/Status.h"

#include <functional>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace frida {
class Session;

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

private:
  static void OnMessage(const FridaScript *script, const gchar *message,
                        GBytes *data, gpointer user_data);

  void ProcessMessage(const FridaScript *script, std::string_view message,
                      GBytes *data);
  std::mutex mMutex;

  std::string mName;
  std::string mSource;
  bool mLoaded{false};

  FridaScript *mScript{nullptr};
  std::unordered_map<std::string, OnMessageCallback> mCallbacks;
  FridaSession *mSession{nullptr};
};
} // namespace frida