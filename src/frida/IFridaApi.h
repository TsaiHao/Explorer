//
// Created by Hao, Zaijun on 2025/4/27.
//
#pragma once

#include "FridaHelper.h"

namespace frida {

/**
 * Abstract interface for Frida C API calls.
 * Enables dependency injection and mocking for unit tests.
 */
class IFridaApi {
public:
  virtual ~IFridaApi() = default;

  // Device manager
  virtual FridaDeviceManager *ManagerNew() = 0;
  virtual FridaDeviceList *
  ManagerEnumerateDevicesSync(FridaDeviceManager *manager,
                              GCancellable *cancellable, GError **error) = 0;
  virtual void ManagerCloseSync(FridaDeviceManager *manager,
                                GCancellable *cancellable,
                                GError **error) = 0;

  // Device
  virtual FridaSession *DeviceAttachSync(FridaDevice *device, guint pid,
                                         FridaSessionOptions *options,
                                         GCancellable *cancellable,
                                         GError **error) = 0;
  virtual guint DeviceSpawnSync(FridaDevice *device, const gchar *program,
                                FridaSpawnOptions *options,
                                GCancellable *cancellable,
                                GError **error) = 0;
  virtual void DeviceResumeSync(FridaDevice *device, guint pid,
                                GCancellable *cancellable,
                                GError **error) = 0;
  virtual void DeviceEnableSpawnGatingSync(FridaDevice *device,
                                           GCancellable *cancellable,
                                           GError **error) = 0;
  virtual void DeviceDisableSpawnGatingSync(FridaDevice *device,
                                            GCancellable *cancellable,
                                            GError **error) = 0;
  virtual FridaSpawnList *
  DeviceEnumeratePendingSpawnSync(FridaDevice *device,
                                  GCancellable *cancellable,
                                  GError **error) = 0;

  // Session
  virtual FridaScript *
  SessionCreateScriptSync(FridaSession *session, const gchar *source,
                           FridaScriptOptions *options,
                           GCancellable *cancellable, GError **error) = 0;
  virtual void SessionResumeSync(FridaSession *session,
                                 GCancellable *cancellable,
                                 GError **error) = 0;
  virtual void SessionDetachSync(FridaSession *session,
                                 GCancellable *cancellable,
                                 GError **error) = 0;

  // Script
  virtual void ScriptLoadSync(FridaScript *script, GCancellable *cancellable,
                               GError **error) = 0;
  virtual void ScriptUnloadSync(FridaScript *script, GCancellable *cancellable,
                                 GError **error) = 0;
  virtual void ScriptPost(FridaScript *script, const gchar *message,
                           GBytes *data) = 0;

  // GObject ref counting
  virtual void Unref(gpointer object) = 0;
  virtual gpointer ObjectRef(gpointer object) = 0;

  // Signal connection
  virtual gulong SignalConnect(gpointer instance, const gchar *signal_name,
                               GCallback handler, gpointer data) = 0;
};

} // namespace frida
