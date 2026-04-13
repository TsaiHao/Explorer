//
// Created by Hao, Zaijun on 2025/4/27.
//
#pragma once

#include "IFridaApi.h"

namespace frida {

/**
 * Concrete IFridaApi that forwards to the real Frida C functions.
 */
class RealFridaApi : public IFridaApi {
public:
  FridaDeviceManager *ManagerNew() override {
    return frida_device_manager_new();
  }

  FridaDeviceList *
  ManagerEnumerateDevicesSync(FridaDeviceManager *manager,
                              GCancellable *cancellable,
                              GError **error) override {
    return frida_device_manager_enumerate_devices_sync(manager, cancellable,
                                                       error);
  }

  void ManagerCloseSync(FridaDeviceManager *manager, GCancellable *cancellable,
                        GError **error) override {
    frida_device_manager_close_sync(manager, cancellable, error);
  }

  FridaSession *DeviceAttachSync(FridaDevice *device, guint pid,
                                  FridaSessionOptions *options,
                                  GCancellable *cancellable,
                                  GError **error) override {
    return frida_device_attach_sync(device, pid, options, cancellable, error);
  }

  guint DeviceSpawnSync(FridaDevice *device, const gchar *program,
                        FridaSpawnOptions *options, GCancellable *cancellable,
                        GError **error) override {
    return frida_device_spawn_sync(device, program, options, cancellable,
                                   error);
  }

  void DeviceResumeSync(FridaDevice *device, guint pid,
                        GCancellable *cancellable, GError **error) override {
    frida_device_resume_sync(device, pid, cancellable, error);
  }

  void DeviceEnableSpawnGatingSync(FridaDevice *device,
                                    GCancellable *cancellable,
                                    GError **error) override {
    frida_device_enable_spawn_gating_sync(device, cancellable, error);
  }

  void DeviceDisableSpawnGatingSync(FridaDevice *device,
                                     GCancellable *cancellable,
                                     GError **error) override {
    frida_device_disable_spawn_gating_sync(device, cancellable, error);
  }

  FridaSpawnList *
  DeviceEnumeratePendingSpawnSync(FridaDevice *device,
                                  GCancellable *cancellable,
                                  GError **error) override {
    return frida_device_enumerate_pending_spawn_sync(device, cancellable,
                                                     error);
  }

  FridaScript *SessionCreateScriptSync(FridaSession *session,
                                        const gchar *source,
                                        FridaScriptOptions *options,
                                        GCancellable *cancellable,
                                        GError **error) override {
    return frida_session_create_script_sync(session, source, options,
                                            cancellable, error);
  }

  void SessionResumeSync(FridaSession *session, GCancellable *cancellable,
                         GError **error) override {
    frida_session_resume_sync(session, cancellable, error);
  }

  void SessionDetachSync(FridaSession *session, GCancellable *cancellable,
                         GError **error) override {
    frida_session_detach_sync(session, cancellable, error);
  }

  void ScriptLoadSync(FridaScript *script, GCancellable *cancellable,
                       GError **error) override {
    frida_script_load_sync(script, cancellable, error);
  }

  void ScriptUnloadSync(FridaScript *script, GCancellable *cancellable,
                         GError **error) override {
    frida_script_unload_sync(script, cancellable, error);
  }

  void ScriptPost(FridaScript *script, const gchar *message,
                   GBytes *data) override {
    frida_script_post(script, message, data);
  }

  void Unref(gpointer object) override { frida_unref(object); }

  gpointer ObjectRef(gpointer object) override {
    return g_object_ref(object);
  }

  gulong SignalConnect(gpointer instance, const gchar *signal_name,
                       GCallback handler, gpointer data) override {
    return g_signal_connect(instance, signal_name, handler, data);
  }
};

} // namespace frida
