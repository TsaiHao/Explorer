#pragma once

#include <gmock/gmock.h>

#include "frida/IFridaApi.h"

namespace frida {

class MockFridaApi : public IFridaApi {
public:
  MOCK_METHOD(FridaDeviceManager *, ManagerNew, (), (override));
  MOCK_METHOD(FridaDeviceList *, ManagerEnumerateDevicesSync,
              (FridaDeviceManager *, GCancellable *, GError **), (override));
  MOCK_METHOD(void, ManagerCloseSync,
              (FridaDeviceManager *, GCancellable *, GError **), (override));

  MOCK_METHOD(FridaSession *, DeviceAttachSync,
              (FridaDevice *, guint, FridaSessionOptions *, GCancellable *,
               GError **),
              (override));
  MOCK_METHOD(guint, DeviceSpawnSync,
              (FridaDevice *, const gchar *, FridaSpawnOptions *,
               GCancellable *, GError **),
              (override));
  MOCK_METHOD(void, DeviceResumeSync,
              (FridaDevice *, guint, GCancellable *, GError **), (override));
  MOCK_METHOD(void, DeviceEnableSpawnGatingSync,
              (FridaDevice *, GCancellable *, GError **), (override));
  MOCK_METHOD(void, DeviceDisableSpawnGatingSync,
              (FridaDevice *, GCancellable *, GError **), (override));
  MOCK_METHOD(FridaSpawnList *, DeviceEnumeratePendingSpawnSync,
              (FridaDevice *, GCancellable *, GError **), (override));

  MOCK_METHOD(FridaScript *, SessionCreateScriptSync,
              (FridaSession *, const gchar *, FridaScriptOptions *,
               GCancellable *, GError **),
              (override));
  MOCK_METHOD(void, SessionResumeSync,
              (FridaSession *, GCancellable *, GError **), (override));
  MOCK_METHOD(void, SessionDetachSync,
              (FridaSession *, GCancellable *, GError **), (override));

  MOCK_METHOD(void, ScriptLoadSync,
              (FridaScript *, GCancellable *, GError **), (override));
  MOCK_METHOD(void, ScriptUnloadSync,
              (FridaScript *, GCancellable *, GError **), (override));
  MOCK_METHOD(void, ScriptPost, (FridaScript *, const gchar *, GBytes *),
              (override));

  MOCK_METHOD(void, Unref, (gpointer), (override));
  MOCK_METHOD(gpointer, ObjectRef, (gpointer), (override));
  MOCK_METHOD(gulong, SignalConnect,
              (gpointer, const gchar *, GCallback, gpointer), (override));
};

} // namespace frida
