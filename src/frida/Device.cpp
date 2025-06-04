//
// Created by Hao, Zaijun on 2025/4/27.
//
#include "Device.h"
#include "utils/Log.h"

namespace frida {
Device::Device() {
  LOG(INFO) << "Creating frida device " << this;

  mManager = frida_device_manager_new();
  CHECK(mManager != nullptr);

  GError *error = nullptr;
  auto *devices =
      frida_device_manager_enumerate_devices_sync(mManager, nullptr, &error);
  CHECK(error == nullptr);

  const auto n_devices = frida_device_list_size(devices);
  for (int i = 0; i < n_devices; ++i) {
    auto *device = frida_device_list_get(devices, i);
    LOG(DEBUG) << "Found device " << frida_device_get_name(device) << ", type: " << frida_device_get_dtype(device);

    if (frida_device_get_dtype(device) == FRIDA_DEVICE_TYPE_LOCAL) {
      mDevice = g_object_ref(device);
      mName = frida_device_get_name(device);
    }

    g_object_unref(device);
  }

  if (mDevice == nullptr) {
    LOG(ERROR) << "No valid device found, current device list:";
    for (int i = 0; i < n_devices; ++i) {
      auto *device = frida_device_list_get(devices, i);
      LOG(ERROR) << "Device " << frida_device_get_name(device);
    }
  }

  frida_unref(devices);
}

Device::~Device() {
  LOG(INFO) << "Destroying frida device " << mName << "@" << this;

  if (mDevice != nullptr) {
    frida_unref(mDevice);
    mDevice = nullptr;
  }
  if (mManager != nullptr) {
    frida_device_manager_close_sync(mManager, nullptr, nullptr);
    frida_unref(mManager);
    mManager = nullptr;
  }
}

Status Device::Attach(pid_t target_pid) {
  LOG(INFO) << "Attaching frida device " << mName << "@" << this
            << " targeting " << target_pid;

  CHECK(mDevice != nullptr);
  CHECK(!mSessions.Contains(target_pid));

  GError *error = nullptr;

  auto *session =
      frida_device_attach_sync(mDevice, target_pid, nullptr, nullptr, &error);
  if (error != nullptr) {
    LOG(ERROR) << "Error attaching frida device: " << error->message;
    frida_unref(session);

    return SdkFailure("frida attach api failed");
  }

  mSessions[target_pid] = std::make_unique<Session>(target_pid, session);

  return Ok();
}

// todo: is this resume-able?
Status Device::Detach(pid_t target_pid) {
  LOG(INFO) << "Detaching frida device " << mName << "@" << this;

  CHECK(mDevice != nullptr);
  CHECK(mSessions.Contains(target_pid));

  mSessions.Erase(target_pid);
  return Ok();
}

Session *Device::GetSession(pid_t target_pid) const {
  if (!mSessions.Contains(target_pid)) {
    return nullptr;
  }
  return mSessions.At(target_pid).get();
}

bool Device::EnumerateSessions(const EnumerateSessionCallback &callback) const {
  for (auto it = mSessions.CBegin(); it != mSessions.CEnd(); ++it) {
    const auto &session = it->second.get();
    if (callback(session)) {
      return true;
    }
  }
  return false;
}

} // namespace frida