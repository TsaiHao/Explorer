/**
 * Minimal stub of frida-core.h for host-side unit tests.
 * Provides opaque type declarations and function stubs so that
 * IFridaApi.h, Device.h, Session.h, Script.h can compile without
 * the real Frida SDK.
 */
#pragma once

#include <cstddef>
#include <cstdint>

// GLib basic types
typedef char gchar;
typedef unsigned int guint;
typedef int gint;
typedef void *gpointer;
typedef const void *gconstpointer;
typedef unsigned long gulong;
typedef size_t gsize;
typedef int gboolean;

// GLib callback
typedef void (*GCallback)(void);
#define G_CALLBACK(f) ((GCallback)(f))

// Opaque GLib types
typedef struct _GError {
  int code;
  char *message;
} GError;

typedef struct _GCancellable GCancellable;
typedef struct _GAsyncResult GAsyncResult;
typedef struct _GObject GObject;

typedef struct _GBytes GBytes;

// Opaque Frida types — defined as empty structs so tests can instantiate them
struct _FridaDeviceManager {};
struct _FridaDeviceList {};
struct _FridaDevice {};
struct _FridaSession {};
struct _FridaScript {};
struct _FridaSessionOptions {};
struct _FridaSpawnOptions {};
struct _FridaScriptOptions {};
struct _FridaSpawnList {};
struct _FridaSpawn {};

typedef struct _FridaDeviceManager FridaDeviceManager;
typedef struct _FridaDeviceList FridaDeviceList;
typedef struct _FridaDevice FridaDevice;
typedef struct _FridaSession FridaSession;
typedef struct _FridaScript FridaScript;
typedef struct _FridaSessionOptions FridaSessionOptions;
typedef struct _FridaSpawnOptions FridaSpawnOptions;
typedef struct _FridaScriptOptions FridaScriptOptions;
typedef struct _FridaSpawnList FridaSpawnList;
typedef struct _FridaSpawn FridaSpawn;

// Frida enums
typedef enum { FRIDA_DEVICE_TYPE_LOCAL = 0 } FridaDeviceType;

typedef enum { FRIDA_SCRIPT_RUNTIME_QJS = 0 } FridaScriptRuntime;

// GLib function stubs (inline no-ops for linking)
inline gpointer g_object_ref(gpointer object) { return object; }
inline void g_object_unref(gpointer) {}
inline void g_error_free(GError *) {}
inline const void *g_bytes_get_data(GBytes *, gsize *size) {
  if (size)
    *size = 0;
  return nullptr;
}
inline gulong g_signal_connect(gpointer, const char *, GCallback, gpointer) {
  return 0;
}

// Frida function stubs
inline void frida_unref(gpointer) {}

// Device list — returns 1 fake local device
inline FridaDevice g_stub_device;
inline gint frida_device_list_size(FridaDeviceList *) { return 1; }
inline FridaDevice *frida_device_list_get(FridaDeviceList *, gint) {
  return &g_stub_device;
}

// Device info
inline const gchar *frida_device_get_name(FridaDevice *) {
  return "stub_device";
}
inline FridaDeviceType frida_device_get_dtype(FridaDevice *) {
  return FRIDA_DEVICE_TYPE_LOCAL;
}

// Spawn options
inline FridaSpawnOptions *frida_spawn_options_new() { return nullptr; }
inline void frida_spawn_options_set_argv(FridaSpawnOptions *, gchar **, gint) {}

// Script options
inline FridaScriptOptions *frida_script_options_new() { return nullptr; }
inline void frida_script_options_set_name(FridaScriptOptions *,
                                          const gchar *) {}
inline void frida_script_options_set_runtime(FridaScriptOptions *,
                                             FridaScriptRuntime) {}

// Spawn list
inline gint frida_spawn_list_size(FridaSpawnList *) { return 0; }
inline FridaSpawn *frida_spawn_list_get(FridaSpawnList *, gint) {
  return nullptr;
}
inline const gchar *frida_spawn_get_identifier(FridaSpawn *) { return ""; }
inline guint frida_spawn_get_pid(FridaSpawn *) { return 0; }

// GAsyncReadyCallback (needed by Coroutine.h)
typedef void (*GAsyncReadyCallback)(GObject *, GAsyncResult *, gpointer);
