
# Explorer
---
## Introduction

This is a tool for exploring the internals of Android applications. It's built on top of Frida, a dynamic instrumentation toolkit for Android.

Currently, it's mainly tested on Fire TV devices.

## Build

### Prerequisites

- Android NDK >= 29 (c++ 23 features are used)
- CMake >= 3.20
- Ninja
- Rooted device or emulator

### Build

1. Export the Android NDK path, for example:

```bash
export ANDROID_NDK_ROOT=$HOME/Library/Android/sdk/ndk/29.0.13113456
```

2. Fetch Frida dependencies

```bash
./install_dep.sh
```

3. Configure 

```bash
cmake --preset android-arm7-debug -B build
```

4. Build

```bash
cmake --build build
```

5. Run

```bash
adb push example/config.json build/explorer /data/local/tmp
adb shell chmod 755 /data/local/tmp/explorer
adb shell /data/local/tmp/explorer
```

### Config files
The `explorer` tool will read the `/data/local/tmp/config.json` file to configure the behavior of the tool.

The config file is a JSON file containing an array of objects, each representing a `Session` targeting a specific application. For instance, the following config file will attempt to
1. load the `/data/local/tmp/script.js` script into the `com.example.app` application,
2. trace the `start` method of the `MediaCodec` class in the `com.example.app` application, all arguments and the return value will be printed and output will be written the logcat.

```json
[
  {
    "app": "com.example.app",
    "script": "/data/local/tmp/script.js",
    "trace": [
      {
        "type": "java",
        "class": "android.media.MediaCodec",
        "method": "start",
        "arguments": true,
        "log": true
      }
    ]
  }
]
```

## Roadmap
- [x] Support spawning new processes
- [ ] Implment process crash and device lost handling
- [ ] Add unit tests
- [ ] Support reading script/config files from a http server