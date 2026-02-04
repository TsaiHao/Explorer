# Explorer

A FRIDA-based dynamic instrumentation framework for Android TV (armv7a). Explorer provides real-time function tracing, SSL/TLS traffic interception, and custom scripting through either a persistent HTTP daemon or a traditional config-file workflow.

## Features

- Java and native C++ function tracing with optional backtraces
- SSL/TLS traffic interception and binary dump
- Custom TypeScript agent execution
- Daemon mode with HTTP API for dynamic session management
- Per-session message caching with atomic drain
- State persistence across daemon restarts
- Legacy config-file mode for batch instrumentation

## Prerequisites

- Android NDK >= 29
- CMake >= 3.20
- Python 3 (used by the build system to fetch dependencies)
- A rooted Android TV device (tested on Fire TV, armv7a)

## Building

```bash
# Clone and enter the repository
git clone <repo-url> && cd explorer

# Configure (dependencies are fetched automatically during this step)
cmake -B build \
  -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake \
  -DANDROID_ABI=armeabi-v7a \
  -DANDROID_PLATFORM=android-29

# Build
cmake --build build

# Deploy to device
adb push build/explorer /data/local/tmp/
adb shell chmod +x /data/local/tmp/explorer
```

Dependency versions are defined in [`cmake/Dependencies.cmake`](cmake/Dependencies.cmake). CMake calls `install_dep.py` at configure time to download Frida, SQLite, spdlog, and Poco into `third_party/`.

### Build options

| Option | Default | Description |
|--------|---------|-------------|
| `TARGET_ANDROID` | `ON` | Compile for Android (links `log`, sets `TARGET_ANDROID` define) |
| `ENABLE_SQLITE` | `OFF` | Build with SQLite for trace data output |
| `ENABLE_DEBUG` | `OFF` | Enable debug-level logging |

## Usage

### Daemon mode (default)

Start the daemon on the device, then control it over HTTP:

```bash
# Start daemon
adb shell "cd /data/local/tmp && ./explorer --daemon --host 0.0.0.0 --port 34512"

# Forward port for local access
adb forward tcp:34512 tcp:34512

# Health check
curl http://127.0.0.1:34512/health

# Start a tracing session
curl -X POST http://127.0.0.1:34512/api/v1/session/start \
  -H "Content-Type: application/json" \
  -d '{
    "action": "start",
    "data": {
      "app": "com.netflix.mediaclient",
      "spawn": true,
      "trace": [{
        "type": "java",
        "class": "android.media.MediaCodec",
        "method": "flush",
        "log": true,
        "backtrace": true
      }]
    }
  }'

# Drain cached trace messages from the session
curl -X POST http://127.0.0.1:34512/api/v1/session/messages \
  -H "Content-Type: application/json" \
  -d '{"action": "drain", "data": {"session": "29851"}}'

# Stop the session
curl -X POST http://127.0.0.1:34512/api/v1/session/stop \
  -H "Content-Type: application/json" \
  -d '{"action": "stop", "data": {"session": "29851"}}'
```

#### Command-line options

```
--daemon              Run in daemon mode (default)
--foreground          Stay in foreground instead of daemonizing
--host HOST           Bind address (default: 0.0.0.0)
--port PORT           Listen port (default: 34512)
--pid-file PATH       PID file location
--config-dir DIR      Configuration directory
```

#### API endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| GET | `/api/v1/metrics` | Operational metrics |
| GET | `/api/v1/daemon/stats` | Daemon statistics |
| POST | `/api/v1/session/start` | Create a session |
| POST | `/api/v1/session/stop` | Terminate a session |
| POST | `/api/v1/session/status` | Query session status |
| POST | `/api/v1/session/list` | List active sessions |
| POST | `/api/v1/session/messages` | Drain cached messages |

All POST endpoints accept `{"action": "<command>", "data": {...}}`. See the [docs/](docs/) directory for full API specifications and handler details.

### Legacy mode

Run a one-shot instrumentation session from a JSON config file:

```bash
adb shell "/data/local/tmp/explorer --legacy"
# Reads /data/local/tmp/config.json by default

adb shell "/data/local/tmp/explorer --config /path/to/config.json"
```

### Python controller

A Python CLI is included for scripted interaction with the daemon:

```bash
python3 tools/explorer_controller.py --host 127.0.0.1 --port 34512 health
python3 tools/explorer_controller.py --host 127.0.0.1 --port 34512 start \
  --app com.netflix.mediaclient \
  --trace-java android.media.MediaCodec flush
```

## Documentation

Detailed documentation lives in the [`docs/`](docs/) directory:

- [API Reference](docs/API_REFERENCE.md) -- complete endpoint reference with client examples
- [API Specification](docs/API_SPECIFICATION.md) -- request/response schemas
- [Daemon Mode](docs/DAEMON_MODE.md) -- daemon architecture and internals
- [Daemon Operation](docs/DAEMON_OPERATION.md) -- deployment, service integration, troubleshooting
- [Session Handlers](docs/SESSION_HANDLERS.md) -- HTTP handler implementation details
- [Device Enhancements](docs/DEVICE_ENHANCEMENTS.md) -- `frida::Device` API for session management
- [Backward Compatibility](docs/BACKWARD_COMPATIBILITY.md) -- legacy mode and migration guide

## Project structure

```
src/
  main.cpp                    Entry point and daemonization
  ApplicationDaemon.{h,cpp}   Daemon mode (PIMPL pattern)
  Application.{h,cpp}         Legacy config-file mode
  frida/                      FRIDA device, session, and script management
  http/                       Poco::Net HTTP server, router, handlers
  plugins/                    FunctionTracer and SslDumper plugins
  utils/                      Status, Result, MessageCache, StateManager, logging
agents/                       TypeScript FRIDA agents
tools/                        Python controller and debug utilities
cmake/                        CMake modules (dependency management, JS embedding)
third_party/                  Downloaded dependencies (frida, spdlog, sqlite, poco)
```

## License

This project is licensed under the MIT License.

## Acknowledgments

- [FRIDA](https://frida.re/) -- dynamic instrumentation toolkit
- [Poco](https://pocoproject.org/) -- C++ networking library
- [nlohmann/json](https://github.com/nlohmann/json) -- JSON for Modern C++
- [spdlog](https://github.com/gabime/spdlog) -- fast C++ logging
