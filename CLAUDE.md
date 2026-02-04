# Explorer - FRIDA Dynamic Instrumentation Tool

## Project Overview

**Explorer** is a FRIDA-based dynamic instrumentation framework designed specifically for Android TV platforms with armv7a CPU architecture. It provides real-time function tracing, SSL/TLS traffic interception, and custom scripting capabilities for analyzing Android applications.

### Key Capabilities
- Real-time Java and native C++ function tracing
- SSL/TLS traffic interception and logging
- Custom TypeScript agent execution
- Multi-session process management via HTTP API
- Per-session message caching with drain API
- Persistent daemon mode with state recovery
- Android TV optimization (Fire TV tested)

## Architecture

Explorer operates in two modes: **Daemon mode** (default, HTTP API) and **Legacy mode** (config-file based).

```
Daemon Mode Architecture
========================
                          HTTP Clients (curl, Python controller, Postman)
                                  │
                    ┌─────────────▼─────────────────────┐
                    │   HTTP Layer (Poco::Net)           │
                    │   HttpServer ─► ApiRouter          │
                    │         │                          │
                    │   ┌─────▼──────────────────────┐   │
                    │   │ Request Handlers            │   │
                    │   │  StartSession  StopSession  │   │
                    │   │  Status  List  DrainMessages│   │
                    │   │  Health  Metrics  Stats     │   │
                    │   └─────┬──────────────────────┘   │
                    └─────────┼──────────────────────────┘
                              │
                    ┌─────────▼──────────────────────────┐
                    │   ApplicationDaemon (PIMPL)         │
                    │   - Session orchestration           │
                    │   - State persistence               │
                    │   - Signal handling                 │
                    └─────────┬──────────────────────────┘
                              │
                    ┌─────────▼──────────────────────────┐
                    │   Device Manager (frida::Device)    │
                    │   - Process attachment/spawning     │
                    │   - Session lifecycle management    │
                    │   - Session metadata tracking       │
                    └─────────┬──────────────────────────┘
                              │
                    ┌─────┬───┴───┬─────────┐
                    │     │       │         │
                 Session1  Session2  ...  SessionN
                (Per-PID) (Per-PID)       (Per-PID)
                    │
          ┌─────────┼──────────┐
          │         │          │
       Scripts  MessageCache  Plugins
                              ├─ FunctionTracer
                              └─ SslDumper
```

## Source Code Structure

```
src/
├── main.cpp                          # Entry point, mode selection, daemonization
├── Application.{h,cpp}               # Legacy config-file mode
├── ApplicationDaemon.{h,cpp}         # Daemon mode (PIMPL pattern)
├── frida/
│   ├── Device.{h,cpp}               # FRIDA device & session management
│   ├── Session.{h,cpp}              # Per-process session with MessageCache
│   ├── Script.{h,cpp}               # TypeScript agent lifecycle & RPC
│   └── FridaHelper.h                # FRIDA SDK type helpers
├── http/
│   ├── HttpServer.{h,cpp}           # Poco::Net HTTP server wrapper
│   ├── ApiRouter.{h,cpp}            # URL route registration & dispatch
│   ├── ApiSchema.{h,cpp}            # Request validation & command parsing
│   ├── RequestHandler.{h,cpp}       # Base handler (JSON parse, responses)
│   ├── AsyncRequestHandler.{h,cpp}  # Async handler with cancellation
│   └── handlers/
│       ├── StartSessionHandler       # POST /api/v1/session/start
│       ├── StopSessionHandler        # POST /api/v1/session/stop
│       ├── StatusHandler             # POST /api/v1/session/status
│       ├── ListSessionsHandler       # POST /api/v1/session/list
│       ├── DrainMessagesHandler      # POST /api/v1/session/messages
│       ├── HealthHandler             # GET  /health, /api/v1/health
│       ├── MetricsHandler            # GET  /api/v1/metrics
│       ├── StatsHandler              # GET  /api/v1/daemon/stats
│       └── SessionDispatcherHandler  # POST /api/v1/session (generic)
├── plugins/
│   ├── Plugin.{h,cpp}               # Plugin base class
│   ├── function_tracer/             # FunctionTracer plugin
│   └── ssl_dumper/                  # SslDumper plugin
└── utils/
    ├── Status.{h,cpp}               # StatusCode enum & Status type
    ├── Result.h                      # Result<T,E> for error propagation
    ├── MessageCache.h                # Thread-safe bounded message buffer
    ├── StateManager.{h,cpp}          # Persistent daemon state & recovery
    ├── SmallMap.h                    # Stack-based small map
    ├── Log.h                         # Logging macros (spdlog/logcat)
    ├── ErrorHandling.{h,cpp}         # HTTP error response helpers
    └── ...                           # DB, HttpDownloader, Subprocess, System, Util

agents/                               # TypeScript FRIDA agents
├── FunctionTracer.ts                 # Function tracing agent
├── SslDumper.ts                      # SSL interception agent
└── Utils.ts                          # Shared utilities

tools/                                # Python tooling
├── explorer_controller.py            # CLI controller for daemon API
├── examples.py                       # Interactive examples
├── debug_health.py                   # Health diagnosis
├── test_endpoints.py                 # Endpoint testing
└── config_templates/                 # Pre-built session configs

docs/                                 # Technical documentation
├── API_REFERENCE.md                  # Complete API reference
├── API_SPECIFICATION.md              # API request/response spec
├── DAEMON_MODE.md                    # Daemon architecture deep dive
├── DAEMON_OPERATION.md               # Operational guide & deployment
├── SESSION_HANDLERS.md               # Handler implementation details
├── DEVICE_ENHANCEMENTS.md            # Device class API docs
└── BACKWARD_COMPATIBILITY.md         # Legacy mode migration guide
```

## HTTP API Endpoints

All session endpoints use `POST` with JSON body `{"action": "<cmd>", "data": {...}}`.

| Method | Endpoint | Handler | Description |
|--------|----------|---------|-------------|
| GET | `/health` | HealthHandler | Basic health check |
| GET | `/api/v1/health` | HealthHandler | Detailed component health |
| GET | `/api/v1/metrics` | MetricsHandler | Operational metrics |
| GET | `/api/v1/daemon/stats` | StatsHandler | Daemon statistics |
| POST | `/api/v1/session/start` | StartSessionHandler | Create session |
| POST | `/api/v1/session/stop` | StopSessionHandler | Terminate session |
| POST | `/api/v1/session/status` | StatusHandler | Query session status |
| POST | `/api/v1/session/list` | ListSessionsHandler | List active sessions |
| POST | `/api/v1/session/messages` | DrainMessagesHandler | Drain cached messages |
| POST | `/api/v1/session` | SessionDispatcherHandler | Generic dispatcher |

### API Command Enum (`ApiSchema`)

```cpp
enum class ApiCommand { kStart, kStop, kStatus, kList, kDrain };
```

## Message Cache System

Each `Session` owns a `utils::MessageCache` -- a thread-safe bounded FIFO buffer (default capacity: 1000 messages). Script messages from FRIDA agents are automatically cached via a registered callback.

**Flow**: FRIDA agent `send()` -> `Script::ProcessMessage()` -> message callbacks -> `MessageCache::Push()`

**Drain API**: `POST /api/v1/session/messages` with `{"action": "drain", "data": {"session": "<pid>"}}` atomically retrieves and clears the buffer, returning `message_count`, `dropped_count`, and the `messages` array.

Only JSON payloads are cached; binary data (e.g., SSL traffic) is not included. The `dropped_count` field reports messages lost to buffer overflow since the last drain.

## Configuration System

### Session Configuration (used by both legacy config.json and daemon API)

```json
{
  "app": "com.example.package",
  "spawn": true,
  "pid": 1234,
  "am_start": "activity/.MainActivity",
  "scripts": ["path/to/script.js"],
  "script_source": "console.log('hi')",
  "trace": [
    {
      "type": "java|native",
      "namespace": "std",
      "class": "android.media.MediaPlayer",
      "method": "start",
      "arguments": true,
      "log": true,
      "backtrace": true,
      "atrace": true,
      "transform": [{"index": 0, "new_value": "replacement_value"}],
      "dump": "/path/to/sqlite.db"
    }
  ],
  "ssl_dumper": {
    "output": "/path/to/dump.bin"
  }
}
```

### Process Attachment Priority
1. **am_start** -- Launch via Android Activity Manager
2. **spawn** -- Spawn application directly
3. **pid** -- Attach to existing process ID
4. **app** -- Find running process by package name

## Communication Protocols

### RPC Protocol: Native <-> TypeScript

**Call** (Native -> TypeScript): `["frida:rpc", callId, "call", "methodName", [params]]`
**Response** (TypeScript -> Native): `["frida:rpc", callId, "ok"|"error", result]`

### Event Message Types

**Function Trace**: `{"event": "enter|exit", "type": "native_trace|java_trace", "identifier": "Class::method", "callId": N, ...}`
**SSL Interception**: `{"event": "ssl", "function": "SSL_read|SSL_write", "ssl_session_id": "...", ...}` with binary GBytes payload.

## Key Design Patterns

### ApplicationDaemon (PIMPL)
```cpp
class ApplicationDaemon {
  std::unique_ptr<Impl> m_impl;
};

class ApplicationDaemon::Impl {
  ApplicationDaemon& m_parent;             // Safe parent reference
  std::unique_ptr<frida::Device> m_device;
  std::unique_ptr<http::HttpServer> m_http_server;
  std::unique_ptr<utils::StateManager> m_state_manager;
};
```
Handlers receive `ApplicationDaemon*` via `&m_parent` (not pointer arithmetic).

### Result<T, E> Error Propagation
All fallible operations return `Result<T, Status>`. No exceptions for control flow.

### Status Codes (`src/utils/Status.h`)
```cpp
enum class StatusCode : int8_t {
  kOk, kPermissionDenied, kNotFound, kBadArgument,
  kInvalidOperation, kInvalidState, kSdkFailure, kTimeout
};
```

### StateManager Locking
`StateManager` uses a single `state_mutex_` for all operations. Methods that call other locked methods must use the internal `FlushToDiskLocked()` helper (not the public `FlushToDisk()`) to avoid self-deadlock on the non-recursive mutex.

## Thread Safety

- **Script callbacks**: `Script::m_mutex` guards callback map and message dispatch
- **Session map**: `Device::m_sessions_mutex` protects session creation/removal/lookup
- **Message cache**: `MessageCache::m_mutex` is leaf-level (never acquires another lock)
- **State persistence**: `StateManager::state_mutex_` guards all state reads/writes
- **Lock ordering**: `sessions_mutex` -> `cache_mutex` (no cycles, no deadlock risk)
- **RPC sync**: `std::condition_variable` for blocking native-to-TypeScript RPC calls

## TypeScript Agent RPC Exports

```typescript
rpc.exports = {
  resolveNativeSymbols(namespace, cls, method): Array<NativeSymbol>,
  resolveJavaSignature(cls, method | null): Promise<Array<JavaMethod>>,
  traceNativeFunctions(addrs[], identifiers[], config): Array<AgentResult>,
  traceJavaMethods(methods[], config): Promise<Array<AgentResult>>
}
```

## Build Requirements

- **Language**: C++17 minimum, C++23 features used
- **Build System**: CMake 3.20+
- **Android NDK**: >= 29 required
- **Target Platform**: Android TV (armv7a, 32-bit)
- **HTTP Server**: Poco::Net framework
- **FRIDA Runtime**: QuickJS (`FRIDA_SCRIPT_RUNTIME_QJS`)

## Development Workflow

```bash
# Build
cd /Users/zaijun/Workspace/code/explorer
make clean && make

# Deploy to Android TV
adb push ./build/explorer /data/local/tmp/
adb shell chmod +x /data/local/tmp/explorer

# Start daemon
adb shell "cd /data/local/tmp && ./explorer --daemon --host 0.0.0.0 --port 34512"

# Port forwarding
adb forward tcp:34512 tcp:34512

# Health check
curl http://127.0.0.1:34512/health

# Monitor logs
adb logcat -s ExplorerDaemon:I ExplorerDaemon:E
```

## Symbol Resolution

Custom C++ mangling pattern for native function lookup:
```
*<namespace_len><namespace><class_len><class><method_len><method>*
Example: *3std6String6length*
```
