# Explorer - FRIDA Dynamic Instrumentation Tool

## Project Overview

**Explorer** is a FRIDA-based dynamic instrumentation framework designed specifically for Android TV platforms with armv7a CPU architecture. It provides real-time function tracing, SSL/TLS traffic interception, and custom scripting capabilities for analyzing Android applications.

### Key Capabilities
- Real-time Java and native C++ function tracing
- SSL/TLS traffic interception and logging
- Custom TypeScript agent execution
- Multi-session process management
- Android TV optimization (Fire TV tested)

## Architecture

```
┌─────────────────────────────────────────────────────┐
│   Configuration Layer (config.json)                 │
│   - JSON-based declarative configuration            │
└──────────────┬──────────────────────────────────────┘
               │
┌──────────────▼──────────────────────────────────────┐
│   Application Layer (main.cpp)                      │
│   - Config loading, logging, privilege checks       │
└──────────────┬──────────────────────────────────────┘
               │
┌──────────────▼──────────────────────────────────────┐
│   Device Manager (frida::Device)                     │
│   - Process attachment/spawning, session coordination│
└──────────────┬──────────────────────────────────────┘
               │
        ┌──────┴──────┬──────────┐
        │             │          │
    Session1      Session2   SessionN
   (Per-PID)     (Per-PID)  (Per-PID)
   │                │         │
   ├─Scripts        ├─Scripts ├─Scripts
   └─Plugins        └─Plugins └─Plugins
     ├─FunctionTracer
     └─SslDumper
```

## Configuration System

### Primary Interface: `/data/local/tmp/config.json`

```json
{
  "sessions": [
    {
      "app": "com.example.package",           // Target package name
      "spawn": true,                          // Launch if not running
      "pid": 1234,                           // Or attach to existing PID
      "am_start": "activity/.MainActivity",   // Or launch via ActivityManager
      "scripts": ["path/to/script.js"],      // External script files
      "script_source": "console.log('hi')",  // Inline JavaScript
      "trace": [/* TraceConfig objects */],   // Function tracing config
      "ssl_dumper": {                        // SSL interception config
        "output": "/path/to/dump.bin"
      }
    }
  ]
}
```

### Trace Configuration Schema

```json
{
  "type": "native|java",                    // Target type
  "namespace": "std",                       // C++ namespace (native only)
  "class": "android.media.MediaPlayer",     // Class name
  "method": "start",                        // Method name
  "arguments": true,                        // Log method arguments
  "log": true,                             // Output to logcat
  "backtrace": true,                       // Include call stack
  "atrace": true,                          // Android atrace integration
  "transform": [                           // Value transformation
    {
      "index": 0,                          // Argument index (-1 = return)
      "new_value": "replacement_value"      // New value to inject
    }
  ],
  "dump": "/path/to/sqlite.db"             // SQLite logging path
}
```

## Communication Protocols

### RPC Protocol: Native ↔ TypeScript

**Protocol**: `frida:rpc`

**Call Format** (Native → TypeScript):
```json
[
  "frida:rpc",        // Protocol identifier
  12345,              // Unique call ID
  "call",             // Method type
  "methodName",       // Target method
  [param1, param2]    // Parameters array
]
```

**Response Format** (TypeScript → Native):
```json
{
  "type": "send",
  "payload": [
    "frida:rpc",      // Protocol ID
    12345,            // Matching call ID
    "ok",             // Status: "ok" or "error"
    result_value      // Return value or error details
  ]
}
```

### Event Message Types

**Function Trace Events**:
```json
{
  "event": "enter|exit",
  "type": "native_trace|java_trace",
  "identifier": "Class::method",
  "callId": 42,                    // Pairs enter/exit events
  "backtrace": "stack trace...",   // Optional
  "arguments": [{"type": "int", "value": 123}],  // On enter
  "result": {"type": "string", "value": "return_value"}  // On exit
}
```

**SSL Interception Events**:
```json
{
  "event": "ssl",
  "function": "SSL_read|SSL_write",
  "ssl_session_id": "deadbeef",
  "src_addr": 167772161,          // IP as integer
  "src_port": 443,
  "dst_addr": 167772162,
  "dst_port": 8080,
  "data": "<binary_payload>"      // Sent as GBytes
}
```

## Core Components

### Key Files
- **Entry Point**: `src/main.cpp` - Config loading, initialization
- **Application**: `src/Application.{h,cpp}` - Main application logic
- **Device Manager**: `src/frida/Device.{h,cpp}` - Process management
- **Session Manager**: `src/frida/Session.{h,cpp}` - Per-process sessions
- **Script Manager**: `src/frida/Script.{h,cpp}` - TypeScript agent management
- **Config Schema**: `tools/config-schema.json` - JSON Schema validation

### Plugin System
- **Base Class**: `src/plugins/Plugin.h` - Plugin interface
- **FunctionTracer**: `src/plugins/function_tracer/` - Function interception
- **SslDumper**: `src/plugins/ssl_dumper/` - SSL traffic capture

### TypeScript Agents
- **Function Tracer**: `agents/FunctionTracer.ts` - Core tracing logic
- **SSL Dumper**: `agents/SslDumper.ts` - SSL interception implementation
- **Utilities**: `agents/Utils.ts` - Common helper functions

## Process Attachment Methods

Priority order:
1. **am_start**: Launch via Android Activity Manager
2. **spawn**: Spawn application directly
3. **pid**: Attach to existing process ID
4. **app**: Find running process by package name

## TypeScript Agent RPC Exports

```typescript
rpc.exports = {
  // Native symbol resolution for C++ functions
  resolveNativeSymbols(namespace: string, cls: string, method: string): Array<NativeSymbol>,

  // Java method signature resolution
  resolveJavaSignature(cls: string, method: string | null): Promise<Array<JavaMethod>>,

  // Start native function tracing
  traceNativeFunctions(addrs: number[], identifiers: string[], config: TraceConfig): Array<AgentResult>,

  // Start Java method tracing
  traceJavaMethods(methods: JavaMethod[], config: TraceConfig): Promise<Array<AgentResult>>
}
```

## Error Handling

### Status Codes (`src/utils/Status.h`)
```cpp
enum class StatusCode : int8_t {
  kOk,                 // Success
  kPermissionDenied,   // Access denied
  kNotFound,           // Resource not found
  kBadArgument,        // Invalid parameter
  kInvalidOperation,   // Operation not allowed
  kInvalidState,       // Illegal state
  kSdkFailure,         // FRIDA SDK error
  kTimeout,            // Operation timeout
};
```

### Result Type Pattern
All operations return `Result<T, E>` for safe error propagation without exceptions.

## Build Requirements

- **Language**: C++17 minimum, C++23 features used
- **Build System**: CMake 3.20+
- **Android NDK**: >= 29 required
- **Target Platform**: Android TV (armv7a)
- **FRIDA Runtime**: QuickJS (FRIDA_SCRIPT_RUNTIME_QJS)

## Usage Examples

### Basic Function Tracing
```json
{
  "sessions": [
    {
      "app": "com.netflix.mediaclient",
      "spawn": true,
      "trace": [
        {
          "type": "java",
          "class": "android.media.MediaCodec",
          "method": "flush",
          "backtrace": true,
          "log": true
        }
      ]
    }
  ]
}
```

### SSL Traffic Capture
```json
{
  "sessions": [
    {
      "app": "com.amazon.tv.localgallery",
      "spawn": true,
      "ssl_dumper": {
        "output": "/data/local/tmp/ssl_traffic.bin"
      }
    }
  ]
}
```

### Native C++ Tracing
```json
{
  "sessions": [
    {
      "app": "com.example.nativeapp",
      "spawn": true,
      "trace": [
        {
          "type": "native",
          "namespace": "std",
          "class": "vector",
          "method": "push_back",
          "arguments": true
        }
      ]
    }
  ]
}
```

## Current Limitations & Improvement Opportunities

### User Experience Issues
- **Complex Configuration**: Users must learn detailed JSON schema
- **Manual Workflow**: Edit config on PC → Deploy to DUT → Run binary
- **Error-Prone**: Typos in JSON cause runtime failures
- **No Discoverability**: Hard to know available methods/classes

### Proposed MCP Server Solution
Enable natural language commands like:
- "Trace MediaCodec.flush with callstack on Netflix app"
- "Capture SSL traffic from Amazon Prime Video"
- "Monitor all file I/O operations in YouTube TV"

The MCP server would:
1. Parse natural language → Generate config.json
2. Deploy config to device automatically
3. Execute explorer binary
4. Stream results back to Claude

This would transform the user experience from manual JSON editing to conversational instrumentation.

## Technical Insights

### Thread Safety
- `std::mutex` for script message callbacks
- Condition variables for RPC synchronization
- Atomic bools for session state management

### Memory Management
- Smart pointers throughout (unique_ptr, shared_ptr)
- FRIDA object refcounting with custom deleters
- Stack-based SmallMap to avoid heap fragmentation

### Symbol Resolution
Custom C++ mangling pattern:
```
*<namespace_len><namespace><class_len><class><method_len><method>*
Example: *3std6String6length*
```

### Binary Data Handling
TypeScript agents can send binary data alongside JSON:
```typescript
send(jsonMessage, binaryData);  // GBytes payload
```

This enables SSL traffic dumps and other binary analysis workflows.