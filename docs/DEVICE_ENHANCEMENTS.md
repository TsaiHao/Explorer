# Device Class Enhancements for Daemon Mode

## Overview

The `frida::Device` class has been significantly enhanced to support dynamic session management for daemon mode operation. This enables the Explorer daemon to create, manage, and monitor instrumentation sessions via HTTP API calls without requiring config file restarts.

## New API Methods

### 1. CreateSession(config)
```cpp
Result<nlohmann::json, Status> CreateSession(const nlohmann::json& config);
```
**Purpose**: Create a new instrumentation session dynamically from JSON configuration.

**Features**:
- Validates session configuration before creation
- Prevents duplicate sessions for same PID/app
- Creates session metadata for tracking
- Returns detailed session information
- Thread-safe operation

**Example Usage**:
```cpp
json config = {
  {"app", "com.example.targetapp"},
  {"spawn", true},
  {"trace", [{{"type", "java"}, {"class", "MainActivity"}, {"method", "onCreate"}}]}
};

auto result = device.CreateSession(config);
if (result.IsOk()) {
  json session_data = result.Unwrap();
  // session_data contains: session_id, pid, app, status, created_at, config
}
```

### 2. RemoveSession(pid)
```cpp
Status RemoveSession(pid_t target_pid);
```
**Purpose**: Gracefully stop and remove an existing session.

**Features**:
- Properly detaches from target process
- Cleans up session resources
- Updates metadata status
- Thread-safe operation

### 3. GetSessionInfo(pid)
```cpp
Result<nlohmann::json, Status> GetSessionInfo(pid_t target_pid) const;
```
**Purpose**: Retrieve detailed information about a specific session.

**Returns**:
- Session ID and PID
- Target app name
- Session status (active/terminated)
- Creation timestamp
- Original configuration
- Additional session metadata

### 4. ListAllSessions(filter)
```cpp
Result<nlohmann::json, Status> ListAllSessions(const nlohmann::json& filter = {}) const;
```
**Purpose**: List all active sessions with optional filtering.

**Features**:
- Filter by app name
- Filter by session status
- Returns comprehensive session list
- Includes total count

**Example Response**:
```json
{
  "sessions": [
    {
      "session_id": "12345",
      "pid": 12345,
      "app": "com.example.app1",
      "status": "active",
      "created_at": 1640995200
    }
  ],
  "total_count": 1
}
```

### 5. DrainSessionMessages(pid)
```cpp
Result<nlohmann::json, Status> DrainSessionMessages(pid_t target_pid);
```
**Purpose**: Atomically retrieve and clear all cached script messages from a session.

**Features**:
- Thread-safe access to session message cache
- Returns message count and dropped count metadata
- Clears the session's message buffer after retrieval
- Lock ordering: `m_sessions_mutex` → `MessageCache::m_mutex` (no deadlock risk)

**Returns**:
- Session ID and PID
- Message count and dropped count
- Array of cached JSON message payloads

**Example Response**:
```json
{
  "session_id": "12345",
  "pid": 12345,
  "message_count": 3,
  "dropped_count": 0,
  "messages": [
    {"event": "enter", "type": "java_trace", "identifier": "MediaCodec.flush", "callId": 1},
    {"event": "exit", "type": "java_trace", "identifier": "MediaCodec.flush", "callId": 1},
    {"event": "enter", "type": "java_trace", "identifier": "MediaCodec.flush", "callId": 2}
  ]
}
```

### 6. GetSessionStatistics()
```cpp
nlohmann::json GetSessionStatistics() const;
```
**Purpose**: Get device-level statistics for monitoring.

**Returns**:
- Number of active sessions
- Total sessions created since startup
- Device uptime
- Device name
- Pending spawns count

## Session Metadata System

### SessionMetadata Structure
```cpp
struct SessionMetadata {
  pid_t pid;
  std::string app_name;
  std::string session_status;
  std::chrono::system_clock::time_point created_at;
  nlohmann::json config;
};
```

**Features**:
- Tracks session lifecycle information
- Stores original configuration for reference
- Maintains creation timestamps
- Updates session status (active → terminated)

## Thread Safety

### Mutex Protection
- Added `std::mutex m_sessions_mutex` for thread-safe access
- All session management operations are protected
- Concurrent API requests are handled safely
- No race conditions between session creation/deletion

### Atomic Statistics
- Session counters use `std::atomic` for thread-safe updates
- Statistics queries are lockless where possible

## Integration with ApplicationDaemon

The enhanced Device class is fully integrated with the ApplicationDaemon:

```cpp
// Session creation
Result<json, Status> ApplicationDaemon::StartSession(const json& config) {
  return m_device->CreateSession(config);
}

// Session termination
Status ApplicationDaemon::StopSession(const std::string& session_id) {
  pid_t pid = std::stoi(session_id);
  return m_device->RemoveSession(pid);
}

// Status queries
Result<json, Status> ApplicationDaemon::GetSessionStatus(const std::string& session_id) {
  if (session_id.empty()) {
    // Return global stats with device statistics
    json device_stats = m_device->GetSessionStatistics();
    // ...
  } else {
    pid_t pid = std::stoi(session_id);
    return m_device->GetSessionInfo(pid);
  }
}

// Session listing
Result<json, Status> ApplicationDaemon::ListSessions(const json& filter) {
  return m_device->ListAllSessions(filter);
}

// Message draining
Result<json, Status> ApplicationDaemon::DrainSessionMessages(const std::string& session_id) {
  pid_t pid = std::stoi(session_id);
  return m_device->DrainSessionMessages(pid);
}
```

## Backward Compatibility

The enhancements are fully backward compatible:
- Existing `BuildSessionsFromConfig()` method unchanged
- Original session management methods still work
- Legacy sessions are handled gracefully
- No breaking changes to existing API

## Error Handling

### Comprehensive Status Codes
- `BadArgument`: Invalid configuration or parameters
- `InvalidOperation`: Duplicate sessions, invalid state
- `NotFound`: Session or process not found
- `SdkFailure`: FRIDA API failures

### Detailed Error Messages
- Clear error descriptions for debugging
- Context-specific error information
- Validation error details for malformed configs

## Performance Considerations

### Efficient Data Structures
- `SmallMap` used for fast session lookups by PID
- Minimal memory overhead for metadata
- O(1) session access in common cases

### Lazy Evaluation
- Statistics computed on demand
- Session info generated when requested
- No unnecessary background processing

## Testing

### Integration Test
Created comprehensive test suite (`enhanced_device_test.cpp`) covering:
- Session creation scenarios
- Session listing and filtering
- Statistics gathering
- Error conditions
- Thread safety validation

### Compilation Verified
- CMake configuration passes
- No compilation errors
- All dependencies resolved

## Future Enhancements

### Planned Improvements
1. Session timeout management
2. Session health monitoring
3. Automatic session recovery
4. Performance metrics collection
5. Session event notifications

### API Extensibility
The new API is designed for future extensions:
- Additional metadata fields
- Custom session filters
- Session state callbacks
- Bulk operations

## Summary

The Device class enhancements provide a robust foundation for daemon mode operation:

✅ **Dynamic Session Management**: Create/destroy sessions via API
✅ **Thread-Safe Operations**: Concurrent request handling
✅ **Session Metadata**: Comprehensive tracking and statistics
✅ **Full Integration**: Seamless ApplicationDaemon integration
✅ **Backward Compatibility**: No breaking changes
✅ **Error Handling**: Comprehensive error reporting
✅ **Performance**: Efficient data structures and operations

The daemon can now manage instrumentation sessions dynamically without config file restarts, enabling true API-driven operation.