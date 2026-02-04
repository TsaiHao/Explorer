# Session Command Handlers Implementation

## Overview

The Explorer daemon implements specialized HTTP request handlers for each type of session management operation. This design provides focused validation, clear error handling, and maintainable code organization while supporting multiple API access patterns.

## Handler Architecture

### Specialized Handlers

Each command type has a dedicated handler class:

```cpp
namespace http {
  class StartSessionHandler : public RequestHandler
  class StopSessionHandler : public RequestHandler
  class StatusHandler : public RequestHandler
  class ListSessionsHandler : public RequestHandler
  class DrainMessagesHandler : public RequestHandler
  class SessionDispatcherHandler : public RequestHandler  // For backward compatibility
}
```

### API Endpoints

The daemon exposes both specialized and generic endpoints:

**Specialized Endpoints** (Direct routing):
- `POST /api/v1/session/start` → `StartSessionHandler`
- `POST /api/v1/session/stop` → `StopSessionHandler`
- `POST /api/v1/session/status` → `StatusHandler`
- `POST /api/v1/session/list` → `ListSessionsHandler`
- `POST /api/v1/session/messages` → `DrainMessagesHandler`

**Generic Endpoint** (Action-based routing):
- `POST /api/v1/session` → `SessionDispatcherHandler` (routes by "action" field)

## Handler Implementations

### 1. StartSessionHandler

**Purpose**: Creates new instrumentation sessions from JSON configuration.

**Key Features**:
- Complex validation logic for session configuration
- Target identification validation (app, pid, am_start)
- Trace configuration validation with detailed error messages
- SSL dumper configuration validation
- Script path and inline source validation
- Integration with `ApplicationDaemon::StartSession()`

**Validation Scope**:
```cpp
// Target identification
Status ValidateTargetIdentification(const json& data);

// Trace configuration
Status ValidateTraceConfiguration(const json& trace_config);

// Overall start session data
Status ValidateStartSessionData(const json& data);
```

**Example Valid Request**:
```json
{
  "action": "start",
  "data": {
    "app": "com.example.targetapp",
    "spawn": true,
    "trace": [{
      "type": "java",
      "class": "android.media.MediaPlayer",
      "method": "start",
      "arguments": true,
      "backtrace": true
    }],
    "ssl_dumper": {
      "output": "/data/local/tmp/ssl_traffic.bin"
    }
  }
}
```

### 2. StopSessionHandler

**Purpose**: Terminates existing instrumentation sessions.

**Key Features**:
- Session ID format validation (must be numeric PID)
- Simple but robust validation logic
- Clear error messages for invalid session IDs
- Integration with `ApplicationDaemon::StopSession()`

**Validation**:
```cpp
Status ValidateStopSessionData(const json& data);
Result<std::string, Status> ExtractSessionId(const json& data);
```

**Example Valid Request**:
```json
{
  "action": "stop",
  "data": {
    "session": "12345"
  }
}
```

### 3. StatusHandler

**Purpose**: Queries session status or global daemon status.

**Key Features**:
- Supports both global and specific session queries
- Optional session ID (empty = global status)
- Session ID format validation when provided
- Integration with `ApplicationDaemon::GetSessionStatus()`

**Flexibility**:
```cpp
// Global status query
{"action": "status", "data": {}}

// Specific session status
{"action": "status", "data": {"session": "12345"}}
```

### 4. ListSessionsHandler

**Purpose**: Enumerates active sessions with optional filtering.

**Key Features**:
- Optional filter criteria validation
- Supports filtering by app name, status, PID
- Graceful handling of unknown filter keys (warns but continues)
- Integration with `ApplicationDaemon::ListSessions()`

**Filter Validation**:
```cpp
Status ValidateFilterCriteria(const json& filter);
json ExtractFilterCriteria(const json& data);
```

**Example Filtered Request**:
```json
{
  "action": "list",
  "data": {
    "filter": {
      "app": "com.example.targetapp",
      "status": "active"
    }
  }
}
```

### 5. DrainMessagesHandler

**Purpose**: Retrieves and clears cached script messages from a session.

**Key Features**:
- Session ID validation (must be non-empty string)
- Atomic drain operation (get + clear in one call)
- Returns message count and dropped message count
- Integration with `ApplicationDaemon::DrainSessionMessages()`

**Validation**:
```cpp
Status ValidateDrainRequest(const json& data);
// Requires: data.session (non-empty string)
```

**Example Valid Request**:
```json
{
  "action": "drain",
  "data": {
    "session": "12345"
  }
}
```

**Response Data**:
- `session_id`: The session that was drained
- `pid`: Target process PID
- `message_count`: Number of messages returned
- `dropped_count`: Messages lost to buffer overflow since last drain
- `messages`: Array of cached message payloads

**Message Cache Behavior**:
- Each session maintains a bounded buffer of up to 1000 messages
- Messages are pushed into the cache as they arrive from FRIDA agent callbacks
- When the buffer is full, the oldest message is dropped and `dropped_count` increments
- Draining clears the buffer and resets the dropped counter

### 6. SessionDispatcherHandler

**Purpose**: Provides backward compatibility for the generic `/api/v1/session` endpoint.

**Key Features**:
- Parses "action" field from requests
- Routes to appropriate specialized handlers
- Maintains API compatibility with original design
- Creates instances of all specialized handlers

**Routing Logic**:
```cpp
void Handle(const httplib::Request& req, httplib::Response& res) override {
  // Parse action field
  std::string action = request_json["action"];

  // Route to specialized handler
  if (action == "start") {
    m_start_handler->Handle(req, res);
  } else if (action == "stop") {
    m_stop_handler->Handle(req, res);
  } // ... etc
}
```

## Validation Architecture

### Multi-Level Validation

Each handler implements validation at multiple levels:

1. **JSON Parsing**: Ensures valid JSON structure
2. **Schema Validation**: Uses `ApiSchema::ValidateRequest()` for basic structure
3. **Action Validation**: Confirms handler receives correct action type
4. **Command-Specific Validation**: Detailed validation per command requirements

### Error Response Format

All handlers use consistent error response format:
```json
{
  "status": "error",
  "message": "Descriptive error message",
  "details": {
    "code": 400,
    "field": "specific_field_if_applicable"
  }
}
```

### Validation Error Examples

**StartSessionHandler**:
- Missing target identification: "Must specify at least one of: 'app', 'pid', or 'am_start'"
- Invalid trace configuration: "Trace item 0 has invalid type: 'invalid' (must be 'java' or 'native')"
- Empty required fields: "Field 'app' cannot be empty"

**StopSessionHandler**:
- Invalid session ID: "Session ID must be a valid integer: Invalid argument"
- Missing session field: "Missing required field: 'session'"

## Integration with ApplicationDaemon

### Handler Registration

```cpp
void ApplicationDaemon::Impl::SetupHttpServer() {
  // Create specialized handlers
  auto start_handler = std::make_shared<http::StartSessionHandler>(daemon_instance);
  auto stop_handler = std::make_shared<http::StopSessionHandler>(daemon_instance);
  auto status_handler = std::make_shared<http::StatusHandler>(daemon_instance);
  auto list_handler = std::make_shared<http::ListSessionsHandler>(daemon_instance);
  auto drain_handler = std::make_shared<http::DrainMessagesHandler>(daemon_instance);

  // Register specialized endpoints
  m_http_server->GetRouter().RegisterPost("/api/v1/session/start", start_handler);
  m_http_server->GetRouter().RegisterPost("/api/v1/session/stop", stop_handler);
  m_http_server->GetRouter().RegisterPost("/api/v1/session/status", status_handler);
  m_http_server->GetRouter().RegisterPost("/api/v1/session/list", list_handler);
  m_http_server->GetRouter().RegisterPost("/api/v1/session/messages", drain_handler);

  // Register generic endpoint with dispatcher
  auto dispatcher_handler = std::make_shared<http::SessionDispatcherHandler>(daemon_instance);
  m_http_server->GetRouter().RegisterPost("/api/v1/session", dispatcher_handler);
}
```

### Method Delegation

Each handler delegates to corresponding daemon methods:

```cpp
// StartSessionHandler
auto result = m_daemon->StartSession(session_config);

// StopSessionHandler
auto status = m_daemon->StopSession(session_id);

// StatusHandler
auto result = m_daemon->GetSessionStatus(session_id);

// ListSessionsHandler
auto result = m_daemon->ListSessions(filter);

// DrainMessagesHandler
auto result = m_daemon->DrainSessionMessages(session_id);
```

## Benefits of Specialized Handlers

### 1. **Focused Validation Logic**
Each handler contains only the validation logic relevant to its specific command, making the code easier to understand and maintain.

### 2. **Improved Error Messages**
Command-specific validation enables detailed, contextual error messages that help users understand exactly what went wrong.

### 3. **Reduced Complexity**
Instead of one large handler with complex branching, we have focused handlers that are easier to test and debug.

### 4. **Enhanced Maintainability**
New command-specific features can be added to individual handlers without affecting others.

### 5. **Better Testability**
Each handler can be tested independently with command-specific test cases.

### 6. **Multiple Access Patterns**
Users can choose between:
- Direct endpoints (`/session/start`) for programmatic access
- Generic endpoint (`/session`) for dynamic/scripted access

### 7. **Backward Compatibility**
The `SessionDispatcherHandler` ensures existing clients continue to work while new clients can use specialized endpoints.

## Error Handling Strategy

### Validation Errors (400 Bad Request)
- Malformed JSON
- Missing required fields
- Invalid field types or values
- Constraint violations (empty strings, negative numbers)

### Operational Errors (500+ Status Codes)
- ApplicationDaemon unavailable
- FRIDA SDK failures
- System-level errors

### Not Found Errors (404)
- Session not found for stop/status operations
- Process not found for attachment

### Conflict Errors (409)
- Duplicate session creation attempts
- Invalid state transitions

## Testing and Validation

### Unit Testing
Each handler can be tested independently:
```cpp
// Test StartSessionHandler
auto daemon = CreateMockDaemon();
auto handler = StartSessionHandler(&daemon);
auto request = CreateMockRequest(valid_start_json);
auto response = MockResponse{};
handler.Handle(request, response);
assert(response.status == 200);
```

### Integration Testing
The `session_handlers_test.cpp` provides comprehensive integration testing covering:
- Handler creation and initialization
- API routing design validation
- Request validation patterns
- Error handling capabilities
- Integration with ApplicationDaemon

## Future Enhancements

### Planned Improvements
1. **Request Rate Limiting**: Per-handler rate limiting for DoS protection
2. **Request Metrics**: Handler-specific performance monitoring
3. **Custom Validation Rules**: Pluggable validation for different deployment scenarios
4. **Batch Operations**: Multi-session commands in single requests
5. **Async Response Handling**: Long-running operations with status polling

### API Extensibility
The handler architecture supports easy addition of new commands:
1. Create new handler class extending `RequestHandler`
2. Implement command-specific validation
3. Register with router
4. Add to dispatcher for backward compatibility

## Summary

The session command handlers implementation provides:

✅ **Specialized Validation**: Command-specific validation logic
✅ **Multiple Access Patterns**: Direct and generic endpoints
✅ **Comprehensive Error Handling**: Detailed error messages and status codes
✅ **Backward Compatibility**: Existing API clients continue working
✅ **Maintainable Architecture**: Focused, testable handler classes
✅ **Full Integration**: Seamless ApplicationDaemon integration
✅ **Production Ready**: Robust validation and error handling

The daemon now provides a complete HTTP API for session management with professional-grade request handling and validation.