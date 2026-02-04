# Explorer Daemon API Specification

## Overview

The Explorer daemon exposes a REST API for managing dynamic instrumentation sessions. All communication uses JSON over HTTP.

**Base URL**: `http://0.0.0.0:34512`
**Content-Type**: `application/json`
**Method**: `POST` (for all commands)

## Request Format

All API requests follow this structure:

```json
{
  "action": "start|stop|status|list|drain",
  "data": {
    // Command-specific parameters
  }
}
```

## Response Format

All API responses follow this structure:

**Success Response**:
```json
{
  "status": "success",
  "data": {
    // Response data payload
  },
  "message": "Optional success message"
}
```

**Error Response**:
```json
{
  "status": "error",
  "message": "Error description",
  "error_code": "OPTIONAL_ERROR_CODE",
  "details": {
    // Optional error details
  }
}
```

## API Endpoints

### Health Check
- **GET** `/health` or `/api/v1/health`
- Returns server health status

**Response**:
```json
{
  "status": "success",
  "data": {
    "status": "healthy",
    "service": "explorer-daemon",
    "timestamp": 1640995200
  }
}
```

### Session Management
- **POST** `/api/v1/session`
- Main endpoint for all session operations

## Commands

### 1. Start Session

Create and start a new instrumentation session.

**Request**:
```json
{
  "action": "start",
  "data": {
    "app": "com.example.targetapp",          // Target package name (required if no pid)
    "pid": 12345,                            // Target PID (required if no app)
    "spawn": true,                           // Launch if not running (optional)
    "am_start": "activity/.MainActivity",    // Launch via ActivityManager (optional)
    "scripts": ["/path/to/script.js"],       // External scripts (optional)
    "script_source": "console.log('hi')",    // Inline script (optional)
    "trace": [                               // Function tracing config (optional)
      {
        "type": "java",                      // "java" or "native"
        "class": "android.media.MediaPlayer",
        "method": "start",
        "arguments": true,                   // Log arguments
        "backtrace": true                    // Include call stack
      }
    ],
    "ssl_dumper": {                          // SSL interception (optional)
      "output": "/path/to/dump.bin"
    }
  }
}
```

**Success Response**:
```json
{
  "status": "success",
  "data": {
    "session_id": "12345",
    "pid": 12345,
    "app": "com.example.targetapp",
    "created_at": 1640995200,
    "status": "active"
  },
  "message": "Session started successfully"
}
```

### 2. Stop Session

Stop and destroy an existing session.

**Request**:
```json
{
  "action": "stop",
  "data": {
    "session": "12345"                       // Session ID (PID)
  }
}
```

**Success Response**:
```json
{
  "status": "success",
  "data": {
    "session_id": "12345",
    "stopped_at": 1640995300
  },
  "message": "Session stopped successfully"
}
```

### 3. Get Session Status

Query the status of a specific session or global status.

**Request** (specific session):
```json
{
  "action": "status",
  "data": {
    "session": "12345"                       // Session ID (optional)
  }
}
```

**Request** (global status):
```json
{
  "action": "status",
  "data": {}
}
```

**Success Response** (specific session):
```json
{
  "status": "success",
  "data": {
    "session_id": "12345",
    "pid": 12345,
    "app": "com.example.targetapp",
    "status": "active",
    "created_at": 1640995200,
    "scripts_loaded": 2,
    "trace_points": 5,
    "ssl_dumper_active": true
  }
}
```

**Success Response** (global status):
```json
{
  "status": "success",
  "data": {
    "daemon_status": "running",
    "uptime_seconds": 3600,
    "active_sessions": 3,
    "total_sessions_created": 10
  }
}
```

### 4. List Sessions

List all active sessions.

**Request**:
```json
{
  "action": "list",
  "data": {
    "filter": {                              // Optional filters
      "app": "com.example.targetapp",
      "status": "active"
    }
  }
}
```

**Success Response**:
```json
{
  "status": "success",
  "data": {
    "sessions": [
      {
        "session_id": "12345",
        "pid": 12345,
        "app": "com.example.targetapp",
        "status": "active",
        "created_at": 1640995200
      },
      {
        "session_id": "54321",
        "pid": 54321,
        "app": "com.netflix.mediaclient",
        "status": "active",
        "created_at": 1640995100
      }
    ],
    "total_count": 2
  }
}
```

### 5. Drain Messages

Retrieve and clear cached script messages from a session.

**Request**:
```json
{
  "action": "drain",
  "data": {
    "session": "12345"
  }
}
```

**Request Fields**:
- `action` (string, required): Must be "drain"
- `data.session` (string, required): Session ID (PID as string)

**Success Response**:
```json
{
  "status": "success",
  "data": {
    "session_id": "12345",
    "pid": 12345,
    "message_count": 2,
    "dropped_count": 0,
    "messages": [
      {"event": "enter", "type": "java_trace", "identifier": "MediaCodec.flush", "callId": 1},
      {"event": "exit", "type": "java_trace", "identifier": "MediaCodec.flush", "callId": 1}
    ]
  },
  "message": "Messages drained successfully"
}
```

**Notes**:
- The operation is atomic: messages are returned and cleared in a single step.
- The buffer capacity is 1000 messages per session. When exceeded, oldest messages are dropped and counted in `dropped_count`.
- Only JSON payloads are cached; binary data (e.g., from SSL captures) is not included.

## Error Codes

| HTTP Code | Error Code | Description |
|-----------|------------|-------------|
| 400 | BAD_REQUEST | Invalid JSON or missing required fields |
| 403 | PERMISSION_DENIED | Insufficient permissions |
| 404 | NOT_FOUND | Session or target not found |
| 409 | INVALID_STATE | Operation not allowed in current state |
| 500 | INTERNAL_ERROR | Server error or FRIDA failure |
| 408 | TIMEOUT | Operation timed out |

## Examples

### Start Netflix Tracing Session
```bash
curl -X POST http://0.0.0.0:34512/api/v1/session \\
  -H "Content-Type: application/json" \\
  -d '{
    "action": "start",
    "data": {
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
  }'
```

### List All Sessions
```bash
curl -X POST http://0.0.0.0:34512/api/v1/session \\
  -H "Content-Type: application/json" \\
  -d '{
    "action": "list",
    "data": {}
  }'
```

### Stop Session
```bash
curl -X POST http://0.0.0.0:34512/api/v1/session \\
  -H "Content-Type: application/json" \\
  -d '{
    "action": "stop",
    "data": {
      "session": "12345"
    }
  }'
```

### Drain Messages
```bash
curl -X POST http://0.0.0.0:34512/api/v1/session/messages \\
  -H "Content-Type: application/json" \\
  -d '{
    "action": "drain",
    "data": {
      "session": "12345"
    }
  }'
```

## Implementation Notes

1. **Session IDs**: Session IDs are currently the target process PID
2. **Concurrency**: The API supports concurrent requests
3. **Validation**: All requests are validated against the schema
4. **Error Handling**: Detailed error messages are provided for debugging
5. **CORS**: CORS headers are included for web client support