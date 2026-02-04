# Explorer Daemon API Reference

Complete API reference for Explorer daemon mode HTTP endpoints.

## Base Information

- **Base URL**: `http://host:port/api/v1/`
- **Default Port**: 34512
- **Protocol**: HTTP/1.1
- **Content-Type**: `application/json` (for POST requests)
- **Response Format**: JSON

## Authentication

Currently, no authentication is required. **⚠️ Warning**: Do not expose the daemon port to untrusted networks.

## Response Format

### Success Response
```json
{
  "success": true,
  "data": { /* response data */ },
  "message": "Operation completed successfully",
  "request_id": "req_1643723400_abc123",
  "timestamp": 1643723400,
  "version": "1.0.0"
}
```

### Error Response
```json
{
  "error": true,
  "code": 4001,
  "message": "Invalid JSON format",
  "details": "Syntax error at line 1, column 5: Expected property name",
  "field": "trace[0].method",
  "request_id": "req_1643723400_abc123",
  "timestamp": 1643723400,
  "context": {
    "received": "invalid_value",
    "expected": "string"
  }
}
```

## Error Codes

| Code | Name | HTTP Status | Description |
|------|------|-------------|-------------|
| 0 | Success | 200 | Operation completed successfully |
| 4000 | Bad Request | 400 | Invalid request format or parameters |
| 4001 | Invalid JSON | 400 | Malformed JSON in request body |
| 4002 | Missing Field | 400 | Required field missing from request |
| 4003 | Invalid Session ID | 400 | Session ID format is invalid |
| 4004 | Invalid App Name | 400 | Application package name is invalid |
| 4005 | Invalid Trace Config | 400 | Trace configuration is malformed |
| 4040 | Session Not Found | 404 | Requested session does not exist |
| 4041 | App Not Found | 404 | Target application not installed |
| 4080 | Request Timeout | 408 | Operation timed out |
| 4090 | Session Conflict | 409 | Session already exists for target |
| 4290 | Rate Limited | 429 | Request rate limit exceeded |
| 5000 | Internal Error | 500 | Unexpected server error |
| 5001 | FRIDA Error | 500 | FRIDA SDK operation failed |
| 5002 | State Error | 500 | State persistence operation failed |
| 5030 | Service Unavailable | 503 | Daemon is shutting down |

## Session Management Endpoints

### Start Session

**Endpoint**: `POST /api/v1/session/start`

**Description**: Creates and starts a new FRIDA session for the specified application.

**Request Body**:
```json
{
  "action": "start",
  "data": {
    "app": "com.example.package",
    "spawn": true,
    "pid": 12345,
    "am_start": "activity/.MainActivity",
    "timeout_seconds": 300,
    "scripts": ["/data/local/tmp/script.js"],
    "script_source": "console.log('Hello FRIDA');",
    "trace": [
      {
        "type": "java|native",
        "namespace": "std",
        "class": "android.media.MediaCodec",
        "method": "flush",
        "arguments": true,
        "log": true,
        "backtrace": true,
        "atrace": true,
        "transform": [
          {
            "index": 0,
            "new_value": "modified_value"
          }
        ],
        "dump": "/data/local/tmp/trace.sqlite"
      }
    ],
    "ssl_dumper": {
      "output": "/data/local/tmp/ssl_traffic.bin",
      "filter": {
        "ports": [443, 8080],
        "hosts": ["api.example.com"]
      }
    }
  }
}
```

**Request Fields**:
- `action` (string, required): Must be "start"
- `data` (object, required): Session configuration
  - `app` (string, conditional): Package name (required if no pid)
  - `spawn` (boolean, optional): Launch app if not running (default: false)
  - `pid` (integer, conditional): Existing process ID to attach
  - `am_start` (string, optional): Activity Manager start command
  - `timeout_seconds` (integer, optional): Session timeout (default: 300)
  - `scripts` (array, optional): External script file paths
  - `script_source` (string, optional): Inline JavaScript code
  - `trace` (array, optional): Function tracing configurations
  - `ssl_dumper` (object, optional): SSL traffic capture configuration

**Success Response**:
```json
{
  "success": true,
  "data": {
    "session_id": "12345",
    "pid": 12345,
    "app_name": "com.example.package",
    "status": "active",
    "created_at": "2024-01-15T10:30:00Z",
    "config": { /* original configuration */ }
  },
  "message": "Session started successfully",
  "request_id": "req_1643723400_abc123",
  "timestamp": 1643723400
}
```

**Example**:
```bash
curl -X POST http://192.168.1.100:34512/api/v1/session/start \
  -H "Content-Type: application/json" \
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
          "log": true,
          "backtrace": true
        }
      ]
    }
  }'
```

### Stop Session

**Endpoint**: `POST /api/v1/session/stop`

**Description**: Stops and removes an existing FRIDA session.

**Request Body**:
```json
{
  "action": "stop",
  "data": {
    "session": "12345",
    "force": false,
    "reason": "User requested"
  }
}
```

**Request Fields**:
- `action` (string, required): Must be "stop"
- `data` (object, required): Stop configuration
  - `session` (string, required): Session ID to stop, or "all" for all sessions
  - `force` (boolean, optional): Force termination (default: false)
  - `reason` (string, optional): Reason for stopping

**Success Response**:
```json
{
  "success": true,
  "data": {
    "session_id": "12345",
    "status": "stopped",
    "stopped_at": "2024-01-15T10:35:00Z",
    "duration_seconds": 300,
    "stats": {
      "messages_processed": 150,
      "bytes_captured": 51200,
      "functions_traced": 25
    }
  },
  "message": "Session stopped successfully",
  "request_id": "req_1643723401_def456",
  "timestamp": 1643723401
}
```

### Session Status

**Endpoint**: `POST /api/v1/session/status`

**Description**: Retrieves status information for one or all sessions.

**Request Body**:
```json
{
  "action": "status",
  "data": {
    "session": "12345",
    "include_stats": true,
    "include_config": false
  }
}
```

**Request Fields**:
- `action` (string, required): Must be "status"
- `data` (object, optional): Status query options
  - `session` (string, optional): Specific session ID, omit for all sessions
  - `include_stats` (boolean, optional): Include performance statistics (default: true)
  - `include_config` (boolean, optional): Include original configuration (default: false)

**Success Response (Single Session)**:
```json
{
  "success": true,
  "data": {
    "session_id": "12345",
    "pid": 12345,
    "app_name": "com.example.package",
    "status": "active",
    "created_at": "2024-01-15T10:30:00Z",
    "last_activity": "2024-01-15T10:34:30Z",
    "uptime_seconds": 270,
    "stats": {
      "messages_sent": 150,
      "messages_received": 145,
      "bytes_processed": 51200,
      "functions_traced": 25,
      "errors": 2
    }
  },
  "message": "Session status retrieved",
  "request_id": "req_1643723402_ghi789",
  "timestamp": 1643723402
}
```

**Success Response (All Sessions)**:
```json
{
  "success": true,
  "data": {
    "total_sessions": 3,
    "active_sessions": 2,
    "sessions": [
      {
        "session_id": "12345",
        "pid": 12345,
        "app_name": "com.example.package",
        "status": "active",
        "uptime_seconds": 270
      },
      {
        "session_id": "12346",
        "pid": 12346,
        "app_name": "com.another.app",
        "status": "inactive",
        "uptime_seconds": 150
      }
    ]
  },
  "message": "All session statuses retrieved",
  "request_id": "req_1643723403_jkl012",
  "timestamp": 1643723403
}
```

### List Sessions

**Endpoint**: `POST /api/v1/session/list`

**Description**: Lists sessions with optional filtering and pagination.

**Request Body**:
```json
{
  "action": "list",
  "data": {
    "filter": {
      "status": "active",
      "app": "com.example.*",
      "created_after": "2024-01-15T10:00:00Z",
      "created_before": "2024-01-15T11:00:00Z"
    },
    "sort": {
      "field": "created_at",
      "order": "desc"
    },
    "limit": 50,
    "offset": 0,
    "include_stats": false
  }
}
```

**Request Fields**:
- `action` (string, required): Must be "list"
- `data` (object, optional): List options
  - `filter` (object, optional): Filtering criteria
    - `status` (string, optional): Filter by status (active|inactive|failed)
    - `app` (string, optional): Filter by app name (supports wildcards)
    - `created_after` (string, optional): ISO 8601 timestamp
    - `created_before` (string, optional): ISO 8601 timestamp
  - `sort` (object, optional): Sorting options
    - `field` (string, optional): Sort field (created_at|app_name|status) (default: created_at)
    - `order` (string, optional): Sort order (asc|desc) (default: desc)
  - `limit` (integer, optional): Maximum results (default: 100, max: 1000)
  - `offset` (integer, optional): Results offset for pagination (default: 0)
  - `include_stats` (boolean, optional): Include performance stats (default: false)

**Success Response**:
```json
{
  "success": true,
  "data": {
    "total_count": 150,
    "filtered_count": 25,
    "limit": 50,
    "offset": 0,
    "sessions": [
      {
        "session_id": "12345",
        "pid": 12345,
        "app_name": "com.example.package",
        "status": "active",
        "created_at": "2024-01-15T10:30:00Z",
        "uptime_seconds": 270
      }
    ]
  },
  "message": "Sessions listed successfully",
  "request_id": "req_1643723404_mno345",
  "timestamp": 1643723404
}
```

### Drain Messages

**Endpoint**: `POST /api/v1/session/messages`

**Description**: Atomically drains (retrieves and clears) cached script messages from a session. Messages are buffered as they arrive from FRIDA agents (function trace events, SSL events, etc.) and this endpoint returns all buffered messages since the last drain.

**Request Body**:
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
- `data` (object, required): Drain parameters
  - `session` (string, required): Session ID (PID) to drain messages from

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

**Response Fields**:
- `session_id` (string): The session ID that was drained
- `pid` (integer): The PID of the target process
- `message_count` (integer): Number of messages returned
- `dropped_count` (integer): Number of messages lost due to buffer overflow since the last drain. The internal buffer holds up to 1000 messages; oldest messages are discarded when this limit is exceeded.
- `messages` (array): The drained message payloads (JSON objects from FRIDA agent `send()` calls)

**Example**:
```bash
curl -X POST http://192.168.1.100:34512/api/v1/session/messages \
  -H "Content-Type: application/json" \
  -d '{
    "action": "drain",
    "data": {
      "session": "29851"
    }
  }'
```

**Notes**:
- Only JSON payloads are cached; binary data from SSL captures is not included.
- The buffer is cleared after each drain call. Calling drain again immediately returns an empty messages array.
- If no messages have been received, the response contains an empty `messages` array with `message_count: 0`.
- Use `dropped_count` to detect if your drain polling interval is too slow for the message volume.

## Generic Session Dispatcher

**Endpoint**: `POST /api/v1/session`

**Description**: Generic endpoint that routes to specific session actions based on the `action` field.

**Request Body**: Same as individual endpoints, with the `action` field determining the operation.

**Supported Actions**:
- `start` - Routes to session start logic
- `stop` - Routes to session stop logic
- `status` - Routes to session status logic
- `list` - Routes to session list logic
- `drain` - Routes to message drain logic

## Alternative Endpoints

For convenience, the following alternative endpoints are also available:

- `POST /session/start` - Equivalent to `/api/v1/session/start`
- `POST /session/stop` - Equivalent to `/api/v1/session/stop`
- `POST /session/status` - Equivalent to `/api/v1/session/status`
- `POST /session/list` - Equivalent to `/api/v1/session/list`
- `POST /session/messages` - Equivalent to `/api/v1/session/messages`

## Health and Monitoring Endpoints

### Basic Health Check

**Endpoint**: `GET /health`

**Description**: Simple health check endpoint for load balancers.

**Response**:
```json
{
  "status": "healthy",
  "healthy": true,
  "timestamp": 1643723400,
  "service": "explorer-daemon",
  "version": "1.0.0",
  "uptime_seconds": 86400
}
```

### Detailed Health Check

**Endpoint**: `GET /api/v1/health`

**Description**: Comprehensive health check with component status.

**Response**:
```json
{
  "success": true,
  "data": {
    "status": "healthy",
    "healthy": true,
    "timestamp": 1643723400,
    "service": "explorer-daemon",
    "version": "1.0.0",
    "uptime_seconds": 86400,
    "check_duration_ms": 15,
    "components": {
      "daemon": {
        "status": "healthy",
        "running": true,
        "message": "Daemon operational"
      },
      "frida": {
        "status": "healthy",
        "initialized": true,
        "active_sessions": 3,
        "total_sessions": 25,
        "message": "FRIDA runtime available"
      },
      "state_manager": {
        "status": "healthy",
        "initialized": true,
        "state_saves": 18,
        "recovery_attempts": 1,
        "message": "State persistence operational"
      },
      "http_server": {
        "status": "healthy",
        "running": true,
        "port": 34512,
        "message": "HTTP server listening"
      },
      "system": {
        "status": "healthy",
        "disk": {
          "usage_percent": 45.2,
          "free_bytes": 5368709120,
          "status": "ok"
        },
        "memory": {
          "usage_percent": 32.1,
          "available_bytes": 2147483648,
          "status": "ok"
        },
        "load_average": {
          "1min": 0.8,
          "5min": 0.6,
          "15min": 0.4,
          "status": "ok"
        },
        "cpu_cores": 4,
        "message": "System resources healthy"
      }
    }
  },
  "message": "Health check completed",
  "request_id": "req_1643723405_pqr678",
  "timestamp": 1643723405
}
```

### Metrics Collection

**Endpoint**: `GET /api/v1/metrics`

**Description**: Comprehensive operational metrics for monitoring.

**Response**:
```json
{
  "success": true,
  "data": {
    "timestamp": 1643723400,
    "service": "explorer-daemon",
    "metrics_version": "1.0",
    "collection_duration_ms": 12,
    "daemon": {
      "status": "running",
      "uptime_seconds": 86400,
      "total_sessions_created": 150,
      "active_sessions_count": 5,
      "failed_sessions_count": 3,
      "restart_count": 0,
      "last_restart": null
    },
    "http_server": {
      "status": "running",
      "port": 34512,
      "total_requests": 1250,
      "successful_requests": 1205,
      "failed_requests": 45,
      "success_rate_percent": 96.4,
      "average_response_time_ms": 145.2,
      "requests_per_second": 2.1,
      "handlers": {
        "StartSessionHandler": {
          "total_requests": 150,
          "successful_requests": 145,
          "failed_requests": 5,
          "success_rate_percent": 96.7,
          "average_response_time_ms": 245.8
        },
        "StopSessionHandler": {
          "total_requests": 148,
          "successful_requests": 148,
          "failed_requests": 0,
          "success_rate_percent": 100.0,
          "average_response_time_ms": 25.2
        }
      }
    },
    "sessions": {
      "active_count": 5,
      "total_created": 150,
      "successful_count": 145,
      "failed_count": 5,
      "success_rate_percent": 96.7,
      "average_duration_seconds": 1800,
      "total_bytes_processed": 52428800
    },
    "state_persistence": {
      "status": "operational",
      "saves_count": 18,
      "loads_count": 1,
      "recovery_attempts": 1,
      "orphaned_cleaned": 0,
      "history_size": 22,
      "last_save": "2024-01-15T10:34:30Z"
    },
    "system": {
      "cpu": {
        "user_time_percent": 12.4,
        "system_time_percent": 3.2,
        "idle_time_percent": 84.4
      },
      "memory": {
        "resident_bytes": 45678592,
        "virtual_bytes": 123456768,
        "heap_bytes": 34567890,
        "usage_percent": 15.2
      },
      "disk": {
        "total_bytes": 16106127360,
        "free_bytes": 8832008192,
        "usage_percent": 45.2,
        "io_read_bytes": 1048576000,
        "io_write_bytes": 524288000
      },
      "network": {
        "bytes_sent": 10485760,
        "bytes_received": 20971520,
        "connections_active": 12,
        "connections_total": 1250
      },
      "file_descriptors": {
        "current": 45,
        "max": 1024,
        "usage_percent": 4.4
      }
    },
    "errors": {
      "total_errors": 8,
      "handler_errors": 5,
      "frida_errors": 2,
      "system_errors": 1,
      "last_error": {
        "code": 5001,
        "message": "FRIDA attachment failed",
        "timestamp": "2024-01-15T10:32:15Z"
      }
    }
  },
  "message": "Metrics collected successfully",
  "request_id": "req_1643723406_stu901",
  "timestamp": 1643723406
}
```

### Daemon Statistics

**Endpoint**: `GET /api/v1/daemon/stats`

**Description**: High-level daemon statistics and performance data.

**Query Parameters**:
- `format` (string, optional): Response format (json|prometheus) (default: json)

**Response**:
```json
{
  "success": true,
  "data": {
    "daemon": {
      "status": "running",
      "uptime_seconds": 86400,
      "start_time": "2024-01-14T10:30:00Z",
      "version": "1.0.0",
      "build": "abc123def",
      "pid": 9876
    },
    "sessions": {
      "total_created": 150,
      "currently_active": 5,
      "total_failed": 3,
      "success_rate_percent": 98.0
    },
    "performance": {
      "memory_usage_mb": 45.2,
      "cpu_usage_percent": 12.1,
      "requests_per_second": 2.1,
      "average_response_time_ms": 145.2
    },
    "system": {
      "platform": "Android TV",
      "architecture": "armv7a",
      "android_version": "9.0",
      "available_memory_mb": 2048,
      "available_disk_gb": 8.2
    }
  },
  "message": "Daemon statistics retrieved",
  "request_id": "req_1643723407_vwx234",
  "timestamp": 1643723407
}
```

### Session History

**Endpoint**: `GET /api/v1/daemon/history`

**Description**: Historical session data with filtering and pagination.

**Query Parameters**:
- `limit` (integer, optional): Maximum results (default: 100, max: 1000)
- `offset` (integer, optional): Results offset (default: 0)
- `status` (string, optional): Filter by status (active|inactive|failed)
- `app` (string, optional): Filter by app name (supports wildcards)
- `since` (string, optional): ISO 8601 timestamp - show sessions since this time
- `format` (string, optional): Response format (json|csv) (default: json)

**Response**:
```json
{
  "success": true,
  "data": {
    "total_count": 150,
    "filtered_count": 25,
    "limit": 100,
    "offset": 0,
    "sessions": [
      {
        "session_id": "12345",
        "pid": 12345,
        "app_name": "com.example.package",
        "status": "completed",
        "created_at": "2024-01-15T10:30:00Z",
        "ended_at": "2024-01-15T10:35:00Z",
        "duration_seconds": 300,
        "reason": "User stopped",
        "stats": {
          "messages_processed": 150,
          "bytes_captured": 51200,
          "functions_traced": 25,
          "errors": 0
        }
      }
    ]
  },
  "message": "Session history retrieved",
  "request_id": "req_1643723408_yza567",
  "timestamp": 1643723408
}
```

## Trace Configuration Reference

### Java Method Tracing
```json
{
  "type": "java",
  "class": "android.media.MediaCodec",
  "method": "flush",
  "arguments": true,
  "log": true,
  "backtrace": true,
  "atrace": true,
  "transform": [
    {
      "index": 0,
      "new_value": "modified_arg"
    },
    {
      "index": -1,
      "new_value": "modified_return"
    }
  ],
  "dump": "/data/local/tmp/java_trace.sqlite"
}
```

### Native Function Tracing
```json
{
  "type": "native",
  "namespace": "std",
  "class": "string",
  "method": "append",
  "arguments": true,
  "log": true,
  "backtrace": true,
  "dump": "/data/local/tmp/native_trace.sqlite"
}
```

### SSL Dumper Configuration
```json
{
  "output": "/data/local/tmp/ssl_traffic.bin",
  "filter": {
    "ports": [443, 8080, 8443],
    "hosts": ["api.example.com", "*.googleapis.com"],
    "protocols": ["TLSv1.2", "TLSv1.3"]
  },
  "format": "pcap",
  "max_size_mb": 100,
  "rotation": true
}
```

## Rate Limiting

The daemon implements rate limiting to prevent abuse:

- **Global Rate Limit**: 100 requests per second (default)
- **Per-IP Rate Limit**: 50 requests per second per IP
- **Burst Allowance**: 10 requests above limit for short bursts

When rate limited, the response includes:
```json
{
  "error": true,
  "code": 4290,
  "message": "Rate limit exceeded",
  "details": "Too many requests. Limit: 100/sec, Current: 125/sec",
  "request_id": "req_1643723409_bcd890",
  "timestamp": 1643723409,
  "retry_after": 5
}
```

## WebSocket Support (Future)

*Note: WebSocket support is planned for future releases*

**Endpoint**: `WS /api/v1/events`

**Description**: Real-time event streaming for session updates, trace data, and system events.

## Client Libraries

### Python Client Example
```python
import requests
import json

class ExplorerClient:
    def __init__(self, host='192.168.1.100', port=34512):
        self.base_url = f'http://{host}:{port}/api/v1'

    def start_session(self, app_name, **kwargs):
        data = {'action': 'start', 'data': {'app': app_name, **kwargs}}
        response = requests.post(f'{self.base_url}/session/start', json=data)
        return response.json()

    def stop_session(self, session_id):
        data = {'action': 'stop', 'data': {'session': session_id}}
        response = requests.post(f'{self.base_url}/session/stop', json=data)
        return response.json()

    def drain_messages(self, session_id):
        data = {'action': 'drain', 'data': {'session': session_id}}
        response = requests.post(f'{self.base_url}/session/messages', json=data)
        return response.json()

    def get_health(self):
        response = requests.get(f'{self.base_url}/health')
        return response.json()

# Usage
client = ExplorerClient('192.168.1.100')
result = client.start_session('com.netflix.mediaclient', spawn=True)
print(f"Session ID: {result['data']['session_id']}")
```

### JavaScript Client Example
```javascript
class ExplorerClient {
    constructor(host = '192.168.1.100', port = 34512) {
        this.baseUrl = `http://${host}:${port}/api/v1`;
    }

    async startSession(appName, options = {}) {
        const data = { action: 'start', data: { app: appName, ...options } };
        const response = await fetch(`${this.baseUrl}/session/start`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        });
        return await response.json();
    }

    async stopSession(sessionId) {
        const data = { action: 'stop', data: { session: sessionId } };
        const response = await fetch(`${this.baseUrl}/session/stop`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        });
        return await response.json();
    }

    async drainMessages(sessionId) {
        const data = { action: 'drain', data: { session: sessionId } };
        const response = await fetch(`${this.baseUrl}/session/messages`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        });
        return await response.json();
    }

    async getHealth() {
        const response = await fetch(`${this.baseUrl}/health`);
        return await response.json();
    }
}

// Usage
const client = new ExplorerClient('192.168.1.100');
const result = await client.startSession('com.netflix.mediaclient', { spawn: true });
console.log(`Session ID: ${result.data.session_id}`);
```

---

This API reference provides complete documentation for all Explorer daemon endpoints. For implementation details, see [DAEMON_MODE.md](DAEMON_MODE.md).