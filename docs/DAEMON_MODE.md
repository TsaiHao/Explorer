# Explorer Daemon Mode - Technical Documentation

This document provides detailed technical information about Explorer's daemon mode implementation, architecture, and advanced usage patterns.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                     Explorer Daemon Architecture                │
├─────────────────────────────────────────────────────────────────┤
│  HTTP Layer                                                     │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │   HttpServer │  │  ApiRouter  │  │  Handlers   │             │
│  │   (cpp-httplib) │  (Routing)   │  (Business    │             │
│  │              │  │             │  │  Logic)     │             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
├─────────────────────────────────────────────────────────────────┤
│  Application Layer                                              │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │                ApplicationDaemon                            │ │
│  │  • Session management         • State persistence          │ │
│  │  • Request routing           • Error handling              │ │
│  │  • Health monitoring         • Metrics collection          │ │
│  └─────────────────────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────────┤
│  FRIDA Layer                                                    │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │   Device    │  │   Session   │  │   Script    │             │
│  │   Manager   │  │   Manager   │  │   Manager   │             │
│  │             │  │             │  │             │             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
├─────────────────────────────────────────────────────────────────┤
│  Plugin Layer                                                  │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │ Function    │  │  SSL        │  │   Custom    │             │
│  │ Tracer      │  │  Dumper     │  │   Plugins   │             │
│  │             │  │             │  │             │             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
├─────────────────────────────────────────────────────────────────┤
│  System Layer                                                  │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │ State       │  │ Error       │  │ Threading   │             │
│  │ Manager     │  │ Handling    │  │ Support     │             │
│  │             │  │             │  │             │             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
└─────────────────────────────────────────────────────────────────┘
```

## Core Components

### ApplicationDaemon Class

The `ApplicationDaemon` class is the central orchestrator for daemon mode operation.

#### Key Responsibilities
- **HTTP Server Management**: Start/stop HTTP server lifecycle
- **Session Orchestration**: Create, manage, and destroy FRIDA sessions
- **State Persistence**: Maintain session state across restarts
- **Health Monitoring**: System and component health tracking
- **Error Management**: Structured error handling and reporting

#### Public Interface
```cpp
class ApplicationDaemon {
public:
  // Lifecycle management
  Status Initialize();
  Status Run();
  void Shutdown();
  bool IsRunning() const;

  // Session management
  Result<json, Status> StartSession(const json& config);
  Status StopSession(const std::string& session_id);
  Result<json, Status> GetSessionStatus(const std::string& session_id = "");
  Result<json, Status> ListSessions(const json& filter = json::object());
  Result<json, Status> DrainSessionMessages(const std::string& session_id);

  // Monitoring and diagnostics
  Result<json, Status> GetDaemonStats();
  Result<json, Status> GetSessionHistory(size_t limit = 100);
  Result<json, Status> GetHealthStatus();
  Result<json, Status> GetMetrics();
};
```

### HTTP Server Infrastructure

#### HttpServer Class
- Built on `cpp-httplib` for lightweight HTTP handling
- Thread-pool based request processing
- Configurable timeouts and connection limits
- CORS and security header support

#### Request Handlers Architecture
All request handlers inherit from `EnhancedRequestHandler` which provides:
- Automatic request ID generation
- Request/response timing
- Rate limiting enforcement
- Structured error responses
- Metrics collection

#### Handler Types
1. **StartSessionHandler** - Creates new FRIDA sessions
2. **StopSessionHandler** - Terminates existing sessions
3. **StatusHandler** - Queries session status information
4. **ListSessionsHandler** - Lists and filters sessions
5. **DrainMessagesHandler** - Drains cached script messages from sessions
6. **HealthHandler** - Component and system health checks
7. **MetricsHandler** - Performance and operational metrics
8. **StatsHandler** - Daemon statistics and uptime info
9. **SessionDispatcherHandler** - Generic session command routing

### State Management

#### StateManager Class
Handles persistent state across daemon restarts:
```cpp
class StateManager {
public:
  Status Initialize(const std::string& state_file_path);
  Status SaveSessionState(const SessionState& session_state);
  Result<std::vector<SessionState>, Status> LoadSessionStates();
  Result<size_t, Status> PerformRecovery(
      std::function<bool(pid_t)> cleanup_callback);
  Status SaveDaemonStats(const json& stats);
  Result<json, Status> LoadDaemonStats();
  Status RotateStateFile(size_t max_history_size = 1000);
};
```

#### Session State Schema
```json
{
  "pid": 12345,
  "app_name": "com.example.app",
  "status": "active|inactive|failed",
  "created_at": "2024-01-15T10:30:00Z",
  "last_activity": "2024-01-15T10:35:00Z",
  "config": { /* original session config */ },
  "stats": {
    "messages_sent": 150,
    "bytes_processed": 51200,
    "errors": 2
  }
}
```

### Error Handling System

#### Structured Error Framework
```cpp
enum class ErrorCode {
  kSuccess = 0,
  kBadRequest = 4000,
  kInvalidJson = 4001,
  kMissingField = 4002,
  kInvalidSessionId = 4003,
  kNotFound = 4040,
  kTimeout = 4080,
  kConflict = 4090,
  kRateLimited = 4290,
  kInternalError = 5000,
  kFridaError = 5001,
  kServiceUnavailable = 5030
};

struct ErrorInfo {
  ErrorCode code;
  std::string message;
  std::string details;
  std::string field;        // Optional field name for validation errors
  std::string request_id;   // Request correlation ID
  json context;             // Additional error context

  json ToJson() const;
  int GetHttpStatusCode() const;
};
```

#### Request Context Tracking
```cpp
struct RequestContext {
  std::string request_id;
  std::string endpoint;
  std::string method;
  std::string client_ip;
  std::chrono::steady_clock::time_point start_time;
  size_t request_size;
  size_t response_size;

  double GetDurationMs() const;
  json ToJson() const;
};
```

## Threading Architecture

### Thread Safety Model
- **Main Thread**: HTTP server and request dispatching
- **Worker Threads**: Session processing and FRIDA operations
- **Background Thread**: State persistence and cleanup
- **Monitoring Thread**: Health checks and metrics collection

### Synchronization Primitives
- `std::mutex` for session map access
- `std::shared_mutex` for read-heavy operations
- `std::atomic` for counters and flags
- `std::condition_variable` for graceful shutdown

### Concurrent Session Management
```cpp
class SessionManager {
private:
  mutable std::shared_mutex sessions_mutex_;
  std::unordered_map<pid_t, std::unique_ptr<Session>> sessions_;
  std::atomic<size_t> session_counter_;
  std::atomic<bool> shutdown_requested_;

public:
  // Thread-safe session operations
  Result<json, Status> CreateSession(const json& config);
  Status RemoveSession(pid_t pid);
  Result<json, Status> GetSessionInfo(pid_t pid) const;
  std::vector<json> ListAllSessions() const;
};
```

## API Design Patterns

### Dual API Access
Explorer daemon provides two API access patterns:

1. **Specialized Endpoints** (Recommended)
   - Direct endpoint mapping: `POST /api/v1/session/start`
   - Type-safe and optimized
   - Clear separation of concerns

2. **Generic Dispatcher** (Advanced)
   - Unified endpoint: `POST /api/v1/session`
   - Action-based routing via JSON payload
   - Flexible for dynamic clients

### Response Standardization
All API responses follow the JSON:API inspired format:
```json
{
  "success": true|false,
  "data": { /* response payload */ },
  "message": "Human readable message",
  "request_id": "req_1234567890",
  "timestamp": 1643723400,
  "version": "1.0.0"
}
```

Error responses include additional fields:
```json
{
  "error": true,
  "code": 4001,
  "message": "Invalid JSON format",
  "details": "Syntax error at line 5, column 12",
  "field": "trace[0].method",
  "request_id": "req_1234567890",
  "timestamp": 1643723400
}
```

### Validation Pipeline
1. **HTTP Level**: Content-type, method validation
2. **JSON Level**: Syntax and structure validation
3. **Schema Level**: Required fields and data types
4. **Business Level**: FRIDA-specific validation
5. **Security Level**: Rate limiting and authorization

## Health Monitoring System

### Health Check Levels
1. **Basic Health** (`/health`) - Load balancer compatible
2. **Detailed Health** (`/api/v1/health`) - Component breakdown
3. **Diagnostics** (`/api/v1/diagnostics`) - Deep system analysis

### Component Health Matrix
```cpp
enum class ComponentStatus {
  kHealthy,      // Normal operation
  kWarning,      // Degraded but functional
  kCritical,     // Severe issues
  kUnhealthy     // Component failure
};

struct ComponentHealth {
  ComponentStatus status;
  std::string message;
  std::chrono::system_clock::time_point last_check;
  json metrics;  // Component-specific metrics
};
```

### System Resource Monitoring
- **CPU Usage**: Process and system CPU utilization
- **Memory Usage**: RSS, VSS, and heap statistics
- **Disk Space**: Available space and I/O statistics
- **Network**: Connection counts and bandwidth usage
- **File Descriptors**: Current usage vs. limits

## Metrics Collection

### Metric Categories
1. **Daemon Metrics**: Uptime, restarts, total sessions
2. **HTTP Metrics**: Request counts, response times, error rates
3. **Session Metrics**: Active count, success rate, failure types
4. **FRIDA Metrics**: Attachment success, script load times
5. **System Metrics**: Resource utilization, performance counters

### Metrics Storage Format
```json
{
  "timestamp": 1643723400,
  "collection_duration_ms": 12,
  "daemon": {
    "status": "running",
    "uptime_seconds": 86400,
    "total_sessions_created": 150,
    "active_sessions_count": 5,
    "failed_sessions_count": 3,
    "restart_count": 1
  },
  "http_server": {
    "status": "running",
    "total_requests": 1250,
    "successful_requests": 1205,
    "failed_requests": 45,
    "average_response_time_ms": 145.2,
    "requests_per_second": 2.1
  },
  "sessions": {
    "active_count": 5,
    "total_created": 150,
    "success_rate_percent": 97.3,
    "average_duration_seconds": 1800
  },
  "system": {
    "cpu_usage_percent": 15.2,
    "memory": {
      "resident_bytes": 52428800,
      "virtual_bytes": 134217728,
      "usage_percent": 12.5
    },
    "disk": {
      "usage_percent": 45.2,
      "free_bytes": 5368709120
    },
    "file_descriptors": {
      "current": 45,
      "max": 1024
    }
  }
}
```

## Security Considerations

### Rate Limiting
- **Global Rate Limit**: Requests per second across all clients
- **Per-IP Rate Limit**: Requests per IP address
- **Per-Session Rate Limit**: Operations per session
- **Burst Allowance**: Short-term request bursts

### Request Validation
- **Content-Type Enforcement**: JSON only for POST requests
- **Size Limits**: Request body size limits
- **Schema Validation**: JSON schema enforcement
- **Field Sanitization**: Input sanitization and validation

### Security Headers
```http
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Content-Security-Policy: default-src 'none'
Strict-Transport-Security: max-age=31536000
```

### Audit Logging
All requests are logged with:
- Request ID for correlation
- Client IP address
- Timestamp and duration
- Request/response sizes
- Success/failure status
- Error details if applicable

## Performance Optimization

### Connection Management
- **Keep-Alive**: HTTP persistent connections
- **Connection Pooling**: Reuse existing connections
- **Timeout Configuration**: Configurable read/write timeouts
- **Graceful Shutdown**: Proper connection draining

### Memory Management
- **Object Pooling**: Reuse expensive objects
- **Smart Pointers**: Automatic memory management
- **Buffer Management**: Efficient buffer allocation
- **Garbage Collection**: Periodic cleanup of stale objects

### Session Optimization
- **Lazy Loading**: Load sessions only when needed
- **Session Caching**: Cache frequently accessed sessions
- **Background Cleanup**: Asynchronous session cleanup
- **Resource Limits**: Maximum concurrent sessions

## Configuration Reference

### Command Line Arguments
```bash
./explorer --daemon [options]

Options:
  --host HOST              Bind address (default: 127.0.0.1)
  --port PORT              HTTP port (default: 34512)
  --state-file FILE        State persistence file
  --log-level LEVEL        Logging level (trace|debug|info|warn|error)
  --pid-file FILE          Process ID file location
  --max-sessions N         Maximum concurrent sessions (default: 50)
  --rate-limit N           Requests per second limit (default: 100)
  --worker-threads N       HTTP worker thread count (default: 4)
  --request-timeout MS     Request timeout in milliseconds (default: 30000)
  --session-timeout MS     Session timeout in milliseconds (default: 300000)
  --enable-cors            Enable CORS headers
  --daemonize              Run in background (double-fork)
```

### Environment Variables
```bash
export EXPLORER_HOST=0.0.0.0
export EXPLORER_PORT=8080
export EXPLORER_STATE_FILE=/data/local/tmp/explorer_state.json
export EXPLORER_LOG_LEVEL=info
export EXPLORER_MAX_SESSIONS=100
export EXPLORER_RATE_LIMIT=200
```

## Production Deployment

### Systemd Service Configuration
```ini
[Unit]
Description=Explorer FRIDA Daemon
After=network.target
Requires=network.target

[Service]
Type=forking
User=root
ExecStart=/data/local/tmp/explorer --daemon --host 0.0.0.0 --port 34512 --daemonize
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=5
PIDFile=/data/local/tmp/explorer.pid

[Install]
WantedBy=multi-user.target
```

### Docker Configuration
```dockerfile
FROM android-tv-base:latest

# Install Explorer
COPY build/explorer /usr/local/bin/explorer
RUN chmod +x /usr/local/bin/explorer

# Configure runtime
EXPOSE 34512
VOLUME ["/data/state"]

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s \
  CMD curl -f http://localhost:34512/health || exit 1

# Run daemon
CMD ["explorer", "--daemon", "--host", "0.0.0.0", "--port", "34512"]
```

### Monitoring Integration

#### Prometheus Metrics
Expose metrics in Prometheus format:
```
# HELP explorer_sessions_active Current active sessions
# TYPE explorer_sessions_active gauge
explorer_sessions_active 5

# HELP explorer_requests_total Total HTTP requests
# TYPE explorer_requests_total counter
explorer_requests_total{method="POST",endpoint="/api/v1/session/start"} 150

# HELP explorer_request_duration_seconds Request duration histogram
# TYPE explorer_request_duration_seconds histogram
explorer_request_duration_seconds_bucket{le="0.1"} 100
explorer_request_duration_seconds_bucket{le="0.5"} 145
explorer_request_duration_seconds_bucket{le="1.0"} 148
explorer_request_duration_seconds_bucket{le="+Inf"} 150
```

#### Grafana Dashboard
Key metrics to monitor:
- Session success rate over time
- HTTP request rates and latency
- System resource utilization
- Error rates by category
- Session lifecycle metrics

## Troubleshooting Guide

### Common Issues

**High Memory Usage**
```bash
# Check memory metrics
curl http://localhost:34512/api/v1/metrics | jq '.data.system.memory'

# Monitor session count
curl http://localhost:34512/api/v1/daemon/stats | jq '.data.active_sessions_count'

# Review session history for leaks
curl http://localhost:34512/api/v1/daemon/history | jq '.data[].status'
```

**HTTP Connection Issues**
```bash
# Test basic connectivity
curl -v http://localhost:34512/health

# Check server logs
journalctl -u explorer -f

# Verify firewall rules
iptables -L | grep 34512
```

**Session Creation Failures**
```bash
# Check FRIDA status
frida-ps -U

# Review error details
curl -X POST http://localhost:34512/api/v1/session/start \
  -H "Content-Type: application/json" \
  -d '{"action": "start", "data": {"app": "com.example.app"}}' | jq
```

### Debug Mode
Enable verbose logging:
```bash
./explorer --daemon --log-level debug --host 0.0.0.0 --port 34512
```

### Performance Profiling
```bash
# CPU profiling
perf record -g ./explorer --daemon
perf report

# Memory profiling
valgrind --tool=massif ./explorer --daemon

# Network profiling
ss -tuln | grep :34512
netstat -i
```

---

This technical documentation provides deep insights into Explorer's daemon mode architecture and implementation. For user-facing documentation, see the main [README.md](../README.md).