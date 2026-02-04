# Explorer Daemon Operation Guide

## Overview

The Explorer main entry point has been completely redesigned to support professional daemon operation alongside backward compatibility with the original config-file mode. The daemon runs as a persistent background service, providing HTTP API access to dynamic instrumentation capabilities.

## Command Line Interface

### Basic Usage

```bash
# Start daemon on default port (34512)
./explorer

# Start daemon on custom port
./explorer --port 8080

# Start daemon in foreground (development mode)
./explorer --foreground

# Use legacy config-file mode
./explorer --legacy

# Show help
./explorer --help
```

### Command Line Options

#### Mode Selection
- `--daemon` - Run in daemon mode (default)
- `--legacy` - Run in legacy config-file mode
- `--foreground` - Run daemon in foreground (don't fork)

#### Daemon Configuration
- `--host HOST` - Bind to specific host (default: 0.0.0.0)
- `--port PORT` - Listen on specific port (default: 34512)
- `--config-dir DIR` - Configuration directory (default: /data/local/tmp)
- `--pid-file PATH` - PID file location (default: /data/local/tmp/explorer.pid)

#### General Options
- `--help` - Show comprehensive help message
- `--version` - Show version information

### Usage Examples

```bash
# Production daemon
./explorer --daemon --port 34512

# Development daemon (stays in terminal)
./explorer --foreground --port 8080 --host 127.0.0.1

# Custom configuration paths
./explorer --config-dir /var/lib/explorer --pid-file /var/run/explorer.pid

# Legacy mode for existing deployments
./explorer --legacy
```

## Daemon Architecture

### Process Model

The Explorer daemon implements a professional UNIX daemon architecture:

1. **Double Fork Pattern**: Prevents daemon from acquiring controlling terminal
2. **Session Leader**: Creates new session with `setsid()`
3. **Working Directory**: Changes to root (/) to avoid mount point issues
4. **File Descriptors**: Closes all inherited descriptors and redirects stdio
5. **File Permissions**: Sets umask(0) for predictable file permissions
6. **PID Management**: Creates and manages PID file for process tracking

### Signal Handling

The daemon responds to standard UNIX signals:

- **SIGINT** (Ctrl+C): Graceful shutdown
- **SIGTERM**: Daemon termination (used by service managers)
- **SIGHUP**: Configuration reload hook (planned future feature)
- **SIGPIPE**: Ignored to prevent HTTP connection crashes

### Logging

#### Daemon Mode (Background)
- Uses `syslog` facility with LOG_DAEMON
- Messages include PID for process identification
- Viewable with `journalctl -u explorer` (systemd) or `/var/log/daemon.log`

#### Foreground Mode (Development)
- Uses console logging via spdlog
- Real-time log output for debugging
- Colored output for better readability

## PID File Management

### Automatic PID File Handling

The daemon automatically manages its PID file:

```bash
# Default location
/data/local/tmp/explorer.pid

# Custom location
./explorer --pid-file /var/run/explorer.pid
```

### Duplicate Prevention

The daemon prevents multiple instances:
1. Checks for existing PID file
2. Verifies if process is still running
3. Removes stale PID files automatically
4. Exits with error if another instance is running

### Manual Process Management

```bash
# Check if daemon is running
if [ -f /data/local/tmp/explorer.pid ]; then
  pid=$(cat /data/local/tmp/explorer.pid)
  if kill -0 $pid 2>/dev/null; then
    echo "Daemon running with PID: $pid"
  else
    echo "Stale PID file found"
  fi
else
  echo "Daemon not running"
fi

# Stop daemon gracefully
kill $(cat /data/local/tmp/explorer.pid)

# Force stop daemon
kill -9 $(cat /data/local/tmp/explorer.pid)
```

## Service Integration

### Systemd Service

Create `/etc/systemd/system/explorer.service`:

```ini
[Unit]
Description=Explorer FRIDA Instrumentation Daemon
After=network.target
Requires=network.target

[Service]
Type=forking
ExecStart=/usr/local/bin/explorer --daemon --port 34512
PIDFile=/var/run/explorer.pid
User=root
Group=root

# Restart policy
Restart=always
RestartSec=5
StartLimitInterval=60
StartLimitBurst=3

# Security (adjust as needed)
NoNewPrivileges=false
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/data/local/tmp /var/log

# Environment
Environment=PATH=/usr/local/bin:/usr/bin:/bin

[Install]
WantedBy=multi-user.target
```

### Service Management Commands

```bash
# Install service
sudo systemctl daemon-reload
sudo systemctl enable explorer

# Start/stop service
sudo systemctl start explorer
sudo systemctl stop explorer
sudo systemctl restart explorer

# Check status
sudo systemctl status explorer
sudo journalctl -u explorer -f  # Follow logs

# Boot configuration
sudo systemctl enable explorer   # Auto-start on boot
sudo systemctl disable explorer  # Disable auto-start
```

### SysV Init Script

For systems without systemd, create `/etc/init.d/explorer`:

```bash
#!/bin/bash
# explorer        Explorer FRIDA Instrumentation Daemon
# chkconfig: 35 99 99
# description: Dynamic instrumentation daemon

. /etc/rc.d/init.d/functions

USER="root"
DAEMON="explorer"
ROOT_DIR="/usr/local/bin"
PID_FILE="/var/run/explorer.pid"

LOCK_FILE="/var/lock/subsys/explorer"

start() {
    if [ -f $PID_FILE ]; then
        echo "Explorer is already running"
        return 1
    fi

    echo -n "Starting $DAEMON: "
    runuser -l "$USER" -c "$ROOT_DIR/$DAEMON --daemon --pid-file $PID_FILE" && echo_success || echo_failure
    RETVAL=$?
    echo
    [ $RETVAL -eq 0 ] && touch $LOCK_FILE
    return $RETVAL
}

stop() {
    echo -n "Shutting down $DAEMON: "
    pid=`ps -aefw | grep "$DAEMON" | grep -v " grep " | awk '{print $2}'`
    kill -9 $pid > /dev/null 2>&1
    [ $? -eq 0 ] && echo_success || echo_failure
    echo
    [ $RETVAL -eq 0 ] && rm -f $LOCK_FILE
    return $RETVAL
}

# Service actions
case "$1" in
    start)
        start
        ;;
    stop)
        stop
        ;;
    status)
        status $DAEMON
        ;;
    restart)
        stop
        start
        ;;
    *)
        echo "Usage: {start|stop|status|restart}"
        exit 1
        ;;
esac
```

## Application Mode Selection

### ApplicationDaemon (Default)

**Features**:
- HTTP API server on configurable port
- Dynamic session management
- JSON-based command interface
- Persistent operation
- Thread-safe concurrent request handling

**Use Cases**:
- Production deployments
- API-driven instrumentation
- Remote session management
- Integration with external tools

### Application (Legacy Mode)

**Features**:
- Config file based operation (`/data/local/tmp/config.json`)
- Single-run execution
- Batch instrumentation jobs
- Original Explorer behavior

**Use Cases**:
- Existing deployment compatibility
- Scripted batch operations
- One-time instrumentation tasks
- Migration transition period

### Mode Selection Logic

```cpp
// Command line priority (first match wins)
if (args.contains("--help") || args.contains("--version")) {
    // Show information and exit
} else if (args.contains("--legacy")) {
    // Use original Application class
    Application app(args);
    app.Run();
} else {
    // Use new ApplicationDaemon class (default)
    ApplicationDaemon daemon(args);
    daemon.Initialize();
    daemon.Run();
}
```

## Error Handling

### Startup Errors

The daemon handles various startup error conditions:

#### Command Line Errors
- Invalid port numbers (≤0 or >65535)
- Unknown command line arguments
- Missing required argument values

```bash
$ ./explorer --port 0
Error: Port must be between 1 and 65535

$ ./explorer --unknown-flag
Error: Unknown argument: --unknown-flag
Use --help for usage information.
```

#### Process Management Errors
- Cannot fork daemon process
- Cannot create new session
- Cannot change working directory
- Cannot redirect file descriptors

#### Resource Errors
- Cannot create PID file (permissions)
- Cannot bind to port (already in use)
- Another daemon instance already running
- FRIDA initialization failure

#### Error Recovery

The daemon implements comprehensive error recovery:

1. **Graceful Shutdown**: Cleanup resources on any error
2. **PID File Cleanup**: Remove PID file on exit
3. **Resource Cleanup**: Destructors handle cleanup automatically
4. **Exit Codes**: Proper exit codes for monitoring systems

### Runtime Error Handling

#### Exception Handling
```cpp
try {
    ApplicationDaemon daemon(args);
    auto status = daemon.Run();
    return status.Ok() ? 0 : 1;
} catch (const std::exception& e) {
    syslog(LOG_ERR, "Exception in daemon mode: %s", e.what());
    return 1;
}
```

#### Signal-Based Shutdown
```cpp
void signal_handler(int signal_num) {
    syslog(LOG_INFO, "Received %s, initiating graceful shutdown...", signal_name);
    if (g_daemon_app) {
        g_daemon_app->Shutdown();  // Graceful shutdown
    }
}
```

## Development and Debugging

### Foreground Mode

For development and debugging, use foreground mode:

```bash
# Run in foreground with console logging
./explorer --foreground --port 8080

# Output:
# Running Explorer daemon in foreground mode
# Server will be available at http://0.0.0.0:8080
# Press Ctrl+C to stop the daemon
# [2025-02-04 16:12:34.567] [12345:12345] [info] HTTP server started successfully
```

### Debug Configuration

```bash
# Development setup
./explorer --foreground --host 127.0.0.1 --port 8080 --config-dir /tmp

# Test API endpoints
curl -X POST http://127.0.0.1:8080/health
curl -X POST http://127.0.0.1:8080/api/v1/session/list -d '{"action":"list","data":{}}'
```

### Log Monitoring

#### Daemon Mode Logs
```bash
# View daemon logs (systemd)
journalctl -u explorer -f

# View daemon logs (traditional syslog)
tail -f /var/log/daemon.log | grep explorer

# View all syslog entries
tail -f /var/log/syslog | grep explorer-daemon
```

#### Log Message Format
```
Feb 04 16:12:34 hostname explorer-daemon[12345]: Daemon initialized successfully
Feb 04 16:12:34 hostname explorer-daemon[12345]: HTTP server started on 0.0.0.0:34512
Feb 04 16:12:35 hostname explorer-daemon[12345]: Session created successfully for PID: 67890
```

## Migration Guide

### From Legacy to Daemon Mode

#### Phase 1: Parallel Operation
```bash
# Keep existing legacy deployment
./explorer --legacy --config-dir /data/local/tmp/legacy

# Start daemon on different port for testing
./explorer --daemon --port 34513

# Test API functionality
curl -X POST http://localhost:34513/health
```

#### Phase 2: Configuration Conversion
```bash
# Convert config.json sessions to API calls
# (This would be a separate migration tool)

# Example: config.json session
{
  "sessions": [{
    "app": "com.example.app",
    "spawn": true,
    "trace": [{"type": "java", "class": "MainActivity", "method": "onCreate"}]
  }]
}

# Equivalent API call
curl -X POST http://localhost:34512/api/v1/session/start \
  -H "Content-Type: application/json" \
  -d '{
    "action": "start",
    "data": {
      "app": "com.example.app",
      "spawn": true,
      "trace": [{"type": "java", "class": "MainActivity", "method": "onCreate"}]
    }
  }'
```

#### Phase 3: Full Migration
```bash
# Replace legacy deployment with daemon
sudo systemctl stop explorer-legacy
sudo systemctl start explorer
sudo systemctl enable explorer
```

### Rollback Plan
```bash
# Emergency rollback to legacy mode
sudo systemctl stop explorer
./explorer --legacy  # Temporary manual start

# Or modify systemd service temporarily
ExecStart=/usr/local/bin/explorer --legacy
```

## Security Considerations

### Process Privileges
- Daemon requires root privileges for Android FRIDA operations
- Consider running with minimal required privileges
- Use systemd security features when available

### Network Security
- Default binding to 0.0.0.0 allows external connections
- Consider using --host 127.0.0.1 for local-only access
- Implement firewall rules for port 34512

### File System Security
- PID file location should have appropriate permissions
- Config directory should be writable by daemon user
- Log files should have restricted access

### API Security
- No authentication implemented yet (planned future feature)
- Consider network-level access controls
- Monitor API access via logs

## Troubleshooting

### Common Issues

#### Daemon Won't Start
```bash
# Check if another instance is running
ps aux | grep explorer

# Check PID file
ls -la /data/local/tmp/explorer.pid

# Check port availability
netstat -tlnp | grep :34512
```

#### Permission Denied
```bash
# Ensure running as root (required for FRIDA on Android)
sudo ./explorer --daemon

# Check file permissions
ls -la /data/local/tmp/
```

#### Port Already in Use
```bash
# Find what's using the port
lsof -i :34512

# Use different port
./explorer --port 34513
```

### Log Analysis

#### Daemon Startup Issues
```bash
# Check daemon logs
journalctl -u explorer -n 50

# Look for specific errors
journalctl -u explorer | grep -i error
```

#### Runtime Issues
```bash
# Follow logs in real-time
journalctl -u explorer -f

# Check for session errors
journalctl -u explorer | grep -i session
```

## Performance Considerations

### Resource Usage
- Daemon uses minimal resources when idle
- Memory usage scales with number of active sessions
- HTTP server uses thread pool for concurrent requests

### Scalability
- Supports multiple concurrent API requests
- Session management is thread-safe
- FRIDA operations are properly serialized

### Monitoring
- Check daemon status: `systemctl status explorer`
- Monitor resource usage: `top -p $(cat /data/local/tmp/explorer.pid)`
- API health check: `curl http://localhost:34512/health`

## Summary

The enhanced main.cpp provides:

✅ **Professional Daemon Operation**: Full UNIX daemon implementation
✅ **Service Integration**: systemd and SysV init support
✅ **PID Management**: Automatic PID file handling with duplicate prevention
✅ **Signal Handling**: Graceful shutdown on SIGINT/SIGTERM/SIGHUP
✅ **Flexible Configuration**: Command-line options for all parameters
✅ **Development Support**: Foreground mode with console logging
✅ **Backward Compatibility**: Legacy mode preserves original behavior
✅ **Error Handling**: Comprehensive error detection and recovery
✅ **Production Ready**: Suitable for enterprise deployment

The Explorer daemon is now ready for production deployment with professional service management capabilities while maintaining full backward compatibility with existing configurations.