# Explorer Backward Compatibility

Explorer maintains full backward compatibility with the original config-file based mode while providing the new daemon mode functionality.

## Legacy Mode Support

### Default Legacy Mode
Use the `--legacy` option to run with the default config file location:
```bash
./explorer --legacy
```
This reads from the default location: `/data/local/tmp/config.json`

### Custom Config File
Use the `--config` option to specify a custom config file:
```bash
./explorer --config /path/to/custom/config.json
```
This automatically enables legacy mode and uses the specified config file.

### Supported Legacy Configuration

The legacy config file format remains unchanged:
```json
{
  "sessions": [
    {
      "app": "com.example.testapp",
      "spawn": true,
      "trace": [
        {
          "type": "java",
          "class": "android.app.Activity",
          "method": "onCreate",
          "arguments": true,
          "log": true
        }
      ]
    }
  ]
}
```

### Legacy vs Daemon Mode

| Feature | Legacy Mode | Daemon Mode |
|---------|-------------|-------------|
| Configuration | JSON file | HTTP API |
| Operation | Single run | Persistent service |
| Session Management | Static at startup | Dynamic via API |
| Monitoring | Logs only | HTTP endpoints |
| Multiple Sessions | Config file only | Runtime creation |
| State Persistence | None | Automatic |

## Migration Guide

### From Legacy to Daemon Mode

**Legacy Command:**
```bash
./explorer --config /data/local/tmp/config.json
```

**Equivalent Daemon Mode:**
```bash
# Start daemon
./explorer --daemon --port 34512

# Create session via API
curl -X POST http://localhost:34512/api/v1/session/start \
  -H "Content-Type: application/json" \
  -d '{
    "action": "start",
    "data": {
      "app": "com.example.testapp",
      "spawn": true,
      "trace": [
        {
          "type": "java",
          "class": "android.app.Activity",
          "method": "onCreate",
          "arguments": true,
          "log": true
        }
      ]
    }
  }'
```

### Configuration Translation

Legacy configurations can be directly translated to daemon API calls:

**Legacy Config:**
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
          "log": true,
          "backtrace": true
        }
      ],
      "ssl_dumper": {
        "output": "/data/local/tmp/ssl.bin"
      }
    }
  ]
}
```

**Daemon API Call:**
```bash
curl -X POST http://localhost:34512/api/v1/session/start \
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
      ],
      "ssl_dumper": {
        "output": "/data/local/tmp/ssl.bin"
      }
    }
  }'
```

## Command Line Options

### Legacy Mode Options
```bash
./explorer [legacy options]

Options:
  --legacy              Run in legacy config-file mode
  --config FILE         Use specified config file (enables legacy mode)
  --help               Show help message
  --version            Show version information
```

### Daemon Mode Options
```bash
./explorer [daemon options]

Options:
  --daemon              Run in daemon mode (default)
  --host HOST           Bind to specific host (default: 0.0.0.0)
  --port PORT           Listen on specific port (default: 34512)
  --foreground          Run daemon in foreground (don't fork)
  --config-dir DIR      Configuration directory
  --pid-file PATH       PID file location
```

## Examples

### Legacy Mode Examples
```bash
# Use default config location
./explorer --legacy

# Use custom config file
./explorer --config /sdcard/my_config.json

# Show legacy help
./explorer --legacy --help

# Show version
./explorer --version
```

### Mixed Usage
You can choose the appropriate mode based on your needs:

**For one-time analysis:**
```bash
./explorer --config analysis_config.json
```

**For continuous monitoring:**
```bash
./explorer --daemon --port 8080
```

**For automation/integration:**
```bash
# Daemon mode with API access
./explorer --daemon --host 0.0.0.0 --port 34512
```

## Compatibility Testing

To verify backward compatibility:

1. **Test Legacy Mode with Default Config:**
   ```bash
   # Create default config
   echo '{"sessions": [{"app": "com.android.settings", "spawn": true}]}' > /data/local/tmp/config.json

   # Run in legacy mode
   ./explorer --legacy
   ```

2. **Test Custom Config File:**
   ```bash
   # Run with custom config
   ./explorer --config /path/to/test_config.json
   ```

3. **Test Daemon Mode:**
   ```bash
   # Start daemon
   ./explorer --daemon

   # Test API
   curl http://localhost:34512/health
   ```

## Error Handling

Both modes maintain their original error handling behavior:

**Legacy Mode:**
- Exits with error codes on configuration issues
- Logs errors to console and system log
- Stops on first session failure

**Daemon Mode:**
- Returns HTTP error responses
- Continues running despite individual session failures
- Maintains error state in metrics

## Performance Considerations

**Legacy Mode:**
- Lower memory footprint
- Single session execution
- No HTTP overhead
- Suitable for batch processing

**Daemon Mode:**
- Higher memory usage due to HTTP server
- Concurrent session support
- Real-time API access
- Better for interactive use and monitoring

## Troubleshooting

### Common Migration Issues

**Config File Not Found:**
```bash
# Legacy mode
Error: Config file not found in location: /data/local/tmp/config.json

# Solution: Ensure config file exists or use --config option
./explorer --config /path/to/existing/config.json
```

**Port Conflicts:**
```bash
# Daemon mode
Error: Address already in use (port 34512)

# Solution: Use different port or stop existing daemon
./explorer --daemon --port 8080
```

**Permission Issues:**
```bash
# Both modes
Error: Permission denied

# Solution: Ensure proper permissions
chmod +x ./explorer
# Or run as root if needed
```

---

Explorer maintains 100% backward compatibility while providing powerful new daemon mode capabilities. Choose the mode that best fits your use case.