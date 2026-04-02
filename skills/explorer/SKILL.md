# Explorer — FRIDA Instrumentation Skill

> Invoke with: `/explorer`

This skill drives the Explorer daemon — a FRIDA-based dynamic instrumentation tool for Android devices. It manages the full lifecycle: device setup, daemon deployment, session creation, function tracing, result collection, and diagnostics.

## Constants

- **DAEMON_PORT**: `34512`
- **DAEMON_URL**: `http://127.0.0.1:34512`
- **DEVICE_DIR**: `/data/local/tmp`
- **BINARY_NAME**: `explorer`
- **DOWNLOAD_URL**: `https://amz.zaijun.org/files/explorer.zip`
- **DOWNLOAD_CREDS**: `zaijun:kIf1sLp`

## Workflow

Always follow this sequence. Do NOT skip steps.

### Phase 1: Device & Daemon Readiness

Run each check in order. Stop and fix before proceeding.

**Step 1 — ADB device connected?**
```bash
adb devices | grep -w device | head -1
```
If no device, tell the user to connect one and stop.

**Step 2 — ROOT access?**
```bash
adb shell id
```
Must see `uid=0(root)`. If not:
```bash
adb root && sleep 2
adb shell id
```
If still no root, stop and tell the user root access is required.

**Step 3 — Port forwarding**
```bash
adb forward tcp:34512 tcp:34512
```

**Step 4 — Daemon health check**
```bash
curl -s --connect-timeout 3 http://127.0.0.1:34512/health
```
If healthy, proceed to Phase 2.

**Step 5 — If daemon unreachable, check binary exists on device**
```bash
adb shell "ls -la /data/local/tmp/explorer"
```

If binary missing, download and deploy:
```bash
cd /tmp && curl -u 'zaijun:kIf1sLp' -O -L https://amz.zaijun.org/files/explorer.zip
unzip -o /tmp/explorer.zip -d /tmp/explorer_pkg
adb push /tmp/explorer_pkg/explorer /data/local/tmp/
adb shell chmod +x /data/local/tmp/explorer
```

**Step 6 — Start daemon on device**
```bash
adb shell "cd /data/local/tmp && nohup ./explorer --daemon --host 0.0.0.0 --port 34512 > /dev/null 2>&1 &"
sleep 2
curl -s --connect-timeout 3 http://127.0.0.1:34512/health
```
If still unreachable after 3 retries with 2s delays, dump logcat for diagnosis:
```bash
adb logcat -d -t 50 -s ExplorerDaemon:* > /tmp/explorer_boot.log
```
Read `/tmp/explorer_boot.log` and report the error to the user.

### Phase 2: Target Discovery

Help the user identify the target app/process.

**Find packages by keyword:**
```bash
adb shell pm list packages | grep -i <keyword>
```

**Check if a package is running and get its PID:**
```bash
adb shell pidof <package_name>
```

**List running processes (filtered):**
```bash
adb shell ps -A | grep -i <keyword>
```

### Phase 3: Session Creation

Build a session config and POST it to the daemon.

**API endpoint:** `POST /api/v1/session/start`

#### Attachment Strategy (IMPORTANT)

Always prefer attaching to a running process over spawning a new one. Spawning terminates the running app, which is destructive and loses existing state.

**Step 1 — Check if target is already running:**
```bash
adb shell pidof <package_name>
```

**Step 2 — Choose attachment method:**

| Situation | Method | Config |
|-----------|--------|--------|
| Process is running | Attach by PID | `"pid": <pid>` |
| Process is NOT running, user hasn't specified launch params | Spawn | `"app": "<package>", "spawn": true` |
| Process is NOT running, user provided explicit `am start` command | Activity Manager | `"am_start": "<activity>"` with launch params |

- **Use `pid`** whenever the process is already running. This is the safest and most common path.
- **Use `spawn`** only when the process is not running and the user wants a simple launch.
- **Use `am_start`** only when the user explicitly provides an Activity Manager command with specific intent parameters. Example: the user says "start YouTube with this command: `adb shell am start -n com.amazon.firetv.youtube/dev.cobalt.app.MainActivity -a android.intent.action.VIEW -d 'https://www.youtube.com/watch?v=JRLK4XgBog0'`"
- **NEVER** use `spawn: true` if the process is already running — this kills the app and restarts it.

**Request format (attach by PID — preferred):**
```json
{
  "action": "start",
  "data": {
    "pid": 12345,
    "trace": [
      {
        "type": "java",
        "class": "android.media.MediaCodec",
        "method": "start",
        "arguments": true,
        "log": true,
        "backtrace": true
      }
    ]
  }
}
```

**Request format (spawn — only when not running):**
```json
{
  "action": "start",
  "data": {
    "app": "<package_name>",
    "spawn": true,
    "trace": [...]
  }
}
```

**Session config fields:**
| Field | Type | Description |
|-------|------|-------------|
| `pid` | int | Attach to existing PID (preferred when process is running) |
| `app` | string | Target package name (used with spawn or as fallback) |
| `spawn` | bool | Spawn the app if not running (ONLY when process is not running) |
| `am_start` | string | Launch via Activity Manager (ONLY when user explicitly provides am command) |
| `scripts` | string[] | Script file paths on device |
| `script_source` | string | Inline JavaScript source |
| `trace` | array | Function tracing config (see below) |
| `ssl_dumper` | object | SSL interception config |

**Trace entry fields:**
| Field | Type | Description |
|-------|------|-------------|
| `type` | string | `"java"` or `"native"` |
| `namespace` | string | Native namespace (for native type) |
| `class` | string | Fully qualified class name |
| `method` | string | Method name |
| `arguments` | bool | Log arguments |
| `log` | bool | Enable logging |
| `backtrace` | bool | Include call stack |
| `atrace` | bool | Android systrace integration |
| `transform` | array | Argument transformation rules |
| `dump` | string | Path to dump SQLite DB |

**Create session command:**
```bash
curl -s -X POST http://127.0.0.1:34512/api/v1/session/start \
  -H "Content-Type: application/json" \
  -d '<json_body>'
```

Check the response `status` field. If `"success"`, note the `session_id` (PID) and proceed.

**If session creation fails**, run diagnostics (see Phase 6).

### Phase 4: User Trigger (IMPORTANT)

After a session is created successfully, the user must manually trigger the target behavior (e.g., start video playback, open an app feature, press a button).

**You MUST:**
1. Tell the user exactly what to do (e.g., "Please start playing a video now to trigger `MediaCodec.start`")
2. Ask the user to confirm when they have triggered the action
3. **Pause and wait** for the user to respond before proceeding to Phase 5

Do NOT drain messages until the user confirms the trigger.

### Phase 5: Result Collection

**Drain messages from session buffer:**
```bash
curl -s -X POST http://127.0.0.1:34512/api/v1/session/messages \
  -H "Content-Type: application/json" \
  -d '{"action": "drain", "data": {"session": "<session_id>"}}'
```

Parse the response:
- `message_count`: number of messages returned
- `dropped_count`: messages lost to buffer overflow (if > 0, warn the user)
- `messages`: array of trace events

If `message_count` is 0, the target function may not have been called yet. Ask the user if they triggered the action.

**Present results** by grouping trace events by function, showing enter/exit pairs, arguments, and backtraces in a readable format.

### Phase 6: Diagnostics

Use these when things go wrong.

**Session failed to attach (even with root):**
```bash
adb logcat -d > /tmp/logcat_full.txt
```
Then search for the process name or PID:
```bash
grep -i "<process_name_or_pid>" /tmp/logcat_full.txt | tail -30
```

Common findings:
- **minijail**: Process is sandboxed. Look for `minijail0` in logcat — this restricts ptrace which FRIDA needs.
- **SELinux denial**: Look for `avc: denied` entries related to the target process.
- **seccomp**: Process has seccomp filters blocking ptrace. Look for `seccomp` entries.
- **Process crashed**: Target may crash on instrumentation. Look for `SIGABRT`, `SIGSEGV`, or `Fatal signal`.

Report findings to the user with the relevant logcat lines.

**Session health check:**
```bash
curl -s -X POST http://127.0.0.1:34512/api/v1/session/status \
  -H "Content-Type: application/json" \
  -d '{"action": "status", "data": {"session": "<session_id>"}}'
```

**List all sessions:**
```bash
curl -s -X POST http://127.0.0.1:34512/api/v1/session/list \
  -H "Content-Type: application/json" \
  -d '{"action": "list", "data": {}}'
```

## Session Cleanup

Always stop sessions when done:
```bash
curl -s -X POST http://127.0.0.1:34512/api/v1/session/stop \
  -H "Content-Type: application/json" \
  -d '{"action": "stop", "data": {"session": "<session_id>"}}'
```

## Script Management

**Load a script into a running session:**
```bash
curl -s -X POST http://127.0.0.1:34512/api/v1/session/script/load \
  -H "Content-Type: application/json" \
  -d '{"action": "load_script", "data": {"session": "<session_id>", "script_source": "<js_code>"}}'
```

**Unload a script:**
```bash
curl -s -X POST http://127.0.0.1:34512/api/v1/session/script/unload \
  -H "Content-Type: application/json" \
  -d '{"action": "unload_script", "data": {"session": "<session_id>", "script": "<script_name>"}}'
```

## Daemon Stats & Metrics

```bash
curl -s http://127.0.0.1:34512/api/v1/daemon/stats
curl -s http://127.0.0.1:34512/api/v1/metrics
```

## Config Templates

Reference these for common use cases. Templates are in the project at `tools/config_templates/`.

**Java method tracing (e.g., MediaCodec):**
```json
{
  "app": "com.netflix.mediaclient",
  "spawn": true,
  "trace": [
    {"type": "java", "class": "android.media.MediaCodec", "method": "start", "arguments": true, "log": true, "backtrace": true},
    {"type": "java", "class": "android.media.MediaCodec", "method": "flush", "arguments": true, "log": true, "backtrace": true},
    {"type": "java", "class": "android.media.MediaCodec", "method": "stop", "log": true}
  ]
}
```

**Native function tracing:**
```json
{
  "app": "com.example.nativeapp",
  "spawn": true,
  "trace": [
    {"type": "native", "namespace": "std", "class": "vector", "method": "push_back", "arguments": true, "log": true, "backtrace": true}
  ]
}
```

**SSL traffic capture:**
```json
{
  "app": "com.amazon.avod.thirdpartyclient",
  "spawn": true,
  "ssl_dumper": {"output": "/data/local/tmp/ssl_traffic.bin"}
}
```

## Error Response Codes

| HTTP | Code | Meaning |
|------|------|---------|
| 400 | BAD_REQUEST | Invalid JSON or missing fields |
| 403 | PERMISSION_DENIED | Insufficient permissions |
| 404 | NOT_FOUND | Session or target not found |
| 409 | INVALID_STATE | Operation not allowed in current state |
| 500 | INTERNAL_ERROR | Server or FRIDA failure |
| 408 | TIMEOUT | Operation timed out |
