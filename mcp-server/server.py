"""Explorer MCP Server — FRIDA instrumentation daemon control via MCP."""

import json
import os
from contextlib import asynccontextmanager
from urllib.parse import urlparse

import httpx
import jsonschema
from fastmcp import FastMCP

from adb_helper import (
    list_devices,
    setup_reverse_port,
    check_if_explorer_daemon_running,
    list_packages,
    list_processes,
)
from explorer_client import ExplorerClient
from schema_cache import SchemaCache

EXPLORER_URL = os.environ.get("EXPLORER_URL", "http://127.0.0.1:34512")

_http_client: httpx.AsyncClient | None = None
_explorer: ExplorerClient | None = None
_schema_cache = SchemaCache()


def _get_port() -> int:
    parsed = urlparse(EXPLORER_URL)
    return parsed.port or 34512


def _error(message: str) -> str:
    return json.dumps({"status": "error", "message": message})


def _ok(data: object) -> str:
    return json.dumps(data, indent=2)


@asynccontextmanager
async def lifespan(app: FastMCP):
    global _http_client, _explorer
    _http_client = httpx.AsyncClient()
    _explorer = ExplorerClient(EXPLORER_URL, _http_client)
    try:
        await _schema_cache.fetch(_http_client)
    except Exception:
        pass  # Best-effort; tools will retry
    try:
        yield
    finally:
        await _http_client.aclose()
        _http_client = None
        _explorer = None


mcp = FastMCP(
    "Explorer",
    instructions="FRIDA instrumentation daemon control for Android TV",
    lifespan=lifespan,
)


# --- Resource ---


@mcp.resource("explorer://config-schema")
def config_schema_resource() -> str:
    """JSON schema for Explorer session configuration."""
    return _schema_cache.get_schema_text()


# --- Tools ---


@mcp.tool()
async def check_health() -> str:
    """Check Explorer daemon health. On connection failure, attempts ADB
    device detection and reverse port forwarding to recover connectivity."""
    if _explorer is None:
        return _error("MCP server not initialized")

    # Try direct health check first
    try:
        result = await _explorer.health()
        return _ok(result)
    except (httpx.ConnectError, httpx.ConnectTimeout):
        pass

    # Daemon unreachable — try ADB recovery
    devices = await list_devices()

    if len(devices) == 0:
        return _error(
            "Explorer daemon unreachable and no ADB devices connected. "
            "Connect an Android device and start the daemon."
        )

    if len(devices) > 1:
        return _error(
            f"Explorer daemon unreachable. Multiple ADB devices found: "
            f"{', '.join(devices)}. Set up port forwarding manually: "
            f"adb -s <serial> forward tcp:{_get_port()} tcp:{_get_port()}"
        )

    # Single device — attempt adb forward
    port = _get_port()
    
    ok = await check_if_explorer_daemon_running()
    if not ok:
        return _error(
            f"Explorer daemon not running on device {devices[0]}. "
            f"Start the daemon on device: "
            f"adb shell 'cd /data/local/tmp && ./explorer")

    ok, msg = await setup_reverse_port(port)
    if not ok:
        return _error(f"ADB reverse port forwarding failed: {msg}")

    # Retry health check after setting up port forwarding
    try:
        result = await _explorer.health()
        return _ok(result)
    except (httpx.ConnectError, httpx.ConnectTimeout):
        return _error(
            f"Port forwarding set but daemon still unreachable. "
            f"Start the daemon on device: "
            f"adb shell 'cd /data/local/tmp && ./explorer --daemon "
            f"--host 0.0.0.0 --port {port}'"
        )
    except Exception as e:
        return _error(str(e))


def _fuzzy_match(keyword: str, package: str) -> float:
    """Score how well keyword matches a package name.
    Returns 0.0 for no match, higher is better (max 1.0)."""
    kw = keyword.lower()
    pkg_lower = package.lower()

    # Exact full match
    if kw == pkg_lower:
        return 1.0

    # Exact segment match (keyword equals one dot-separated part)
    segments = pkg_lower.split(".")
    if kw in segments:
        return 0.9

    # Contiguous substring in original package name
    if kw in pkg_lower:
        # Shorter packages with the match rank higher
        return 0.8 - len(pkg_lower) / 10000

    # Contiguous substring after stripping dots (catches "net.flix" -> "netflix")
    collapsed = pkg_lower.replace(".", "")
    if kw in collapsed:
        return 0.6 - len(pkg_lower) / 10000

    # All keyword characters appear in order (subsequence match)
    ki = 0
    for ch in collapsed:
        if ki < len(kw) and ch == kw[ki]:
            ki += 1
    if ki == len(kw):
        # Score by how many characters were needed to consume the keyword
        return 0.3 - len(pkg_lower) / 10000

    return 0.0


@mcp.tool()
async def find_package(keyword: str) -> str:
    """Search for Android packages matching a keyword and find their PIDs.

    Queries installed packages and running processes in parallel, then
    performs fuzzy matching on the keyword. Returns a list of matches,
    each with package name and PID (-1 if the process is not running).

    Args:
        keyword: Search term (e.g. "netflix", "chrome", "media").
    """
    import asyncio

    (pkg_ok, packages), (ps_ok, processes) = await asyncio.gather(
        list_packages(), list_processes(),
    )

    if not pkg_ok:
        return _error("Failed to list packages. Is an ADB device connected?")

    # Build process name -> pid lookup
    proc_map: dict[str, int] = {}
    if ps_ok:
        for pid, name in processes:
            proc_map[name] = pid

    # Score and filter packages
    scored: list[tuple[float, str]] = []
    for pkg in packages:
        score = _fuzzy_match(keyword, pkg)
        if score > 0.0:
            scored.append((score, pkg))

    scored.sort(key=lambda x: -x[0])

    # Cap results
    scored = scored[:20]

    results = []
    for score, pkg in scored:
        pid = proc_map.get(pkg, -1)
        results.append({"package": pkg, "pid": pid, "running": pid > 0})

    return _ok({
        "status": "success",
        "keyword": keyword,
        "match_count": len(results),
        "matches": results,
    })


@mcp.tool()
async def get_config_schema() -> str:
    """Return the JSON schema for Explorer session configuration.
    Useful for understanding valid configuration fields before creating
    a session. Refreshes automatically every 24 hours."""
    if _http_client is None:
        return _error("MCP server not initialized")
    try:
        schema = await _schema_cache.get_schema(_http_client)
        return _ok(schema)
    except Exception as e:
        return _error(f"Failed to fetch schema: {e}")


@mcp.tool()
async def list_sessions() -> str:
    """List all active instrumentation sessions on the Explorer daemon."""
    if _explorer is None:
        return _error("MCP server not initialized")
    try:
        result = await _explorer.list_sessions()
        return _ok(result)
    except Exception as e:
        return _error(str(e))


@mcp.tool()
async def session_status(session_id: str) -> str:
    """Get detailed status for a specific session.

    Args:
        session_id: The session PID as a string (e.g. "12345").
    """
    if _explorer is None:
        return _error("MCP server not initialized")
    try:
        result = await _explorer.session_status(session_id)
        return _ok(result)
    except Exception as e:
        return _error(str(e))


@mcp.tool()
async def create_session(config: dict) -> str:
    """Create a new instrumentation session on the Explorer daemon.

    The config is validated against the session schema before sending.
    On validation error, returns the field path so you can correct it.

    Args:
        config: Session configuration dict. Must include at least one of:
            app (package name), pid (process ID), am_start (activity),
            or spawn (boolean). Can also include trace, scripts,
            script_source, and ssl_dumper settings.
    """
    if _explorer is None or _http_client is None:
        return _error("MCP server not initialized")

    # Validate against schema if available
    try:
        session_schema = await _schema_cache.get_session_schema(_http_client)
        if session_schema is not None:
            jsonschema.validate(instance=config, schema=session_schema)
    except jsonschema.ValidationError as e:
        path = " -> ".join(str(p) for p in e.absolute_path) or "(root)"
        return json.dumps({
            "status": "validation_error",
            "message": e.message,
            "field_path": path,
            "schema_path": list(e.absolute_schema_path),
        })
    except Exception:
        pass  # Schema unavailable; let daemon validate

    try:
        result = await _explorer.start_session(config)
        return _ok(result)
    except Exception as e:
        return _error(str(e))


@mcp.tool()
async def stop_session(session_id: str) -> str:
    """Stop an active instrumentation session.

    Args:
        session_id: The session PID as a string (e.g. "12345").
    """
    if _explorer is None:
        return _error("MCP server not initialized")
    try:
        result = await _explorer.stop_session(session_id)
        return _ok(result)
    except Exception as e:
        return _error(str(e))


@mcp.tool()
async def get_results(session_id: str) -> str:
    """Drain and return cached messages from a session's buffer.
    This atomically retrieves all buffered messages and clears the buffer.
    Returns message_count, dropped_count, and the messages array.

    Args:
        session_id: The session PID as a string (e.g. "12345").
    """
    if _explorer is None:
        return _error("MCP server not initialized")
    try:
        result = await _explorer.drain_messages(session_id)
        return _ok(result)
    except Exception as e:
        return _error(str(e))


@mcp.tool()
async def get_stats() -> str:
    """Get combined daemon statistics and operational metrics."""
    if _explorer is None:
        return _error("MCP server not initialized")
    try:
        stats = await _explorer.stats()
        metrics = await _explorer.metrics()
        combined = {
            "stats": stats.get("data", stats),
            "metrics": metrics.get("data", metrics),
        }
        return _ok(combined)
    except Exception as e:
        return _error(str(e))


def main():
    mcp.run()


if __name__ == "__main__":
    main()
