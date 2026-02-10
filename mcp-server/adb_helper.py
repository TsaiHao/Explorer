"""ADB device detection and reverse port forwarding helpers."""

import asyncio
import shutil


def _find_adb() -> str | None:
    return shutil.which("adb")


async def _run(cmd: list[str]) -> tuple[int, str, str]:
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    return proc.returncode or 0, stdout.decode(), stderr.decode()


async def list_devices() -> list[str]:
    """Return list of connected ADB device serial numbers."""
    adb = _find_adb()
    if adb is None:
        return []
    code, stdout, _ = await _run([adb, "devices"])
    if code != 0:
        return []
    serials = []
    for line in stdout.strip().splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "device":
            serials.append(parts[0])
    return serials


async def setup_reverse_port(port: int) -> tuple[bool, str]:
    """Run adb reverse tcp:<port> tcp:<port>. Returns (success, message)."""
    adb = _find_adb()
    if adb is None:
        return False, "adb not found in PATH"
    code, stdout, stderr = await _run(
        [adb, "forward", f"tcp:{port}", f"tcp:{port}"]
    )
    if code != 0:
        return False, stderr.strip() or "adb reverse failed"
    return True, stdout.strip() or f"Reverse port forwarding set for port {port}"


async def check_root_access() -> tuple[bool, str]:
    """Check if adb has root access on the connected device. Returns
    (has_root, message)."""
    adb = _find_adb()
    if adb is None:
        return False, "adb not found in PATH"
    code, stdout, stderr = await _run([adb, "shell", "id"])
    if code != 0:
        return False, stderr.strip() or "adb shell command failed"
    if "uid=0(root)" in stdout:
        return True, "ADB has root access on the device"
    else:
        return False, "ADB does not have root access on the device"
    

async def list_packages() -> tuple[bool, list[str]]:
    """Run `adb shell pm list packages` and return package names.
    Returns (success, packages)."""
    adb = _find_adb()
    if adb is None:
        return False, []
    code, stdout, _ = await _run([adb, "shell", "pm", "list", "packages"])
    if code != 0:
        return False, []
    packages = []
    for line in stdout.strip().splitlines():
        # Lines are "package:com.example.app"
        line = line.strip()
        if line.startswith("package:"):
            packages.append(line[8:])
    return True, packages


async def list_processes() -> tuple[bool, list[tuple[int, str]]]:
    """Run `adb shell ps -A` and return (pid, name) pairs.
    Returns (success, processes)."""
    adb = _find_adb()
    if adb is None:
        return False, []
    code, stdout, _ = await _run([adb, "shell", "ps", "-A"])
    if code != 0:
        return False, []
    processes = []
    for line in stdout.strip().splitlines()[1:]:  # Skip header
        cols = line.split()
        # ps -A output: USER PID PPID VSZ RSS WCHAN ADDR S NAME
        if len(cols) >= 9:
            try:
                pid = int(cols[1])
                name = cols[-1]
                processes.append((pid, name))
            except ValueError:
                continue
    return True, processes


async def check_if_explorer_daemon_running() -> bool:
    """Check if the Explorer daemon is running on the connected device
    by attempting to connect to the specified port via adb shell."""
    adb = _find_adb()
    if adb is None:
        return False
    code, _, _ = await _run(
        [adb, "shell", f"pidof explorer"]
    )
    return code == 0