from __future__ import annotations
import json
import math
import os
import runpy
import sys
from pathlib import Path
from typing import Any


def _worker_write(*values: Any, error: bool = False, sep: str = " ", end: str = "\n", flush: bool = False) -> None:
    stream = sys.stderr if error else sys.stdout
    stream.write(sep.join(str(value) for value in values) + end)
    if flush:
        stream.flush()


def _record_recoverable(operation: str) -> None:
    exc = sys.exception()
    if exc is None:
        raise RuntimeError("_record_recoverable() must run inside an except block")
    _worker_write(
        f"recoverable sandbox boundary failure in {operation}: {type(exc).__name__}: {exc}",
        error=True,
        flush=True,
    )



def _apply_posix_resource_limits() -> None:
    




    raw_budget = os.environ.pop("ARENYXA_PLUGIN_SANDBOX_BUDGET", "")
    if os.name == "nt" or not raw_budget:
        return
    try:
        budget = json.loads(raw_budget)
    except (TypeError, ValueError, json.JSONDecodeError):
        raise RuntimeError("invalid plugin sandbox budget")
    if not isinstance(budget, dict):
        raise RuntimeError("invalid plugin sandbox budget")
    try:
        import resource
    except ImportError as exc:
        raise RuntimeError("POSIX plugin sandbox requires resource limits support") from exc

    def clamp_limit(kind: int, desired: int) -> None:
        soft, hard = resource.getrlimit(kind)
        infinity = resource.RLIM_INFINITY
        ceiling = desired if hard == infinity else min(desired, int(hard))
        resource.setrlimit(kind, (ceiling, ceiling))

    timeout = max(1.0, min(300.0, float(budget.get("timeout_seconds", 15.0))))
    output = max(1024, min(64 * 1024 * 1024, int(budget.get("max_output_bytes", 4 * 1024 * 1024))))
    requested_memory = max(32, min(4096, int(budget.get("max_memory_mb", 256))))
    requested_processes = max(1, min(8, int(budget.get("max_processes", 1))))
                                                                                                  
                                                                                                   
    address_space_mb = max(768, requested_memory)
    try:
        clamp_limit(resource.RLIMIT_CPU, max(1, int(math.ceil(timeout)) + 1))
    except (OSError, ValueError):
        _record_recoverable('_apply_posix_resource_limits:55')
    if hasattr(resource, "RLIMIT_CORE"):
        try:
            clamp_limit(resource.RLIMIT_CORE, 0)
        except (OSError, ValueError):
            _record_recoverable('_apply_posix_resource_limits:60')
    if hasattr(resource, "RLIMIT_FSIZE"):
        try:
            clamp_limit(resource.RLIMIT_FSIZE, max(1024 * 1024, output))
        except (OSError, ValueError):
            _record_recoverable('_apply_posix_resource_limits:65')
    if hasattr(resource, "RLIMIT_NOFILE"):
        try:
            clamp_limit(resource.RLIMIT_NOFILE, 64)
        except (OSError, ValueError):
            _record_recoverable('_apply_posix_resource_limits:70')
    if hasattr(resource, "RLIMIT_AS"):
        try:
            clamp_limit(resource.RLIMIT_AS, address_space_mb * 1024 * 1024)
        except (OSError, ValueError) as exc:
            raise RuntimeError("POSIX plugin memory limit could not be enforced") from exc
    if hasattr(resource, "RLIMIT_NPROC"):
        try:
            clamp_limit(resource.RLIMIT_NPROC, requested_processes)
        except (OSError, ValueError) as exc:
            raise RuntimeError("POSIX plugin process limit could not be enforced") from exc

                                                                                             
    if sys.platform.startswith("linux"):
        try:
            import ctypes
            libc = ctypes.CDLL(None, use_errno=True)
            if libc.prctl(38, 1, 0, 0, 0) != 0:                       
                raise OSError(ctypes.get_errno(), "prctl(PR_SET_NO_NEW_PRIVS) failed")
        except (ImportError, OSError, AttributeError) as exc:
            raise RuntimeError("Linux plugin sandbox could not enable no_new_privs") from exc
    os.umask(0o077)


def _read_text_limited(path: Path, max_bytes: int) -> str:
    limit = max(1, int(max_bytes))
    if path.stat().st_size > limit:
        raise ValueError(f"file exceeds {limit} byte limit")
    with path.open("rb") as stream:
        payload = stream.read(limit + 1)
    if len(payload) > limit:
        raise ValueError(f"file exceeds {limit} byte limit")
    return payload.decode("utf-8")


def run(manifest_path_value: str | os.PathLike[str], grant_payload: str) -> int:
    _apply_posix_resource_limits()
    manifest_path = Path(manifest_path_value).resolve()
    try:
        manifest = json.loads(_read_text_limited(manifest_path, 1024 * 1024))
        granted: dict[str, Any] = json.loads(grant_payload)
    except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError) as exc:
        _worker_write(f"invalid worker metadata: {exc}", error=True)
        return 2
    if not isinstance(manifest, dict) or not isinstance(granted, dict):
        _worker_write("invalid worker metadata root", error=True)
        return 2
    plugin_root = manifest_path.parent
    raw_entry = manifest.get("entry")
    if not isinstance(raw_entry, str) or not raw_entry.strip():
        _worker_write("plugin manifest entry is invalid", error=True)
        return 3
    entry = (plugin_root / raw_entry).resolve()
    if plugin_root not in entry.parents:
        _worker_write("entry escapes plugin root", error=True)
        return 3
    install_audit_hook(plugin_root, granted)
                                                                                               
                                                                                          
                                                                               
    plugin_root_text = str(plugin_root)
    if plugin_root_text not in sys.path:
        sys.path.append(plugin_root_text)
    raw_request = sys.stdin.read(16 * 1024 * 1024 + 1)
    if len(raw_request) > 16 * 1024 * 1024:
        _worker_write("plugin request exceeds 16 MiB limit", error=True)
        return 5
    try:
        request = json.loads(raw_request)
    except json.JSONDecodeError as exc:
        _worker_write(f"invalid plugin request: {exc}", error=True)
        return 5
    namespace = runpy.run_path(str(entry), run_name="arenyxa_plugin")
    handler = namespace.get("handle")
    if not callable(handler):
        _worker_write("plugin must define handle(request)", error=True)
        return 4
    response = handler(request)
    sys.stdout.write(json.dumps(response, ensure_ascii=False, default=str))
    return 0


def install_audit_hook(plugin_root: Path, granted: dict[str, Any]) -> None:
    storage = granted.get("storage", {})
    runtime_roots = {
        Path(sys.base_prefix).resolve(),
        Path(sys.prefix).resolve(),
        Path(sys.executable).resolve().parent,
    }
    allowed_read_roots = {plugin_root.resolve(), *runtime_roots}
    allowed_storage_roots: set[Path] = {plugin_root.resolve()}
    for configured in storage.get("paths", []) if isinstance(storage, dict) else []:
        try:
            root = Path(configured).expanduser().resolve()
        except (OSError, RuntimeError):
            continue
        allowed_storage_roots.add(root)
        allowed_read_roots.add(root)

    def inside(path: Path, roots: set[Path]) -> bool:
        return any(root == path or root in path.parents for root in roots)

    def resolve_path(raw_path: Any) -> Path | None:
                                                                                            
                                                                           
        if isinstance(raw_path, int):
            return None
        if not isinstance(raw_path, (str, bytes, os.PathLike)):
            raise PermissionError("plugin file path type denied")
        if isinstance(raw_path, bytes):
            raw_path = raw_path.decode(errors="surrogateescape")
        try:
            return Path(raw_path).expanduser().resolve(strict=False)
        except (OSError, RuntimeError, ValueError):
            raise PermissionError("plugin file path could not be resolved")

    def require_read(raw_path: Any) -> None:
        path = resolve_path(raw_path)
        if path is not None and not inside(path, allowed_read_roots):
            raise PermissionError("plugin storage read permission denied")

    def require_write(raw_path: Any) -> None:
        path = resolve_path(raw_path)
        if "storage" not in granted or path is None or not inside(path, allowed_storage_roots):
            raise PermissionError("plugin storage write permission denied")

    def open_writes(mode: Any, flags: Any = None) -> bool:
        






        write_mask = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
        if isinstance(mode, int):
            if mode & write_mask:
                return True
        if isinstance(flags, int) and flags & write_mask:
            return True
        return any(flag in str(mode) for flag in ("w", "a", "+", "x"))

    write_events = {
        "os.remove", "os.unlink", "os.rmdir", "os.mkdir", "os.makedirs",
        "os.chmod", "os.chown", "os.lchown", "os.truncate", "os.utime",
        "os.mknod", "os.mkfifo",
    }
    two_path_write_events = {"os.rename", "os.replace", "os.link"}
    read_path_events = {"os.listdir", "os.scandir", "os.chdir"}

    def audit(event: str, args: tuple[Any, ...]) -> None:
                                                                                         
                                                                                            
        if event.startswith("socket.") and "network" not in granted:
            raise PermissionError("plugin network permission denied")

        process_event = (
            event.startswith("subprocess.")
            or event.startswith("os.spawn")
            or event.startswith("os.exec")
            or event in {"os.system", "os.posix_spawn", "os.startfile", "os.fork", "os.forkpty", "pty.spawn"}
        )
        if process_event and "process" not in granted:
            raise PermissionError("plugin process permission denied")

        if event == "open" and args:
            raw_path = args[0]
            mode = args[1] if len(args) > 1 else "r"
            flags = args[2] if len(args) > 2 else None
            if open_writes(mode, flags):
                require_write(raw_path)
            else:
                require_read(raw_path)

        if event in write_events and args:
            require_write(args[0])
        elif event in two_path_write_events and len(args) >= 2:
            require_write(args[0])
            require_write(args[1])
        elif event == "os.symlink":
                                                                                            
                                                                                              
            raise PermissionError("plugin symlink creation denied")
        elif event in read_path_events and args and args[0] is not None:
            require_read(args[0])

                                                                                          
                                                                                        
        if event.startswith("ctypes.") and "process" not in granted:
            raise PermissionError("plugin native API permission denied")

    sys.addaudithook(audit)


def main() -> int:
    if len(sys.argv) != 3:
        _worker_write("invalid worker arguments", error=True)
        return 2
    return run(sys.argv[1], sys.argv[2])


if __name__ == "__main__":
    raise SystemExit(main())
