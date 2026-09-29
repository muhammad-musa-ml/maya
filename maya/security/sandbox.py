"""
The per-platform sandbox, with its tier declared rather than assumed (§17.2).

Every user artifact runs in a *separate interpreter* (``python -I``), with an
empty working directory, a stripped environment, rlimit caps where the OS
provides them, a wall-clock kill, an output-size cap, and networking disabled
in the child. The tier reported here is honest about what that amounts to:

- ``strong`` on Linux when a probe child *verifies* all of it: a bubblewrap
  jail (fresh user, pid, network, mount, ipc and uts namespaces; an unmapped
  uid; a read-only root holding only system libraries and the interpreter — not
  the home directory, not MAYA's storage), a seccomp-bpf deny-list, and a
  cgroup v2 scope capping memory, CPU and tasks. All unprivileged.
- ``moderate`` on macOS when ``sandbox-exec`` is present (network denied by a
  kernel profile, plus rlimits).
- ``moderate`` on Linux when seccomp and one of the other two are verified.
- ``minimal`` otherwise: rlimits (POSIX) or the wall clock alone (Windows).
  Network blocking in the child is best-effort (the socket module is disabled
  in-process, which native code could bypass).

The tier is recorded on every validation report so a reviewer knows what a
green tick was worth.

Copyright (c) 2026 Ashutosh Sinha. All rights reserved.
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

RUNNER = Path(__file__).with_name("sandbox_runner.py")
TIER_ORDER = ("minimal", "moderate", "strong")
_MAC_PROFILE = '(version 1)(allow default)(deny network*)(deny file-write* (subpath "/"))'
SANDBOX_UID = 65534
_CACHE: dict[str, Any] = {}

# What the probe child does: every line tries something the sandbox must stop.
_PROBE = """
import os, sys
def run(X, params):
    out = {"uid": os.getuid()}
    try:
        import _socket
        _socket.socket(); out["socket"] = "open"
    except OSError:
        out["socket"] = "refused"
    try:
        open("/maya-sandbox-probe", "w").close(); out["root_write"] = "allowed"
    except OSError:
        out["root_write"] = "refused"
    out["storage_visible"] = os.path.exists(params["storage"])
    out["secrets_visible"] = [p for p in params["secrets"] if os.path.exists(p)]
    with open("/proc/self/status") as fh:
        out["seccomp"] = next((l.split()[1] for l in fh if l.startswith("Seccomp:")), "0")
    return out
"""


def _works(argv: list[str], env: dict[str, str] | None = None) -> bool:
    try:
        return (
            subprocess.run(argv, capture_output=True, timeout=20, check=False, env=env).returncode
            == 0
        )
    except (OSError, subprocess.SubprocessError):
        return False


def capabilities() -> dict[str, bool]:
    """Which isolation primitives this host gives an unprivileged process (cached)."""
    if "caps" not in _CACHE:
        linux = platform.system() == "Linux"
        bwrap = shutil.which("bwrap")
        systemd = shutil.which("systemd-run")
        _CACHE["caps"] = {
            "linux": linux,
            "bwrap": bool(
                linux and bwrap and _works([bwrap, "--ro-bind", "/", "/", "--unshare-all", "true"])
            ),
            "cgroup": bool(
                linux
                and systemd
                and _works(
                    [
                        systemd,
                        "--user",
                        "--scope",
                        "-q",
                        "--collect",
                        "-p",
                        "MemoryMax=64M",
                        "true",
                    ],
                    env=_child_env(),
                )
            ),
        }
    return _CACHE["caps"]


def _binds() -> list[str]:
    """bubblewrap arguments exposing only what Python needs, read-only — never the home
    directory or MAYA's data. Top-level symlinks (merged /usr: /bin -> usr/bin) are
    recreated as symlinks, so the loader finds its paths."""
    args: list[str] = []
    bound: list[str] = []
    for path in ("/usr", "/etc", "/lib", "/lib64", "/lib32", "/bin", "/sbin"):
        if os.path.islink(path):
            args += ["--symlink", os.readlink(path), path]
        elif os.path.isdir(path):
            args += ["--ro-bind", path, path]
            bound.append(path)
    for path in (sys.base_prefix, sys.prefix):
        real = os.path.realpath(path)
        if os.path.isdir(real) and not any(real == b or real.startswith(b + "/") for b in bound):
            args += ["--ro-bind", real, real]
            bound.append(real)
        if path != real and not any(path.startswith(b + "/") for b in bound):
            args += ["--symlink", real, path]  # a symlinked prefix stays reachable
    # The interpreter itself can be a chain of links through directories that are not
    # bound: a virtual environment made with ``~/.local/bin/python3.13 -m venv`` points at
    # ``~/.local/bin/python3.13``, which points at the real interpreter. Inside the sandbox
    # the home directory does not exist, so the chain breaks and the child cannot start --
    # and the tier probe then fails and MAYA falls back to the minimal tier without the
    # user having changed anything. Each unbound hop is recreated as a symlink straight to
    # the real interpreter, which *is* bound (it lives under ``sys.base_prefix``).
    target = os.path.realpath(sys.executable)
    hop, seen = sys.executable, set()
    while os.path.islink(hop) and hop not in seen:
        seen.add(hop)
        nxt = os.readlink(hop)
        nxt = nxt if os.path.isabs(nxt) else os.path.join(os.path.dirname(hop), nxt)
        nxt = os.path.normpath(nxt)
        if not any(nxt == b or nxt.startswith(b + "/") for b in bound) and nxt != target:
            args += ["--symlink", target, nxt]
            bound.append(nxt)
        hop = nxt
    return args


def _linux_prefix(workdir: str, memory_mb: int, cpu_seconds: int) -> tuple[list[str], str]:
    """Command prefix and the runner path as the child will see it."""
    caps = capabilities()
    prefix: list[str] = []
    runner = str(Path(workdir) / "sandbox_runner.py")
    if caps["cgroup"]:
        prefix += [
            shutil.which("systemd-run") or "systemd-run",
            "--user",
            "--scope",
            "-q",
            "--collect",
            "-p",
            f"MemoryMax={memory_mb}M",
            "-p",
            "MemorySwapMax=0",
            "-p",
            "CPUQuota=100%",
            "-p",
            "TasksMax=64",
            "--",
        ]
    if caps["bwrap"]:
        prefix += [
            shutil.which("bwrap") or "bwrap",
            "--unshare-all",
            "--die-with-parent",
            "--new-session",
            "--uid",
            str(SANDBOX_UID),
            "--gid",
            str(SANDBOX_UID),
            "--dev",
            "/dev",
            "--proc",
            "/proc",
            "--tmpfs",
            "/tmp",  # nosec B108 - jail's own
            *[arg for var in BUS_VARS for arg in ("--unsetenv", var)],
        ]
        prefix += _binds()  # nosec B108 - /tmp here is the jail's own tmpfs, not the host's
        prefix += [
            "--ro-bind",
            workdir,
            "/sandbox",
            "--remount-ro",
            "/",  # nosec B108
            "--chdir",
            "/tmp",
        ]
        runner = "/sandbox/sandbox_runner.py"
    return prefix, runner


def sandbox_tier() -> dict[str, str]:
    """The tier this host delivers — measured by a probe that tries to escape, not assumed."""
    if "tier" in _CACHE:
        return _CACHE["tier"]
    system = platform.system()
    if system == "Darwin" and shutil.which("sandbox-exec"):
        tier = {
            "tier": "moderate",
            "mechanism": "sandbox-exec profile + setrlimit",
            "reason": "network and filesystem writes denied by a kernel sandbox profile; "
            "no separate OS user",
        }
    elif system == "Windows":
        tier = {
            "tier": "minimal",
            "mechanism": "subprocess + wall-clock kill",
            "reason": "no Job Object or restricted token is configured; CPU and memory "
            "are bounded only by the wall clock; network blocking is best-effort",
        }
    else:
        tier = _linux_tier()
    _CACHE["tier"] = tier
    return tier


def _linux_tier() -> dict[str, str]:
    caps = capabilities()
    home = os.path.expanduser("~")
    secrets = [
        os.path.realpath("config/application.yaml"),
        os.path.join(home, ".ssh"),
        os.path.join(home, ".bashrc"),
        os.path.join(home, ".profile"),
    ]
    probe = run_sandboxed(
        _PROBE,
        "run",
        {
            "X": {},
            "params": {
                "storage": os.path.realpath(os.environ.get("MAYA_HOME", "data")),
                "secrets": [p for p in secrets if os.path.exists(p)],
            },
        },
        wall_seconds=30,
        preload=(),
        _probing=True,
    )
    seen = probe.get("result") or {}
    seccomp = seen.get("seccomp") == "2"
    isolated = (
        caps["bwrap"]
        and seen.get("uid") == SANDBOX_UID
        and seen.get("socket") == "refused"
        and seen.get("root_write") == "refused"
        and not seen.get("storage_visible")
        and not seen.get("secrets_visible")
    )
    parts = [
        name
        for name, ok in (
            (
                "bubblewrap namespaces (user, pid, net, mount, ipc, uts) "
                "with a read-only minimal root",
                isolated,
            ),
            ("seccomp-bpf deny-list", seccomp),
            ("cgroup v2 scope (memory, CPU, tasks)", caps["cgroup"]),
        )
        if ok
    ] + ["setrlimit"]
    if isolated and seccomp and caps["cgroup"]:
        name, reason = (
            "strong",
            (
                "verified by a probe child: separate uid, no network, "
                "read-only root without the home directory or MAYA's "
                "storage, seccomp filter active, cgroup caps"
            ),
        )
    elif seccomp and (isolated or caps["cgroup"]):
        name, reason = (
            "moderate",
            (
                "partial isolation verified by probe; missing: "
                + ", ".join(
                    m
                    for m, ok in (("bubblewrap", isolated), ("cgroup delegation", caps["cgroup"]))
                    if not ok
                )
            ),
        )
    else:
        name, reason = (
            "minimal",
            (
                "subprocess with setrlimit only; "
                + (
                    f"probe failed: {probe.get('error')}"
                    if not probe.get("ok")
                    else "bubblewrap/seccomp/cgroup were not all available"
                )
            ),
        )
    return {"tier": name, "mechanism": " + ".join(parts), "reason": reason}


def _exit_reason(code: int | None) -> str:
    """Name the signal behind a death, whether the kernel reported it directly (negative)
    or a wrapper such as bubblewrap passed it on as 128 + signal."""
    import signal

    sig = -code if code is not None and code < 0 else (code - 128 if code and code > 128 else 0)
    if sig:
        try:
            name = signal.Signals(sig).name
        except ValueError:
            name = f"signal {sig}"
        cause = {
            "SIGXCPU": "CPU-time limit",
            "SIGKILL": "memory or task limit",
            "SIGSYS": "a forbidden system call",
            "SIGXFSZ": "file-size limit",
        }.get(name)
        return f"killed by a resource limit ({name}{': ' + cause if cause else ''})"
    return f"exit code {code}"


def tier_at_least(tier: str, minimum: str) -> bool:
    """True when ``tier`` meets the configured minimum."""
    return TIER_ORDER.index(tier) >= TIER_ORDER.index(minimum)


BUS_VARS = ("XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS")


def _child_env() -> dict[str, str]:
    """The stripped environment, plus the user-bus address systemd-run needs to place
    the child in a cgroup scope. bubblewrap unsets those before the artifact runs."""
    env = {
        "PYTHONHASHSEED": "0",
        "OPENBLAS_NUM_THREADS": "1",
        "OMP_NUM_THREADS": "1",
        "MKL_NUM_THREADS": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "LANG": "C.UTF-8",
    }
    if "SYSTEMROOT" in os.environ:  # Windows cannot start Python without it
        env["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
    if platform.system() == "Linux":
        env.update({k: os.environ[k] for k in BUS_VARS if k in os.environ})
        if "XDG_RUNTIME_DIR" not in env:
            runtime = f"/run/user/{os.getuid()}"
            if os.path.isdir(runtime):
                env["XDG_RUNTIME_DIR"] = runtime
    return env


def _argv(workdir: str, memory_mb: int, cpu_seconds: int) -> list[str]:
    if platform.system() == "Linux":
        prefix, runner = _linux_prefix(workdir, memory_mb, cpu_seconds)
        return [*prefix, sys.executable, "-I", "-B", runner]
    argv = [sys.executable, "-I", "-B", str(Path(workdir) / "sandbox_runner.py")]
    if platform.system() == "Darwin" and shutil.which("sandbox-exec"):
        argv = ["sandbox-exec", "-p", _MAC_PROFILE, *argv]
    return argv


def _await_child(
    proc: subprocess.Popen[bytes],
    readers: list[threading.Thread],
    exceeded: threading.Event,
    wall_seconds: int,
) -> str | None:
    """Wait for the child and its pipes; ``"output"`` or ``"timeout"`` if a cap stopped it."""
    deadline = time.monotonic() + wall_seconds
    while not exceeded.is_set():
        if time.monotonic() >= deadline:
            return "timeout"
        if proc.poll() is not None and not any(thread.is_alive() for thread in readers):
            # a reader may set the flag on its last chunk just before it finishes
            return "output" if exceeded.is_set() else None
        time.sleep(0.01)
    return "output"


def _run_capped(
    argv: list[str],
    request: str,
    cwd: str,
    env: dict[str, str],
    wall_seconds: int,
    output_limit_bytes: int,
) -> tuple[bytes, bytes, int | None, str | None]:
    """Drain both pipes while the child runs; never retain more than the output cap.

    ``subprocess.run(capture_output=True)`` buffers unbounded output before its caller
    can check a limit. Reader threads work on Windows too, where selectors cannot
    select anonymous subprocess pipes. The writer is separate so a large input cannot
    deadlock against a child that writes before reading it.
    """
    proc = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=cwd,
        env=env,
    )
    assert proc.stdin is not None and proc.stdout is not None and proc.stderr is not None
    stdout = bytearray()
    stderr = bytearray()
    exceeded = threading.Event()
    lock = threading.Lock()
    retained = 0

    def drain(pipe: Any, target: bytearray) -> None:
        nonlocal retained
        with pipe:
            while chunk := os.read(pipe.fileno(), 65536):
                with lock:
                    space = max(0, output_limit_bytes - retained)
                    target.extend(chunk[:space])
                    retained += min(len(chunk), space)
                    if len(chunk) > space:
                        exceeded.set()

    def write_input() -> None:
        try:
            with proc.stdin:
                proc.stdin.write(request.encode("utf-8"))
        except (BrokenPipeError, OSError):
            pass  # a child may refuse or exit before reading its request

    readers = [
        threading.Thread(target=drain, args=(proc.stdout, stdout), daemon=True),
        threading.Thread(target=drain, args=(proc.stderr, stderr), daemon=True),
    ]
    for thread in readers:
        thread.start()
    writer = threading.Thread(target=write_input, daemon=True)
    writer.start()
    reason = _await_child(proc, readers, exceeded, wall_seconds)
    if reason is not None and proc.poll() is None:
        proc.kill()
    proc.wait()
    for thread in readers:
        thread.join(timeout=0.5)
    writer.join(timeout=0.5)
    return bytes(stdout), bytes(stderr), proc.returncode, reason


def run_sandboxed(
    source: str,
    entry: str,
    payload: dict[str, Any],
    *,
    cpu_seconds: int = 10,
    memory_mb: int = 512,
    wall_seconds: int = 20,
    output_limit_bytes: int = 2_000_000,
    preload: tuple[str, ...] = ("numpy",),
    _probing: bool = False,
) -> dict[str, Any]:
    """Run ``entry`` from ``source`` on ``payload`` in a capped child interpreter."""
    tier = {"tier": "probe"} if _probing else sandbox_tier()
    request = json.dumps(
        {
            "source": source,
            "entry": entry,
            "payload": payload,
            "preload": list(preload),
            "limits": {"cpu_seconds": cpu_seconds, "memory_mb": memory_mb},
            "seccomp": platform.system() == "Linux",
        }
    )
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="maya-sbx-") as cwd:
        shutil.copy(RUNNER, Path(cwd) / "sandbox_runner.py")
        out, err, returncode, reason = _run_capped(
            _argv(cwd, memory_mb, cpu_seconds),
            request,
            cwd,
            _child_env(),
            wall_seconds,
            output_limit_bytes,
        )
        if reason == "timeout":
            return {
                "ok": False,
                "result": None,
                "tier": tier["tier"],
                "error": f"wall-clock limit of {wall_seconds}s exceeded; the process was killed",
                "failure": "timeout",
                "duration": time.monotonic() - started,
            }
        if reason == "output":
            return {
                "ok": False,
                "result": None,
                "tier": tier["tier"],
                "duration": time.monotonic() - started,
                "error": f"output exceeded the {output_limit_bytes}-byte cap",
                "failure": "output",
            }
    duration = time.monotonic() - started
    try:
        response = json.loads(out)
    except json.JSONDecodeError:
        why = _exit_reason(returncode)
        return {
            "ok": False,
            "result": None,
            "tier": tier["tier"],
            "duration": duration,
            "error": f"sandboxed process produced no result ({why}): {err.decode('utf-8', 'replace')[-500:]}",
            "failure": "no_result",
        }
    return {
        "ok": bool(response.get("ok")),
        "result": response.get("result"),
        "error": response.get("error"),
        "failure": None if response.get("ok") else "raised",
        "tier": tier["tier"],
        "duration": duration,
        "limits_applied": response.get("limits_applied", []),
    }


def net_jail() -> list[str]:
    """A command prefix that runs trusted software with no network, or ``[]``.

    This is not the artifact sandbox: it is for MAYA's *own* helpers — the LaTeX build of
    §17.1, which must not reach the network — where the code is trusted and only the
    network needs taking away. So the jail unshares the network and pid namespaces and
    binds the filesystem through unchanged, rather than assembling a minimal root: a TeX
    engine needs its cache, its fonts and its output directory, and a read-only root would
    only mean no PDF. The pid namespace is what bounds the build's processes, which is why
    a jailed build does not also take an ``RLIMIT_NPROC`` — that limit is per user, and a
    user already past it could not create the namespace in the first place.

    The probe is the same shape as the command, because a bubblewrap that works with
    ``--ro-bind`` is not evidence that this one does. An empty list means the host offers
    no namespace, and the caller falls back to policy (a cached-only build in a fixed
    environment), which is weaker and says so.
    """
    if "net_jail" not in _CACHE:
        bwrap = shutil.which("bwrap") if platform.system() == "Linux" else None
        argv = (
            [
                bwrap,
                "--dev-bind",
                "/",
                "/",
                "--unshare-net",
                "--unshare-pid",
                "--die-with-parent",
                "--",
            ]
            if bwrap
            else []
        )
        _CACHE["net_jail"] = argv if argv and _works([*argv, "true"]) else []
    return list(_CACHE["net_jail"])
