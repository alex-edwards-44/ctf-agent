#!/usr/bin/env python3
"""
Smart supervisor for exploit-sandbox.

Usage: run_target [flask|fastapi|django|express|spring|auto]

Steps:
  1. Detect or accept framework hint.
  2. Install dependencies (pip/npm/mvn).
  3. Find a free port.
  4. Start the app, injecting PORT env var.
  5. Wait up to 60 s for the port to accept connections.
  6. Print  APP_PORT=<port>  so the solver can parse it.
"""

from __future__ import annotations

import glob
import os
import select
import signal
import socket
import subprocess
import sys
import time

TARGET = "/target"
PID_FILE = "/tmp/run_target.pid"


# ── helpers ──────────────────────────────────────────────────────────────────

def _kill_previous() -> None:
    if not os.path.exists(PID_FILE):
        return
    try:
        with open(PID_FILE) as fh:
            old = int(fh.read().strip())
        os.kill(old, signal.SIGTERM)
        time.sleep(0.5)
    except Exception:
        pass


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("", 0))
        return s.getsockname()[1]


def _wait_for_port(port: int, timeout: int = 60) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except OSError:
            time.sleep(0.5)
    return False


def _collect_startup(proc: subprocess.Popen, seconds: float = 5.0) -> str:
    lines: list[str] = []
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        r, _, _ = select.select([proc.stdout], [], [], 0.2)
        if r:
            chunk = proc.stdout.read(4096)
            if not chunk:
                break
            lines.append(chunk.decode("utf-8", errors="replace"))
    return "".join(lines)


# ── framework detection ───────────────────────────────────────────────────────

def detect_framework() -> str:
    if os.path.exists(os.path.join(TARGET, "pom.xml")):
        return "spring"
    if os.path.exists(os.path.join(TARGET, "package.json")):
        return "express"
    if os.path.exists(os.path.join(TARGET, "manage.py")):
        return "django"
    if os.path.exists(os.path.join(TARGET, "requirements.txt")):
        reqs = open(os.path.join(TARGET, "requirements.txt")).read().lower()
        if "fastapi" in reqs or "uvicorn" in reqs:
            return "fastapi"
        return "flask"
    return "manual"


# ── dependency installation ───────────────────────────────────────────────────

def install_deps(framework: str) -> None:
    req = os.path.join(TARGET, "requirements.txt")
    pkg = os.path.join(TARGET, "package.json")
    pom = os.path.join(TARGET, "pom.xml")

    if framework in ("flask", "fastapi", "django") and os.path.exists(req):
        print("Installing Python deps...", flush=True)
        subprocess.run(
            ["pip3", "install", "-r", req, "--break-system-packages", "-q"],
            check=False,
        )
    elif framework == "express" and os.path.exists(pkg):
        print("Installing npm deps...", flush=True)
        subprocess.run(["npm", "install", "--prefix", TARGET, "-q"], check=False)
    elif framework == "spring" and os.path.exists(pom):
        print("Building Maven project...", flush=True)
        subprocess.run(
            ["mvn", "package", "-q", "-DskipTests", "-f", pom],
            check=False,
        )


# ── command builder ───────────────────────────────────────────────────────────

def build_start_cmd(framework: str, port: int) -> tuple[list[str], dict[str, str]]:
    env = {
        **os.environ,
        "PORT": str(port),
        "FLASK_RUN_PORT": str(port),
        "FLASK_ENV": "development",
        "FLASK_DEBUG": "0",
    }

    if framework == "flask":
        for entry in ("app.py", "run.py", "main.py", "server.py"):
            if os.path.exists(os.path.join(TARGET, entry)):
                return ["python3", entry], env
        return ["flask", "run", "--host", "0.0.0.0", "--port", str(port)], env

    if framework == "fastapi":
        for entry in ("main.py", "app.py", "server.py"):
            path = os.path.join(TARGET, entry)
            if os.path.exists(path):
                module = entry[:-3]
                return ["uvicorn", f"{module}:app", "--host", "0.0.0.0", "--port", str(port)], env
        return ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", str(port)], env

    if framework == "django":
        return ["python3", "manage.py", "runserver", f"0:{port}"], env

    if framework == "express":
        for entry in ("server.js", "app.js", "index.js", "src/index.js"):
            if os.path.exists(os.path.join(TARGET, entry)):
                return ["node", entry], env
        return ["node", "index.js"], env

    if framework == "spring":
        jars = glob.glob(os.path.join(TARGET, "target", "*.jar"))
        if jars:
            return ["java", "-jar", jars[0], f"--server.port={port}"], env
        return [], env

    # manual — solver must figure it out
    return [], env


# ── main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    hint = sys.argv[1] if len(sys.argv) > 1 else "auto"
    framework = hint if hint != "auto" else detect_framework()
    print(f"Framework detected: {framework}", flush=True)

    _kill_previous()
    install_deps(framework)

    port = _free_port()
    print(f"Binding app to port {port}...", flush=True)

    cmd, env = build_start_cmd(framework, port)
    if not cmd:
        print(
            "ERROR: cannot determine start command. "
            "Use 'run_target <framework>' or start the app manually.",
            flush=True,
        )
        sys.exit(1)

    proc = subprocess.Popen(
        cmd,
        cwd=TARGET,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    with open(PID_FILE, "w") as fh:
        fh.write(str(proc.pid))

    startup_output = _collect_startup(proc, seconds=5.0)
    if startup_output:
        print(startup_output[:3000], flush=True)

    if _wait_for_port(port, timeout=60):
        print(f"APP_PORT={port}", flush=True)
        print(f"App is up at http://127.0.0.1:{port}", flush=True)
    else:
        print(f"WARNING: port {port} did not respond within 60 s", flush=True)
        print(f"APP_PORT={port}", flush=True)


if __name__ == "__main__":
    main()
