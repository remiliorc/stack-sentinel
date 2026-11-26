"""Collectors discover targets and return one ``Check`` per target.

- DockerCollector: every container from the Docker Engine API (unix socket).
  Opt out per container with the label ``sentinel.ignore=true``.
- SystemdCollector: systemd services that match glob patterns.
- HttpCollector: health endpoints, with status and latency.
"""

from __future__ import annotations

import fnmatch
import subprocess
import time
from dataclasses import dataclass, field
from typing import Callable, Protocol

import httpx

OK, WARN, FAIL = "ok", "warn", "fail"


@dataclass(frozen=True)
class Check:
    name: str
    status: str
    detail: str = ""
    metrics: dict = field(default_factory=dict)
    # True when the collector could not enumerate its targets this cycle;
    # the engine then keeps the collector's previous targets instead of
    # treating them as removed.
    discovery_error: bool = False


class Collector(Protocol):
    def collect(self) -> list[Check]: ...


class DockerCollector:
    def __init__(self, socket: str = "/var/run/docker.sock",
                 transport: httpx.BaseTransport | None = None,
                 ignore_clean_exit: bool = True):
        self.ignore_clean_exit = ignore_clean_exit
        self.client = httpx.Client(
            transport=transport or httpx.HTTPTransport(uds=socket),
            base_url="http://docker", timeout=5)

    def collect(self) -> list[Check]:
        try:
            r = self.client.get("/containers/json", params={"all": "1"})
            items = r.json() if r.status_code == 200 else None
        except (httpx.HTTPError, ValueError) as e:
            return [Check("docker:engine", FAIL, f"engine unreachable: {type(e).__name__}",
                          discovery_error=True)]
        if not isinstance(items, list):
            return [Check("docker:engine", FAIL, f"unexpected engine reply (HTTP {r.status_code})",
                          discovery_error=True)]
        out = []
        for c in items:
            labels = c.get("Labels") or {}
            if str(labels.get("sentinel.ignore", "")).lower() == "true":
                continue
            name = "docker:" + (c.get("Names") or ["?"])[0].lstrip("/")
            state, status = c.get("State", ""), c.get("Status", "")
            if self.ignore_clean_exit and state == "exited" and status.startswith("Exited (0)"):
                continue  # one-shot jobs that finished successfully
            if state != "running":
                out.append(Check(name, FAIL, f"{state}: {status}"))
            elif "(unhealthy)" in status:
                out.append(Check(name, FAIL, "running but unhealthy"))
            elif "(health: starting)" in status:
                out.append(Check(name, WARN, "health check starting"))
            else:
                out.append(Check(name, OK, status))
        return out


Runner = Callable[[list[str]], str]


def _run(cmd: list[str]) -> str:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=True).stdout


class SystemdCollector:
    def __init__(self, patterns: list[str], runner: Runner = _run):
        self.patterns = patterns
        self.runner = runner

    def collect(self) -> list[Check]:
        try:
            text = self.runner(["systemctl", "list-units", "--type=service", "--all",
                                "--plain", "--no-legend", "--no-pager"])
        except (OSError, subprocess.SubprocessError) as e:
            return [Check("systemd", FAIL, f"systemctl failed: {type(e).__name__}",
                          discovery_error=True)]
        out = []
        for line in text.splitlines():
            parts = line.split(None, 4)
            if len(parts) < 4:
                continue
            unit, _load, active, sub = parts[:4]
            if not any(fnmatch.fnmatch(unit, p) for p in self.patterns):
                continue
            if active == "active" and sub == "running":
                out.append(Check(f"systemd:{unit}", OK, "running"))
            elif active == "activating":
                out.append(Check(f"systemd:{unit}", WARN, f"{active}/{sub}"))
            else:
                out.append(Check(f"systemd:{unit}", FAIL, f"{active}/{sub}"))
        return out


class HttpCollector:
    def __init__(self, targets: dict[str, str], timeout: float = 5,
                 slow_ms: float = 1500, transport: httpx.BaseTransport | None = None):
        self.targets = targets
        self.slow_ms = slow_ms
        self.client = httpx.Client(timeout=timeout, transport=transport)

    def collect(self) -> list[Check]:
        out = []
        for name, url in self.targets.items():
            t0 = time.perf_counter()
            try:
                r = self.client.get(url)
            except Exception as e:  # HTTPError, InvalidURL...: fail this target only
                out.append(Check(f"http:{name}", FAIL, type(e).__name__))
                continue
            ms = (time.perf_counter() - t0) * 1000
            m = {"latency_ms": round(ms, 1)}
            # redirects are not followed: a 3xx counts as reachable
            if r.status_code == 429:  # alive, but throttling the probe
                out.append(Check(f"http:{name}", WARN, "HTTP 429 (rate limited)", m))
            elif r.status_code >= 400:
                out.append(Check(f"http:{name}", FAIL, f"HTTP {r.status_code}", m))
            elif ms > self.slow_ms:
                out.append(Check(f"http:{name}", WARN, f"slow ({ms:.0f} ms)", m))
            else:
                out.append(Check(f"http:{name}", OK, f"HTTP {r.status_code}", m))
        return out
