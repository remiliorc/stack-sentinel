"""Alerting engine: debounce, recovery, heartbeat, anomaly events."""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from typing import Callable

from .anomaly import EwmaDetector
from .collectors import FAIL, OK, Check, Collector


@dataclass
class Event:
    kind: str            # down | recovered | flapping | anomaly | heartbeat
    name: str
    message: str
    ts: float = field(default_factory=time.time)


@dataclass
class _Track:
    status: str = OK
    alerted: bool = False
    fail_streak: int = 0
    ok_streak: int = 0
    last_seen: float = 0.0
    discovery: bool = False   # this target reports a discovery failure
    history: deque = field(default_factory=deque)  # recent OK/FAIL results
    flapping: bool = False


class Sentinel:
    """Turns raw checks into a small number of meaningful events.

    - ``down``: after ``fail_after`` consecutive failures. One alert, not one per cycle.
    - ``recovered``: after ``recover_after`` consecutive OK results following a down
      alert. WARN results neither count as failures nor toward recovery.
    - A collector that cannot enumerate its targets (engine down, systemctl
      missing) keeps its previous targets as they were: no false "removed".
    - A collector that crashes is reported as a target of its own
      (``collector:<Name>``), with the same debounce.
    - A target that disappears while alerted is reported once as ``recovered``
      with the message "target removed" (or "discovery restored" when the
      alerted target was a collector's own discovery failure).
    - ``flapping``: a target that changes between OK and FAIL at least
      ``flap_changes`` times within its last ``flap_window`` results, without
      ever reaching the debounce threshold. Reported once; cleared silently
      once the window is stable again.
    - ``heartbeat``: every ``heartbeat_s`` seconds, a summary proving the watcher is alive.
    - ``anomaly``: a numeric metric that deviates from its EWMA baseline,
      rate-limited per metric (``anomaly_cooldown`` cycles).
    """

    def __init__(self, collectors: list[Collector], notify: Callable[[Event], None],
                 fail_after: int = 3, recover_after: int = 2,
                 heartbeat_s: float = 6 * 3600, detector: EwmaDetector | None = None,
                 clock: Callable[[], float] = time.time, anomaly_cooldown: int = 10,
                 flap_window: int = 10, flap_changes: int = 6):
        self.collectors = collectors
        self.notify = notify
        self.fail_after, self.recover_after = fail_after, recover_after
        self.heartbeat_s = heartbeat_s
        self.detector = detector or EwmaDetector()
        self.clock = clock
        self.tracks: dict[str, _Track] = {}
        self.owner: dict[str, int] = {}          # target -> collector index
        self.anomaly_cooldown = anomaly_cooldown
        self.flap_window, self.flap_changes = flap_window, flap_changes
        self._anomaly_quiet: dict[str, int] = {}  # key -> cycles left
        self._last_heartbeat = clock()

    def _emit(self, kind: str, name: str, message: str) -> Event:
        e = Event(kind, name, message, self.clock())
        self.notify(e)
        return e

    def _flap(self, name: str, t: _Track, status: str) -> list[Event]:
        t.history.append(status)
        while len(t.history) > self.flap_window:
            t.history.popleft()
        h = list(t.history)
        changes = sum(a != b for a, b in zip(h, h[1:]))
        if changes == 0 and len(h) == self.flap_window:
            t.flapping = False
        if changes >= self.flap_changes and not t.flapping and not t.alerted:
            t.flapping = True
            return [self._emit("flapping", name,
                               f"{changes} OK/FAIL changes in the last {len(h)} checks")]
        return []

    def cycle(self) -> list[Event]:
        now = self.clock()
        events: list[Event] = []
        checks: list[Check] = []
        blind: set[int] = set()   # collectors that could not enumerate targets
        for i, c in enumerate(self.collectors):
            try:
                got = c.collect()
            except Exception as e:  # a broken collector must not stop the others
                blind.add(i)
                got = [Check(f"collector:{type(c).__name__}", FAIL,
                             f"{type(e).__name__}: {e}", discovery_error=True)]
            if any(ch.discovery_error for ch in got):
                blind.add(i)
            for ch in got:
                self.owner[ch.name] = i
            checks += got
        for key in list(self._anomaly_quiet):
            self._anomaly_quiet[key] -= 1
            if self._anomaly_quiet[key] <= 0:
                del self._anomaly_quiet[key]
        seen = set()
        for ch in checks:
            seen.add(ch.name)
            t = self.tracks.setdefault(ch.name, _Track())
            t.last_seen, t.status = now, ch.status
            t.discovery = ch.discovery_error
            if ch.status == FAIL:
                t.fail_streak += 1
                t.ok_streak = 0
                if t.fail_streak >= self.fail_after and not t.alerted:
                    t.alerted = True
                    t.history.clear()      # the down alert covers this episode
                    t.flapping = False
                    events.append(self._emit("down", ch.name, ch.detail))
            elif ch.status == OK:
                t.ok_streak += 1
                t.fail_streak = 0
                if t.alerted and t.ok_streak >= self.recover_after:
                    t.alerted = False
                    t.history.clear()      # start flap counting afresh
                    t.flapping = False
                    events.append(self._emit("recovered", ch.name, ch.detail))
            if ch.status in (OK, FAIL):
                events += self._flap(ch.name, t, ch.status)
            for metric, value in ch.metrics.items():
                key = f"{ch.name}:{metric}"
                z = self.detector.update(key, float(value))
                if z is not None and key not in self._anomaly_quiet:
                    self._anomaly_quiet[key] = self.anomaly_cooldown
                    events.append(self._emit("anomaly", ch.name, f"{metric}={value} (z={z})"))
        for name in list(self.tracks):
            if name not in seen and self.owner.get(name) not in blind:
                t = self.tracks.pop(name)
                self.owner.pop(name, None)
                if t.alerted:
                    msg = "discovery restored" if t.discovery else "target removed"
                    events.append(self._emit("recovered", name, msg))
        if now - self._last_heartbeat >= self.heartbeat_s:
            self._last_heartbeat = now
            down = sorted(n for n, t in self.tracks.items() if t.alerted)
            msg = (f"{len(self.tracks)} targets, all healthy" if not down
                   else f"{len(self.tracks)} targets, {len(down)} down: {', '.join(down)}")
            events.append(self._emit("heartbeat", "sentinel", msg))
        return events
