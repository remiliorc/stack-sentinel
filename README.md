# stack-sentinel

A small, **low-noise** health watcher for self-hosted stacks: one box, a few
VMs, or an edge site with no full monitoring suite. It discovers what to watch,
alerts once when something is really down, tells you when it recovers, and
proves it is alive with a periodic heartbeat.

## What it watches

| Collector | Discovery | Fails when |
|---|---|---|
| Docker | Every container from the Engine API (unix socket). Opt out with the label `sentinel.ignore=true`. One-shot containers that exited with code 0 are skipped (`docker.ignore_clean_exit`; turn it off if a long-running service could be stopped cleanly) | Container not running, or its health check reports `(unhealthy)` |
| systemd | Services matching glob patterns, e.g. `myapp-*.service` | Unit not `active/running` (`activating` only warns) |
| HTTP | Named health URLs | 5xx, 4xx (except 429), or a connection error. 429 and slow responses only warn. Redirects are not followed, and a 3xx counts as reachable |

## How it keeps the noise down

- **Debounce**: alerts after `fail_after` consecutive failures (default 3). One alert per incident, not one per cycle.
- **Hysteresis on recovery**: declares recovery after `recover_after` consecutive OK results. WARN results count neither as failures nor toward recovery.
- **Flapping is reported once**: a target alternating FAIL and OK never reaches the debounce threshold, so it gets a single `flapping` event when it changes state at least `flap_changes` times in the last `flap_window` checks (default 6 in 10).
- **Removed targets**: a container that disappears while alerted produces a single "target removed" event.
- **Heartbeat** every N hours: "12 targets, all healthy" or "12 targets, 1 down: db". If the heartbeat stops arriving, the watcher itself is down.
- **Isolated collectors**: a collector that crashes, or cannot list its targets (Docker engine down, `systemctl` missing), becomes a debounced alert of its own. Its previous targets are kept as they were, so an engine outage never produces fake "recovered" messages, and the others keep running.
- **Rate-limited anomalies**: at most one anomaly event per metric every `anomaly.cooldown_cycles` cycles (YAML setting).

## Anomaly detection

Numeric metrics, such as HTTP latency, feed a streaming **EWMA mean and variance**
per target and metric. A sample is flagged when `|x − mean| / std > z` after a
warm-up period. A spike is only lightly absorbed into the baseline, so it does
not mask the next one. A real level shift still becomes the new normal after a
while.

The tests check the false-alarm rate on pure noise (at most 2 flagged samples
out of 500 at z = 4), spike detection, and adaptation to a level shift. That
rate holds for Gaussian noise; real latencies are heavy-tailed, so expect more
flags in practice and tune `z` and the cooldown on your own data.

## Notifiers

Console, JSONL file, a generic JSON webhook (the full event), and a chat
webhook (a plain-text message for a chat tool's incoming webhook; the field
name is configurable). Webhook URLs come only from environment variables
(`SENTINEL_WEBHOOK_URL`, `SENTINEL_CHAT_WEBHOOK_URL`), and errors never print
them, because incoming-webhook URLs embed their secret.

## Run

```bash
pip install -e ".[dev]"
pytest -q
stack-sentinel --config examples/sentinel.yaml --once   # single cycle
stack-sentinel --config examples/sentinel.yaml          # loop every interval_s
```

Sample output of one cycle (`fail_after: 1`, on a machine without Docker running):

```
[DOWN] docker:engine: engine unreachable: ConnectError
[DOWN] http:missing: HTTP 404
[DOWN] http:closed: ConnectError
```

## Testing notes

The Docker and systemd collectors are tested against recorded Engine API and
`systemctl` output (`httpx.MockTransport` and an injected command runner). The
HTTP collector was also exercised against a live local server.

## License

MIT
