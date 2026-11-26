import random
from pathlib import Path

import yaml

import httpx

from stack_sentinel import (FAIL, OK, WARN, Check, DockerCollector, EwmaDetector,
                            HttpCollector, Sentinel, SystemdCollector)
from stack_sentinel.cli import build
from stack_sentinel.notify import ChatWebhookNotifier, WebhookNotifier, format_event


class Fake:
    def __init__(self):
        self.checks = []

    def collect(self):
        return list(self.checks)


def make(fail_after=3, recover_after=2, heartbeat_s=100):
    t = [0.0]
    events = []
    f = Fake()
    s = Sentinel([f], events.append, fail_after, recover_after, heartbeat_s,
                 clock=lambda: t[0])
    return s, f, events, t


def test_debounce_single_alert_and_recovery():
    s, f, ev, _ = make()
    f.checks = [Check("svc", FAIL, "boom")]
    for _ in range(5):
        s.cycle()
    assert [e.kind for e in ev] == ["down"]
    f.checks = [Check("svc", OK)]
    s.cycle()
    assert [e.kind for e in ev] == ["down"]          # one OK is not enough
    s.cycle()
    assert [e.kind for e in ev] == ["down", "recovered"]


def test_flapping_does_not_alert():
    s, f, ev, _ = make(fail_after=3)
    for status in [FAIL, FAIL, OK, FAIL, FAIL, OK, FAIL]:
        f.checks = [Check("svc", status)]
        s.cycle()
    assert ev == []


def test_warn_does_not_count_as_failure():
    s, f, ev, _ = make(fail_after=1)
    f.checks = [Check("svc", WARN)]
    s.cycle()
    assert ev == []


def test_removed_target_while_down_is_reported():
    s, f, ev, _ = make(fail_after=1)
    f.checks = [Check("old", FAIL)]
    s.cycle()
    f.checks = []
    s.cycle()
    assert [(e.kind, e.message) for e in ev] == [("down", ""), ("recovered", "target removed")]


def test_heartbeat_lists_down_targets():
    s, f, ev, t = make(fail_after=1, heartbeat_s=100)
    f.checks = [Check("a", OK), Check("b", FAIL, "x")]
    s.cycle()
    t[0] = 150
    s.cycle()
    hb = [e for e in ev if e.kind == "heartbeat"]
    assert len(hb) == 1 and "1 down: b" in hb[0].message


def test_broken_collector_is_isolated():
    class Boom:
        def collect(self):
            raise RuntimeError("bad")
    events = []
    good = Fake()
    good.checks = [Check("svc", FAIL)]
    s = Sentinel([Boom(), good], events.append, fail_after=1)
    s.cycle()
    assert sorted(e.name for e in events) == ["collector:Boom", "svc"]
    assert all(e.kind == "down" for e in events)


def test_ewma_flags_spike_but_not_noise():
    rng = random.Random(0)
    d = EwmaDetector(alpha=0.1, z=4, warmup=20)
    flagged = [d.update("lat", 100 + rng.gauss(0, 5)) for _ in range(500)]
    assert sum(x is not None for x in flagged) <= 2   # false-alarm rate on pure noise
    assert d.update("lat", 200) is not None
    # the spike barely moves the baseline, so normal values stay normal
    assert d.update("lat", 101) is None


def test_ewma_tracks_level_shift_eventually():
    d = EwmaDetector(alpha=0.2, z=4, warmup=5)
    rng = random.Random(1)
    for _ in range(30):
        d.update("x", 10 + rng.random())
    hits = [d.update("x", 50.0) is not None for _ in range(80)]
    assert hits[0] and not hits[-1]   # alarms at the step, then adapts


def test_anomaly_event_from_metrics():
    s, f, ev, _ = make()
    s.detector = EwmaDetector(alpha=0.1, z=4, warmup=10)
    rng = random.Random(2)
    for _ in range(40):
        f.checks = [Check("http:api", OK, metrics={"latency_ms": 50 + rng.gauss(0, 2)})]
        s.cycle()
    f.checks = [Check("http:api", OK, metrics={"latency_ms": 400})]
    s.cycle()
    assert any(e.kind == "anomaly" and "latency_ms=400" in e.message for e in ev)


def test_docker_collector_parses_engine_api():
    payload = [
        {"Names": ["/api"], "State": "running", "Status": "Up 2 hours (healthy)", "Labels": {}},
        {"Names": ["/db"], "State": "running", "Status": "Up 1 hour (unhealthy)", "Labels": {}},
        {"Names": ["/job"], "State": "exited", "Status": "Exited (1) 3 min ago", "Labels": {}},
        {"Names": ["/web"], "State": "running", "Status": "Up 5 s (health: starting)", "Labels": {}},
        {"Names": ["/tmp"], "State": "exited", "Status": "Exited (1)",
         "Labels": {"sentinel.ignore": "true"}},
        {"Names": ["/migrate"], "State": "exited", "Status": "Exited (0) 1 hour ago",
         "Labels": {}},
    ]
    def handler(req):
        assert req.url.path == "/containers/json"
        return httpx.Response(200, json=payload)
    got = {c.name: c.status for c in DockerCollector(transport=httpx.MockTransport(handler)).collect()}
    assert got == {"docker:api": OK, "docker:db": FAIL, "docker:job": FAIL, "docker:web": WARN}


def test_docker_engine_unreachable():
    def handler(req):
        raise httpx.ConnectError("no socket")
    c = DockerCollector(transport=httpx.MockTransport(handler)).collect()
    assert c[0].name == "docker:engine" and c[0].status == FAIL


def test_systemd_collector_filters_and_maps_states():
    out = ("myapp-api.service loaded active running API\n"
           "myapp-worker.service loaded failed failed Worker\n"
           "myapp-sync.service loaded activating start Sync\n"
           "unrelated.service loaded active running Other\n")
    got = {c.name: c.status for c in SystemdCollector(["myapp-*.service"],
                                                      runner=lambda cmd: out).collect()}
    assert got == {"systemd:myapp-api.service": OK,
                   "systemd:myapp-worker.service": FAIL,
                   "systemd:myapp-sync.service": WARN}


def test_http_collector():
    def handler(req):
        return {"/ok": httpx.Response(200), "/err": httpx.Response(503)}.get(
            req.url.path, httpx.Response(404))
    c = HttpCollector({"a": "http://x/ok", "b": "http://x/err", "c": "http://x/missing"},
                      transport=httpx.MockTransport(handler))
    got = {x.name: x.status for x in c.collect()}
    assert got == {"http:a": OK, "http:b": FAIL, "http:c": FAIL}
    assert "latency_ms" in c.collect()[0].metrics


def test_notifiers_never_leak_token(capsys):
    def handler(req):
        raise httpx.ConnectError("down")
    cl = httpx.Client(transport=httpx.MockTransport(handler))
    from stack_sentinel import Event
    ChatWebhookNotifier("https://chat.example.test/hooks/SECRET", client=cl)(Event("down", "svc", "x"))
    WebhookNotifier("https://hooks.example.test/abc", client=cl)(Event("down", "svc", "x"))
    err = capsys.readouterr().err
    assert "SECRET" not in err and "hooks.example.test" not in err
    assert format_event(Event("down", "svc", "boom")) == "[DOWN] svc: boom"


def test_build_from_example_config():
    cfg = yaml.safe_load((Path(__file__).parents[1] / "examples/sentinel.yaml").read_text())
    s, interval = build(cfg)
    assert interval == 60 and len(s.collectors) == 3 and s.fail_after == 3
    assert s.anomaly_cooldown == 10 and s.collectors[0].ignore_clean_exit is True


def test_engine_outage_does_not_fake_recovery():
    s, f, ev, _ = make(fail_after=1, recover_after=1)
    f.checks = [Check("docker:db", FAIL, "unhealthy")]
    s.cycle()
    f.checks = [Check("docker:engine", FAIL, "unreachable", discovery_error=True)]
    s.cycle()
    s.cycle()
    f.checks = [Check("docker:db", FAIL, "unhealthy")]
    s.cycle()
    db_events = [e.kind for e in ev if e.name == "docker:db"]
    assert db_events == ["down"]   # no fake recovery, no duplicate alert


def test_warn_does_not_count_toward_recovery():
    s, f, ev, _ = make(fail_after=1, recover_after=2)
    f.checks = [Check("svc", FAIL)]
    s.cycle()
    for status in [WARN, WARN, WARN]:
        f.checks = [Check("svc", status)]
        s.cycle()
    assert [e.kind for e in ev] == ["down"]


def test_anomaly_events_are_rate_limited():
    s, f, ev, _ = make()
    s.detector = EwmaDetector(alpha=0.1, z=4, warmup=10)
    s.anomaly_cooldown = 5
    for i in range(30):
        f.checks = [Check("http:api", OK, metrics={"latency_ms": 50.0 + (i % 2)})]
        s.cycle()
    for _ in range(4):
        f.checks = [Check("http:api", OK, metrics={"latency_ms": 900.0})]
        s.cycle()
    assert sum(e.kind == "anomaly" for e in ev) == 1


def test_docker_unexpected_reply_is_discovery_error():
    def handler(req):
        return httpx.Response(500, json={"message": "boom"})
    c = DockerCollector(transport=httpx.MockTransport(handler)).collect()
    assert c[0].discovery_error and c[0].status == FAIL


def test_chat_webhook_posts_text():
    sent = []
    def handler(req):
        sent.append(req.read())
        return httpx.Response(200)
    cl = httpx.Client(transport=httpx.MockTransport(handler))
    from stack_sentinel import Event
    ChatWebhookNotifier("https://chat.example.test/hooks/abc", text_field="content",
                        client=cl)(Event("down", "svc", "boom"))
    assert sent == [b'{"content":"[DOWN] svc: boom"}']


def test_engine_back_online_is_reported_as_discovery_restored():
    s, f, ev, _ = make(fail_after=1)
    f.checks = [Check("docker:engine", FAIL, "unreachable", discovery_error=True)]
    s.cycle()
    f.checks = [Check("docker:api", OK)]
    s.cycle()
    assert [(e.kind, e.message) for e in ev] == [("down", "unreachable"),
                                                 ("recovered", "discovery restored")]


def test_failing_notifier_does_not_stop_others_or_the_watcher(tmp_path, capsys):
    from stack_sentinel.notify import Fanout, JsonlNotifier
    got = []
    bad = JsonlNotifier(str(tmp_path / "missing-dir" / "events.jsonl"))
    s = Sentinel([Fake()], Fanout(bad, got.append), fail_after=1)
    s.collectors[0].checks = [Check("svc", FAIL)]
    s.cycle()                       # must not raise
    assert [e.kind for e in got] == ["down"]
    assert "JsonlNotifier failed" in capsys.readouterr().err


def test_webhook_error_status_is_reported(capsys):
    from stack_sentinel import Event
    cl = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(500)))
    WebhookNotifier("https://hooks.example.test/x", client=cl)(Event("down", "svc", "x"))
    err = capsys.readouterr().err
    assert "HTTP 500" in err and "hooks.example.test" not in err


def test_invalid_url_fails_only_that_target():
    def handler(req):
        return httpx.Response(200)
    c = HttpCollector({"ok": "http://x/ok", "bad": "http//no-scheme"},
                      transport=httpx.MockTransport(handler))
    got = {x.name: x.status for x in c.collect()}
    assert got == {"http:ok": OK, "http:bad": FAIL}


def test_persistent_flapping_is_reported_once():
    s, f, ev, _ = make(fail_after=3)
    for i in range(30):
        f.checks = [Check("svc", FAIL if i % 2 else OK)]
        s.cycle()
    assert [e.kind for e in ev] == ["flapping"]
    f.checks = [Check("svc", OK)]
    for _ in range(10):            # a full stable window clears the flag
        s.cycle()
    for i in range(10):
        f.checks = [Check("svc", FAIL if i % 2 else OK)]
        s.cycle()
    assert [e.kind for e in ev] == ["flapping", "flapping"]


def test_http_4xx_fails_but_429_only_warns():
    def handler(req):
        return {"/gone": httpx.Response(410), "/busy": httpx.Response(429)}[req.url.path]
    c = HttpCollector({"g": "http://x/gone", "b": "http://x/busy"},
                      transport=httpx.MockTransport(handler))
    got = {x.name: x.status for x in c.collect()}
    assert got == {"http:g": FAIL, "http:b": WARN}


def test_no_flapping_event_right_after_recovery():
    s, f, ev, _ = make(fail_after=3, recover_after=2)
    for status in [FAIL] * 3 + [OK, FAIL] * 4 + [OK, OK]:
        f.checks = [Check("svc", status)]
        s.cycle()
    assert [e.kind for e in ev] == ["down", "recovered"]


def test_flapping_after_a_short_outage_is_reported_again():
    s, f, ev, _ = make(fail_after=3, recover_after=2)
    seq = [OK, FAIL] * 5 + [FAIL] * 3 + [OK, OK] + [FAIL, OK] * 6
    for status in seq:
        f.checks = [Check("svc", status)]
        s.cycle()
    assert [e.kind for e in ev] == ["flapping", "down", "recovered", "flapping"]
