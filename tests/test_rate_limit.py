import app.main as main_module
from fastapi.testclient import TestClient
from app.rate_limit import RateLimiter


def test_rate_limiter_blocks_after_limit():
    limiter = RateLimiter(max_requests=2, window_seconds=60)

    assert limiter.allow("agent-1") == (True, 0)
    assert limiter.allow("agent-1") == (True, 0)

    allowed, retry_after = limiter.allow("agent-1")

    assert allowed is False
    assert retry_after > 0


def test_rate_limiter_resets_after_window(monkeypatch):
    import app.rate_limit as rate_module

    current_time = [100.0]
    monkeypatch.setattr(
        rate_module.time,
        "monotonic",
        lambda: current_time[0]
    )

    limiter = RateLimiter(max_requests=1, window_seconds=10)

    assert limiter.allow("agent-1") == (True, 0)

    current_time[0] = 105.0
    assert limiter.allow("agent-1")[0] is False

    current_time[0] = 111.0
    assert limiter.allow("agent-1") == (True, 0)


def test_invalid_api_key_does_not_consume_rate_limit(monkeypatch):
    monkeypatch.setenv(
        "AGENTSHIELD_API_KEY",
        "test-only-agentshield-key"
    )

    monkeypatch.setattr(
        main_module,
        "rate_limiter",
        RateLimiter(max_requests=1, window_seconds=60)
    )

    client = TestClient(main_module.app)

    invalid = client.get(
        "/v1/history",
        headers={"Authorization": "Bearer wrong-key"}
    )
    assert invalid.status_code == 401

    valid_headers = {
        "Authorization": "Bearer test-only-agentshield-key"
    }

    first = client.get("/v1/history", headers=valid_headers)
    assert first.status_code == 200

    second = client.get("/v1/history", headers=valid_headers)
    assert second.status_code == 429
    assert "Retry-After" in second.headers


def test_rate_limiter_cleanup_removes_expired_clients(monkeypatch):
    import app.rate_limit as rate_module

    current_time = [100.0]

    monkeypatch.setattr(
        rate_module.time,
        "monotonic",
        lambda: current_time[0]
    )

    limiter = RateLimiter(
        max_requests=2,
        window_seconds=10,
        cleanup_interval=5
    )

    assert limiter.allow("old-agent") == (True, 0)
    assert "old-agent" in limiter.requests

    current_time[0] = 111.0

    assert limiter.allow("new-agent") == (True, 0)

    assert "old-agent" not in limiter.requests
    assert "new-agent" in limiter.requests


def test_rate_limiter_keeps_clients_separate():
    limiter = RateLimiter(max_requests=2, window_seconds=60)

    assert limiter.allow("agent-1") == (True, 0)
    assert limiter.allow("agent-1") == (True, 0)
    assert limiter.allow("agent-1")[0] is False

    assert limiter.allow("agent-2") == (True, 0)


def test_forwarded_for_cannot_bypass_rate_limit(monkeypatch):
    monkeypatch.setenv(
        "AGENTSHIELD_API_KEY",
        "test-only-agentshield-key"
    )
    monkeypatch.setattr(
        main_module,
        "rate_limiter",
        RateLimiter(max_requests=1, window_seconds=60)
    )

    client = TestClient(main_module.app)
    headers = {
        "Authorization": "Bearer test-only-agentshield-key"
    }

    first = client.get(
        "/v1/history",
        headers={**headers, "X-Forwarded-For": "1.1.1.1"}
    )
    second = client.get(
        "/v1/history",
        headers={**headers, "X-Forwarded-For": "8.8.8.8"}
    )

    assert first.status_code == 200
    assert second.status_code == 429
