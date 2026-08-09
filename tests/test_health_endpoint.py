import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from starlette.requests import Request

from core.sse_server import health_check_handler


def _request() -> Request:
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/health",
            "raw_path": b"/health",
            "query_string": b"",
            "headers": [],
            "scheme": "http",
            "server": ("testserver", 8080),
            "client": ("127.0.0.1", 1234),
        }
    )


def _request_with_config(*, semantic_enabled: bool, behavioral_enabled: bool) -> Request:
    request = _request()
    request.scope["app"] = SimpleNamespace(
        state=SimpleNamespace(
            vanguard_config=SimpleNamespace(
                semantic_enabled=semantic_enabled,
                behavioral_enabled=behavioral_enabled,
            )
        )
    )
    return request


@pytest.mark.asyncio
async def test_health_handler_uses_starlette_request_contract(monkeypatch):
    monkeypatch.setattr("core.behavioral.check_redis_health", AsyncMock(return_value=False))
    monkeypatch.setattr("core.semantic.check_semantic_health", AsyncMock(return_value=True))

    response = await health_check_handler(_request())

    assert response.status_code == 503
    payload = json.loads(response.body)
    assert payload["status"] == "degraded"
    assert payload["layers"]["l1_rules"] == "ok"
    assert payload["layers"]["l3_behavioral"] == "redis_disconnected"


@pytest.mark.asyncio
async def test_health_handler_does_not_probe_disabled_layers(monkeypatch):
    redis_health = AsyncMock(side_effect=AssertionError("Redis must not be probed"))
    semantic_health = AsyncMock(side_effect=AssertionError("semantic backend must not be probed"))
    monkeypatch.setattr("core.behavioral.check_redis_health", redis_health)
    monkeypatch.setattr("core.semantic.check_semantic_health", semantic_health)

    response = await health_check_handler(
        _request_with_config(semantic_enabled=False, behavioral_enabled=False)
    )

    assert response.status_code == 200
    payload = json.loads(response.body)
    assert payload["status"] == "ok"
    assert payload["layers"] == {
        "l1_rules": "ok",
        "l2_semantic": "disabled",
        "l3_behavioral": "disabled",
    }
    assert payload["layer_enabled"] == {
        "l1_rules": True,
        "l2_semantic": False,
        "l3_behavioral": False,
    }
    redis_health.assert_not_awaited()
    semantic_health.assert_not_awaited()
