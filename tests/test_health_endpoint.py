import json
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
