import pytest
from unittest.mock import AsyncMock, MagicMock

from core.sse_server import ServerContext, _validate_message_request, handle_messages


def test_validate_message_request_rejects_bad_content_type():
    cfg = {"MAX_BODY_BYTES": 1024}
    ok, status, message = _validate_message_request(
        {"headers": [(b"content-type", b"text/plain"), (b"content-length", b"2")]},
        cfg,
    )
    assert ok is False
    assert status == 415
    assert "application/json" in message


def test_validate_message_request_rejects_oversized_body():
    cfg = {"MAX_BODY_BYTES": 10}
    ok, status, message = _validate_message_request(
        {"headers": [(b"content-type", b"application/json"), (b"content-length", b"11")]},
        cfg,
    )
    assert ok is False
    assert status == 413
    assert "10" in message


@pytest.mark.asyncio
async def test_handle_messages_rejects_unsupported_content_type():
    ctx = ServerContext(
        server_command=["python", "-c", "print('hello')"],
        config=None,
        sse_transport=MagicMock(),
        cfg={
            "API_KEY": "",
            "ALLOWED_IPS": [],
            "MAX_CONCURRENCY": 5,
            "MAX_GLOBAL_CONNECTIONS": 10,
            "RATE_LIMIT_PER_SEC": 10.0,
            "MAX_BODY_BYTES": 1024,
        },
    )

    scope = {
        "type": "http",
        "client": ["127.0.0.1", 1234],
        "headers": [(b"content-type", b"text/plain"), (b"content-length", b"12")],
    }

    with pytest.MonkeyPatch.context() as mp:
        send_error = AsyncMock()
        mp.setattr("core.sse_server._send_error", send_error)
        await handle_messages(scope, AsyncMock(), AsyncMock(), ctx)
        send_error.assert_awaited_once()
        assert send_error.await_args.args[1] == 415
