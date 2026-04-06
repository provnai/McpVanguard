from starlette.testclient import TestClient

from core.dashboard import app


def test_dashboard_home_is_self_contained():
    client = TestClient(app)

    response = client.get("/")

    assert response.status_code == 200
    html = response.text
    assert "https://unpkg.com" not in html
    assert "https://cdn.tailwindcss.com" not in html
    assert "refreshLogs" in html
    assert "Live Monitoring" in html
