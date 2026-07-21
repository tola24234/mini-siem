from tests.conftest import login


def test_dashboard_and_api_require_login(client):
    assert client.get("/").status_code == 302
    assert client.get("/api/alerts").status_code == 302
    assert client.get("/api/stats").status_code == 302


def test_login_requires_valid_csrf_token(client, user):
    response = client.post(
        "/login",
        data={"username": user.username, "password": "correct-horse-battery-staple"},
    )

    assert response.status_code == 400


def test_login_and_logout(client, user):
    response = login(client)
    assert response.status_code == 302
    assert response.headers["Location"] == "/"

    assert client.get("/").status_code == 200
    assert client.post("/logout", data={}).status_code == 400

    client.get("/")
    with client.session_transaction() as session:
        csrf_token = session["csrf_token"]
    response = client.post("/logout", data={"csrf_token": csrf_token})

    assert response.status_code == 302
    assert response.headers["Location"] == "/login"
    assert client.get("/").status_code == 302


def test_login_rejects_invalid_password(client, user):
    response = login(client, password="not-the-password")

    assert response.status_code == 401
    assert b"Invalid username or password" in response.data
