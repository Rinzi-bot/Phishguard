def test_home_page(client):
    response = client.get("/")
    assert response.status_code in [200, 302]


def test_login_page(client):
    response = client.get("/auth/login")
    assert response.status_code == 200