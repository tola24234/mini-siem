from tests.conftest import login


def test_alert_search_matches_alert_fields(client, user, alert_factory):
    alert_factory(source_ip="192.0.2.1", country="Ethiopia", mitre_id="T1110")
    alert_factory(
        source_ip="198.51.100.8",
        event_type="Port scan",
        severity="MEDIUM",
        description="Service enumeration",
        mitre_id="T1046",
        country="Kenya",
    )
    login(client)

    response = client.get("/api/alerts?q=ethiopia")

    assert response.status_code == 200
    assert response.json["matching_total"] == 1
    assert response.json["query"] == "ethiopia"
    assert response.json["alerts"][0]["source_ip"] == "192.0.2.1"


def test_alert_search_treats_like_characters_as_text(client, user, alert_factory):
    alert_factory(description="100% packet loss")
    alert_factory(description="ordinary event")
    login(client)

    assert client.get("/api/alerts?q=%25").json["matching_total"] == 1
    assert client.get("/api/alerts?q=_").json["matching_total"] == 0


def test_statistics_return_severity_top_ips_and_timeline(client, user, alert_factory):
    alert_factory(timestamp="2026-07-20 12:00:00", source_ip="192.0.2.1", severity="HIGH")
    alert_factory(timestamp="2026-07-21 09:00:00", source_ip="192.0.2.1", severity="LOW")
    alert_factory(timestamp="2026-07-21 10:00:00", source_ip="198.51.100.8", severity="MEDIUM")
    login(client)

    response = client.get("/api/stats")

    assert response.status_code == 200
    assert response.json["severity"] == {"HIGH": 1, "MEDIUM": 1, "LOW": 1}
    assert response.json["top_ips"][0] == {"ip": "192.0.2.1", "count": 2}
    assert response.json["alerts_by_day"] == [
        {"date": "2026-07-20", "count": 1},
        {"date": "2026-07-21", "count": 2},
    ]
