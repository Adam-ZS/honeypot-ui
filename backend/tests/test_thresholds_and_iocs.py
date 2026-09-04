"""Two features that existed only as storage.

Alert thresholds could be created, listed and edited, and the pipeline decided
with a hardcoded severity check — a setting that saved and did nothing.
Indicators were written on every session and read by no route at all.
"""

import os

from app.models import UserRole

INGEST_HEADERS = {"X-Honeypot-Token": os.environ["HONEYPOT_INGEST_TOKEN"]}

RECON_SESSION = {
    "protocol": "ssh",
    "attacker_ip": "198.51.100.4",
    "started_at": "2026-03-03T03:03:00Z",
    "status": "completed",
    "duration_seconds": 12.0,
    "commands": ["uname -a", "id"],
    "payload": "",
    "uploads": [],
    "failed_logins": 0,
    "packets": [],
    "events": [
        {
            "event_type": "file_download",
            "tool": "wget",
            "url": "http://c2.example.net/stage1",
            "host": "c2.example.net",
            "filename": "stage1",
            "fetched": False,
        }
    ],
}


async def _node(client, admin):
    response = await client.post(
        "/api/v1/nodes/",
        headers=admin,
        json={"name": "edge", "protocol": "ssh", "ip_address": "10.0.0.9", "port": 2222},
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


async def _ingest(client, node_id, overrides=None):
    payload = {**RECON_SESSION, **(overrides or {})}
    response = await client.post(
        f"/api/v1/sessions/ingest-internal?node_id={node_id}",
        headers=INGEST_HEADERS,
        json=payload,
    )
    assert response.status_code == 200, response.text
    return response.json()


class TestThresholdsAreConsulted:
    async def test_a_low_threshold_raises_an_alert_a_hardcoded_rule_would_not(
        self, client, auth_headers
    ):
        admin = await auth_headers(UserRole.ADMIN)
        node_id = await _node(client, admin)

        before = (await client.get("/api/v1/alerts/stats", headers=admin)).json()
        baseline = before["new"]

        created = await client.post(
            "/api/v1/settings/thresholds",
            headers=admin,
            json={"name": "catch-everything", "min_severity": "low"},
        )
        assert created.status_code == 201, created.text

        await _ingest(client, node_id)

        after = (await client.get("/api/v1/alerts/stats", headers=admin)).json()
        assert after["new"] > baseline

    async def test_an_inactive_threshold_is_ignored(self, db_session):
        """Policy is asserted directly.

        Going through the pipeline would make this depend on what the
        classifier happens to decide about a sample session, which is not what
        is under test and is not stable while the model is synthetic.
        """
        from app.models import AlertThreshold, AttackSeverity
        from app.services import thresholds

        db_session.add(
            AlertThreshold(
                name="disabled-rule",
                min_severity=AttackSeverity.LOW,
                is_active=False,
            )
        )
        await db_session.commit()

        decision = await thresholds.evaluate(db_session, AttackSeverity.LOW, 0.0)
        assert decision.should_alert is False
        assert decision.matched == []


class TestThresholdPolicy:
    """The rule engine itself, away from the classifier's opinions."""

    async def test_no_rules_falls_back_to_the_previous_behaviour(self, db_session):
        """A deployment that never opens the settings page must not go quiet."""
        from app.models import AttackSeverity
        from app.services import thresholds

        assert (await thresholds.evaluate(db_session, AttackSeverity.HIGH, 0.0)).should_alert
        assert (await thresholds.evaluate(db_session, AttackSeverity.CRITICAL, 0.0)).should_alert
        assert not (await thresholds.evaluate(db_session, AttackSeverity.MEDIUM, 0.0)).should_alert

    async def test_severity_is_ordered_not_compared_by_equality(self, db_session):
        from app.models import AlertThreshold, AttackSeverity
        from app.services import thresholds

        db_session.add(AlertThreshold(name="medium-up", min_severity=AttackSeverity.MEDIUM))
        await db_session.commit()

        assert (await thresholds.evaluate(db_session, AttackSeverity.CRITICAL, 0.0)).should_alert
        assert (await thresholds.evaluate(db_session, AttackSeverity.MEDIUM, 0.0)).should_alert
        assert not (await thresholds.evaluate(db_session, AttackSeverity.LOW, 0.0)).should_alert

    async def test_anomaly_score_can_fire_on_its_own(self, db_session):
        """The reason to have an anomaly threshold at all is to catch what the
        severity heuristic scored too low."""
        from app.models import AlertThreshold, AttackSeverity
        from app.services import thresholds

        db_session.add(
            AlertThreshold(
                name="odd-behaviour",
                min_severity=AttackSeverity.CRITICAL,
                anomaly_score_threshold=0.8,
            )
        )
        await db_session.commit()

        decision = await thresholds.evaluate(db_session, AttackSeverity.LOW, 0.95)
        assert decision.should_alert is True
        assert decision.matched == ["odd-behaviour"]

        assert not (await thresholds.evaluate(db_session, AttackSeverity.LOW, 0.5)).should_alert

    async def test_channels_are_unioned_across_matching_rules(self, db_session):
        from app.models import AlertThreshold, AttackSeverity
        from app.services import thresholds

        db_session.add_all([
            AlertThreshold(
                name="email-only", min_severity=AttackSeverity.LOW,
                email_enabled=True, webhook_enabled=False,
            ),
            AlertThreshold(
                name="webhook-only", min_severity=AttackSeverity.LOW,
                email_enabled=False, webhook_enabled=True,
            ),
        ])
        await db_session.commit()

        decision = await thresholds.evaluate(db_session, AttackSeverity.HIGH, 0.0)
        assert decision.email is True
        assert decision.webhook is True
        assert sorted(decision.matched) == ["email-only", "webhook-only"]

    async def test_alerts_list_no_longer_recurses(self, client, auth_headers):
        """_to_response called itself; three of four alert routes raised."""
        admin = await auth_headers(UserRole.ADMIN)
        node_id = await _node(client, admin)
        await client.post(
            "/api/v1/settings/thresholds",
            headers=admin,
            json={"name": "all", "min_severity": "low"},
        )
        await _ingest(client, node_id)

        listing = await client.get("/api/v1/alerts/", headers=admin)
        assert listing.status_code == 200, listing.text
        alerts = listing.json()["alerts"]
        assert alerts

        one = await client.get(f"/api/v1/alerts/{alerts[0]['id']}", headers=admin)
        assert one.status_code == 200, one.text
        assert one.json()["id"] == alerts[0]["id"]

    async def test_an_alert_can_be_acknowledged(self, client, auth_headers):
        admin = await auth_headers(UserRole.ADMIN)
        node_id = await _node(client, admin)
        await client.post(
            "/api/v1/settings/thresholds",
            headers=admin,
            json={"name": "all", "min_severity": "low"},
        )
        await _ingest(client, node_id)
        alert_id = (await client.get("/api/v1/alerts/", headers=admin)).json()["alerts"][0]["id"]

        patched = await client.patch(
            f"/api/v1/alerts/{alert_id}",
            headers=admin,
            json={"status": "acknowledged"},
        )
        assert patched.status_code == 200, patched.text
        assert patched.json()["status"] == "acknowledged"


class TestIndicatorRoutes:
    async def test_indicators_are_grouped_by_value(self, client, auth_headers):
        admin = await auth_headers(UserRole.ADMIN)
        node_id = await _node(client, admin)
        await _ingest(client, node_id)
        await _ingest(client, node_id, {"attacker_ip": "198.51.100.5"})

        response = await client.get("/api/v1/iocs/?ioc_type=domain", headers=admin)
        assert response.status_code == 200, response.text
        rows = response.json()["indicators"]

        c2 = [r for r in rows if r["value"] == "c2.example.net"]
        assert len(c2) == 1, "the same host across two sessions must be one row"
        assert c2[0]["sessions"] == 2

    async def test_min_sessions_filters_one_off_observations(self, client, auth_headers):
        admin = await auth_headers(UserRole.ADMIN)
        node_id = await _node(client, admin)
        await _ingest(client, node_id)

        response = await client.get(
            "/api/v1/iocs/?ioc_type=domain&min_sessions=2", headers=admin
        )
        assert response.json()["indicators"] == []

    async def test_unknown_type_is_400_not_an_empty_list(self, client, auth_headers):
        admin = await auth_headers(UserRole.ADMIN)
        response = await client.get("/api/v1/iocs/?ioc_type=nonsense", headers=admin)
        assert response.status_code == 400

    async def test_session_scoped_indicators(self, client, auth_headers):
        admin = await auth_headers(UserRole.ADMIN)
        node_id = await _node(client, admin)
        session_id = (await _ingest(client, node_id))["session_id"]

        response = await client.get(f"/api/v1/iocs/session/{session_id}", headers=admin)
        assert response.status_code == 200, response.text
        values = {r["value"] for r in response.json()}
        assert "http://c2.example.net/stage1" in values
        assert "198.51.100.4" in values

    async def test_session_scoped_indicators_404_for_unknown_session(
        self, client, auth_headers
    ):
        admin = await auth_headers(UserRole.ADMIN)
        response = await client.get("/api/v1/iocs/session/999999", headers=admin)
        assert response.status_code == 404

    async def test_feed_is_one_value_per_line(self, client, auth_headers):
        admin = await auth_headers(UserRole.ADMIN)
        node_id = await _node(client, admin)
        await _ingest(client, node_id)
        await _ingest(client, node_id)

        response = await client.get(
            "/api/v1/iocs/feed?ioc_type=domain&min_sessions=1", headers=admin
        )
        assert response.status_code == 200, response.text
        lines = [l for l in response.text.splitlines() if not l.startswith("#")]
        assert lines == ["c2.example.net"]

    async def test_feed_requires_authentication(self, client):
        response = await client.get("/api/v1/iocs/feed")
        assert response.status_code in (401, 403)
