"""Unit tests for firewall_delete_zone tool."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import pytest


@pytest.fixture(autouse=True)
def set_env(monkeypatch):
    """Set required env vars so server.py doesn't exit."""
    monkeypatch.setenv("NAUTOBOT_URL", "http://test")
    monkeypatch.setenv("NAUTOBOT_TOKEN", "test-token")
    monkeypatch.setenv("ITSM_ENABLED", "false")
    monkeypatch.setenv("ITSM_LAB_MODE", "true")


@pytest.mark.asyncio
async def test_delete_zone_success():
    """When zone exists and is not referenced, deletes successfully."""
    zone_graphql = {"zones": [{"id": "zone-uuid-1", "name": "dmz"}]}
    rules_graphql = {"policy_rules": []}

    async def mock_graphql(query):
        if "zones" in query:
            return zone_graphql
        if "policy_rules" in query:
            return rules_graphql
        return {}

    with patch("server.client.graphql", new_callable=AsyncMock, side_effect=mock_graphql):
        with patch("server.client.rest_delete", new_callable=AsyncMock) as mock_delete:
            import server

            result = await server.firewall_delete_zone(name="dmz")
            data = json.loads(result)
            assert data["status"] == "deleted"
            assert data["name"] == "dmz"
            mock_delete.assert_called_once_with("plugins/firewall/zones/zone-uuid-1")


@pytest.mark.asyncio
async def test_delete_zone_not_found():
    """When zone does not exist, returns error."""
    zone_graphql = {"zones": []}

    with patch("server.client.graphql", new_callable=AsyncMock, return_value=zone_graphql):
        import server

        result = await server.firewall_delete_zone(name="nonexistent")
        data = json.loads(result)
        assert "error" in data
        assert "not found" in data["error"]
        assert "nonexistent" in data["error"]


@pytest.mark.asyncio
async def test_delete_zone_referenced_by_source_zone():
    """When zone is referenced as source_zone in a policy rule, returns in-use error."""
    zone_graphql = {"zones": [{"id": "zone-uuid-1", "name": "trust"}]}
    rules_graphql = {
        "policy_rules": [
            {
                "id": "rule-1",
                "source_zone": {"id": "zone-uuid-1"},
                "destination_zone": {"id": "other-zone-uuid"},
            }
        ]
    }

    async def mock_graphql(query):
        if "zones" in query:
            return zone_graphql
        if "policy_rules" in query:
            return rules_graphql
        return {}

    with patch("server.client.graphql", new_callable=AsyncMock, side_effect=mock_graphql):
        import server

        result = await server.firewall_delete_zone(name="trust")
        data = json.loads(result)
        assert "error" in data
        assert "referenced by policy rules" in data["error"]
        assert "trust" in data["error"]


@pytest.mark.asyncio
async def test_delete_zone_referenced_by_destination_zone():
    """When zone is referenced as destination_zone in a policy rule, returns in-use error."""
    zone_graphql = {"zones": [{"id": "zone-uuid-2", "name": "untrust"}]}
    rules_graphql = {
        "policy_rules": [
            {
                "id": "rule-1",
                "source_zone": {"id": "some-other-zone"},
                "destination_zone": {"id": "zone-uuid-2"},
            }
        ]
    }

    async def mock_graphql(query):
        if "zones" in query:
            return zone_graphql
        if "policy_rules" in query:
            return rules_graphql
        return {}

    with patch("server.client.graphql", new_callable=AsyncMock, side_effect=mock_graphql):
        import server

        result = await server.firewall_delete_zone(name="untrust")
        data = json.loads(result)
        assert "error" in data
        assert "referenced by policy rules" in data["error"]
        assert "untrust" in data["error"]


@pytest.mark.asyncio
async def test_delete_zone_itsm_blocked(monkeypatch):
    """When ITSM is enforced and no cr_number, returns ITSM error."""
    monkeypatch.setenv("ITSM_ENABLED", "true")
    monkeypatch.setenv("ITSM_LAB_MODE", "false")

    # Need to reimport to pick up the changed env vars
    import importlib
    import server

    importlib.reload(server)

    result = await server.firewall_delete_zone(name="trust")
    data = json.loads(result)
    assert "error" in data
    assert "ITSM" in data["error"]


@pytest.mark.asyncio
async def test_delete_zone_itsm_with_cr_number(monkeypatch):
    """When ITSM is enforced and cr_number is provided, proceeds normally."""
    monkeypatch.setenv("ITSM_ENABLED", "true")
    monkeypatch.setenv("ITSM_LAB_MODE", "false")

    import importlib
    import server

    importlib.reload(server)

    zone_graphql = {"zones": [{"id": "zone-uuid-1", "name": "dmz"}]}
    rules_graphql = {"policy_rules": []}

    async def mock_graphql(query):
        if "zones" in query:
            return zone_graphql
        if "policy_rules" in query:
            return rules_graphql
        return {}

    with patch("server.client.graphql", new_callable=AsyncMock, side_effect=mock_graphql):
        with patch("server.client.rest_delete", new_callable=AsyncMock):
            result = await server.firewall_delete_zone(name="dmz", cr_number="CHG0012345")
            data = json.loads(result)
            assert data["status"] == "deleted"
            assert data["name"] == "dmz"


@pytest.mark.asyncio
async def test_delete_zone_handles_nautobot_error(monkeypatch):
    """When NautobotError is raised, returns structured error."""
    monkeypatch.setenv("ITSM_ENABLED", "false")
    monkeypatch.setenv("ITSM_LAB_MODE", "true")

    import importlib
    import server

    importlib.reload(server)

    from nautobot_client import NautobotError

    with patch(
        "server.client.graphql",
        new_callable=AsyncMock,
        side_effect=NautobotError("Nautobot unreachable: timeout"),
    ):
        result = await server.firewall_delete_zone(name="trust")
        data = json.loads(result)
        assert "error" in data
        assert "Nautobot unreachable" in data["error"]


@pytest.mark.asyncio
async def test_delete_zone_no_references_with_null_zones(monkeypatch):
    """When policy rules have null source/destination zones, deletion proceeds."""
    monkeypatch.setenv("ITSM_ENABLED", "false")
    monkeypatch.setenv("ITSM_LAB_MODE", "true")

    import importlib
    import server

    importlib.reload(server)

    zone_graphql = {"zones": [{"id": "zone-uuid-1", "name": "dmz"}]}
    rules_graphql = {
        "policy_rules": [
            {
                "id": "rule-1",
                "source_zone": None,
                "destination_zone": None,
            }
        ]
    }

    async def mock_graphql(query):
        if "zones" in query:
            return zone_graphql
        if "policy_rules" in query:
            return rules_graphql
        return {}

    with patch("server.client.graphql", new_callable=AsyncMock, side_effect=mock_graphql):
        with patch("server.client.rest_delete", new_callable=AsyncMock) as mock_delete:
            result = await server.firewall_delete_zone(name="dmz")
            data = json.loads(result)
            assert data["status"] == "deleted"
            mock_delete.assert_called_once_with("plugins/firewall/zones/zone-uuid-1")
