"""Unit tests for firewall_create_zone tool."""

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
async def test_create_zone_success_minimal():
    """Creates zone with just a name when no interfaces/VRFs provided."""
    zone_graphql = {"zones": []}

    async def mock_graphql(query):
        if "zones" in query:
            return zone_graphql
        return {}

    mock_post_result = {"id": "new-zone-uuid", "name": "DMZ"}

    with patch("server.client.graphql", new_callable=AsyncMock, side_effect=mock_graphql):
        with patch(
            "server.client.rest_post", new_callable=AsyncMock, return_value=mock_post_result
        ) as mock_post:
            import server

            result = await server.firewall_create_zone(name="DMZ")
            data = json.loads(result)
            assert data["status"] == "created"
            assert data["id"] == "new-zone-uuid"
            assert data["name"] == "DMZ"

            # Verify POST call
            mock_post.assert_called_once()
            call_args = mock_post.call_args
            assert call_args[0][0] == "plugins/firewall/zones"
            payload = call_args[0][1]
            assert payload["name"] == "DMZ"
            assert payload["interfaces"] == []
            assert payload["vrfs"] == []
            assert payload["status"] == {"name": "Active"}
            assert payload["description"] == ""


@pytest.mark.asyncio
async def test_create_zone_idempotent():
    """When zone already exists, returns idempotent response without creating."""
    zone_graphql = {"zones": [{"id": "existing-zone-uuid", "name": "INSIDE"}]}

    with patch("server.client.graphql", new_callable=AsyncMock, return_value=zone_graphql):
        with patch("server.client.rest_post", new_callable=AsyncMock) as mock_post:
            import server

            result = await server.firewall_create_zone(name="INSIDE")
            data = json.loads(result)
            assert data["status"] == "exists"
            assert data["id"] == "existing-zone-uuid"
            assert data["name"] == "INSIDE"
            mock_post.assert_not_called()


@pytest.mark.asyncio
async def test_create_zone_with_interfaces():
    """Resolves interface UUIDs via GraphQL before creating zone."""
    call_count = {"n": 0}

    async def mock_graphql(query):
        call_count["n"] += 1
        if "zones(name:" in query:
            return {"zones": []}
        if "interfaces(name:" in query:
            if "eth0" in query:
                return {"interfaces": [{"id": "iface-uuid-1"}]}
            if "eth1" in query:
                return {"interfaces": [{"id": "iface-uuid-2"}]}
        return {}

    mock_post_result = {"id": "new-zone-uuid", "name": "LAN"}

    with patch("server.client.graphql", new_callable=AsyncMock, side_effect=mock_graphql):
        with patch(
            "server.client.rest_post", new_callable=AsyncMock, return_value=mock_post_result
        ) as mock_post:
            import server

            result = await server.firewall_create_zone(
                name="LAN", interfaces=["eth0", "eth1"]
            )
            data = json.loads(result)
            assert data["status"] == "created"

            payload = mock_post.call_args[0][1]
            assert payload["interfaces"] == ["iface-uuid-1", "iface-uuid-2"]


@pytest.mark.asyncio
async def test_create_zone_with_vrfs():
    """Resolves VRF UUIDs via GraphQL before creating zone."""

    async def mock_graphql(query):
        if "zones(name:" in query:
            return {"zones": []}
        if "vrfs(name:" in query:
            if "MGMT" in query:
                return {"vrfs": [{"id": "vrf-uuid-1"}]}
        return {}

    mock_post_result = {"id": "new-zone-uuid", "name": "MGMT-ZONE"}

    with patch("server.client.graphql", new_callable=AsyncMock, side_effect=mock_graphql):
        with patch(
            "server.client.rest_post", new_callable=AsyncMock, return_value=mock_post_result
        ) as mock_post:
            import server

            result = await server.firewall_create_zone(name="MGMT-ZONE", vrfs=["MGMT"])
            data = json.loads(result)
            assert data["status"] == "created"

            payload = mock_post.call_args[0][1]
            assert payload["vrfs"] == ["vrf-uuid-1"]


@pytest.mark.asyncio
async def test_create_zone_interface_not_found():
    """Returns error when a specified interface cannot be resolved."""

    async def mock_graphql(query):
        if "zones(name:" in query:
            return {"zones": []}
        if "interfaces(name:" in query:
            return {"interfaces": []}
        return {}

    with patch("server.client.graphql", new_callable=AsyncMock, side_effect=mock_graphql):
        with patch("server.client.rest_post", new_callable=AsyncMock) as mock_post:
            import server

            result = await server.firewall_create_zone(
                name="DMZ", interfaces=["nonexistent-iface"]
            )
            data = json.loads(result)
            assert "error" in data
            assert "nonexistent-iface" in data["error"]
            assert "not found" in data["error"]
            mock_post.assert_not_called()


@pytest.mark.asyncio
async def test_create_zone_vrf_not_found():
    """Returns error when a specified VRF cannot be resolved."""

    async def mock_graphql(query):
        if "zones(name:" in query:
            return {"zones": []}
        if "interfaces(name:" in query:
            return {"interfaces": [{"id": "iface-uuid"}]}
        if "vrfs(name:" in query:
            return {"vrfs": []}
        return {}

    with patch("server.client.graphql", new_callable=AsyncMock, side_effect=mock_graphql):
        with patch("server.client.rest_post", new_callable=AsyncMock) as mock_post:
            import server

            result = await server.firewall_create_zone(
                name="DMZ", interfaces=["eth0"], vrfs=["MISSING-VRF"]
            )
            data = json.loads(result)
            assert "error" in data
            assert "MISSING-VRF" in data["error"]
            assert "not found" in data["error"]
            mock_post.assert_not_called()


@pytest.mark.asyncio
async def test_create_zone_itsm_blocked(monkeypatch):
    """When ITSM is enforced and no cr_number, returns ITSM error."""
    monkeypatch.setenv("ITSM_ENABLED", "true")
    monkeypatch.setenv("ITSM_LAB_MODE", "false")

    import importlib
    import server

    importlib.reload(server)

    result = await server.firewall_create_zone(name="DMZ")
    data = json.loads(result)
    assert "error" in data
    assert "ITSM" in data["error"]


@pytest.mark.asyncio
async def test_create_zone_itsm_with_cr_number(monkeypatch):
    """When ITSM is enforced and cr_number is provided, proceeds normally."""
    monkeypatch.setenv("ITSM_ENABLED", "true")
    monkeypatch.setenv("ITSM_LAB_MODE", "false")

    import importlib
    import server

    importlib.reload(server)

    async def mock_graphql(query):
        if "zones(name:" in query:
            return {"zones": []}
        return {}

    mock_post_result = {"id": "new-zone-uuid", "name": "DMZ"}

    with patch("server.client.graphql", new_callable=AsyncMock, side_effect=mock_graphql):
        with patch(
            "server.client.rest_post", new_callable=AsyncMock, return_value=mock_post_result
        ):
            result = await server.firewall_create_zone(name="DMZ", cr_number="CHG0012345")
            data = json.loads(result)
            assert data["status"] == "created"
            assert data["id"] == "new-zone-uuid"


@pytest.mark.asyncio
async def test_create_zone_with_description():
    """Description is passed to the POST payload."""
    import importlib
    import server

    importlib.reload(server)

    async def mock_graphql(query):
        if "zones(name:" in query:
            return {"zones": []}
        return {}

    mock_post_result = {"id": "zone-uuid", "name": "WAN"}

    with patch("server.client.graphql", new_callable=AsyncMock, side_effect=mock_graphql):
        with patch(
            "server.client.rest_post", new_callable=AsyncMock, return_value=mock_post_result
        ) as mock_post:
            result = await server.firewall_create_zone(
                name="WAN", description="External facing zone"
            )
            data = json.loads(result)
            assert data["status"] == "created"

            payload = mock_post.call_args[0][1]
            assert payload["description"] == "External facing zone"


@pytest.mark.asyncio
async def test_create_zone_handles_nautobot_error():
    """When NautobotError is raised, returns structured error."""
    import importlib
    import server

    importlib.reload(server)

    from nautobot_client import NautobotError

    with patch(
        "server.client.graphql",
        new_callable=AsyncMock,
        side_effect=NautobotError("Nautobot unreachable: timeout"),
    ):
        result = await server.firewall_create_zone(name="DMZ")
        data = json.loads(result)
        assert "error" in data
        assert "Nautobot unreachable" in data["error"]
