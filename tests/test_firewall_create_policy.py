"""Unit tests for firewall_create_policy tool."""

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
async def test_create_policy_success_minimal():
    """Creates policy with just a name when no device is provided."""
    async def mock_graphql(query):
        if "policies(name:" in query:
            return {"policies": []}
        return {}

    mock_post_result = {"id": "new-policy-uuid", "name": "OUTSIDE-TO-INSIDE"}

    with patch("server.client.graphql", new_callable=AsyncMock, side_effect=mock_graphql):
        with patch(
            "server.client.rest_post", new_callable=AsyncMock, return_value=mock_post_result
        ) as mock_post:
            import server

            result = await server.firewall_create_policy(name="OUTSIDE-TO-INSIDE")
            data = json.loads(result)
            assert data["status"] == "created"
            assert data["id"] == "new-policy-uuid"
            assert data["name"] == "OUTSIDE-TO-INSIDE"

            # Verify POST call
            mock_post.assert_called_once()
            call_args = mock_post.call_args
            assert call_args[0][0] == "plugins/firewall/policies"
            payload = call_args[0][1]
            assert payload["name"] == "OUTSIDE-TO-INSIDE"
            assert payload["assigned_devices"] == []
            assert payload["status"] == {"name": "Active"}
            assert payload["description"] == ""


@pytest.mark.asyncio
async def test_create_policy_idempotent():
    """When policy already exists, returns idempotent response without creating."""
    async def mock_graphql(query):
        if "policies(name:" in query:
            return {"policies": [{"id": "existing-policy-uuid", "name": "DMZ-POLICY", "assigned_devices": []}]}
        return {}

    with patch("server.client.graphql", new_callable=AsyncMock, side_effect=mock_graphql):
        with patch("server.client.rest_post", new_callable=AsyncMock) as mock_post:
            import server

            result = await server.firewall_create_policy(name="DMZ-POLICY")
            data = json.loads(result)
            assert data["status"] == "exists"
            assert data["id"] == "existing-policy-uuid"
            assert data["name"] == "DMZ-POLICY"
            mock_post.assert_not_called()


@pytest.mark.asyncio
async def test_create_policy_with_device():
    """Resolves device UUID via GraphQL and assigns it to the policy."""
    async def mock_graphql(query):
        if "policies(name:" in query:
            return {"policies": []}
        if "devices(name:" in query:
            return {"devices": [{"id": "device-uuid-1"}]}
        return {}

    mock_post_result = {"id": "new-policy-uuid", "name": "FW-POLICY"}

    with patch("server.client.graphql", new_callable=AsyncMock, side_effect=mock_graphql):
        with patch(
            "server.client.rest_post", new_callable=AsyncMock, return_value=mock_post_result
        ) as mock_post:
            import server

            result = await server.firewall_create_policy(name="FW-POLICY", device="fw01")
            data = json.loads(result)
            assert data["status"] == "created"
            assert data["id"] == "new-policy-uuid"

            payload = mock_post.call_args[0][1]
            assert payload["assigned_devices"] == ["device-uuid-1"]


@pytest.mark.asyncio
async def test_create_policy_device_not_found():
    """Returns error when specified device cannot be resolved."""
    async def mock_graphql(query):
        if "policies(name:" in query:
            return {"policies": []}
        if "devices(name:" in query:
            return {"devices": []}
        return {}

    with patch("server.client.graphql", new_callable=AsyncMock, side_effect=mock_graphql):
        with patch("server.client.rest_post", new_callable=AsyncMock) as mock_post:
            import server

            result = await server.firewall_create_policy(name="FW-POLICY", device="nonexistent-device")
            data = json.loads(result)
            assert "error" in data
            assert "nonexistent-device" in data["error"]
            assert "not found" in data["error"]
            mock_post.assert_not_called()


@pytest.mark.asyncio
async def test_create_policy_itsm_blocked(monkeypatch):
    """When ITSM is enforced and no cr_number, returns ITSM error."""
    monkeypatch.setenv("ITSM_ENABLED", "true")
    monkeypatch.setenv("ITSM_LAB_MODE", "false")

    import importlib
    import server

    importlib.reload(server)

    result = await server.firewall_create_policy(name="FW-POLICY")
    data = json.loads(result)
    assert "error" in data
    assert "ITSM" in data["error"]


@pytest.mark.asyncio
async def test_create_policy_itsm_with_cr_number(monkeypatch):
    """When ITSM is enforced and cr_number is provided, proceeds normally."""
    monkeypatch.setenv("ITSM_ENABLED", "true")
    monkeypatch.setenv("ITSM_LAB_MODE", "false")

    import importlib
    import server

    importlib.reload(server)

    async def mock_graphql(query):
        if "policies(name:" in query:
            return {"policies": []}
        return {}

    mock_post_result = {"id": "new-policy-uuid", "name": "FW-POLICY"}

    with patch("server.client.graphql", new_callable=AsyncMock, side_effect=mock_graphql):
        with patch(
            "server.client.rest_post", new_callable=AsyncMock, return_value=mock_post_result
        ):
            result = await server.firewall_create_policy(name="FW-POLICY", cr_number="CHG0012345")
            data = json.loads(result)
            assert data["status"] == "created"
            assert data["id"] == "new-policy-uuid"


@pytest.mark.asyncio
async def test_create_policy_with_description():
    """Description is passed to the POST payload."""
    import importlib
    import server

    importlib.reload(server)

    async def mock_graphql(query):
        if "policies(name:" in query:
            return {"policies": []}
        return {}

    mock_post_result = {"id": "policy-uuid", "name": "LAN-POLICY"}

    with patch("server.client.graphql", new_callable=AsyncMock, side_effect=mock_graphql):
        with patch(
            "server.client.rest_post", new_callable=AsyncMock, return_value=mock_post_result
        ) as mock_post:
            result = await server.firewall_create_policy(
                name="LAN-POLICY", description="LAN to WAN traffic policy"
            )
            data = json.loads(result)
            assert data["status"] == "created"

            payload = mock_post.call_args[0][1]
            assert payload["description"] == "LAN to WAN traffic policy"


@pytest.mark.asyncio
async def test_create_policy_handles_nautobot_error():
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
        result = await server.firewall_create_policy(name="FW-POLICY")
        data = json.loads(result)
        assert "error" in data
        assert "Nautobot unreachable" in data["error"]


@pytest.mark.asyncio
async def test_create_policy_idempotent_with_device():
    """Idempotency check correctly filters by device when provided."""
    async def mock_graphql(query):
        if "policies(name:" in query:
            return {"policies": [
                {"id": "policy-uuid-1", "name": "SHARED-POLICY", "assigned_devices": [{"name": "fw01"}]},
                {"id": "policy-uuid-2", "name": "SHARED-POLICY", "assigned_devices": [{"name": "fw02"}]},
            ]}
        return {}

    with patch("server.client.graphql", new_callable=AsyncMock, side_effect=mock_graphql):
        with patch("server.client.rest_post", new_callable=AsyncMock) as mock_post:
            import server

            result = await server.firewall_create_policy(name="SHARED-POLICY", device="fw01")
            data = json.loads(result)
            assert data["status"] == "exists"
            assert data["id"] == "policy-uuid-1"
            mock_post.assert_not_called()
