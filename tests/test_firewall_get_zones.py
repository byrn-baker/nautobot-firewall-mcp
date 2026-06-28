"""Unit tests for firewall_get_zones tool."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import pytest


@pytest.fixture(autouse=True)
def set_env(monkeypatch):
    """Set required env vars so server.py doesn't exit."""
    monkeypatch.setenv("NAUTOBOT_URL", "http://test")
    monkeypatch.setenv("NAUTOBOT_TOKEN", "test-token")


@pytest.mark.asyncio
async def test_get_zones_returns_all_zones():
    """When no device filter, returns all zones."""
    mock_data = {
        "zones": [
            {
                "id": "uuid-1",
                "name": "trust",
                "status": {"name": "Active"},
                "description": "Internal zone",
                "interfaces": [{"name": "eth0", "device": {"name": "fw01"}}],
                "vrfs": [{"name": "default"}],
            },
            {
                "id": "uuid-2",
                "name": "untrust",
                "status": {"name": "Active"},
                "description": "External zone",
                "interfaces": [{"name": "eth1", "device": {"name": "fw02"}}],
                "vrfs": [],
            },
        ]
    }

    with patch("server.client.graphql", new_callable=AsyncMock, return_value=mock_data):
        import server

        result = await server.firewall_get_zones()
        zones = json.loads(result)
        assert len(zones) == 2
        assert zones[0]["name"] == "trust"
        assert zones[1]["name"] == "untrust"


@pytest.mark.asyncio
async def test_get_zones_filters_by_device():
    """When device filter provided, returns only zones with matching interfaces."""
    mock_data = {
        "zones": [
            {
                "id": "uuid-1",
                "name": "trust",
                "status": {"name": "Active"},
                "description": "Internal zone",
                "interfaces": [{"name": "eth0", "device": {"name": "fw01"}}],
                "vrfs": [{"name": "default"}],
            },
            {
                "id": "uuid-2",
                "name": "untrust",
                "status": {"name": "Active"},
                "description": "External zone",
                "interfaces": [{"name": "eth1", "device": {"name": "fw02"}}],
                "vrfs": [],
            },
        ]
    }

    with patch("server.client.graphql", new_callable=AsyncMock, return_value=mock_data):
        import server

        result = await server.firewall_get_zones(device="fw01")
        zones = json.loads(result)
        assert len(zones) == 1
        assert zones[0]["name"] == "trust"


@pytest.mark.asyncio
async def test_get_zones_device_filter_no_match():
    """When device filter matches no zones, returns empty list."""
    mock_data = {
        "zones": [
            {
                "id": "uuid-1",
                "name": "trust",
                "status": {"name": "Active"},
                "description": "",
                "interfaces": [{"name": "eth0", "device": {"name": "fw01"}}],
                "vrfs": [],
            },
        ]
    }

    with patch("server.client.graphql", new_callable=AsyncMock, return_value=mock_data):
        import server

        result = await server.firewall_get_zones(device="fw99")
        zones = json.loads(result)
        assert len(zones) == 0


@pytest.mark.asyncio
async def test_get_zones_handles_nautobot_error():
    """When NautobotError is raised, returns error JSON."""
    from nautobot_client import NautobotError

    with patch(
        "server.client.graphql",
        new_callable=AsyncMock,
        side_effect=NautobotError("Nautobot unreachable: timeout"),
    ):
        import server

        result = await server.firewall_get_zones()
        data = json.loads(result)
        assert "error" in data
        assert "Nautobot unreachable" in data["error"]


@pytest.mark.asyncio
async def test_get_zones_empty_result():
    """When no zones exist, returns empty list."""
    mock_data = {"zones": []}

    with patch("server.client.graphql", new_callable=AsyncMock, return_value=mock_data):
        import server

        result = await server.firewall_get_zones()
        zones = json.loads(result)
        assert zones == []


@pytest.mark.asyncio
async def test_get_zones_multi_interface_device_filter():
    """Zone with multiple interfaces from different devices — filtered correctly."""
    mock_data = {
        "zones": [
            {
                "id": "uuid-1",
                "name": "dmz",
                "status": {"name": "Active"},
                "description": "DMZ zone",
                "interfaces": [
                    {"name": "eth0", "device": {"name": "fw01"}},
                    {"name": "eth2", "device": {"name": "fw02"}},
                ],
                "vrfs": [],
            },
        ]
    }

    with patch("server.client.graphql", new_callable=AsyncMock, return_value=mock_data):
        import server

        # fw01 is in the interface list, so zone should be included
        result = await server.firewall_get_zones(device="fw01")
        zones = json.loads(result)
        assert len(zones) == 1
        assert zones[0]["name"] == "dmz"

        # fw03 is NOT in the interface list
        result = await server.firewall_get_zones(device="fw03")
        zones = json.loads(result)
        assert len(zones) == 0
