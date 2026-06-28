"""Unit tests for firewall_get_service_objects tool."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import pytest

# We need to set environment variables before importing server
import os

os.environ.setdefault("NAUTOBOT_URL", "https://nautobot.test")
os.environ.setdefault("NAUTOBOT_TOKEN", "test-token")


@pytest.fixture
def sample_service_objects():
    return [
        {
            "id": "uuid-1",
            "name": "HTTPS",
            "ip_protocol": "TCP",
            "port": "443",
            "status": {"name": "Active"},
            "description": "HTTPS traffic",
        },
        {
            "id": "uuid-2",
            "name": "DNS",
            "ip_protocol": "UDP",
            "port": "53",
            "status": {"name": "Active"},
            "description": "DNS queries",
        },
        {
            "id": "uuid-3",
            "name": "ICMP-ALL",
            "ip_protocol": "ICMP",
            "port": None,
            "status": {"name": "Active"},
            "description": "All ICMP",
        },
        {
            "id": "uuid-4",
            "name": "HighPorts",
            "ip_protocol": "TCP",
            "port": "1024-65535",
            "status": {"name": "Active"},
            "description": "High port range",
        },
    ]


@pytest.mark.asyncio
async def test_get_service_objects_no_filter(sample_service_objects):
    """Returns all service objects when no search_term is provided."""
    with patch("server.client") as mock_client:
        mock_client.graphql = AsyncMock(
            return_value={"service_objects": sample_service_objects}
        )

        from server import firewall_get_service_objects

        result = await firewall_get_service_objects()
        objects = json.loads(result)

        assert len(objects) == 4
        assert objects[0]["name"] == "HTTPS"
        assert objects[2]["port"] is None


@pytest.mark.asyncio
async def test_get_service_objects_filter_by_name(sample_service_objects):
    """Filters by name substring match (case-insensitive)."""
    with patch("server.client") as mock_client:
        mock_client.graphql = AsyncMock(
            return_value={"service_objects": sample_service_objects}
        )

        from server import firewall_get_service_objects

        result = await firewall_get_service_objects(search_term="dns")
        objects = json.loads(result)

        assert len(objects) == 1
        assert objects[0]["name"] == "DNS"


@pytest.mark.asyncio
async def test_get_service_objects_filter_by_protocol(sample_service_objects):
    """Filters by protocol match (case-insensitive)."""
    with patch("server.client") as mock_client:
        mock_client.graphql = AsyncMock(
            return_value={"service_objects": sample_service_objects}
        )

        from server import firewall_get_service_objects

        result = await firewall_get_service_objects(search_term="tcp")
        objects = json.loads(result)

        assert len(objects) == 2
        names = [o["name"] for o in objects]
        assert "HTTPS" in names
        assert "HighPorts" in names


@pytest.mark.asyncio
async def test_get_service_objects_filter_by_port(sample_service_objects):
    """Filters by port match (case-insensitive)."""
    with patch("server.client") as mock_client:
        mock_client.graphql = AsyncMock(
            return_value={"service_objects": sample_service_objects}
        )

        from server import firewall_get_service_objects

        result = await firewall_get_service_objects(search_term="443")
        objects = json.loads(result)

        assert len(objects) == 1
        assert objects[0]["name"] == "HTTPS"


@pytest.mark.asyncio
async def test_get_service_objects_filter_no_match(sample_service_objects):
    """Returns empty list when search_term matches nothing."""
    with patch("server.client") as mock_client:
        mock_client.graphql = AsyncMock(
            return_value={"service_objects": sample_service_objects}
        )

        from server import firewall_get_service_objects

        result = await firewall_get_service_objects(search_term="nonexistent")
        objects = json.loads(result)

        assert objects == []


@pytest.mark.asyncio
async def test_get_service_objects_handles_nautobot_error():
    """Returns JSON error object on NautobotError."""
    from nautobot_client import NautobotError

    with patch("server.client") as mock_client:
        mock_client.graphql = AsyncMock(
            side_effect=NautobotError("Nautobot unreachable: connection refused")
        )

        from server import firewall_get_service_objects

        result = await firewall_get_service_objects()
        parsed = json.loads(result)

        assert "error" in parsed
        assert "Nautobot unreachable" in parsed["error"]


@pytest.mark.asyncio
async def test_get_service_objects_filter_handles_none_port(sample_service_objects):
    """Filter handles None port values without crashing."""
    with patch("server.client") as mock_client:
        mock_client.graphql = AsyncMock(
            return_value={"service_objects": sample_service_objects}
        )

        from server import firewall_get_service_objects

        # This should not raise even though ICMP-ALL has port=None
        result = await firewall_get_service_objects(search_term="icmp")
        objects = json.loads(result)

        assert len(objects) == 1
        assert objects[0]["name"] == "ICMP-ALL"
