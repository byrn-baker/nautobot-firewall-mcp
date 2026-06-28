"""Tests for firewall_get_address_objects tool."""

from __future__ import annotations

import json
import sys
import os
from unittest.mock import AsyncMock, patch

import pytest

# Set required env vars before importing server
os.environ.setdefault("NAUTOBOT_URL", "https://nautobot.test")
os.environ.setdefault("NAUTOBOT_TOKEN", "test-token")

sys.path.insert(0, os.path.dirname(__file__))

from nautobot_client import NautobotError


@pytest.fixture
def mock_client():
    with patch("server.client") as mock:
        mock.graphql = AsyncMock()
        yield mock


@pytest.mark.asyncio
async def test_get_address_objects_returns_all(mock_client):
    """Returns all address objects when no search_term is provided."""
    mock_client.graphql.return_value = {
        "address_objects": [
            {
                "id": "uuid-1",
                "name": "web-server",
                "status": {"name": "Active"},
                "description": "Web server IP",
                "ip_address": {"address": "192.168.1.10/32"},
                "prefix": None,
                "ip_range": None,
                "fqdn": None,
            },
            {
                "id": "uuid-2",
                "name": "internal-net",
                "status": {"name": "Active"},
                "description": "Internal network",
                "ip_address": None,
                "prefix": {"prefix": "10.0.0.0/8"},
                "ip_range": None,
                "fqdn": None,
            },
            {
                "id": "uuid-3",
                "name": "dhcp-range",
                "status": {"name": "Active"},
                "description": "DHCP pool",
                "ip_address": None,
                "prefix": None,
                "ip_range": {"start_address": "192.168.1.100", "end_address": "192.168.1.200"},
                "fqdn": None,
            },
        ]
    }

    from server import firewall_get_address_objects

    result = await firewall_get_address_objects()
    objects = json.loads(result)

    assert len(objects) == 3
    assert objects[0]["name"] == "web-server"
    assert objects[0]["ip_address"]["address"] == "192.168.1.10/32"
    assert objects[1]["prefix"]["prefix"] == "10.0.0.0/8"
    assert objects[2]["ip_range"]["start_address"] == "192.168.1.100"


@pytest.mark.asyncio
async def test_get_address_objects_filters_by_search_term(mock_client):
    """Filters address objects by name substring match (case-insensitive)."""
    mock_client.graphql.return_value = {
        "address_objects": [
            {
                "id": "uuid-1",
                "name": "web-server",
                "status": {"name": "Active"},
                "description": "",
                "ip_address": {"address": "192.168.1.10/32"},
                "prefix": None,
                "ip_range": None,
                "fqdn": None,
            },
            {
                "id": "uuid-2",
                "name": "WEB-proxy",
                "status": {"name": "Active"},
                "description": "",
                "ip_address": {"address": "192.168.1.20/32"},
                "prefix": None,
                "ip_range": None,
                "fqdn": None,
            },
            {
                "id": "uuid-3",
                "name": "db-server",
                "status": {"name": "Active"},
                "description": "",
                "ip_address": {"address": "192.168.1.30/32"},
                "prefix": None,
                "ip_range": None,
                "fqdn": None,
            },
        ]
    }

    from server import firewall_get_address_objects

    result = await firewall_get_address_objects(search_term="web")
    objects = json.loads(result)

    assert len(objects) == 2
    assert objects[0]["name"] == "web-server"
    assert objects[1]["name"] == "WEB-proxy"


@pytest.mark.asyncio
async def test_get_address_objects_search_no_match(mock_client):
    """Returns empty list when search_term matches no objects."""
    mock_client.graphql.return_value = {
        "address_objects": [
            {
                "id": "uuid-1",
                "name": "web-server",
                "status": {"name": "Active"},
                "description": "",
                "ip_address": {"address": "192.168.1.10/32"},
                "prefix": None,
                "ip_range": None,
                "fqdn": None,
            },
        ]
    }

    from server import firewall_get_address_objects

    result = await firewall_get_address_objects(search_term="nonexistent")
    objects = json.loads(result)

    assert len(objects) == 0


@pytest.mark.asyncio
async def test_get_address_objects_error_handling(mock_client):
    """Returns error JSON on NautobotError."""
    mock_client.graphql.side_effect = NautobotError("Nautobot unreachable: connection refused")

    from server import firewall_get_address_objects

    result = await firewall_get_address_objects()
    data = json.loads(result)

    assert "error" in data
    assert "Nautobot unreachable" in data["error"]
