"""Tests for firewall_get_policies tool."""

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
async def test_get_policies_returns_all(mock_client):
    """Returns all policies when no device filter is provided."""
    mock_client.graphql.return_value = {
        "policies": [
            {
                "id": "uuid-1",
                "name": "WAN-Policy",
                "status": {"name": "Active"},
                "description": "WAN policy",
                "assigned_devices": [{"name": "fw01"}],
                "policy_rules": [
                    {"id": "r1", "name": "allow-http", "index": 1, "action": "permit"},
                    {"id": "r2", "name": "deny-all", "index": 2, "action": "deny"},
                ],
            },
            {
                "id": "uuid-2",
                "name": "LAN-Policy",
                "status": {"name": "Active"},
                "description": "LAN policy",
                "assigned_devices": [{"name": "fw02"}],
                "policy_rules": [],
            },
        ]
    }

    from server import firewall_get_policies

    result = await firewall_get_policies()
    policies = json.loads(result)

    assert len(policies) == 2
    assert policies[0]["name"] == "WAN-Policy"
    assert policies[0]["rule_count"] == 2
    assert policies[1]["name"] == "LAN-Policy"
    assert policies[1]["rule_count"] == 0


@pytest.mark.asyncio
async def test_get_policies_filters_by_device(mock_client):
    """Filters policies by assigned device name."""
    mock_client.graphql.return_value = {
        "policies": [
            {
                "id": "uuid-1",
                "name": "WAN-Policy",
                "status": {"name": "Active"},
                "description": "",
                "assigned_devices": [{"name": "fw01"}],
                "policy_rules": [{"id": "r1", "name": "rule1", "index": 1, "action": "permit"}],
            },
            {
                "id": "uuid-2",
                "name": "LAN-Policy",
                "status": {"name": "Active"},
                "description": "",
                "assigned_devices": [{"name": "fw02"}],
                "policy_rules": [{"id": "r2", "name": "rule2", "index": 1, "action": "deny"}],
            },
        ]
    }

    from server import firewall_get_policies

    result = await firewall_get_policies(device="fw01")
    policies = json.loads(result)

    assert len(policies) == 1
    assert policies[0]["name"] == "WAN-Policy"
    assert policies[0]["rule_count"] == 1


@pytest.mark.asyncio
async def test_get_policies_device_not_found(mock_client):
    """Returns empty list when device matches no policies."""
    mock_client.graphql.return_value = {
        "policies": [
            {
                "id": "uuid-1",
                "name": "WAN-Policy",
                "status": {"name": "Active"},
                "description": "",
                "assigned_devices": [{"name": "fw01"}],
                "policy_rules": [],
            },
        ]
    }

    from server import firewall_get_policies

    result = await firewall_get_policies(device="nonexistent")
    policies = json.loads(result)

    assert len(policies) == 0


@pytest.mark.asyncio
async def test_get_policies_error_handling(mock_client):
    """Returns error JSON on NautobotError."""
    mock_client.graphql.side_effect = NautobotError("Nautobot unreachable: connection refused")

    from server import firewall_get_policies

    result = await firewall_get_policies()
    data = json.loads(result)

    assert "error" in data
    assert "Nautobot unreachable" in data["error"]
