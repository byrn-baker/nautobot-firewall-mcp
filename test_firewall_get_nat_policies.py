"""Tests for firewall_get_nat_policies tool."""

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
async def test_get_nat_policies_returns_all(mock_client):
    """Returns all NAT policies when no device filter is provided."""
    mock_client.graphql.return_value = {
        "nat_policies": [
            {
                "id": "nat-uuid-1",
                "name": "NAT-Outbound",
                "status": {"name": "Active"},
                "description": "Outbound NAT policy",
                "assigned_devices": [{"name": "fw01"}],
                "nat_policy_rules": [
                    {"id": "nr1", "name": "snat-lan", "index": 1},
                    {"id": "nr2", "name": "snat-dmz", "index": 2},
                ],
            },
            {
                "id": "nat-uuid-2",
                "name": "NAT-Inbound",
                "status": {"name": "Active"},
                "description": "Inbound NAT policy",
                "assigned_devices": [{"name": "fw02"}],
                "nat_policy_rules": [
                    {"id": "nr3", "name": "dnat-web", "index": 1},
                ],
            },
        ]
    }

    from server import firewall_get_nat_policies

    result = await firewall_get_nat_policies()
    policies = json.loads(result)

    assert len(policies) == 2
    assert policies[0]["name"] == "NAT-Outbound"
    assert len(policies[0]["nat_policy_rules"]) == 2
    assert policies[1]["name"] == "NAT-Inbound"
    assert len(policies[1]["nat_policy_rules"]) == 1


@pytest.mark.asyncio
async def test_get_nat_policies_filters_by_device(mock_client):
    """Filters NAT policies by assigned device name."""
    mock_client.graphql.return_value = {
        "nat_policies": [
            {
                "id": "nat-uuid-1",
                "name": "NAT-Outbound",
                "status": {"name": "Active"},
                "description": "",
                "assigned_devices": [{"name": "fw01"}],
                "nat_policy_rules": [{"id": "nr1", "name": "snat-lan", "index": 1}],
            },
            {
                "id": "nat-uuid-2",
                "name": "NAT-Inbound",
                "status": {"name": "Active"},
                "description": "",
                "assigned_devices": [{"name": "fw02"}],
                "nat_policy_rules": [{"id": "nr2", "name": "dnat-web", "index": 1}],
            },
        ]
    }

    from server import firewall_get_nat_policies

    result = await firewall_get_nat_policies(device="fw02")
    policies = json.loads(result)

    assert len(policies) == 1
    assert policies[0]["name"] == "NAT-Inbound"


@pytest.mark.asyncio
async def test_get_nat_policies_device_not_found(mock_client):
    """Returns empty list when device matches no NAT policies."""
    mock_client.graphql.return_value = {
        "nat_policies": [
            {
                "id": "nat-uuid-1",
                "name": "NAT-Outbound",
                "status": {"name": "Active"},
                "description": "",
                "assigned_devices": [{"name": "fw01"}],
                "nat_policy_rules": [],
            },
        ]
    }

    from server import firewall_get_nat_policies

    result = await firewall_get_nat_policies(device="nonexistent")
    policies = json.loads(result)

    assert len(policies) == 0


@pytest.mark.asyncio
async def test_get_nat_policies_empty_result(mock_client):
    """Returns empty list when no NAT policies exist."""
    mock_client.graphql.return_value = {"nat_policies": []}

    from server import firewall_get_nat_policies

    result = await firewall_get_nat_policies()
    policies = json.loads(result)

    assert policies == []


@pytest.mark.asyncio
async def test_get_nat_policies_multiple_devices_assigned(mock_client):
    """Filters correctly when a policy is assigned to multiple devices."""
    mock_client.graphql.return_value = {
        "nat_policies": [
            {
                "id": "nat-uuid-1",
                "name": "NAT-Shared",
                "status": {"name": "Active"},
                "description": "",
                "assigned_devices": [{"name": "fw01"}, {"name": "fw02"}],
                "nat_policy_rules": [{"id": "nr1", "name": "shared-rule", "index": 1}],
            },
        ]
    }

    from server import firewall_get_nat_policies

    # Both fw01 and fw02 should match
    result = await firewall_get_nat_policies(device="fw01")
    policies = json.loads(result)
    assert len(policies) == 1
    assert policies[0]["name"] == "NAT-Shared"

    result = await firewall_get_nat_policies(device="fw02")
    policies = json.loads(result)
    assert len(policies) == 1
    assert policies[0]["name"] == "NAT-Shared"


@pytest.mark.asyncio
async def test_get_nat_policies_error_handling(mock_client):
    """Returns error JSON on NautobotError."""
    mock_client.graphql.side_effect = NautobotError("Nautobot unreachable: connection refused")

    from server import firewall_get_nat_policies

    result = await firewall_get_nat_policies()
    data = json.loads(result)

    assert "error" in data
    assert "Nautobot unreachable" in data["error"]
