"""Tests for firewall_get_policy_rules tool."""

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
async def test_get_policy_rules_returns_sorted_rules(mock_client):
    """Returns policy rules sorted by index ascending."""
    # First call: find_policy resolves the policy UUID
    # Second call: query policy_rules with full detail
    mock_client.graphql.side_effect = [
        {
            "policies": [
                {
                    "id": "policy-uuid-1",
                    "name": "WAN-Policy",
                    "assigned_devices": [{"name": "fw01"}],
                }
            ]
        },
        {
            "policy_rules": [
                {
                    "id": "rule-3",
                    "name": "deny-all",
                    "index": 3,
                    "action": "deny",
                    "log": True,
                    "status": {"name": "Active"},
                    "description": "Default deny",
                    "source_zone": {"name": "untrust"},
                    "destination_zone": {"name": "trust"},
                    "source_addresses": [],
                    "source_address_groups": [],
                    "destination_addresses": [],
                    "destination_address_groups": [],
                    "source_services": [],
                    "source_service_groups": [],
                    "destination_services": [],
                    "destination_service_groups": [],
                },
                {
                    "id": "rule-1",
                    "name": "allow-http",
                    "index": 1,
                    "action": "permit",
                    "log": False,
                    "status": {"name": "Active"},
                    "description": "Allow HTTP",
                    "source_zone": {"name": "trust"},
                    "destination_zone": {"name": "untrust"},
                    "source_addresses": [{"name": "LAN-Net"}],
                    "source_address_groups": [],
                    "destination_addresses": [{"name": "Web-Servers"}],
                    "destination_address_groups": [],
                    "source_services": [],
                    "source_service_groups": [],
                    "destination_services": [{"name": "HTTP"}],
                    "destination_service_groups": [],
                },
                {
                    "id": "rule-2",
                    "name": "allow-https",
                    "index": 2,
                    "action": "permit",
                    "log": False,
                    "status": {"name": "Active"},
                    "description": "Allow HTTPS",
                    "source_zone": {"name": "trust"},
                    "destination_zone": {"name": "untrust"},
                    "source_addresses": [{"name": "LAN-Net"}],
                    "source_address_groups": [],
                    "destination_addresses": [{"name": "Web-Servers"}],
                    "destination_address_groups": [],
                    "source_services": [],
                    "source_service_groups": [],
                    "destination_services": [{"name": "HTTPS"}],
                    "destination_service_groups": [],
                },
            ]
        },
    ]

    from server import firewall_get_policy_rules

    result = await firewall_get_policy_rules(policy_name="WAN-Policy")
    rules = json.loads(result)

    assert len(rules) == 3
    # Verify sorted by index ascending
    assert rules[0]["index"] == 1
    assert rules[0]["name"] == "allow-http"
    assert rules[1]["index"] == 2
    assert rules[1]["name"] == "allow-https"
    assert rules[2]["index"] == 3
    assert rules[2]["name"] == "deny-all"
    # Verify full detail is present
    assert rules[0]["source_zone"] == {"name": "trust"}
    assert rules[0]["destination_services"] == [{"name": "HTTP"}]


@pytest.mark.asyncio
async def test_get_policy_rules_policy_not_found(mock_client):
    """Returns error when policy name doesn't match any policy."""
    mock_client.graphql.return_value = {"policies": []}

    from server import firewall_get_policy_rules

    result = await firewall_get_policy_rules(policy_name="Nonexistent-Policy")
    data = json.loads(result)

    assert "error" in data
    assert "Nonexistent-Policy" in data["error"]
    assert "not found" in data["error"]


@pytest.mark.asyncio
async def test_get_policy_rules_with_device_filter(mock_client):
    """Resolves policy by name and device filter."""
    mock_client.graphql.side_effect = [
        {
            "policies": [
                {
                    "id": "policy-uuid-1",
                    "name": "WAN-Policy",
                    "assigned_devices": [{"name": "fw01"}],
                },
                {
                    "id": "policy-uuid-2",
                    "name": "WAN-Policy",
                    "assigned_devices": [{"name": "fw02"}],
                },
            ]
        },
        {
            "policy_rules": [
                {
                    "id": "rule-1",
                    "name": "allow-all",
                    "index": 1,
                    "action": "permit",
                    "log": False,
                    "status": {"name": "Active"},
                    "description": "",
                    "source_zone": None,
                    "destination_zone": None,
                    "source_addresses": [],
                    "source_address_groups": [],
                    "destination_addresses": [],
                    "destination_address_groups": [],
                    "source_services": [],
                    "source_service_groups": [],
                    "destination_services": [],
                    "destination_service_groups": [],
                },
            ]
        },
    ]

    from server import firewall_get_policy_rules

    result = await firewall_get_policy_rules(policy_name="WAN-Policy", device="fw02")
    rules = json.loads(result)

    assert len(rules) == 1
    # Verify the second graphql call uses the correct policy UUID (fw02's)
    call_args = mock_client.graphql.call_args_list[1]
    assert "policy-uuid-2" in call_args[0][0]


@pytest.mark.asyncio
async def test_get_policy_rules_device_not_matched(mock_client):
    """Returns error when device doesn't match the policy."""
    mock_client.graphql.return_value = {
        "policies": [
            {
                "id": "policy-uuid-1",
                "name": "WAN-Policy",
                "assigned_devices": [{"name": "fw01"}],
            }
        ]
    }

    from server import firewall_get_policy_rules

    result = await firewall_get_policy_rules(policy_name="WAN-Policy", device="nonexistent")
    data = json.loads(result)

    assert "error" in data
    assert "not found" in data["error"]


@pytest.mark.asyncio
async def test_get_policy_rules_error_handling(mock_client):
    """Returns error JSON on NautobotError."""
    mock_client.graphql.side_effect = NautobotError("Nautobot unreachable: timeout")

    from server import firewall_get_policy_rules

    result = await firewall_get_policy_rules(policy_name="WAN-Policy")
    data = json.loads(result)

    assert "error" in data
    assert "Nautobot unreachable" in data["error"]


@pytest.mark.asyncio
async def test_get_policy_rules_empty_policy(mock_client):
    """Returns empty list for a policy with no rules."""
    mock_client.graphql.side_effect = [
        {
            "policies": [
                {
                    "id": "policy-uuid-empty",
                    "name": "Empty-Policy",
                    "assigned_devices": [],
                }
            ]
        },
        {"policy_rules": []},
    ]

    from server import firewall_get_policy_rules

    result = await firewall_get_policy_rules(policy_name="Empty-Policy")
    rules = json.loads(result)

    assert rules == []
