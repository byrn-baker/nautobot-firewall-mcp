"""Tests for firewall_reconcile_rules tool."""

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


def _make_nautobot_policy(device_name, rules):
    """Helper to build a Nautobot policy response with given rules."""
    return {
        "id": "policy-uuid-1",
        "name": "TEST-POLICY",
        "assigned_devices": [{"name": device_name}],
        "policy_rules": rules,
    }


def _make_nautobot_rule(name, action, source_ip=None, dest_ip=None, dest_prefix=None, svc_port=None, svc_proto=None):
    """Helper to build a Nautobot policy rule with addresses and services."""
    src_addrs = []
    if source_ip:
        src_addrs = [{"name": "src", "ip_address": {"address": source_ip}, "prefix": None}]

    dst_addrs = []
    if dest_ip:
        dst_addrs = [{"name": "dst", "ip_address": {"address": dest_ip}, "prefix": None}]
    elif dest_prefix:
        dst_addrs = [{"name": "dst", "ip_address": None, "prefix": {"prefix": dest_prefix}}]

    dst_svcs = []
    if svc_port or svc_proto:
        dst_svcs = [{"name": "svc", "ip_protocol": svc_proto or "", "port": svc_port or ""}]

    return {
        "name": name,
        "action": action,
        "source_addresses": src_addrs,
        "destination_addresses": dst_addrs,
        "destination_services": dst_svcs,
    }


@pytest.mark.asyncio
async def test_reconcile_in_sync(mock_client):
    """Returns in_sync=True when Nautobot rules match live rules exactly."""
    nb_rules = [
        _make_nautobot_rule("allow-https", "permit", source_ip="192.168.1.0/24", dest_ip=None, dest_prefix=None, svc_port="443", svc_proto="tcp"),
    ]
    # For destination "any", Nautobot has no destination address objects
    nb_rules[0]["destination_addresses"] = []

    mock_client.graphql.return_value = {
        "policies": [_make_nautobot_policy("fw01", nb_rules)]
    }

    live_rules = json.dumps([
        {
            "id": 0,
            "type": "pass",
            "interface": "lan",
            "protocol": "tcp",
            "source": "192.168.1.0/24",
            "destination": "any",
            "destination_port": "443",
            "description": "Allow HTTPS",
        }
    ])

    from server import firewall_reconcile_rules

    result = await firewall_reconcile_rules(device="fw01", live_rules=live_rules)
    data = json.loads(result)

    assert data["device"] == "fw01"
    assert data["in_sync"] is True
    assert data["nautobot_rule_count"] == 1
    assert data["live_rule_count"] == 1
    assert data["drift"]["in_nautobot_not_live"] == []
    assert data["drift"]["in_live_not_nautobot"] == []
    assert data["drift"]["action_mismatch"] == []


@pytest.mark.asyncio
async def test_reconcile_in_nautobot_not_live(mock_client):
    """Detects rules present in Nautobot but missing from live firewall."""
    nb_rules = [
        _make_nautobot_rule("allow-https", "permit", source_ip="192.168.1.0/24", svc_port="443", svc_proto="tcp"),
        _make_nautobot_rule("allow-ssh", "permit", source_ip="10.0.0.0/8", svc_port="22", svc_proto="tcp"),
    ]
    nb_rules[0]["destination_addresses"] = []
    nb_rules[1]["destination_addresses"] = []

    mock_client.graphql.return_value = {
        "policies": [_make_nautobot_policy("fw01", nb_rules)]
    }

    # Live only has the HTTPS rule
    live_rules = json.dumps([
        {
            "id": 0,
            "type": "pass",
            "protocol": "tcp",
            "source": "192.168.1.0/24",
            "destination": "any",
            "destination_port": "443",
        }
    ])

    from server import firewall_reconcile_rules

    result = await firewall_reconcile_rules(device="fw01", live_rules=live_rules)
    data = json.loads(result)

    assert data["in_sync"] is False
    assert len(data["drift"]["in_nautobot_not_live"]) == 1
    assert data["drift"]["in_nautobot_not_live"][0]["source"] == "10.0.0.0/8"
    assert data["drift"]["in_nautobot_not_live"][0]["destination_port"] == "22"
    assert len(data["drift"]["in_live_not_nautobot"]) == 0


@pytest.mark.asyncio
async def test_reconcile_in_live_not_nautobot(mock_client):
    """Detects rules present on live firewall but missing from Nautobot."""
    nb_rules = [
        _make_nautobot_rule("allow-https", "permit", source_ip="192.168.1.0/24", svc_port="443", svc_proto="tcp"),
    ]
    nb_rules[0]["destination_addresses"] = []

    mock_client.graphql.return_value = {
        "policies": [_make_nautobot_policy("fw01", nb_rules)]
    }

    # Live has HTTPS + an extra undocumented rule
    live_rules = json.dumps([
        {
            "id": 0,
            "type": "pass",
            "protocol": "tcp",
            "source": "192.168.1.0/24",
            "destination": "any",
            "destination_port": "443",
        },
        {
            "id": 1,
            "type": "pass",
            "protocol": "udp",
            "source": "any",
            "destination": "8.8.8.8",
            "destination_port": "53",
            "description": "Undocumented DNS rule",
        },
    ])

    from server import firewall_reconcile_rules

    result = await firewall_reconcile_rules(device="fw01", live_rules=live_rules)
    data = json.loads(result)

    assert data["in_sync"] is False
    assert len(data["drift"]["in_live_not_nautobot"]) == 1
    assert data["drift"]["in_live_not_nautobot"][0]["destination"] == "8.8.8.8"
    assert data["drift"]["in_live_not_nautobot"][0]["protocol"] == "udp"
    assert data["drift"]["in_live_not_nautobot"][0]["destination_port"] == "53"


@pytest.mark.asyncio
async def test_reconcile_action_mismatch(mock_client):
    """Detects rules that exist in both but have different actions."""
    nb_rules = [
        _make_nautobot_rule("block-ssh", "deny", source_ip="any", svc_port="22", svc_proto="tcp"),
    ]
    nb_rules[0]["source_addresses"] = []  # "any" source
    nb_rules[0]["destination_addresses"] = []  # "any" destination

    mock_client.graphql.return_value = {
        "policies": [_make_nautobot_policy("fw01", nb_rules)]
    }

    # Live has same rule but with action "pass" instead of "block"
    live_rules = json.dumps([
        {
            "id": 0,
            "type": "pass",
            "protocol": "tcp",
            "source": "any",
            "destination": "any",
            "destination_port": "22",
        }
    ])

    from server import firewall_reconcile_rules

    result = await firewall_reconcile_rules(device="fw01", live_rules=live_rules)
    data = json.loads(result)

    assert data["in_sync"] is False
    assert len(data["drift"]["action_mismatch"]) == 1
    mismatch = data["drift"]["action_mismatch"][0]
    assert mismatch["nautobot_action"] == "block"
    assert mismatch["live_action"] == "pass"
    assert mismatch["destination_port"] == "22"
    assert mismatch["protocol"] == "tcp"


@pytest.mark.asyncio
async def test_reconcile_invalid_json(mock_client):
    """Returns error when live_rules is not valid JSON."""
    from server import firewall_reconcile_rules

    result = await firewall_reconcile_rules(device="fw01", live_rules="not valid json {{{")
    data = json.loads(result)

    assert "error" in data
    assert "Invalid JSON" in data["error"]


@pytest.mark.asyncio
async def test_reconcile_live_rules_not_array(mock_client):
    """Returns error when live_rules parses but is not an array."""
    from server import firewall_reconcile_rules

    result = await firewall_reconcile_rules(device="fw01", live_rules='{"key": "value"}')
    data = json.loads(result)

    assert "error" in data
    assert "must be a JSON array" in data["error"]


@pytest.mark.asyncio
async def test_reconcile_nautobot_error(mock_client):
    """Returns error JSON on NautobotError from GraphQL query."""
    mock_client.graphql.side_effect = NautobotError("Nautobot unreachable: timeout")

    from server import firewall_reconcile_rules

    live_rules = json.dumps([{"type": "pass", "source": "any", "destination": "any"}])
    result = await firewall_reconcile_rules(device="fw01", live_rules=live_rules)
    data = json.loads(result)

    assert "error" in data
    assert "Nautobot unreachable" in data["error"]


@pytest.mark.asyncio
async def test_reconcile_no_policies_for_device(mock_client):
    """Returns in_sync=False when device has no policies but live rules exist."""
    mock_client.graphql.return_value = {
        "policies": [
            {
                "id": "p1",
                "name": "OTHER-POLICY",
                "assigned_devices": [{"name": "other-fw"}],
                "policy_rules": [
                    _make_nautobot_rule("rule1", "permit", source_ip="10.0.0.1/32", svc_port="80", svc_proto="tcp")
                ],
            }
        ]
    }

    live_rules = json.dumps([
        {
            "id": 0,
            "type": "pass",
            "protocol": "tcp",
            "source": "192.168.1.0/24",
            "destination": "any",
            "destination_port": "443",
        }
    ])

    from server import firewall_reconcile_rules

    result = await firewall_reconcile_rules(device="fw01", live_rules=live_rules)
    data = json.loads(result)

    assert data["in_sync"] is False
    assert data["nautobot_rule_count"] == 0
    assert data["live_rule_count"] == 1
    assert len(data["drift"]["in_live_not_nautobot"]) == 1


@pytest.mark.asyncio
async def test_reconcile_empty_both_sides(mock_client):
    """Returns in_sync=True when both Nautobot and live have no rules."""
    mock_client.graphql.return_value = {
        "policies": [_make_nautobot_policy("fw01", [])]
    }

    live_rules = json.dumps([])

    from server import firewall_reconcile_rules

    result = await firewall_reconcile_rules(device="fw01", live_rules=live_rules)
    data = json.loads(result)

    assert data["in_sync"] is True
    assert data["nautobot_rule_count"] == 0
    assert data["live_rule_count"] == 0


@pytest.mark.asyncio
async def test_reconcile_prefix_based_address(mock_client):
    """Handles Nautobot rules with prefix-based addresses (network objects)."""
    nb_rule = {
        "name": "allow-internal",
        "action": "permit",
        "source_addresses": [{"name": "internal-net", "ip_address": None, "prefix": {"prefix": "10.0.0.0/8"}}],
        "destination_addresses": [{"name": "dmz-net", "ip_address": None, "prefix": {"prefix": "172.16.0.0/12"}}],
        "destination_services": [{"name": "HTTP", "ip_protocol": "tcp", "port": "80"}],
    }

    mock_client.graphql.return_value = {
        "policies": [_make_nautobot_policy("fw01", [nb_rule])]
    }

    live_rules = json.dumps([
        {
            "id": 0,
            "type": "pass",
            "protocol": "tcp",
            "source": "10.0.0.0/8",
            "destination": "172.16.0.0/12",
            "destination_port": "80",
        }
    ])

    from server import firewall_reconcile_rules

    result = await firewall_reconcile_rules(device="fw01", live_rules=live_rules)
    data = json.loads(result)

    assert data["in_sync"] is True


@pytest.mark.asyncio
async def test_reconcile_missing_optional_fields_in_live(mock_client):
    """Handles live rules with missing optional fields gracefully."""
    mock_client.graphql.return_value = {
        "policies": [_make_nautobot_policy("fw01", [])]
    }

    # Live rule missing protocol, destination_port, etc.
    live_rules = json.dumps([
        {
            "id": 0,
            "type": "block",
            "source": "10.0.0.5",
            "destination": "any",
        }
    ])

    from server import firewall_reconcile_rules

    result = await firewall_reconcile_rules(device="fw01", live_rules=live_rules)
    data = json.loads(result)

    assert data["in_sync"] is False
    assert data["live_rule_count"] == 1
    assert len(data["drift"]["in_live_not_nautobot"]) == 1
    extra_rule = data["drift"]["in_live_not_nautobot"][0]
    assert extra_rule["source"] == "10.0.0.5"
    assert extra_rule["protocol"] == ""
    assert extra_rule["destination_port"] == ""
