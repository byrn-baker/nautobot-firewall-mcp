"""Unit tests for firewall_delete_policy_rule tool."""

from __future__ import annotations

import json
import os
from unittest.mock import AsyncMock, patch, call

import pytest

os.environ.setdefault("NAUTOBOT_URL", "https://nautobot.test")
os.environ.setdefault("NAUTOBOT_TOKEN", "test-token")


@pytest.mark.asyncio
async def test_delete_policy_rule_success():
    """Deletes rule and re-indexes remaining rules that had higher index."""
    policies_graphql = {"policies": [{"id": "pol-uuid-1", "name": "OUTSIDE-IN", "assigned_devices": []}]}
    rule_graphql = {
        "policy_rules": [
            {"id": "rule-1", "name": "allow-http", "index": 1},
            {"id": "rule-2", "name": "allow-https", "index": 2},
            {"id": "rule-3", "name": "deny-all", "index": 3},
        ]
    }
    # After deletion of rule-2 (index 2), remaining rules:
    remaining_graphql = {
        "policy_rules": [
            {"id": "rule-1", "name": "allow-http", "index": 1},
            {"id": "rule-3", "name": "deny-all", "index": 3},
        ]
    }

    call_count = {"graphql": 0}

    async def mock_graphql(query):
        call_count["graphql"] += 1
        if "policies" in query:
            return policies_graphql
        if "policy_rules" in query:
            # First call finds the rule; second call gets remaining after delete
            if call_count["graphql"] <= 2:
                return rule_graphql
            return remaining_graphql
        return {}

    with patch("server.client.graphql", new_callable=AsyncMock, side_effect=mock_graphql):
        with patch("server.client.rest_delete", new_callable=AsyncMock) as mock_delete:
            with patch("server.client.rest_patch", new_callable=AsyncMock) as mock_patch:
                from server import firewall_delete_policy_rule

                result = await firewall_delete_policy_rule(
                    policy="OUTSIDE-IN", rule_name="allow-https"
                )
                data = json.loads(result)

                assert data["status"] == "deleted"
                assert data["rule_name"] == "allow-https"
                assert data["policy"] == "OUTSIDE-IN"

                # Verify DELETE was called for the rule
                mock_delete.assert_called_once_with("plugins/firewall/policy-rules/rule-2")

                # Verify PATCH was called to decrement index of rule-3 (index 3 -> 2)
                mock_patch.assert_called_once_with(
                    "plugins/firewall/policy-rules/rule-3",
                    {"index": 2},
                )


@pytest.mark.asyncio
async def test_delete_policy_rule_no_reindex_needed():
    """Deletes the last rule — no re-indexing needed."""
    policies_graphql = {"policies": [{"id": "pol-uuid-1", "name": "MY-POLICY", "assigned_devices": []}]}
    rule_graphql = {
        "policy_rules": [
            {"id": "rule-1", "name": "allow-http", "index": 1},
            {"id": "rule-2", "name": "deny-all", "index": 2},
        ]
    }
    remaining_graphql = {
        "policy_rules": [
            {"id": "rule-1", "name": "allow-http", "index": 1},
        ]
    }

    call_count = {"graphql": 0}

    async def mock_graphql(query):
        call_count["graphql"] += 1
        if "policies" in query:
            return policies_graphql
        if "policy_rules" in query:
            if call_count["graphql"] <= 2:
                return rule_graphql
            return remaining_graphql
        return {}

    with patch("server.client.graphql", new_callable=AsyncMock, side_effect=mock_graphql):
        with patch("server.client.rest_delete", new_callable=AsyncMock) as mock_delete:
            with patch("server.client.rest_patch", new_callable=AsyncMock) as mock_patch:
                from server import firewall_delete_policy_rule

                result = await firewall_delete_policy_rule(
                    policy="MY-POLICY", rule_name="deny-all"
                )
                data = json.loads(result)

                assert data["status"] == "deleted"
                assert data["rule_name"] == "deny-all"
                mock_delete.assert_called_once()
                # No re-indexing needed since rule was at the end
                mock_patch.assert_not_called()


@pytest.mark.asyncio
async def test_delete_policy_rule_policy_not_found():
    """Returns error when policy does not exist."""
    policies_graphql = {"policies": []}

    with patch("server.client.graphql", new_callable=AsyncMock, return_value=policies_graphql):
        from server import firewall_delete_policy_rule

        result = await firewall_delete_policy_rule(
            policy="NONEXISTENT", rule_name="allow-http"
        )
        data = json.loads(result)
        assert "error" in data
        assert "Policy 'NONEXISTENT' not found" in data["error"]


@pytest.mark.asyncio
async def test_delete_policy_rule_rule_not_found():
    """Returns error when rule does not exist in the policy."""
    policies_graphql = {"policies": [{"id": "pol-uuid-1", "name": "OUTSIDE-IN", "assigned_devices": []}]}
    rule_graphql = {
        "policy_rules": [
            {"id": "rule-1", "name": "allow-http", "index": 1},
        ]
    }

    async def mock_graphql(query):
        if "policies" in query:
            return policies_graphql
        if "policy_rules" in query:
            return rule_graphql
        return {}

    with patch("server.client.graphql", new_callable=AsyncMock, side_effect=mock_graphql):
        from server import firewall_delete_policy_rule

        result = await firewall_delete_policy_rule(
            policy="OUTSIDE-IN", rule_name="nonexistent-rule"
        )
        data = json.loads(result)
        assert "error" in data
        assert "Rule 'nonexistent-rule' not found" in data["error"]


@pytest.mark.asyncio
async def test_delete_policy_rule_itsm_blocked():
    """When ITSM is enabled and no cr_number provided, returns ITSM error."""
    with patch("server.ITSM_ENABLED", True), \
         patch("server.ITSM_LAB_MODE", False):
        from server import firewall_delete_policy_rule

        result = await firewall_delete_policy_rule(
            policy="OUTSIDE-IN", rule_name="allow-http"
        )
        data = json.loads(result)
        assert "error" in data
        assert "ITSM" in data["error"]


@pytest.mark.asyncio
async def test_delete_policy_rule_itsm_allowed_with_cr():
    """When ITSM is enabled with cr_number, proceeds normally."""
    policies_graphql = {"policies": [{"id": "pol-uuid-1", "name": "OUTSIDE-IN", "assigned_devices": []}]}
    rule_graphql = {
        "policy_rules": [
            {"id": "rule-1", "name": "allow-http", "index": 1},
        ]
    }
    remaining_graphql = {"policy_rules": []}

    call_count = {"graphql": 0}

    async def mock_graphql(query):
        call_count["graphql"] += 1
        if "policies" in query:
            return policies_graphql
        if "policy_rules" in query:
            if call_count["graphql"] <= 2:
                return rule_graphql
            return remaining_graphql
        return {}

    with patch("server.ITSM_ENABLED", True), \
         patch("server.ITSM_LAB_MODE", False):
        with patch("server.client.graphql", new_callable=AsyncMock, side_effect=mock_graphql):
            with patch("server.client.rest_delete", new_callable=AsyncMock):
                with patch("server.client.rest_patch", new_callable=AsyncMock):
                    from server import firewall_delete_policy_rule

                    result = await firewall_delete_policy_rule(
                        policy="OUTSIDE-IN",
                        rule_name="allow-http",
                        cr_number="CR-12345",
                    )
                    data = json.loads(result)
                    assert data["status"] == "deleted"


@pytest.mark.asyncio
async def test_delete_policy_rule_nautobot_error():
    """When NautobotError is raised, returns structured error."""
    from nautobot_client import NautobotError

    with patch(
        "server.client.graphql",
        new_callable=AsyncMock,
        side_effect=NautobotError("Nautobot unreachable: timeout"),
    ):
        from server import firewall_delete_policy_rule

        result = await firewall_delete_policy_rule(
            policy="OUTSIDE-IN", rule_name="allow-http"
        )
        data = json.loads(result)
        assert "error" in data
        assert "Nautobot unreachable" in data["error"]


@pytest.mark.asyncio
async def test_delete_policy_rule_multiple_reindex():
    """Deleting first rule re-indexes all subsequent rules."""
    policies_graphql = {"policies": [{"id": "pol-uuid-1", "name": "MY-POLICY", "assigned_devices": []}]}
    rule_graphql = {
        "policy_rules": [
            {"id": "rule-1", "name": "first-rule", "index": 1},
            {"id": "rule-2", "name": "second-rule", "index": 2},
            {"id": "rule-3", "name": "third-rule", "index": 3},
        ]
    }
    remaining_graphql = {
        "policy_rules": [
            {"id": "rule-2", "name": "second-rule", "index": 2},
            {"id": "rule-3", "name": "third-rule", "index": 3},
        ]
    }

    call_count = {"graphql": 0}

    async def mock_graphql(query):
        call_count["graphql"] += 1
        if "policies" in query:
            return policies_graphql
        if "policy_rules" in query:
            if call_count["graphql"] <= 2:
                return rule_graphql
            return remaining_graphql
        return {}

    with patch("server.client.graphql", new_callable=AsyncMock, side_effect=mock_graphql):
        with patch("server.client.rest_delete", new_callable=AsyncMock) as mock_delete:
            with patch("server.client.rest_patch", new_callable=AsyncMock) as mock_patch:
                from server import firewall_delete_policy_rule

                result = await firewall_delete_policy_rule(
                    policy="MY-POLICY", rule_name="first-rule"
                )
                data = json.loads(result)

                assert data["status"] == "deleted"
                assert data["rule_name"] == "first-rule"

                mock_delete.assert_called_once_with("plugins/firewall/policy-rules/rule-1")

                # Both remaining rules should be decremented
                assert mock_patch.call_count == 2
                mock_patch.assert_any_call(
                    "plugins/firewall/policy-rules/rule-2",
                    {"index": 1},
                )
                mock_patch.assert_any_call(
                    "plugins/firewall/policy-rules/rule-3",
                    {"index": 2},
                )
