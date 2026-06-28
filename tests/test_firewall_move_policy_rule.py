"""Unit tests for firewall_move_policy_rule tool."""

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
async def test_move_rule_down():
    """Moving a rule to a higher index shifts intermediate rules up."""
    async def mock_graphql(query):
        if "policies(name:" in query:
            return {"policies": [{"id": "policy-uuid", "name": "FW-POLICY", "assigned_devices": []}]}
        if "policy_rules(policy:" in query:
            return {"policy_rules": [
                {"id": "rule-1", "name": "rule-A", "index": 1},
                {"id": "rule-2", "name": "rule-B", "index": 2},
                {"id": "rule-3", "name": "rule-C", "index": 3},
                {"id": "rule-4", "name": "rule-D", "index": 4},
            ]}
        return {}

    with patch("server.client.graphql", new_callable=AsyncMock, side_effect=mock_graphql):
        with patch("server.client.rest_patch", new_callable=AsyncMock) as mock_patch:
            import server

            result = await server.firewall_move_policy_rule(
                policy="FW-POLICY", rule_name="rule-A", new_index=3
            )
            data = json.loads(result)
            assert data["status"] == "moved"
            assert data["rule_name"] == "rule-A"
            assert data["old_index"] == 1
            assert data["new_index"] == 3

            # Rules B (index 2) and C (index 3) should be shifted up (decremented)
            # Plus the target rule itself is patched to new_index
            assert mock_patch.call_count == 3

            patch_calls = mock_patch.call_args_list
            # Affected rules: rule-2 (index 2) and rule-3 (index 3) should be decremented
            affected_calls = patch_calls[:-1]
            affected_endpoints = [(c[0][0], c[0][1]) for c in affected_calls]
            assert ("plugins/firewall/policy-rules/rule-2", {"index": 1}) in affected_endpoints
            assert ("plugins/firewall/policy-rules/rule-3", {"index": 2}) in affected_endpoints

            # Target rule patched to new index
            target_call = patch_calls[-1]
            assert target_call[0] == ("plugins/firewall/policy-rules/rule-1", {"index": 3})


@pytest.mark.asyncio
async def test_move_rule_up():
    """Moving a rule to a lower index shifts intermediate rules down."""
    async def mock_graphql(query):
        if "policies(name:" in query:
            return {"policies": [{"id": "policy-uuid", "name": "FW-POLICY", "assigned_devices": []}]}
        if "policy_rules(policy:" in query:
            return {"policy_rules": [
                {"id": "rule-1", "name": "rule-A", "index": 1},
                {"id": "rule-2", "name": "rule-B", "index": 2},
                {"id": "rule-3", "name": "rule-C", "index": 3},
                {"id": "rule-4", "name": "rule-D", "index": 4},
            ]}
        return {}

    with patch("server.client.graphql", new_callable=AsyncMock, side_effect=mock_graphql):
        with patch("server.client.rest_patch", new_callable=AsyncMock) as mock_patch:
            import server

            result = await server.firewall_move_policy_rule(
                policy="FW-POLICY", rule_name="rule-D", new_index=2
            )
            data = json.loads(result)
            assert data["status"] == "moved"
            assert data["rule_name"] == "rule-D"
            assert data["old_index"] == 4
            assert data["new_index"] == 2

            # Rules B (index 2) and C (index 3) should be shifted down (incremented)
            # Plus the target rule itself is patched to new_index
            assert mock_patch.call_count == 3

            patch_calls = mock_patch.call_args_list
            # Affected rules shifted down (sorted descending to avoid collisions)
            affected_calls = patch_calls[:-1]
            affected_endpoints = [(c[0][0], c[0][1]) for c in affected_calls]
            # rule-3 (index 3 -> 4) before rule-2 (index 2 -> 3) due to descending sort
            assert ("plugins/firewall/policy-rules/rule-3", {"index": 4}) in affected_endpoints
            assert ("plugins/firewall/policy-rules/rule-2", {"index": 3}) in affected_endpoints

            # Target rule patched to new index
            target_call = patch_calls[-1]
            assert target_call[0] == ("plugins/firewall/policy-rules/rule-4", {"index": 2})


@pytest.mark.asyncio
async def test_move_rule_no_op_same_index():
    """Moving a rule to the same index is a no-op — no PATCHes issued."""
    async def mock_graphql(query):
        if "policies(name:" in query:
            return {"policies": [{"id": "policy-uuid", "name": "FW-POLICY", "assigned_devices": []}]}
        if "policy_rules(policy:" in query:
            return {"policy_rules": [
                {"id": "rule-1", "name": "rule-A", "index": 1},
                {"id": "rule-2", "name": "rule-B", "index": 2},
            ]}
        return {}

    with patch("server.client.graphql", new_callable=AsyncMock, side_effect=mock_graphql):
        with patch("server.client.rest_patch", new_callable=AsyncMock) as mock_patch:
            import server

            result = await server.firewall_move_policy_rule(
                policy="FW-POLICY", rule_name="rule-B", new_index=2
            )
            data = json.loads(result)
            assert data["status"] == "moved"
            assert data["old_index"] == 2
            assert data["new_index"] == 2

            # No patches should have been issued
            mock_patch.assert_not_called()


@pytest.mark.asyncio
async def test_move_rule_policy_not_found():
    """Returns error when the policy cannot be resolved."""
    async def mock_graphql(query):
        if "policies(name:" in query:
            return {"policies": []}
        return {}

    with patch("server.client.graphql", new_callable=AsyncMock, side_effect=mock_graphql):
        with patch("server.client.rest_patch", new_callable=AsyncMock) as mock_patch:
            import server

            result = await server.firewall_move_policy_rule(
                policy="NONEXISTENT", rule_name="rule-A", new_index=1
            )
            data = json.loads(result)
            assert "error" in data
            assert "NONEXISTENT" in data["error"]
            assert "not found" in data["error"]
            mock_patch.assert_not_called()


@pytest.mark.asyncio
async def test_move_rule_not_found():
    """Returns error when the rule name is not found in the policy."""
    async def mock_graphql(query):
        if "policies(name:" in query:
            return {"policies": [{"id": "policy-uuid", "name": "FW-POLICY", "assigned_devices": []}]}
        if "policy_rules(policy:" in query:
            return {"policy_rules": [
                {"id": "rule-1", "name": "rule-A", "index": 1},
            ]}
        return {}

    with patch("server.client.graphql", new_callable=AsyncMock, side_effect=mock_graphql):
        with patch("server.client.rest_patch", new_callable=AsyncMock) as mock_patch:
            import server

            result = await server.firewall_move_policy_rule(
                policy="FW-POLICY", rule_name="NONEXISTENT", new_index=1
            )
            data = json.loads(result)
            assert "error" in data
            assert "NONEXISTENT" in data["error"]
            assert "not found" in data["error"]
            mock_patch.assert_not_called()


@pytest.mark.asyncio
async def test_move_rule_itsm_blocked(monkeypatch):
    """When ITSM is enforced and no cr_number, returns error."""
    monkeypatch.setenv("ITSM_ENABLED", "true")
    monkeypatch.setenv("ITSM_LAB_MODE", "false")

    import importlib
    import server

    importlib.reload(server)

    result = await server.firewall_move_policy_rule(
        policy="FW-POLICY", rule_name="rule-A", new_index=2
    )
    data = json.loads(result)
    assert "error" in data
    assert "ITSM" in data["error"]
