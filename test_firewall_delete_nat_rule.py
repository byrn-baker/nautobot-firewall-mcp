"""Unit tests for firewall_delete_nat_rule tool."""

from __future__ import annotations

import json
import os
from unittest.mock import AsyncMock, patch

import pytest

os.environ.setdefault("NAUTOBOT_URL", "https://nautobot.test")
os.environ.setdefault("NAUTOBOT_TOKEN", "test-token")


@pytest.mark.asyncio
async def test_delete_nat_rule_basic():
    """Deletes a NAT rule and re-indexes remaining rules."""
    with patch("server.client") as mock_client, \
         patch("server.find_nat_policy", new_callable=AsyncMock, return_value="nat-pol-uuid-1"), \
         patch("server.find_nat_policy_rule", new_callable=AsyncMock, return_value={
             "id": "rule-uuid-2", "index": 2, "name": "DELETE-ME"
         }):

        # After deletion, remaining rules at index 3 and 4
        mock_client.graphql = AsyncMock(return_value={
            "nat_policy_rules": [
                {"id": "rule-uuid-1", "index": 1},
                {"id": "rule-uuid-3", "index": 3},
                {"id": "rule-uuid-4", "index": 4},
            ]
        })
        mock_client.rest_delete = AsyncMock()
        mock_client.rest_patch = AsyncMock()

        from server import firewall_delete_nat_rule

        result = await firewall_delete_nat_rule(
            nat_policy="NAT-OUTSIDE",
            rule_name="DELETE-ME",
        )
        parsed = json.loads(result)

        assert parsed["status"] == "deleted"
        assert parsed["rule_name"] == "DELETE-ME"
        assert parsed["nat_policy"] == "NAT-OUTSIDE"

        # Verify DELETE was called with correct endpoint
        mock_client.rest_delete.assert_called_once_with(
            "plugins/firewall/nat-policy-rules/rule-uuid-2"
        )

        # Verify re-indexing: rules at index 3 and 4 should be decremented
        patch_calls = mock_client.rest_patch.call_args_list
        assert len(patch_calls) == 2
        # First patch: rule at index 3 -> 2
        assert patch_calls[0][0] == (
            "plugins/firewall/nat-policy-rules/rule-uuid-3",
            {"index": 2},
        )
        # Second patch: rule at index 4 -> 3
        assert patch_calls[1][0] == (
            "plugins/firewall/nat-policy-rules/rule-uuid-4",
            {"index": 3},
        )


@pytest.mark.asyncio
async def test_delete_nat_rule_last_rule():
    """Deletes the last rule — no re-indexing needed."""
    with patch("server.client") as mock_client, \
         patch("server.find_nat_policy", new_callable=AsyncMock, return_value="nat-pol-uuid-1"), \
         patch("server.find_nat_policy_rule", new_callable=AsyncMock, return_value={
             "id": "rule-uuid-3", "index": 3, "name": "LAST-RULE"
         }):

        # After deletion, only rules at index 1 and 2 remain (no shifting needed)
        mock_client.graphql = AsyncMock(return_value={
            "nat_policy_rules": [
                {"id": "rule-uuid-1", "index": 1},
                {"id": "rule-uuid-2", "index": 2},
            ]
        })
        mock_client.rest_delete = AsyncMock()
        mock_client.rest_patch = AsyncMock()

        from server import firewall_delete_nat_rule

        result = await firewall_delete_nat_rule(
            nat_policy="NAT-OUTSIDE",
            rule_name="LAST-RULE",
        )
        parsed = json.loads(result)

        assert parsed["status"] == "deleted"

        # No re-indexing should occur since all remaining rules are below deleted index
        mock_client.rest_patch.assert_not_called()


@pytest.mark.asyncio
async def test_delete_nat_rule_only_rule():
    """Deletes the only rule in the policy — no re-indexing needed."""
    with patch("server.client") as mock_client, \
         patch("server.find_nat_policy", new_callable=AsyncMock, return_value="nat-pol-uuid-1"), \
         patch("server.find_nat_policy_rule", new_callable=AsyncMock, return_value={
             "id": "rule-uuid-only", "index": 1, "name": "ONLY-RULE"
         }):

        # After deletion, no remaining rules
        mock_client.graphql = AsyncMock(return_value={"nat_policy_rules": []})
        mock_client.rest_delete = AsyncMock()
        mock_client.rest_patch = AsyncMock()

        from server import firewall_delete_nat_rule

        result = await firewall_delete_nat_rule(
            nat_policy="NAT-OUTSIDE",
            rule_name="ONLY-RULE",
        )
        parsed = json.loads(result)

        assert parsed["status"] == "deleted"
        mock_client.rest_patch.assert_not_called()


@pytest.mark.asyncio
async def test_delete_nat_rule_policy_not_found():
    """Returns error when NAT policy does not exist."""
    with patch("server.find_nat_policy", new_callable=AsyncMock, return_value=None):
        from server import firewall_delete_nat_rule

        result = await firewall_delete_nat_rule(
            nat_policy="NONEXISTENT-POLICY",
            rule_name="SOME-RULE",
        )
        parsed = json.loads(result)

        assert "error" in parsed
        assert "NONEXISTENT-POLICY" in parsed["error"]
        assert "not found" in parsed["error"]


@pytest.mark.asyncio
async def test_delete_nat_rule_rule_not_found():
    """Returns error when rule name does not exist in the policy."""
    with patch("server.find_nat_policy", new_callable=AsyncMock, return_value="nat-pol-uuid-1"), \
         patch("server.find_nat_policy_rule", new_callable=AsyncMock, return_value=None):

        from server import firewall_delete_nat_rule

        result = await firewall_delete_nat_rule(
            nat_policy="NAT-OUTSIDE",
            rule_name="NONEXISTENT-RULE",
        )
        parsed = json.loads(result)

        assert "error" in parsed
        assert "NONEXISTENT-RULE" in parsed["error"]
        assert "not found" in parsed["error"]


@pytest.mark.asyncio
async def test_delete_nat_rule_itsm_blocked():
    """Returns error when ITSM is enabled and no cr_number provided."""
    with patch("server.ITSM_ENABLED", True), \
         patch("server.ITSM_LAB_MODE", False):
        from server import firewall_delete_nat_rule

        result = await firewall_delete_nat_rule(
            nat_policy="NAT-OUTSIDE",
            rule_name="BLOCKED-RULE",
        )
        parsed = json.loads(result)

        assert "error" in parsed
        assert "ITSM" in parsed["error"]


@pytest.mark.asyncio
async def test_delete_nat_rule_itsm_with_cr():
    """Proceeds when ITSM is enabled and cr_number is provided."""
    with patch("server.ITSM_ENABLED", True), \
         patch("server.ITSM_LAB_MODE", False), \
         patch("server.client") as mock_client, \
         patch("server.find_nat_policy", new_callable=AsyncMock, return_value="nat-pol-uuid-1"), \
         patch("server.find_nat_policy_rule", new_callable=AsyncMock, return_value={
             "id": "rule-uuid-cr", "index": 1, "name": "CR-RULE"
         }):

        mock_client.graphql = AsyncMock(return_value={"nat_policy_rules": []})
        mock_client.rest_delete = AsyncMock()
        mock_client.rest_patch = AsyncMock()

        from server import firewall_delete_nat_rule

        result = await firewall_delete_nat_rule(
            nat_policy="NAT-OUTSIDE",
            rule_name="CR-RULE",
            cr_number="CHG0099999",
        )
        parsed = json.loads(result)

        assert parsed["status"] == "deleted"
        assert parsed["rule_name"] == "CR-RULE"


@pytest.mark.asyncio
async def test_delete_nat_rule_nautobot_error():
    """Returns error JSON on NautobotError."""
    from nautobot_client import NautobotError

    with patch("server.find_nat_policy", new_callable=AsyncMock, return_value="nat-pol-uuid-1"), \
         patch("server.find_nat_policy_rule", new_callable=AsyncMock, return_value={
             "id": "rule-uuid-err", "index": 1, "name": "ERR-RULE"
         }), \
         patch("server.client") as mock_client:

        mock_client.rest_delete = AsyncMock(
            side_effect=NautobotError("API error (500): internal server error")
        )

        from server import firewall_delete_nat_rule

        result = await firewall_delete_nat_rule(
            nat_policy="NAT-OUTSIDE",
            rule_name="ERR-RULE",
        )
        parsed = json.loads(result)

        assert "error" in parsed
        assert "API error" in parsed["error"]


@pytest.mark.asyncio
async def test_delete_nat_rule_first_rule_shifts_all():
    """Deletes the first rule and shifts all remaining rules down by 1."""
    with patch("server.client") as mock_client, \
         patch("server.find_nat_policy", new_callable=AsyncMock, return_value="nat-pol-uuid-1"), \
         patch("server.find_nat_policy_rule", new_callable=AsyncMock, return_value={
             "id": "rule-uuid-1", "index": 1, "name": "FIRST-RULE"
         }):

        # After deletion, remaining rules at index 2, 3, 4
        mock_client.graphql = AsyncMock(return_value={
            "nat_policy_rules": [
                {"id": "rule-uuid-2", "index": 2},
                {"id": "rule-uuid-3", "index": 3},
                {"id": "rule-uuid-4", "index": 4},
            ]
        })
        mock_client.rest_delete = AsyncMock()
        mock_client.rest_patch = AsyncMock()

        from server import firewall_delete_nat_rule

        result = await firewall_delete_nat_rule(
            nat_policy="NAT-OUTSIDE",
            rule_name="FIRST-RULE",
        )
        parsed = json.loads(result)

        assert parsed["status"] == "deleted"

        # All 3 remaining rules should be re-indexed
        patch_calls = mock_client.rest_patch.call_args_list
        assert len(patch_calls) == 3
        assert patch_calls[0][0] == ("plugins/firewall/nat-policy-rules/rule-uuid-2", {"index": 1})
        assert patch_calls[1][0] == ("plugins/firewall/nat-policy-rules/rule-uuid-3", {"index": 2})
        assert patch_calls[2][0] == ("plugins/firewall/nat-policy-rules/rule-uuid-4", {"index": 3})
