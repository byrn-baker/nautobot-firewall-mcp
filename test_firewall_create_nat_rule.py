"""Unit tests for firewall_create_nat_rule tool."""

from __future__ import annotations

import json
import os
from unittest.mock import AsyncMock, patch

import pytest

os.environ.setdefault("NAUTOBOT_URL", "https://nautobot.test")
os.environ.setdefault("NAUTOBOT_TOKEN", "test-token")


@pytest.mark.asyncio
async def test_create_nat_rule_basic():
    """Creates a NAT rule with original and translated source addresses."""
    with patch("server.client") as mock_client, \
         patch("server.find_nat_policy", new_callable=AsyncMock, return_value="nat-pol-uuid-1"), \
         patch("server.find_address_object", new_callable=AsyncMock) as mock_find_addr:

        # find_address_object returns different UUIDs for different names
        mock_find_addr.side_effect = lambda c, name: {
            "internal-net": "addr-uuid-1",
            "nat-pool": "addr-uuid-2",
        }.get(name)

        # No existing rules — auto-assign index 1
        mock_client.graphql = AsyncMock(return_value={"nat_policy_rules": []})
        mock_client.rest_post = AsyncMock(return_value={
            "id": "nat-rule-uuid-1",
            "name": "PAT-INSIDE-OUT",
        })

        from server import firewall_create_nat_rule

        result = await firewall_create_nat_rule(
            nat_policy="NAT-OUTSIDE",
            name="PAT-INSIDE-OUT",
            original_source="internal-net",
            translated_source="nat-pool",
        )
        parsed = json.loads(result)

        assert parsed["status"] == "created"
        assert parsed["id"] == "nat-rule-uuid-1"
        assert parsed["name"] == "PAT-INSIDE-OUT"
        assert parsed["index"] == 1
        assert parsed["nat_policy"] == "NAT-OUTSIDE"

        # Verify REST body
        call_args = mock_client.rest_post.call_args
        assert call_args[0][0] == "plugins/firewall/nat-policy-rules"
        body = call_args[0][1]
        assert body["name"] == "PAT-INSIDE-OUT"
        assert body["nat_policy"] == "nat-pol-uuid-1"
        assert body["original_source"] == "addr-uuid-1"
        assert body["translated_source"] == "addr-uuid-2"
        assert body["original_destination"] is None
        assert body["translated_destination"] is None
        assert body["index"] == 1


@pytest.mark.asyncio
async def test_create_nat_rule_auto_index_appends():
    """Auto-assigns index as max(existing) + 1 when not provided."""
    with patch("server.client") as mock_client, \
         patch("server.find_nat_policy", new_callable=AsyncMock, return_value="nat-pol-uuid-1"), \
         patch("server.find_address_object", new_callable=AsyncMock, return_value="addr-uuid-x"):

        # Existing rules at indices 1, 2, 3
        mock_client.graphql = AsyncMock(return_value={
            "nat_policy_rules": [
                {"id": "r1", "index": 1},
                {"id": "r2", "index": 2},
                {"id": "r3", "index": 3},
            ]
        })
        mock_client.rest_post = AsyncMock(return_value={
            "id": "nat-rule-uuid-new",
            "name": "NEW-RULE",
        })

        from server import firewall_create_nat_rule

        result = await firewall_create_nat_rule(
            nat_policy="NAT-OUTSIDE",
            name="NEW-RULE",
            original_source="some-addr",
        )
        parsed = json.loads(result)

        assert parsed["status"] == "created"
        assert parsed["index"] == 4  # max(1,2,3) + 1


@pytest.mark.asyncio
async def test_create_nat_rule_explicit_index():
    """Uses the provided index instead of auto-assigning."""
    with patch("server.client") as mock_client, \
         patch("server.find_nat_policy", new_callable=AsyncMock, return_value="nat-pol-uuid-1"), \
         patch("server.find_address_object", new_callable=AsyncMock, return_value="addr-uuid-x"):

        mock_client.rest_post = AsyncMock(return_value={
            "id": "nat-rule-uuid-2",
            "name": "INSERT-RULE",
        })

        from server import firewall_create_nat_rule

        result = await firewall_create_nat_rule(
            nat_policy="NAT-OUTSIDE",
            name="INSERT-RULE",
            original_destination="some-addr",
            index=5,
        )
        parsed = json.loads(result)

        assert parsed["status"] == "created"
        assert parsed["index"] == 5

        # Should NOT query for existing rules when index is explicit
        mock_client.graphql.assert_not_called()


@pytest.mark.asyncio
async def test_create_nat_rule_all_addresses():
    """Creates rule with all four address fields specified."""
    with patch("server.client") as mock_client, \
         patch("server.find_nat_policy", new_callable=AsyncMock, return_value="nat-pol-uuid-1"), \
         patch("server.find_address_object", new_callable=AsyncMock) as mock_find_addr:

        mock_find_addr.side_effect = lambda c, name: {
            "orig-src": "uuid-os",
            "trans-src": "uuid-ts",
            "orig-dst": "uuid-od",
            "trans-dst": "uuid-td",
        }.get(name)

        mock_client.rest_post = AsyncMock(return_value={
            "id": "nat-rule-uuid-full",
            "name": "FULL-NAT",
        })

        from server import firewall_create_nat_rule

        result = await firewall_create_nat_rule(
            nat_policy="NAT-OUTSIDE",
            name="FULL-NAT",
            original_source="orig-src",
            translated_source="trans-src",
            original_destination="orig-dst",
            translated_destination="trans-dst",
            index=1,
        )
        parsed = json.loads(result)

        assert parsed["status"] == "created"

        body = mock_client.rest_post.call_args[0][1]
        assert body["original_source"] == "uuid-os"
        assert body["translated_source"] == "uuid-ts"
        assert body["original_destination"] == "uuid-od"
        assert body["translated_destination"] == "uuid-td"


@pytest.mark.asyncio
async def test_create_nat_rule_nat_policy_not_found():
    """Returns error when NAT policy does not exist."""
    with patch("server.find_nat_policy", new_callable=AsyncMock, return_value=None):
        from server import firewall_create_nat_rule

        result = await firewall_create_nat_rule(
            nat_policy="NONEXISTENT-POLICY",
            name="SOME-RULE",
        )
        parsed = json.loads(result)

        assert "error" in parsed
        assert "NONEXISTENT-POLICY" in parsed["error"]
        assert "not found" in parsed["error"]


@pytest.mark.asyncio
async def test_create_nat_rule_address_object_not_found():
    """Returns error when an address object cannot be resolved."""
    with patch("server.find_nat_policy", new_callable=AsyncMock, return_value="nat-pol-uuid-1"), \
         patch("server.find_address_object", new_callable=AsyncMock, return_value=None):

        from server import firewall_create_nat_rule

        result = await firewall_create_nat_rule(
            nat_policy="NAT-OUTSIDE",
            name="BAD-RULE",
            original_source="nonexistent-addr",
        )
        parsed = json.loads(result)

        assert "error" in parsed
        assert "nonexistent-addr" in parsed["error"]
        assert "not found" in parsed["error"]


@pytest.mark.asyncio
async def test_create_nat_rule_itsm_blocked():
    """Returns error when ITSM is enabled and no cr_number provided."""
    with patch("server.ITSM_ENABLED", True), \
         patch("server.ITSM_LAB_MODE", False):
        from server import firewall_create_nat_rule

        result = await firewall_create_nat_rule(
            nat_policy="NAT-OUTSIDE",
            name="BLOCKED-RULE",
        )
        parsed = json.loads(result)

        assert "error" in parsed
        assert "ITSM" in parsed["error"]


@pytest.mark.asyncio
async def test_create_nat_rule_itsm_with_cr():
    """Proceeds when ITSM is enabled and cr_number is provided."""
    with patch("server.ITSM_ENABLED", True), \
         patch("server.ITSM_LAB_MODE", False), \
         patch("server.client") as mock_client, \
         patch("server.find_nat_policy", new_callable=AsyncMock, return_value="nat-pol-uuid-1"), \
         patch("server.find_address_object", new_callable=AsyncMock, return_value="addr-uuid-x"):

        mock_client.graphql = AsyncMock(return_value={"nat_policy_rules": []})
        mock_client.rest_post = AsyncMock(return_value={
            "id": "nat-rule-uuid-cr",
            "name": "CR-RULE",
        })

        from server import firewall_create_nat_rule

        result = await firewall_create_nat_rule(
            nat_policy="NAT-OUTSIDE",
            name="CR-RULE",
            original_source="some-addr",
            cr_number="CHG0099999",
        )
        parsed = json.loads(result)

        assert parsed["status"] == "created"
        assert parsed["id"] == "nat-rule-uuid-cr"


@pytest.mark.asyncio
async def test_create_nat_rule_nautobot_error():
    """Returns error JSON on NautobotError."""
    from nautobot_client import NautobotError

    with patch("server.find_nat_policy", new_callable=AsyncMock, return_value="nat-pol-uuid-1"), \
         patch("server.find_address_object", new_callable=AsyncMock, return_value="addr-uuid-x"), \
         patch("server.client") as mock_client:

        mock_client.graphql = AsyncMock(return_value={"nat_policy_rules": []})
        mock_client.rest_post = AsyncMock(
            side_effect=NautobotError("API error (400): invalid payload")
        )

        from server import firewall_create_nat_rule

        result = await firewall_create_nat_rule(
            nat_policy="NAT-OUTSIDE",
            name="ERR-RULE",
            original_source="some-addr",
        )
        parsed = json.loads(result)

        assert "error" in parsed
        assert "API error" in parsed["error"]


@pytest.mark.asyncio
async def test_create_nat_rule_no_addresses():
    """Creates a NAT rule with no address objects (all None)."""
    with patch("server.client") as mock_client, \
         patch("server.find_nat_policy", new_callable=AsyncMock, return_value="nat-pol-uuid-1"):

        mock_client.graphql = AsyncMock(return_value={"nat_policy_rules": []})
        mock_client.rest_post = AsyncMock(return_value={
            "id": "nat-rule-uuid-empty",
            "name": "EMPTY-RULE",
        })

        from server import firewall_create_nat_rule

        result = await firewall_create_nat_rule(
            nat_policy="NAT-OUTSIDE",
            name="EMPTY-RULE",
        )
        parsed = json.loads(result)

        assert parsed["status"] == "created"
        assert parsed["index"] == 1

        body = mock_client.rest_post.call_args[0][1]
        assert body["original_source"] is None
        assert body["translated_source"] is None
        assert body["original_destination"] is None
        assert body["translated_destination"] is None
