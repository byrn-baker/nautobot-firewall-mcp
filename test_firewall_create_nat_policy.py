"""Unit tests for firewall_create_nat_policy tool."""

from __future__ import annotations

import json
import os
from unittest.mock import AsyncMock, patch

import pytest

os.environ.setdefault("NAUTOBOT_URL", "https://nautobot.test")
os.environ.setdefault("NAUTOBOT_TOKEN", "test-token")


@pytest.mark.asyncio
async def test_create_nat_policy_basic():
    """Creates a NAT policy without a device assignment."""
    with patch("server.client") as mock_client, \
         patch("server.find_nat_policy", new_callable=AsyncMock, return_value=None):
        mock_client.rest_post = AsyncMock(return_value={
            "id": "nat-pol-uuid-1",
            "name": "NAT-OUTSIDE",
        })

        from server import firewall_create_nat_policy

        result = await firewall_create_nat_policy(
            name="NAT-OUTSIDE", description="Outbound NAT policy"
        )
        parsed = json.loads(result)

        assert parsed["status"] == "created"
        assert parsed["id"] == "nat-pol-uuid-1"
        assert parsed["name"] == "NAT-OUTSIDE"

        # Verify REST body
        call_args = mock_client.rest_post.call_args
        assert call_args[0][0] == "plugins/firewall/nat-policies"
        body = call_args[0][1]
        assert body["name"] == "NAT-OUTSIDE"
        assert body["assigned_devices"] == []
        assert body["status"] == {"name": "Active"}
        assert body["description"] == "Outbound NAT policy"


@pytest.mark.asyncio
async def test_create_nat_policy_with_device():
    """Creates a NAT policy assigned to a device."""
    with patch("server.client") as mock_client, \
         patch("server.find_nat_policy", new_callable=AsyncMock, return_value=None):
        mock_client.graphql = AsyncMock(return_value={
            "devices": [{"id": "device-uuid-abc"}]
        })
        mock_client.rest_post = AsyncMock(return_value={
            "id": "nat-pol-uuid-2",
            "name": "PAT-INSIDE",
        })

        from server import firewall_create_nat_policy

        result = await firewall_create_nat_policy(
            name="PAT-INSIDE", device="fw01", description="Inside PAT"
        )
        parsed = json.loads(result)

        assert parsed["status"] == "created"
        assert parsed["id"] == "nat-pol-uuid-2"
        assert parsed["name"] == "PAT-INSIDE"

        # Verify device was resolved and included
        body = mock_client.rest_post.call_args[0][1]
        assert body["assigned_devices"] == ["device-uuid-abc"]
        assert body["description"] == "Inside PAT"


@pytest.mark.asyncio
async def test_create_nat_policy_idempotent():
    """Returns existing NAT policy when name already exists."""
    with patch("server.find_nat_policy", new_callable=AsyncMock, return_value="existing-nat-uuid"):
        from server import firewall_create_nat_policy

        result = await firewall_create_nat_policy(name="NAT-OUTSIDE")
        parsed = json.loads(result)

        assert parsed["status"] == "exists"
        assert parsed["id"] == "existing-nat-uuid"
        assert parsed["name"] == "NAT-OUTSIDE"


@pytest.mark.asyncio
async def test_create_nat_policy_device_not_found():
    """Returns error when the specified device does not exist."""
    with patch("server.client") as mock_client, \
         patch("server.find_nat_policy", new_callable=AsyncMock, return_value=None):
        mock_client.graphql = AsyncMock(return_value={"devices": []})

        from server import firewall_create_nat_policy

        result = await firewall_create_nat_policy(
            name="NAT-OUTSIDE", device="nonexistent-fw"
        )
        parsed = json.loads(result)

        assert "error" in parsed
        assert "nonexistent-fw" in parsed["error"]
        assert "not found" in parsed["error"]


@pytest.mark.asyncio
async def test_create_nat_policy_itsm_blocked():
    """Returns error when ITSM is enabled and no cr_number provided."""
    with patch("server.ITSM_ENABLED", True), \
         patch("server.ITSM_LAB_MODE", False):
        from server import firewall_create_nat_policy

        result = await firewall_create_nat_policy(name="NAT-OUTSIDE")
        parsed = json.loads(result)

        assert "error" in parsed
        assert "ITSM" in parsed["error"]


@pytest.mark.asyncio
async def test_create_nat_policy_itsm_with_cr():
    """Proceeds when ITSM is enabled and cr_number is provided."""
    with patch("server.ITSM_ENABLED", True), \
         patch("server.ITSM_LAB_MODE", False), \
         patch("server.client") as mock_client, \
         patch("server.find_nat_policy", new_callable=AsyncMock, return_value=None):
        mock_client.rest_post = AsyncMock(return_value={
            "id": "nat-pol-uuid-3",
            "name": "NAT-DMZ",
        })

        from server import firewall_create_nat_policy

        result = await firewall_create_nat_policy(
            name="NAT-DMZ", cr_number="CHG0099999"
        )
        parsed = json.loads(result)

        assert parsed["status"] == "created"
        assert parsed["id"] == "nat-pol-uuid-3"


@pytest.mark.asyncio
async def test_create_nat_policy_nautobot_error():
    """Returns error JSON on NautobotError."""
    from nautobot_client import NautobotError

    with patch("server.find_nat_policy", new_callable=AsyncMock, return_value=None), \
         patch("server.client") as mock_client:
        mock_client.rest_post = AsyncMock(
            side_effect=NautobotError("API error (400): invalid payload")
        )

        from server import firewall_create_nat_policy

        result = await firewall_create_nat_policy(name="BAD-NAT")
        parsed = json.loads(result)

        assert "error" in parsed
        assert "API error" in parsed["error"]


@pytest.mark.asyncio
async def test_create_nat_policy_empty_description_defaults():
    """Description defaults to empty string when not provided."""
    with patch("server.client") as mock_client, \
         patch("server.find_nat_policy", new_callable=AsyncMock, return_value=None):
        mock_client.rest_post = AsyncMock(return_value={
            "id": "nat-pol-uuid-4",
            "name": "NAT-SIMPLE",
        })

        from server import firewall_create_nat_policy

        result = await firewall_create_nat_policy(name="NAT-SIMPLE")
        parsed = json.loads(result)

        assert parsed["status"] == "created"

        body = mock_client.rest_post.call_args[0][1]
        assert body["description"] == ""
