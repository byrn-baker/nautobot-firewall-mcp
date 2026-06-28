"""Unit tests for firewall_create_service_object tool."""

from __future__ import annotations

import json
import os
from unittest.mock import AsyncMock, patch

import pytest

os.environ.setdefault("NAUTOBOT_URL", "https://nautobot.test")
os.environ.setdefault("NAUTOBOT_TOKEN", "test-token")


@pytest.mark.asyncio
async def test_create_service_object_tcp_with_port():
    """Creates a TCP service object with a single port."""
    with patch("server.client") as mock_client, \
         patch("server.find_service_object", new_callable=AsyncMock, return_value=None):
        mock_client.rest_post = AsyncMock(return_value={
            "id": "new-uuid-1",
            "name": "HTTPS",
        })

        from server import firewall_create_service_object

        result = await firewall_create_service_object(
            name="HTTPS", protocol="TCP", port="443", description="HTTPS traffic"
        )
        parsed = json.loads(result)

        assert parsed["status"] == "created"
        assert parsed["id"] == "new-uuid-1"
        assert parsed["name"] == "HTTPS"
        assert parsed["protocol"] == "TCP"
        assert parsed["port"] == "443"

        # Verify REST body
        call_args = mock_client.rest_post.call_args
        assert call_args[0][0] == "plugins/firewall/service-objects"
        body = call_args[0][1]
        assert body["name"] == "HTTPS"
        assert body["ip_protocol"] == "TCP"
        assert body["port"] == "443"
        assert body["status"] == {"name": "Active"}
        assert body["description"] == "HTTPS traffic"


@pytest.mark.asyncio
async def test_create_service_object_port_range():
    """Creates a service object with a port range."""
    with patch("server.client") as mock_client, \
         patch("server.find_service_object", new_callable=AsyncMock, return_value=None):
        mock_client.rest_post = AsyncMock(return_value={
            "id": "new-uuid-2",
            "name": "HighPorts",
        })

        from server import firewall_create_service_object

        result = await firewall_create_service_object(
            name="HighPorts", protocol="TCP", port="1024-65535"
        )
        parsed = json.loads(result)

        assert parsed["status"] == "created"
        assert parsed["port"] == "1024-65535"

        body = mock_client.rest_post.call_args[0][1]
        assert body["port"] == "1024-65535"


@pytest.mark.asyncio
async def test_create_service_object_icmp_no_port():
    """Creates an ICMP service object without a port field."""
    with patch("server.client") as mock_client, \
         patch("server.find_service_object", new_callable=AsyncMock, return_value=None):
        mock_client.rest_post = AsyncMock(return_value={
            "id": "new-uuid-3",
            "name": "PING",
        })

        from server import firewall_create_service_object

        result = await firewall_create_service_object(
            name="PING", protocol="ICMP"
        )
        parsed = json.loads(result)

        assert parsed["status"] == "created"
        assert parsed["protocol"] == "ICMP"
        assert parsed["port"] is None

        # Verify port is NOT in the body
        body = mock_client.rest_post.call_args[0][1]
        assert "port" not in body
        assert body["ip_protocol"] == "ICMP"


@pytest.mark.asyncio
async def test_create_service_object_idempotent():
    """Returns existing object when name already exists."""
    with patch("server.find_service_object", new_callable=AsyncMock, return_value="existing-uuid"):
        from server import firewall_create_service_object

        result = await firewall_create_service_object(
            name="HTTPS", protocol="TCP", port="443"
        )
        parsed = json.loads(result)

        assert parsed["status"] == "exists"
        assert parsed["id"] == "existing-uuid"
        assert parsed["name"] == "HTTPS"


@pytest.mark.asyncio
async def test_create_service_object_itsm_blocked():
    """Returns error when ITSM is enabled and no cr_number provided."""
    with patch("server.ITSM_ENABLED", True), \
         patch("server.ITSM_LAB_MODE", False):
        from server import firewall_create_service_object

        result = await firewall_create_service_object(
            name="HTTPS", protocol="TCP", port="443"
        )
        parsed = json.loads(result)

        assert "error" in parsed
        assert "ITSM" in parsed["error"]


@pytest.mark.asyncio
async def test_create_service_object_itsm_with_cr():
    """Proceeds when ITSM is enabled and cr_number is provided."""
    with patch("server.ITSM_ENABLED", True), \
         patch("server.ITSM_LAB_MODE", False), \
         patch("server.client") as mock_client, \
         patch("server.find_service_object", new_callable=AsyncMock, return_value=None):
        mock_client.rest_post = AsyncMock(return_value={
            "id": "new-uuid-4",
            "name": "SSH",
        })

        from server import firewall_create_service_object

        result = await firewall_create_service_object(
            name="SSH", protocol="TCP", port="22", cr_number="CHG0012345"
        )
        parsed = json.loads(result)

        assert parsed["status"] == "created"
        assert parsed["id"] == "new-uuid-4"


@pytest.mark.asyncio
async def test_create_service_object_nautobot_error():
    """Returns error JSON on NautobotError."""
    from nautobot_client import NautobotError

    with patch("server.find_service_object", new_callable=AsyncMock, return_value=None), \
         patch("server.client") as mock_client:
        mock_client.rest_post = AsyncMock(
            side_effect=NautobotError("API error (400): validation failed")
        )

        from server import firewall_create_service_object

        result = await firewall_create_service_object(
            name="BAD", protocol="INVALID", port="99999"
        )
        parsed = json.loads(result)

        assert "error" in parsed
        assert "API error" in parsed["error"]


@pytest.mark.asyncio
async def test_create_service_object_empty_description_defaults():
    """Description defaults to empty string when not provided."""
    with patch("server.client") as mock_client, \
         patch("server.find_service_object", new_callable=AsyncMock, return_value=None):
        mock_client.rest_post = AsyncMock(return_value={
            "id": "new-uuid-5",
            "name": "DNS-UDP",
        })

        from server import firewall_create_service_object

        result = await firewall_create_service_object(
            name="DNS-UDP", protocol="UDP", port="53"
        )
        parsed = json.loads(result)

        assert parsed["status"] == "created"

        body = mock_client.rest_post.call_args[0][1]
        assert body["description"] == ""
