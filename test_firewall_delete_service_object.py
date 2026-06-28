"""Unit tests for firewall_delete_service_object tool."""

from __future__ import annotations

import json
import os
from unittest.mock import AsyncMock, patch

import pytest

os.environ.setdefault("NAUTOBOT_URL", "https://nautobot.test")
os.environ.setdefault("NAUTOBOT_TOKEN", "test-token")


@pytest.mark.asyncio
async def test_delete_service_object_success():
    """When service object exists and is not referenced, deletes successfully."""
    svc_graphql = {"service_objects": [{"id": "svc-uuid-1", "name": "HTTPS"}]}
    rules_graphql = {"policy_rules": []}

    async def mock_graphql(query):
        if "service_objects" in query:
            return svc_graphql
        if "policy_rules" in query:
            return rules_graphql
        return {}

    with patch("server.client.graphql", new_callable=AsyncMock, side_effect=mock_graphql):
        with patch("server.client.rest_delete", new_callable=AsyncMock) as mock_delete:
            from server import firewall_delete_service_object

            result = await firewall_delete_service_object(name="HTTPS")
            data = json.loads(result)
            assert data["status"] == "deleted"
            assert data["name"] == "HTTPS"
            mock_delete.assert_called_once_with("plugins/firewall/service-objects/svc-uuid-1")


@pytest.mark.asyncio
async def test_delete_service_object_not_found():
    """When service object does not exist, returns error."""
    svc_graphql = {"service_objects": []}

    with patch("server.client.graphql", new_callable=AsyncMock, return_value=svc_graphql):
        from server import firewall_delete_service_object

        result = await firewall_delete_service_object(name="NONEXISTENT")
        data = json.loads(result)
        assert "error" in data
        assert "not found" in data["error"]
        assert "NONEXISTENT" in data["error"]


@pytest.mark.asyncio
async def test_delete_service_object_referenced_by_source_services():
    """When service object is used as source_service in a rule, returns in-use error."""
    svc_graphql = {"service_objects": [{"id": "svc-uuid-1", "name": "DNS-UDP"}]}
    rules_graphql = {
        "policy_rules": [
            {
                "id": "rule-1",
                "source_services": [{"id": "svc-uuid-1"}],
                "destination_services": [],
            }
        ]
    }

    async def mock_graphql(query):
        if "service_objects" in query:
            return svc_graphql
        if "policy_rules" in query:
            return rules_graphql
        return {}

    with patch("server.client.graphql", new_callable=AsyncMock, side_effect=mock_graphql):
        from server import firewall_delete_service_object

        result = await firewall_delete_service_object(name="DNS-UDP")
        data = json.loads(result)
        assert "error" in data
        assert "referenced by policy rules" in data["error"]
        assert "DNS-UDP" in data["error"]


@pytest.mark.asyncio
async def test_delete_service_object_referenced_by_destination_services():
    """When service object is used as destination_service in a rule, returns in-use error."""
    svc_graphql = {"service_objects": [{"id": "svc-uuid-2", "name": "HTTPS"}]}
    rules_graphql = {
        "policy_rules": [
            {
                "id": "rule-1",
                "source_services": [],
                "destination_services": [{"id": "svc-uuid-2"}],
            }
        ]
    }

    async def mock_graphql(query):
        if "service_objects" in query:
            return svc_graphql
        if "policy_rules" in query:
            return rules_graphql
        return {}

    with patch("server.client.graphql", new_callable=AsyncMock, side_effect=mock_graphql):
        from server import firewall_delete_service_object

        result = await firewall_delete_service_object(name="HTTPS")
        data = json.loads(result)
        assert "error" in data
        assert "referenced by policy rules" in data["error"]
        assert "HTTPS" in data["error"]


@pytest.mark.asyncio
async def test_delete_service_object_itsm_blocked():
    """When ITSM is enabled and no cr_number provided, returns ITSM error."""
    with patch("server.ITSM_ENABLED", True), \
         patch("server.ITSM_LAB_MODE", False):
        from server import firewall_delete_service_object

        result = await firewall_delete_service_object(name="HTTPS")
        data = json.loads(result)
        assert "error" in data
        assert "ITSM" in data["error"]


@pytest.mark.asyncio
async def test_delete_service_object_nautobot_error():
    """When NautobotError is raised, returns structured error."""
    from nautobot_client import NautobotError

    with patch(
        "server.client.graphql",
        new_callable=AsyncMock,
        side_effect=NautobotError("Nautobot unreachable: timeout"),
    ):
        from server import firewall_delete_service_object

        result = await firewall_delete_service_object(name="HTTPS")
        data = json.loads(result)
        assert "error" in data
        assert "Nautobot unreachable" in data["error"]
