"""Unit tests for firewall_create_policy_rule tool."""

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
async def test_create_policy_rule_append_to_empty_policy():
    """Creates rule with index=1 when policy has no existing rules."""
    async def mock_graphql(query):
        if "policies(name:" in query:
            return {"policies": [{"id": "policy-uuid", "name": "FW-POLICY", "assigned_devices": []}]}
        if "policy_rules(policy:" in query:
            return {"policy_rules": []}
        return {}

    mock_post_result = {"id": "new-rule-uuid", "name": "allow-web"}

    with patch("server.client.graphql", new_callable=AsyncMock, side_effect=mock_graphql):
        with patch(
            "server.client.rest_post", new_callable=AsyncMock, return_value=mock_post_result
        ) as mock_post:
            import server

            result = await server.firewall_create_policy_rule(
                policy="FW-POLICY", name="allow-web", action="permit"
            )
            data = json.loads(result)
            assert data["status"] == "created"
            assert data["id"] == "new-rule-uuid"
            assert data["name"] == "allow-web"
            assert data["index"] == 1
            assert data["policy"] == "FW-POLICY"

            # Verify POST call
            mock_post.assert_called_once()
            call_args = mock_post.call_args
            assert call_args[0][0] == "plugins/firewall/policy-rules"
            payload = call_args[0][1]
            assert payload["name"] == "allow-web"
            assert payload["policy"] == "policy-uuid"
            assert payload["index"] == 1
            assert payload["action"] == "permit"
            assert payload["log"] is False


@pytest.mark.asyncio
async def test_create_policy_rule_append_to_existing_rules():
    """Appends rule with index = max(existing) + 1."""
    async def mock_graphql(query):
        if "policies(name:" in query:
            return {"policies": [{"id": "policy-uuid", "name": "FW-POLICY", "assigned_devices": []}]}
        if "policy_rules(policy:" in query:
            return {"policy_rules": [
                {"id": "rule-1", "name": "rule-one", "index": 1},
                {"id": "rule-2", "name": "rule-two", "index": 2},
                {"id": "rule-3", "name": "rule-three", "index": 3},
            ]}
        return {}

    mock_post_result = {"id": "new-rule-uuid", "name": "deny-all"}

    with patch("server.client.graphql", new_callable=AsyncMock, side_effect=mock_graphql):
        with patch(
            "server.client.rest_post", new_callable=AsyncMock, return_value=mock_post_result
        ) as mock_post:
            import server

            result = await server.firewall_create_policy_rule(
                policy="FW-POLICY", name="deny-all", action="deny"
            )
            data = json.loads(result)
            assert data["status"] == "created"
            assert data["index"] == 4  # max(1,2,3) + 1

            payload = mock_post.call_args[0][1]
            assert payload["index"] == 4


@pytest.mark.asyncio
async def test_create_policy_rule_insert_at_index_shifts_rules():
    """Inserting at a specific index shifts existing rules at >= index."""
    async def mock_graphql(query):
        if "policies(name:" in query:
            return {"policies": [{"id": "policy-uuid", "name": "FW-POLICY", "assigned_devices": []}]}
        if "policy_rules(policy:" in query:
            return {"policy_rules": [
                {"id": "rule-1", "name": "rule-one", "index": 1},
                {"id": "rule-2", "name": "rule-two", "index": 2},
                {"id": "rule-3", "name": "rule-three", "index": 3},
            ]}
        return {}

    mock_post_result = {"id": "new-rule-uuid", "name": "insert-here"}

    with patch("server.client.graphql", new_callable=AsyncMock, side_effect=mock_graphql):
        with patch(
            "server.client.rest_post", new_callable=AsyncMock, return_value=mock_post_result
        ) as mock_post:
            with patch(
                "server.client.rest_patch", new_callable=AsyncMock
            ) as mock_patch:
                import server

                result = await server.firewall_create_policy_rule(
                    policy="FW-POLICY", name="insert-here", action="permit", index=2
                )
                data = json.loads(result)
                assert data["status"] == "created"
                assert data["index"] == 2

                # Rules at index 2 and 3 should be shifted
                assert mock_patch.call_count == 2

                # Verify the shifted rules (sorted descending: rule-3 first, then rule-2)
                patch_calls = mock_patch.call_args_list
                # rule-3 (index 3) shifted to 4
                assert patch_calls[0][0] == ("plugins/firewall/policy-rules/rule-3", {"index": 4})
                # rule-2 (index 2) shifted to 3
                assert patch_calls[1][0] == ("plugins/firewall/policy-rules/rule-2", {"index": 3})

                # Verify POST used index=2
                payload = mock_post.call_args[0][1]
                assert payload["index"] == 2


@pytest.mark.asyncio
async def test_create_policy_rule_with_zones():
    """Resolves source and destination zone UUIDs."""
    async def mock_graphql(query):
        if "policies(name:" in query:
            return {"policies": [{"id": "policy-uuid", "name": "FW-POLICY", "assigned_devices": []}]}
        if "zones(name:" in query:
            if "INSIDE" in query:
                return {"zones": [{"id": "zone-inside-uuid", "name": "INSIDE"}]}
            if "OUTSIDE" in query:
                return {"zones": [{"id": "zone-outside-uuid", "name": "OUTSIDE"}]}
        if "policy_rules(policy:" in query:
            return {"policy_rules": []}
        return {}

    mock_post_result = {"id": "new-rule-uuid", "name": "zone-rule"}

    with patch("server.client.graphql", new_callable=AsyncMock, side_effect=mock_graphql):
        with patch(
            "server.client.rest_post", new_callable=AsyncMock, return_value=mock_post_result
        ) as mock_post:
            import server

            result = await server.firewall_create_policy_rule(
                policy="FW-POLICY",
                name="zone-rule",
                source_zone="INSIDE",
                dest_zone="OUTSIDE",
            )
            data = json.loads(result)
            assert data["status"] == "created"

            payload = mock_post.call_args[0][1]
            assert payload["source_zone"] == "zone-inside-uuid"
            assert payload["destination_zone"] == "zone-outside-uuid"


@pytest.mark.asyncio
async def test_create_policy_rule_with_addresses_and_services():
    """Resolves address and service object UUIDs."""
    async def mock_graphql(query):
        if "policies(name:" in query:
            return {"policies": [{"id": "policy-uuid", "name": "FW-POLICY", "assigned_devices": []}]}
        if "address_objects(name:" in query:
            if "web-server" in query:
                return {"address_objects": [{"id": "addr-web-uuid", "name": "web-server"}]}
            if "db-server" in query:
                return {"address_objects": [{"id": "addr-db-uuid", "name": "db-server"}]}
        if "service_objects(name:" in query:
            if "HTTPS" in query:
                return {"service_objects": [{"id": "svc-https-uuid", "name": "HTTPS"}]}
            if "SSH" in query:
                return {"service_objects": [{"id": "svc-ssh-uuid", "name": "SSH"}]}
        if "policy_rules(policy:" in query:
            return {"policy_rules": []}
        return {}

    mock_post_result = {"id": "new-rule-uuid", "name": "full-rule"}

    with patch("server.client.graphql", new_callable=AsyncMock, side_effect=mock_graphql):
        with patch(
            "server.client.rest_post", new_callable=AsyncMock, return_value=mock_post_result
        ) as mock_post:
            import server

            result = await server.firewall_create_policy_rule(
                policy="FW-POLICY",
                name="full-rule",
                source_addresses=["web-server"],
                dest_addresses=["db-server"],
                source_services=["SSH"],
                dest_services=["HTTPS"],
            )
            data = json.loads(result)
            assert data["status"] == "created"

            payload = mock_post.call_args[0][1]
            assert payload["source_addresses"] == ["addr-web-uuid"]
            assert payload["destination_addresses"] == ["addr-db-uuid"]
            assert payload["source_services"] == ["svc-ssh-uuid"]
            assert payload["destination_services"] == ["svc-https-uuid"]


@pytest.mark.asyncio
async def test_create_policy_rule_policy_not_found():
    """Returns error when policy cannot be resolved."""
    async def mock_graphql(query):
        if "policies(name:" in query:
            return {"policies": []}
        return {}

    with patch("server.client.graphql", new_callable=AsyncMock, side_effect=mock_graphql):
        with patch("server.client.rest_post", new_callable=AsyncMock) as mock_post:
            import server

            result = await server.firewall_create_policy_rule(
                policy="NONEXISTENT", name="rule-1"
            )
            data = json.loads(result)
            assert "error" in data
            assert "NONEXISTENT" in data["error"]
            assert "not found" in data["error"]
            mock_post.assert_not_called()


@pytest.mark.asyncio
async def test_create_policy_rule_zone_not_found():
    """Returns error when source zone cannot be resolved."""
    async def mock_graphql(query):
        if "policies(name:" in query:
            return {"policies": [{"id": "policy-uuid", "name": "FW-POLICY", "assigned_devices": []}]}
        if "zones(name:" in query:
            return {"zones": []}
        return {}

    with patch("server.client.graphql", new_callable=AsyncMock, side_effect=mock_graphql):
        with patch("server.client.rest_post", new_callable=AsyncMock) as mock_post:
            import server

            result = await server.firewall_create_policy_rule(
                policy="FW-POLICY", name="rule-1", source_zone="BOGUS"
            )
            data = json.loads(result)
            assert "error" in data
            assert "BOGUS" in data["error"]
            mock_post.assert_not_called()


@pytest.mark.asyncio
async def test_create_policy_rule_address_not_found():
    """Returns error when an address object cannot be resolved."""
    async def mock_graphql(query):
        if "policies(name:" in query:
            return {"policies": [{"id": "policy-uuid", "name": "FW-POLICY", "assigned_devices": []}]}
        if "address_objects(name:" in query:
            return {"address_objects": []}
        if "policy_rules(policy:" in query:
            return {"policy_rules": []}
        return {}

    with patch("server.client.graphql", new_callable=AsyncMock, side_effect=mock_graphql):
        with patch("server.client.rest_post", new_callable=AsyncMock) as mock_post:
            import server

            result = await server.firewall_create_policy_rule(
                policy="FW-POLICY", name="rule-1", source_addresses=["nonexistent-addr"]
            )
            data = json.loads(result)
            assert "error" in data
            assert "nonexistent-addr" in data["error"]
            mock_post.assert_not_called()


@pytest.mark.asyncio
async def test_create_policy_rule_itsm_blocked(monkeypatch):
    """When ITSM is enforced and no cr_number, returns error."""
    monkeypatch.setenv("ITSM_ENABLED", "true")
    monkeypatch.setenv("ITSM_LAB_MODE", "false")

    import importlib
    import server

    importlib.reload(server)

    result = await server.firewall_create_policy_rule(
        policy="FW-POLICY", name="rule-1"
    )
    data = json.loads(result)
    assert "error" in data
    assert "ITSM" in data["error"]


@pytest.mark.asyncio
async def test_create_policy_rule_with_log_enabled(monkeypatch):
    """Log flag is passed in the POST payload."""
    monkeypatch.setenv("ITSM_ENABLED", "false")
    monkeypatch.setenv("ITSM_LAB_MODE", "true")

    import importlib
    import server

    importlib.reload(server)

    async def mock_graphql(query):
        if "policies(name:" in query:
            return {"policies": [{"id": "policy-uuid", "name": "FW-POLICY", "assigned_devices": []}]}
        if "policy_rules(policy:" in query:
            return {"policy_rules": []}
        return {}

    mock_post_result = {"id": "new-rule-uuid", "name": "logged-rule"}

    with patch("server.client.graphql", new_callable=AsyncMock, side_effect=mock_graphql):
        with patch(
            "server.client.rest_post", new_callable=AsyncMock, return_value=mock_post_result
        ) as mock_post:
            result = await server.firewall_create_policy_rule(
                policy="FW-POLICY", name="logged-rule", log=True
            )
            data = json.loads(result)
            assert data["status"] == "created"

            payload = mock_post.call_args[0][1]
            assert payload["log"] is True
