"""Firewall object resolution helpers for Nautobot GraphQL lookups."""

from __future__ import annotations

from typing import Optional

from nautobot_client import NautobotClient, NautobotError


def _esc(s: str) -> str:
    """Escape a string for safe embedding in GraphQL queries."""
    return s.replace("\\", "\\\\").replace('"', '\\"')


async def find_zone(client: NautobotClient, name: str) -> Optional[str]:
    """Look up a security zone by name, returning its UUID or None."""
    query = f'{{ zones(name: "{_esc(name)}") {{ id name }} }}'
    data = await client.graphql(query)
    results = data.get("zones", [])
    if results:
        return results[0]["id"]
    return None


async def find_address_object(client: NautobotClient, name: str) -> Optional[str]:
    """Look up an address object by name, returning its UUID or None."""
    query = f'{{ address_objects(name: "{_esc(name)}") {{ id name }} }}'
    data = await client.graphql(query)
    results = data.get("address_objects", [])
    if results:
        return results[0]["id"]
    return None


async def find_service_object(client: NautobotClient, name: str) -> Optional[str]:
    """Look up a service object by name, returning its UUID or None."""
    query = f'{{ service_objects(name: "{_esc(name)}") {{ id name }} }}'
    data = await client.graphql(query)
    results = data.get("service_objects", [])
    if results:
        return results[0]["id"]
    return None


async def find_policy(
    client: NautobotClient, name: str, device: Optional[str] = None
) -> Optional[str]:
    """Look up a firewall policy by name, optionally filtered by device assignment.

    Returns the policy UUID or None.
    """
    query = f'{{ policies(name: "{_esc(name)}") {{ id name assigned_devices {{ name }} }} }}'
    data = await client.graphql(query)
    results = data.get("policies", [])
    if not results:
        return None
    if device:
        for policy in results:
            devices = [d["name"] for d in policy.get("assigned_devices", [])]
            if device in devices:
                return policy["id"]
        return None
    return results[0]["id"]


async def find_policy_rule(
    client: NautobotClient, policy_id: str, rule_name: str
) -> Optional[dict]:
    """Find a policy rule by name within a given policy.

    Returns a dict with {id, index, name} or None if not found.
    """
    query = f"""{{
  policy_rules(policy: "{_esc(policy_id)}") {{
    id name index
  }}
}}"""
    data = await client.graphql(query)
    rules = data.get("policy_rules", [])
    for rule in rules:
        if rule.get("name") == rule_name:
            return {"id": rule["id"], "index": rule["index"], "name": rule["name"]}
    return None


async def find_nat_policy(
    client: NautobotClient, name: str, device: Optional[str] = None
) -> Optional[str]:
    """Look up a NAT policy by name, optionally filtered by device assignment.

    Returns the NAT policy UUID or None.
    """
    query = f'{{ nat_policies(name: "{_esc(name)}") {{ id name assigned_devices {{ name }} }} }}'
    data = await client.graphql(query)
    results = data.get("nat_policies", [])
    if not results:
        return None
    if device:
        for policy in results:
            devices = [d["name"] for d in policy.get("assigned_devices", [])]
            if device in devices:
                return policy["id"]
        return None
    return results[0]["id"]


async def find_nat_policy_rule(
    client: NautobotClient, nat_policy_id: str, rule_name: str
) -> Optional[dict]:
    """Find a NAT policy rule by name within a given NAT policy.

    Returns a dict with {id, index, name} or None if not found.
    """
    query = f"""{{
  nat_policy_rules(nat_policy: "{_esc(nat_policy_id)}") {{
    id name index
  }}
}}"""
    data = await client.graphql(query)
    rules = data.get("nat_policy_rules", [])
    for rule in rules:
        if rule.get("name") == rule_name:
            return {"id": rule["id"], "index": rule["index"], "name": rule["name"]}
    return None


async def resolve_address_objects(
    client: NautobotClient, names: list[str]
) -> list[str]:
    """Resolve a list of address object names to their UUIDs.

    Raises NautobotError if any name cannot be resolved.
    """
    uuids = []
    for name in names:
        uid = await find_address_object(client, name)
        if uid is None:
            raise NautobotError(f"Address object '{name}' not found")
        uuids.append(uid)
    return uuids


async def resolve_service_objects(
    client: NautobotClient, names: list[str]
) -> list[str]:
    """Resolve a list of service object names to their UUIDs.

    Raises NautobotError if any name cannot be resolved.
    """
    uuids = []
    for name in names:
        uid = await find_service_object(client, name)
        if uid is None:
            raise NautobotError(f"Service object '{name}' not found")
        uuids.append(uid)
    return uuids
