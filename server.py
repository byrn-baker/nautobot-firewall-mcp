"""Nautobot Firewall MCP Server — manages firewall security models in Nautobot."""

from __future__ import annotations

import json
import logging
import os
import sys
from typing import Optional

from fastmcp import FastMCP

from nautobot_client import NautobotError

# ---------------------------------------------------------------------------
# Logging — all logs go to stderr so stdout stays clean for stdio transport
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("nautobot-firewall-mcp")

# ---------------------------------------------------------------------------
# Environment variable validation (Requirement 9.6)
# ---------------------------------------------------------------------------
_missing: list[str] = []
if not os.environ.get("NAUTOBOT_URL"):
    _missing.append("NAUTOBOT_URL")
if not os.environ.get("NAUTOBOT_TOKEN"):
    _missing.append("NAUTOBOT_TOKEN")

if _missing:
    logger.error("Missing required environment variables: %s", ", ".join(_missing))
    sys.exit(1)

# ---------------------------------------------------------------------------
# FastMCP instance and shared Nautobot client
# ---------------------------------------------------------------------------
mcp = FastMCP("nautobot-firewall-mcp")

from nautobot_client import NautobotClient  # noqa: E402

client = NautobotClient()

# ---------------------------------------------------------------------------
# ITSM Gate (Requirements 8.1, 8.2, 8.3, 8.4)
# ---------------------------------------------------------------------------
ITSM_ENABLED: bool = os.environ.get("ITSM_ENABLED", "false").lower() == "true"
ITSM_LAB_MODE: bool = os.environ.get("ITSM_LAB_MODE", "true").lower() == "true"


def _check_itsm(cr_number: Optional[str]) -> Optional[str]:
    """Return error message if ITSM blocks this write, else None."""
    if ITSM_ENABLED and not ITSM_LAB_MODE:
        if not cr_number:
            return "Write operation blocked: ITSM is enabled. Provide a cr_number parameter."
    return None


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

from firewall_helpers import (  # noqa: E402
    find_address_object,
    find_nat_policy,
    find_nat_policy_rule,
    find_policy,
    find_policy_rule,
    find_service_object,
    find_zone,
    resolve_address_objects,
    resolve_service_objects,
    _esc,
)


@mcp.tool()
async def firewall_get_policies(device: Optional[str] = None) -> str:
    """List firewall policies with assigned devices and rule counts.

    Args:
        device: If provided, filter policies assigned to this device name.

    Returns:
        JSON string with list of policies including rule_count field.
    """
    query = """
{
  policies {
    id name status { name } description
    assigned_devices { name }
    policy_rules { id name index action }
  }
}
"""
    try:
        data = await client.graphql(query)
        policies = data.get("policies", [])

        if device:
            policies = [
                p for p in policies
                if any(d["name"] == device for d in p.get("assigned_devices", []))
            ]

        for p in policies:
            p["rule_count"] = len(p.get("policy_rules", []))

        return json.dumps(policies)
    except NautobotError as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Read Tools (GraphQL-based)
# ---------------------------------------------------------------------------

@mcp.tool()
async def firewall_get_zones(device: Optional[str] = None) -> str:
    """List security zones with their associated interfaces and VRFs.

    Args:
        device: Optional device name to filter zones by interface membership.

    Returns:
        JSON string with list of zones, or error object on failure.
    """
    try:
        query = """{
  zones {
    id name status { name } description
    interfaces { name device { name } }
    vrfs { name }
  }
}"""
        data = await client.graphql(query)
        zones = data.get("zones", [])

        if device:
            zones = [
                z for z in zones
                if any(
                    iface.get("device", {}).get("name") == device
                    for iface in z.get("interfaces", [])
                )
            ]

        return json.dumps(zones)
    except NautobotError as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
async def firewall_get_address_objects(search_term: Optional[str] = None) -> str:
    """List or search address objects with their associated IP, prefix, range, or FQDN details.

    Args:
        search_term: Optional substring to filter address objects by name (case-insensitive).

    Returns:
        JSON string with list of address objects, or error object on failure.
    """
    query = """{
  address_objects {
    id name status { name } description
    ip_address { address }
    prefix { prefix }
    ip_range { start_address end_address }
    fqdn { name }
  }
}"""
    try:
        data = await client.graphql(query)
        objects = data.get("address_objects", [])

        if search_term:
            term_lower = search_term.lower()
            objects = [
                obj for obj in objects
                if term_lower in obj.get("name", "").lower()
            ]

        return json.dumps(objects)
    except NautobotError as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
async def firewall_get_service_objects(search_term: Optional[str] = None) -> str:
    """List/search service objects with protocol, port, and status.

    Args:
        search_term: Optional filter — matches name, ip_protocol, or port (case-insensitive).

    Returns:
        JSON array of service objects, or {"error": "..."} on failure.
    """
    query = """{
  service_objects {
    id name ip_protocol port status { name } description
  }
}"""
    try:
        data = await client.graphql(query)
        objects = data.get("service_objects", [])
        if search_term:
            term = search_term.lower()
            objects = [
                obj for obj in objects
                if term in (obj.get("name") or "").lower()
                or term in (obj.get("ip_protocol") or "").lower()
                or term in (obj.get("port") or "").lower()
            ]
        return json.dumps(objects)
    except NautobotError as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Policy Rules Tool
# ---------------------------------------------------------------------------


@mcp.tool()
async def firewall_get_policy_rules(policy_name: str, device: Optional[str] = None) -> str:
    """Get ordered firewall policy rules with full detail (zones, addresses, services, action).

    Args:
        policy_name: Name of the firewall policy to retrieve rules for.
        device: Optional device name to disambiguate policies with the same name.

    Returns:
        JSON array of policy rules sorted by index ascending, or an error object.
    """
    try:
        policy_id = await find_policy(client, policy_name, device)
        if not policy_id:
            return json.dumps({"error": f"Policy '{policy_name}' not found"})

        query = f"""{{
  policy_rules(policy: "{_esc(policy_id)}") {{
    id name index action log status {{ name }} description
    source_zone {{ name }}
    destination_zone {{ name }}
    source_addresses {{ name }}
    source_address_groups {{ name }}
    destination_addresses {{ name }}
    destination_address_groups {{ name }}
    source_services {{ name }}
    source_service_groups {{ name }}
    destination_services {{ name }}
    destination_service_groups {{ name }}
  }}
}}"""
        data = await client.graphql(query)
        rules = data.get("policy_rules", [])
        sorted_rules = sorted(rules, key=lambda r: r.get("index", 0))
        return json.dumps(sorted_rules)
    except NautobotError as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# NAT Policy Tools
# ---------------------------------------------------------------------------


@mcp.tool()
async def firewall_get_nat_policies(device: Optional[str] = None) -> str:
    """List NAT policies with assigned devices and rules.

    Args:
        device: If provided, filter NAT policies assigned to this device name.

    Returns:
        JSON string with list of NAT policies, or error object on failure.
    """
    query = """{
  nat_policies {
    id name status { name } description
    assigned_devices { name }
    nat_policy_rules { id name index }
  }
}"""
    try:
        data = await client.graphql(query)
        nat_policies = data.get("nat_policies", [])

        if device:
            nat_policies = [
                p for p in nat_policies
                if any(d["name"] == device for d in p.get("assigned_devices", []))
            ]

        return json.dumps(nat_policies)
    except NautobotError as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Write Tools (REST-based, ITSM-gated)
# ---------------------------------------------------------------------------


@mcp.tool()
async def firewall_create_zone(
    name: str,
    interfaces: Optional[list[str]] = None,
    vrfs: Optional[list[str]] = None,
    description: Optional[str] = None,
    cr_number: Optional[str] = None,
) -> str:
    """Create a security zone in Nautobot. Idempotent — returns existing zone if name matches.

    Args:
        name: Zone name (e.g., 'INSIDE', 'OUTSIDE', 'DMZ').
        interfaces: Optional list of interface names to associate with the zone.
        vrfs: Optional list of VRF names to associate with the zone.
        description: Optional description for the zone.
        cr_number: Change request number (required when ITSM is enabled).

    Returns:
        JSON with status ('created' or 'exists'), zone id, and name.
    """
    try:
        # 1. Check ITSM gate
        itsm_err = _check_itsm(cr_number)
        if itsm_err:
            return json.dumps({"error": itsm_err})

        # 2. Idempotency check
        existing_id = await find_zone(client, name)
        if existing_id:
            return json.dumps({"status": "exists", "id": existing_id, "name": name})

        # 3. Resolve interface UUIDs
        interface_uuids = []
        if interfaces:
            for iface_name in interfaces:
                query = f'{{ interfaces(name: "{_esc(iface_name)}") {{ id }} }}'
                data = await client.graphql(query)
                results = data.get("interfaces", [])
                if not results:
                    return json.dumps({"error": f"Interface '{iface_name}' not found"})
                interface_uuids.append(results[0]["id"])

        # 4. Resolve VRF UUIDs
        vrf_uuids = []
        if vrfs:
            for vrf_name in vrfs:
                query = f'{{ vrfs(name: "{_esc(vrf_name)}") {{ id }} }}'
                data = await client.graphql(query)
                results = data.get("vrfs", [])
                if not results:
                    return json.dumps({"error": f"VRF '{vrf_name}' not found"})
                vrf_uuids.append(results[0]["id"])

        # 5. POST to create zone
        payload = {
            "name": name,
            "interfaces": interface_uuids,
            "vrfs": vrf_uuids,
            "status": {"name": "Active"},
            "description": description or "",
        }
        result = await client.rest_post("plugins/firewall/zone", payload)

        # 6. Return created zone
        return json.dumps({
            "status": "created",
            "id": result.get("id"),
            "name": result.get("name", name),
        })

    except NautobotError as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
async def firewall_delete_zone(name: str, cr_number: Optional[str] = None) -> str:
    """Delete a security zone from Nautobot.

    The zone must not be referenced by any policy rules. If it is in use,
    an error is returned instead of deleting.

    Args:
        name: Name of the security zone to delete.
        cr_number: Optional ITSM change request number (required when ITSM is enforced).

    Returns:
        JSON string with deletion confirmation, or error object on failure.
    """
    try:
        # ITSM gate check
        itsm_error = _check_itsm(cr_number)
        if itsm_error:
            return json.dumps({"error": itsm_error})

        # Resolve zone UUID
        zone_id = await find_zone(client, name)
        if not zone_id:
            return json.dumps({"error": f"Zone '{name}' not found"})

        # Referential safety: check if any policy rules reference this zone
        ref_query = "{ policy_rules { id source_zone { id } destination_zone { id } } }"
        ref_data = await client.graphql(ref_query)
        policy_rules = ref_data.get("policy_rules", [])

        for rule in policy_rules:
            src_zone = rule.get("source_zone")
            dst_zone = rule.get("destination_zone")
            if (src_zone and src_zone.get("id") == zone_id) or (
                dst_zone and dst_zone.get("id") == zone_id
            ):
                return json.dumps(
                    {"error": f"Zone '{name}' is referenced by policy rules and cannot be deleted"}
                )

        # Delete the zone
        await client.rest_delete(f"plugins/firewall/zone/{zone_id}")

        return json.dumps({"status": "deleted", "name": name})
    except NautobotError as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
async def firewall_create_address_object(
    name: str,
    type: str,
    value: str,
    description: Optional[str] = None,
    cr_number: Optional[str] = None,
) -> str:
    """Create an address object in Nautobot. Idempotent — returns existing object if name matches.

    Args:
        name: Address object name (e.g., 'web-server', 'internal-net').
        type: Object type — one of 'host', 'network', 'range', 'fqdn'.
        value: The address value. For host: IP address (e.g., '10.0.1.50/32').
               For network: prefix (e.g., '10.0.1.0/24').
               For range: 'start-end' format (e.g., '10.0.1.100-10.0.1.200').
               For fqdn: domain name (e.g., 'app.example.com').
        description: Optional description for the address object.
        cr_number: Change request number (required when ITSM is enabled).

    Returns:
        JSON with status ('created' or 'exists'), object id, name, and type.
    """
    try:
        # 1. Validate type
        valid_types = ("host", "network", "range", "fqdn")
        if type not in valid_types:
            return json.dumps({
                "error": "Invalid address object type. Must be one of: host, network, range, fqdn"
            })

        # 2. Check ITSM gate
        itsm_err = _check_itsm(cr_number)
        if itsm_err:
            return json.dumps({"error": itsm_err})

        # 3. Idempotency check
        existing_id = await find_address_object(client, name)
        if existing_id:
            return json.dumps({"status": "exists", "id": existing_id, "name": name})

        # 4. Build POST body based on type
        payload: dict = {
            "name": name,
            "status": {"name": "Active"},
        }
        if description:
            payload["description"] = description

        if type == "host":
            payload["ip_address"] = {"address": value}
        elif type == "network":
            payload["prefix"] = {"prefix": value}
        elif type == "range":
            # Parse "start-end" format
            parts = value.split("-", 1)
            if len(parts) != 2:
                return json.dumps({
                    "error": "Range value must be in 'start-end' format (e.g., '10.0.1.100-10.0.1.200')"
                })
            payload["ip_range"] = {
                "start_address": parts[0].strip(),
                "end_address": parts[1].strip(),
            }
        elif type == "fqdn":
            payload["fqdn"] = {"name": value}

        # 5. POST to create address object
        result = await client.rest_post("plugins/firewall/address-object", payload)

        # 6. Return created object
        return json.dumps({
            "status": "created",
            "id": result.get("id"),
            "name": result.get("name", name),
            "type": type,
        })

    except NautobotError as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
async def firewall_create_service_object(
    name: str,
    protocol: str,
    port: Optional[str] = None,
    description: Optional[str] = None,
    cr_number: Optional[str] = None,
) -> str:
    """Create a firewall service object (e.g., TCP/443, UDP/53, ICMP). Idempotent.

    Args:
        name: Service object name (e.g., "HTTPS", "DNS-UDP", "PING").
        protocol: IP protocol — "TCP", "UDP", "ICMP", etc.
        port: Port number ("443"), range ("1024-65535"), or omit for protocol-only (ICMP).
        description: Optional description.
        cr_number: Change request number (required when ITSM is enforced).

    Returns:
        JSON with status "created" or "exists", or error object on failure.
    """
    try:
        # ITSM gate check
        itsm_err = _check_itsm(cr_number)
        if itsm_err:
            return json.dumps({"error": itsm_err})

        # Idempotency check
        existing_id = await find_service_object(client, name)
        if existing_id:
            return json.dumps({"status": "exists", "id": existing_id, "name": name})

        # Build request body
        body: dict = {
            "name": name,
            "ip_protocol": protocol,
            "status": {"name": "Active"},
            "description": description or "",
        }

        # Only include port if provided (omit for ICMP / protocol-only)
        if port:
            body["port"] = port

        # Create via REST
        result = await client.rest_post("plugins/firewall/service-object", body)

        return json.dumps({
            "status": "created",
            "id": result.get("id"),
            "name": result.get("name", name),
            "protocol": protocol,
            "port": port,
        })
    except NautobotError as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
async def firewall_delete_service_object(
    name: str, cr_number: Optional[str] = None
) -> str:
    """Delete a service object from Nautobot.

    The service object must not be referenced by any policy rules. If it is
    in use as a source or destination service, an error is returned instead
    of deleting.

    Args:
        name: Name of the service object to delete.
        cr_number: Optional ITSM change request number (required when ITSM is enforced).

    Returns:
        JSON string with deletion confirmation, or error object on failure.
    """
    try:
        # 1. ITSM gate check
        itsm_err = _check_itsm(cr_number)
        if itsm_err:
            return json.dumps({"error": itsm_err})

        # 2. Find the service object
        object_id = await find_service_object(client, name)
        if not object_id:
            return json.dumps({"error": f"Service object '{name}' not found"})

        # 3. Check policy rule references (referential safety)
        ref_query = """{ policy_rules { id source_services { id } destination_services { id } } }"""
        ref_data = await client.graphql(ref_query)
        policy_rules = ref_data.get("policy_rules", [])

        for rule in policy_rules:
            src_svcs = rule.get("source_services") or []
            dst_svcs = rule.get("destination_services") or []
            for svc in src_svcs:
                if svc.get("id") == object_id:
                    return json.dumps(
                        {"error": f"Service object '{name}' is referenced by policy rules and cannot be deleted"}
                    )
            for svc in dst_svcs:
                if svc.get("id") == object_id:
                    return json.dumps(
                        {"error": f"Service object '{name}' is referenced by policy rules and cannot be deleted"}
                    )

        # 4. Delete the service object
        await client.rest_delete(f"plugins/firewall/service-object/{object_id}")

        # 5. Return success
        return json.dumps({"status": "deleted", "name": name})

    except NautobotError as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
async def firewall_create_policy(
    name: str,
    device: Optional[str] = None,
    description: Optional[str] = None,
    cr_number: Optional[str] = None,
) -> str:
    """Create a firewall policy in Nautobot. Idempotent — returns existing policy if name matches.

    Args:
        name: Policy name (e.g., 'OUTSIDE-TO-INSIDE', 'DMZ-POLICY').
        device: Optional device name to assign the policy to.
        description: Optional description for the policy.
        cr_number: Change request number (required when ITSM is enabled).

    Returns:
        JSON with status ('created' or 'exists'), policy id, and name.
    """
    try:
        # 1. Check ITSM gate
        itsm_err = _check_itsm(cr_number)
        if itsm_err:
            return json.dumps({"error": itsm_err})

        # 2. Idempotency check
        existing_id = await find_policy(client, name, device)
        if existing_id:
            return json.dumps({"status": "exists", "id": existing_id, "name": name})

        # 3. Resolve device UUID if provided
        device_uuids = []
        if device:
            query = f'{{ devices(name: "{_esc(device)}") {{ id }} }}'
            data = await client.graphql(query)
            results = data.get("devices", [])
            if not results:
                return json.dumps({"error": f"Device '{device}' not found"})
            device_uuids.append(results[0]["id"])

        # 4. POST to create policy
        payload = {
            "name": name,
            "assigned_devices": device_uuids,
            "status": {"name": "Active"},
            "description": description or "",
        }
        result = await client.rest_post("plugins/firewall/policy", payload)

        # 5. Return created policy
        return json.dumps({
            "status": "created",
            "id": result.get("id"),
            "name": result.get("name", name),
        })

    except NautobotError as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
async def firewall_create_policy_rule(
    policy: str,
    name: str,
    source_zone: Optional[str] = None,
    dest_zone: Optional[str] = None,
    source_addresses: Optional[list[str]] = None,
    dest_addresses: Optional[list[str]] = None,
    source_services: Optional[list[str]] = None,
    dest_services: Optional[list[str]] = None,
    action: str = "permit",
    index: Optional[int] = None,
    log: bool = False,
    cr_number: Optional[str] = None,
) -> str:
    """Create a firewall policy rule with zone, address, and service bindings.

    The rule is appended to the end of the policy by default. If an index is
    specified, existing rules at or above that index are shifted to make room.

    Args:
        policy: Name of the firewall policy to add the rule to.
        name: Rule name (e.g., 'allow-web-traffic', 'deny-all').
        source_zone: Optional source security zone name.
        dest_zone: Optional destination security zone name.
        source_addresses: Optional list of source address object names.
        dest_addresses: Optional list of destination address object names.
        source_services: Optional list of source service object names.
        dest_services: Optional list of destination service object names.
        action: Rule action — 'permit' or 'deny' (default: 'permit').
        index: Optional position to insert the rule. If omitted, appends to end.
        log: Whether to enable logging for this rule (default: False).
        cr_number: Change request number (required when ITSM is enabled).

    Returns:
        JSON with status 'created', rule id, name, index, and policy name.
    """
    try:
        # 1. Check ITSM gate
        itsm_err = _check_itsm(cr_number)
        if itsm_err:
            return json.dumps({"error": itsm_err})

        # 2. Resolve policy UUID
        policy_id = await find_policy(client, policy)
        if not policy_id:
            return json.dumps({"error": f"Policy '{policy}' not found"})

        # 3. Resolve source zone UUID (if provided)
        source_zone_id = None
        if source_zone:
            source_zone_id = await find_zone(client, source_zone)
            if not source_zone_id:
                return json.dumps({"error": f"Source zone '{source_zone}' not found"})

        # 4. Resolve destination zone UUID (if provided)
        dest_zone_id = None
        if dest_zone:
            dest_zone_id = await find_zone(client, dest_zone)
            if not dest_zone_id:
                return json.dumps({"error": f"Destination zone '{dest_zone}' not found"})

        # 5. Resolve address object UUIDs (if provided)
        source_addr_uuids: list[str] = []
        if source_addresses:
            source_addr_uuids = await resolve_address_objects(client, source_addresses)

        dest_addr_uuids: list[str] = []
        if dest_addresses:
            dest_addr_uuids = await resolve_address_objects(client, dest_addresses)

        # 6. Resolve service object UUIDs (if provided)
        source_svc_uuids: list[str] = []
        if source_services:
            source_svc_uuids = await resolve_service_objects(client, source_services)

        dest_svc_uuids: list[str] = []
        if dest_services:
            dest_svc_uuids = await resolve_service_objects(client, dest_services)

        # 7. Determine rule index
        # Query existing rules for this policy
        rules_query = f"""{{
  policy_rules(policy: "{_esc(policy_id)}") {{
    id name index
  }}
}}"""
        rules_data = await client.graphql(rules_query)
        existing_rules = rules_data.get("policy_rules", [])

        if index is None:
            # Auto-assign: max existing index + 1, default 1 if no rules
            if existing_rules:
                max_index = max(r.get("index", 0) for r in existing_rules)
                rule_index = max_index + 1
            else:
                rule_index = 1
        else:
            # Insert at specified index: shift existing rules at >= index
            rule_index = index
            rules_to_shift = [
                r for r in existing_rules if r.get("index", 0) >= index
            ]
            # Sort descending to avoid conflicts when incrementing
            rules_to_shift.sort(key=lambda r: r.get("index", 0), reverse=True)
            for rule in rules_to_shift:
                await client.rest_patch(
                    f"plugins/firewall/policy-rule/{rule['id']}",
                    {"index": rule["index"] + 1},
                )

        # 8. POST new rule
        payload: dict = {
            "name": name,
            "policy": policy_id,
            "index": rule_index,
            "action": action,
            "log": log,
            "status": {"name": "Active"},
            "source_addresses": source_addr_uuids,
            "destination_addresses": dest_addr_uuids,
            "source_services": source_svc_uuids,
            "destination_services": dest_svc_uuids,
        }

        if source_zone_id:
            payload["source_zone"] = source_zone_id
        if dest_zone_id:
            payload["destination_zone"] = dest_zone_id

        result = await client.rest_post("plugins/firewall/policy-rule", payload)

        # 9. Return created rule
        return json.dumps({
            "status": "created",
            "id": result.get("id"),
            "name": result.get("name", name),
            "index": rule_index,
            "policy": policy,
        })

    except NautobotError as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
async def firewall_delete_address_object(
    name: str, cr_number: Optional[str] = None
) -> str:
    """Delete an address object from Nautobot.

    The address object must not be referenced by any policy rules. If it is
    in use as a source or destination address, an error is returned instead
    of deleting.

    Args:
        name: Name of the address object to delete.
        cr_number: Optional ITSM change request number (required when ITSM is enforced).

    Returns:
        JSON string with deletion confirmation, or error object on failure.
    """
    try:
        # 1. ITSM gate check
        itsm_err = _check_itsm(cr_number)
        if itsm_err:
            return json.dumps({"error": itsm_err})

        # 2. Find the address object
        object_id = await find_address_object(client, name)
        if not object_id:
            return json.dumps({"error": f"Address object '{name}' not found"})

        # 3. Check policy rule references (referential safety)
        ref_query = """{ policy_rules { id source_addresses { id } destination_addresses { id } } }"""
        ref_data = await client.graphql(ref_query)
        policy_rules = ref_data.get("policy_rules", [])

        for rule in policy_rules:
            src_addrs = rule.get("source_addresses") or []
            dst_addrs = rule.get("destination_addresses") or []
            for addr in src_addrs:
                if addr.get("id") == object_id:
                    return json.dumps(
                        {"error": f"Address object '{name}' is referenced by policy rules and cannot be deleted"}
                    )
            for addr in dst_addrs:
                if addr.get("id") == object_id:
                    return json.dumps(
                        {"error": f"Address object '{name}' is referenced by policy rules and cannot be deleted"}
                    )

        # 4. Delete the address object
        await client.rest_delete(f"plugins/firewall/address-object/{object_id}")

        # 5. Return success
        return json.dumps({"status": "deleted", "name": name})

    except NautobotError as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
async def firewall_create_nat_policy(
    name: str,
    device: Optional[str] = None,
    description: Optional[str] = None,
    cr_number: Optional[str] = None,
) -> str:
    """Create a NAT policy in Nautobot. Idempotent — returns existing policy if name matches.

    Args:
        name: NAT policy name (e.g., 'NAT-OUTSIDE', 'PAT-INSIDE').
        device: Optional device name to assign this NAT policy to.
        description: Optional description for the NAT policy.
        cr_number: Change request number (required when ITSM is enabled).

    Returns:
        JSON with status ('created' or 'exists'), policy id, and name.
    """
    try:
        # 1. Check ITSM gate
        itsm_err = _check_itsm(cr_number)
        if itsm_err:
            return json.dumps({"error": itsm_err})

        # 2. Idempotency check
        existing_id = await find_nat_policy(client, name, device)
        if existing_id:
            return json.dumps({"status": "exists", "id": existing_id, "name": name})

        # 3. Resolve device UUID if provided
        device_uuids: list[str] = []
        if device:
            query = f'{{ devices(name: "{_esc(device)}") {{ id }} }}'
            data = await client.graphql(query)
            results = data.get("devices", [])
            if not results:
                return json.dumps({"error": f"Device '{device}' not found"})
            device_uuids.append(results[0]["id"])

        # 4. POST to create NAT policy
        payload = {
            "name": name,
            "assigned_devices": device_uuids,
            "status": {"name": "Active"},
            "description": description or "",
        }
        result = await client.rest_post("plugins/firewall/nat-policy", payload)

        # 5. Return created policy
        return json.dumps({
            "status": "created",
            "id": result.get("id"),
            "name": result.get("name", name),
        })

    except NautobotError as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
async def firewall_create_nat_rule(
    nat_policy: str,
    name: str,
    original_source: Optional[str] = None,
    translated_source: Optional[str] = None,
    original_destination: Optional[str] = None,
    translated_destination: Optional[str] = None,
    index: Optional[int] = None,
    cr_number: Optional[str] = None,
) -> str:
    """Create a NAT rule within a NAT policy. Auto-assigns index if not provided.

    Args:
        nat_policy: Name of the NAT policy to add the rule to.
        name: Name for the NAT rule (e.g., 'PAT-INSIDE-OUT', 'STATIC-WEB').
        original_source: Optional address object name for the original source.
        translated_source: Optional address object name for the translated source.
        original_destination: Optional address object name for the original destination.
        translated_destination: Optional address object name for the translated destination.
        index: Optional rule position. If omitted, appends to end of policy.
        cr_number: Change request number (required when ITSM is enabled).

    Returns:
        JSON with status 'created', rule id, name, index, and nat_policy name.
    """
    try:
        # 1. Check ITSM gate
        itsm_err = _check_itsm(cr_number)
        if itsm_err:
            return json.dumps({"error": itsm_err})

        # 2. Resolve NAT policy UUID
        nat_policy_id = await find_nat_policy(client, nat_policy)
        if not nat_policy_id:
            return json.dumps({"error": f"NAT policy '{nat_policy}' not found"})

        # 3. Resolve address object UUIDs for each provided parameter
        orig_src_uuid = None
        if original_source:
            orig_src_uuid = await find_address_object(client, original_source)
            if not orig_src_uuid:
                return json.dumps({"error": f"Address object '{original_source}' not found"})

        trans_src_uuid = None
        if translated_source:
            trans_src_uuid = await find_address_object(client, translated_source)
            if not trans_src_uuid:
                return json.dumps({"error": f"Address object '{translated_source}' not found"})

        orig_dst_uuid = None
        if original_destination:
            orig_dst_uuid = await find_address_object(client, original_destination)
            if not orig_dst_uuid:
                return json.dumps({"error": f"Address object '{original_destination}' not found"})

        trans_dst_uuid = None
        if translated_destination:
            trans_dst_uuid = await find_address_object(client, translated_destination)
            if not trans_dst_uuid:
                return json.dumps({"error": f"Address object '{translated_destination}' not found"})

        # 4. Auto-assign index if not provided
        if index is None:
            query = f"""{{
  nat_policy_rules(nat_policy: "{_esc(nat_policy_id)}") {{
    id index
  }}
}}"""
            data = await client.graphql(query)
            existing_rules = data.get("nat_policy_rules", [])
            if existing_rules:
                max_index = max(r.get("index", 0) for r in existing_rules)
                index = max_index + 1
            else:
                index = 1

        # 5. POST to create NAT policy rule
        payload: dict = {
            "name": name,
            "nat_policy": nat_policy_id,
            "original_source": orig_src_uuid,
            "translated_source": trans_src_uuid,
            "original_destination": orig_dst_uuid,
            "translated_destination": trans_dst_uuid,
            "index": index,
        }
        result = await client.rest_post("plugins/firewall/nat-policy-rule", payload)

        # 6. Return created rule
        return json.dumps({
            "status": "created",
            "id": result.get("id"),
            "name": result.get("name", name),
            "index": index,
            "nat_policy": nat_policy,
        })

    except NautobotError as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
async def firewall_delete_policy_rule(
    policy: str,
    rule_name: str,
    cr_number: Optional[str] = None,
) -> str:
    """Delete a firewall policy rule and re-index remaining rules to close the gap.

    After deletion, rules that had a higher index than the deleted rule are
    decremented by 1 to maintain a contiguous index sequence.

    Args:
        policy: Name of the firewall policy containing the rule.
        rule_name: Name of the rule to delete.
        cr_number: Change request number (required when ITSM is enabled).

    Returns:
        JSON with status 'deleted', rule_name, and policy name, or error object.
    """
    try:
        # 1. Check ITSM gate
        itsm_err = _check_itsm(cr_number)
        if itsm_err:
            return json.dumps({"error": itsm_err})

        # 2. Resolve policy UUID
        policy_id = await find_policy(client, policy)
        if not policy_id:
            return json.dumps({"error": f"Policy '{policy}' not found"})

        # 3. Find rule by name within policy
        rule_info = await find_policy_rule(client, policy_id, rule_name)
        if not rule_info:
            return json.dumps({"error": f"Rule '{rule_name}' not found in policy '{policy}'"})

        rule_id = rule_info["id"]
        deleted_index = rule_info["index"]

        # 4. DELETE the rule
        await client.rest_delete(f"plugins/firewall/policy-rule/{rule_id}")

        # 5. Query remaining rules for the policy
        remaining_query = f"""{{
  policy_rules(policy: "{_esc(policy_id)}") {{
    id name index
  }}
}}"""
        remaining_data = await client.graphql(remaining_query)
        remaining_rules = remaining_data.get("policy_rules", [])

        # 6. Re-index: decrement index for rules that were above the deleted rule
        rules_to_shift = [
            r for r in remaining_rules if r.get("index", 0) > deleted_index
        ]
        # Sort ascending so we patch from lowest to highest
        rules_to_shift.sort(key=lambda r: r.get("index", 0))
        for rule in rules_to_shift:
            await client.rest_patch(
                f"plugins/firewall/policy-rule/{rule['id']}",
                {"index": rule["index"] - 1},
            )

        # 7. Return success
        return json.dumps({
            "status": "deleted",
            "rule_name": rule_name,
            "policy": policy,
        })

    except NautobotError as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
async def firewall_move_policy_rule(
    policy: str,
    rule_name: str,
    new_index: int,
    cr_number: Optional[str] = None,
) -> str:
    """Move a firewall policy rule to a new position within its policy.

    Reorders surrounding rules to maintain contiguous indices.

    Args:
        policy: Name of the firewall policy containing the rule.
        rule_name: Name of the rule to move.
        new_index: Target index position for the rule.
        cr_number: Change request number (required when ITSM is enabled).

    Returns:
        JSON with status 'moved', rule_name, old_index, and new_index.
    """
    try:
        # 1. Check ITSM gate
        itsm_err = _check_itsm(cr_number)
        if itsm_err:
            return json.dumps({"error": itsm_err})

        # 2. Resolve policy UUID
        policy_id = await find_policy(client, policy)
        if not policy_id:
            return json.dumps({"error": f"Policy '{policy}' not found"})

        # 3. Find rule by name within policy
        rule_info = await find_policy_rule(client, policy_id, rule_name)
        if not rule_info:
            return json.dumps({"error": f"Rule '{rule_name}' not found in policy '{policy}'"})

        rule_id = rule_info["id"]
        old_index = rule_info["index"]

        # 4. No-op if already at target index
        if new_index == old_index:
            return json.dumps({
                "status": "moved",
                "rule_name": rule_name,
                "old_index": old_index,
                "new_index": new_index,
            })

        # 5. Get all rules for the policy to compute shifts
        rules_query = f"""{{
  policy_rules(policy: "{_esc(policy_id)}") {{
    id name index
  }}
}}"""
        rules_data = await client.graphql(rules_query)
        all_rules = rules_data.get("policy_rules", [])

        # 6. Compute move and shift affected rules
        if new_index > old_index:
            # Moving DOWN: shift rules in range (old_index+1 ... new_index) UP by decrementing index
            affected = [
                r for r in all_rules
                if r["id"] != rule_id and old_index < r.get("index", 0) <= new_index
            ]
            for r in affected:
                await client.rest_patch(
                    f"plugins/firewall/policy-rule/{r['id']}",
                    {"index": r["index"] - 1},
                )
        else:
            # Moving UP: shift rules in range (new_index ... old_index-1) DOWN by incrementing index
            affected = [
                r for r in all_rules
                if r["id"] != rule_id and new_index <= r.get("index", 0) < old_index
            ]
            # Sort descending to avoid index collisions when incrementing
            affected.sort(key=lambda r: r.get("index", 0), reverse=True)
            for r in affected:
                await client.rest_patch(
                    f"plugins/firewall/policy-rule/{r['id']}",
                    {"index": r["index"] + 1},
                )

        # 7. PATCH target rule to new_index
        await client.rest_patch(
            f"plugins/firewall/policy-rule/{rule_id}",
            {"index": new_index},
        )

        # 8. Return result
        return json.dumps({
            "status": "moved",
            "rule_name": rule_name,
            "old_index": old_index,
            "new_index": new_index,
        })

    except NautobotError as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
async def firewall_delete_nat_rule(
    nat_policy: str,
    rule_name: str,
    cr_number: Optional[str] = None,
) -> str:
    """Delete a NAT rule from a NAT policy and re-index remaining rules.

    After deletion, remaining rules are re-indexed to maintain a contiguous
    sequence with no gaps.

    Args:
        nat_policy: Name of the NAT policy containing the rule.
        rule_name: Name of the NAT rule to delete.
        cr_number: Change request number (required when ITSM is enabled).

    Returns:
        JSON with status 'deleted', rule_name, and nat_policy, or error object on failure.
    """
    try:
        # 1. Check ITSM gate
        itsm_err = _check_itsm(cr_number)
        if itsm_err:
            return json.dumps({"error": itsm_err})

        # 2. Resolve NAT policy UUID
        nat_policy_id = await find_nat_policy(client, nat_policy)
        if not nat_policy_id:
            return json.dumps({"error": f"NAT policy '{nat_policy}' not found"})

        # 3. Find rule by name within NAT policy
        rule_info = await find_nat_policy_rule(client, nat_policy_id, rule_name)
        if not rule_info:
            return json.dumps({"error": f"NAT rule '{rule_name}' not found in policy '{nat_policy}'"})

        rule_id = rule_info["id"]
        deleted_index = rule_info["index"]

        # 4. DELETE the rule
        await client.rest_delete(f"plugins/firewall/nat-policy-rule/{rule_id}")

        # 5. Query remaining NAT rules for the policy
        remaining_query = f"""{{
  nat_policy_rules(nat_policy: "{_esc(nat_policy_id)}") {{
    id index
  }}
}}"""
        remaining_data = await client.graphql(remaining_query)
        remaining_rules = remaining_data.get("nat_policy_rules", [])

        # 6. Re-index: for each remaining rule where index > deleted_index, decrement by 1
        rules_to_shift = [
            r for r in remaining_rules if r.get("index", 0) > deleted_index
        ]
        # Sort ascending so we update in order
        rules_to_shift.sort(key=lambda r: r.get("index", 0))
        for rule in rules_to_shift:
            new_idx = rule["index"] - 1
            await client.rest_patch(
                f"plugins/firewall/nat-policy-rule/{rule['id']}",
                {"index": new_idx},
            )

        # 7. Return success
        return json.dumps({
            "status": "deleted",
            "rule_name": rule_name,
            "nat_policy": nat_policy,
        })

    except NautobotError as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Reconciliation Tool
# ---------------------------------------------------------------------------


@mcp.tool()
async def firewall_reconcile_rules(device: str, live_rules: str) -> str:
    """Compare Nautobot modeled firewall rules against live pfSense rules to detect drift.

    Normalizes both Nautobot policy rules and live pfSense rules into a common format,
    then compares using a composite key of (source, destination, destination_port, protocol).

    Args:
        device: Device name to retrieve modeled policies for.
        live_rules: JSON array string of live firewall rules in pfSense MCP format.
                    Each entry should have: type, protocol, source, destination,
                    destination_port fields.

    Returns:
        JSON drift report with in_nautobot_not_live, in_live_not_nautobot,
        action_mismatch arrays, and an in_sync boolean.
    """
    try:
        # 1. Parse live_rules JSON
        try:
            live_rules_parsed = json.loads(live_rules)
        except (json.JSONDecodeError, TypeError) as e:
            return json.dumps({"error": f"Invalid JSON in live_rules: {e}"})

        if not isinstance(live_rules_parsed, list):
            return json.dumps({"error": "live_rules must be a JSON array"})

        # 2. Query Nautobot policies assigned to the device with full rule detail
        query = """{
  policies {
    id name
    assigned_devices { name }
    policy_rules {
      name action
      source_addresses { name ip_address { address } prefix { prefix } }
      destination_addresses { name ip_address { address } prefix { prefix } }
      destination_services { name ip_protocol port }
    }
  }
}"""
        data = await client.graphql(query)
        policies = data.get("policies", [])

        # Filter policies assigned to this device
        device_policies = [
            p for p in policies
            if any(d["name"] == device for d in p.get("assigned_devices", []))
        ]

        # 3. Normalize Nautobot rules
        nautobot_normalized = []
        for policy in device_policies:
            for rule in policy.get("policy_rules", []):
                normalized = _normalize_nautobot_rule(rule)
                nautobot_normalized.append(normalized)

        # 4. Normalize live rules
        live_normalized = []
        for entry in live_rules_parsed:
            normalized = _normalize_live_rule(entry)
            live_normalized.append(normalized)

        # 5. Compare using composite key (source, destination, destination_port, protocol)
        nb_by_key = {}
        for rule in nautobot_normalized:
            key = (rule["source"], rule["destination"], rule["destination_port"], rule["protocol"])
            nb_by_key[key] = rule

        live_by_key = {}
        for rule in live_normalized:
            key = (rule["source"], rule["destination"], rule["destination_port"], rule["protocol"])
            live_by_key[key] = rule

        nb_keys = set(nb_by_key.keys())
        live_keys = set(live_by_key.keys())

        # 6. Build drift report
        in_nautobot_not_live = [
            nb_by_key[k] for k in sorted(nb_keys - live_keys)
        ]
        in_live_not_nautobot = [
            live_by_key[k] for k in sorted(live_keys - nb_keys)
        ]
        action_mismatch = []
        for k in sorted(nb_keys & live_keys):
            nb_action = nb_by_key[k]["action"]
            live_action = live_by_key[k]["action"]
            if nb_action != live_action:
                action_mismatch.append({
                    "source": k[0],
                    "destination": k[1],
                    "destination_port": k[2],
                    "protocol": k[3],
                    "nautobot_action": nb_action,
                    "live_action": live_action,
                })

        in_sync = (
            len(in_nautobot_not_live) == 0
            and len(in_live_not_nautobot) == 0
            and len(action_mismatch) == 0
        )

        return json.dumps({
            "device": device,
            "nautobot_rule_count": len(nautobot_normalized),
            "live_rule_count": len(live_normalized),
            "in_sync": in_sync,
            "drift": {
                "in_nautobot_not_live": in_nautobot_not_live,
                "in_live_not_nautobot": in_live_not_nautobot,
                "action_mismatch": action_mismatch,
            },
        })

    except NautobotError as e:
        return json.dumps({"error": str(e)})


def _normalize_nautobot_rule(rule: dict) -> dict:
    """Normalize a Nautobot policy rule to the common comparison format.

    Extracts the first source/destination address and first destination service
    from the rule's relationship arrays.
    """
    # Extract source address
    source = "any"
    src_addrs = rule.get("source_addresses") or []
    if src_addrs:
        addr_obj = src_addrs[0]
        ip_addr = addr_obj.get("ip_address")
        prefix = addr_obj.get("prefix")
        if ip_addr and ip_addr.get("address"):
            source = ip_addr["address"]
        elif prefix and prefix.get("prefix"):
            source = prefix["prefix"]

    # Extract destination address
    destination = "any"
    dst_addrs = rule.get("destination_addresses") or []
    if dst_addrs:
        addr_obj = dst_addrs[0]
        ip_addr = addr_obj.get("ip_address")
        prefix = addr_obj.get("prefix")
        if ip_addr and ip_addr.get("address"):
            destination = ip_addr["address"]
        elif prefix and prefix.get("prefix"):
            destination = prefix["prefix"]

    # Extract destination service (port + protocol)
    destination_port = ""
    protocol = ""
    dst_svcs = rule.get("destination_services") or []
    if dst_svcs:
        svc = dst_svcs[0]
        destination_port = str(svc.get("port", "") or "")
        protocol = str(svc.get("ip_protocol", "") or "")

    # Map Nautobot action to pfSense action
    action_map = {"permit": "pass", "deny": "block", "reject": "reject"}
    raw_action = rule.get("action", "")
    action = action_map.get(raw_action, raw_action)

    return {
        "source": source,
        "destination": destination,
        "destination_port": destination_port,
        "protocol": protocol,
        "action": action,
    }


def _normalize_live_rule(entry: dict) -> dict:
    """Normalize a live pfSense rule entry to the common comparison format."""
    source = entry.get("source") or "any"
    destination = entry.get("destination") or "any"
    destination_port = str(entry.get("destination_port", "") or "")
    protocol = str(entry.get("protocol", "") or "")
    action = str(entry.get("type", "") or "")

    return {
        "source": source,
        "destination": destination,
        "destination_port": destination_port,
        "protocol": protocol,
        "action": action,
    }


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    mcp.run(transport="stdio")
