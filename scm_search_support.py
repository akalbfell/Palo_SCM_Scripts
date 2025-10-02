#!/usr/bin/env python3
"""Interactive helper to list SCM address objects and locate them in security rules."""
from __future__ import annotations

import argparse
import os
from collections import defaultdict
from typing import Any, Dict, Iterable, List, Sequence, Set, Tuple

import requests

DEFAULT_BASE_URL = "https://api.strata.paloaltonetworks.com"
DEFAULT_ADDRESS_ENDPOINT = "/config/objects/v1/addresses"
DEFAULT_ADDRESS_GROUPS_PATH = "/config/objects/v1/address-groups"
DEFAULT_SECURITY_RULES_ENDPOINT = "/config/security/v1/security-rules"
DEFAULT_FOLDER = "Home"
DEFAULT_TENANT_ID = ""
DEFAULT_AUTH_URL = "https://auth.apps.paloaltonetworks.com/oauth2/access_token"


def build_url(base_url: str, endpoint: str) -> str:
    base = base_url.rstrip("/")
    path = "/" + endpoint.lstrip("/")
    return f"{base}{path}"


def is_configured(value: object) -> bool:
    if value is None:
        return False
    if isinstance(value, str) and value.startswith("REPLACE_WITH"):
        return False
    return bool(value)


def make_headers(access_token: str, tenant_id: str) -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {access_token}",
        "X-PAN-SC-TENANT": tenant_id,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def fetch_json(
    url: str,
    headers: Dict[str, str],
    params: Dict[str, Any],
    description: str,
) -> Dict[str, Any]:
    try:
        response = requests.get(url, headers=headers, params=params, timeout=30)
        response.raise_for_status()
    except requests.RequestException as err:
        raise SystemExit(f"{description} request failed: {err}") from err

    try:
        return response.json()
    except ValueError as err:
        raise SystemExit(f"Failed to decode {description} response: {err}") from err


def fetch_addresses(
    url: str,
    headers: Dict[str, str],
    folder: str,
    limit: int,
) -> Dict[str, Any]:
    params = {
        "folder": folder,
        "limit": limit,
    }
    return fetch_json(url, headers, params, "Address list")


def fetch_security_rules(
    url: str,
    headers: Dict[str, str],
    folder: str,
    limit: int,
    position: str | None,
) -> Dict[str, Any]:
    params: Dict[str, Any] = {
        "folder": folder,
        "limit": limit,
    }
    if position:
        params["position"] = position

    return fetch_json(url, headers, params, "Security rules")


def fetch_security_rule_detail(
    base_url: str,
    rule_id: str,
    headers: Dict[str, str],
    folder: str,
) -> Dict[str, Any] | None:
    detail_url = f"{base_url.rstrip('/')}/{rule_id}"
    params = {"folder": folder}

    try:
        response = requests.get(detail_url, headers=headers, params=params, timeout=30)
        response.raise_for_status()
    except requests.HTTPError:
        return None
    except requests.RequestException:
        return None

    try:
        payload = response.json()
    except ValueError:
        return None

    if isinstance(payload, dict):
        nested = payload.get("data")
        if isinstance(nested, dict):
            return nested
        return payload
    return None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "List address objects from Strata Cloud Manager and interactively search "
            "for security rules that reference a chosen object, including matches via "
            "address groups when available."
        )
    )

    parser.add_argument(
        "--base-url",
        default=os.environ.get("SCM_BASE_URL", DEFAULT_BASE_URL),
        help="Base URL for the SCM tenant (default: %(default)s)",
    )
    parser.add_argument(
        "--address-endpoint",
        default=os.environ.get("SCM_LIST_ADDRESSES_PATH", DEFAULT_ADDRESS_ENDPOINT),
        help="Endpoint path used to list address objects (default: %(default)s)",
    )
    parser.add_argument(
        "--address-groups-endpoint",
        default=os.environ.get("SCM_ADDRESS_GROUPS_PATH", DEFAULT_ADDRESS_GROUPS_PATH),
        help="Endpoint path used to list address groups (default: %(default)s)",
    )
    parser.add_argument(
        "--rules-endpoint",
        default=os.environ.get("SCM_SECURITY_RULES_PATH", DEFAULT_SECURITY_RULES_ENDPOINT),
        help="Endpoint path used to list security rules (default: %(default)s)",
    )
    parser.add_argument(
        "--access-token",
        default=os.environ.get("SCM_ACCESS_TOKEN"),
        help="Optional existing OAuth access token for SCM.",
    )
    parser.add_argument(
        "--client-id",
        default=os.environ.get("SCM_CLIENT_ID"),
        help="Client identifier used to obtain an access token when one is not provided.",
    )
    parser.add_argument(
        "--client-secret",
        default=os.environ.get("SCM_CLIENT_SECRET"),
        help="Client secret used with the client identifier to request an access token.",
    )
    parser.add_argument(
        "--auth-url",
        default=os.environ.get("SCM_AUTH_URL", DEFAULT_AUTH_URL),
        help="OAuth token endpoint used for the client credentials flow (default: %(default)s)",
    )
    parser.add_argument(
        "--tenant-id",
        default=os.environ.get("SCM_TENANT_ID", DEFAULT_TENANT_ID),
        help="SCM tenant (TSG) identifier. Defaults to SCM_TENANT_ID env var.",
    )
    parser.add_argument(
        "--folder",
        default=os.environ.get("SCM_FOLDER", DEFAULT_FOLDER),
        help="Configuration folder to query (default: %(default)s)",
    )

    env_page_size = os.environ.get("SCM_PAGE_SIZE")
    default_limit = 200
    if env_page_size:
        try:
            default_limit = int(env_page_size)
        except ValueError:
            pass

    parser.add_argument(
        "--limit",
        type=int,
        default=default_limit,
        help="Maximum number of objects/rules to fetch per request (default: %(default)s)",
    )
    parser.add_argument(
        "--position",
        default=os.environ.get("SCM_POSITION"),
        help="Optional policy position (Pre, Post, etc.) when supported by the API.",
    )
    parser.add_argument(
        "--no-rule-details",
        action="store_true",
        help="Skip per-rule detail lookups (faster, but may miss some references).",
    )
    parser.add_argument(
        "--no-address-groups",
        action="store_true",
        help="Skip address group lookups (only direct references are considered).",
    )
    return parser.parse_args()


def extract_items(payload: Dict[str, Any], candidate_keys: Sequence[str]) -> List[Dict[str, Any]]:
    for key in candidate_keys:
        maybe_items = payload.get(key)
        if isinstance(maybe_items, list):
            return [item for item in maybe_items if isinstance(item, dict)]
    return []


def format_address_value(address: Dict[str, Any]) -> str:
    for key in ("value", "fqdn", "ip_netmask", "ip_range", "ip_wildcard"):
        val = address.get(key)
        if isinstance(val, str) and val:
            return val
    return ""


def show_addresses(addresses: List[Dict[str, Any]]) -> None:
    print("Available address objects:\n")
    for index, address in enumerate(addresses, start=1):
        name = address.get("name") or "<unnamed>"
        address_id = address.get("id") or "<no-id>"
        value = format_address_value(address)
        folder = address.get("folder")
        folder_prefix = f"[{folder}] " if isinstance(folder, str) and folder else ""
        suffix = f" - {value}" if value else ""
        print(f"{index:3}: {folder_prefix}{name} (id: {address_id}){suffix}")
    print()


def resolve_address_selection(
    user_input: str, addresses: List[Dict[str, Any]]
) -> Tuple[int, Dict[str, Any]] | None:
    if user_input.isdigit():
        index = int(user_input) - 1
        if 0 <= index < len(addresses):
            return index, addresses[index]

    lowered = user_input.casefold()
    for idx, address in enumerate(addresses):
        address_id = address.get("id")
        if isinstance(address_id, str) and address_id.casefold() == lowered:
            return idx, address
    for idx, address in enumerate(addresses):
        name = address.get("name")
        if isinstance(name, str) and name.casefold() == lowered:
            return idx, address
    return None


def gather_address_identifiers(address: Dict[str, Any]) -> Dict[str, str]:
    identifiers: Dict[str, str] = {}
    interesting_exact = {
        "id",
        "name",
        "displayname",
        "display_name",
        "objectid",
        "object_id",
        "uuid",
    }
    interesting_suffixes = ("id", "name", "uuid")

    for key, value in address.items():
        if not isinstance(value, str) or not value:
            continue
        lowered = key.casefold()
        if lowered in interesting_exact or any(lowered.endswith(suffix) for suffix in interesting_suffixes):
            identifiers.setdefault(value, key)

    value_str = format_address_value(address)
    if value_str:
        identifiers.setdefault(value_str, "value")

    folder = address.get("folder")
    name = address.get("name")
    if isinstance(folder, str) and folder and isinstance(name, str) and name:
        identifiers.setdefault(f"{folder}/{name}", "folder/name")

    return identifiers


def build_address_identifier_index(
    addresses: List[Dict[str, Any]]
) -> Tuple[List[Dict[str, str]], Dict[str, Set[int]]]:
    identifier_maps: List[Dict[str, str]] = []
    index: Dict[str, Set[int]] = defaultdict(set)

    for idx, address in enumerate(addresses):
        identifiers = gather_address_identifiers(address)
        identifier_maps.append(identifiers)
        for identifier in identifiers:
            index[identifier.casefold()].add(idx)

    return identifier_maps, index


def gather_group_identifiers(group: Dict[str, Any]) -> Dict[str, str]:
    identifiers: Dict[str, str] = {}
    interesting_exact = {
        "id",
        "name",
        "displayname",
        "display_name",
        "objectid",
        "object_id",
        "uuid",
    }
    interesting_suffixes = ("id", "name", "uuid", "uri")

    for key, value in group.items():
        if not isinstance(value, str) or not value:
            continue
        lowered = key.casefold()
        if lowered in interesting_exact or any(lowered.endswith(suffix) for suffix in interesting_suffixes):
            identifiers.setdefault(value, key)

    folder = group.get("folder")
    name = group.get("name")
    if isinstance(folder, str) and folder and isinstance(name, str) and name:
        identifiers.setdefault(f"{folder}/{name}", "folder/name")

    return identifiers


def build_group_identifier_index(
    groups: List[Dict[str, Any]]
) -> Tuple[List[Dict[str, str]], Dict[str, Set[int]]]:
    identifier_maps: List[Dict[str, str]] = []
    index: Dict[str, Set[int]] = defaultdict(set)

    for idx, group in enumerate(groups):
        identifiers = gather_group_identifiers(group)
        identifier_maps.append(identifiers)
        for identifier in identifiers:
            index[identifier.casefold()].add(idx)

    return identifier_maps, index


def collect_group_member_strings(group: Dict[str, Any]) -> Set[str]:
    membership_strings: Set[str] = set()
    hint_keys = {
        "static",
        "dynamic",
        "members",
        "member",
        "entries",
        "entry",
        "addresses",
        "address",
        "objects",
        "object",
        "targets",
        "target",
        "selected",
        "selection",
        "children",
        "elements",
    }

    def _walk(node: Any, hinted: bool) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                lowered = key.casefold()
                is_hint = hinted or lowered in hint_keys or lowered.endswith("members") or lowered.endswith("addresses")
                _walk(value, is_hint)
        elif isinstance(node, list):
            for item in node:
                _walk(item, hinted)
        elif isinstance(node, str):
            if hinted:
                membership_strings.add(node)
        elif isinstance(node, (int, float)):
            if hinted:
                membership_strings.add(str(node))

    _walk(group, False)
    return membership_strings


def build_group_relationships(
    groups: List[Dict[str, Any]],
    address_identifier_index: Dict[str, Set[int]],
    group_identifier_index: Dict[str, Set[int]],
) -> Tuple[Dict[int, Set[int]], Dict[int, Set[int]]]:
    direct_members: Dict[int, Set[int]] = {idx: set() for idx in range(len(groups))}
    group_links: Dict[int, Set[int]] = {idx: set() for idx in range(len(groups))}

    for idx, group in enumerate(groups):
        for candidate in collect_group_member_strings(group):
            key = candidate.casefold()
            for address_idx in address_identifier_index.get(key, set()):
                direct_members[idx].add(address_idx)
            for group_idx in group_identifier_index.get(key, set()):
                if group_idx != idx:
                    group_links[idx].add(group_idx)

    return direct_members, group_links


def compute_group_address_closure(
    direct_members: Dict[int, Set[int]],
    group_links: Dict[int, Set[int]],
) -> Dict[int, Set[int]]:
    resolved: Dict[int, Set[int]] = {}

    def _resolve(group_idx: int, visiting: Set[int]) -> Set[int]:
        if group_idx in resolved:
            return resolved[group_idx]
        if group_idx in visiting:
            return set()

        visiting.add(group_idx)
        addresses = set(direct_members.get(group_idx, set()))
        for child_idx in group_links.get(group_idx, set()):
            addresses.update(_resolve(child_idx, visiting))
        visiting.remove(group_idx)

        resolved[group_idx] = addresses
        return addresses

    for idx in set(direct_members.keys()).union(group_links.keys()):
        _resolve(idx, set())

    for idx in group_links.keys():
        resolved.setdefault(idx, set())

    return resolved


def build_address_to_groups_map(
    group_address_closure: Dict[int, Set[int]]
) -> Dict[int, List[int]]:
    mapping: Dict[int, List[int]] = defaultdict(list)
    for group_idx, address_indices in group_address_closure.items():
        for address_idx in address_indices:
            mapping[address_idx].append(group_idx)

    for address_idx, group_list in list(mapping.items()):
        mapping[address_idx] = sorted(set(group_list))

    return dict(mapping)


def build_target_catalog(
    address: Dict[str, Any],
    address_identifiers: Dict[str, str],
    group_indices: Sequence[int],
    groups: List[Dict[str, Any]],
    group_identifier_maps: List[Dict[str, str]],
) -> Dict[str, Dict[str, Any]]:
    catalog: Dict[str, Dict[str, Any]] = {}
    address_name = address.get("name") or address.get("id") or "(unknown)"

    for identifier, source in address_identifiers.items():
        if not identifier:
            continue
        entry = catalog.setdefault(identifier, {"identifier": identifier})
        entry.setdefault("address_sources", set()).add(source)
        entry["address_name"] = address_name

    value_str = format_address_value(address)
    if value_str:
        entry = catalog.setdefault(value_str, {"identifier": value_str})
        entry.setdefault("address_sources", set()).add("value")
        entry["address_name"] = address_name

    folder = address.get("folder")
    if isinstance(folder, str) and folder and isinstance(address_name, str) and address_name:
        combined = f"{folder}/{address_name}"
        entry = catalog.setdefault(combined, {"identifier": combined})
        entry.setdefault("address_sources", set()).add("folder/name")
        entry["address_name"] = address_name

    for group_idx in group_indices:
        if not (0 <= group_idx < len(groups)):
            continue
        group = groups[group_idx]
        group_identifiers = (
            group_identifier_maps[group_idx] if group_idx < len(group_identifier_maps) else {}
        )
        group_name = group.get("name") or group.get("id") or "(unnamed)"
        group_folder = group.get("folder")

        for identifier, source in group_identifiers.items():
            if not identifier:
                continue
            entry = catalog.setdefault(identifier, {"identifier": identifier})
            entry.setdefault("groups", [])
            entry["groups"].append(
                {
                    "name": group_name,
                    "id": group.get("id"),
                    "folder": group_folder,
                    "source": source,
                }
            )

        if isinstance(group_folder, str) and group_folder and group_name:
            combined = f"{group_folder}/{group_name}"
            entry = catalog.setdefault(combined, {"identifier": combined})
            entry.setdefault("groups", [])
            entry["groups"].append(
                {
                    "name": group_name,
                    "id": group.get("id"),
                    "folder": group_folder,
                    "source": "folder/name",
                }
            )

    for entry in catalog.values():
        sources = entry.get("address_sources")
        if isinstance(sources, set):
            entry["address_sources"] = sorted(sources)

    return catalog


def find_rule_matches(
    rule: Dict[str, Any],
    target_catalog: Dict[str, Dict[str, Any]],
) -> Dict[str, List[str]]:
    if not target_catalog:
        return {}

    lookup = {identifier.casefold(): identifier for identifier in target_catalog}
    matches: Dict[str, Set[str]] = defaultdict(set)

    def _search(node: Any, path: List[str]) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                _search(value, path + [str(key)])
        elif isinstance(node, list):
            for idx, item in enumerate(node):
                _search(item, path + [f"[{idx}]"])
        elif isinstance(node, str):
            canonical = lookup.get(node.casefold())
            if canonical:
                matches[canonical].add(".".join(path))
        elif isinstance(node, (int, float)):
            canonical = lookup.get(str(node).casefold())
            if canonical:
                matches[canonical].add(".".join(path))

    _search(rule, [])
    return {identifier: sorted(paths) for identifier, paths in matches.items()}


def ensure_configuration(args: argparse.Namespace) -> None:
    missing = []
    if not is_configured(args.tenant_id):
        missing.append("tenant id")
    if missing:
        raise SystemExit(
            "Missing required arguments: "
            + ", ".join(missing)
            + ". Provide values via CLI options or environment variables."
        )


def request_access_token(auth_url: str, client_id: str, client_secret: str) -> str:
    payload = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
    }
    try:
        response = requests.post(auth_url, data=payload, timeout=30)
        response.raise_for_status()
    except requests.RequestException as err:
        raise SystemExit(f"Token request failed: {err}") from err

    try:
        data = response.json()
    except ValueError as err:
        raise SystemExit(f"Unable to decode token response: {err}") from err

    token = data.get("access_token")
    if not isinstance(token, str) or not token:
        raise SystemExit("Token response missing 'access_token'.")
    return token


def resolve_access_token(args: argparse.Namespace) -> str:
    if is_configured(args.access_token):
        return args.access_token

    missing = []
    if not is_configured(args.client_id):
        missing.append("client id")
    if not is_configured(args.client_secret):
        missing.append("client secret")
    if missing:
        raise SystemExit(
            "Provide either an access token or client credentials. Missing: "
            + ", ".join(missing)
        )

    return request_access_token(args.auth_url, args.client_id, args.client_secret)


def enrich_rules(
    rules: List[Dict[str, Any]],
    rule_url: str,
    headers: Dict[str, str],
    folder: str,
) -> List[Dict[str, Any]]:
    enriched: List[Dict[str, Any]] = []
    for rule in rules:
        rule_id = rule.get("id")
        if not isinstance(rule_id, str):
            enriched.append(rule)
            continue
        detail = fetch_security_rule_detail(rule_url, rule_id, headers, folder)
        if isinstance(detail, dict) and detail:
            merged = {**rule, **detail}
            enriched.append(merged)
        else:
            enriched.append(rule)
    return enriched


def interactive_loop(
    addresses: List[Dict[str, Any]],
    rules: List[Dict[str, Any]],
    address_identifier_maps: List[Dict[str, str]],
    address_groups_map: Dict[int, List[int]],
    groups: List[Dict[str, Any]],
    group_identifier_maps: List[Dict[str, str]],
) -> None:
    show_addresses(addresses)
    if not rules:
        print("No security rules returned from the API; nothing to search.")
        return

    print("Enter the list index, name, or id of an address object to search for.")
    print("Press Enter on an empty line to exit. Type 'list' to reprint address objects.\n")

    while True:
        try:
            user_input = input("Address selection> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            break

        if not user_input:
            print("Done.")
            break
        if user_input.casefold() in {"list", "ls"}:
            show_addresses(addresses)
            continue

        selection = resolve_address_selection(user_input, addresses)
        if not selection:
            print("Could not find an address with that reference. Try again.")
            continue

        index, address = selection
        address_identifiers = (
            address_identifier_maps[index] if index < len(address_identifier_maps) else {}
        )
        group_indices = address_groups_map.get(index, [])
        target_catalog = build_target_catalog(
            address,
            address_identifiers,
            group_indices,
            groups,
            group_identifier_maps,
        )

        if group_indices:
            labels: List[str] = []
            for group_idx in group_indices:
                if 0 <= group_idx < len(groups):
                    group = groups[group_idx]
                    label = group.get("name") or group.get("id") or "<unnamed>"
                    folder = group.get("folder")
                    if isinstance(folder, str) and folder:
                        label = f"{folder}/{label}"
                    labels.append(label)
            if labels:
                unique_labels = ", ".join(sorted(set(labels)))
                print(f"Address is a member of groups: {unique_labels}")

        matching_rules: List[Tuple[Dict[str, Any], Dict[str, List[str]]]] = []
        for rule in rules:
            matches = find_rule_matches(rule, target_catalog)
            if matches:
                matching_rules.append((rule, matches))

        name = address.get("name") or address.get("id") or "(unknown)"
        if not matching_rules:
            print(f"No security rules reference '{name}'.\n")
            continue

        print(f"Security rules referencing '{name}':")
        for rule, matches in matching_rules:
            rule_name = rule.get("name") or "<unnamed>"
            rule_id = rule.get("id") or "<no-id>"
            location = rule.get("position") or rule.get("folder") or ""
            location_suffix = f" [{location}]" if location else ""
            print(f"- {rule_name} (id: {rule_id}){location_suffix}")

            direct_lines: Set[str] = set()
            group_matches: Dict[str, List[Tuple[str, str, List[str]]]] = defaultdict(list)

            for identifier, paths in matches.items():
                entry = target_catalog.get(identifier, {})
                address_sources = entry.get("address_sources") or []
                if address_sources:
                    source_desc = "/".join(address_sources)
                    direct_lines.add(
                        f"  direct match on {source_desc} '{identifier}': " + ", ".join(paths)
                    )
                for group_meta in entry.get("groups", []):
                    group_name = group_meta.get("name") or group_meta.get("id") or "<unnamed>"
                    folder = group_meta.get("folder")
                    if isinstance(folder, str) and folder:
                        group_label = f"{folder}/{group_name}"
                    else:
                        group_label = group_name
                    source = group_meta.get("source") or ""
                    group_matches[group_label].append((identifier, source, paths))

            for line in sorted(direct_lines):
                print(line)

            for group_label in sorted(group_matches):
                entries = group_matches[group_label]
                unique_paths = sorted({path for _, _, paths in entries for path in paths})
                detail_parts = sorted(
                    {
                        f"{source}='{identifier}'" if source else f"identifier '{identifier}'"
                        for identifier, source, _ in entries
                    }
                )
                if detail_parts:
                    detail_str = "; ".join(detail_parts)
                    print(f"  via group '{group_label}' ({detail_str}): " + ", ".join(unique_paths))
                else:
                    print(f"  via group '{group_label}': " + ", ".join(unique_paths))
        print()


def main() -> None:
    args = parse_args()
    ensure_configuration(args)

    access_token = resolve_access_token(args)

    base_url = args.base_url.rstrip("/")
    address_url = build_url(base_url, args.address_endpoint)
    rules_url = build_url(base_url, args.rules_endpoint)
    headers = make_headers(access_token, args.tenant_id)

    address_payload = fetch_addresses(address_url, headers, args.folder, args.limit)
    addresses = extract_items(address_payload, ("data", "items", "objects"))
    if not addresses:
        print("No address objects returned from SCM.")
        return

    address_identifier_maps, address_identifier_index = build_address_identifier_index(addresses)

    groups: List[Dict[str, Any]] = []
    group_identifier_maps: List[Dict[str, str]] = []
    address_groups_map: Dict[int, List[int]] = {}

    if not args.no_address_groups:
        address_groups_url = build_url(base_url, args.address_groups_endpoint)
        try:
            group_payload = fetch_addresses(address_groups_url, headers, args.folder, args.limit)
        except SystemExit as err:
            print(f"Warning: unable to fetch address groups ({err}). Continuing without group matching.")
        else:
            groups = extract_items(group_payload, ("data", "items", "objects", "groups"))
            if groups:
                group_identifier_maps, group_identifier_index = build_group_identifier_index(groups)
                direct_members, group_links = build_group_relationships(
                    groups, address_identifier_index, group_identifier_index
                )
                group_address_closure = compute_group_address_closure(direct_members, group_links)
                address_groups_map = build_address_to_groups_map(group_address_closure)

    rules_payload = fetch_security_rules(
        rules_url,
        headers,
        args.folder,
        args.limit,
        args.position,
    )
    rules = extract_items(rules_payload, ("data", "items", "rules"))

    if not args.no_rule_details and rules:
        rules = enrich_rules(rules, rules_url, headers, args.folder)

    interactive_loop(
        addresses,
        rules,
        address_identifier_maps,
        address_groups_map,
        groups,
        group_identifier_maps,
    )


if __name__ == "__main__":
    main()
