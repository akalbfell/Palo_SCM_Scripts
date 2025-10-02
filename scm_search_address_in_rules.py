#!/usr/bin/env python3
"""Thin CLI wrapper that relies on :mod:`scm_search_support` for core logic."""
from __future__ import annotations

import scm_search_support as support


def main() -> None:
    args = support.parse_args()
    support.ensure_configuration(args)

    access_token = support.resolve_access_token(args)

    base_url = args.base_url.rstrip("/")
    address_url = support.build_url(base_url, args.address_endpoint)
    rules_url = support.build_url(base_url, args.rules_endpoint)
    headers = support.make_headers(access_token, args.tenant_id)

    address_payload = support.fetch_addresses(address_url, headers, args.folder, args.limit)
    addresses = support.extract_items(address_payload, ("data", "items", "objects"))
    if not addresses:
        print("No address objects returned from SCM.")
        return

    address_identifier_maps, address_identifier_index = support.build_address_identifier_index(addresses)

    groups: list[dict[str, object]] = []
    group_identifier_maps: list[dict[str, str]] = []
    address_groups_map: dict[int, list[int]] = {}

    if not args.no_address_groups:
        address_groups_url = support.build_url(base_url, args.address_groups_endpoint)
        try:
            group_payload = support.fetch_addresses(address_groups_url, headers, args.folder, args.limit)
        except SystemExit as err:
            print(f"Warning: unable to fetch address groups ({err}). Continuing without group matching.")
        else:
            groups = support.extract_items(group_payload, ("data", "items", "objects", "groups"))
            if groups:
                group_identifier_maps, group_identifier_index = support.build_group_identifier_index(groups)
                direct_members, group_links = support.build_group_relationships(
                    groups, address_identifier_index, group_identifier_index
                )
                group_address_closure = support.compute_group_address_closure(direct_members, group_links)
                address_groups_map = support.build_address_to_groups_map(group_address_closure)

    rules_payload = support.fetch_security_rules(
        rules_url,
        headers,
        args.folder,
        args.limit,
        args.position,
    )
    rules = support.extract_items(rules_payload, ("data", "items", "rules"))

    if not args.no_rule_details and rules:
        rules = support.enrich_rules(rules, rules_url, headers, args.folder)

    support.interactive_loop(
        addresses,
        rules,
        address_identifier_maps,
        address_groups_map,
        groups,
        group_identifier_maps,
    )


if __name__ == "__main__":
    main()
