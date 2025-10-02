# SCM Search Address in Rules

This repository contains a Python utility that helps Strata Cloud Manager (SCM) administrators track where a specific address object appears inside security policies. The script talks to SCM's REST APIs, lists address objects, optionally resolves address group membership (including nested groups), and then scans security rules for direct or indirect references.

## Repository Contents

- `scm_search_address_in_rules.py` – interactive CLI that retrieves address objects and security rules, then guides you through searching for references.
- `scm_search_support.py` – shared constants and helper functions used by the CLI; can be imported by other automation.
- `scm_list_addresses.py` and `scm_list_security_rules.py` – original helper scripts retained for reference.

## Requirements

- Python 3.9 or later. 
- The `requests` library (`pip install requests`).
- API credentials (either a bearer token or client credentials) with permission to read addresses, address groups, and security rules in SCM.

## Authentication

At runtime you can either supply an existing bearer token or let the script obtain one using the OAuth client-credentials flow. When credentials are provided the token request is sent to `https://auth.apps.paloaltonetworks.com/oauth2/access_token` by default, but you can override the URL if your tenant uses a different base.

```text
# option 1: provide an access token directly
python3 scm_search_address_in_rules.py --access-token $SCM_ACCESS_TOKEN --tenant-id 123456789

# option 2: exchange client credentials for a token at runtime
python3 scm_search_address_in_rules.py \
  --client-id "$SCM_CLIENT_ID" \
  --client-secret "$SCM_CLIENT_SECRET" \
  --tenant-id 123456789
```

## Command-Line Arguments

| Flag | Description | Default |
| ---- | ----------- | ------- |
| `--base-url` | SCM API base URL. | `https://api.strata.paloaltonetworks.com` |
| `--address-endpoint` | Endpoint that lists address objects. | `/config/objects/v1/addresses` |
| `--address-groups-endpoint` | Endpoint that lists address groups. | `/config/objects/v1/address-groups` |
| `--rules-endpoint` | Endpoint that lists security rules. | `/config/security/v1/security-rules` |
| `--access-token` | Pre-existing bearer token. | None |
| `--client-id` / `--client-secret` | Credentials used to obtain a token when `--access-token` is omitted. | None |
| `--auth-url` | OAuth token endpoint used for client credentials flow. | `https://auth.apps.paloaltonetworks.com/oauth2/access_token` |
| `--tenant-id` | SCM tenant (TSG) identifier. | *Required* |
| `--folder` | Configuration folder to query (e.g., `Home`, `Shared`). | `Home` |
| `--limit` | Page size for address, group, and rule queries. | `200` or value from `SCM_PAGE_SIZE` |
| `--position` | Policy position filter (`pre`, `post`)
| `--no-rule-details` | Skip per-rule detail lookups (faster, but may omit some references). | Disabled |
| `--no-address-groups` | Skip address-group retrieval (only direct address usage is shown). | Disabled |

Every flag also respects a matching environment variable (`SCM_BASE_URL`, `SCM_LIST_ADDRESSES_PATH`, `SCM_ADDRESS_GROUPS_PATH`, `SCM_SECURITY_RULES_PATH`, `SCM_ACCESS_TOKEN`, `SCM_CLIENT_ID`, `SCM_CLIENT_SECRET`, `SCM_AUTH_URL`, `SCM_TENANT_ID`, `SCM_FOLDER`, `SCM_PAGE_SIZE`, `SCM_POSITION`). Command-line arguments always take precedence.

## Typical Workflow

1. Export any credentials or defaults you prefer, or pass them on the command line.
2. Run the script. Example targeting the *Home* folder and *Post* position:
   ```bash
   python3 scm_search_address_in_rules.py \
     --client-id "$SCM_CLIENT_ID" \
     --client-secret "$SCM_CLIENT_SECRET" \
     --tenant-id 123456789 \
     --folder Home \
     --position post
   ```
3. The script fetches address objects, address groups (unless suppressed), security rules, and optional rule-details.
4. An interactive prompt prints every address object (index, id, folder, and resolved value). Enter one of:
   - The list index (e.g., `12`).
   - The exact object name or id.
   - `list` or `ls` to redisplay the address list.
   - Press `Enter` on a blank line (or `Ctrl-D`) to exit.
5. The script searches all retrieved security rules. Results are grouped as:
   - **Direct matches** – exact string matches on the address’ identifiers (name, id, folder/name, resolved value, etc.).
   - **Group matches** – references that occur because the address is a member of one or more address groups (nested groups are resolved transitively).
6. For each matching rule the script reports:
   - The rule name, id, and position/folder when available.
   - The field paths where each identifier was found (e.g., `source.addresses[0]`).
   - Address group context (group names/folders and which identifiers triggered the match).

### Example Output Fragment

```text
Address is a member of groups: Home/Corp-Servers, Home/DMZ
Security rules referencing 'prod-web-01':
- Allow-Web (id: 1234) [Post]
  direct match on name 'prod-web-01': source.addresses[0]
  via group 'Home/Corp-Servers' (name='Corp-Servers'): source.address-groups[1]
```

## Performance Tips

- Use `--position` to narrow the ruleset (for example `--position Post` for post-rules or `--position Pre` for pre-rules).
- Toggle `--no-rule-details` if the per-rule detail endpoint is slow or rate limited; the trade-off is reduced visibility into nested fields.
- Disable group processing with `--no-address-groups` if you only care about direct references or want faster execution.

## Error Handling & Troubleshooting

- Missing credentials trigger clear fatal messages (for example, “Provide either an access token or client credentials”).
- Problems fetching address groups only emit a warning; rule discovery continues with direct matches.
- API errors include the HTTP status text and body excerpt when available.
- If you see a reference in the UI but not in the output, confirm:
  - You queried the correct folder.
  - You fetched the relevant rule position (`Pre`, `Post`, etc.).
  - Address group processing is enabled so indirect references are captured.

## Development Notes

The script reuses helper functions (`build_url`, `make_headers`, `fetch_addresses`, etc.) exposed by `scm_list_addresses.py`. Static code validation can be performed with:

```bash
python3 -m py_compile scm_search_address_in_rules.py
```

