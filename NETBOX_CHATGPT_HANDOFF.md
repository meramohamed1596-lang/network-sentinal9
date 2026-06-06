# Network Sentinel NetBox Handoff for ChatGPT

## Project Context

Network Sentinel is a Python Flask and SQLite network management prototype.

Main features:
- Validate Cisco, Juniper, and Huawei network configuration text.
- Store devices, snapshots, logs, alerts, and topology links.
- Integrate with EVE-NG for lab testing and startup-config uploads.
- Integrate with NetBox for inventory/IPAM synchronization.

The main files are:
- `app.py` - Flask routes and page flow.
- `network_core.py` - SQLite persistence and config parsing helpers.
- `netbox_connector.py` - NetBox REST API connector.
- `eve_connector.py` - EVE-NG REST API connector.
- `templates/settings.html` - Integration settings UI.
- `templates/devices.html` - Device inventory and per-device sync actions.
- `templates/topology.html` - EVE-NG or local inventory topology display.
- `tests/test_integrations.py` - NetBox/EVE/topology regression tests added during this work.

## What We Fixed So Far

### NetBox Connector

Fixed a broken Authorization header in `netbox_connector.py`.

Before, the code used an undefined hard-coded variable:

```python
'Authorization': f'Token {nbt_UM4OrWHyHe7w}'
```

Now it correctly uses the saved API token:

```python
'Authorization': f'Token {api_token}'
```

Added `format_ipam_address()` so plain management IPs are acceptable for NetBox IPAM:

```python
192.168.1.1 -> 192.168.1.1/32
2001:db8::1 -> 2001:db8::1/128
10.0.0.1/24 -> 10.0.0.1/24
```

The device sync flow now uses that formatter before creating NetBox IP address records.

### NetBox Routes

Updated the NetBox API routes in `app.py`:

- `/api/netbox/test`
  - Now tests the values currently typed in the Settings form, not only the values already saved in SQLite.

- `/api/netbox/overview`
  - Now returns a clear failure if no NetBox API token is saved.

- `/api/netbox/sync_all`
  - Now returns a clear failure if no NetBox API token is saved.
  - Now reports partial/full sync failure honestly with:
    - `success`
    - `synced_count`
    - `failed_count`
    - `results`

### Settings Page

Updated `templates/settings.html` so the NetBox Test button sends the current form values as JSON:

```js
fetch('/api/netbox/test', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify(settingsPayload(['netbox_url', 'netbox_token']))
})
```

The UI now reminds the user to click `Save All Settings` before syncing devices.

### Device Sync Flow

Per-device NetBox sync is available from the Devices page:

```text
Devices -> NetBox button on a device card
```

Route:

```text
POST /devices/<device_id>/sync_netbox
```

The route:
- Requires a saved NetBox API token.
- Uses the logged-in user's company as the NetBox tenant name.
- Calls `netbox.sync_device_to_netbox(...)`.
- Saves the NetBox device ID into `devices.netbox_id` when successful.

### Topology Clarification

Local manual topology links were previously shown as `up`, which looked like live connectivity.

Changed wording/UI to:

```text
Inventory Links
Inventory link
```

This matters because a local inventory link is not the same as:
- EVE-NG node link.
- NetBox cable.
- Live device connection.

## Current NetBox Sync Design

`NetBoxConnector.sync_device_to_netbox()` currently:

1. Gets or creates a tenant using the user's company name.
2. Gets or creates a site called `Main Site`.
3. Reads existing NetBox device roles.
4. Reads existing NetBox device types.
5. Chooses the first matching device type by vendor/manufacturer/model, or falls back to the first available type.
6. Checks if the device already exists for the tenant.
7. Creates the NetBox device if missing.
8. Creates a management IP address record if the local device has `ip_address`.

Important limitation:
- NetBox must already have at least one Device Role and at least one Device Type.
- The app does not currently create manufacturers, device types, or roles.
- The created IP address is not currently assigned to a device interface.
- The app does not currently create NetBox interfaces or cables from local topology links.

## What Needs To Be Done For NetBox

### 1. Confirm NetBox Settings

In Network Sentinel Settings:

```text
NetBox URL: http://<netbox-host>:<port>
API Token: <valid NetBox token>
```

Then:

1. Click `Test`.
2. Confirm it reports the NetBox version.
3. Click `Save All Settings`.
4. Go to Devices.
5. Click `NetBox` on a device card.

### 2. Confirm NetBox Token Permissions

The API token needs permission to read and create at least:

- Tenants
- Sites
- Devices
- Device roles
- Device types
- IP addresses

Likely NetBox models:

```text
tenancy.tenant
dcim.site
dcim.device
dcim.devicerole
dcim.devicetype
ipam.ipaddress
```

If we later sync interfaces/cables, it will also need:

```text
dcim.interface
dcim.cable
```

### 3. Confirm Required NetBox Seed Data

Before syncing a device, NetBox should have:

- At least one Device Role, such as `Router`, `Switch`, or `Network Device`.
- At least one Device Type.
- Ideally a Manufacturer matching the local vendor, such as Cisco, Juniper, or Huawei.

If these do not exist, current sync can fail with:

```text
No device roles or types configured in NetBox
```

### 4. Improve Device Type/Role Mapping

Current mapping is very loose:

- Role: first available NetBox role.
- Type: first matching vendor/manufacturer/model, otherwise first available type.

Suggested improvement:

- Map local `device_type` to NetBox role:
  - router -> Router
  - switch -> Switch
  - firewall -> Firewall
  - server -> Server
  - ap -> Access Point

- Map local `vendor` to NetBox manufacturer:
  - cisco -> Cisco
  - juniper -> Juniper
  - huawei -> Huawei

- If a required role/type/manufacturer is missing, return a clear actionable error.

### 5. Improve Management IP Sync

Current behavior:

- Creates an IP address in NetBox IPAM.
- Does not create or assign an interface.
- Does not set the device primary IP.

Recommended next behavior:

1. Create or find an interface, e.g. `mgmt0` or `Management`.
2. Create the IP address with:
   - `assigned_object_type = dcim.interface`
   - `assigned_object_id = <interface id>`
3. PATCH the NetBox device with:
   - `primary_ip4` or `primary_ip6`

### 6. Decide Whether To Sync Local Topology Links To NetBox Cables

Currently local links are only inventory links in SQLite.

Potential future sync:

1. For each local topology link, find the corresponding NetBox devices.
2. Create/find source and target interfaces.
3. Create a NetBox cable between interfaces.

Need to confirm:

- Should local topology links become NetBox cables?
- Should the app create missing interfaces automatically?
- What interface naming convention should be used when the local link has blank interfaces?

### 7. Add Better UI Feedback

Recommended UI improvements:

- On Settings page:
  - Show whether settings are saved or only tested.
  - Show NetBox URL being tested.

- On Devices page:
  - Show NetBox sync failure details near each device.
  - Show NetBox device ID and link to NetBox device detail if possible.

- On Topology page:
  - Separate:
    - Inventory topology
    - EVE-NG topology
    - NetBox cables/topology

## Possible Issues To Ask ChatGPT To Help Debug

Ask ChatGPT to review:

1. Is the current NetBox API endpoint usage compatible with the installed NetBox version?
2. Are the payloads for `dcim/devices/`, `ipam/ip-addresses/`, `dcim/interfaces/`, and `dcim/cables/` correct for the target NetBox version?
3. Should this app create missing Device Roles, Manufacturers, and Device Types, or require them to be pre-created?
4. How should local inventory links map to NetBox Cables?
5. How should management IPs be assigned to devices properly?
6. How should API token permissions be configured securely?
7. What extra regression tests should be added before enabling NetBox cable/interface sync?

## Verification Already Run

Commands already run locally:

```powershell
.\.venv_new\Scripts\python.exe -m unittest discover -s tests
```

Result:

```text
22 tests passed
```

Also run:

```powershell
.\.venv_new\Scripts\python.exe -m compileall app.py network_core.py eve_connector.py netbox_connector.py
```

Authenticated Flask smoke checks rendered these routes with HTTP 200:

```text
/dashboard
/devices
/topology
/configuration
/settings
/logs
/alerts
/snapshots
```

## Suggested Prompt For ChatGPT

Please review this Flask/SQLite Network Sentinel NetBox integration design and suggest the safest next changes. Focus on NetBox API correctness, token permissions, required seed data, assigning management IPs to interfaces, setting primary IPs, and syncing local topology links to NetBox cables. Assume the current code already fixes token handling, settings test behavior, plain IP CIDR formatting, and honest bulk sync failure reporting.
