# Network Sentinel Project Summary

This file summarizes the project for ChatGPT or another developer.

## Short Description

Network Sentinel is a Python Flask/Streamlit network management prototype. It validates Cisco, Juniper, and Huawei network configuration commands, suggests fixes, stores configs and snapshots in SQLite, logs user activity, manages device inventory/topology, and now integrates with EVE-NG for simulation.

The Flask app is the main interface. The Streamlit app is an alternate lightweight interface.

## Stack

- Python 3.14+
- Flask
- Streamlit
- Werkzeug
- Requests
- SQLite
- Jinja templates
- Custom CSS

## Main Files

- `app.py`: Main Flask app with auth, dashboard, config validation, device management, topology, snapshots, logs, alerts, settings, EVE-NG API proxy routes, and NetBox routes.
- `streamlit_app.py`: Alternate Streamlit UI using the same core/database logic.
- `network_core.py`: Shared database, settings, devices, snapshots, logs, alerts, config parsing, vendor detection, and config generation logic.
- `eve_connector.py`: EVE-NG REST API connector for login, lab/node operations, topology, start/stop, console metadata, and startup-config upload.
- `netbox_connector.py`: NetBox REST API connector.
- `schema.sql`: SQLite schema.
- `templates/`: Flask HTML templates.
- `static/style.css`: Flask UI styling.
- `large_network_config.txt`: Sample config used for validation.

## How To Run

```powershell
cd D:\Abdo\Work\network-sentinal
py -3.14 -m venv .venv_new
.\.venv_new\Scripts\python.exe -m pip install -r requirements.txt
.\.venv_new\Scripts\python.exe app.py
```

Open:

```text
http://127.0.0.1:5000
```

Streamlit alternative:

```powershell
.\.venv_new\Scripts\python.exe -m streamlit run streamlit_app.py
```

Open:

```text
http://127.0.0.1:8501
```

## Flask Features

- Register/login/logout.
- Dashboard metrics.
- Config upload/manual input.
- Vendor auto-detection for Cisco/Juniper/Huawei.
- Line-by-line validation.
- Auto-fix suggestions.
- Auto-corrected config output.
- Upload fixed config to an EVE-NG node startup config.
- Device inventory.
- EVE-NG node sync by matching device name to EVE-NG node name.
- EVE-NG topology preview and start/stop controls.
- NetBox sync.
- Manual and automatic config snapshots.
- Logs and alerts.
- Settings for backups, EVE-NG, and NetBox.

## EVE-NG Integration

The app uses EVE-NG as its simulation backend.

Settings now store:

- `eve_url`, for example `http://192.168.1.50`
- `eve_username`, default `admin`
- `eve_password`, default `eve`
- `eve_lab_path`, for example `/Network-Sentinel.unl`

Device records now use:

- `eve_node_id`

Important EVE-NG routes exposed by Flask:

- `/api/eve/test`
- `/api/eve/lab`
- `/api/eve/topology`
- `/api/eve/start_all`
- `/api/eve/stop_all`
- `/api/eve/start_node/<node_id>`
- `/api/eve/stop_node/<node_id>`

`eve_connector.py` logs in through `/api/auth/login`, loads nodes from `/api/labs/<lab>/nodes`, loads topology from `/api/labs/<lab>/topology`, and uploads startup configs through `/api/labs/<lab>/configs/<node_id>`.

## Database

SQLite tables include:

- `users`
- `logs`
- `snapshots`
- `settings`
- `configs`
- `devices`
- `topology_links`
- `validation_rules`
- `alerts`

`network_core.ensure_runtime_schema()` adds missing EVE-NG columns to older existing databases, so users do not need to delete `network_system.db` after the switch.

## Known Caveats

- Flask still uses a hard-coded `SECRET_KEY`.
- Flask runs with `debug=True` when launched directly.
- EVE-NG and NetBox passwords/tokens are stored in plaintext SQLite settings.
- No CSRF protection is visible on forms.
- The NetBox connector has an authorization header bug that should be fixed before serious NetBox use.
- Config upload to EVE-NG writes startup config; the node may need a restart/wipe/reload depending on image behavior.
- Tests exist for config parsing and the EVE-NG connector, but the project does not yet have full integration tests.

## Mental Model For ChatGPT

Describe this as:

"A Python Flask/Streamlit network management prototype called Network Sentinel. It validates Cisco/Juniper/Huawei configs, suggests fixes, stores configs/snapshots in SQLite, logs activity, manages device inventory and topology links, integrates with EVE-NG for simulation, and integrates with NetBox for inventory/IPAM. The main logic is in `network_core.py`; the EVE-NG integration is in `eve_connector.py`; the Flask UI is in `app.py` and `templates/`."
