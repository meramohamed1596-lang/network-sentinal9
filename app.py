import os
import json
from datetime import datetime, timedelta
from functools import wraps
from threading import Thread
from time import sleep
from flask import Flask, redirect, render_template, request, session, url_for, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from network_core import (
    DATABASE,
    DEFAULT_BACKUP_MINUTES,
    init_db,
    query_db,
    execute_db,
    parse_network_config,
    summarize_config_risk,
    build_fix_review,
    build_config_diff,
    split_config_blocks,
    review_security_baseline,
    build_security_reviewed_config,
    detect_vendor,
    generate_device_config,
    save_snapshot,
    add_log,
    get_backup_interval,
    ensure_default_settings,
    get_user_settings,
    update_user_settings,
    get_user_by_email,
    get_user_by_id,
    create_user,
    get_user_snapshots,
    get_snapshot_by_id,
    delete_snapshot,
    get_user_logs,
    get_all_logs,
    save_user_config,
    get_last_config,
    add_device,
    get_user_devices,
    get_device_by_id,
    get_device_by_name,
    update_device_status,
    update_device_eve_id,
    update_device_netbox_id,
    delete_device,
    save_device_config_application,
    get_latest_device_config_application,
    get_device_config_applications,
    get_user_latest_device_applications,
    infer_topology_links,
    add_link,
    add_link_if_missing,
    get_user_links,
    delete_link,
    create_alert,
    get_user_alerts,
    resolve_alert,
    create_network_group,
    get_user_network_groups,
    get_network_group_by_id,
    get_network_group_by_name,
    delete_network_group,
    get_devices_by_group,
    create_network_snapshot,
    get_user_network_snapshots,
    get_network_snapshot_by_id,
    delete_network_snapshot,
    get_devices_by_snapshot,
)
from eve_connector import get_eve_connector, EVENGConnector
from netbox_connector import get_netbox_connector, NetBoxConnector

app = Flask(__name__)
app.config.from_mapping(
    SECRET_KEY=os.environ.get('SECRET_KEY', 'network-sentinel-dev-secret-key'),
    DATABASE=DATABASE,
)


# =============================================================================
# BACKGROUND WORKER: Auto Backup
# =============================================================================

def backup_worker():
    while True:
        with app.app_context():
            try:
                users = query_db('SELECT id FROM users')
                if users:
                    for user in users:
                        interval = get_backup_interval(user['id'])
                        recent = query_db(
                            'SELECT created_at FROM snapshots WHERE user_id = ? ORDER BY created_at DESC LIMIT 1',
                            (user['id'],), one=True
                        )
                        if recent is None or datetime.fromisoformat(recent['created_at']) + timedelta(minutes=interval) <= datetime.now():
                            config = query_db('SELECT config_text FROM configs WHERE user_id = ? ORDER BY updated_at DESC LIMIT 1', (user['id'],), one=True)
                            if config:
                                save_snapshot(user['id'], f'Auto backup {datetime.now().strftime("%Y-%m-%d %H:%M")}', config['config_text'], snapshot_type='auto')
            except Exception as e:
                print(f"Error in backup worker: {e}")
        sleep(60)


backup_thread = None


def start_backup_worker():
    """Start the backup worker once for direct app runs."""
    global backup_thread
    if os.environ.get('NETWORK_SENTINEL_DISABLE_BACKUP_WORKER') == '1':
        return None
    if backup_thread and backup_thread.is_alive():
        return backup_thread
    backup_thread = Thread(target=backup_worker, daemon=True)
    backup_thread.start()
    return backup_thread


# =============================================================================
# AUTH DECORATORS
# =============================================================================

def login_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return view(**kwargs)
    return wrapped_view


def admin_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        user = get_user_by_id(session['user_id'])
        if user['role'] != 'admin':
            flash('Access denied. Admin only.', 'danger')
            return redirect(url_for('dashboard'))
        return view(**kwargs)
    return wrapped_view


# =============================================================================
# CONTEXT PROCESSOR - inject global template variables
# =============================================================================

@app.context_processor
def inject_globals():
    if 'user_id' in session:
        user = get_user_by_id(session['user_id'])
        settings = get_user_settings(session['user_id']) if user else None
        alerts = get_user_alerts(session['user_id'], resolved=0) if user else []
        devices = get_user_devices(session['user_id']) if user else []
        return dict(
            current_user=user,
            user_settings=settings,
            unread_alerts=len(alerts) if alerts else 0,
            user_devices=devices,
        )
    return dict(current_user=None, user_settings=None, unread_alerts=0, user_devices=[])


def merge_settings_payload(user_settings, fields):
    """Merge saved settings with submitted integration fields."""
    merged = dict(user_settings) if user_settings else {}
    payload = request.get_json(silent=True) or request.form.to_dict()
    for field in fields:
        if field in payload:
            value = payload.get(field)
            merged[field] = value.strip() if isinstance(value, str) else value
    return merged


def build_inventory_topology(devices, links, application_map=None, network_groups_map=None, snapshot_id=None):
    """Build a display-only topology from local inventory records."""
    application_map = application_map or {}
    network_groups_map = network_groups_map or {}
    return {
        'nodes': [
            {
                'id': str(device['id']),
                'device_id': device['id'],
                'device_url': f'/devices/{device["id"]}',
                'name': device['name'],
                'type': device['device_type'],
                'status': 'inventory',
                'vendor': device['vendor'],
                'network_group': device['network_group'] if 'network_group' in device.keys() else None,
                'network_group_name': network_groups_map.get(str(device['network_group'])) if 'network_group' in device.keys() and device['network_group'] else None,
                'snapshot_id': snapshot_id,
                'application_state': (
                    application_map.get(device['id'])['application_state']
                    if application_map.get(device['id']) else 'not_configured'
                ),
                'application_label': application_state_label(
                    application_map.get(device['id'])['application_state']
                    if application_map.get(device['id']) else 'not_configured'
                ),
            }
            for device in devices
        ],
        'links': [{
            'id': str(link['id']),
            'source_id': str(link['source_device_id']),
            'target_id': str(link['target_device_id']),
            'source_port': link['source_interface'] or '',
            'target_port': link['target_interface'] or '',
            'source_name': link['source_name'],
            'target_name': link['target_name'],
            'status': 'inventory',
        } for link in links],
        'node_count': len(devices),
        'link_count': len(links),
        'source': 'inventory',
        'snapshot_id': snapshot_id,
    }


APPLICATION_STATE_LABELS = {
    'uploaded_eve': 'Applied Preview',
    'local_preview': 'Local Preview',
    'blocked': 'Blocked',
    'needs_mapping': 'Needs Mapping',
    'upload_failed': 'Upload Failed',
    'not_configured': 'No Config',
}


def application_state_label(state):
    return APPLICATION_STATE_LABELS.get(state or 'not_configured', state or 'No Config')


def _match_eve_node_by_name(eve, device):
    if not hasattr(eve, 'get_nodes'):
        return None
    nodes_result = eve.get_nodes()
    if not nodes_result.get('success'):
        return None
    for node in nodes_result.get('nodes', []):
        if node.get('name') == device['name']:
            return node.get('id')
    return None


def apply_config_to_lab_or_preview(user_id, device, raw_config, corrected_config, vendor, source='configuration'):
    """Store an application record as a local network preview."""
    corrected_result = parse_network_config(corrected_config, vendor=vendor or 'auto')
    corrected_summary = summarize_config_risk(corrected_result)
    validation_state = corrected_summary['state']
    eve_node_id = None
    eve_result = {'message': 'Stored inside Network Sentinel as a local network preview.'}
    application_state = 'local_preview'

    if validation_state == 'blocked':
        application_state = 'blocked'
        eve_result = {'success': False, 'error': 'Corrected configuration still has blocking validation errors.'}

    app_id = save_device_config_application(
        user_id,
        device['id'],
        source,
        raw_config,
        corrected_config,
        corrected_result.get('vendor', vendor or device['vendor']),
        validation_state,
        application_state,
        eve_node_id,
        eve_result,
    )

    if application_state == 'uploaded_eve':
        update_device_status(device['id'], 'configured')
        add_log(user_id, 'hybrid_lab_upload', f'Applied reviewed preview for {device["name"]}')
        create_alert(user_id, device['id'], 'hybrid_lab_upload', 'info',
                     f'Configuration applied as a preview for {device["name"]}')
    elif application_state == 'local_preview':
        update_device_status(device['id'], 'preview')
        add_log(user_id, 'hybrid_lab_preview', f'Stored local network preview for {device["name"]}')
    elif application_state == 'blocked':
        add_log(user_id, 'hybrid_lab_blocked', f'Blocked lab application for {device["name"]}')
    else:
        add_log(user_id, 'hybrid_lab_upload_failed',
                f'Failed preview save for {device["name"]}: {eve_result.get("error", "Unknown error")}')

    return {
        'id': app_id,
        'application_state': application_state,
        'application_label': application_state_label(application_state),
        'validation_state': validation_state,
        'eve_node_id': eve_node_id,
        'eve_result': eve_result,
    }


# =============================================================================
# AUTH ROUTES
# =============================================================================

@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = get_user_by_email(email)
        if user and check_password_hash(user['password_hash'], password):
            session.clear()
            session['user_id'] = user['id']
            session['username'] = user['name']
            add_log(user['id'], 'login', 'User logged in', request.remote_addr)
            ensure_default_settings(user['id'])
            return redirect(url_for('dashboard'))
        flash('Invalid email or password.', 'danger')
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name'].strip()
        company = request.form['company'].strip()
        email = request.form['email'].strip()
        password = request.form['password']

        if not all([name, company, email, password]):
            flash('All fields are required.', 'danger')
            return render_template('register.html')

        if get_user_by_email(email):
            flash('Email already registered.', 'warning')
            return render_template('register.html')

        user_id = create_user(name, company, email, generate_password_hash(password))
        add_log(user_id, 'register', f'New account created for {name} ({company})')
        flash('Account created! Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/logout')
def logout():
    if 'user_id' in session:
        add_log(session['user_id'], 'logout', 'User logged out')
    session.clear()
    return redirect(url_for('login'))


# =============================================================================
# DASHBOARD
# =============================================================================

@app.route('/dashboard')
@login_required
def dashboard():
    user_id = session['user_id']
    user = get_user_by_id(user_id)
    settings = get_user_settings(user_id)
    logs = get_user_logs(user_id, limit=10)
    snapshots = get_user_snapshots(user_id)
    devices = get_user_devices(user_id)
    links = get_user_links(user_id)
    alerts = get_user_alerts(user_id, resolved=0)
    recent_snapshot = snapshots[0] if snapshots else None

    return render_template('dashboard.html',
                           user=user,
                           settings=settings,
                           logs=logs,
                           log_count=len(get_user_logs(user_id)),
                           snapshots=snapshots,
                           snapshot_count=len(snapshots),
                           recent_snapshot=recent_snapshot,
                           devices=devices,
                           device_count=len(devices),
                           links=links,
                           alerts=alerts,
                           alert_count=len(alerts))


# =============================================================================
# CONFIGURATION - Command Validation & Auto-Fix
# =============================================================================

@app.route('/configuration', methods=['GET', 'POST'])
@login_required
def configuration():
    user_id = session['user_id']
    result = None
    risk_summary = None
    fix_review = []
    config_diff = []
    security_review = None
    reviewed_config = ''
    eve_lab_nodes = []
    eve_status = None
    submitted_config = ''
    config_blocks = []
    vendor = request.form.get('vendor', 'auto') if request.method == 'POST' else 'auto'
    selected_device_id = request.form.get('device_id', '')

    if request.method == 'POST':
        raw_config = request.form.get('raw_config', '')
        vendor = request.form.get('vendor', 'auto')

        # Check for file upload
        uploaded_file = request.files.get('config_file')
        if uploaded_file and uploaded_file.filename:
            try:
                file_content = uploaded_file.read().decode('utf-8', errors='replace')
                if file_content.strip():
                    raw_config = file_content
                    flash(f'File "{uploaded_file.filename}" loaded successfully.', 'success')
            except Exception as e:
                flash(f'Error reading file: {e}', 'danger')

        # If device selected, load its vendor
        if selected_device_id:
            device = get_device_by_id(int(selected_device_id), user_id)
            if device and vendor == 'auto':
                vendor = device['vendor']

        if not raw_config.strip():
            flash('Please enter network commands or upload a config file.', 'warning')
            return redirect(url_for('configuration'))

        submitted_config = raw_config

        # Parse and validate
        result = parse_network_config(raw_config, vendor=vendor)
        risk_summary = summarize_config_risk(result)
        fix_review = build_fix_review(result)
        selected_device = get_device_by_id(int(selected_device_id), user_id) if selected_device_id else None
        selected_device_type = selected_device['device_type'] if selected_device else 'router'
        security_review = review_security_baseline(result['corrected'], result['vendor'], selected_device_type)
        reviewed_config = build_security_reviewed_config(result['corrected'], security_review)
        config_diff = build_config_diff(raw_config, result['corrected'])
        save_user_config(user_id, raw_config)
        add_log(
            user_id,
            'configuration',
            f'Validated {result["total_lines"]} commands '
            f'(Vendor: {result["vendor"]}, Risk: {risk_summary["label"]} {risk_summary["score"]}/100)',
            request.remote_addr,
        )

        alert_device_id = int(selected_device_id) if selected_device_id else None
        if risk_summary['state'] == 'blocked':
            create_alert(
                user_id,
                alert_device_id,
                'config_blocked',
                'error',
                f'{result["error_count"]} blocking error(s) found in last configuration check',
            )
        elif risk_summary['state'] == 'warning':
            create_alert(
                user_id,
                alert_device_id,
                'config_warning',
                'warning',
                f'{result["warning_count"]} warning(s) found in last configuration check',
            )

    # Load last config
    last_config = get_last_config(user_id)
    last_config_text = last_config['config_text'] if last_config else ''

    devices = get_user_devices(user_id)

    if result:
        selected_device = get_device_by_id(int(selected_device_id), user_id) if selected_device_id else None
        device_lookup = {device['name'].lower(): device for device in devices}
        raw_blocks = split_config_blocks(submitted_config)
        for block in raw_blocks:
            block_vendor = block['vendor'] if vendor == 'auto' else vendor
            block_result = parse_network_config(block['raw_config'], vendor=block_vendor)
            block_summary = summarize_config_risk(block_result)
            block_security_review = review_security_baseline(
                block_result['corrected'],
                block_result['vendor'],
                block.get('device_type') or 'router',
            )
            block_reviewed_config = build_security_reviewed_config(block_result['corrected'], block_security_review)
            corrected_check = parse_network_config(block_reviewed_config, vendor=block_result['vendor'])
            corrected_summary = summarize_config_risk(corrected_check)
            matched_device = None
            if selected_device and len(raw_blocks) == 1:
                matched_device = selected_device
            elif block.get('device_name'):
                matched_device = device_lookup.get(block['device_name'].lower())
            config_blocks.append({
                'index': block['index'],
                'device_name': block.get('device_name') or f'Config block {block["index"]}',
                'device_type': block_result.get('device_type') or (block.get('device_type') or 'router'),
                'vendor': block_result['vendor'],
                'raw_config': block['raw_config'],
                'corrected_config': block_result['corrected'],
                'reviewed_config': block_reviewed_config,
                'security_review': block_security_review,
                'risk_summary': block_summary,
                'corrected_summary': corrected_summary,
                'matched_device': matched_device,
                'can_apply': corrected_summary['state'] != 'blocked',
            })

    return render_template('configuration.html',
                           result=result,
                           risk_summary=risk_summary,
                           fix_review=fix_review,
                           config_diff=config_diff,
                           security_review=security_review,
                           reviewed_config=reviewed_config,
                           eve_lab_nodes=eve_lab_nodes,
                           eve_status=eve_status,
                           submitted_config=submitted_config,
                           last_config=last_config_text,
                           selected_vendor=vendor,
                           config_blocks=config_blocks,
                           devices=devices,
                           selected_device_id=selected_device_id)


@app.route('/validator/api', methods=['POST'])
@login_required
def validator_api():
    payload = request.get_json(silent=True) or {}
    raw_config = payload.get('config', '')
    vendor = payload.get('vendor', 'auto')
    if not raw_config.strip():
        return jsonify({'error': 'Empty configuration provided.'}), 400

    result = parse_network_config(raw_config, vendor=vendor)
    response_lines = []
    for line in result.get('line_details', []):
        status = 'ok'
        msg = None
        if line.get('errors'):
            status = 'error'
            msg = '; '.join(line.get('errors') or [])
        elif line.get('warnings'):
            status = 'warning'
            msg = '; '.join(line.get('warnings') or [])
        note = 'comment' if line.get('line', '').strip().startswith(('!', '#', '//')) else None
        response_lines.append({
            'ln': line.get('num'),
            'raw': line.get('line'),
            'status': status,
            'msg': msg,
            'note': note,
        })

    return jsonify({
        'results': response_lines,
        'vendor': result.get('vendor'),
        'corrected': result.get('corrected', result.get('ready', raw_config)),
        'ready': result.get('ready', raw_config),
        'error_count': result.get('error_count', 0),
        'warning_count': result.get('warning_count', 0),
        'summary': result.get('analysis', ''),
        'total_lines': result.get('total_lines', 0),
        'fix_count': result.get('fix_count', 0),
        'accuracy': result.get('accuracy', 0),
    })


@app.route('/configuration/snapshot', methods=['POST'])
@login_required
def create_change_snapshot():
    """Save a reviewed change snapshot before previewing."""
    user_id = session['user_id']
    name = request.form.get('snapshot_name', '').strip()
    original_config = request.form.get('original_config', '')
    corrected_config = request.form.get('corrected_config', '')
    vendor = request.form.get('vendor', 'unknown')
    risk_state = request.form.get('risk_state', 'unknown')
    device_id = request.form.get('device_id', '').strip()

    config_text = corrected_config.strip() or original_config.strip()
    if not config_text:
        flash('No configuration is available to snapshot.', 'warning')
        return redirect(url_for('configuration'))

    device_name = None
    if device_id:
        device = get_device_by_id(int(device_id), user_id)
        if device:
            device_name = device['name']

    if not name:
        name = f'Change snapshot {datetime.now().strftime("%Y-%m-%d %H:%M")}'

    save_snapshot(
        user_id,
        name,
        config_text,
        device_name=device_name,
        snapshot_type='change',
    )
    add_log(
        user_id,
        'change_snapshot',
        f'Created change snapshot "{name}" for {device_name or "general config"} '
        f'({vendor}, risk {risk_state})',
        request.remote_addr,
    )
    flash(f'Change snapshot "{name}" saved. You can now continue to Network Preview.', 'success')
    return redirect(url_for('configuration'))


@app.route('/configuration/apply/<int:device_id>', methods=['POST'])
@login_required
def apply_config_to_device(device_id):
    """Upload the validated configuration to an EVE-NG lab device."""
    user_id = session['user_id']
    device = get_device_by_id(device_id, user_id)
    if not device:
        flash('Device not found.', 'danger')
        return redirect(url_for('configuration'))

    config_text = request.form.get('config_text', '')
    settings = get_user_settings(user_id)

    if not config_text.strip():
        flash('No corrected configuration is available for EVE-NG lab testing.', 'warning')
        return redirect(url_for('configuration'))

    if not settings['eve_lab_path'] or not device['eve_node_id']:
        flash('Device is not linked to an EVE-NG node. Please sync with EVE-NG first.', 'warning')
        return redirect(url_for('configuration'))

    eve = get_eve_connector(settings)
    result = eve.upload_node_config(device['eve_node_id'], config_text)

    if result['success']:
        add_log(user_id, 'eve_lab_upload', f'Uploaded reviewed config to EVE-NG node for {device["name"]}')
        create_alert(user_id, device_id, 'eve_lab_upload', 'info',
                     f'Configuration uploaded to EVE-NG lab node for {device["name"]}')
        flash(f'Configuration uploaded to EVE-NG lab node for {device["name"]}.', 'success')
    else:
        add_log(user_id, 'eve_lab_upload_failed', f'Failed to upload config to EVE-NG node for {device["name"]}: {result["error"]}')
        flash(f'Failed to upload config to EVE-NG: {result["error"]}', 'danger')

    return redirect(url_for('configuration'))


@app.route('/configuration/apply/eve-node', methods=['POST'])
@login_required
def apply_config_to_eve_node():
    """Upload the reviewed configuration directly to a selected EVE-NG lab node."""
    user_id = session['user_id']
    config_text = request.form.get('config_text', '')
    eve_node_id = request.form.get('eve_node_id', '').strip()
    eve_node_name = request.form.get('eve_node_name', '').strip() or f'node {eve_node_id}'
    settings = get_user_settings(user_id)

    if not config_text.strip():
        flash('No corrected configuration is available for EVE-NG lab testing.', 'warning')
        return redirect(url_for('configuration'))

    if not eve_node_id:
        flash('Select an EVE-NG lab node before uploading the configuration.', 'warning')
        return redirect(url_for('configuration'))

    if not settings['eve_lab_path']:
        flash('EVE-NG lab path not configured. Save the lab path in Settings first.', 'warning')
        return redirect(url_for('configuration'))

    eve = get_eve_connector(settings)
    result = eve.upload_node_config(eve_node_id, config_text)

    if result['success']:
        add_log(
            user_id,
            'eve_lab_upload',
            f'Uploaded reviewed config to EVE-NG node {eve_node_name}',
            request.remote_addr,
        )
        create_alert(
            user_id,
            None,
            'eve_lab_upload',
            'info',
            f'Configuration uploaded to EVE-NG lab node {eve_node_name}',
        )
        flash(f'Configuration uploaded to EVE-NG lab node {eve_node_name}.', 'success')
    else:
        add_log(
            user_id,
            'eve_lab_upload_failed',
            f'Failed to upload config to EVE-NG node {eve_node_name}: {result["error"]}',
            request.remote_addr,
        )
        flash(f'Failed to upload config to EVE-NG: {result["error"]}', 'danger')

    return redirect(url_for('configuration'))


@app.route('/configuration/apply-hybrid', methods=['POST'])
@login_required
def apply_hybrid_config():
    """Apply a reviewed config to EVE-NG when possible or save a local preview."""
    user_id = session['user_id']
    raw_config = request.form.get('raw_config', '')
    corrected_config = request.form.get('corrected_config', '').strip() or raw_config.strip()
    vendor = request.form.get('vendor', 'auto')
    device_id = request.form.get('device_id', '').strip()
    create_device = request.form.get('create_device') == '1'

    if not corrected_config:
        flash('No corrected configuration is available to apply or preview.', 'warning')
        return redirect(url_for('configuration'))

    device = None
    if device_id:
        device = get_device_by_id(int(device_id), user_id)
    elif create_device:
        device_name = request.form.get('device_name', '').strip()
        device_type = request.form.get('device_type', '').strip() or 'router'
        if not device_name:
            flash('Device name is required before saving a network preview.', 'warning')
            return redirect(url_for('configuration'))
        device = get_device_by_name(user_id, device_name)
        if not device:
            new_device_id = add_device(user_id, device_name, device_type, vendor if vendor != 'auto' else detect_vendor(corrected_config))
            add_log(user_id, 'add_device', f'Created device from reviewed config: {device_name}', request.remote_addr)
            device = get_device_by_id(new_device_id, user_id)

    if not device:
        flash('Map this configuration to a device before applying it.', 'warning')
        return redirect(url_for('configuration'))

    result = apply_config_to_lab_or_preview(
        user_id,
        device,
        raw_config or corrected_config,
        corrected_config,
        vendor if vendor != 'auto' else device['vendor'],
    )

    if result['application_state'] == 'uploaded_eve':
        flash(f'Configuration applied as a preview for {device["name"]}.', 'success')
    elif result['application_state'] == 'local_preview':
        flash(f'Configuration saved as a Local Preview for {device["name"]}.', 'success')
    elif result['application_state'] == 'blocked':
        flash(f'Configuration for {device["name"]} is still blocked by validation errors.', 'danger')
    else:
        flash(f'Preview save failed for {device["name"]}. The config was saved for inspection.', 'warning')

    return redirect(url_for('device_detail', device_id=device['id']))


@app.route('/configuration/build-network', methods=['POST'])
@login_required
def build_full_network():
    """Build all detected config blocks as one isolated network snapshot."""
    user_id = session['user_id']
    full_config = request.form.get('full_config', '')
    vendor = request.form.get('vendor', 'auto')
    network_name = request.form.get('network_name', '').strip() or None

    if not full_config.strip():
        flash('Paste or upload a full network configuration before building the network.', 'warning')
        return redirect(url_for('configuration'))

    blocks = split_config_blocks(full_config)
    if not blocks:
        flash('No device configs were detected in the submitted network config.', 'warning')
        return redirect(url_for('configuration'))

    # Create network snapshot for isolated topology
    snapshot_name = network_name or f'Network {datetime.now().strftime("%Y-%m-%d %H:%M")}'
    snapshot_id = create_network_snapshot(
        user_id,
        snapshot_name,
        f'Built from configuration upload',
        config_source='build_network',
    )

    built_device_configs = []
    skipped_blocks = 0

    for block in blocks:
        block_vendor = block['vendor'] if vendor == 'auto' else vendor
        parsed = parse_network_config(block['raw_config'], vendor=block_vendor)
        security_review = review_security_baseline(
            parsed['corrected'],
            parsed['vendor'],
            block.get('device_type') or 'router',
        )
        reviewed_config = build_security_reviewed_config(parsed['corrected'], security_review)
        reviewed_parse = parse_network_config(reviewed_config, vendor=parsed['vendor'])
        reviewed_summary = summarize_config_risk(reviewed_parse)
        
        # Don't skip even if blocked - try to create device anyway with corrected config
        # if reviewed_summary['state'] == 'blocked':
        #     skipped_blocks += 1
        #     continue

        device_name = block.get('device_name') or f'Config block {block["index"]}'
        # Auto-detect device type from config
        device_type = parsed.get('device_type') or block.get('device_type') or 'router'
        device = get_device_by_name(user_id, device_name)
        if not device:
            # Create device linked to this snapshot
            device_id = add_device(
                user_id, 
                device_name, 
                device_type,  # Use auto-detected type
                parsed['vendor'],
                snapshot_id=snapshot_id
            )
            add_log(
                user_id,
                'add_device',
                f'Created device from network snapshot: {device_name}',
                request.remote_addr,
            )
            device = get_device_by_id(device_id, user_id)

        apply_config_to_lab_or_preview(
            user_id,
            device,
            block['raw_config'],
            reviewed_config,
            parsed['vendor'],
            source='build_network',
        )
        built_device_configs.append({
            'device_id': device['id'],
            'device_name': device['name'],
            'vendor': parsed['vendor'],
            'config_text': reviewed_config,
        })

    inferred_links = infer_topology_links(built_device_configs)
    created_link_count = 0
    for link in inferred_links:
        link_id = add_link_if_missing(
            user_id,
            link['source_device_id'],
            link['target_device_id'],
            link['source_interface'],
            link['target_interface'],
        )
        if link_id:
            created_link_count += 1

    # Update snapshot with counts
    execute_db(
        'UPDATE network_snapshots SET device_count = ?, link_count = ? WHERE id = ?',
        (len(built_device_configs), created_link_count, snapshot_id)
    )

    add_log(
        user_id,
        'build_full_network',
        f'Built network snapshot "{snapshot_name}": {len(built_device_configs)} device(s), {created_link_count} link(s)',
        request.remote_addr,
    )
    flash(
        f'Network snapshot "{snapshot_name}" created with {len(built_device_configs)} device(s) and {created_link_count} link(s).'
        + (f' Skipped {skipped_blocks} blocked config block(s).' if skipped_blocks else ''),
        'success' if built_device_configs else 'warning',
    )
    return redirect(url_for('topology'))


@app.route('/devices/<int:device_id>/retry_eve_upload', methods=['POST'])
@login_required
def retry_device_eve_upload(device_id):
    """Retry uploading the latest local/failed device config to EVE-NG."""
    user_id = session['user_id']
    device = get_device_by_id(device_id, user_id)
    if not device:
        flash('Device not found.', 'danger')
        return redirect(url_for('devices'))

    latest = get_latest_device_config_application(device_id, user_id)
    if not latest:
        flash('No saved lab config is available for this device.', 'warning')
        return redirect(url_for('device_detail', device_id=device_id))

    result = apply_config_to_lab_or_preview(
        user_id,
        device,
        latest['raw_config'],
        latest['corrected_config'],
        latest['vendor'],
        source='retry',
    )

    if result['application_state'] == 'uploaded_eve':
        flash(f'Retry succeeded. Configuration uploaded to EVE-NG for {device["name"]}.', 'success')
    elif result['application_state'] == 'local_preview':
        flash('EVE-NG is still unavailable or not linked. Local Preview was refreshed.', 'warning')
    else:
        flash('Retry failed. Check EVE-NG settings and device node linkage.', 'danger')

    return redirect(url_for('device_detail', device_id=device_id))


@app.route('/configuration/generate', methods=['POST'])
@login_required
def generate_config():
    """Generate a baseline configuration template."""
    user_id = session['user_id']
    vendor = request.form.get('vendor', 'cisco')
    device_type = request.form.get('device_type', 'router')
    hostname = request.form.get('hostname', 'Router1')

    interfaces = []
    iface_count = int(request.form.get('interface_count', 2))
    for i in range(iface_count):
        iface_name = request.form.get(f'iface_name_{i}', f'GigabitEthernet0/{i}')
        iface_ip = request.form.get(f'iface_ip_{i}', '')
        iface_mask = request.form.get(f'iface_mask_{i}', '255.255.255.0')
        iface_desc = request.form.get(f'iface_desc_{i}', '')
        if iface_ip:
            interfaces.append({
                'name': iface_name,
                'ip': iface_ip,
                'mask': iface_mask,
                'description': iface_desc,
            })

    config = generate_device_config(vendor, device_type, hostname, interfaces)
    add_log(user_id, 'generate_config', f'Generated {vendor} config for {hostname}')
    return jsonify({'success': True, 'config': config})


# =============================================================================
# DEVICES
# =============================================================================

@app.route('/devices')
@login_required
def devices():
    user_id = session['user_id']
    user_devices = get_user_devices(user_id)
    links = get_user_links(user_id)
    application_map = get_user_latest_device_applications(user_id)
    network_groups = get_user_network_groups(user_id)
    
    # Get selected group filter
    selected_group = request.args.get('group', '').strip() or None
    if selected_group and selected_group.isdigit():
        filtered_devices = get_devices_by_group(user_id, int(selected_group))
    elif selected_group == 'ungrouped':
        filtered_devices = get_devices_by_group(user_id, None)
    else:
        filtered_devices = user_devices
    
    return render_template('devices.html',
                           devices=filtered_devices,
                           all_devices=user_devices,
                           links=links,
                           application_map=application_map,
                           application_state_label=application_state_label,
                           network_groups=network_groups,
                           selected_group=selected_group)


@app.route('/devices/add', methods=['GET', 'POST'])
@login_required
def add_device_route():
    if request.method == 'POST':
        user_id = session['user_id']
        name = request.form['name'].strip()
        device_type = request.form['device_type']
        vendor = request.form.get('vendor', 'cisco')
        ip_address = request.form.get('ip_address', '').strip() or None
        network_group = request.form.get('network_group', '').strip() or None

        if not name or not device_type:
            flash('Name and device type are required.', 'danger')
            return redirect(url_for('add_device_route'))

        # If network_group is a name, try to find or create it
        if network_group and not network_group.isdigit():
            group = get_network_group_by_name(user_id, network_group)
            if not group:
                # Create new group
                group_id = create_network_group(user_id, network_group)
                network_group = str(group_id)
            else:
                network_group = str(group['id'])

        device_id = add_device(user_id, name, device_type, vendor, ip_address, network_group=network_group)
        add_log(user_id, 'add_device', f'Added device: {name} ({vendor} {device_type})', request.remote_addr)
        flash(f'Device "{name}" added successfully.', 'success')
        return redirect(url_for('devices'))

    user_id = session['user_id']
    network_groups = get_user_network_groups(user_id)
    return render_template('add_device.html', network_groups=network_groups)


@app.route('/devices/<int:device_id>')
@login_required
def device_detail(device_id):
    user_id = session['user_id']
    device = get_device_by_id(device_id, user_id)
    if not device:
        flash('Device not found.', 'danger')
        return redirect(url_for('devices'))

    console_info = None
    netbox_info = None

    latest_application = get_latest_device_config_application(device_id, user_id)
    recent_applications = get_device_config_applications(device_id, user_id, limit=5)
    application_diff = []
    if latest_application:
        application_diff = build_config_diff(
            latest_application['raw_config'],
            latest_application['corrected_config'],
        )

    return render_template('device_detail.html',
                           device=device,
                           console_info=console_info,
                           netbox_info=netbox_info,
                           latest_application=latest_application,
                           recent_applications=recent_applications,
                           application_diff=application_diff,
                           application_state_label=application_state_label)


@app.route('/devices/<int:device_id>/delete', methods=['POST'])
@login_required
def delete_device_route(device_id):
    user_id = session['user_id']
    device = get_device_by_id(device_id, user_id)
    if device:
        add_log(user_id, 'delete_device', f'Deleted device: {device["name"]}', request.remote_addr)
        delete_device(device_id, user_id)
        flash(f'Device "{device["name"]}" deleted.', 'success')
    return redirect(url_for('devices'))


@app.route('/devices/<int:device_id>/sync_eve', methods=['POST'])
@login_required
def sync_device_eve(device_id):
    """Sync a device with EVE-NG - find a matching node in the configured lab."""
    user_id = session['user_id']
    device = get_device_by_id(device_id, user_id)
    if not device:
        flash('Device not found.', 'danger')
        return redirect(url_for('devices'))

    settings = get_user_settings(user_id)
    if not settings or not settings['eve_lab_path']:
        flash('EVE-NG lab path is not saved. Enter it in Settings and click Save All Settings before syncing devices.', 'warning')
        return redirect(url_for('devices'))

    eve = get_eve_connector(settings)
    nodes_result = eve.get_nodes()

    if nodes_result['success']:
        # Try to find a matching node by name
        for node in nodes_result['nodes']:
            if node['name'] == device['name']:
                update_device_eve_id(device_id, node['id'])
                update_device_status(device_id, node.get('status', 'unknown'))
                add_log(user_id, 'sync_eve', f'Synced device {device["name"]} with EVE-NG node')
                flash(f'Device "{device["name"]}" synced with EVE-NG node.', 'success')
                return redirect(url_for('devices'))

        flash(f'No EVE-NG node found with name "{device["name"]}". Create it in EVE-NG first.', 'warning')
    else:
        flash(f'Cannot connect to EVE-NG: {nodes_result["error"]}', 'danger')

    return redirect(url_for('devices'))


@app.route('/devices/<int:device_id>/sync_netbox', methods=['POST'])
@login_required
def sync_device_netbox(device_id):
    """Sync a device with NetBox."""
    user_id = session['user_id']
    device = get_device_by_id(device_id, user_id)
    if not device:
        flash('Device not found.', 'danger')
        return redirect(url_for('devices'))

    settings = get_user_settings(user_id)
    if not settings or not settings['netbox_token']:
        flash('NetBox URL and API token are not saved. Enter them in Settings and click Save All Settings before syncing devices.', 'warning')
        return redirect(url_for('devices'))

    netbox = get_netbox_connector(settings)
    user = get_user_by_id(user_id)
    result = netbox.sync_device_to_netbox(
        device_name=device['name'],
        device_type=device['device_type'],
        vendor=device['vendor'],
        ip_address=device['ip_address'],
        tenant_name=user['company'] if user else None
    )

    if result['success']:
        update_device_netbox_id(device_id, result['device_id'])
        add_log(user_id, 'sync_netbox', f'Synced device {device["name"]} with NetBox (ID: {result["device_id"]})')
        flash(f'Device "{device["name"]}" synced with NetBox.', 'success')
    else:
        flash(f'NetBox sync failed: {result["error"]}', 'danger')

    return redirect(url_for('devices'))


# =============================================================================
# TOPOLOGY
# =============================================================================

@app.route('/topology')
@login_required
def topology():
    user_id = session['user_id']
    
    # Get selected network snapshot
    selected_snapshot = request.args.get('snapshot', '').strip() or None
    snapshot = None
    
    if selected_snapshot and selected_snapshot.isdigit():
        # Load isolated topology from snapshot
        snapshot = get_network_snapshot_by_id(int(selected_snapshot), user_id)
        if snapshot:
            # Get ONLY devices from this snapshot
            devices = get_devices_by_snapshot(user_id, int(selected_snapshot))
            flash(f'Viewing isolated network: {snapshot["name"]} ({len(devices)} devices, {snapshot["link_count"]} links)', 'info')
        else:
            # Snapshot not found, show all devices
            devices = get_user_devices(user_id)
    else:
        # No snapshot selected, show all devices
        devices = get_user_devices(user_id)
    
    # Get all links
    all_links = get_user_links(user_id)
    
    application_map = get_user_latest_device_applications(user_id)
    network_groups = get_user_network_groups(user_id)
    network_snapshots = get_user_network_snapshots(user_id)
    
    # Build network groups map (id -> name)
    network_groups_map = {str(g['id']): g['name'] for g in network_groups}
    
    # Filter links to only show links for selected devices
    device_ids = {d['id'] for d in devices}
    filtered_links = [link for link in all_links if link['source_device_id'] in device_ids and link['target_device_id'] in device_ids]
    
    # Build topology with snapshot info
    inventory_topology = build_inventory_topology(
        devices, 
        filtered_links, 
        application_map, 
        network_groups_map,
        snapshot_id=selected_snapshot
    )

    return render_template('topology.html',
                           devices=devices,
                           all_devices=get_user_devices(user_id),
                           links=filtered_links,
                           all_links=all_links,
                           inventory_topology=inventory_topology,
                           network_groups=network_groups,
                           network_snapshots=network_snapshots,
                           selected_snapshot=selected_snapshot,
                           snapshot=snapshot,
                           selected_group=None)


@app.route('/topology/add_link', methods=['POST'])
@login_required
def add_link_route():
    user_id = session['user_id']
    source_id = request.form.get('source_device_id')
    target_id = request.form.get('target_device_id')
    source_iface = request.form.get('source_interface', '')
    target_iface = request.form.get('target_interface', '')

    if source_id and target_id and source_id != target_id:
        add_link(user_id, int(source_id), int(target_id), source_iface, target_iface)
        add_log(user_id, 'add_link', f'Added link between devices', request.remote_addr)
        flash('Link added successfully.', 'success')
    else:
        flash('Invalid link configuration.', 'danger')

    return redirect(url_for('topology'))


@app.route('/topology/delete_link/<int:link_id>', methods=['POST'])
@login_required
def delete_link_route(link_id):
    user_id = session['user_id']
    delete_link(link_id, user_id)
    add_log(user_id, 'delete_link', f'Deleted link', request.remote_addr)
    flash('Link deleted.', 'success')
    return redirect(url_for('topology'))


@app.route('/topology/api/delete_device/<int:device_id>', methods=['POST'])
def api_delete_topology_device(device_id):
    """AJAX endpoint: delete a device from the topology canvas."""
    user_id = session['user_id']
    device = get_device_by_id(device_id, user_id)
    if not device:
        return jsonify({'ok': False, 'error': 'Device not found'}), 404
    delete_device(device_id, user_id)
    add_log(user_id, 'delete_device', f'Deleted device: {device["name"]} from topology', request.remote_addr)
    return jsonify({'ok': True, 'device_id': device_id})


@app.route('/topology/api/delete_link/<int:link_id>', methods=['POST'])
def api_delete_topology_link(link_id):
    """AJAX endpoint: delete a link from the topology canvas."""
    user_id = session['user_id']
    delete_link(link_id, user_id)
    add_log(user_id, 'delete_link', f'Deleted link from topology', request.remote_addr)
    return jsonify({'ok': True, 'link_id': link_id})


# =============================================================================
# SNAPSHOTS
# =============================================================================

@app.route('/snapshots')
@login_required
def snapshots():
    user_id = session['user_id']
    user_snapshots = get_user_snapshots(user_id)
    return render_template('snapshots.html', snapshots=user_snapshots)


@app.route('/snapshots/restore/<int:snapshot_id>', methods=['POST'])
@login_required
def restore_snapshot(snapshot_id):
    user_id = session['user_id']
    snapshot = get_snapshot_by_id(snapshot_id, user_id)
    if snapshot:
        save_user_config(user_id, snapshot['config_text'])
        add_log(user_id, 'restore_snapshot', f'Restored snapshot: {snapshot["name"]}', request.remote_addr)
        flash(f'Snapshot "{snapshot["name"]}" restored successfully.', 'success')
    else:
        flash('Snapshot not found.', 'danger')
    return redirect(url_for('snapshots'))


@app.route('/snapshots/delete/<int:snapshot_id>', methods=['POST'])
@login_required
def delete_snapshot_route(snapshot_id):
    user_id = session['user_id']
    snapshot = get_snapshot_by_id(snapshot_id, user_id)
    if snapshot:
        add_log(user_id, 'delete_snapshot', f'Deleted snapshot: {snapshot["name"]}', request.remote_addr)
        delete_snapshot(snapshot_id, user_id)
        flash(f'Snapshot "{snapshot["name"]}" deleted.', 'success')
    return redirect(url_for('snapshots'))


@app.route('/snapshots/backup_now', methods=['POST'])
@login_required
def backup_now():
    user_id = session['user_id']
    config = get_last_config(user_id)
    if config:
        save_snapshot(user_id, f'Manual backup {datetime.now().strftime("%Y-%m-%d %H:%M")}',
                      config['config_text'], snapshot_type='manual')
        add_log(user_id, 'manual_backup', 'Manual backup saved', request.remote_addr)
        flash('Backup saved successfully.', 'success')
    else:
        flash('No configuration to backup.', 'warning')
    return redirect(url_for('snapshots'))


# =============================================================================
# LOGS
# =============================================================================

@app.route('/logs')
@login_required
def logs():
    user_id = session['user_id']
    user = get_user_by_id(user_id)
    user_logs = get_user_logs(user_id, limit=500)
    return render_template('logs.html', logs=user_logs, user=user)


# =============================================================================
# ALERTS
# =============================================================================

@app.route('/alerts')
@login_required
def alerts():
    user_id = session['user_id']
    user_alerts = get_user_alerts(user_id)
    return render_template('alerts.html', alerts=user_alerts)


@app.route('/alerts/<int:alert_id>/resolve', methods=['POST'])
@login_required
def resolve_alert_route(alert_id):
    user_id = session['user_id']
    resolve_alert(alert_id, user_id)
    add_log(user_id, 'resolve_alert', f'Resolved alert #{alert_id}', request.remote_addr)
    flash('Alert resolved.', 'success')
    return redirect(url_for('alerts'))


# =============================================================================
# SETTINGS
# =============================================================================

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    user_id = session['user_id']
    user_settings = get_user_settings(user_id)

    if request.method == 'POST':
        backup_minutes = int(request.form.get('backup_minutes', 15))
        eve_url = request.form.get('eve_url', '').strip()
        eve_username = request.form.get('eve_username', '').strip()
        eve_password = request.form.get('eve_password', '').strip()
        eve_lab_path = request.form.get('eve_lab_path', '').strip()
        netbox_url = request.form.get('netbox_url', '').strip()
        netbox_token = request.form.get('netbox_token', '').strip()
        auto_remediate = 1 if request.form.get('auto_remediate') else 0

        update_user_settings(user_id,
                             backup_minutes=backup_minutes,
                             eve_url=eve_url,
                             eve_username=eve_username,
                             eve_password=eve_password,
                             eve_lab_path=eve_lab_path,
                             netbox_url=netbox_url,
                             netbox_token=netbox_token,
                             auto_remediate=auto_remediate)

        add_log(user_id, 'update_settings', 'Settings updated', request.remote_addr)
        flash('Settings saved successfully.', 'success')
        return redirect(url_for('settings'))

    return render_template('settings.html', settings=user_settings)


# =============================================================================
# EVE-NG API PROXY ROUTES
# =============================================================================

@app.route('/api/eve/test', methods=['POST'])
@login_required
def api_eve_test():
    user_id = session['user_id']
    user_settings = merge_settings_payload(
        get_user_settings(user_id),
        ('eve_url', 'eve_username', 'eve_password', 'eve_lab_path'),
    )
    eve = get_eve_connector(user_settings)
    result = eve.test_connection()
    if not result['success']:
        return jsonify(result)

    lab_path = (user_settings.get('eve_lab_path') or '').strip()
    if not lab_path:
        result.update({
            'success': False,
            'lab_success': False,
            'error': 'Connected to EVE-NG, but the lab path is not configured. Save an EVE-NG lab path before syncing devices.',
        })
        return jsonify(result)

    nodes_result = eve.get_nodes()
    if nodes_result['success']:
        result.update({
            'success': True,
            'lab_success': True,
            'node_count': len(nodes_result.get('nodes', [])),
            'message': f'Connected to EVE-NG lab. {len(nodes_result.get("nodes", []))} node(s) found.',
        })
    else:
        result.update({
            'success': False,
            'lab_success': False,
            'error': f'Connected to EVE-NG, but the lab path could not be loaded: {nodes_result["error"]}',
        })
    return jsonify(result)


@app.route('/api/eve/lab', methods=['GET'])
@login_required
def api_eve_lab():
    user_id = session['user_id']
    user_settings = get_user_settings(user_id)
    eve = get_eve_connector(user_settings)
    result = eve.get_lab()
    return jsonify(result)


@app.route('/api/eve/topology', methods=['GET'])
@login_required
def api_eve_topology():
    user_id = session['user_id']
    user_settings = get_user_settings(user_id)
    eve = get_eve_connector(user_settings)
    result = eve.get_topology_summary()
    return jsonify(result)


@app.route('/api/eve/start_all', methods=['POST'])
@login_required
def api_eve_start_all():
    user_id = session['user_id']
    user_settings = get_user_settings(user_id)
    eve = get_eve_connector(user_settings)
    result = eve.start_all_nodes()
    if result['success']:
        add_log(user_id, 'eve_start_all', 'Started all EVE-NG nodes')
    return jsonify(result)


@app.route('/api/eve/stop_all', methods=['POST'])
@login_required
def api_eve_stop_all():
    user_id = session['user_id']
    user_settings = get_user_settings(user_id)
    eve = get_eve_connector(user_settings)
    result = eve.stop_all_nodes()
    if result['success']:
        add_log(user_id, 'eve_stop_all', 'Stopped all EVE-NG nodes')
    return jsonify(result)


@app.route('/api/eve/start_node/<node_id>', methods=['POST'])
@login_required
def api_eve_start_node(node_id):
    user_id = session['user_id']
    user_settings = get_user_settings(user_id)
    eve = get_eve_connector(user_settings)
    result = eve.start_node(node_id)
    return jsonify(result)


@app.route('/api/eve/stop_node/<node_id>', methods=['POST'])
@login_required
def api_eve_stop_node(node_id):
    user_id = session['user_id']
    user_settings = get_user_settings(user_id)
    eve = get_eve_connector(user_settings)
    result = eve.stop_node(node_id)
    return jsonify(result)


# =============================================================================
# NETBOX API PROXY ROUTES
# =============================================================================

@app.route('/api/netbox/test', methods=['POST'])
@login_required
def api_netbox_test():
    user_id = session['user_id']
    user_settings = merge_settings_payload(
        get_user_settings(user_id),
        ('netbox_url', 'netbox_token'),
    )
    try:
        netbox = get_netbox_connector(user_settings)
        result = netbox.test_connection()
    except Exception as e:
        result = {'success': False, 'error': f'NetBox test failed: {e}'}
    return jsonify(result)


@app.route('/api/netbox/overview', methods=['GET'])
@login_required
def api_netbox_overview():
    user_id = session['user_id']
    user_settings = get_user_settings(user_id)
    if not user_settings['netbox_token']:
        return jsonify({
            'success': False,
            'error': 'NetBox API token is not saved. Add the token in Settings before loading NetBox data.',
        })
    user = get_user_by_id(user_id)
    netbox = get_netbox_connector(user_settings)
    result = netbox.get_network_overview(tenant_name=user['company'] if user else None)
    return jsonify(result)


@app.route('/api/netbox/sync_all', methods=['POST'])
@login_required
def api_netbox_sync_all():
    """Sync all local devices to NetBox."""
    user_id = session['user_id']
    user_settings = get_user_settings(user_id)
    if not user_settings['netbox_token']:
        return jsonify({
            'success': False,
            'error': 'NetBox API token is not saved. Add the token in Settings before syncing devices.',
        })
    netbox = get_netbox_connector(user_settings)
    user = get_user_by_id(user_id)
    devices = get_user_devices(user_id)

    results = []
    failed_count = 0
    for device in devices:
        result = netbox.sync_device_to_netbox(
            device_name=device['name'],
            device_type=device['device_type'],
            vendor=device['vendor'],
            ip_address=device['ip_address'],
            tenant_name=user['company'] if user else None
        )
        if result['success']:
            update_device_netbox_id(device['id'], result['device_id'])
        else:
            failed_count += 1
        results.append({'device': device['name'], 'result': result})

    synced_count = len(devices) - failed_count
    add_log(user_id, 'netbox_sync_all', f'Synced {synced_count}/{len(devices)} devices to NetBox')
    return jsonify({
        'success': failed_count == 0,
        'synced_count': synced_count,
        'failed_count': failed_count,
        'results': results,
    })


# =============================================================================
# API: Validate config (AJAX)
# =============================================================================

@app.route('/api/validate', methods=['POST'])
@login_required
def api_validate():
    """AJAX endpoint for real-time config validation."""
    data = request.get_json()
    config_text = data.get('config', '')
    vendor = data.get('vendor', 'auto')
    result = parse_network_config(config_text, vendor=vendor)
    return jsonify(result)


# =============================================================================
# MAIN
# =============================================================================

if __name__ == '__main__':
    if not os.path.exists(DATABASE):
        with app.app_context():
            init_db()
            print("Database initialized.")

    start_backup_worker()
    app.run(debug=True, host='127.0.0.1', port=5000, use_reloader=False)
