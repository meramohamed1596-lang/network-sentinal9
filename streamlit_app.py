import os
from datetime import datetime, timedelta
import streamlit as st
from werkzeug.security import generate_password_hash, check_password_hash
from network_core import (
    DATABASE,
    DEFAULT_BACKUP_MINUTES,
    init_db,
    get_user_by_email,
    get_user_by_id,
    create_user,
    query_db,
    execute_db,
    parse_network_config,
    save_snapshot,
    add_log,
    get_backup_interval,
    ensure_default_settings,
    get_user_settings,
    update_user_settings,
    get_user_snapshots,
    get_user_logs,
    save_user_config,
    get_last_config,
    add_device,
    get_user_devices,
    get_device_by_id,
    delete_device,
    get_user_links,
    get_user_alerts,
    resolve_alert,
    generate_device_config,
)
from eve_connector import get_eve_connector
from netbox_connector import get_netbox_connector

if not os.path.exists(DATABASE):
    init_db()

st.set_page_config(page_title='Network Sentinel', layout='wide', page_icon='🛡️')

if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.user_id = None
    st.session_state.username = ''
    st.session_state.company = ''


def login_user(user):
    st.session_state.logged_in = True
    st.session_state.user_id = user['id']
    st.session_state.username = user['name']
    st.session_state.company = user['company']


def logout_user():
    st.session_state.logged_in = False
    st.session_state.user_id = None
    st.session_state.username = ''
    st.session_state.company = ''
    st.rerun()


def maybe_auto_backup(user_id):
    ensure_default_settings(user_id)
    interval = get_backup_interval(user_id)
    latest = query_db('SELECT created_at FROM snapshots WHERE user_id = ? ORDER BY created_at DESC LIMIT 1', (user_id,), one=True)
    config = get_last_config(user_id)
    if config:
        last_time = datetime.fromisoformat(latest['created_at']) if latest else None
        if last_time is None or last_time + timedelta(minutes=interval) <= datetime.now():
            save_snapshot(user_id, f'Auto backup {datetime.now().strftime("%Y-%m-%d %H:%M")}', config['config_text'], snapshot_type='auto')
            add_log(user_id, 'auto_backup', 'Automatic snapshot saved')


def show_dashboard():
    st.header('Dashboard')
    user_id = st.session_state.user_id
    devices = get_user_devices(user_id)
    logs = get_user_logs(user_id, limit=5)
    snapshots = get_user_snapshots(user_id)
    alerts = get_user_alerts(user_id, resolved=0)
    settings = get_user_settings(user_id)

    # Metrics
    col1, col2, col3, col4 = st.columns(4)
    col1.metric('Devices', len(devices))
    col2.metric('Log Entries', len(get_user_logs(user_id)))
    col3.metric('Snapshots', len(snapshots))
    col4.metric('Active Alerts', len(alerts))

    # Topology
    st.subheader('Network Topology')
    if devices:
        cols = st.columns(min(len(devices), 4))
        for i, dev in enumerate(devices):
            with cols[i % len(cols)]:
                vendor_icon = {'cisco': '🔵', 'juniper': '🟢', 'huawei': '🔴'}.get(dev['vendor'], '⚪')
                st.info(f"{vendor_icon} **{dev['name']}**\n\n{dev['vendor'].title()} {dev['device_type'].title()}")
    else:
        st.info('No devices yet. Add your first device!')

    # Status
    col1, col2, col3 = st.columns(3)
    col1.success('System: Stable')
    col2.warning(f'Alerts: {len(alerts)}')
    col3.info(f"Last Snapshot: {snapshots[0]['created_at'][:16] if snapshots else 'None'}")

    # Recent Activity
    st.subheader('Recent Activity')
    for log in logs:
        st.write(f"**{log['action']}** — {log['details']} — {log['created_at'][:16]}")


def show_configuration():
    st.header('Configuration Input')
    user_id = st.session_state.user_id

    vendor = st.selectbox('Vendor', ['auto', 'cisco', 'juniper', 'huawei'], format_func=lambda x: {'auto': 'Auto-detect', 'cisco': 'Cisco IOS', 'juniper': 'Juniper JunOS', 'huawei': 'Huawei VRP'}[x])

    raw_config = st.text_area('Enter network commands...', height=260,
                              value=st.session_state.get('last_config', ''))

    if st.button('Validate & Analyze', type='primary'):
        if raw_config.strip():
            result = parse_network_config(raw_config, vendor=vendor)
            save_user_config(user_id, raw_config)
            add_log(user_id, 'configuration', f'Validated {result["total_lines"]} commands (Vendor: {result["vendor"]})')

            # Results
            if result['error_count'] > 0:
                st.error(f"Found {result['error_count']} error(s) and {result['warning_count']} warning(s)")
            elif result['warning_count'] > 0:
                st.warning(f"Found {result['warning_count']} warning(s)")
            else:
                st.success(f'All {result["total_lines"]} commands are valid!')

            st.info(f"Detected Vendor: **{result['vendor'].upper()}**")

            # Line-by-line
            st.subheader('Line-by-Line Validation')
            for line in result['line_details']:
                if line['errors']:
                    st.error(f"Line {line['num']}: `{line['line']}` — {', '.join(line['errors'])}")
                elif line['warnings']:
                    st.warning(f"Line {line['num']}: `{line['line']}` — {', '.join(line['warnings'])}")
                else:
                    st.success(f"Line {line['num']}: `{line['line']}` ✓")

            # Auto-fix
            if result['suggestions']:
                st.subheader('Auto-Fix Suggestions')
                for fix in result['suggestions']:
                    st.code(fix)

            # Ready config
            st.subheader('Ready-to-Apply Config')
            st.code(result['ready'])

            # Corrected config
            if result['corrected'] != result['ready']:
                st.subheader('Auto-Corrected Config')
                st.code(result['corrected'])

    # Load last config
    last = get_last_config(user_id)
    if last and not st.session_state.get('last_config'):
        st.session_state.last_config = last['config_text']


def show_devices():
    st.header('Devices')
    user_id = st.session_state.user_id
    devices = get_user_devices(user_id)

    # Add device form
    with st.expander('Add New Device'):
        with st.form('add_device_form'):
            name = st.text_input('Device Name')
            device_type = st.selectbox('Device Type', ['router', 'switch', 'firewall', 'server', 'ap'])
            vendor = st.selectbox('Vendor', ['cisco', 'juniper', 'huawei'])
            ip_address = st.text_input('Management IP (optional)')
            submitted = st.form_submit_button('Add Device')
            if submitted and name:
                add_device(user_id, name, device_type, vendor, ip_address or None)
                add_log(user_id, 'add_device', f'Added device: {name} ({vendor} {device_type})')
                st.success(f'Device "{name}" added!')
                st.rerun()

    # Device list
    if devices:
        for dev in devices:
            with st.container():
                col1, col2, col3 = st.columns([3, 2, 1])
                vendor_icon = {'cisco': '🔵', 'juniper': '🟢', 'huawei': '🔴'}.get(dev['vendor'], '⚪')
                col1.markdown(f"{vendor_icon} **{dev['name']}** — {dev['vendor'].title()} {dev['device_type'].title()}")
                col2.write(f"IP: {dev['ip_address'] or 'N/A'} | EVE-NG: {'✓' if dev['eve_node_id'] else '✗'} | NetBox: {'✓' if dev['netbox_id'] else '✗'}")
                if col3.button('Delete', key=f'del_{dev["id"]}'):
                    delete_device(dev['id'], user_id)
                    add_log(user_id, 'delete_device', f'Deleted device: {dev["name"]}')
                    st.rerun()
    else:
        st.info('No devices yet.')


def show_topology():
    st.header('Network Topology')
    user_id = st.session_state.user_id
    settings = get_user_settings(user_id)
    devices = get_user_devices(user_id)
    links = get_user_links(user_id)

    # EVE-NG Integration
    st.subheader('EVE-NG Integration')
    col1, col2, col3 = st.columns(3)
    if col1.button('Test EVE-NG Connection'):
        eve = get_eve_connector(settings)
        result = eve.test_connection()
        if result['success']:
            st.success('Connected to EVE-NG')
        else:
            st.error(result['error'])

    if col2.button('Start All Nodes'):
        eve = get_eve_connector(settings)
        eve.start_all_nodes()
        st.info('Starting all nodes...')

    if col3.button('Stop All Nodes'):
        eve = get_eve_connector(settings)
        eve.stop_all_nodes()
        st.info('Stopping all nodes...')

    # Topology display
    st.subheader('Device Map')
    if devices:
        for dev in devices:
            vendor_color = {'cisco': '🔵', 'juniper': '🟢', 'huawei': '🔴'}.get(dev['vendor'], '⚪')
            st.markdown(f"{vendor_color} **{dev['name']}** — {dev['status']}")

    if links:
        st.subheader('Connections')
        for link in links:
            st.write(f"{link['source_name']} [{link['source_interface'] or '-'}] ↔ {link['target_name']} [{link['target_interface'] or '-'}]")


def show_snapshots():
    st.header('Snapshots')
    user_id = st.session_state.user_id

    if st.button('Backup Now', type='primary'):
        config = get_last_config(user_id)
        if config:
            save_snapshot(user_id, f'Manual backup {datetime.now().strftime("%Y-%m-%d %H:%M")}', config['config_text'], snapshot_type='manual')
            add_log(user_id, 'manual_backup', 'Manual backup saved')
            st.success('Backup saved!')
            st.rerun()

    snapshots = get_user_snapshots(user_id)
    if snapshots:
        for snap in snapshots:
            snap_type = '🔄 Auto' if snap['snapshot_type'] == 'auto' else '💾 Manual'
            with st.expander(f"{snap_type} — {snap['name']} — {snap['created_at'][:16]}"):
                st.code(snap['config_text'])
                if st.button(f'Restore', key=f'restore_{snap["id"]}'):
                    save_user_config(user_id, snap['config_text'])
                    add_log(user_id, 'restore_snapshot', f'Restored snapshot: {snap["name"]}')
                    st.success('Snapshot restored!')
    else:
        st.info('No snapshots yet.')


def show_logs():
    st.header('Activity Logs')
    user_id = st.session_state.user_id
    logs = get_user_logs(user_id, limit=200)

    if logs:
        for log in logs:
            action_icons = {
                'login': '🔑', 'logout': '🚪', 'register': '📝', 'configuration': '⚙️',
                'add_device': '➕', 'delete_device': '🗑️', 'manual_backup': '💾',
                'auto_backup': '🔄', 'restore_snapshot': '⏪', 'update_settings': '🔧',
            }
            icon = action_icons.get(log['action'], '📋')
            st.markdown(f"{icon} **{log['action']}** — {log['details']} — _{log['created_at'][:16]}_")
    else:
        st.info('No logs yet.')


def show_alerts():
    st.header('Alerts')
    user_id = st.session_state.user_id
    alerts = get_user_alerts(user_id)

    if alerts:
        for alert in alerts:
            severity_icon = {'error': '🔴', 'warning': '🟡', 'info': '🔵'}.get(alert['severity'], '⚪')
            if alert['resolved']:
                st.markdown(f"~~{severity_icon} **{alert['alert_type']}** — {alert['message']}~~ ✅ Resolved")
            else:
                col1, col2 = st.columns([4, 1])
                col1.markdown(f"{severity_icon} **{alert['alert_type']}** — {alert['message']} — _{alert['created_at'][:16]}_")
                if col2.button('Resolve', key=f'resolve_{alert["id"]}'):
                    resolve_alert(alert['id'], user_id)
                    add_log(user_id, 'resolve_alert', f'Resolved alert #{alert["id"]}')
                    st.rerun()
    else:
        st.success('No alerts. System is running smoothly!')


def show_settings():
    st.header('Settings')
    user_id = st.session_state.user_id
    settings = get_user_settings(user_id)

    # Backup settings
    st.subheader('Backup Settings')
    new_interval = st.number_input('Auto-Backup Interval (minutes)', min_value=1, value=settings['backup_minutes'])

    # EVE-NG settings
    st.subheader('EVE-NG Integration')
    eve_url = st.text_input('EVE-NG URL', value=settings['eve_url'])
    eve_username = st.text_input('EVE-NG Username', value=settings['eve_username'])
    eve_password = st.text_input('EVE-NG Password', value=settings['eve_password'], type='password')
    eve_lab_path = st.text_input('EVE-NG Lab Path', value=settings['eve_lab_path'])

    # NetBox settings
    st.subheader('NetBox Integration')
    netbox_url = st.text_input('NetBox URL', value=settings['netbox_url'])
    netbox_token = st.text_input('API Token', value=settings['netbox_token'], type='password')

    if st.button('Save All Settings', type='primary'):
        update_user_settings(user_id,
                             backup_minutes=new_interval,
                             eve_url=eve_url,
                             eve_username=eve_username,
                             eve_password=eve_password,
                             eve_lab_path=eve_lab_path,
                             netbox_url=netbox_url,
                             netbox_token=netbox_token)
        add_log(user_id, 'update_settings', 'Settings updated')
        st.success('Settings saved!')


def show_app():
    if not st.session_state.logged_in:
        st.title('Network Sentinel')
        st.write('Intelligent Network Management System')
        auth_mode = st.radio('Choose', ['Login', 'Register'])
        if auth_mode == 'Login':
            with st.form('login_form'):
                email = st.text_input('Email')
                password = st.text_input('Password', type='password')
                submitted = st.form_submit_button('Sign In')
            if submitted:
                user = get_user_by_email(email.strip())
                if user and check_password_hash(user['password_hash'], password):
                    login_user(user)
                    add_log(user['id'], 'login', 'User logged in')
                    ensure_default_settings(user['id'])
                    st.rerun()
                else:
                    st.error('Invalid email or password.')
        else:
            with st.form('register_form'):
                name = st.text_input('Full Name')
                company = st.text_input('Company Name')
                email = st.text_input('Email')
                password = st.text_input('Password', type='password')
                submitted = st.form_submit_button('Create Account')
            if submitted:
                if get_user_by_email(email.strip()):
                    st.warning('Email already registered.')
                else:
                    create_user(name.strip(), company.strip(), email.strip(), generate_password_hash(password))
                    st.success('Account created! Please login.')
    else:
        st.sidebar.title(f'Welcome, {st.session_state.username}')
        st.sidebar.write(f'Company: {st.session_state.company}')
        page = st.sidebar.radio('Menu', ['Dashboard', 'Configuration', 'Devices', 'Topology', 'Snapshots', 'Logs', 'Alerts', 'Settings'])
        if st.sidebar.button('Logout'):
            logout_user()

        maybe_auto_backup(st.session_state.user_id)

        if page == 'Dashboard':
            show_dashboard()
        elif page == 'Configuration':
            show_configuration()
        elif page == 'Devices':
            show_devices()
        elif page == 'Topology':
            show_topology()
        elif page == 'Snapshots':
            show_snapshots()
        elif page == 'Logs':
            show_logs()
        elif page == 'Alerts':
            show_alerts()
        elif page == 'Settings':
            show_settings()


if __name__ == '__main__':
    show_app()
