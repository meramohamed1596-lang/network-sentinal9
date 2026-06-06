CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    company TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    action TEXT NOT NULL,
    details TEXT,
    ip_address TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    config_text TEXT,
    device_name TEXT,
    snapshot_type TEXT DEFAULT 'manual',
    created_at TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS settings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    backup_minutes INTEGER NOT NULL DEFAULT 15,
    eve_url TEXT DEFAULT 'http://127.0.0.1',
    eve_username TEXT DEFAULT 'admin',
    eve_password TEXT DEFAULT 'eve',
    eve_lab_path TEXT DEFAULT '',
    netbox_url TEXT DEFAULT 'http://192.168.163.145:8000',
    netbox_token TEXT DEFAULT '',
    auto_remediate INTEGER DEFAULT 0,
    FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS configs (
    user_id INTEGER PRIMARY KEY,
    config_text TEXT,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    device_type TEXT NOT NULL,
    vendor TEXT NOT NULL DEFAULT 'cisco',
    ip_address TEXT,
    status TEXT DEFAULT 'unknown',
    eve_node_id TEXT,
    netbox_id INTEGER,
    network_group TEXT,
    snapshot_id INTEGER,
    last_seen TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(snapshot_id) REFERENCES network_snapshots(id)
);

CREATE TABLE IF NOT EXISTS device_config_applications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    device_id INTEGER NOT NULL,
    source TEXT NOT NULL DEFAULT 'configuration',
    raw_config TEXT NOT NULL,
    corrected_config TEXT NOT NULL,
    vendor TEXT NOT NULL,
    validation_state TEXT NOT NULL,
    application_state TEXT NOT NULL,
    eve_node_id TEXT,
    eve_result TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(device_id) REFERENCES devices(id)
);

CREATE TABLE IF NOT EXISTS topology_links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    source_device_id INTEGER NOT NULL,
    target_device_id INTEGER NOT NULL,
    source_interface TEXT,
    target_interface TEXT,
    link_status TEXT DEFAULT 'mapped',
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(source_device_id) REFERENCES devices(id),
    FOREIGN KEY(target_device_id) REFERENCES devices(id)
);

CREATE TABLE IF NOT EXISTS network_groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS network_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    config_source TEXT,
    device_count INTEGER DEFAULT 0,
    link_count INTEGER DEFAULT 0,
    created_at TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS validation_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vendor TEXT NOT NULL DEFAULT 'cisco',
    category TEXT NOT NULL,
    pattern TEXT NOT NULL,
    error_message TEXT,
    fix_template TEXT,
    severity TEXT DEFAULT 'error'
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    device_id INTEGER,
    alert_type TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'warning',
    message TEXT NOT NULL,
    resolved INTEGER DEFAULT 0,
    created_at TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(device_id) REFERENCES devices(id)
);

-- Seed validation rules for Cisco
INSERT OR IGNORE INTO validation_rules (vendor, category, pattern, error_message, fix_template, severity) VALUES
('cisco', 'interface', 'interface\s+\S+', NULL, NULL, 'info'),
('cisco', 'ip_address', 'ip\s+address\s+\d+\.\d+\.\d+\.\d+', 'Missing subnet mask for IP address', 'ip address {ip} {mask}', 'error'),
('cisco', 'ip_address', 'ip\s+address\s+\d+\.\d+\.\d+\.\d+\s+\d+\.\d+\.\d+\.\d+', NULL, NULL, 'info'),
('cisco', 'ospf', 'router\s+ospf\s+\d+', NULL, NULL, 'info'),
('cisco', 'ospf_network', 'network\s+\d+\.\d+\.\d+\.\d+\s+\d+\.\d+\.\d+\.\d+\s+area\s+\d+', NULL, NULL, 'info'),
('cisco', 'vlan', 'vlan\s+\d+', NULL, NULL, 'info'),
('cisco', 'hostname', 'hostname\s+\S+', NULL, NULL, 'info'),
('cisco', 'acl', 'access-list\s+\d+\s+(permit|deny)\s+', NULL, NULL, 'info'),
('cisco', 'routing', 'ip\s+route\s+\d+\.\d+\.\d+\.\d+\s+\d+\.\d+\.\d+\.\d+\s+\d+\.\d+\.\d+\.\d+', NULL, NULL, 'info'),
('cisco', 'snmp', 'snmp-server\s+community\s+\S+\s+(RO|RW)', 'SNMP community should specify access level', 'snmp-server community {community} RO', 'warning'),
('cisco', 'ntp', 'ntp\s+server\s+\S+', NULL, NULL, 'info'),
('cisco', 'no_shutdown', 'no\s+shutdown', NULL, NULL, 'info'),
('cisco', 'enable_secret', 'enable\s+secret\s+\S+', NULL, NULL, 'info'),
('cisco', 'description', 'description\s+.+', NULL, NULL, 'info'),
('cisco', 'switchport', 'switchport\s+(mode|access|trunk)\s+\S+', NULL, NULL, 'info'),
('cisco', 'dhcp', 'ip\s+dhcp\s+pool\s+\S+', NULL, NULL, 'info'),
('cisco', 'nat', 'ip\s+nat\s+(inside|outside)\s+source\s+', NULL, NULL, 'info'),

-- Juniper validation rules
('juniper', 'interface', 'set\s+interfaces\s+\S+', NULL, NULL, 'info'),
('juniper', 'ip_address', 'set\s+interfaces\s+\S+\s+unit\s+\d+\s+family\s+inet\s+address\s+\d+\.\d+\.\d+\.\d+/\d+', NULL, NULL, 'info'),
('juniper', 'ospf', 'set\s+protocols\s+ospf\s+area\s+\d+\s+interface\s+\S+', NULL, NULL, 'info'),
('juniper', 'vlan', 'set\s+vlans\s+\S+\s+vlan-id\s+\d+', NULL, NULL, 'info'),
('juniper', 'hostname', 'set\s+system\s+host-name\s+\S+', NULL, NULL, 'info'),
('juniper', 'routing', 'set\s+routing-options\s+static\s+route\s+\S+', NULL, NULL, 'info'),
('juniper', 'snmp', 'set\s+snmp\s+community\s+\S+', NULL, NULL, 'info'),
('juniper', 'firewall', 'set\s+firewall\s+family\s+inet\s+filter\s+\S+\s+term\s+\S+', NULL, NULL, 'info'),

-- Huawei validation rules
('huawei', 'interface', 'interface\s+\S+', NULL, NULL, 'info'),
('huawei', 'ip_address', 'ip\s+address\s+\d+\.\d+\.\d+\.\d+\s+\d+\.\d+\.\d+\.\d+', NULL, NULL, 'info'),
('huawei', 'ospf', 'ospf\s+\d+\s+area\s+\d+', NULL, NULL, 'info'),
('huawei', 'vlan', 'vlan\s+\d+', NULL, NULL, 'info'),
('huawei', 'hostname', 'sysname\s+\S+', NULL, NULL, 'info'),
('huawei', 'acl', 'acl\s+number\s+\d+', NULL, NULL, 'info'),
('huawei', 'route', 'ip\s+route-static\s+\d+\.\d+\.\d+\.\d+\s+\d+\.\d+\.\d+\.\d+\s+\S+', NULL, NULL, 'info');
