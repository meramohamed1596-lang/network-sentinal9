# ==========================================
# COMPREHENSIVE AUTO-FIX REFERENCE - v3
# Cisco (25) + Juniper (15) + Huawei (26)
# With category + error_type for every rule
# ==========================================
import re


def _default_mask_for_ip(ip_str):
    """Return default subnet mask based on IP address class.

    Class A (1-126):   255.0.0.0     (/8)
    Class B (128-191): 255.255.0.0   (/16)
    Class C (192-223): 255.255.255.0 (/24)
    """
    try:
        first = int(ip_str.strip().split('.')[0])
    except (ValueError, IndexError):
        return '255.255.255.0'
    if 1 <= first <= 126:
        return '255.0.0.0'
    elif 128 <= first <= 191:
        return '255.255.0.0'
    return '255.255.255.0'


def _default_cidr_for_ip(ip_str):
    """Return default CIDR prefix length based on IP address class."""
    try:
        first = int(ip_str.strip().split('.')[0])
    except (ValueError, IndexError):
        return '24'
    if 1 <= first <= 126:
        return '8'
    elif 128 <= first <= 191:
        return '16'
    return '24'


def _add_class_mask(line):
    """Add a class-based default mask to an 'ip address X.X.X.X' line."""
    m = re.match(r'^(\s*ip\s+address\s+)(\d+\.\d+\.\d+\.\d+)\s*$', line, re.IGNORECASE)
    if m:
        return m.group(1) + m.group(2) + ' ' + _default_mask_for_ip(m.group(2))
    return line


def _add_class_cidr(line):
    """Add a class-based /prefix to a Juniper address line missing it."""
    m = re.match(r'^(.*address\s+)(\d+\.\d+\.\d+\.\d+)\s*$', line, re.IGNORECASE)
    if m:
        return m.group(1) + m.group(2) + '/' + _default_cidr_for_ip(m.group(2))
    return line

ERROR_FIXES = {
    'cisco': [
        # === IP ADDRESS FIXES ===
        {
            'check': lambda line: bool(re.match(r'^\s*ip\s+address\s+\d+\.\d+\.\d+\.\d+\s*$', line, re.IGNORECASE)),
            'error': 'Missing subnet mask in IP address',
            'fix': lambda line: _add_class_mask(line),
            'severity': 'error',
            'source': 'Cisco IOS IP Addressing Guide',
            'category': 'ip_address',
            'error_type': 'syntax',
        },
        {
            'check': lambda line: 'no shut' in line.lower() and 'no shutdown' not in line.lower(),
            'error': 'Abbreviated command: no shut',
            'fix': lambda line: re.sub(r'(?i)no\s+shut', 'no shutdown', line),
            'severity': 'error',
            'source': 'Cisco IOS Command Reference',
            'category': 'interface',
            'error_type': 'syntax',
        },
        {
            'check': lambda line: bool(re.match(r'^\s*hostname\s*$', line, re.IGNORECASE)),
            'error': 'Hostname missing device name',
            'fix': lambda line: line.strip() + ' Router',
            'severity': 'error',
            'source': 'Cisco Configuration Guide',
            'category': 'management',
            'error_type': 'compliance',
        },
        {
            'check': lambda line: bool(re.match(r'^\s*router\s+ospf\s*$', line, re.IGNORECASE)),
            'error': 'OSPF missing process ID',
            'fix': lambda line: line.strip() + ' 1',
            'severity': 'error',
            'source': 'Cisco OSPF Configuration Guide',
            'category': 'routing',
            'error_type': 'syntax',
        },
        {
            'check': lambda line: bool(re.match(r'^\s*network\s+\d+\.\d+\.\d+\.\d+\s*$', line, re.IGNORECASE)),
            'error': 'Network statement may need wildcard mask and area (OSPF) or is valid as-is (RIP/EIGRP)',
            'fix': None,
            'severity': 'warning',
            'source': 'Cisco Routing Protocol Guide',
            'category': 'routing',
            'error_type': 'semantic',
        },
        {
            'check': lambda line: bool(re.match(r'^\s*network\s+\d+\.\d+\.\d+\.\d+\s+\d+\.\d+\.\d+\.\d+\s*$', line, re.IGNORECASE)),
            'error': 'OSPF network statement missing area ID',
            'fix': lambda line: line.strip() + ' area 0',
            'severity': 'error',
            'source': 'Cisco OSPF Configuration Guide',
            'category': 'routing',
            'error_type': 'syntax',
        },
        {
            'check': lambda line: bool(re.match(r'^\s*router\s+eigrp\s*$', line, re.IGNORECASE)),
            'error': 'EIGRP missing AS number',
            'fix': lambda line: line.strip() + ' 100',
            'severity': 'error',
            'source': 'Cisco EIGRP Configuration Guide',
            'category': 'routing',
            'error_type': 'syntax',
        },
        {
            'check': lambda line: bool(re.match(r'^\s*router\s+bgp\s*$', line, re.IGNORECASE)),
            'error': 'BGP missing AS number',
            'fix': lambda line: line.strip() + ' 65001',
            'severity': 'error',
            'source': 'Cisco BGP Configuration Guide',
            'category': 'routing',
            'error_type': 'syntax',
        },
        {
            'check': lambda line: bool(re.match(r'^\s*neighbor\s+\d+\.\d+\.\d+\.\d+\s*$', line, re.IGNORECASE)),
            'error': 'BGP neighbor missing remote-as',
            'fix': lambda line: line.strip() + ' remote-as 65002',
            'severity': 'error',
            'source': 'Cisco BGP Configuration Guide',
            'category': 'routing',
            'error_type': 'syntax',
        },
        {
            'check': lambda line: bool(re.match(r'^\s*neighbor\s+\d+\.\d+\.\d+\.\d+\s+remote-as\s*$', line, re.IGNORECASE)),
            'error': 'BGP neighbor remote-as missing AS number',
            'fix': lambda line: line.strip() + ' 65002',
            'severity': 'error',
            'source': 'Cisco BGP Configuration Guide',
            'category': 'routing',
            'error_type': 'syntax',
        },
        {
            'check': lambda line: bool(re.match(r'^\s*vlan\s*$', line, re.IGNORECASE)),
            'error': 'VLAN missing ID',
            'fix': lambda line: line.strip() + ' 10',
            'severity': 'error',
            'source': 'Cisco VLAN Configuration Guide',
            'category': 'switching',
            'error_type': 'syntax',
        },
        {
            'check': lambda line: bool(re.match(r'^\s*switchport\s+mode\s*$', line, re.IGNORECASE)),
            'error': 'Switchport mode not specified',
            'fix': lambda line: line.strip() + ' access',
            'severity': 'warning',
            'source': 'Cisco Switchport Configuration Guide',
            'category': 'switching',
            'error_type': 'compliance',
        },
        {
            'check': lambda line: bool(re.match(r'^\s*switchport\s+access\s+vlan\s*$', line, re.IGNORECASE)),
            'error': 'Access VLAN not specified',
            'fix': lambda line: line.strip() + ' 1',
            'severity': 'error',
            'source': 'Cisco Switchport Configuration Guide',
            'category': 'switching',
            'error_type': 'syntax',
        },
        # === SNMP ===
        {
            'check': lambda line: bool(re.match(r'^\s*snmp-server\s+community\s*$|^\s*snmp-server\s+community\s+\S+\s*$', line, re.IGNORECASE)),
            'error': 'SNMP community incomplete',
            'fix': lambda line: line.strip() + ' public RO' if line.strip() == 'snmp-server community' else line.strip(),
            'severity': 'warning',
            'source': 'Cisco SNMP Configuration Guide',
            'category': 'management',
            'error_type': 'compliance',
        },
        # === SECURITY ===
        {
            'check': lambda line: bool(re.match(r'^\s*password\s*$', line, re.IGNORECASE)),
            'error': 'Password not specified',
            'fix': lambda line: line.strip() + ' cisco123',
            'severity': 'error',
            'source': 'Cisco Security Guide',
            'category': 'security',
            'error_type': 'syntax',
        },
        {
            'check': lambda line: bool(re.match(r'^\s*enable\s+password\s*$', line, re.IGNORECASE)),
            'error': 'Enable password missing',
            'fix': lambda line: line.strip() + ' cisco123',
            'severity': 'error',
            'source': 'Cisco Security Guide',
            'category': 'security',
            'error_type': 'syntax',
        },
        {
            'check': lambda line: bool(re.match(r'^\s*crypto\s+key\s+generate\s+rsa\s*$', line, re.IGNORECASE)),
            'error': 'RSA key missing modulus size',
            'fix': lambda line: line.strip() + ' modulus 2048',
            'severity': 'warning',
            'source': 'Cisco SSH Configuration Guide',
            'category': 'security',
            'error_type': 'compliance',
        },
        # === ROUTING ===
        {
            'check': lambda line: bool(re.match(r'^\s*ip\s+route\s+\d+\.\d+\.\d+\.\d+\s+\d+\.\d+\.\d+\.\d+\s*$', line, re.IGNORECASE)),
            'error': 'Static route missing next-hop or exit interface',
            'fix': None,  # Cannot auto-fix: next-hop depends on network topology
            'severity': 'error',
            'source': 'Cisco Routing Configuration Guide',
            'category': 'routing',
            'error_type': 'syntax',
        },
        {
            'check': lambda line: bool(re.match(r'^\s*access-list\s+\d+\s+(permit|deny)\s+\d+\.\d+\.\d+\.\d+\s*$', line, re.IGNORECASE)),
            'error': 'ACL entry missing wildcard mask',
            'fix': lambda line: line.strip() + ' 0.0.0.0',
            'severity': 'error',
            'source': 'Cisco ACL Configuration Guide',
            'category': 'security',
            'error_type': 'syntax',
        },
        {
            'check': lambda line: bool(re.match(r'^\s*router-id\s*$', line, re.IGNORECASE)),
            'error': 'Router ID not specified',
            'fix': lambda line: line.strip() + ' 1.1.1.1',
            'severity': 'warning',
            'source': 'Cisco OSPF Configuration Guide',
            'category': 'routing',
            'error_type': 'compliance',
        },
        # === INTERFACE ===
        {
            'check': lambda line: bool(re.match(r'^\s*speed\s*$', line, re.IGNORECASE)),
            'error': 'Interface speed not specified',
            'fix': lambda line: line.strip() + ' 1000',
            'severity': 'warning',
            'source': 'Cisco Interface Configuration Guide',
            'category': 'interface',
            'error_type': 'compliance',
        },
        {
            'check': lambda line: bool(re.match(r'^\s*duplex\s*$', line, re.IGNORECASE)),
            'error': 'Duplex mode not specified',
            'fix': lambda line: line.strip() + ' full',
            'severity': 'warning',
            'source': 'Cisco Interface Configuration Guide',
            'category': 'interface',
            'error_type': 'compliance',
        },
        {
            'check': lambda line: bool(re.match(r'^\s*description\s*$', line, re.IGNORECASE)),
            'error': 'Interface description is empty',
            'fix': lambda line: line.strip() + ' Configured by Network Sentinel',
            'severity': 'warning',
            'source': 'Cisco Best Practices',
            'category': 'interface',
            'error_type': 'compliance',
        },
        # === LINE / MANAGEMENT ===
        {
            'check': lambda line: bool(re.match(r'^\s*line\s+(console|vty)\s+\d+\s*$', line, re.IGNORECASE)),
            'error': None,
            'fix': None,
            'severity': 'info',
            'source': 'Cisco Line Configuration Guide',
            'category': 'management',
            'error_type': 'syntax',
        },
        # === SECONDARY IP ===
        {
            'check': lambda line: bool(re.match(r'^\s*ip\s+address\s+\d+\.\d+\.\d+\.\d+\s+\d+\.\d+\.\d+\.\d+\s+secondary\s*$', line, re.IGNORECASE)),
            'error': None,
            'fix': None,
            'severity': 'info',
            'source': 'Cisco IOS IP Addressing Guide',
            'category': 'ip_address',
            'error_type': 'syntax',
        },
    ],
    'juniper': [
        # === SYSTEM & HOSTNAME ===
        {
            'check': lambda line: bool(re.match(r'^\s*set\s+system\s+host-name\s*$', line, re.IGNORECASE)),
            'error': 'Juniper hostname not specified',
            'fix': lambda line: line.strip() + ' Juniper-Router',
            'severity': 'error',
            'source': 'Juniper Junos OS Configuration Guide',
            'category': 'management',
            'error_type': 'compliance',
        },
        {
            'check': lambda line: bool(re.match(r'^\s*set\s+system\s+root-authentication\s*$', line, re.IGNORECASE)),
            'error': 'Root authentication missing password',
            'fix': lambda line: line.strip() + ' "$6$RbB3$..."',
            'severity': 'error',
            'source': 'Juniper Security Guide',
            'category': 'security',
            'error_type': 'syntax',
        },
        # === INTERFACE FIXES ===
        {
            'check': lambda line: bool(re.match(r'^\s*set\s+interfaces\s+\S+\s+unit\s+\d+\s*$', line, re.IGNORECASE)),
            'error': 'Interface unit incomplete',
            'fix': lambda line: line.strip() + ' family inet',
            'severity': 'error',
            'source': 'Juniper Interface Guide',
            'category': 'interface',
            'error_type': 'syntax',
        },
        {
            'check': lambda line: bool(re.match(r'^\s*set\s+interfaces\s+\S+\s+unit\s+\d+\s+family\s+inet\s*$', line, re.IGNORECASE)),
            'error': 'Interface missing IP address',
            'fix': lambda line: line.strip() + ' address 192.168.1.1/24',
            'severity': 'error',
            'source': 'Juniper Interface Guide',
            'category': 'ip_address',
            'error_type': 'syntax',
        },
        {
            'check': lambda line: bool(re.match(r'^\s*set\s+interfaces\s+\S+\s+unit\s+\d+\s+family\s+inet\s+address\s+\d+\.\d+\.\d+\.\d+\s*$', line, re.IGNORECASE)),
            'error': 'IP address missing CIDR prefix',
            'fix': lambda line: _add_class_cidr(line),
            'severity': 'error',
            'source': 'Juniper Interface Guide',
            'category': 'ip_address',
            'error_type': 'syntax',
        },
        {
            'check': lambda line: bool(re.match(r'^\s*set\s+interfaces\s+\S+\s+disable\s*$', line, re.IGNORECASE)),
            'error': 'Interface is disabled',
            'fix': lambda line: re.sub(r'disable', 'enable', line, flags=re.IGNORECASE),
            'severity': 'warning',
            'source': 'Juniper Interface Guide',
            'category': 'interface',
            'error_type': 'compliance',
        },
        # === ROUTING FIXES ===
        {
            'check': lambda line: bool(re.match(r'^\s*set\s+protocols\s+ospf\s+area\s*$', line, re.IGNORECASE)),
            'error': 'OSPF area number missing',
            'fix': lambda line: line.strip() + ' 0.0.0.0',
            'severity': 'error',
            'source': 'Juniper OSPF Guide',
            'category': 'routing',
            'error_type': 'syntax',
        },
        {
            'check': lambda line: bool(re.match(r'^\s*set\s+protocols\s+ospf\s+area\s+\S+\s+interface\s*$', line, re.IGNORECASE)),
            'error': 'OSPF interface not specified',
            'fix': lambda line: line.strip() + ' ge-0/0/0.0',
            'severity': 'error',
            'source': 'Juniper OSPF Guide',
            'category': 'routing',
            'error_type': 'syntax',
        },
        {
            'check': lambda line: bool(re.match(r'^\s*set\s+protocols\s+bgp\s+group\s+\S+\s+type\s*$', line, re.IGNORECASE)),
            'error': 'BGP group type missing',
            'fix': lambda line: line.strip() + ' external',
            'severity': 'error',
            'source': 'Juniper BGP Guide',
            'category': 'routing',
            'error_type': 'syntax',
        },
        {
            'check': lambda line: bool(re.match(r'^\s*set\s+protocols\s+bgp\s+group\s+\S+\s+neighbor\s+\d+\.\d+\.\d+\.\d+\s*$', line, re.IGNORECASE)),
            'error': 'BGP neighbor missing peer-as',
            'fix': lambda line: line.strip() + ' peer-as 65002',
            'severity': 'error',
            'source': 'Juniper BGP Guide',
            'category': 'routing',
            'error_type': 'syntax',
        },
        # === SNMP ===
        {
            'check': lambda line: bool(re.match(r'^\s*set\s+snmp\s+community\s+\S+\s*$', line, re.IGNORECASE)),
            'error': 'SNMP community missing authorization',
            'fix': lambda line: line.strip() + ' authorization read-only',
            'severity': 'warning',
            'source': 'Juniper SNMP Guide',
            'category': 'management',
            'error_type': 'compliance',
        },
        # === SECURITY ===
        {
            'check': lambda line: bool(re.match(r'^\s*set\s+system\s+services\s+telnet\s*$', line, re.IGNORECASE)),
            'error': 'Telnet is insecure',
            'fix': lambda line: '# ' + line.strip(),
            'severity': 'warning',
            'source': 'Juniper Security Best Practices',
            'category': 'security',
            'error_type': 'security',
        },
        {
            'check': lambda line: bool(re.match(r'^\s*set\s+routing-options\s+static\s+route\s+\S+\s*$', line, re.IGNORECASE)),
            'error': 'Static route missing next-hop',
            'fix': None,  # Cannot auto-fix: next-hop depends on topology
            'severity': 'error',
            'source': 'Juniper Routing Configuration Guide',
            'category': 'routing',
            'error_type': 'syntax',
        },
        {
            'check': lambda line: bool(re.match(r'^\s*set\s+vlans\s+\S+\s+vlan-id\s*$', line, re.IGNORECASE)),
            'error': 'VLAN ID not specified',
            'fix': lambda line: line.strip() + ' 10',
            'severity': 'error',
            'source': 'Juniper VLAN Configuration Guide',
            'category': 'switching',
            'error_type': 'syntax',
        },
        # === NEW: autonomous-system, firewall then, login class ===
        {
            'check': lambda line: bool(re.match(r'^\s*set\s+routing-options\s+autonomous-system\s*$', line, re.IGNORECASE)),
            'error': 'BGP autonomous-system not specified',
            'fix': lambda line: line.strip() + ' 65001',
            'severity': 'error',
            'source': 'Juniper BGP Configuration Guide',
            'category': 'routing',
            'error_type': 'syntax',
        },
    ],
    'huawei': [
        # === SYSTEM ===
        {
            'check': lambda line: bool(re.match(r'^\s*sysname\s*$', line, re.IGNORECASE)),
            'error': 'Huawei sysname not specified',
            'fix': lambda line: line.strip() + ' Huawei-Router',
            'severity': 'error',
            'source': 'Huawei VRP Configuration Guide',
            'category': 'management',
            'error_type': 'compliance',
        },
        # === INTERFACE FIXES ===
        {
            'check': lambda line: bool(re.match(r'^\s*ip\s+address\s+\d+\.\d+\.\d+\.\d+\s*$', line, re.IGNORECASE)),
            'error': 'IP address missing subnet mask',
            'fix': lambda line: _add_class_mask(line),
            'severity': 'error',
            'source': 'Huawei VRP Interface Guide',
            'category': 'ip_address',
            'error_type': 'syntax',
        },
        {
            'check': lambda line: bool(re.match(r'^\s*shutdown\s*$', line, re.IGNORECASE)),
            'error': 'Interface is shut down',
            'fix': lambda line: 'undo shutdown',
            'severity': 'warning',
            'source': 'Huawei VRP Interface Guide',
            'category': 'interface',
            'error_type': 'compliance',
        },
        {
            'check': lambda line: bool(re.match(r'^\s*description\s*$', line, re.IGNORECASE)),
            'error': 'Interface description missing',
            'fix': lambda line: line.strip() + ' Configured by Network Sentinel',
            'severity': 'warning',
            'source': 'Huawei VRP Interface Guide',
            'category': 'interface',
            'error_type': 'compliance',
        },
        {
            'check': lambda line: bool(re.match(r'^\s*port\s+link-type\s*$', line, re.IGNORECASE)),
            'error': 'Port link-type not specified',
            'fix': lambda line: line.strip() + ' access',
            'severity': 'warning',
            'source': 'Huawei VRP Switching Guide',
            'category': 'switching',
            'error_type': 'compliance',
        },
        {
            'check': lambda line: bool(re.match(r'^\s*port\s+default\s+vlan\s*$', line, re.IGNORECASE)),
            'error': 'Default VLAN not specified',
            'fix': lambda line: line.strip() + ' 1',
            'severity': 'error',
            'source': 'Huawei VRP Switching Guide',
            'category': 'switching',
            'error_type': 'syntax',
        },
        {
            'check': lambda line: bool(re.match(r'^\s*port\s+trunk\s+allow-pass\s+vlan\s*$', line, re.IGNORECASE)),
            'error': 'Trunk allowed VLANs missing',
            'fix': lambda line: line.strip() + ' 1 to 4094',
            'severity': 'warning',
            'source': 'Huawei VRP Switching Guide',
            'category': 'switching',
            'error_type': 'compliance',
        },
        # === ROUTING FIXES ===
        {
            'check': lambda line: bool(re.match(r'^\s*ospf\s*$', line, re.IGNORECASE)),
            'error': 'OSPF process ID missing',
            'fix': lambda line: line.strip() + ' 1',
            'severity': 'error',
            'source': 'Huawei VRP OSPF Guide',
            'category': 'routing',
            'error_type': 'syntax',
        },
        {
            'check': lambda line: bool(re.match(r'^\s*network\s+\d+\.\d+\.\d+\.\d+\s*$', line, re.IGNORECASE)),
            'error': 'OSPF network missing wildcard mask',
            'fix': lambda line: line.strip() + ' 0.0.0.255',
            'severity': 'error',
            'source': 'Huawei VRP OSPF Guide',
            'category': 'routing',
            'error_type': 'syntax',
        },
        {
            'check': lambda line: bool(re.match(r'^\s*area\s*$', line, re.IGNORECASE)),
            'error': 'OSPF area number missing',
            'fix': lambda line: line.strip() + ' 0',
            'severity': 'error',
            'source': 'Huawei VRP OSPF Guide',
            'category': 'routing',
            'error_type': 'syntax',
        },
        {
            'check': lambda line: bool(re.match(r'^\s*bgp\s*$', line, re.IGNORECASE)),
            'error': 'BGP AS number missing',
            'fix': lambda line: line.strip() + ' 65001',
            'severity': 'error',
            'source': 'Huawei VRP BGP Guide',
            'category': 'routing',
            'error_type': 'syntax',
        },
        {
            'check': lambda line: bool(re.match(r'^\s*peer\s+\d+\.\d+\.\d+\.\d+\s*$', line, re.IGNORECASE)),
            'error': 'BGP peer missing AS number',
            'fix': lambda line: line.strip() + ' as-number 65002',
            'severity': 'error',
            'source': 'Huawei VRP BGP Guide',
            'category': 'routing',
            'error_type': 'syntax',
        },
        # === VLAN FIXES ===
        {
            'check': lambda line: bool(re.match(r'^\s*vlan\s*$', line, re.IGNORECASE)),
            'error': 'VLAN ID missing',
            'fix': lambda line: line.strip() + ' 10',
            'severity': 'error',
            'source': 'Huawei VRP VLAN Guide',
            'category': 'switching',
            'error_type': 'syntax',
        },
        {
            'check': lambda line: bool(re.match(r'^\s*vlan\s+batch\s*$', line, re.IGNORECASE)),
            'error': 'VLAN batch list missing',
            'fix': lambda line: line.strip() + ' 10 20 30',
            'severity': 'warning',
            'source': 'Huawei VRP VLAN Guide',
            'category': 'switching',
            'error_type': 'compliance',
        },
        # === SNMP FIXES ===
        {
            'check': lambda line: bool(re.match(r'^\s*snmp-agent\s+community\s+read\s*$', line, re.IGNORECASE)),
            'error': 'SNMP read community missing',
            'fix': lambda line: line.strip() + ' public',
            'severity': 'error',
            'source': 'Huawei VRP SNMP Guide',
            'category': 'management',
            'error_type': 'syntax',
        },
        {
            'check': lambda line: bool(re.match(r'^\s*snmp-agent\s+community\s+write\s*$', line, re.IGNORECASE)),
            'error': 'SNMP write community missing',
            'fix': lambda line: line.strip() + ' private',
            'severity': 'error',
            'source': 'Huawei VRP SNMP Guide',
            'category': 'management',
            'error_type': 'syntax',
        },
        {
            'check': lambda line: bool(re.match(r'^\s*snmp-agent\s+sys-info\s+location\s*$', line, re.IGNORECASE)),
            'error': 'SNMP location missing',
            'fix': lambda line: line.strip() + ' Data Center',
            'severity': 'warning',
            'source': 'Huawei VRP SNMP Guide',
            'category': 'management',
            'error_type': 'compliance',
        },
        # === SECURITY FIXES ===
        {
            'check': lambda line: bool(re.match(r'^\s*local-user\s+\S+\s+password\s*$', line, re.IGNORECASE)),
            'error': 'Local user password missing',
            'fix': lambda line: line.strip() + ' cipher Huawei123',
            'severity': 'error',
            'source': 'Huawei VRP Security Guide',
            'category': 'security',
            'error_type': 'syntax',
        },
        {
            'check': lambda line: bool(re.match(r'^\s*authentication-mode\s*$', line, re.IGNORECASE)),
            'error': 'Authentication mode not specified',
            'fix': lambda line: line.strip() + ' aaa',
            'severity': 'error',
            'source': 'Huawei VRP Security Guide',
            'category': 'security',
            'error_type': 'syntax',
        },
        {
            'check': lambda line: bool(re.match(r'^\s*protocol\s+inbound\s*$', line, re.IGNORECASE)),
            'error': 'VTY protocol not specified',
            'fix': lambda line: line.strip() + ' ssh',
            'severity': 'warning',
            'source': 'Huawei VRP VTY Guide',
            'category': 'security',
            'error_type': 'compliance',
        },
        # === STP FIXES ===
        {
            'check': lambda line: bool(re.match(r'^\s*stp\s+mode\s*$', line, re.IGNORECASE)),
            'error': 'STP mode not specified',
            'fix': lambda line: line.strip() + ' rstp',
            'severity': 'warning',
            'source': 'Huawei VRP STP Guide',
            'category': 'switching',
            'error_type': 'compliance',
        },
        {
            'check': lambda line: bool(re.match(r'^\s*stp\s+priority\s*$', line, re.IGNORECASE)),
            'error': 'STP priority missing',
            'fix': lambda line: line.strip() + ' 32768',
            'severity': 'warning',
            'source': 'Huawei VRP STP Guide',
            'category': 'switching',
            'error_type': 'compliance',
        },
        # === ROUTING ===
        {
            'check': lambda line: bool(re.match(r'^\s*ip\s+route-static\s+\d+\.\d+\.\d+\.\d+\s+\d+\.\d+\.\d+\.\d+\s*$', line, re.IGNORECASE)),
            'error': 'Static route missing next-hop',
            'fix': None,  # Cannot auto-fix: next-hop depends on topology
            'severity': 'error',
            'source': 'Huawei VRP Routing Guide',
            'category': 'routing',
            'error_type': 'syntax',
        },
        {
            'check': lambda line: bool(re.match(r'^\s*rule\s+\d+\s+(permit|deny)\s*$', line, re.IGNORECASE)),
            'error': 'ACL rule missing match criteria',
            'fix': lambda line: line.strip() + ' source any',
            'severity': 'error',
            'source': 'Huawei VRP ACL Guide',
            'category': 'security',
            'error_type': 'syntax',
        },
        {
            'check': lambda line: bool(re.match(r'^\s*dhcp\s+select\s*$', line, re.IGNORECASE)),
            'error': 'DHCP select mode not specified',
            'fix': lambda line: line.strip() + ' interface',
            'severity': 'error',
            'source': 'Huawei VRP DHCP Guide',
            'category': 'interface',
            'error_type': 'syntax',
        },
        {
            'check': lambda line: bool(re.match(r'^\s*import-route\s*$', line, re.IGNORECASE)),
            'error': 'Import-route type not specified',
            'fix': lambda line: line.strip() + ' direct',
            'severity': 'error',
            'source': 'Huawei VRP Routing Guide',
            'category': 'routing',
            'error_type': 'syntax',
        },
        {
            'check': lambda line: bool(re.match(r'^\s*cost\s*$', line, re.IGNORECASE)),
            'error': 'OSPF cost not specified',
            'fix': lambda line: line.strip() + ' 1',
            'severity': 'warning',
            'source': 'Huawei VRP OSPF Guide',
            'category': 'routing',
            'error_type': 'compliance',
        },
    ],
}
