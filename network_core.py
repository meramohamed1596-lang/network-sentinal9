import os
import difflib
import json
import re
import sqlite3
import ipaddress
from datetime import datetime
from time import sleep
from werkzeug.security import generate_password_hash, check_password_hash

# Import comprehensive error fixes
from comprehensive_error_fixes import ERROR_FIXES

# Import semantic validation engine
from config_validator import ConfigValidator, is_valid_ip as _cv_is_ip, is_valid_netmask as _cv_is_netmask

DATABASE = os.path.join(os.path.dirname(__file__), 'network_system.db')
DEFAULT_BACKUP_MINUTES = 15
SCHEMA_FILE = os.path.join(os.path.dirname(__file__), 'schema.sql')
_SCHEMA_COMPATIBLE = False
SQLITE_TIMEOUT_SECONDS = 30
SQLITE_BUSY_TIMEOUT_MS = 30000
SQLITE_LOCK_RETRIES = 3

CISCO_INTERFACE_NAME_PATTERN = r'(?:GigabitEthernet|FastEthernet|Ethernet|Serial|Loopback|Vlan|Tunnel|Port-channel)\s*\d+(?:/\d+)*(?:\.\d+)?'
CISCO_INTERFACE_RANGE_END_PATTERN = rf'(?:{CISCO_INTERFACE_NAME_PATTERN}|\d+(?:/\d+)*(?:\.\d+)?)'
CISCO_INTERFACE_RANGE_LOOSE_RE = re.compile(
    rf'^interface\s+range\s+({CISCO_INTERFACE_NAME_PATTERN})\s*-\s*({CISCO_INTERFACE_RANGE_END_PATTERN})$',
    re.IGNORECASE,
)
CISCO_INTERFACE_RANGE_VALID_RE = re.compile(
    rf'^interface\s+range\s+{CISCO_INTERFACE_NAME_PATTERN}\s+-\s+{CISCO_INTERFACE_RANGE_END_PATTERN}$',
    re.IGNORECASE,
)
CONFIG_BLOCK_MARKER_RE = re.compile(r'^\s*###\s*device\s*:\s*(?P<name>.+?)\s*$', re.IGNORECASE)
DEVICE_NAME_PATTERNS = (
    re.compile(r'^\s*hostname\s+(?P<name>\S+)\s*$', re.IGNORECASE),
    re.compile(r'^\s*sysname\s+(?P<name>\S+)\s*$', re.IGNORECASE),
    re.compile(r'^\s*set\s+system\s+host-name\s+(?P<name>\S+)\s*$', re.IGNORECASE),
)

# ===================================================================
#  SPELLING CORRECTION DICTIONARY
#  Common typos in network configs -> correct form
# ===================================================================
SPELLING_CORRECTIONS = {
    # === Cisco / General ===
    'adress': 'address',
    'addres': 'address',
    'addrerss': 'address',
    'adres': 'address',
    'addrss': 'address',
    'interace': 'interface',
    'interfce': 'interface',
    'inteface': 'interface',
    'interafce': 'interface',
    'nterface': 'interface',
    'interfcae': 'interface',
    'intreface': 'interface',
    'trunck': 'trunk',
    'trunc': 'trunk',
    'trnk': 'trunk',
    'swichport': 'switchport',
    'switchpotr': 'switchport',
    'swtichport': 'switchport',
    'swicthport': 'switchport',
    'shutdow': 'shutdown',
    'shutdonw': 'shutdown',
    'shutdwon': 'shutdown',
    'shutown': 'shutdown',
    'hostnme': 'hostname',
    'hostame': 'hostname',
    'hostnam': 'hostname',
    'hostnamne': 'hostname',
    'passwrod': 'password',
    'passowrd': 'password',
    'pasword': 'password',
    'passsword': 'password',
    'enbable': 'enable',
    'enabel': 'enable',
    'enbale': 'enable',
    'dscription': 'description',
    'descripton': 'description',
    'descrption': 'description',
    'descripion': 'description',
    'neigbor': 'neighbor',
    'neghbor': 'neighbor',
    'neighbour': 'neighbor',
    'neghbour': 'neighbor',
    'netwok': 'network',
    'netowrk': 'network',
    'netwrk': 'network',
    'nework': 'network',
    'routre': 'router',
    'ruter': 'router',
    'routr': 'router',
    'spaning': 'spanning',
    'spanning': 'spanning',
    'spaningtree': 'spanning-tree',
    'alllowed': 'allowed',
    'alowed': 'allowed',
    'allwoed': 'allowed',
    'duplex': 'duplex',
    'duplx': 'duplex',
    'duples': 'duplex',
    'accesss': 'access',
    'acess': 'access',
    'acces': 'access',
    'vlan': 'vlan',
    'vlna': 'vlan',
    'valn': 'vlan',
    'communty': 'community',
    'comunity': 'community',
    'communtiy': 'community',
    'cryto': 'crypto',
    'cypto': 'crypto',
    'modulus': 'modulus',
    'modulas': 'modulus',
    'secrect': 'secret',
    'secert': 'secret',
    'secrte': 'secret',
    'defualt': 'default',
    'deafult': 'default',
    'dafault': 'default',
    'deault': 'default',
    'secondary': 'secondary',
    'secondry': 'secondary',
    'verison': 'version',
    'verson': 'version',
    'vrersion': 'version',
    'encapulation': 'encapsulation',
    'encapsualtion': 'encapsulation',
    'ecapsulation': 'encapsulation',
    'encap': 'encapsulation',
    'bandwith': 'bandwidth',
    'bandwdith': 'bandwidth',
    'static': 'static',
    'statc': 'static',
    'redistrubute': 'redistribute',
    'redistribue': 'redistribute',
    'autonomous': 'autonomous',
    'autnomous': 'autonomous',
    'authenication': 'authentication',
    'authenitcation': 'authentication',
    'authenticaion': 'authentication',
    'authorzation': 'authorization',
    'authorizaton': 'authorization',
    'accountng': 'accounting',
    'previlage': 'privilege',
    'privelege': 'privilege',
    'privilige': 'privilege',
    'tranport': 'transport',
    'transprot': 'transport',
    'tunnel': 'tunnel',
    'tunel': 'tunnel',
    'standy': 'standby',
    'standbay': 'standby',
    'channel': 'channel',
    'chanell': 'channel',
    'ethernet': 'ethernet',
    'ethrnet': 'ethernet',
    'gigabit': 'gigabit',
    'gigbait': 'gigabit',
    'serial': 'serial',
    'serail': 'serial',
    'loopback': 'loopback',
    'looback': 'loopback',
    'loging': 'logging',
    'loggging': 'logging',
    'syslog': 'syslog',
    'sylog': 'syslog',
    'permit': 'permit',
    'pemrit': 'permit',
    'deny': 'deny',
    'denny': 'deny',
    # === Huawei VRP ===
    'sysnme': 'sysname',
    'sysame': 'sysname',
    'sysnam': 'sysname',
    'undo': 'undo',
    'portgrou': 'portgroup',
    'lnk-type': 'link-type',
    'lnk': 'link',
    'vlanif': 'vlanif',
    'vlaniff': 'vlanif',
    'routestatic': 'route-static',
    'rout-static': 'route-static',
    'stelnet': 'stelnet',
    'stlnet': 'stelnet',
    # === Juniper ===
    'famly': 'family',
    'familiy': 'family',
    'famliy': 'family',
    'familty': 'family',
    'chasis': 'chassis',
    'chasssis': 'chassis',
    'commit': 'commit',
    'comit': 'commit',
    'commmit': 'commit',
}


# ===================================================================
#  VALID COMMANDS MATRIX (Context-Aware State Machine)
#  Maps mode -> vendor -> list of valid command prefixes
# ===================================================================
VALID_COMMANDS_MATRIX = {
    'GLOBAL': {
        'cisco': [
            'hostname', 'ip route', 'router ospf', 'router rip', 'router eigrp',
            'router bgp', 'vlan', 'enable', 'configure terminal', 'aaa',
            'no ip domain-lookup', 'ip domain-name', 'service password-encryption',
            'username', 'line', 'ntp', 'snmp-server', 'access-list',
            'ip default-gateway', 'ip name-server', 'clock', 'banner',
            'logging', 'crypto key', 'ip ssh', 'transport', 'end', 'write',
            'copy', 'spanning-tree', 'vtp', 'ip routing', 'default-gateway',
        ],
        'huawei': [
            'sysname', 'ip route-static', 'ospf', 'rip', 'vlan', 'aaa',
            'local-user', 'stelnet', 'user-interface', 'ntp-service',
            'snmp-agent', 'acl', 'dhcp', 'undo', 'return', 'save',
            'telnet', 'ssh', 'info-center', 'header',
        ],
        'juniper': [
            'set system', 'set routing-options', 'set protocols', 'set interfaces',
            'set vlans', 'set security', 'set policy-options', 'set firewall',
            'set snmp', 'set class-of-service', 'set chassis', 'set access',
            'commit', 'delete', 'rollback',
        ],
    },
    'INTERFACE': {
        'cisco': [
            'ip address', 'no shutdown', 'shutdown', 'switchport mode',
            'switchport access', 'switchport trunk', 'switchport port-security',
            'encapsulation dot1q', 'encap dot1q', 'description', 'speed',
            'duplex', 'standby', 'channel-group', 'spanning-tree', 'mtu',
            'bandwidth', 'ip helper-address', 'ip nat', 'ip access-group',
            'ip ospf', 'ip pim', 'cdp', 'lldp', 'exit', 'no cdp',
        ],
        'huawei': [
            'ip address', 'undo shutdown', 'shutdown', 'port link-type',
            'port default vlan', 'port trunk', 'port-security', 'description',
            'speed', 'duplex', 'stp', 'mtu', 'bandwidth', 'dhcp',
            'ospf', 'quit', 'undo ip', 'undo port',
        ],
        'juniper': [
            'set interfaces', 'set unit', 'set family', 'set address',
            'set description', 'set mtu', 'set speed', 'set disable',
            'set enable', 'delete disable',
        ],
    },
    'ROUTER_OSPF': {
        'cisco': [
            'network', 'area', 'router-id', 'timers', 'auto-cost',
            'default-information', 'redistribute', 'passive-interface',
            'log-adjacency-changes', 'max-lsa', 'exit', 'distance',
            'summary-address', 'distribute-list', 'neighbor',
        ],
        'huawei': [
            'network', 'area', 'router-id', 'cost', 'timers',
            'default-route-advertise', 'import-route', 'silent-interface',
            'description', 'quit', 'maximum', 'preference',
        ],
        'juniper': [
            'set protocols ospf', 'set area', 'set interface',
        ],
    },
    'ROUTER_RIP': {
        'cisco': [
            'version', 'network', 'no auto-summary', 'passive-interface',
            'timers', 'distribute-list', 'offset-list', 'distance',
            'redistribute', 'neighbor', 'exit',
        ],
        'huawei': [
            'version', 'network', 'undo summary', 'silent-interface',
            'timers', 'preference', 'quit', 'import-route',
        ],
        'juniper': [
            'set protocols rip', 'set group', 'set neighbor',
        ],
    },
    'ROUTER_EIGRP': {
        'cisco': [
            'network', 'no auto-summary', 'passive-interface', 'eigrp',
            'redistribute', 'variance', 'maximum-paths', 'timers',
            'distribute-list', 'metric', 'exit', 'address-family',
            'autonomous-system', 'neighbor',
        ],
        'huawei': [],
        'juniper': [],
    },
    'ROUTER_BGP': {
        'cisco': [
            'neighbor', 'network', 'redistribute', 'no synchronization',
            'timers', 'bgp', 'address-family', 'exit-address-family',
            'exit', 'distance', 'aggregate-address',
        ],
        'huawei': [
            'peer', 'network', 'import-route', 'undo synchronization',
            'timer', 'quit', 'ipv4-family', 'group',
        ],
        'juniper': [
            'set protocols bgp', 'set group', 'set neighbor', 'set type',
            'set peer-as', 'set local-as',
        ],
    },
    'MONITORING': {
        'cisco': [
            'show ip interface', 'show interfaces', 'show run', 'show ospf',
            'show ip route', 'show vlan', 'show spanning-tree', 'show ip bgp',
            'show version', 'show clock', 'show ntp', 'show logging',
            'show mac', 'show arp', 'show cdp', 'show lldp', 'show ip arp',
            'show access-lists', 'show ip nat', 'show ip ospf neighbor',
            'show ip protocols', 'show controllers', 'show diag',
        ],
        'huawei': [
            'display ip interface', 'display interface', 'display current-configuration',
            'display ospf', 'display ip routing-table', 'display vlan',
            'display stp', 'display bgp', 'display version', 'display clock',
            'display ntp', 'display logbuffer', 'display mac-address',
            'display arp', 'display lldp', 'display acl', 'display nat',
            'display ip protocols', 'display ip routing-table',
        ],
        'juniper': [
            'show interfaces', 'show route', 'show ospf', 'show bgp',
            'show configuration', 'show version', 'show system',
            'show chassis', 'show log', 'show vlans', 'show ethernet',
            'show arp', 'show lldp', 'show firewall', 'show security',
        ],
    },
}


# ===================================================================
#  VENDOR TRANSLATION MATRIX (Cross-Vendor Command Mapping)
#  Maps conceptual operation -> vendor -> command form
# ===================================================================
VENDOR_TRANSLATION_MATRIX = {
    'no_shutdown': {
        'cisco': 'no shutdown',
        'huawei': 'undo shutdown',
        'juniper': 'delete disable',
    },
    'shutdown': {
        'cisco': 'shutdown',
        'huawei': 'shutdown',
        'juniper': 'set disable',
    },
    'trunk_mode': {
        'cisco': 'switchport mode trunk',
        'huawei': 'port link-type trunk',
        'juniper': 'set interfaces interface-mode trunk',
    },
    'access_mode': {
        'cisco': 'switchport mode access',
        'huawei': 'port link-type access',
        'juniper': 'set interfaces interface-mode access',
    },
    'hostname': {
        'cisco': 'hostname',
        'huawei': 'sysname',
        'juniper': 'set system host-name',
    },
}

# Pre-compile a regex for word-boundary replacement
_SPELLING_RE = re.compile(
    r'\b(' + '|'.join(re.escape(k) for k in SPELLING_CORRECTIONS.keys()) + r')\b',
    re.IGNORECASE,
)


def fix_spelling(line):
    """Fix common spelling mistakes in a config line.

    Replaces misspelled keywords with their correct forms while preserving
    the original casing style of the line.
    """
    def _replace(match):
        typo = match.group(0)
        correct = SPELLING_CORRECTIONS.get(typo.lower(), typo)
        # Preserve original casing: all-upper stays upper, title stays title
        if typo.isupper():
            return correct.upper()
        if typo[0].isupper():
            return correct[0].upper() + correct[1:]
        return correct
    return _SPELLING_RE.sub(_replace, line)


# ===================================================================
#  IP CLASS-BASED DEFAULT SUBNET MASK
# ===================================================================

def get_default_mask_for_ip(ip_str):
    """Return the default subnet mask based on IP address class.

    Class A (1-126):   255.0.0.0     (/8)
    Class B (128-191): 255.255.0.0   (/16)
    Class C (192-223): 255.255.255.0 (/24)
    Class D/E:         255.255.255.0 (/24) fallback
    """
    try:
        first_octet = int(ip_str.strip().split('.')[0])
    except (ValueError, IndexError):
        return '255.255.255.0'
    if 1 <= first_octet <= 126:
        return '255.0.0.0'
    elif 128 <= first_octet <= 191:
        return '255.255.0.0'
    else:
        return '255.255.255.0'


# ===================================================================
#  CROSS-VENDOR NORMALIZATION
# ===================================================================

def cross_vendor_to_huawei(line):
    """Convert Cisco-style commands to Huawei VRP equivalents.

    Applied when vendor=huawei but the user wrote Cisco-style syntax.
    """
    stripped = line.strip()
    ll = stripped.lower()

    # no shutdown -> undo shutdown
    if re.match(r'^no\s+shutdown\s*$', ll):
        return 'undo shutdown'
    # shutdown -> undo undo shutdown is just shutdown in Huawei, keep as-is
    # no ip address -> undo ip address
    m = re.match(r'^no\s+(ip\s+address\s+.+)$', stripped, re.IGNORECASE)
    if m:
        return f'undo {m.group(1)}'
    # no description -> undo description
    if re.match(r'^no\s+description\s*$', ll):
        return 'undo description'
    # spanning-tree -> stp
    if re.match(r'^spanning-tree\b', ll):
        return re.sub(r'^spanning-tree', 'stp', stripped, flags=re.IGNORECASE)
    # switchport mode trunk -> port link-type trunk
    m = re.match(r'^switchport\s+mode\s+trunk\s*$', ll)
    if m:
        return 'port link-type trunk'
    # switchport mode access -> port link-type access
    m = re.match(r'^switchport\s+mode\s+access\s*$', ll)
    if m:
        return 'port link-type access'
    # switchport access vlan X -> port default vlan X
    m = re.match(r'^switchport\s+access\s+vlan\s+(\d+)', stripped, re.IGNORECASE)
    if m:
        return f'port default vlan {m.group(1)}'
    # switchport trunk allowed vlan X -> port trunk allow-pass vlan X
    m = re.match(r'^switchport\s+trunk\s+allowed\s+vlan\s+(.+)', stripped, re.IGNORECASE)
    if m:
        return f'port trunk allow-pass vlan {m.group(1).strip()}'

    return stripped


def cross_vendor_to_juniper(line):
    """Convert flat Cisco/Huawei-style commands to Juniper set syntax.

    Applied when vendor=juniper but the user wrote non-Juniper syntax.
    """
    stripped = line.strip()
    ll = stripped.lower()

    # hostname X -> set system host-name X
    m = re.match(r'^hostname\s+(\S+)', stripped, re.IGNORECASE)
    if m:
        return f'set system host-name {m.group(1)}'
    # sysname X -> set system host-name X
    m = re.match(r'^sysname\s+(\S+)', stripped, re.IGNORECASE)
    if m:
        return f'set system host-name {m.group(1)}'
    # interface X ip address A.B.C.D M.M.M.M -> set interfaces X unit 0 family inet address A.B.C.D/XX
    m = re.match(
        r'^interface\s+(\S+)\s*$', stripped, re.IGNORECASE
    )
    # Just 'interface X' -> can't fully convert without children, skip
    # ip address X.X.X.X Y.Y.Y.Y (standalone) -> set interfaces <current> unit 0 family inet address ...
    m = re.match(
        r'^ip\s+address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)',
        stripped, re.IGNORECASE,
    )
    if m:
        ip, mask = m.group(1), m.group(2)
        try:
            cidr = ipaddress.IPv4Network(f'0.0.0.0/{mask}', strict=False).prefixlen
            return f'set interfaces ge-0/0/0 unit 0 family inet address {ip}/{cidr}'
        except ValueError:
            return f'set interfaces ge-0/0/0 unit 0 family inet address {ip}/24'
    # ip address X.X.X.X (no mask) -> set with /24 default
    m = re.match(r'^ip\s+address\s+(\d+\.\d+\.\d+\.\d+)\s*$', stripped, re.IGNORECASE)
    if m:
        return f'set interfaces ge-0/0/0 unit 0 family inet address {m.group(1)}/24'
    # no shutdown -> delete interfaces ... disable  (Juniper removes 'disable')
    if re.match(r'^no\s+shutdown\s*$', ll):
        return 'delete interfaces ge-0/0/0 disable'
    # shutdown -> set interfaces ... disable
    if re.match(r'^shutdown\s*$', ll):
        return 'set interfaces ge-0/0/0 disable'
    # router ospf 1 -> set protocols ospf area 0.0.0.0 interface all
    m = re.match(r'^router\s+ospf\s+\d+', stripped, re.IGNORECASE)
    if m:
        return 'set protocols ospf area 0.0.0.0 interface all'
    # network X.X.X.X W.W.W.W area A -> set protocols ospf area A interface <auto>
    m = re.match(
        r'^network\s+(\S+)\s+(\S+)\s+area\s+(\S+)', stripped, re.IGNORECASE
    )
    if m:
        area = m.group(3)
        # Convert numeric area to dotted format if needed
        if area.isdigit():
            area_int = int(area)
            area = f'{(area_int >> 24) & 0xFF}.{(area_int >> 16) & 0xFF}.{(area_int >> 8) & 0xFF}.{area_int & 0xFF}'
        return f'set protocols ospf area {area} interface all'

    return stripped


def normalize_cisco_interface_range(line):
    match = CISCO_INTERFACE_RANGE_LOOSE_RE.match(line)
    if not match:
        return line
    return f'interface range {match.group(1).strip()} - {match.group(2).strip()}'


def normalize_cisco_interface_name(name):
    """Expand common Cisco interface abbreviations into config-style names."""
    compact = name.strip()
    replacements = (
        (r'^(?:g|gi|gig)\s*(\d.+)$', 'GigabitEthernet'),
        (r'^(?:f|fa|fast)\s*(\d.+)$', 'FastEthernet'),
        (r'^(?:e|eth)\s*(\d.+)$', 'Ethernet'),
        (r'^(?:s|se)\s*(\d.+)$', 'Serial'),
        (r'^(?:lo|loop)\s*(\d.+)$', 'Loopback'),
        (r'^(?:vl|vlan)\s*(\d.+)$', 'Vlan'),
        (r'^(?:tu|tun)\s*(\d.+)$', 'Tunnel'),
        (r'^(?:po)\s*(\d.+)$', 'Port-channel'),
    )
    for pattern, full_name in replacements:
        match = re.match(pattern, compact, re.IGNORECASE)
        if match:
            return f'{full_name}{match.group(1).strip()}'
    return compact


def normalize_cisco_cli_abbreviation(line):
    """Normalize common interactive Cisco shorthand into full config commands."""
    stripped = line.strip()
    interface_match = re.match(r'^(?:int|interface)\s+(.+)$', stripped, re.IGNORECASE)
    if interface_match:
        return f'interface {normalize_cisco_interface_name(interface_match.group(1))}'

    ip_add_match = re.match(r'^ip\s+add(?:ress)?\s+(.+)$', stripped, re.IGNORECASE)
    if ip_add_match:
        return f'ip address {ip_add_match.group(1).strip()}'

    simple_replacements = {
        'no shut': 'no shutdown',
        'shut': 'shutdown',
        'wr': 'write memory',
        'do wr': 'write memory',
        'copy run start': 'copy running-config startup-config',
        'conf t': 'configure terminal',
    }
    return simple_replacements.get(stripped.lower(), stripped)


def normalize_huawei_abbreviation(line):
    """Normalize common Huawei VRP shorthand."""
    stripped = line.strip()
    # Huawei uses 'dis' as shorthand for 'display'
    if stripped.lower().startswith('dis ') or stripped.lower() == 'dis':
        return 'display' + stripped[3:]
    return stripped


def normalize_juniper_abbreviation(line):
    """Normalize common Juniper JunOS shorthand."""
    stripped = line.strip()
    # 'sho' or 'sh' for 'show'
    if re.match(r'^(?:sho|sh)\s+', stripped, re.IGNORECASE):
        return 'show ' + re.sub(r'^(?:sho|sh)\s+', '', stripped, flags=re.IGNORECASE)
    return stripped


def normalize_config_line(line, vendor='auto'):
    """Apply spelling fixes, cross-vendor translation, and CLI shorthand normalization.

    Pipeline:
    1. Fix spelling mistakes (always)
    2. Cross-vendor normalization (if vendor != cisco and line looks like Cisco syntax)
    3. Vendor-specific CLI abbreviation expansion
    4. Cisco interface range spacing fix
    """
    # Step 1: Fix spelling mistakes
    corrected = fix_spelling(line)

    # Step 2: Cross-vendor normalization
    if vendor == 'huawei':
        cross = cross_vendor_to_huawei(corrected)
        if cross != corrected:
            corrected = cross
    elif vendor == 'juniper':
        cross = cross_vendor_to_juniper(corrected)
        if cross != corrected:
            corrected = cross

    # Step 3: Vendor-specific abbreviation expansion
    normalized = normalize_cisco_cli_abbreviation(corrected)
    # Also normalize Cisco interface range syntax (spacing, casing)
    range_normalized = normalize_cisco_interface_range(normalized)
    if range_normalized != normalized:
        normalized = range_normalized
    if normalized == corrected:  # No Cisco normalization applied
        normalized = normalize_huawei_abbreviation(corrected)
    if normalized == corrected:  # No Huawei normalization applied
        normalized = normalize_juniper_abbreviation(corrected)
    return normalized


# ===================================================================
#  CONTEXT-AWARE STATE MACHINE
# ===================================================================

def _detect_mode_transition(line, current_mode, vendor):
    """Determine the next mode based on the current line content.

    Returns (next_mode, is_temporary) where is_temporary indicates the
    mode applies only to this line (e.g. MONITORING for show commands).
    """
    stripped = line.strip()
    ll = stripped.lower()

    # Device marker or empty -> reset to GLOBAL
    if not stripped or CONFIG_BLOCK_MARKER_RE.match(stripped):
        return 'GLOBAL', False

    # Interface context
    if re.match(r'^interface\s+\S+', ll):
        return 'INTERFACE', False

    # Router context - OSPF
    if re.match(r'^router\s+ospf', ll) or re.match(r'^ospf\s+\d+', ll):
        return 'ROUTER_OSPF', False
    if re.match(r'^set\s+protocols\s+ospf', ll):
        return 'ROUTER_OSPF', False

    # Router context - RIP
    if re.match(r'^router\s+rip', ll) or re.match(r'^rip\s+\d+', ll):
        return 'ROUTER_RIP', False
    if re.match(r'^set\s+protocols\s+rip', ll):
        return 'ROUTER_RIP', False

    # Router context - EIGRP
    if re.match(r'^router\s+eigrp', ll):
        return 'ROUTER_EIGRP', False

    # Router context - BGP
    if re.match(r'^router\s+bgp', ll) or re.match(r'^bgp\s+\d+', ll):
        return 'ROUTER_BGP', False
    if re.match(r'^set\s+protocols\s+bgp', ll):
        return 'ROUTER_BGP', False

    # Huawei area context (sub-mode of OSPF)
    if re.match(r'^area\s+\S+', ll) and current_mode == 'ROUTER_OSPF':
        return 'ROUTER_OSPF', False

    # Exit/quit -> return to GLOBAL
    if ll in ('exit', 'quit', 'end', 'exit-address-family'):
        return 'GLOBAL', False

    # Monitoring commands (temporary)
    if ll.startswith('show ') or ll.startswith('display '):
        return 'MONITORING', True

    # Stay in current mode
    return current_mode, False


def _validate_in_mode(line, mode, vendor):
    """Check if a line is valid in the given mode for the vendor.

    Returns True if the line matches any valid command prefix for this mode.
    """
    stripped = line.strip().lower()
    mode_commands = VALID_COMMANDS_MATRIX.get(mode, {}).get(vendor, [])
    for prefix in mode_commands:
        if stripped.startswith(prefix.lower()):
            return True
    return False


def _smart_fix_network_for_mode(line, mode, vendor):
    """Apply smart auto-fix for 'network' statements based on the current mode.

    ROUTER_RIP: Strip wildcard masks and area from network statements.
    ROUTER_OSPF: Add default wildcard mask if missing.
    """
    stripped = line.strip()

    if mode == 'ROUTER_RIP':
        # In RIP mode: strip extra params, keep only network address
        # e.g. 'network 192.168.30.0 0.0.0.255 area 0' -> 'network 192.168.30.0'
        m = re.match(r'^network\s+(\d+\.\d+\.\d+\.\d+)\s*.+$', stripped, re.IGNORECASE)
        if m:
            return f'network {m.group(1)}'
        return stripped

    if mode == 'ROUTER_OSPF':
        # In OSPF mode: add wildcard mask if missing
        # 'network 172.16.0.0 area 0' -> 'network 172.16.0.0 0.0.0.255 area 0'
        m = re.match(r'^network\s+(\d+\.\d+\.\d+\.\d+)\s+area\s+(\S+)\s*$', stripped, re.IGNORECASE)
        if m:
            ip = m.group(1)
            area = m.group(2)
            # Calculate wildcard from IP class
            try:
                first_octet = int(ip.split('.')[0])
                if 1 <= first_octet <= 126:
                    wildcard = '0.255.255.255'
                elif 128 <= first_octet <= 191:
                    wildcard = '0.0.255.255'
                else:
                    wildcard = '0.0.0.255'
            except (ValueError, IndexError):
                wildcard = '0.0.0.255'
            return f'network {ip} {wildcard} area {area}'
        return stripped

    return stripped


def _apply_vendor_translation(line, vendor):
    """Apply cross-vendor translation for common operations.

    Used in the after_config (corrected config) when vendor is Huawei or Juniper.
    """
    stripped = line.strip()
    ll = stripped.lower()

    # no shutdown -> vendor equivalent
    if re.match(r'^no\s+shutdown\s*$', ll):
        return VENDOR_TRANSLATION_MATRIX['no_shutdown'].get(vendor, stripped)

    # shutdown (standalone) -> vendor equivalent
    if re.match(r'^shutdown\s*$', ll):
        return VENDOR_TRANSLATION_MATRIX['shutdown'].get(vendor, stripped)

    # switchport mode trunk -> vendor equivalent
    if re.match(r'^switchport\s+mode\s+trunk\s*$', ll):
        return VENDOR_TRANSLATION_MATRIX['trunk_mode'].get(vendor, stripped)

    # switchport mode access -> vendor equivalent
    if re.match(r'^switchport\s+mode\s+access\s*$', ll):
        return VENDOR_TRANSLATION_MATRIX['access_mode'].get(vendor, stripped)

    return stripped


def cisco_interface_range_needs_fix(line):
    return bool(CISCO_INTERFACE_RANGE_LOOSE_RE.match(line)) and not bool(CISCO_INTERFACE_RANGE_VALID_RE.match(line))


def extract_config_device_name(config_text):
    """Return the first device name declared in a config block."""
    for line in config_text.splitlines():
        for pattern in DEVICE_NAME_PATTERNS:
            match = pattern.match(line)
            if match:
                return match.group('name').strip()
    return None


def guess_device_type_from_config(config_text):
    """Infer a practical inventory type from common config commands."""
    lowered = config_text.lower()
    if 'switchport' in lowered or 'vlan ' in lowered or 'set vlans ' in lowered:
        return 'switch'
    if 'firewall' in lowered or 'access-list' in lowered or 'acl number' in lowered:
        return 'firewall'
    return 'router'


def _build_config_block(lines, marker_name=None, index=1):
    raw_config = '\n'.join(line for line in lines if line.strip()).strip()
    if not raw_config:
        return None
    device_name = marker_name or extract_config_device_name(raw_config)
    return {
        'index': index,
        'device_name': device_name,
        'raw_config': raw_config,
        'vendor': detect_vendor(raw_config),
        'device_type': guess_device_type_from_config(raw_config),
    }


def split_config_blocks(config_text):
    """Split one upload into device-sized config blocks."""
    lines = config_text.splitlines()
    marker_blocks = []
    current_name = None
    current_lines = []

    for line in lines:
        marker = CONFIG_BLOCK_MARKER_RE.match(line)
        if marker:
            block = _build_config_block(current_lines, current_name, len(marker_blocks) + 1)
            if block:
                marker_blocks.append(block)
            current_name = marker.group('name').strip()
            current_lines = []
            continue
        current_lines.append(line)

    if current_name is not None:
        block = _build_config_block(current_lines, current_name, len(marker_blocks) + 1)
        if block:
            marker_blocks.append(block)
        return marker_blocks

    name_blocks = []
    current_lines = []
    current_name = None
    for line in lines:
        line_name = None
        for pattern in DEVICE_NAME_PATTERNS:
            match = pattern.match(line)
            if match:
                line_name = match.group('name').strip()
                break
        if line_name and current_lines:
            block = _build_config_block(current_lines, current_name, len(name_blocks) + 1)
            if block:
                name_blocks.append(block)
            current_lines = [line]
            current_name = line_name
        else:
            if line_name and not current_name:
                current_name = line_name
            current_lines.append(line)

    block = _build_config_block(current_lines, current_name, len(name_blocks) + 1)
    if block:
        name_blocks.append(block)

    # If still no blocks found, treat entire config as one block
    if not name_blocks and current_lines:
        return [{
            'index': 1,
            'device_name': 'Router1',
            'device_type': 'router',
            'raw_config': '\n'.join(current_lines),
            'vendor': detect_vendor('\n'.join(current_lines)),
        }]

    return name_blocks


def get_db_connection():
    conn = sqlite3.connect(DATABASE, timeout=SQLITE_TIMEOUT_SECONDS, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute(f"PRAGMA busy_timeout = {SQLITE_BUSY_TIMEOUT_MS}")
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = get_db_connection()
    with open(SCHEMA_FILE, 'r', encoding='utf-8') as f:
        conn.executescript(f.read())
    conn.commit()
    conn.close()
    ensure_runtime_schema()


def ensure_runtime_schema():
    """Add columns needed by current code when an older SQLite DB already exists."""
    global _SCHEMA_COMPATIBLE
    if _SCHEMA_COMPATIBLE:
        return

    conn = get_db_connection()
    settings_columns = {row['name'] for row in conn.execute('PRAGMA table_info(settings)').fetchall()}
    devices_columns = {row['name'] for row in conn.execute('PRAGMA table_info(devices)').fetchall()}

    setting_additions = {
        'eve_url': "ALTER TABLE settings ADD COLUMN eve_url TEXT DEFAULT 'http://127.0.0.1'",
        'eve_username': "ALTER TABLE settings ADD COLUMN eve_username TEXT DEFAULT 'admin'",
        'eve_password': "ALTER TABLE settings ADD COLUMN eve_password TEXT DEFAULT 'eve'",
        'eve_lab_path': "ALTER TABLE settings ADD COLUMN eve_lab_path TEXT DEFAULT ''",
    }
    device_additions = {
        'eve_node_id': "ALTER TABLE devices ADD COLUMN eve_node_id TEXT",
        'network_group': "ALTER TABLE devices ADD COLUMN network_group TEXT",
        'snapshot_id': "ALTER TABLE devices ADD COLUMN snapshot_id INTEGER",
    }

    for column, sql in setting_additions.items():
        if column not in settings_columns:
            conn.execute(sql)
    for column, sql in device_additions.items():
        if column not in devices_columns:
            conn.execute(sql)

    conn.execute(
        '''CREATE TABLE IF NOT EXISTS device_config_applications (
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
        )'''
    )

    conn.execute(
        '''CREATE TABLE IF NOT EXISTS network_groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )'''
    )

    conn.execute(
        '''CREATE TABLE IF NOT EXISTS network_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            config_source TEXT,
            device_count INTEGER DEFAULT 0,
            link_count INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )'''
    )

    conn.commit()
    conn.close()
    _SCHEMA_COMPATIBLE = True


def query_db(query, args=(), one=False):
    conn = get_db_connection()
    cur = conn.execute(query, args)
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return (rows[0] if rows else None) if one else rows


def execute_db(query, args=()):
    for attempt in range(SQLITE_LOCK_RETRIES):
        conn = None
        cur = None
        try:
            conn = get_db_connection()
            cur = conn.execute(query, args)
            conn.commit()
            return cur.lastrowid
        except sqlite3.OperationalError as exc:
            if 'database is locked' not in str(exc).lower() or attempt == SQLITE_LOCK_RETRIES - 1:
                raise
            sleep(0.2 * (attempt + 1))
        finally:
            if cur is not None:
                cur.close()
            if conn is not None:
                conn.close()


# =============================================================================
# USER MANAGEMENT
# =============================================================================

def get_user_by_email(email):
    return query_db('SELECT * FROM users WHERE email = ?', (email,), one=True)


def get_user_by_id(user_id):
    return query_db('SELECT * FROM users WHERE id = ?', (user_id,), one=True)


def create_user(name, company, email, password_hash):
    return execute_db(
        'INSERT INTO users (name, company, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?, ?)',
        (name, company, email, password_hash, 'user', datetime.now().isoformat())
    )


# =============================================================================
# SETTINGS
# =============================================================================

def get_backup_interval(user_id):
    ensure_runtime_schema()
    row = query_db('SELECT backup_minutes FROM settings WHERE user_id = ?', (user_id,), one=True)
    if row:
        return int(row['backup_minutes'])
    return DEFAULT_BACKUP_MINUTES


def ensure_default_settings(user_id):
    ensure_runtime_schema()
    # Check if user exists first
    user = query_db('SELECT id FROM users WHERE id = ?', (user_id,), one=True)
    if not user:
        # User doesn't exist, skip settings creation
        return
    
    row = query_db('SELECT id FROM settings WHERE user_id = ?', (user_id,), one=True)
    if not row:
        execute_db(
            '''INSERT INTO settings
               (user_id, backup_minutes, eve_url, eve_username, eve_password, eve_lab_path, netbox_url, netbox_token)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
            (user_id, DEFAULT_BACKUP_MINUTES, 'http://127.0.0.1', 'admin', 'eve', '', 'http://192.168.163.145:8000', '')
        )


def get_user_settings(user_id):
    ensure_default_settings(user_id)
    return query_db('SELECT * FROM settings WHERE user_id = ?', (user_id,), one=True)


def update_user_settings(user_id, **kwargs):
    ensure_runtime_schema()
    sets = []
    vals = []
    for k, v in kwargs.items():
        sets.append(f'{k} = ?')
        vals.append(v)
    vals.append(user_id)
    execute_db(f'UPDATE settings SET {", ".join(sets)} WHERE user_id = ?', vals)


# =============================================================================
# SNAPSHOTS / BACKUPS
# =============================================================================

def save_snapshot(user_id, name, config_text, device_name=None, snapshot_type='manual'):
    # Check if user exists first
    user = query_db('SELECT id FROM users WHERE id = ?', (user_id,), one=True)
    if not user:
        return None
    execute_db(
        'INSERT INTO snapshots (user_id, name, config_text, device_name, snapshot_type, created_at) VALUES (?, ?, ?, ?, ?, ?)',
        (user_id, name, config_text, device_name, snapshot_type, datetime.now().isoformat())
    )


def get_user_snapshots(user_id):
    return query_db('SELECT * FROM snapshots WHERE user_id = ? ORDER BY created_at DESC', (user_id,))


def get_snapshot_by_id(snapshot_id, user_id):
    return query_db('SELECT * FROM snapshots WHERE id = ? AND user_id = ?', (snapshot_id, user_id), one=True)


def delete_snapshot(snapshot_id, user_id):
    execute_db('DELETE FROM snapshots WHERE id = ? AND user_id = ?', (snapshot_id, user_id))


# =============================================================================
# LOGGING
# =============================================================================

def add_log(user_id, action, details, ip_address=None):
    # Check if user exists first
    user = query_db('SELECT id FROM users WHERE id = ?', (user_id,), one=True)
    if not user:
        return None
    execute_db(
        'INSERT INTO logs (user_id, action, details, ip_address, created_at) VALUES (?, ?, ?, ?, ?)',
        (user_id, action, details, ip_address, datetime.now().isoformat())
    )


def get_user_logs(user_id, limit=200):
    return query_db(
        'SELECT l.*, u.name as user_name FROM logs l JOIN users u ON l.user_id = u.id WHERE l.user_id = ? ORDER BY l.created_at DESC LIMIT ?',
        (user_id, limit)
    )


def get_all_logs(limit=500):
    return query_db(
        'SELECT l.*, u.name as user_name, u.company as user_company FROM logs l JOIN users u ON l.user_id = u.id ORDER BY l.created_at DESC LIMIT ?',
        (limit,)
    )


# =============================================================================
# CONFIGS
# =============================================================================

def save_user_config(user_id, raw_config):
    # Check if user exists first
    user = query_db('SELECT id FROM users WHERE id = ?', (user_id,), one=True)
    if not user:
        return None
    return execute_db(
        'INSERT OR REPLACE INTO configs (user_id, config_text, updated_at) VALUES (?, ?, ?)',
        (user_id, raw_config, datetime.now().isoformat())
    )


def get_last_config(user_id):
    return query_db('SELECT config_text FROM configs WHERE user_id = ? ORDER BY updated_at DESC LIMIT 1', (user_id,), one=True)


# =============================================================================
# DEVICES
# =============================================================================

def add_device(user_id, name, device_type, vendor='cisco', ip_address=None, eve_node_id=None, netbox_id=None, network_group=None, snapshot_id=None):
    ensure_runtime_schema()
    # Check if user exists first
    user = query_db('SELECT id FROM users WHERE id = ?', (user_id,), one=True)
    if not user:
        return None
    return execute_db(
        'INSERT INTO devices (user_id, name, device_type, vendor, ip_address, status, eve_node_id, netbox_id, network_group, snapshot_id, last_seen, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        (user_id, name, device_type, vendor, ip_address, 'unknown', eve_node_id, netbox_id, network_group, snapshot_id, datetime.now().isoformat(), datetime.now().isoformat())
    )


def get_user_devices(user_id):
    ensure_runtime_schema()
    return query_db('SELECT * FROM devices WHERE user_id = ? ORDER BY name', (user_id,))


def get_device_by_id(device_id, user_id):
    ensure_runtime_schema()
    return query_db('SELECT * FROM devices WHERE id = ? AND user_id = ?', (device_id, user_id), one=True)


def get_device_by_name(user_id, name):
    ensure_runtime_schema()
    return query_db(
        'SELECT * FROM devices WHERE user_id = ? AND LOWER(name) = LOWER(?)',
        (user_id, name),
        one=True,
    )


def update_device_status(device_id, status):
    execute_db('UPDATE devices SET status = ?, last_seen = ? WHERE id = ?', (status, datetime.now().isoformat(), device_id))


def update_device_eve_id(device_id, eve_node_id):
    ensure_runtime_schema()
    execute_db('UPDATE devices SET eve_node_id = ? WHERE id = ?', (eve_node_id, device_id))


def update_device_netbox_id(device_id, netbox_id):
    execute_db('UPDATE devices SET netbox_id = ? WHERE id = ?', (netbox_id, device_id))


def delete_device(device_id, user_id):
    execute_db('DELETE FROM topology_links WHERE source_device_id = ? OR target_device_id = ?', (device_id, device_id))
    execute_db('DELETE FROM device_config_applications WHERE device_id = ? AND user_id = ?', (device_id, user_id))
    execute_db('DELETE FROM devices WHERE id = ? AND user_id = ?', (device_id, user_id))


# =============================================================================
# NETWORK GROUPS
# =============================================================================

def create_network_group(user_id, name, description=None):
    """Create a new network group for isolating devices."""
    return execute_db(
        'INSERT INTO network_groups (user_id, name, description, created_at) VALUES (?, ?, ?, ?)',
        (user_id, name, description, datetime.now().isoformat())
    )


def get_user_network_groups(user_id):
    """Get all network groups for a user."""
    return query_db(
        'SELECT * FROM network_groups WHERE user_id = ? ORDER BY created_at DESC',
        (user_id,)
    )


def get_network_group_by_id(group_id, user_id):
    """Get a specific network group."""
    return query_db(
        'SELECT * FROM network_groups WHERE id = ? AND user_id = ?',
        (group_id, user_id),
        one=True
    )


def get_network_group_by_name(user_id, name):
    """Get a network group by name."""
    return query_db(
        'SELECT * FROM network_groups WHERE user_id = ? AND LOWER(name) = LOWER(?)',
        (user_id, name),
        one=True
    )


def delete_network_group(group_id, user_id):
    """Delete a network group (doesn't delete devices)."""
    execute_db('UPDATE devices SET network_group = NULL WHERE network_group = ? AND user_id = ?', (group_id, user_id))
    execute_db('DELETE FROM network_groups WHERE id = ? AND user_id = ?', (group_id, user_id))


def get_devices_by_group(user_id, group_id=None):
    """Get devices filtered by network group."""
    ensure_runtime_schema()
    if group_id is None:
        return query_db(
            'SELECT * FROM devices WHERE user_id = ? AND network_group IS NULL ORDER BY name',
            (user_id,)
        )
    return query_db(
        'SELECT * FROM devices WHERE user_id = ? AND network_group = ? ORDER BY name',
        (user_id, group_id)
    )


def get_devices_by_snapshot(user_id, snapshot_id):
    """Get devices filtered by network snapshot."""
    ensure_runtime_schema()
    return query_db(
        'SELECT * FROM devices WHERE user_id = ? AND snapshot_id = ? ORDER BY name',
        (user_id, snapshot_id)
    )


# =============================================================================
# NETWORK SNAPSHOTS - Isolated Topology Per Config
# =============================================================================

def create_network_snapshot(user_id, name, description=None, config_source=None, device_count=0, link_count=0):
    """Create a snapshot for an isolated network topology."""
    return execute_db(
        'INSERT INTO network_snapshots (user_id, name, description, config_source, device_count, link_count, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
        (user_id, name, description, config_source, device_count, link_count, datetime.now().isoformat())
    )


def get_user_network_snapshots(user_id):
    """Get all network snapshots for a user."""
    return query_db(
        'SELECT * FROM network_snapshots WHERE user_id = ? ORDER BY created_at DESC',
        (user_id,)
    )


def get_network_snapshot_by_id(snapshot_id, user_id):
    """Get a specific network snapshot."""
    return query_db(
        'SELECT * FROM network_snapshots WHERE id = ? AND user_id = ?',
        (snapshot_id, user_id),
        one=True
    )


def delete_network_snapshot(snapshot_id, user_id):
    """Delete a network snapshot."""
    execute_db('DELETE FROM network_snapshots WHERE id = ? AND user_id = ?', (snapshot_id, user_id))


# =============================================================================
# DEVICE CONFIG APPLICATIONS
# =============================================================================

def save_device_config_application(user_id, device_id, source, raw_config, corrected_config,
                                   vendor, validation_state, application_state,
                                   eve_node_id=None, eve_result=None):
    ensure_runtime_schema()
    if eve_result is None:
        eve_result_text = None
    elif isinstance(eve_result, str):
        eve_result_text = eve_result
    else:
        eve_result_text = json.dumps(eve_result, sort_keys=True)

    return execute_db(
        '''INSERT INTO device_config_applications
           (user_id, device_id, source, raw_config, corrected_config, vendor,
            validation_state, application_state, eve_node_id, eve_result, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
        (
            user_id,
            device_id,
            source,
            raw_config,
            corrected_config,
            vendor,
            validation_state,
            application_state,
            eve_node_id,
            eve_result_text,
            datetime.now().isoformat(),
        ),
    )


def get_latest_device_config_application(device_id, user_id):
    ensure_runtime_schema()
    return query_db(
        '''SELECT * FROM device_config_applications
           WHERE device_id = ? AND user_id = ?
           ORDER BY created_at DESC, id DESC
           LIMIT 1''',
        (device_id, user_id),
        one=True,
    )


def get_device_config_applications(device_id, user_id, limit=10):
    ensure_runtime_schema()
    return query_db(
        '''SELECT * FROM device_config_applications
           WHERE device_id = ? AND user_id = ?
           ORDER BY created_at DESC, id DESC
           LIMIT ?''',
        (device_id, user_id, limit),
    )


def get_user_latest_device_applications(user_id):
    ensure_runtime_schema()
    rows = query_db(
        '''SELECT dca.*
           FROM device_config_applications dca
           JOIN (
               SELECT device_id, MAX(id) AS latest_id
               FROM device_config_applications
               WHERE user_id = ?
               GROUP BY device_id
           ) latest ON latest.latest_id = dca.id
           WHERE dca.user_id = ?''',
        (user_id, user_id),
    )
    return {row['device_id']: row for row in rows}


# =============================================================================
# TOPOLOGY LINKS
# =============================================================================

def _is_loopback_interface(interface_name):
    lowered = (interface_name or '').lower()
    return lowered.startswith(('loopback', 'lo0', 'lo'))


def extract_interface_addresses(config_text, vendor='auto'):
    """Extract routed IPv4 interface addresses from config text."""
    detected_vendor = detect_vendor(config_text) if vendor == 'auto' else vendor
    addresses = []
    current_interface = None

    for raw_line in config_text.splitlines():
        line = normalize_config_line(raw_line.strip(), detected_vendor)
        if not line or line.startswith(('!', '#', '//')):
            continue

        juniper_match = re.match(
            r'^set\s+interfaces\s+(\S+)\s+unit\s+(\d+)\s+family\s+inet\s+address\s+(\d+\.\d+\.\d+\.\d+/\d+)$',
            line,
            re.IGNORECASE,
        )
        if juniper_match:
            interface_name = f'{juniper_match.group(1)}.{juniper_match.group(2)}'
            if _is_loopback_interface(interface_name):
                continue
            network = ipaddress.ip_network(juniper_match.group(3), strict=False)
            addresses.append({
                'interface': interface_name,
                'ip': str(ipaddress.ip_interface(juniper_match.group(3)).ip),
                'network': network,
            })
            continue

        interface_match = re.match(r'^interface\s+(.+)$', line, re.IGNORECASE)
        if interface_match:
            current_interface = interface_match.group(1).strip()
            continue

        ip_match = re.match(
            r'^ip\s+address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)$',
            line,
            re.IGNORECASE,
        )
        if ip_match and current_interface and not _is_loopback_interface(current_interface):
            ip_value, mask_value = ip_match.group(1), ip_match.group(2)
            if validate_ip_address(ip_value) and validate_subnet_mask(mask_value):
                addresses.append({
                    'interface': current_interface,
                    'ip': ip_value,
                    'network': ipaddress.ip_network(f'{ip_value}/{mask_value}', strict=False),
                })

    return addresses


def infer_topology_links(device_configs):
    """Infer simple topology links from shared IPv4 subnets."""
    endpoints_by_network = {}
    for device_config in device_configs:
        for address in extract_interface_addresses(
            device_config.get('config_text', ''),
            device_config.get('vendor', 'auto'),
        ):
            network_key = str(address['network'])
            endpoints_by_network.setdefault(network_key, []).append({
                'device_id': device_config['device_id'],
                'device_name': device_config.get('device_name', ''),
                'interface': address['interface'],
                'ip': address['ip'],
            })

    inferred_links = []
    seen_pairs = set()
    for network_key, endpoints in endpoints_by_network.items():
        if len(endpoints) < 2:
            continue
        hub = endpoints[0]
        for endpoint in endpoints[1:]:
            pair_key = tuple(sorted((hub['device_id'], endpoint['device_id']))) + (network_key,)
            if pair_key in seen_pairs:
                continue
            seen_pairs.add(pair_key)
            inferred_links.append({
                'source_device_id': hub['device_id'],
                'target_device_id': endpoint['device_id'],
                'source_interface': hub['interface'],
                'target_interface': endpoint['interface'],
                'network': network_key,
            })

    return inferred_links


def add_link(user_id, source_device_id, target_device_id, source_interface=None, target_interface=None):
    return execute_db(
        'INSERT INTO topology_links (user_id, source_device_id, target_device_id, source_interface, target_interface, link_status) VALUES (?, ?, ?, ?, ?, ?)',
        (user_id, source_device_id, target_device_id, source_interface, target_interface, 'mapped')
    )


def topology_link_exists(user_id, source_device_id, target_device_id, source_interface=None, target_interface=None):
    """Return True when a topology link already exists in either direction."""
    rows = query_db(
        '''SELECT id FROM topology_links
           WHERE user_id = ?
             AND (
               (source_device_id = ? AND target_device_id = ?)
               OR
               (source_device_id = ? AND target_device_id = ?)
             )
           LIMIT 1''',
        (user_id, source_device_id, target_device_id, target_device_id, source_device_id),
    )
    return bool(rows)


def add_link_if_missing(user_id, source_device_id, target_device_id, source_interface=None, target_interface=None):
    """Create a topology link only when the device pair is not already linked."""
    if source_device_id == target_device_id:
        return None
    if topology_link_exists(user_id, source_device_id, target_device_id, source_interface, target_interface):
        return None
    return add_link(user_id, source_device_id, target_device_id, source_interface, target_interface)


def get_user_links(user_id):
    return query_db(
        '''SELECT tl.*,
           d1.name as source_name, d1.vendor as source_vendor, d1.device_type as source_type,
           d2.name as target_name, d2.vendor as target_vendor, d2.device_type as target_type
           FROM topology_links tl
           JOIN devices d1 ON tl.source_device_id = d1.id
           JOIN devices d2 ON tl.target_device_id = d2.id
           WHERE tl.user_id = ?''',
        (user_id,)
    )


def delete_link(link_id, user_id):
    execute_db('DELETE FROM topology_links WHERE id = ? AND user_id = ?', (link_id, user_id))


# =============================================================================
# ALERTS
# =============================================================================

def create_alert(user_id, device_id, alert_type, severity, message):
    # Check if user exists first
    user = query_db('SELECT id FROM users WHERE id = ?', (user_id,), one=True)
    if not user:
        return None
    execute_db(
        'INSERT INTO alerts (user_id, device_id, alert_type, severity, message, created_at) VALUES (?, ?, ?, ?, ?, ?)',
        (user_id, device_id, alert_type, severity, message, datetime.now().isoformat())
    )


def get_user_alerts(user_id, resolved=None):
    if resolved is not None:
        return query_db('SELECT a.*, d.name as device_name FROM alerts a LEFT JOIN devices d ON a.device_id = d.id WHERE a.user_id = ? AND a.resolved = ? ORDER BY a.created_at DESC', (user_id, resolved))
    return query_db('SELECT a.*, d.name as device_name FROM alerts a LEFT JOIN devices d ON a.device_id = d.id WHERE a.user_id = ? ORDER BY a.created_at DESC', (user_id,))


def resolve_alert(alert_id, user_id):
    execute_db('UPDATE alerts SET resolved = 1 WHERE id = ? AND user_id = ?', (alert_id, user_id))


# =============================================================================
# ADVANCED NETWORK COMMAND VALIDATION (PATTERN MATCHING / BATCH FISH)
# =============================================================================

# Comprehensive vendor-specific command databases
CISCO_COMMANDS = {
    'global': [
        {'pattern': r'^enable$', 'desc': 'Enter privileged EXEC mode', 'category': 'system'},
        {'pattern': r'^configure\s+terminal$', 'desc': 'Enter global configuration mode', 'category': 'system'},
        {'pattern': r'^hostname\s+\S+$', 'desc': 'Set device hostname', 'category': 'system'},
        {'pattern': r'^enable\s+secret\s+\S+$', 'desc': 'Set enable secret password', 'category': 'security'},
        {'pattern': r'^enable\s+password\s+\S+$', 'desc': 'Set legacy enable password', 'category': 'security'},
        {'pattern': r'^aaa\s+new-model$', 'desc': 'Enable AAA', 'category': 'security'},
        {'pattern': r'^aaa\s+authentication\s+login\s+\S+\s+.+$', 'desc': 'Configure AAA login authentication', 'category': 'security'},
        {'pattern': r'^aaa\s+authorization\s+\S+\s+\S+\s+.+$', 'desc': 'Configure AAA authorization', 'category': 'security'},
        {'pattern': r'^no\s+ip\s+domain-lookup$', 'desc': 'Disable DNS lookup', 'category': 'system'},
        {'pattern': r'^ip\s+domain-name\s+\S+$', 'desc': 'Set domain name', 'category': 'system'},
        {'pattern': r'^ip\s+name-server\s+\d+\.\d+\.\d+\.\d+', 'desc': 'Set DNS server', 'category': 'system'},
        {'pattern': r'^clock\s+timezone\s+\S+', 'desc': 'Set timezone', 'category': 'system'},
        {'pattern': r'^ntp\s+server\s+\S+$', 'desc': 'Configure NTP server', 'category': 'system'},
        {'pattern': r'^snmp-server\s+community\s+\S+\s+(RO|RW)$', 'desc': 'Configure SNMP community', 'category': 'management'},
        {'pattern': r'^snmp-server\s+host\s+\d+\.\d+\.\d+\.\d+\s+\S+$', 'desc': 'Configure SNMP trap destination', 'category': 'management'},
        {'pattern': r'^ip\s+route\s+\d+\.\d+\.\d+\.\d+\s+\d+\.\d+\.\d+\.\d+\s+\d+\.\d+\.\d+\.\d+$', 'desc': 'Configure static route', 'category': 'routing'},
        {'pattern': r'^ip\s+route\s+\d+\.\d+\.\d+\.\d+\s+\d+\.\d+\.\d+\.\d+\s+\d+\.\d+\.\d+\.\d+\s+\d+$', 'desc': 'Configure static route with AD', 'category': 'routing'},
        {'pattern': r'^ip\s+route\s+\d+\.\d+\.\d+\.\d+\s+\d+\.\d+\.\d+\.\d+\s+(GigabitEthernet|FastEthernet|Ethernet|Serial|Loopback|Vlan|Tunnel|Port-channel)\S*$', 'desc': 'Configure static route via interface', 'category': 'routing'},
        {'pattern': r'^ip\s+route\s+\d+\.\d+\.\d+\.\d+\s+\d+\.\d+\.\d+\.\d+\s+(GigabitEthernet|FastEthernet|Ethernet|Serial|Loopback|Vlan|Tunnel|Port-channel)\S*\s+\d+$', 'desc': 'Configure static route via interface with AD', 'category': 'routing'},
        {'pattern': r'^ip\s+default-gateway\s+\d+\.\d+\.\d+\.\d+$', 'desc': 'Set default gateway', 'category': 'routing'},
        {'pattern': r'^ip\s+dhcp\s+pool\s+\S+$', 'desc': 'Create DHCP pool', 'category': 'services'},
        {'pattern': r'^network\s+\d+\.\d+\.\d+\.\d+\s+\d+\.\d+\.\d+\.\d+$', 'desc': 'DHCP network statement', 'category': 'services'},
        {'pattern': r'^default-router\s+\d+\.\d+\.\d+\.\d+$', 'desc': 'DHCP default router', 'category': 'services'},
        {'pattern': r'^dns-server\s+\d+\.\d+\.\d+\.\d+$', 'desc': 'DHCP DNS server', 'category': 'services'},
        {'pattern': r'^access-list\s+\d+\s+(permit|deny)\s+\d+\.\d+\.\d+\.\d+\s+\d+\.\d+\.\d+\.\d+$', 'desc': 'Standard ACL entry', 'category': 'security'},
        {'pattern': r'^access-list\s+\d+\s+(permit|deny)\s+(tcp|udp|icmp)\s+.+$', 'desc': 'Extended ACL entry', 'category': 'security'},
        {'pattern': r'^ip\s+access-list\s+(standard|extended)\s+\S+$', 'desc': 'Named ACL', 'category': 'security'},
        {'pattern': r'^line\s+(console|vty|aux)\s+\d+', 'desc': 'Enter line configuration', 'category': 'security'},
        {'pattern': r'^login\s+local$', 'desc': 'Use local authentication', 'category': 'security'},
        {'pattern': r'^login$', 'desc': 'Use line password authentication', 'category': 'security'},
        {'pattern': r'^transport\s+input\s+\S+$', 'desc': 'Set transport input protocol', 'category': 'security'},
        {'pattern': r'^transport\s+output\s+\S+$', 'desc': 'Set outbound transport protocol', 'category': 'security'},
        {'pattern': r'^exec-timeout\s+\d+\s+\d+$', 'desc': 'Set line idle timeout', 'category': 'security'},
        {'pattern': r'^logging\s+synchronous$', 'desc': 'Synchronize line logging', 'category': 'system'},
        {'pattern': r'^privilege\s+level\s+\d+$', 'desc': 'Set line privilege level', 'category': 'security'},
        {'pattern': r'^password\s+\S+$', 'desc': 'Set line password', 'category': 'security'},
        {'pattern': r'^username\s+\S+\s+(secret|password)\s+\S+$', 'desc': 'Create local user', 'category': 'security'},
        {'pattern': r'^banner\s+(motd|login)\s+.+$', 'desc': 'Set banner message', 'category': 'system'},
        {'pattern': r'^service\s+password-encryption$', 'desc': 'Enable password encryption', 'category': 'security'},
        {'pattern': r'^crypto\s+key\s+generate\s+rsa$', 'desc': 'Generate RSA keys for SSH', 'category': 'security'},
        {'pattern': r'^crypto\s+key\s+generate\s+rsa\s+.*$', 'desc': 'Generate RSA keys for SSH', 'category': 'security'},
        {'pattern': r'^ip\s+ssh\s+version\s+2$', 'desc': 'Enable SSH version 2', 'category': 'security'},
        {'pattern': r'^ip\s+ssh\s+time-out\s+\d+$', 'desc': 'Set SSH timeout', 'category': 'security'},
        {'pattern': r'^ip\s+ssh\s+authentication-retries\s+\d+$', 'desc': 'Set SSH authentication retries', 'category': 'security'},
        {'pattern': r'^security\s+passwords\s+min-length\s+\d+$', 'desc': 'Set minimum password length', 'category': 'security'},
        {'pattern': r'^login\s+block-for\s+\d+\s+attempts\s+\d+\s+within\s+\d+$', 'desc': 'Block repeated login failures', 'category': 'security'},
        {'pattern': r'^spanning-tree\s+mode\s+\S+$', 'desc': 'Set spanning-tree mode', 'category': 'switching'},
        {'pattern': r'^spanning-tree\s+vlan\s+\d+\s+root\s+(primary|secondary)$', 'desc': 'Set STP root bridge', 'category': 'switching'},
        {'pattern': r'^vtp\s+(mode|domain)\s+\S+$', 'desc': 'Configure VTP', 'category': 'switching'},
        {'pattern': r'^ip\s+routing$', 'desc': 'Enable IP routing', 'category': 'routing'},
        {'pattern': r'^router\s+ospf\s+\d+$', 'desc': 'Enter OSPF process', 'category': 'routing'},
        {'pattern': r'^router\s+rip$', 'desc': 'Enter RIP process', 'category': 'routing'},
        {'pattern': r'^router\s+eigrp\s+\S+$', 'desc': 'Enter EIGRP process', 'category': 'routing'},
        {'pattern': r'^router\s+bgp\s+\S+$', 'desc': 'Enter BGP process', 'category': 'routing'},
        {'pattern': r'^router\s+eigrp\s+\S+$', 'desc': 'Enter EIGRP named mode', 'category': 'routing'},
        {'pattern': r'^network\s+\d+\.\d+\.\d+\.\d+\s+\d+\.\d+\.\d+\.\d+\s+area\s+\d+$', 'desc': 'OSPF network statement', 'category': 'routing'},
        {'pattern': r'^network\s+\d+\.\d+\.\d+\.\d+$', 'desc': 'RIP/EIGRP network statement', 'category': 'routing'},
        {'pattern': r'^default-information\s+originate$', 'desc': 'Originate default route', 'category': 'routing'},
        {'pattern': r'^redistribute\s+(connected|static|ospf|eigrp|rip)\s*.*$', 'desc': 'Redistribute routes', 'category': 'routing'},
        {'pattern': r'^ip\s+nat\s+(inside|outside)$', 'desc': 'Set NAT interface direction', 'category': 'services'},
        {'pattern': r'^ip\s+nat\s+inside\s+source\s+static\s+\d+\.\d+\.\d+\.\d+\s+\d+\.\d+\.\d+\.\d+$', 'desc': 'Static NAT entry', 'category': 'services'},
        {'pattern': r'^ip\s+nat\s+inside\s+source\s+list\s+\d+\s+interface\s+\S+\s+overload$', 'desc': 'PAT configuration', 'category': 'services'},
        {'pattern': r'^access-list\s+\d+\s+permit\s+\d+\.\d+\.\d+\.\d+\s+\d+\.\d+\.\d+\.\d+$', 'desc': 'NAT ACL for PAT', 'category': 'services'},
        {'pattern': r'^version\s+\S+$', 'desc': 'Set config version', 'category': 'system'},
        {'pattern': r'^end$', 'desc': 'End configuration mode', 'category': 'system'},
        {'pattern': r'^exit$', 'desc': 'Exit current mode', 'category': 'system'},
        {'pattern': r'^write\s*(memory)?$|^copy\s+running-config\s+startup-config$', 'desc': 'Save configuration', 'category': 'system'},
        # === ADDITIONAL ROUTING ===
        {'pattern': r'^passive-interface\s+\S+$', 'desc': 'Set passive interface for routing', 'category': 'routing'},
        {'pattern': r'^passive-interface\s+default$', 'desc': 'Set all interfaces passive by default', 'category': 'routing'},
        {'pattern': r'^router-id\s+\d+\.\d+\.\d+\.\d+$', 'desc': 'Set router ID', 'category': 'routing'},
        {'pattern': r'^auto-cost\s+reference-bandwidth\s+\d+$', 'desc': 'Set OSPF reference bandwidth', 'category': 'routing'},
        {'pattern': r'^log-adjacency-changes(\s+detail)?$', 'desc': 'Log OSPF adjacency changes', 'category': 'routing'},
        {'pattern': r'^area\s+\d+\s+authentication(\s+message-digest)?$', 'desc': 'Set OSPF area authentication', 'category': 'routing'},
        {'pattern': r'^area\s+\d+\s+nssa(\s+.*)?$', 'desc': 'Configure OSPF NSSA area', 'category': 'routing'},
        {'pattern': r'^area\s+\d+\s+stub(\s+.*)?$', 'desc': 'Configure OSPF stub area', 'category': 'routing'},
        {'pattern': r'^area\s+\d+\s+default-cost\s+\d+$', 'desc': 'Set OSPF stub area default cost', 'category': 'routing'},
        {'pattern': r'^area\s+\d+\s+range\s+\S+\s+\S+$', 'desc': 'Set OSPF area range summary', 'category': 'routing'},
        {'pattern': r'^maximum-paths\s+\d+$', 'desc': 'Set maximum equal-cost paths', 'category': 'routing'},
        {'pattern': r'^no\s+auto-summary$', 'desc': 'Disable auto-summary (RIP/EIGRP)', 'category': 'routing'},
        {'pattern': r'^version\s+2$', 'desc': 'Set RIP version 2', 'category': 'routing'},
        {'pattern': r'^eigrp\s+router-id\s+\S+$', 'desc': 'Set EIGRP router ID', 'category': 'routing'},
        {'pattern': r'^variance\s+\d+$', 'desc': 'Set EIGRP variance', 'category': 'routing'},
        # EIGRP Named Mode
        {'pattern': r'^address-family\s+ipv4\s+unicast(\s+autonomous-system\s+\d+)?$', 'desc': 'EIGRP named mode address family', 'category': 'routing'},
        {'pattern': r'^af-interface\s+\S+$', 'desc': 'EIGRP address family interface', 'category': 'routing'},
        {'pattern': r'^topology\s+base$', 'desc': 'EIGRP named mode base topology', 'category': 'routing'},
        {'pattern': r'^nsf$', 'desc': 'Enable NSF (Non-Stop Forwarding)', 'category': 'routing'},
        {'pattern': r'^metric\s+weights\s+.+$', 'desc': 'Set EIGRP metric weights', 'category': 'routing'},
        {'pattern': r'^distribute-list\s+\S+\s+(in|out)(\s+\S+)?$', 'desc': 'Apply distribute-list', 'category': 'routing'},
        {'pattern': r'^offset-list\s+\S+\s+(in|out)\s+\d+(\s+\S+)?$', 'desc': 'Apply offset-list', 'category': 'routing'},
        {'pattern': r'^distance\s+\d+(\s+\S+\s+\S+)?$', 'desc': 'Set administrative distance', 'category': 'routing'},
        {'pattern': r'^summary-address\s+\S+\s+\S+$', 'desc': 'Configure EIGRP summary address', 'category': 'routing'},
        {'pattern': r'^neighbor\s+\S+\s+remote-as\s+\d+$', 'desc': 'Configure BGP neighbor remote AS', 'category': 'routing'},
        {'pattern': r'^neighbor\s+\S+\s+update-source\s+\S+$', 'desc': 'Set BGP update source', 'category': 'routing'},
        {'pattern': r'^neighbor\s+\S+\s+next-hop-self$', 'desc': 'Set BGP next-hop-self', 'category': 'routing'},
        {'pattern': r'^neighbor\s+\S+\s+ebgp-multihop\s+\d+$', 'desc': 'Set BGP EBGP multihop', 'category': 'routing'},
        {'pattern': r'^neighbor\s+\S+\s+password\s+\S+$', 'desc': 'Set BGP neighbor password', 'category': 'routing'},
        {'pattern': r'^neighbor\s+\S+\s+route-map\s+\S+\s+(in|out)$', 'desc': 'Apply BGP route-map', 'category': 'routing'},
        {'pattern': r'^neighbor\s+\S+\s+(activate|shutdown)$', 'desc': 'Activate/shutdown BGP neighbor', 'category': 'routing'},
        {'pattern': r'^neighbor\s+\S+\s+peer-group\s+\S+$', 'desc': 'Assign BGP peer group', 'category': 'routing'},
        {'pattern': r'^bgp\s+router-id\s+\S+$', 'desc': 'Set BGP router ID', 'category': 'routing'},
        {'pattern': r'^bgp\s+log-neighbor-changes$', 'desc': 'Log BGP neighbor changes', 'category': 'routing'},
        {'pattern': r'^no\s+synchronization$', 'desc': 'Disable BGP synchronization', 'category': 'routing'},
        {'pattern': r'^no\s+bgp\s+default\s+ipv4-unicast$', 'desc': 'Disable default IPv4 unicast', 'category': 'routing'},
        {'pattern': r'^address-family\s+\S+(\s+\S+)?$', 'desc': 'Enter address family', 'category': 'routing'},
        {'pattern': r'^network\s+\S+(\s+mask\s+\S+)?(\s+route-map\s+\S+)?$', 'desc': 'BGP network statement', 'category': 'routing'},
        {'pattern': r'^aggregate-address\s+\S+\s+\S+(\s+.*)?$', 'desc': 'BGP aggregate address', 'category': 'routing'},
        {'pattern': r'^timers\s+bgp\s+\d+\s+\d+(\s+\d+)?$', 'desc': 'Set BGP timers', 'category': 'routing'},
        # === ADDITIONAL SYSTEM ===
        {'pattern': r'^ip\s+classless$', 'desc': 'Enable classless routing', 'category': 'system'},
        {'pattern': r'^ip\s+domain[\s-]lookup(\s+.*)?$', 'desc': 'Configure domain lookup', 'category': 'system'},
        {'pattern': r'^ip\s+http\s+server$', 'desc': 'Enable HTTP server', 'category': 'management'},
        {'pattern': r'^ip\s+http\s+secure-server$', 'desc': 'Enable HTTPS server', 'category': 'management'},
        {'pattern': r'^ip\s+scp\s+server\s+enable$', 'desc': 'Enable SCP server', 'category': 'management'},
        {'pattern': r'^ip\s+tftp\s+source-interface\s+\S+$', 'desc': 'Set TFTP source interface', 'category': 'system'},
        {'pattern': r'^ip\s+cef$', 'desc': 'Enable CEF', 'category': 'system'},
        {'pattern': r'^logging\s+buffered(\s+\d+)?$', 'desc': 'Enable buffered logging', 'category': 'management'},
        {'pattern': r'^logging\s+console(\s+\S+)?$', 'desc': 'Enable console logging', 'category': 'management'},
        {'pattern': r'^logging\s+trap(\s+\S+)?$', 'desc': 'Set syslog trap level', 'category': 'management'},
        {'pattern': r'^logging\s+host\s+\S+$', 'desc': 'Set syslog host', 'category': 'management'},
        {'pattern': r'^no\s+cdp\s+run$', 'desc': 'Disable CDP globally', 'category': 'system'},
        {'pattern': r'^cdp\s+run$', 'desc': 'Enable CDP globally', 'category': 'system'},
        {'pattern': r'^lldp\s+run$', 'desc': 'Enable LLDP globally', 'category': 'system'},
        {'pattern': r'^ip\s+sla\s+\d+$', 'desc': 'Configure IP SLA', 'category': 'management'},
        {'pattern': r'^track\s+\d+\s+.+$', 'desc': 'Configure tracking', 'category': 'management'},
        {'pattern': r'^route-map\s+\S+\s+(permit|deny)\s+\d+$', 'desc': 'Create route-map entry', 'category': 'routing'},
        {'pattern': r'^ip\s+prefix-list\s+\S+\s+.+$', 'desc': 'Configure IP prefix-list', 'category': 'routing'},
        {'pattern': r'^match\s+.+$', 'desc': 'Route-map match clause', 'category': 'routing'},
        {'pattern': r'^set\s+.+$', 'desc': 'Route-map set clause', 'category': 'routing'},
        {'pattern': r'^snmp-server\s+location\s+.+$', 'desc': 'Set SNMP location', 'category': 'management'},
        {'pattern': r'^snmp-server\s+contact\s+.+$', 'desc': 'Set SNMP contact', 'category': 'management'},
        {'pattern': r'^snmp-server\s+enable\s+.+$', 'desc': 'Enable SNMP traps', 'category': 'management'},
        {'pattern': r'^snmp-server\s+trap-source\s+\S+$', 'desc': 'Set SNMP trap source', 'category': 'management'},
        {'pattern': r'^snmp-server\s+group\s+\S+\s+.+$', 'desc': 'Configure SNMP group', 'category': 'management'},
        {'pattern': r'^snmp-server\s+user\s+\S+\s+.+$', 'desc': 'Configure SNMP user', 'category': 'management'},
        {'pattern': r'^no\s+ip\s+finger$', 'desc': 'Disable finger service', 'category': 'security'},
        {'pattern': r'^no\s+service\s+finger$', 'desc': 'Disable finger service', 'category': 'security'},
        {'pattern': r'^no\s+ip\s+bootp\s+server$', 'desc': 'Disable BOOTP server', 'category': 'security'},
        {'pattern': r'^no\s+ip\s+http\s+server$', 'desc': 'Disable HTTP server', 'category': 'security'},
        {'pattern': r'^no\s+service\s+pad$', 'desc': 'Disable PAD service', 'category': 'security'},
        {'pattern': r'^no\s+service\s+tcp-small-servers$', 'desc': 'Disable small TCP servers', 'category': 'security'},
        {'pattern': r'^no\s+service\s+udp-small-servers$', 'desc': 'Disable small UDP servers', 'category': 'security'},
        {'pattern': r'^ip\s+source-route$', 'desc': 'Enable source routing', 'category': 'system'},
        {'pattern': r'^no\s+ip\s+source-route$', 'desc': 'Disable source routing', 'category': 'security'},
        {'pattern': r'^aaa\s+accounting\s+.+$', 'desc': 'Configure AAA accounting', 'category': 'security'},
        {'pattern': r'^aaa\s+session-id\s+\S+$', 'desc': 'Set AAA session ID', 'category': 'security'},
        {'pattern': r'^archive\s*$', 'desc': 'Enter archive configuration', 'category': 'system'},
        {'pattern': r'^path\s+\S+$', 'desc': 'Set archive path', 'category': 'system'},
        {'pattern': r'^maximum\s+\d+$', 'desc': 'Set maximum value', 'category': 'system'},
        {'pattern': r'^time-period\s+\S+$', 'desc': 'Set time period', 'category': 'system'},
        {'pattern': r'^write-memory$', 'desc': 'Write memory on archive', 'category': 'system'},
        {'pattern': r'^errdisable\s+recovery\s+.+$', 'desc': 'Configure errdisable recovery', 'category': 'system'},
        {'pattern': r'^udld\s+\S+$', 'desc': 'Configure UDLD', 'category': 'system'},
        {'pattern': r'^cdp\s+timer\s+\d+$', 'desc': 'Set CDP timer', 'category': 'system'},
        {'pattern': r'^cdp\s+holdtime\s+\d+$', 'desc': 'Set CDP holdtime', 'category': 'system'},
        {'pattern': r'^line\s+console\s+\d+\s+\d+$', 'desc': 'Enter console line range', 'category': 'security'},
        {'pattern': r'^line\s+vty\s+\d+\s+\d+$', 'desc': 'Enter VTY line range', 'category': 'security'},
        {'pattern': r'^line\s+aux\s+\d+$', 'desc': 'Enter aux line', 'category': 'security'},
        {'pattern': r'^transport\s+input\s+(telnet|ssh|all|none)(\s+\S+)?$', 'desc': 'Set transport input', 'category': 'security'},
        {'pattern': r'^transport\s+output\s+(telnet|ssh|all|none)(\s+\S+)?$', 'desc': 'Set transport output', 'category': 'security'},
        {'pattern': r'^stopbits\s+\d+$', 'desc': 'Set stop bits', 'category': 'security'},
        {'pattern': r'^no\s+exec$', 'desc': 'Disable exec on line', 'category': 'security'},
    ],
    'interface': [
        {'pattern': r'^interface\s+(GigabitEthernet|FastEthernet|Ethernet|Serial|Loopback|Vlan|Tunnel|Port-channel)\d+(/\d+)*(\.\d+)?$', 'desc': 'Enter interface configuration', 'category': 'interface'},
        {'pattern': rf'^interface\s+range\s+{CISCO_INTERFACE_NAME_PATTERN}\s+-\s+{CISCO_INTERFACE_RANGE_END_PATTERN}$', 'desc': 'Enter interface range configuration', 'category': 'interface'},
        {'pattern': r'^ip\s+address\s+\d+\.\d+\.\d+\.\d+\s+\d+\.\d+\.\d+\.\d+$', 'desc': 'Set IP address with mask', 'category': 'interface'},
        {'pattern': r'^ip\s+address\s+\d+\.\d+\.\d+\.\d+$', 'desc': 'IP address missing subnet mask', 'category': 'interface', 'error': True},
        {'pattern': r'^no\s+shutdown$', 'desc': 'Enable interface', 'category': 'interface'},
        {'pattern': r'^shutdown$', 'desc': 'Disable interface', 'category': 'interface'},
        {'pattern': r'^description\s+.+$', 'desc': 'Set interface description', 'category': 'interface'},
        {'pattern': r'^switchport\s+mode\s+(access|trunk)$', 'desc': 'Set switchport mode', 'category': 'switching'},
        {'pattern': r'^switchport\s+access\s+vlan\s+\d+$', 'desc': 'Assign access VLAN', 'category': 'switching'},
        {'pattern': r'^switchport\s+trunk\s+allowed\s+vlan\s+.+$', 'desc': 'Set trunk allowed VLANs', 'category': 'switching'},
        {'pattern': r'^switchport\s+trunk\s+encapsulation\s+(dot1q|isl)$', 'desc': 'Set trunk encapsulation', 'category': 'switching'},
        {'pattern': r'^switchport\s+nonegotiate$', 'desc': 'Disable DTP', 'category': 'switching'},
        {'pattern': r'^channel-group\s+\d+\s+mode\s+(active|passive|desirable|auto|on)$', 'desc': 'Configure EtherChannel', 'category': 'interface'},
        {'pattern': r'^standby\s+\d+\s+ip\s+\d+\.\d+\.\d+\.\d+$', 'desc': 'Configure HSRP', 'category': 'interface'},
        {'pattern': r'^standby\s+\d+\s+(preempt|priority)\s+\d+$', 'desc': 'Configure HSRP priority/preempt', 'category': 'interface'},
        {'pattern': r'^standby\s+\d+\s+track\s+\d+(\s+decrement\s+\d+)?$', 'desc': 'HSRP tracking', 'category': 'interface'},
        {'pattern': r'^standby\s+version\s+\d+$', 'desc': 'Set HSRP version', 'category': 'interface'},
        {'pattern': r'^duplex\s+(full|half|auto)$', 'desc': 'Set duplex mode', 'category': 'interface'},
        {'pattern': r'^speed\s+(10|100|1000|auto)$', 'desc': 'Set interface speed', 'category': 'interface'},
        {'pattern': r'^ip\s+helper-address\s+\d+\.\d+\.\d+\.\d+$', 'desc': 'Configure DHCP relay', 'category': 'interface'},
        {'pattern': r'^ip\s+address\s+dhcp$', 'desc': 'Get IP address via DHCP', 'category': 'interface'},
        {'pattern': r'^ip\s+nat\s+(inside|outside)$', 'desc': 'Set NAT direction on interface', 'category': 'interface'},
        {'pattern': r'^ip\s+virtual-reassembly$', 'desc': 'Enable virtual reassembly', 'category': 'interface'},
        {'pattern': r'^ip\s+tcp\s+adjust-mss\s+\d+$', 'desc': 'Adjust TCP MSS', 'category': 'interface'},
        {'pattern': r'^ip\s+mtu\s+\d+$', 'desc': 'Set IP MTU', 'category': 'interface'},
        {'pattern': r'^mtu\s+\d+$', 'desc': 'Set interface MTU', 'category': 'interface'},
        {'pattern': r'^bandwidth\s+\d+$', 'desc': 'Set interface bandwidth', 'category': 'interface'},
        {'pattern': r'^ip\s+ospf\s+cost\s+\d+$', 'desc': 'Set OSPF cost', 'category': 'interface'},
        {'pattern': r'^ip\s+ospf\s+priority\s+\d+$', 'desc': 'Set OSPF priority', 'category': 'interface'},
        {'pattern': r'^ip\s+ospf\s+hello-interval\s+\d+$', 'desc': 'Set OSPF hello interval', 'category': 'interface'},
        {'pattern': r'^ip\s+ospf\s+dead-interval\s+\d+$', 'desc': 'Set OSPF dead interval', 'category': 'interface'},
        {'pattern': r'^ip\s+ospf\s+network\s+(broadcast|non-broadcast|point-to-point|point-to-multipoint)$', 'desc': 'Set OSPF network type', 'category': 'interface'},
        {'pattern': r'^ip\s+ospf\s+authentication(\s+message-digest)?$', 'desc': 'Set OSPF authentication', 'category': 'interface'},
        {'pattern': r'^ip\s+ospf\s+message-digest-key\s+\d+\s+md5\s+\S+$', 'desc': 'Set OSPF MD5 key', 'category': 'interface'},
        {'pattern': r'^ip\s+ospf\s+passive-interface$', 'desc': 'Set OSPF passive interface', 'category': 'interface'},
        {'pattern': r'^ip\s+pim\s+(dense-mode|sparse-mode|sparse-dense-mode)$', 'desc': 'Set PIM mode', 'category': 'interface'},
        {'pattern': r'^ipv6\s+address\s+\S+$', 'desc': 'Set IPv6 address', 'category': 'interface'},
        {'pattern': r'^ipv6\s+enable$', 'desc': 'Enable IPv6 on interface', 'category': 'interface'},
        {'pattern': r'^ipv6\s+nd\s+.+$', 'desc': 'Configure IPv6 ND', 'category': 'interface'},
        {'pattern': r'^encapsulation\s+(dot1Q|ppp|frame-relay|hdlc)\s*\d*$', 'desc': 'Set encapsulation', 'category': 'interface'},
        {'pattern': r'^ppp\s+encapsulation\s+\S+$', 'desc': 'Set PPP encapsulation', 'category': 'interface'},
        {'pattern': r'^ppp\s+authentication\s+\S+(\s+\S+)?$', 'desc': 'Set PPP authentication', 'category': 'interface'},
        {'pattern': r'^ppp\s+ipcp\s+dns\s+\S+$', 'desc': 'Set PPP IPCP DNS', 'category': 'interface'},
        {'pattern': r'^dialer\s+.+$', 'desc': 'Configure dialer', 'category': 'interface'},
        {'pattern': r'^no\s+cdp\s+enable$', 'desc': 'Disable CDP on interface', 'category': 'interface'},
        {'pattern': r'^no\s+lldp\s+(transmit|receive)$', 'desc': 'Disable LLDP on interface', 'category': 'interface'},
        {'pattern': r'^spanning-tree\s+portfast(\s+edge)?$', 'desc': 'Enable portfast', 'category': 'switching'},
        {'pattern': r'^spanning-tree\s+portfast\s+trunk$', 'desc': 'Enable portfast on trunk', 'category': 'switching'},
        {'pattern': r'^spanning-tree\s+bpduguard\s+enable$', 'desc': 'Enable BPDU guard', 'category': 'switching'},
        {'pattern': r'^spanning-tree\s+guard\s+\S+$', 'desc': 'Set STP guard', 'category': 'switching'},
        {'pattern': r'^storm-control\s+.+$', 'desc': 'Configure storm control', 'category': 'switching'},
        {'pattern': r'^switchport\s+mode\s+(access|trunk|dynamic\s+(auto|desirable))$', 'desc': 'Set switchport mode', 'category': 'switching'},
        {'pattern': r'^switchport\s+voice\s+vlan\s+\d+$', 'desc': 'Set voice VLAN', 'category': 'switching'},
        {'pattern': r'^switchport\s+port-security(\s+.*)?$', 'desc': 'Configure port security', 'category': 'switching'},
        {'pattern': r'^switchport\s+port-security\s+maximum\s+\d+$', 'desc': 'Set port security max MACs', 'category': 'switching'},
        {'pattern': r'^switchport\s+port-security\s+violation\s+(protect|restrict|shutdown)$', 'desc': 'Set port security violation action', 'category': 'switching'},
        {'pattern': r'^switchport\s+port-security\s+mac-address\s+sticky(\s+\S+)?$', 'desc': 'Enable sticky MAC learning', 'category': 'switching'},
        {'pattern': r'^switchport\s+port-security\s+mac-address\s+\S+$', 'desc': 'Set static MAC for port security', 'category': 'switching'},
        {'pattern': r'^switchport\s+port-security\s+aging\s+\S+$', 'desc': 'Configure port security aging', 'category': 'switching'},
        {'pattern': r'^tunnel\s+source\s+\S+$', 'desc': 'Set tunnel source', 'category': 'interface'},
        {'pattern': r'^tunnel\s+destination\s+\S+$', 'desc': 'Set tunnel destination', 'category': 'interface'},
        {'pattern': r'^tunnel\s+mode\s+\S+$', 'desc': 'Set tunnel mode', 'category': 'interface'},
        {'pattern': r'^tunnel\s+path-mtu-discovery$', 'desc': 'Enable tunnel PMTUD', 'category': 'interface'},
        {'pattern': r'^crypto\s+map\s+\S+$', 'desc': 'Apply crypto map', 'category': 'interface'},
        {'pattern': r'^zone-member\s+security\s+\S+$', 'desc': 'Assign zone member', 'category': 'security'},
        {'pattern': r'^ip\s+verify\s+source\s+.+$', 'desc': 'Enable IP source guard', 'category': 'security'},
        {'pattern': r'^ip\s+dhcp\s+snooping\s+limit\s+\d+$', 'desc': 'Set DHCP snooping limit', 'category': 'security'},
        {'pattern': r'^ip\s+inspect\s+\S+\s+(in|out)$', 'desc': 'Apply CBAC inspection', 'category': 'security'},
        {'pattern': r'^service-policy\s+(input|output)\s+\S+$', 'desc': 'Apply QoS policy', 'category': 'interface'},
        {'pattern': r'^priority-queue\s+\S+$', 'desc': 'Set priority queue', 'category': 'interface'},
        {'pattern': r'^bandwidth\s+(percent|remaining)\s+\d+$', 'desc': 'Set bandwidth percentage', 'category': 'interface'},
    ],
    'vlan': [
        {'pattern': r'^vlan\s+\d+(?:\s*[-,]\s*\d+)*$', 'desc': 'Create VLAN or VLAN range', 'category': 'switching'},
        {'pattern': r'^name\s+\S+$', 'desc': 'Set VLAN name', 'category': 'switching'},
        {'pattern': r'^interface\s+Vlan\d+$', 'desc': 'Enter SVI configuration', 'category': 'switching'},
        {'pattern': r'^vlan\s+internal\s+allocation\s+policy\s+\S+$', 'desc': 'Set VLAN allocation policy', 'category': 'switching'},
        {'pattern': r'^ip\s+dhcp\s+snooping\s+vlan\s+.+$', 'desc': 'Enable DHCP snooping on VLAN', 'category': 'switching'},
    ],
}

JUNIPER_COMMANDS = {
    'global': [
        {'pattern': r'^set\s+system\s+host-name\s+\S+$', 'desc': 'Set hostname', 'category': 'system'},
        {'pattern': r'^set\s+system\s+root-authentication\s+.+$', 'desc': 'Configure root authentication', 'category': 'security'},
        {'pattern': r'^set\s+system\s+login\s+user\s+\S+\s+class\s+\S+\s+authentication\s+.+$', 'desc': 'Configure local user authentication', 'category': 'security'},
        {'pattern': r'^set\s+system\s+time-zone\s+\S+$', 'desc': 'Set timezone', 'category': 'system'},
        {'pattern': r'^set\s+system\s+name-server\s+\S+$', 'desc': 'Configure DNS name server', 'category': 'system'},
        {'pattern': r'^set\s+system\s+ntp\s+server\s+\S+$', 'desc': 'Configure NTP', 'category': 'system'},
        {'pattern': r'^set\s+system\s+services\s+(ssh|telnet|netconf)\s*$', 'desc': 'Enable service', 'category': 'system'},
        {'pattern': r'^set\s+system\s+services\s+ssh\s+.+$', 'desc': 'Configure SSH service', 'category': 'security'},
        {'pattern': r'^set\s+system\s+syslog\s+.+$', 'desc': 'Configure syslog', 'category': 'management'},
        {'pattern': r'^set\s+snmp\s+community\s+\S+\s+authorization\s+(read-only|read-write)$', 'desc': 'Configure SNMP', 'category': 'management'},
        {'pattern': r'^set\s+routing-options\s+static\s+route\s+\S+\s+next-hop\s+\S+$', 'desc': 'Configure static route', 'category': 'routing'},
        {'pattern': r'^set\s+routing-options\s+router-id\s+\S+$', 'desc': 'Set router ID', 'category': 'routing'},
        {'pattern': r'^set\s+routing-options\s+autonomous-system\s+\d+$', 'desc': 'Set AS number', 'category': 'routing'},
        {'pattern': r'^set\s+routing-options\s+forwarding-table\s+.+$', 'desc': 'Configure forwarding table', 'category': 'routing'},
        {'pattern': r'^set\s+protocols\s+ospf\s+area\s+\S+\s+interface\s+\S+$', 'desc': 'Configure OSPF', 'category': 'routing'},
        {'pattern': r'^set\s+protocols\s+ospf\s+area\s+\S+\s+interface\s+\S+\s+.+$', 'desc': 'Configure OSPF interface option', 'category': 'routing'},
        {'pattern': r'^set\s+protocols\s+ospf\s+export\s+\S+$', 'desc': 'Export routes to OSPF', 'category': 'routing'},
        # RIP
        {'pattern': r'^set\s+protocols\s+rip\s+group\s+\S+\s+neighbor\s+\S+$', 'desc': 'Configure RIP neighbor', 'category': 'routing'},
        {'pattern': r'^set\s+protocols\s+rip\s+group\s+\S+\s+export\s+\S+$', 'desc': 'Configure RIP export policy', 'category': 'routing'},
        {'pattern': r'^set\s+protocols\s+rip\s+group\s+\S+\s+import\s+\S+$', 'desc': 'Configure RIP import policy', 'category': 'routing'},
        {'pattern': r'^set\s+protocols\s+rip\s+traceoptions\s+.+$', 'desc': 'Configure RIP trace options', 'category': 'routing'},
        # IS-IS
        {'pattern': r'^set\s+protocols\s+isis\s+interface\s+\S+\s+.+$', 'desc': 'Configure IS-IS interface', 'category': 'routing'},
        {'pattern': r'^set\s+protocols\s+isis\s+level\s+\S+\s+.+$', 'desc': 'Configure IS-IS level', 'category': 'routing'},
        # LDP
        {'pattern': r'^set\s+protocols\s+ldp\s+interface\s+\S+$', 'desc': 'Configure LDP interface', 'category': 'routing'},
        # More routing options
        {'pattern': r'^set\s+routing-options\s+aggregate\s+route\s+\S+\s+.+$', 'desc': 'Configure aggregate route', 'category': 'routing'},
        {'pattern': r'^set\s+routing-options\s+static\s+route\s+\S+\s+discard$', 'desc': 'Configure discard route', 'category': 'routing'},
        {'pattern': r'^set\s+routing-options\s+static\s+route\s+\S+\s+reject$', 'desc': 'Configure reject route', 'category': 'routing'},
        {'pattern': r'^set\s+protocols\s+bgp\s+group\s+\S+\s+type\s+\S+$', 'desc': 'Set BGP group type', 'category': 'routing'},
        {'pattern': r'^set\s+protocols\s+bgp\s+group\s+\S+\s+neighbor\s+\S+\s+peer-as\s+\d+$', 'desc': 'Configure BGP peer AS', 'category': 'routing'},
        {'pattern': r'^set\s+protocols\s+bgp\s+group\s+\S+\s+neighbor\s+\S+$', 'desc': 'Configure BGP neighbor', 'category': 'routing'},
        {'pattern': r'^set\s+protocols\s+bgp\s+group\s+\S+\s+(local-address|export|import)\s+.+$', 'desc': 'Configure BGP group option', 'category': 'routing'},
        {'pattern': r'^set\s+protocols\s+lldp\s+.+$', 'desc': 'Configure LLDP', 'category': 'system'},
        {'pattern': r'^set\s+protocols\s+stp\s+.+$', 'desc': 'Configure STP', 'category': 'switching'},
        {'pattern': r'^set\s+protocols\s+rstp\s+.+$', 'desc': 'Configure RSTP', 'category': 'switching'},
        {'pattern': r'^set\s+firewall\s+family\s+inet\s+filter\s+\S+\s+term\s+\S+\s+from\s+.+$', 'desc': 'Configure firewall filter', 'category': 'security'},
        {'pattern': r'^set\s+firewall\s+family\s+inet\s+filter\s+\S+\s+term\s+\S+\s+then\s+(accept|reject|discard|count|policer|log)\s*.*$', 'desc': 'Configure firewall action', 'category': 'security'},
        {'pattern': r'^set\s+firewall\s+family\s+inet\s+filter\s+\S+\s+term\s+\S+\s+then\s+\S+$', 'desc': 'Configure firewall action', 'category': 'security'},
        {'pattern': r'^set\s+interfaces\s+\S+\s+unit\s+\d+\s+family\s+inet\s+address\s+\d+\.\d+\.\d+\.\d+/\d+$', 'desc': 'Set interface IP', 'category': 'interface'},
        {'pattern': r'^set\s+interfaces\s+\S+\s+unit\s+\d+\s+family\s+inet$', 'desc': 'Set interface family inet', 'category': 'interface'},
        {'pattern': r'^set\s+interfaces\s+\S+\s+unit\s+\d+\s+description\s+\S+$', 'desc': 'Set interface description', 'category': 'interface'},
        {'pattern': r'^set\s+interfaces\s+\S+\s+unit\s+\d+\s+description\s+".+"$', 'desc': 'Set interface description quoted', 'category': 'interface'},
        {'pattern': r'^set\s+interfaces\s+\S+\s+description\s+\S+$', 'desc': 'Set physical interface description', 'category': 'interface'},
        {'pattern': r'^set\s+interfaces\s+\S+\s+mtu\s+\d+$', 'desc': 'Set interface MTU', 'category': 'interface'},
        {'pattern': r'^set\s+interfaces\s+\S+\s+speed\s+\S+$', 'desc': 'Set interface speed', 'category': 'interface'},
        {'pattern': r'^set\s+interfaces\s+\S+\s+link-mode\s+\S+$', 'desc': 'Set link mode', 'category': 'interface'},
        {'pattern': r'^set\s+interfaces\s+\S+\s+ether-options\s+.+$', 'desc': 'Set ethernet options', 'category': 'interface'},
        {'pattern': r'^set\s+interfaces\s+\S+\s+gigether-options\s+.+$', 'desc': 'Set gigabit ethernet options', 'category': 'interface'},
        {'pattern': r'^set\s+interfaces\s+\S+\s+aggregated-ether-options\s+.+$', 'desc': 'Set LAG options', 'category': 'interface'},
        {'pattern': r'^set\s+interfaces\s+\S+\s+vlan-id\s+\d+$', 'desc': 'Set interface VLAN ID', 'category': 'interface'},
        {'pattern': r'^set\s+vlans\s+\S+\s+vlan-id\s+\d+$', 'desc': 'Configure VLAN', 'category': 'switching'},
        {'pattern': r'^set\s+vlans\s+\S+\s+interface\s+\S+$', 'desc': 'Assign VLAN to interface', 'category': 'switching'},
        {'pattern': r'^set\s+vlans\s+\S+\s+description\s+\S+$', 'desc': 'Set VLAN description', 'category': 'switching'},
        {'pattern': r'^set\s+vlans\s+\S+\s+l3-interface\s+\S+$', 'desc': 'Set VLAN L3 interface', 'category': 'switching'},
        {'pattern': r'^set\s+policy-options\s+policy-statement\s+\S+\s+.+$', 'desc': 'Configure policy statement', 'category': 'routing'},
        {'pattern': r'^set\s+policy-options\s+prefix-list\s+\S+\s+.+$', 'desc': 'Configure prefix list', 'category': 'routing'},
        {'pattern': r'^set\s+security\s+.+$', 'desc': 'Configure security', 'category': 'security'},
        {'pattern': r'^set\s+chassis\s+.+$', 'desc': 'Configure chassis', 'category': 'system'},
        {'pattern': r'^set\s+class-of-service\s+.+$', 'desc': 'Configure CoS', 'category': 'system'},
        {'pattern': r'^set\s+system\s+domain-name\s+\S+$', 'desc': 'Set domain name', 'category': 'system'},
        {'pattern': r'^set\s+system\s+services\s+ftp\s+.+$', 'desc': 'Configure FTP service', 'category': 'system'},
        {'pattern': r'^set\s+system\s+services\s+netconf\s+.+$', 'desc': 'Configure NETCONF', 'category': 'system'},
        {'pattern': r'^set\s+system\s+login\s+user\s+\S+\s+.+$', 'desc': 'Configure login user', 'category': 'security'},
        {'pattern': r'^set\s+system\s+syslog\s+.+$', 'desc': 'Configure syslog', 'category': 'management'},
        {'pattern': r'^set\s+system\s+archival\s+.+$', 'desc': 'Configure archival', 'category': 'system'},
        {'pattern': r'^set\s+snmp\s+community\s+\S+\s+authorization\s+(read-only|read-write)$', 'desc': 'Configure SNMP community', 'category': 'management'},
        {'pattern': r'^set\s+snmp\s+location\s+\S+$', 'desc': 'Set SNMP location', 'category': 'management'},
        {'pattern': r'^set\s+snmp\s+contact\s+\S+$', 'desc': 'Set SNMP contact', 'category': 'management'},
        {'pattern': r'^set\s+groups\s+\S+\s+.+$', 'desc': 'Configure config groups', 'category': 'system'},
        {'pattern': r'^set\s+apply-groups\s+\S+$', 'desc': 'Apply config groups', 'category': 'system'},
        {'pattern': r'^delete\s+\S+', 'desc': 'Delete configuration', 'category': 'system'},
        {'pattern': r'^commit$', 'desc': 'Commit configuration', 'category': 'system'},
    ],
    'interface': [
        {'pattern': r'^set\s+interfaces\s+\S+\s+unit\s+\d+\s+family\s+inet\s+address\s+\d+\.\d+\.\d+\.\d+/\d+$', 'desc': 'Set interface IP with CIDR', 'category': 'interface'},
        {'pattern': r'^set\s+interfaces\s+\S+\s+unit\s+\d+\s+family\s+inet$', 'desc': 'Set interface family inet', 'category': 'interface'},
        {'pattern': r'^set\s+interfaces\s+\S+\s+unit\s+\d+\s+description\s+.+$', 'desc': 'Set interface description', 'category': 'interface'},
        {'pattern': r'^set\s+interfaces\s+\S+\s+enable$', 'desc': 'Enable interface', 'category': 'interface'},
        {'pattern': r'^set\s+interfaces\s+\S+\s+disable$', 'desc': 'Disable interface', 'category': 'interface'},
        {'pattern': r'^set\s+interfaces\s+\S+\s+mtu\s+\d+$', 'desc': 'Set interface MTU', 'category': 'interface'},
        {'pattern': r'^set\s+interfaces\s+\S+\s+speed\s+\S+$', 'desc': 'Set interface speed', 'category': 'interface'},
        {'pattern': r'^set\s+interfaces\s+\S+\s+ether-options\s+.+$', 'desc': 'Set ethernet options', 'category': 'interface'},
        {'pattern': r'^set\s+interfaces\s+\S+\s+gigether-options\s+.+$', 'desc': 'Set gigabit ethernet options', 'category': 'interface'},
        {'pattern': r'^set\s+interfaces\s+\S+\s+aggregated-ether-options\s+.+$', 'desc': 'Set LAG options', 'category': 'interface'},
        {'pattern': r'^set\s+interfaces\s+\S+\s+native-vlan-id\s+\d+$', 'desc': 'Set native VLAN ID', 'category': 'interface'},
        {'pattern': r'^set\s+interfaces\s+\S+\s+unit\s+\d+\s+family\s+inet\s+filter\s+.+$', 'desc': 'Apply firewall filter', 'category': 'interface'},
    ],
}

HUAWEI_COMMANDS = {
    'global': [
        {'pattern': r'^sysname\s+\S+$', 'desc': 'Set system name', 'category': 'system'},
        {'pattern': r'^clock\s+timezone\s+\S+', 'desc': 'Set timezone', 'category': 'system'},
        {'pattern': r'^aaa$', 'desc': 'Enter AAA view', 'category': 'security'},
        {'pattern': r'^local-user\s+\S+\s+password\s+(irreversible-cipher|cipher|simple)\s+\S+$', 'desc': 'Configure local user password', 'category': 'security'},
        {'pattern': r'^local-user\s+\S+\s+privilege\s+level\s+\d+$', 'desc': 'Configure local user privilege', 'category': 'security'},
        {'pattern': r'^local-user\s+\S+\s+service-type\s+.+$', 'desc': 'Configure local user service type', 'category': 'security'},
        {'pattern': r'^stelnet\s+server\s+enable$', 'desc': 'Enable secure Telnet/SSH server', 'category': 'security'},
        {'pattern': r'^ssh\s+user\s+\S+\s+.+$', 'desc': 'Configure SSH user', 'category': 'security'},
        {'pattern': r'^user-interface\s+vty\s+\d+\s+\d+$', 'desc': 'Enter VTY user interface', 'category': 'security'},
        {'pattern': r'^authentication-mode\s+(aaa|password)$', 'desc': 'Configure VTY authentication mode', 'category': 'security'},
        {'pattern': r'^protocol\s+inbound\s+.+$', 'desc': 'Configure inbound VTY protocols', 'category': 'security'},
        {'pattern': r'^ntp\s+server\s+\S+$', 'desc': 'Configure NTP', 'category': 'system'},
        {'pattern': r'^ntp-service\s+unicast-server\s+\S+$', 'desc': 'Configure NTP server', 'category': 'system'},
        {'pattern': r'^snmp-agent\s+community\s+\S+\s+(read|write)$', 'desc': 'Configure SNMP', 'category': 'management'},
        {'pattern': r'^snmp-agent\s+community\s+(read|write)\s+.+$', 'desc': 'Configure SNMP community', 'category': 'management'},
        {'pattern': r'^snmp-agent\s+sys-info\s+version\s+.+$', 'desc': 'Configure SNMP version', 'category': 'management'},
        {'pattern': r'^undo\s+telnet\s+server\s+enable$', 'desc': 'Disable Telnet server', 'category': 'security'},
        {'pattern': r'^ip\s+route-static\s+\d+\.\d+\.\d+\.\d+\s+\d+\.\d+\.\d+\.\d+\s+\S+$', 'desc': 'Configure static route', 'category': 'routing'},
        {'pattern': r'^ospf\s+\d+(\s+area\s+\d+)?$', 'desc': 'Enter OSPF process (optionally with area)', 'category': 'routing'},
        {'pattern': r'^ospf\s+\d+$', 'desc': 'Enter OSPF process', 'category': 'routing'},
        {'pattern': r'^area\s+\d+$', 'desc': 'Enter OSPF area', 'category': 'routing'},
        {'pattern': r'^vlan\s+\d+$', 'desc': 'Create VLAN', 'category': 'switching'},
        {'pattern': r'^acl\s+number\s+\d+$', 'desc': 'Create ACL', 'category': 'security'},
        {'pattern': r'^interface\s+\S+$', 'desc': 'Enter interface', 'category': 'interface'},
        {'pattern': r'^ip\s+address\s+\d+\.\d+\.\d+\.\d+\s+\d+\.\d+\.\d+\.\d+$', 'desc': 'Set IP address', 'category': 'interface'},
        {'pattern': r'^return$', 'desc': 'Return to user view', 'category': 'system'},
        {'pattern': r'^quit$', 'desc': 'Exit current view', 'category': 'system'},
        {'pattern': r'^save(?:\s+force)?$', 'desc': 'Save configuration', 'category': 'system'},
        {'pattern': r'^bgp\s+\d+$', 'desc': 'Enter BGP view', 'category': 'routing'},
        {'pattern': r'^rip\s+\d+$', 'desc': 'Enter RIP process', 'category': 'routing'},
        {'pattern': r'^version\s+2$', 'desc': 'Set RIP version 2', 'category': 'routing'},
        {'pattern': r'^undo\s+summary\s+automatic$', 'desc': 'Disable RIP auto-summary', 'category': 'routing'},
        {'pattern': r'^network\s+\d+\.\d+\.\d+\.\d+$', 'desc': 'RIP/OSPF network statement', 'category': 'routing'},
        {'pattern': r'^peer\s+\S+\s+as-number\s+\d+$', 'desc': 'Configure BGP peer', 'category': 'routing'},
        {'pattern': r'^peer\s+\S+\s+connect-interface\s+\S+$', 'desc': 'Set BGP peer connect interface', 'category': 'routing'},
        {'pattern': r'^peer\s+\S+\s+ebgp-max-hop\s+\d+$', 'desc': 'Set BGP peer max hop', 'category': 'routing'},
        {'pattern': r'^network\s+\d+\.\d+\.\d+\.\d+\s+\d+\.\d+\.\d+\.\d+$', 'desc': 'Advertise network in routing process', 'category': 'routing'},
        {'pattern': r'^import-route\s+(direct|static|ospf|bgp|rip)(\s+\d+)?$', 'desc': 'Import routes into routing process', 'category': 'routing'},
        {'pattern': r'^cost\s+\d+$', 'desc': 'Set OSPF cost', 'category': 'routing'},
        {'pattern': r'^preference\s+\d+$', 'desc': 'Set routing preference', 'category': 'routing'},
        {'pattern': r'^silent-interface\s+\S+$', 'desc': 'Suppress OSPF hello on interface', 'category': 'routing'},
        {'pattern': r'^vlan\s+batch\s+[\d\s]+$', 'desc': 'Create VLAN batch', 'category': 'switching'},
        {'pattern': r'^vlan\s+\d+\s+to\s+\d+$', 'desc': 'Create VLAN range', 'category': 'switching'},
        {'pattern': r'^stp\s+mode\s+\S+$', 'desc': 'Set STP mode', 'category': 'switching'},
        {'pattern': r'^stp\s+priority\s+\d+$', 'desc': 'Set STP priority', 'category': 'switching'},
        {'pattern': r'^stp\s+enable$', 'desc': 'Enable STP', 'category': 'switching'},
        {'pattern': r'^undo\s+stp\s+enable$', 'desc': 'Disable STP', 'category': 'switching'},
        {'pattern': r'^port\s+link-type\s+(access|trunk|hybrid)$', 'desc': 'Set port link type', 'category': 'switching'},
        {'pattern': r'^port\s+default\s+vlan\s+\d+$', 'desc': 'Set default VLAN', 'category': 'switching'},
        {'pattern': r'^port\s+trunk\s+allow-pass\s+vlan\s+.+$', 'desc': 'Set trunk allowed VLANs', 'category': 'switching'},
        {'pattern': r'^port\s+hybrid\s+tagged\s+vlan\s+.+$', 'desc': 'Set hybrid tagged VLANs', 'category': 'switching'},
        {'pattern': r'^port\s+hybrid\s+untagged\s+vlan\s+.+$', 'desc': 'Set hybrid untagged VLANs', 'category': 'switching'},
        {'pattern': r'^port\s+hybrid\s+pvid\s+vlan\s+\d+$', 'desc': 'Set hybrid PVID', 'category': 'switching'},
        {'pattern': r'^dhcp\s+enable$', 'desc': 'Enable DHCP globally', 'category': 'services'},
        {'pattern': r'^dhcp\s+select\s+(interface|global|relay)$', 'desc': 'Set DHCP mode', 'category': 'services'},
        {'pattern': r'^dns\s+list\s+\d+\.\d+\.\d+\.\d+$', 'desc': 'Set DNS server', 'category': 'services'},
        {'pattern': r'^ip\s+address\s+\d+\.\d+\.\d+\.\d+\s+\d+\.\d+\.\d+\.\d+\s+sub$', 'desc': 'Set secondary IP address', 'category': 'interface'},
        {'pattern': r'^speed\s+\S+$', 'desc': 'Set interface speed', 'category': 'interface'},
        {'pattern': r'^duplex\s+\S+$', 'desc': 'Set interface duplex', 'category': 'interface'},
        {'pattern': r'^mtu\s+\d+$', 'desc': 'Set interface MTU', 'category': 'interface'},
        {'pattern': r'^bandwidth\s+\d+$', 'desc': 'Set interface bandwidth', 'category': 'interface'},
        {'pattern': r'^ip\s+nat\s+(inside|outside)$', 'desc': 'Set NAT direction', 'category': 'services'},
        {'pattern': r'^ip\s+nat\s+server\s+.+$', 'desc': 'Configure NAT server', 'category': 'services'},
        {'pattern': r'^nat\s+static\s+.+$', 'desc': 'Configure static NAT', 'category': 'services'},
        {'pattern': r'^acl\s+number\s+\d+\s+match-order\s+\S+$', 'desc': 'Create ACL with match order', 'category': 'security'},
        {'pattern': r'^rule\s+\d+\s+(permit|deny)\s+.+$', 'desc': 'ACL rule', 'category': 'security'},
        {'pattern': r'^rule\s+(permit|deny)\s+.+$', 'desc': 'ACL rule', 'category': 'security'},
        {'pattern': r'^firewall\s+zone\s+\S+$', 'desc': 'Enter firewall zone', 'category': 'security'},
        {'pattern': r'^add\s+interface\s+\S+$', 'desc': 'Add interface to zone', 'category': 'security'},
        {'pattern': r'^zone-pair\s+security\s+.+$', 'desc': 'Configure zone-pair security', 'category': 'security'},
        {'pattern': r'^packet-filter\s+\d+\s+(inbound|outbound)$', 'desc': 'Apply packet filter', 'category': 'security'},
        {'pattern': r'^service-manage\s+.+$', 'desc': 'Configure service manage policy', 'category': 'security'},
        {'pattern': r'^ipsec\s+.+$', 'desc': 'Configure IPsec', 'category': 'security'},
        {'pattern': r'^ike\s+.+$', 'desc': 'Configure IKE', 'category': 'security'},
        {'pattern': r'^tunnel\s+.+$', 'desc': 'Configure tunnel', 'category': 'interface'},
        {'pattern': r'^source\s+\S+$', 'desc': 'Set tunnel source', 'category': 'interface'},
        {'pattern': r'^destination\s+\S+$', 'desc': 'Set tunnel destination', 'category': 'interface'},
        {'pattern': r'^ntp-service\s+.+$', 'desc': 'Configure NTP service', 'category': 'system'},
        {'pattern': r'^info-center\s+.+$', 'desc': 'Configure info center (logging)', 'category': 'management'},
        {'pattern': r'^syslog-server\s+.+$', 'desc': 'Configure syslog server', 'category': 'management'},
        {'pattern': r'^snmp-agent\s+.+$', 'desc': 'Configure SNMP agent', 'category': 'management'},
        {'pattern': r'^telnet\s+server\s+\S+$', 'desc': 'Configure telnet server', 'category': 'system'},
        {'pattern': r'^ssh\s+.+$', 'desc': 'Configure SSH', 'category': 'security'},
        {'pattern': r'^rsa\s+.+$', 'desc': 'Configure RSA', 'category': 'security'},
        {'pattern': r'^local-user\s+.+$', 'desc': 'Configure local user', 'category': 'security'},
        {'pattern': r'^authentication-mode\s+.+$', 'desc': 'Set authentication mode', 'category': 'security'},
        {'pattern': r'^protocol\s+inbound\s+.+$', 'desc': 'Set protocol inbound', 'category': 'security'},
        {'pattern': r'^user-interface\s+.+$', 'desc': 'Enter user interface', 'category': 'system'},
        {'pattern': r'^idle-timeout\s+\d+\s+\d+$', 'desc': 'Set idle timeout', 'category': 'security'},
        {'pattern': r'^history-command\s+max-size\s+\d+$', 'desc': 'Set history command size', 'category': 'system'},
        {'pattern': r'^super\s+password\s+.+$', 'desc': 'Set super password', 'category': 'security'},
        {'pattern': r'^set\s+authentication\s+password\s+.+$', 'desc': 'Set authentication password', 'category': 'security'},
        {'pattern': r'^command-privilege\s+level\s+\d+\s+.+$', 'desc': 'Set command privilege level', 'category': 'security'},
        {'pattern': r'^ip\s+vpn-instance\s+\S+$', 'desc': 'Create VPN instance', 'category': 'routing'},
        {'pattern': r'^ipv4-family$', 'desc': 'Enter IPv4 family', 'category': 'routing'},
        {'pattern': r'^route-distinguisher\s+\S+$', 'desc': 'Set route distinguisher', 'category': 'routing'},
        {'pattern': r'^vpn-target\s+\S+\s+(import|export|both)(?:\s+extcommunity)?$', 'desc': 'Set VPN target', 'category': 'routing'},
        {'pattern': r'^mpls$', 'desc': 'Enable MPLS', 'category': 'routing'},
        {'pattern': r'^mpls\s+ldp$', 'desc': 'Enable MPLS LDP', 'category': 'routing'},
        {'pattern': r'^mpls\s+ip\s+vpn-instance\s+\S+$', 'desc': 'Bind MPLS to VPN instance', 'category': 'routing'},
    ],
    'interface': [
        {'pattern': r'^interface\s+(GigabitEthernet|Ethernet|Vlanif|LoopBack|Tunnel|GE|XGE|MEth)\S*$', 'desc': 'Enter interface', 'category': 'interface'},
        {'pattern': r'^ip\s+address\s+\d+\.\d+\.\d+\.\d+\s+\d+\.\d+\.\d+\.\d+$', 'desc': 'Set IP address', 'category': 'interface'},
        {'pattern': r'^ip\s+address\s+\d+\.\d+\.\d+\.\d+\s+\d+\.\d+\.\d+\.\d+\s+sub$', 'desc': 'Set secondary IP address', 'category': 'interface'},
        {'pattern': r'^undo\s+shutdown$', 'desc': 'Enable interface', 'category': 'interface'},
        {'pattern': r'^shutdown$', 'desc': 'Disable interface', 'category': 'interface'},
        {'pattern': r'^description\s+.+$', 'desc': 'Set description', 'category': 'interface'},
        {'pattern': r'^port\s+link-type\s+(access|trunk|hybrid)$', 'desc': 'Set port link type', 'category': 'switching'},
        {'pattern': r'^port\s+default\s+vlan\s+\d+$', 'desc': 'Assign access VLAN', 'category': 'switching'},
        {'pattern': r'^port\s+trunk\s+allow-pass\s+vlan\s+.+$', 'desc': 'Set trunk allowed VLANs', 'category': 'switching'},
        {'pattern': r'^port\s+hybrid\s+.+$', 'desc': 'Configure hybrid port', 'category': 'switching'},
        # Port Security
        {'pattern': r'^port-security\s+enable$', 'desc': 'Enable port security', 'category': 'switching'},
        {'pattern': r'^port-security\s+max-mac-num\s+\d+$', 'desc': 'Set port security max MACs', 'category': 'switching'},
        {'pattern': r'^port-security\s+protect-action\s+(restrict|protect|shutdown)$', 'desc': 'Set port security violation action', 'category': 'switching'},
        {'pattern': r'^port-security\s+mac-address\s+sticky$', 'desc': 'Enable sticky MAC learning', 'category': 'switching'},
        {'pattern': r'^port-security\s+mac-address\s+\S+$', 'desc': 'Set static secure MAC', 'category': 'switching'},
        {'pattern': r'^speed\s+\S+$', 'desc': 'Set interface speed', 'category': 'interface'},
        {'pattern': r'^duplex\s+\S+$', 'desc': 'Set interface duplex', 'category': 'interface'},
        {'pattern': r'^mtu\s+\d+$', 'desc': 'Set interface MTU', 'category': 'interface'},
        {'pattern': r'^ip\s+nat\s+(inside|outside)$', 'desc': 'Set NAT direction', 'category': 'interface'},
        {'pattern': r'^dhcp\s+select\s+\S+$', 'desc': 'Set DHCP mode on interface', 'category': 'interface'},
        {'pattern': r'^ospf\s+cost\s+\d+$', 'desc': 'Set OSPF cost on interface', 'category': 'interface'},
        {'pattern': r'^ospf\s+network-type\s+\S+$', 'desc': 'Set OSPF network type', 'category': 'interface'},
        {'pattern': r'^ospf\s+authentication-mode\s+\S+$', 'desc': 'Set OSPF authentication', 'category': 'interface'},
        {'pattern': r'^mpls\s+enable$', 'desc': 'Enable MPLS on interface', 'category': 'interface'},
        {'pattern': r'^mpls\s+ldp\s+enable$', 'desc': 'Enable MPLS LDP on interface', 'category': 'interface'},
        {'pattern': r'^ip\s+binding\s+vpn-instance\s+\S+$', 'desc': 'Bind VPN instance to interface', 'category': 'interface'},
        {'pattern': r'^nat\s+static\s+.+$', 'desc': 'Configure static NAT on interface', 'category': 'interface'},
        {'pattern': r'^service-manage\s+.+$', 'desc': 'Configure service manage on interface', 'category': 'interface'},
        {'pattern': r'^dot1q\s+termination\s+vid\s+\S+$', 'desc': 'Configure dot1q termination', 'category': 'interface'},
        {'pattern': r'^arp\s+.+$', 'desc': 'Configure ARP', 'category': 'interface'},
    ],
}


# =============================================================================
# SHOW / DISPLAY COMMAND DATABASES (Operational / Diagnostic Commands)
# =============================================================================

CISCO_SHOW_COMMANDS = {
    'operational': [
        # === SHOW RUNNING / STARTUP ===
        {'pattern': r'^show\s+running-config(\s+.+)?$', 'desc': 'Show running configuration', 'category': 'show'},
        {'pattern': r'^show\s+startup-config(\s+.+)?$', 'desc': 'Show startup configuration', 'category': 'show'},
        {'pattern': r'^show\s+archive(\s+.+)?$', 'desc': 'Show configuration archive', 'category': 'show'},
        # === SHOW INTERFACES ===
        {'pattern': r'^show\s+interfaces(\s+.+)?$', 'desc': 'Show interface information', 'category': 'show'},
        {'pattern': r'^show\s+ip\s+interface(\s+.+)?$', 'desc': 'Show IP interface information', 'category': 'show'},
        {'pattern': r'^show\s+ip\s+interface\s+brief(\s+.+)?$', 'desc': 'Show IP interface brief', 'category': 'show'},
        {'pattern': r'^show\s+controllers(\s+.+)?$', 'desc': 'Show controller information', 'category': 'show'},
        {'pattern': r'^show\s+interfaces\s+status(\s+.+)?$', 'desc': 'Show interface status', 'category': 'show'},
        {'pattern': r'^show\s+interfaces\s+description(\s+.+)?$', 'desc': 'Show interface descriptions', 'category': 'show'},
        {'pattern': r'^show\s+interfaces\s+counters(\s+.+)?$', 'desc': 'Show interface counters', 'category': 'show'},
        {'pattern': r'^show\s+interfaces\s+switchport(\s+.+)?$', 'desc': 'Show switchport info', 'category': 'show'},
        {'pattern': r'^show\s+interfaces\s+trunk(\s+.+)?$', 'desc': 'Show trunk interfaces', 'category': 'show'},
        # === SHOW IP ROUTING ===
        {'pattern': r'^show\s+ip\s+route(\s+.+)?$', 'desc': 'Show IP routing table', 'category': 'show'},
        {'pattern': r'^show\s+ip\s+route\s+ospf(\s+.+)?$', 'desc': 'Show OSPF routes', 'category': 'show'},
        {'pattern': r'^show\s+ip\s+route\s+bgp(\s+.+)?$', 'desc': 'Show BGP routes', 'category': 'show'},
        {'pattern': r'^show\s+ip\s+route\s+eigrp(\s+.+)?$', 'desc': 'Show EIGRP routes', 'category': 'show'},
        {'pattern': r'^show\s+ip\s+route\s+rip(\s+.+)?$', 'desc': 'Show RIP routes', 'category': 'show'},
        {'pattern': r'^show\s+ip\s+route\s+static(\s+.+)?$', 'desc': 'Show static routes', 'category': 'show'},
        {'pattern': r'^show\s+ip\s+route\s+summary(\s+.+)?$', 'desc': 'Show route summary', 'category': 'show'},
        {'pattern': r'^show\s+ip\s+cef(\s+.+)?$', 'desc': 'Show CEF forwarding table', 'category': 'show'},
        # === SHOW OSPF ===
        {'pattern': r'^show\s+ip\s+ospf(\s+.+)?$', 'desc': 'Show OSPF information', 'category': 'show'},
        {'pattern': r'^show\s+ip\s+ospf\s+neighbor(\s+.+)?$', 'desc': 'Show OSPF neighbors', 'category': 'show'},
        {'pattern': r'^show\s+ip\s+ospf\s+database(\s+.+)?$', 'desc': 'Show OSPF database', 'category': 'show'},
        {'pattern': r'^show\s+ip\s+ospf\s+interface(\s+.+)?$', 'desc': 'Show OSPF interfaces', 'category': 'show'},
        {'pattern': r'^show\s+ip\s+ospf\s+border-routers(\s+.+)?$', 'desc': 'Show OSPF border routers', 'category': 'show'},
        # === SHOW BGP ===
        {'pattern': r'^show\s+ip\s+bgp(\s+.+)?$', 'desc': 'Show BGP information', 'category': 'show'},
        {'pattern': r'^show\s+ip\s+bgp\s+summary(\s+.+)?$', 'desc': 'Show BGP summary', 'category': 'show'},
        {'pattern': r'^show\s+ip\s+bgp\s+neighbors(\s+.+)?$', 'desc': 'Show BGP neighbors', 'category': 'show'},
        {'pattern': r'^show\s+ip\s+bgp\s+\d+\.\d+\.\d+\.\d+(\s+.+)?$', 'desc': 'Show BGP entry for prefix', 'category': 'show'},
        # === SHOW EIGRP ===
        {'pattern': r'^show\s+ip\s+eigrp(\s+.+)?$', 'desc': 'Show EIGRP information', 'category': 'show'},
        {'pattern': r'^show\s+ip\s+eigrp\s+neighbors(\s+.+)?$', 'desc': 'Show EIGRP neighbors', 'category': 'show'},
        {'pattern': r'^show\s+ip\s+eigrp\s+topology(\s+.+)?$', 'desc': 'Show EIGRP topology', 'category': 'show'},
        {'pattern': r'^show\s+ip\s+eigrp\s+interfaces(\s+.+)?$', 'desc': 'Show EIGRP interfaces', 'category': 'show'},
        # === SHOW VLAN ===
        {'pattern': r'^show\s+vlan(\s+.+)?$', 'desc': 'Show VLAN information', 'category': 'show'},
        {'pattern': r'^show\s+vlan\s+brief(\s+.+)?$', 'desc': 'Show VLAN brief', 'category': 'show'},
        {'pattern': r'^show\s+vtp\s+status(\s+.+)?$', 'desc': 'Show VTP status', 'category': 'show'},
        # === SHOW STP ===
        {'pattern': r'^show\s+spanning-tree(\s+.+)?$', 'desc': 'Show spanning tree info', 'category': 'show'},
        {'pattern': r'^show\s+spanning-tree\s+summary(\s+.+)?$', 'desc': 'Show STP summary', 'category': 'show'},
        # === SHOW CDP / LLDP ===
        {'pattern': r'^show\s+cdp(\s+.+)?$', 'desc': 'Show CDP information', 'category': 'show'},
        {'pattern': r'^show\s+cdp\s+neighbors(\s+.+)?$', 'desc': 'Show CDP neighbors', 'category': 'show'},
        {'pattern': r'^show\s+lldp(\s+.+)?$', 'desc': 'Show LLDP information', 'category': 'show'},
        {'pattern': r'^show\s+lldp\s+neighbors(\s+.+)?$', 'desc': 'Show LLDP neighbors', 'category': 'show'},
        # === SHOW ARP / MAC ===
        {'pattern': r'^show\s+arp(\s+.+)?$', 'desc': 'Show ARP table', 'category': 'show'},
        {'pattern': r'^show\s+mac-address-table(\s+.+)?$', 'desc': 'Show MAC address table', 'category': 'show'},
        {'pattern': r'^show\s+mac\s+address-table(\s+.+)?$', 'desc': 'Show MAC address table', 'category': 'show'},
        # === SHOW ACL ===
        {'pattern': r'^show\s+access-lists(\s+.+)?$', 'desc': 'Show access lists', 'category': 'show'},
        {'pattern': r'^show\s+ip\s+access-lists(\s+.+)?$', 'desc': 'Show IP access lists', 'category': 'show'},
        # === SHOW NAT ===
        {'pattern': r'^show\s+ip\s+nat\s+translations(\s+.+)?$', 'desc': 'Show NAT translations', 'category': 'show'},
        {'pattern': r'^show\s+ip\s+nat\s+statistics(\s+.+)?$', 'desc': 'Show NAT statistics', 'category': 'show'},
        # === SHOW SECURITY ===
        {'pattern': r'^show\s+crypto\s+.+$', 'desc': 'Show crypto information', 'category': 'show'},
        {'pattern': r'^show\s+ip\s+ssh(\s+.+)?$', 'desc': 'Show SSH status', 'category': 'show'},
        {'pattern': r'^show\s+ssh(\s+.+)?$', 'desc': 'Show SSH sessions', 'category': 'show'},
        {'pattern': r'^show\s+users(\s+.+)?$', 'desc': 'Show active users', 'category': 'show'},
        # === SHOW SYSTEM ===
        {'pattern': r'^show\s+version(\s+.+)?$', 'desc': 'Show system version', 'category': 'show'},
        {'pattern': r'^show\s+clock(\s+.+)?$', 'desc': 'Show system clock', 'category': 'show'},
        {'pattern': r'^show\s+ntp\s+status(\s+.+)?$', 'desc': 'Show NTP status', 'category': 'show'},
        {'pattern': r'^show\s+ntp\s+associations(\s+.+)?$', 'desc': 'Show NTP associations', 'category': 'show'},
        {'pattern': r'^show\s+logging(\s+.+)?$', 'desc': 'Show logging buffer', 'category': 'show'},
        {'pattern': r'^show\s+environment(\s+.+)?$', 'desc': 'Show environment status', 'category': 'show'},
        {'pattern': r'^show\s+process\s+cpu(\s+.+)?$', 'desc': 'Show CPU utilization', 'category': 'show'},
        {'pattern': r'^show\s+process\s+memory(\s+.+)?$', 'desc': 'Show memory utilization', 'category': 'show'},
        {'pattern': r'^show\s+memory(\s+.+)?$', 'desc': 'Show memory summary', 'category': 'show'},
        {'pattern': r'^show\s+flash(\s+.+)?$', 'desc': 'Show flash memory', 'category': 'show'},
        {'pattern': r'^show\s+redundancy(\s+.+)?$', 'desc': 'Show redundancy status', 'category': 'show'},
        {'pattern': r'^show\s+inventory(\s+.+)?$', 'desc': 'Show device inventory', 'category': 'show'},
        {'pattern': r'^show\s+tech-support(\s+.+)?$', 'desc': 'Show tech-support dump', 'category': 'show'},
        {'pattern': r'^show\s+diagnostic\s+.+$', 'desc': 'Show diagnostic information', 'category': 'show'},
        # === SHOW SNMP ===
        {'pattern': r'^show\s+snmp(\s+.+)?$', 'desc': 'Show SNMP status', 'category': 'show'},
        # === PING / TRACEROUTE ===
        {'pattern': r'^ping\s+\S+(\s+.+)?$', 'desc': 'Ping target', 'category': 'diagnostic'},
        {'pattern': r'^traceroute\s+\S+(\s+.+)?$', 'desc': 'Traceroute to target', 'category': 'diagnostic'},
        {'pattern': r'^telnet\s+\S+(\s+.+)?$', 'desc': 'Telnet to target', 'category': 'diagnostic'},
    ],
}

JUNIPER_SHOW_COMMANDS = {
    'operational': [
        # === SHOW CONFIGURATION ===
        {'pattern': r'^show\s+configuration(\s+.+)?$', 'desc': 'Show configuration', 'category': 'show'},
        {'pattern': r'^show\s+configuration\s+\|\s+.+$', 'desc': 'Show configuration with pipe', 'category': 'show'},
        # === SHOW INTERFACES ===
        {'pattern': r'^show\s+interfaces(\s+.+)?$', 'desc': 'Show interface information', 'category': 'show'},
        {'pattern': r'^show\s+interfaces\s+terse(\s+.+)?$', 'desc': 'Show interfaces terse', 'category': 'show'},
        {'pattern': r'^show\s+interfaces\s+extensive(\s+.+)?$', 'desc': 'Show interfaces extensive', 'category': 'show'},
        # === SHOW ROUTE ===
        {'pattern': r'^show\s+route(\s+.+)?$', 'desc': 'Show routing table', 'category': 'show'},
        {'pattern': r'^show\s+route\s+summary(\s+.+)?$', 'desc': 'Show route summary', 'category': 'show'},
        {'pattern': r'^show\s+route\s+forwarding-table(\s+.+)?$', 'desc': 'Show forwarding table', 'category': 'show'},
        # === SHOW PROTOCOLS ===
        {'pattern': r'^show\s+ospf(\s+.+)?$', 'desc': 'Show OSPF information', 'category': 'show'},
        {'pattern': r'^show\s+ospf\s+neighbor(\s+.+)?$', 'desc': 'Show OSPF neighbors', 'category': 'show'},
        {'pattern': r'^show\s+ospf\s+database(\s+.+)?$', 'desc': 'Show OSPF database', 'category': 'show'},
        {'pattern': r'^show\s+ospf\s+overview(\s+.+)?$', 'desc': 'Show OSPF overview', 'category': 'show'},
        {'pattern': r'^show\s+bgp\s+summary(\s+.+)?$', 'desc': 'Show BGP summary', 'category': 'show'},
        {'pattern': r'^show\s+bgp\s+neighbor(\s+.+)?$', 'desc': 'Show BGP neighbors', 'category': 'show'},
        # === SHOW SYSTEM ===
        {'pattern': r'^show\s+system\s+.+$', 'desc': 'Show system information', 'category': 'show'},
        {'pattern': r'^show\s+version(\s+.+)?$', 'desc': 'Show system version', 'category': 'show'},
        {'pattern': r'^show\s+chassis\s+.+$', 'desc': 'Show chassis information', 'category': 'show'},
        {'pattern': r'^show\s+log(\s+.+)?$', 'desc': 'Show log files', 'category': 'show'},
        # === SHOW SECURITY ===
        {'pattern': r'^show\s+security(\s+.+)?$', 'desc': 'Show security information', 'category': 'show'},
        {'pattern': r'^show\s+firewall(\s+.+)?$', 'desc': 'Show firewall filters', 'category': 'show'},
        {'pattern': r'^show\s+policer(\s+.+)?$', 'desc': 'Show policers', 'category': 'show'},
        # === SHOW VLAN / SWITCHING ===
        {'pattern': r'^show\s+vlans(\s+.+)?$', 'desc': 'Show VLANs', 'category': 'show'},
        {'pattern': r'^show\s+ethernet-switching\s+.+$', 'desc': 'Show ethernet switching', 'category': 'show'},
        {'pattern': r'^show\s+lldp\s+neighbors(\s+.+)?$', 'desc': 'Show LLDP neighbors', 'category': 'show'},
        # === SHOW SNMP ===
        {'pattern': r'^show\s+snmp(\s+.+)?$', 'desc': 'Show SNMP status', 'category': 'show'},
        # === SHOW NTP ===
        {'pattern': r'^show\s+ntp\s+.+$', 'desc': 'Show NTP status', 'category': 'show'},
        # === PING / TRACEROUTE ===
        {'pattern': r'^ping\s+\S+(\s+.+)?$', 'desc': 'Ping target', 'category': 'diagnostic'},
        {'pattern': r'^traceroute\s+\S+(\s+.+)?$', 'desc': 'Traceroute to target', 'category': 'diagnostic'},
        # === OPERATIONAL MODE ===
        {'pattern': r'^show\s+\S+(\s+.+)?$', 'desc': 'Show operational information', 'category': 'show'},
    ],
}

HUAWEI_DISPLAY_COMMANDS = {
    'operational': [
        # === DISPLAY CURRENT CONFIGURATION ===
        {'pattern': r'^display\s+current-configuration(\s+.+)?$', 'desc': 'Show current configuration', 'category': 'display'},
        {'pattern': r'^display\s+saved-configuration(\s+.+)?$', 'desc': 'Show saved configuration', 'category': 'display'},
        # === DISPLAY INTERFACES ===
        {'pattern': r'^display\s+interface(\s+.+)?$', 'desc': 'Show interface information', 'category': 'display'},
        {'pattern': r'^display\s+interface\s+brief(\s+.+)?$', 'desc': 'Show interface brief', 'category': 'display'},
        {'pattern': r'^display\s+ip\s+interface\s+brief(\s+.+)?$', 'desc': 'Show IP interface brief', 'category': 'display'},
        # === DISPLAY ROUTING ===
        {'pattern': r'^display\s+ip\s+routing-table(\s+.+)?$', 'desc': 'Show IP routing table', 'category': 'display'},
        {'pattern': r'^display\s+ip\s+routing-table\s+protocol\s+\S+(\s+.+)?$', 'desc': 'Show protocol-specific routes', 'category': 'display'},
        # === DISPLAY OSPF ===
        {'pattern': r'^display\s+ospf(\s+.+)?$', 'desc': 'Show OSPF information', 'category': 'display'},
        {'pattern': r'^display\s+ospf\s+peer(\s+.+)?$', 'desc': 'Show OSPF peers', 'category': 'display'},
        {'pattern': r'^display\s+ospf\s+lsdb(\s+.+)?$', 'desc': 'Show OSPF LSDB', 'category': 'display'},
        {'pattern': r'^display\s+ospf\s+interface(\s+.+)?$', 'desc': 'Show OSPF interfaces', 'category': 'display'},
        # === DISPLAY BGP ===
        {'pattern': r'^display\s+bgp\s+peer(\s+.+)?$', 'desc': 'Show BGP peers', 'category': 'display'},
        {'pattern': r'^display\s+bgp\s+routing-table(\s+.+)?$', 'desc': 'Show BGP routing table', 'category': 'display'},
        {'pattern': r'^display\s+bgp\s+\S+(\s+.+)?$', 'desc': 'Show BGP information', 'category': 'display'},
        # === DISPLAY VLAN ===
        {'pattern': r'^display\s+vlan(\s+.+)?$', 'desc': 'Show VLAN information', 'category': 'display'},
        {'pattern': r'^display\s+vlan\s+verbose(\s+.+)?$', 'desc': 'Show VLAN verbose', 'category': 'display'},
        # === DISPLAY STP ===
        {'pattern': r'^display\s+stp(\s+.+)?$', 'desc': 'Show STP information', 'category': 'display'},
        {'pattern': r'^display\s+stp\s+brief(\s+.+)?$', 'desc': 'Show STP brief', 'category': 'display'},
        # === DISPLAY ARP / MAC ===
        {'pattern': r'^display\s+arp(\s+.+)?$', 'desc': 'Show ARP table', 'category': 'display'},
        {'pattern': r'^display\s+mac-address(\s+.+)?$', 'desc': 'Show MAC address table', 'category': 'display'},
        # === DISPLAY ACL ===
        {'pattern': r'^display\s+acl(\s+.+)?$', 'desc': 'Show ACL information', 'category': 'display'},
        # === DISPLAY NAT ===
        {'pattern': r'^display\s+nat\s+.+$', 'desc': 'Show NAT information', 'category': 'display'},
        # === DISPLAY SYSTEM ===
        {'pattern': r'^display\s+version(\s+.+)?$', 'desc': 'Show system version', 'category': 'display'},
        {'pattern': r'^display\s+device(\s+.+)?$', 'desc': 'Show device information', 'category': 'display'},
        {'pattern': r'^display\s+clock(\s+.+)?$', 'desc': 'Show system clock', 'category': 'display'},
        {'pattern': r'^display\s+cpu-usage(\s+.+)?$', 'desc': 'Show CPU usage', 'category': 'display'},
        {'pattern': r'^display\s+memory(\s+.+)?$', 'desc': 'Show memory usage', 'category': 'display'},
        {'pattern': r'^display\s+logbuffer(\s+.+)?$', 'desc': 'Show log buffer', 'category': 'display'},
        {'pattern': r'^display\s+health(\s+.+)?$', 'desc': 'Show system health', 'category': 'display'},
        {'pattern': r'^display\s+alarm(\s+.+)?$', 'desc': 'Show alarms', 'category': 'display'},
        # === DISPLAY SECURITY ===
        {'pattern': r'^display\s+ssh\s+.+$', 'desc': 'Show SSH information', 'category': 'display'},
        {'pattern': r'^display\s+users(\s+.+)?$', 'desc': 'Show logged-in users', 'category': 'display'},
        # === DISPLAY SNMP ===
        {'pattern': r'^display\s+snmp-agent(\s+.+)?$', 'desc': 'Show SNMP agent info', 'category': 'display'},
        # === DISPLAY NTP ===
        {'pattern': r'^display\s+ntp-service(\s+.+)?$', 'desc': 'Show NTP service status', 'category': 'display'},
        {'pattern': r'^display\s+ntp\s+session(\s+.+)?$', 'desc': 'Show NTP sessions', 'category': 'display'},
        # === DISPLAY LLDP ===
        {'pattern': r'^display\s+lldp\s+neighbor(\s+.+)?$', 'desc': 'Show LLDP neighbors', 'category': 'display'},
        # === DISPLAY MPLS ===
        {'pattern': r'^display\s+mpls\s+.+$', 'desc': 'Show MPLS information', 'category': 'display'},
        # === DISPLAY VPN ===
        {'pattern': r'^display\s+ip\s+vpn-instance(\s+.+)?$', 'desc': 'Show VPN instances', 'category': 'display'},
        # === PING / TRACERT ===
        {'pattern': r'^ping\s+\S+(\s+.+)?$', 'desc': 'Ping target', 'category': 'diagnostic'},
        {'pattern': r'^tracert\s+\S+(\s+.+)?$', 'desc': 'Traceroute to target', 'category': 'diagnostic'},
        {'pattern': r'^telnet\s+\S+(\s+.+)?$', 'desc': 'Telnet to target', 'category': 'diagnostic'},
        # === CATCH-ALL ===
        {'pattern': r'^display\s+\S+(\s+.+)?$', 'desc': 'Show operational information', 'category': 'display'},
    ],
}

# NOTE: Comprehensive error fixes are imported from comprehensive_error_fixes.py
# The ERROR_FIXES variable below is kept for backward compatibility but not used
_error_fixes_old = {
    'cisco': [
        # === IP Address Fixes ===
        {
            'check': lambda line: bool(re.match(r'^\s*ip\s+address\s+\d+\.\d+\.\d+\.\d+\s*$', line, re.IGNORECASE)),
            'error': 'Missing subnet mask in IP address',
            'fix': lambda line: line.strip() + ' 255.255.255.0',
            'severity': 'error',
            'source': 'Cisco IOS Configuration Guide',
        },
        {
            'check': lambda line: bool(re.match(r'^\s*ip\s+address\s+\d+\.\d+\.\d+\.\d+\s+\d+\.\d+\.\d+\.\d+.*secondary\s*$', line, re.IGNORECASE)),
            'error': 'Secondary IP address syntax error',
            'fix': lambda line: line.strip().replace(' secondary', '').replace('Secondary', '') + ' secondary',
            'severity': 'error',
            'source': 'Cisco IOS IP Addressing Guide',
        },
        
        # === Interface Fixes ===
        {
            'check': lambda line: 'no shut' in line.lower() and 'no shutdown' not in line.lower(),
            'error': 'Abbreviated command may not be accepted in config mode',
            'fix': lambda line: re.sub(r'(?i)no\s+shut', 'no shutdown', line),
            'severity': 'error',
            'source': 'Cisco IOS Command Reference',
        },
        {
            'check': lambda line: bool(re.match(r'^\s*shutdown\s*$', line, re.IGNORECASE)),
            'error': 'Interface is administratively shut down',
            'fix': lambda line: 'no shutdown',
            'severity': 'warning',
            'source': 'Cisco Interface Configuration Guide',
        },
        {
            'check': lambda line: bool(re.match(r'^\s*description\s*$', line, re.IGNORECASE)),
            'error': 'Interface description is missing text',
            'fix': lambda line: line.strip() + ' Configured by Network Sentinel',
            'severity': 'warning',
            'source': 'Cisco Best Practices',
        },
        {
            'check': lambda line: bool(re.match(r'^\s*speed\s*$', line, re.IGNORECASE)),
            'error': 'Interface speed not specified',
            'fix': lambda line: line.strip() + ' 1000',
            'severity': 'warning',
            'source': 'Cisco Interface Configuration Guide',
        },
        {
            'check': lambda line: bool(re.match(r'^\s*duplex\s*$', line, re.IGNORECASE)),
            'error': 'Duplex mode not specified',
            'fix': lambda line: line.strip() + ' full',
            'severity': 'warning',
            'source': 'Cisco Interface Configuration Guide',
        },
        
        # === Hostname Fixes ===
        {
            'check': lambda line: bool(re.match(r'^\s*hostname\s*$', line, re.IGNORECASE)),
            'error': 'Hostname command missing device name',
            'fix': lambda line: line.strip() + ' Router',
            'severity': 'error',
            'source': 'Cisco Configuration Guide',
        },
        
        # === OSPF Fixes ===
        {
            'check': lambda line: bool(re.match(r'^\s*router\s+ospf\s*$', line, re.IGNORECASE)),
            'error': 'OSPF router configuration missing process ID',
            'fix': lambda line: line.strip() + ' 1',
            'severity': 'error',
            'source': 'Cisco OSPF Configuration Guide',
        },
        {
            'check': lambda line: bool(re.match(r'^\s*network\s+\d+\.\d+\.\d+\.\d+\s*$', line, re.IGNORECASE)),
            'error': 'OSPF network statement missing wildcard mask',
            'fix': lambda line: line.strip() + ' 0.0.0.255 area 0',
            'severity': 'error',
            'source': 'Cisco OSPF Configuration Guide',
        },
        {
            'check': lambda line: bool(re.match(r'^\s*network\s+\d+\.\d+\.\d+\.\d+\s+\d+\.\d+\.\d+\.\d+\s*$', line, re.IGNORECASE)),
            'error': 'OSPF network statement missing area ID',
            'fix': lambda line: line.strip() + ' area 0',
            'severity': 'error',
            'source': 'Cisco OSPF Configuration Guide',
        },
        {
            'check': lambda line: bool(re.match(r'^\s*router-id\s*$', line, re.IGNORECASE)),
            'error': 'OSPF router-id not specified',
            'fix': lambda line: line.strip() + ' 1.1.1.1',
            'severity': 'warning',
            'source': 'Cisco OSPF Configuration Guide',
        },
        
        # === EIGRP Fixes ===
        {
            'check': lambda line: bool(re.match(r'^\s*router\s+eigrp\s*$', line, re.IGNORECASE)),
            'error': 'EIGRP router configuration missing AS number',
            'fix': lambda line: line.strip() + ' 100',
            'severity': 'error',
            'source': 'Cisco EIGRP Configuration Guide',
        },
        {
            'check': lambda line: bool(re.match(r'^\s*router\s+eigrp\s+\d+\s*$', line, re.IGNORECASE)),
            'error': None,  # Valid, just tracking
            'fix': None,
            'severity': 'info',
            'source': 'Cisco EIGRP Configuration Guide',
        },
        
        # === BGP Fixes ===
        {
            'check': lambda line: bool(re.match(r'^\s*router\s+bgp\s*$', line, re.IGNORECASE)),
            'error': 'BGP router configuration missing AS number',
            'fix': lambda line: line.strip() + ' 65001',
            'severity': 'error',
            'source': 'Cisco BGP Configuration Guide',
        },
        {
            'check': lambda line: bool(re.match(r'^\s*neighbor\s+\d+\.\d+\.\d+\.\d+\s*$', line, re.IGNORECASE)),
            'error': 'BGP neighbor missing remote-as',
            'fix': lambda line: line.strip() + ' remote-as 65002',
            'severity': 'error',
            'source': 'Cisco BGP Configuration Guide',
        },
        
        # === VLAN Fixes ===
        {
            'check': lambda line: bool(re.match(r'^\s*vlan\s*$', line, re.IGNORECASE)),
            'error': 'VLAN command missing VLAN ID',
            'fix': lambda line: line.strip() + ' 10',
            'severity': 'error',
            'source': 'Cisco VLAN Configuration Guide',
        },
        {
            'check': lambda line: bool(re.match(r'^\s*name\s*$', line, re.IGNORECASE)) and 'vlan' in line.lower(),
            'error': 'VLAN name not specified',
            'fix': lambda line: line.strip() + ' VLAN10',
            'severity': 'warning',
            'source': 'Cisco VLAN Configuration Guide',
        },
        
        # === Switchport Fixes ===
        {
            'check': lambda line: bool(re.match(r'^\s*switchport\s+mode\s*$', line, re.IGNORECASE)),
            'error': 'Switchport mode not specified',
            'fix': lambda line: line.strip() + ' access',
            'severity': 'warning',
            'source': 'Cisco Switchport Configuration Guide',
        },
        {
            'check': lambda line: bool(re.match(r'^\s*switchport\s+access\s+vlan\s*$', line, re.IGNORECASE)),
            'error': 'Access VLAN not specified',
            'fix': lambda line: line.strip() + ' 1',
            'severity': 'error',
            'source': 'Cisco Switchport Configuration Guide',
        },
        {
            'check': lambda line: bool(re.match(r'^\s*switchport\s+trunk\s+encapsulation\s*$', line, re.IGNORECASE)),
            'error': 'Trunk encapsulation not specified',
            'fix': lambda line: line.strip() + ' dot1q',
            'severity': 'warning',
            'source': 'Cisco Switchport Configuration Guide',
        },
        
        # === ACL Fixes ===
        {
            'check': lambda line: bool(re.match(r'^\s*access-list\s+\d+\s+(permit|deny)\s+\d+\.\d+\.\d+\.\d+\s*$', line, re.IGNORECASE)),
            'error': 'ACL missing wildcard mask',
            'fix': lambda line: re.sub(r'(\d+\.\d+\.\d+\.\d+)\s*$', r'\1 0.0.0.255', line),
            'severity': 'error',
            'source': 'Cisco ACL Configuration Guide',
        },
        
        # === SNMP Fixes ===
        {
            'check': lambda line: bool(re.match(r'^\s*snmp-server\s+community\s+\S+\s*$', line, re.IGNORECASE)),
            'error': 'SNMP community missing access level (RO/RW)',
            'fix': lambda line: line.strip() + ' RO',
            'severity': 'warning',
            'source': 'Cisco SNMP Configuration Guide',
        },
        {
            'check': lambda line: bool(re.match(r'^\s*snmp-server\s+community\s*$', line, re.IGNORECASE)),
            'error': 'SNMP community string not specified',
            'fix': lambda line: line.strip() + ' public RO',
            'severity': 'error',
            'source': 'Cisco SNMP Configuration Guide',
        },
        
        # === Line (Console/VTY) Fixes ===
        {
            'check': lambda line: bool(re.match(r'^\s*line\s+(console|vty|aux)\s+\d+\s*$', line, re.IGNORECASE)) and 'password' not in line.lower(),
            'error': 'Line configuration missing password',
            'fix': lambda line: line.strip() + '\n password cisco123\n login',
            'severity': 'error',
            'source': 'Cisco Line Configuration Guide',
        },
        
        # === Security Fixes ===
        {
            'check': lambda line: bool(re.match(r'^\s*crypto\s+key\s+generate\s+rsa\s*$', line, re.IGNORECASE)),
            'error': 'RSA key generation missing modulus size',
            'fix': lambda line: line.strip() + ' modulus 2048',
            'severity': 'warning',
            'source': 'Cisco Security Configuration Guide',
        },
        {
            'check': lambda line: bool(re.match(r'^\s*enable\s+password\s*$', line, re.IGNORECASE)),
            'error': 'Enable password not specified',
            'fix': lambda line: line.strip() + ' cisco123',
            'severity': 'error',
            'source': 'Cisco Security Configuration Guide',
        },
        {
            'check': lambda line: bool(re.match(r'^\s*service\s+password-encryption\s*$', line, re.IGNORECASE)),
            'error': None,
            'fix': None,
            'severity': 'info',
            'source': 'Cisco Security Best Practices',
        },
    ],
    'juniper': [
        {
            'check': lambda line: bool(re.match(r'^\s*set\s+interfaces\s+\S+\s+unit\s+\d+\s+family\s+inet\s+address\s+\d+\.\d+\.\d+\.\d+\s*$', line, re.IGNORECASE)),
            'error': 'IP address missing CIDR prefix length',
            'fix': lambda line: line.strip() + '/24',
            'severity': 'error',
            'source': 'Juniper Junos OS Documentation',
        },
        {
            'check': lambda line: bool(re.match(r'^\s*set\s+snmp\s+community\s+\S+\s*$', line, re.IGNORECASE)),
            'error': 'SNMP community missing authorization',
            'fix': lambda line: line.strip() + ' authorization read-only',
            'severity': 'warning',
            'source': 'Juniper Junos OS Documentation',
        },
    ],
    'huawei': [
        {
            'check': lambda line: bool(re.match(r'^\s*ip\s+address\s+\d+\.\d+\.\d+\.\d+\s*$', line, re.IGNORECASE)),
            'error': 'IP address missing subnet mask',
            'fix': lambda line: line.strip() + ' 255.255.255.0',
            'severity': 'error',
            'source': 'Huawei VRP Configuration Guide',
        },
        {
            'check': lambda line: bool(re.match(r'^\s*undo\s+shutdown\s*$', line, re.IGNORECASE)),
            'error': None,
            'fix': None,
            'severity': 'info',
            'source': 'Huawei VRP Interface Guide',
        },
    ],
}


def detect_vendor(config_text):
    """Auto-detect the vendor based on config syntax."""
    lines = [l.strip() for l in config_text.splitlines() if l.strip()]

    juniper_score = 0
    cisco_score = 0
    huawei_score = 0

    for line in lines:
        if line.startswith('set '):
            juniper_score += 2
        if line.startswith('delete '):
            juniper_score += 2
        if line.startswith('sysname '):
            huawei_score += 3
        if line.startswith('undo '):
            huawei_score += 2
        if 'GigabitEthernet' in line and 'Vlanif' not in line:
            cisco_score += 1
        if 'Vlanif' in line:
            huawei_score += 2
        if re.match(r'^interface\s+(GigabitEthernet|FastEthernet)', line):
            cisco_score += 1
        if re.match(r'^router\s+ospf', line):
            cisco_score += 2
        if re.match(r'^ospf\s+\d+\s+area', line):
            huawei_score += 2
        if line.startswith('hostname '):
            cisco_score += 2
        if 'commit' in line:
            juniper_score += 2
        if line.startswith('spanning-tree') or line.startswith('switchport'):
            cisco_score += 2
        if line.startswith('port ') and ('link-type' in line or 'default' in line or 'trunk' in line):
            huawei_score += 2
        if 'snmp-server' in line:
            cisco_score += 1
        if 'snmp-agent' in line:
            huawei_score += 1
        if 'save' == line.strip():
            huawei_score += 1

    scores = {'cisco': cisco_score, 'juniper': juniper_score, 'huawei': huawei_score}
    best = max(scores, key=scores.get)
    if scores[best] == 0:
        return 'cisco'  # default
    return best


def validate_ip_address(ip_str):
    """Validate an IP address using netutils (preferred) or stdlib."""
    return _cv_is_ip(ip_str)


def validate_subnet_mask(mask_str):
    """Validate a subnet mask using netutils (preferred) or manual check."""
    return _cv_is_netmask(mask_str)


def validate_cidr(cidr_str):
    """Validate CIDR notation (e.g., /24)."""
    try:
        if '/' not in cidr_str:
            return False
        ipaddress.ip_network(cidr_str, strict=False)
        return True
    except ValueError:
        return False


def dedupe_preserving_order(items):
    """Return unique items while keeping the first occurrence order."""
    seen = set()
    unique_items = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        unique_items.append(item)
    return unique_items


def detect_device_type(config_text):
    """Automatically detect device type from config content."""
    config_lower = config_text.lower()
    
    # Switch indicators
    switch_patterns = [
        r'switchport',
        r'switching-mode',
        r'vlan\s+\d+',
        r'spanning-tree',
        r'interface\s+vlan',
        r'interface\s+fastethernet',
        r'interface\s+gigabitethernet',
        r'ip\s+default-gateway',
        r'mls\s+qos',
        r'mac-address-table',
    ]
    
    # Firewall indicators
    firewall_patterns = [
        r'firewall',
        r'access-list\s+\d+',
        r'zone-pair',
        r'zone\s+security',
        r'ips\s+signature',
        r'utm',
        r'anti-virus',
        r'intrusion',
        r'security-level',
        r'nameif',
        r'same-security-traffic',
    ]
    
    # Router indicators
    router_patterns = [
        r'router\s+(ospf|eigrp|bgp|rip)',
        r'interface\s+serial',
        r'interface\s+tunnel',
        r'ip\s+route\s+\d',
        r'subinterface',
        r'nat\s+\(inside',
        r'crypto\s+map',
        r'ipsec',
    ]
    
    # Count matches
    switch_score = sum(1 for pattern in switch_patterns if re.search(pattern, config_lower))
    firewall_score = sum(1 for pattern in firewall_patterns if re.search(pattern, config_lower))
    router_score = sum(1 for pattern in router_patterns if re.search(pattern, config_lower))
    
    # Return type with highest score
    if firewall_score > switch_score and firewall_score > router_score:
        return 'firewall'
    elif switch_score > router_score:
        return 'switch'
    else:
        return 'router'


def _parse_config_no_semantic(text, vendor='auto', device_type='router'):
    """Lightweight re-parse for post-fix verification (no semantic checks)."""
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    errors = []
    detected_vendor = detect_vendor(text) if vendor == 'auto' else vendor
    cmd_db = {}
    if detected_vendor == 'juniper':
        cmd_db = dict(JUNIPER_COMMANDS)
        for s, cmds in JUNIPER_SHOW_COMMANDS.items():
            cmd_db.setdefault(s, [])
            cmd_db[s] += cmds
        error_db = ERROR_FIXES.get('juniper', [])
    elif detected_vendor == 'huawei':
        cmd_db = dict(HUAWEI_COMMANDS)
        for s, cmds in HUAWEI_DISPLAY_COMMANDS.items():
            cmd_db.setdefault(s, [])
            cmd_db[s] += cmds
        error_db = ERROR_FIXES.get('huawei', [])
    else:
        cmd_db = dict(CISCO_COMMANDS)
        for s, cmds in CISCO_SHOW_COMMANDS.items():
            cmd_db.setdefault(s, [])
            cmd_db[s] += cmds
        error_db = ERROR_FIXES.get('cisco', [])
    for i, line in enumerate(lines, 1):
        if line.startswith('!') or line.startswith('#') or line.startswith('//'):
            continue
        normalized = normalize_config_line(line, detected_vendor)
        validation_line = normalized
        is_valid = False
        is_error = False
        line_errors = []
        for fix_rule in error_db:
            try:
                if fix_rule['check'](validation_line):
                    if fix_rule.get('error'):
                        if fix_rule['severity'] == 'error':
                            line_errors.append(fix_rule['error'])
                            is_error = True
            except Exception:
                pass
        for section, commands in cmd_db.items():
            for cmd in commands:
                if re.match(cmd['pattern'], validation_line, re.IGNORECASE):
                    is_valid = True
                    if cmd.get('error') and not line_errors:
                        line_errors.append(cmd.get('desc', 'Syntax error'))
                        is_error = True
                    break
            if is_valid:
                break
        if not is_valid and not is_error:
            line_errors.append(f'Unknown command (line {i}): {line}')
            is_error = True
        errors.extend([f'Line {i}: {e}' for e in line_errors])
    return {'error_count': len(errors), 'errors': errors}


def parse_network_config(text, vendor='auto'):
    """
    Advanced network configuration parser with comprehensive pattern matching.
    Validates commands, detects errors, suggests fixes, and outputs ready-to-apply config.
    Supports multi-vendor configs by detecting vendor per section.
    """
    # Auto-detect device type
    device_type = detect_device_type(text)
    
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    errors = []
    warnings = []
    suggestions = []
    ready_lines = []
    valid_lines = []
    context_stack = []
    requested_vendor = vendor
    vendors_detected = set()
    has_device_markers = False

    for line in lines:
        if CONFIG_BLOCK_MARKER_RE.match(line):
            has_device_markers = True
        if line.startswith('set '):
            vendors_detected.add('juniper')
        if line.startswith('sysname '):
            vendors_detected.add('huawei')
        if line.startswith('undo '):
            vendors_detected.add('huawei')
        if re.match(r'^(hostname|router\s+ospf|switchport|spanning-tree|no\s+shutdown)\b', line):
            vendors_detected.add('cisco')
        if line.startswith('snmp-server'):
            vendors_detected.add('cisco')
        if line.startswith('snmp-agent'):
            vendors_detected.add('huawei')

    detected_vendor = detect_vendor(text)

    # For multi-vendor support, merge all command databases
    # and try matching against all vendors
    use_multi_vendor = has_device_markers or len(vendors_detected) > 1

    # Vendor priority:
    # 1. Device markers present (multi-vendor config) -> always use auto-detect per block
    # 2. Manual selection (from UI dropdown) -> always wins over auto-detect
    # 3. vendor='auto' -> auto-detect applies
    if has_device_markers:
        # Multi-vendor config with explicit markers: use auto-detect regardless of user selection
        vendor = detected_vendor
    elif vendor == 'auto':
        vendor = detected_vendor

    # Select command database
    if use_multi_vendor:
        # Merge all vendor databases for multi-vendor config
        cmd_db = {}
        for section in set(list(CISCO_COMMANDS.keys()) + list(JUNIPER_COMMANDS.keys()) + list(HUAWEI_COMMANDS.keys())):
            cmd_db[section] = CISCO_COMMANDS.get(section, []) + JUNIPER_COMMANDS.get(section, []) + HUAWEI_COMMANDS.get(section, [])
        # Add show/display operational commands from all vendors
        for section in set(list(CISCO_SHOW_COMMANDS.keys()) + list(JUNIPER_SHOW_COMMANDS.keys()) + list(HUAWEI_DISPLAY_COMMANDS.keys())):
            cmd_db.setdefault(section, [])
            cmd_db[section] += CISCO_SHOW_COMMANDS.get(section, []) + JUNIPER_SHOW_COMMANDS.get(section, []) + HUAWEI_DISPLAY_COMMANDS.get(section, [])
        error_db = ERROR_FIXES.get('cisco', []) + ERROR_FIXES.get('juniper', []) + ERROR_FIXES.get('huawei', [])
    elif vendor == 'juniper':
        cmd_db = dict(JUNIPER_COMMANDS)
        for section, commands in JUNIPER_SHOW_COMMANDS.items():
            cmd_db.setdefault(section, [])
            cmd_db[section] += commands
        error_db = ERROR_FIXES.get('juniper', [])
    elif vendor == 'huawei':
        cmd_db = dict(HUAWEI_COMMANDS)
        for section, commands in HUAWEI_DISPLAY_COMMANDS.items():
            cmd_db.setdefault(section, [])
            cmd_db[section] += commands
        error_db = ERROR_FIXES.get('huawei', [])
    else:
        cmd_db = dict(CISCO_COMMANDS)
        for section, commands in CISCO_SHOW_COMMANDS.items():
            cmd_db.setdefault(section, [])
            cmd_db[section] += commands
        error_db = ERROR_FIXES.get('cisco', [])

    # ===========================================================
    # CONTEXT-AWARE STATE MACHINE: Initialize mode
    # ===========================================================
    current_mode = 'GLOBAL'

    for i, line in enumerate(lines):
        line_num = i + 1
        is_valid = False
        is_error = False
        line_errors = []
        line_warnings = []
        line_fixes = []
        validation_line = line

        # Skip comments
        if line.startswith('!') or line.startswith('#') or line.startswith('//'):
            ready_lines.append(line)
            valid_lines.append({'line': line, 'num': line_num, 'valid': True, 'category': 'comment', 'errors': [], 'warnings': [], 'fixes': []})
            continue

        # ===========================================================
        # CONTEXT-AWARE STATE MACHINE: Mode Transition
        # ===========================================================
        next_mode, is_temporary = _detect_mode_transition(line, current_mode, vendor)
        if is_temporary:
            # For MONITORING mode, validate but don't change current_mode
            effective_mode = 'MONITORING'
        else:
            current_mode = next_mode
            effective_mode = current_mode

        normalized_line = normalize_config_line(line, vendor)
        if normalized_line != line:
            validation_line = normalized_line
            line_fixes.append(normalized_line)

        # ===========================================================
        # STATE-MACHINE AWARE: Smart fix for network statements
        # ===========================================================
        if effective_mode in ('ROUTER_RIP', 'ROUTER_OSPF'):
            mode_fixed = _smart_fix_network_for_mode(validation_line, effective_mode, vendor)
            if mode_fixed != validation_line:
                line_fixes.append(mode_fixed)
                validation_line = mode_fixed

        # Check against error/fix database first (SMART AUTO-FIX)
        applied_fixes = []
        for fix_rule in error_db:
            try:
                if fix_rule['check'](validation_line):
                    has_fix = fix_rule.get('fix') is not None
                    if fix_rule.get('context_check'):
                        # Context-aware checks - need to look at surrounding lines
                        if fix_rule['error']:
                            if fix_rule['severity'] == 'error':
                                line_errors.append(fix_rule['error'])
                                is_error = True
                            else:
                                line_warnings.append(fix_rule['error'])
                    else:
                        if fix_rule['error']:
                            if has_fix:
                                # Auto-fixable: apply fix silently, don't count as blocking error
                                if fix_rule['severity'] == 'error':
                                    line_warnings.append(fix_rule['error'] + ' (auto-fixed)')
                                else:
                                    line_warnings.append(fix_rule['error'])
                            elif fix_rule['severity'] == 'error':
                                line_errors.append(fix_rule['error'])
                                is_error = True
                            else:
                                line_warnings.append(fix_rule['error'])
                        if has_fix:
                            fixed_line = fix_rule['fix'](validation_line)
                            if fixed_line not in applied_fixes:
                                line_fixes.append(fixed_line)
                                applied_fixes.append(fixed_line)
                                print(f"[AUTO-FIX] Line {line_num}: {validation_line} -> {fixed_line}")
            except Exception as e:
                print(f"[AUTO-FIX ERROR] Line {line_num}: {str(e)}")

        # Validate against known commands
        for section, commands in cmd_db.items():
            for cmd in commands:
                if re.match(cmd['pattern'], validation_line, re.IGNORECASE):
                    is_valid = True
                    # Only add cmd-db error if error_db hasn't already flagged this line
                    if cmd.get('error') and not line_errors:
                        line_errors.append(cmd.get('desc', 'Syntax error'))
                        is_error = True
                    break
            if is_valid:
                break

        # ===========================================================
        # STATE-MACHINE AWARE: Validate in current mode
        # Also accept MONITORING commands as valid
        # ===========================================================
        if not is_valid and not is_error:
            if _validate_in_mode(validation_line, effective_mode, vendor):
                is_valid = True

        # Additional contextual validations for Cisco (or multi-vendor)
        if vendor == 'cisco' or use_multi_vendor:
            # Check IP address validity
            ip_match = re.search(r'ip\s+address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)', validation_line)
            if ip_match:
                ip, mask = ip_match.group(1), ip_match.group(2)
                if not validate_ip_address(ip):
                    line_errors.append(f'Invalid IP address: {ip}')
                    is_error = True
                if not validate_subnet_mask(mask):
                    line_errors.append(f'Invalid subnet mask: {mask}')
                    is_error = True

            # Check for network statement with invalid IP
            net_match = re.match(r'^network\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)', validation_line)
            if net_match:
                ip, wc = net_match.group(1), net_match.group(2)
                if not validate_ip_address(ip):
                    line_errors.append(f'Invalid network address: {ip}')
                    is_error = True

            # Check for OSPF without network statements following
            if re.match(r'^router\s+ospf\s+\d+$', validation_line):
                context_stack.append(('ospf', line_num))

            # Track interface context
            if re.match(r'^interface\s+\S+', validation_line):
                context_stack.append(('interface', line_num))

        # Additional contextual validations for Juniper
        if vendor == 'juniper' or use_multi_vendor:
            cidr_match = re.search(r'address\s+(\d+\.\d+\.\d+\.\d+/\d+)', validation_line)
            if cidr_match:
                cidr = cidr_match.group(1)
                if not validate_cidr(cidr):
                    line_warnings.append(f'Invalid CIDR notation: {cidr}')

        # Additional contextual validations for Huawei
        if vendor == 'huawei' or use_multi_vendor:
            ip_match = re.search(r'ip\s+address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)', validation_line)
            if ip_match:
                ip, mask = ip_match.group(1), ip_match.group(2)
                if not validate_ip_address(ip):
                    line_errors.append(f'Invalid IP address: {ip}')
                    is_error = True

        # If not recognized at all
        if not is_valid and not is_error:
            # Try partial match for helpful suggestions
            partial_match = None
            for section, commands in cmd_db.items():
                for cmd in commands:
                    cmd_start = cmd['pattern'][:20].replace(r'^', '').replace(r'\s+', ' ')
                    if validation_line[:20].lower().startswith(cmd_start[:20].lower()):
                        partial_match = cmd['desc']
                        break
                if partial_match:
                    break

            line_errors.append(f'Unknown or unsupported command (line {line_num}): {line}')
            if partial_match:
                line_fixes.append(f'# Did you mean: {partial_match}?')
            else:
                line_fixes.append(f'# Check syntax for: {line}')
            is_error = True

        line_errors = dedupe_preserving_order(line_errors)
        line_warnings = dedupe_preserving_order(line_warnings)
        line_fixes = dedupe_preserving_order(line_fixes)

        # Build result for this line
        line_result = {
            'line': line,
            'num': line_num,
            'valid': not is_error,
            'category': 'unknown',
            'errors': line_errors,
            'warnings': line_warnings,
            'fixes': line_fixes,
            'has_fix': len([f for f in line_fixes if not f.startswith('#')]) > 0,
            'mode': effective_mode,
        }

        # Determine category
        for section, commands in cmd_db.items():
            for cmd in commands:
                if re.match(cmd['pattern'], validation_line, re.IGNORECASE):
                    line_result['category'] = cmd.get('category', 'unknown')
                    break

        valid_lines.append(line_result)

        # CRITICAL: Apply actual fixes to the output config
        actual_fixes = [fix for fix in line_fixes if not fix.startswith('#')]
        if actual_fixes:
            # Use the LAST fix (most recent/most complete)
            ready_lines.append(actual_fixes[-1])
        else:
            ready_lines.append(line)

        errors.extend([f'Line {line_num}: {e}' for e in line_errors])
        warnings.extend([f'Line {line_num}: {w}' for w in line_warnings])
        suggestions.extend([fix for fix in line_fixes if not fix.startswith('#')])

    # Build analysis summary
    total = len(lines)
    error_count = len(errors)
    warning_count = len(warnings)

    if error_count == 0 and warning_count == 0:
        analysis = f'All {total} command(s) are valid. Configuration is ready to apply to device.'
    elif error_count > 0:
        analysis = f'Found {error_count} error(s) and {warning_count} warning(s) in {total} command(s). Fix errors before applying.'
    else:
        analysis = f'Found {warning_count} warning(s) in {total} command(s). Review before applying.'

    # Build ready-to-apply config
    ready_config = '\n'.join(ready_lines)

    # Build corrected config (with fixes applied)
    corrected_lines = []
    fix_count = 0
    for vl in valid_lines:
        if vl['fixes']:
            actual_fixes = [fix for fix in vl['fixes'] if not fix.startswith('#')]
            if actual_fixes:
                corrected_lines.append(actual_fixes[-1])
                fix_count += 1
            else:
                corrected_lines.append(vl['line'])
        else:
            corrected_lines.append(vl['line'])
    corrected_config = '\n'.join(corrected_lines)

    # Calculate accuracy percentage AFTER fixes
    if total > 0:
        # Count lines that are valid AFTER applying fixes
        total_valid_after_fixes = 0
        for vl in valid_lines:
            has_fix = vl.get('has_fix', False)
            has_errors = bool(vl.get('errors'))
            # A line counts as valid if:
            # - It originally had no errors, OR
            # - It had errors BUT has a fix applied (the fix resolves the error)
            if not has_errors or has_fix:
                total_valid_after_fixes += 1
        accuracy = round((total_valid_after_fixes / total) * 100, 1)
    else:
        accuracy = 100.0

    # ------------------------------------------------------------------
    # SEMANTIC VALIDATION (cross-line checks using ciscoconfparse+netutils)
    # ------------------------------------------------------------------
    semantic_errors = []
    error_categories = {}
    try:
        semantic_errors = ConfigValidator.run_semantic_checks(lines, vendor)
        if semantic_errors:
            for err in semantic_errors:
                cat = err.get('category', 'general')
                sev = err.get('severity', 'error')
                error_categories[cat] = error_categories.get(cat, 0) + 1
                line_prefix = ''
                if err.get('line_numbers') and err['line_numbers'][0] is not None:
                    line_prefix = f'Line {err["line_numbers"][0]}: '
                formatted = f'{line_prefix}{err["message"]}'
                if sev in ('error', 'critical'):
                    errors.append(formatted)
                    error_count += 1
                elif sev == 'warning':
                    warnings.append(formatted)
                    warning_count += 1
    except Exception as exc:
        print(f'[SEMANTIC] Validation skipped: {exc}')

    # ------------------------------------------------------------------
    # POST-FIX VERIFICATION (re-parse corrected config to confirm fixes)
    # ------------------------------------------------------------------
    unresolved_errors = []
    fix_confidence = 'verified' if fix_count > 0 else 'none'
    if corrected_config and corrected_config != ready_config and fix_count > 0:
        try:
            # Re-parse the corrected config (without recursion)
            corrected_check = _parse_config_no_semantic(
                corrected_config, vendor=vendor, device_type=device_type,
            )
            remaining = corrected_check.get('error_count', 0)
            if remaining > 0:
                fix_confidence = 'partial'
                unresolved_errors = corrected_check.get('errors', [])[:5]  # cap at 5
            else:
                fix_confidence = 'verified'
        except Exception:
            fix_confidence = 'unverified'

    return {
        'lines': lines,
        'total_lines': total,
        'vendor': vendor,
        'device_type': device_type,
        'multi_vendor': use_multi_vendor,
        'errors': errors,
        'warnings': warnings,
        'suggestions': suggestions,
        'ready': ready_config,
        'corrected': corrected_config,
        'analysis': analysis,
        'error_count': error_count,
        'warning_count': warning_count,
        'fix_count': fix_count,
        'auto_fixed': fix_count > 0,
        'accuracy': accuracy,
        'valid_lines': valid_lines,
        'line_details': valid_lines,
        'semantic_errors': semantic_errors,
        'error_categories': error_categories,
        'fix_confidence': fix_confidence,
        'unresolved_errors': unresolved_errors,
    }


def summarize_config_risk(result):
    """Turn parser output into a small operational risk summary."""
    error_count = int(result.get('error_count', 0))
    warning_count = int(result.get('warning_count', 0))
    fix_count = int(result.get('fix_count', 0))
    total_lines = int(result.get('total_lines', 0))
    
    # If auto-fix was applied, count fixed errors as resolved
    resolved_errors = min(error_count, fix_count)
    remaining_errors = error_count - resolved_errors
    
    # Calculate risk based on REMAINING errors (after fixes)
    risk_score = min(100, remaining_errors * 35 + warning_count * 12)
    safety_score = max(0, 100 - risk_score)

    # If auto-fix was applied and corrected the config, don't block
    has_fixes = fix_count > 0 or result.get('auto_fixed', False)
    
    if remaining_errors and not has_fixes:
        state = 'blocked'
        label = 'Blocked'
        message = 'Fix blocking errors before lab testing or deployment.'
    elif remaining_errors and has_fixes:
        # Auto-fix will handle these
        state = 'warning'
        label = 'Warning - Auto-fixing'
        message = f'Errors detected but auto-fix will correct {fix_count} issue(s). Review the fixes before continuing.'
    elif warning_count:
        state = 'warning'
        label = 'Warning'
        message = 'Review warnings and suggested fixes before continuing.'
    else:
        state = 'safe'
        label = 'Safe'
        message = 'No blocking issues found. Review the diff and snapshot before testing.'

    return {
        'state': state,
        'label': label,
        'score': safety_score,
        'risk_score': risk_score,
        'total_lines': total_lines,
        'error_count': error_count,
        'warning_count': warning_count,
        'message': message,
        'can_lab_test': state != 'blocked',
    }


def _issue_explanation(issue, severity):
    issue_lower = issue.lower()
    if 'subnet mask' in issue_lower or 'cidr' in issue_lower:
        return 'The device may reject the address or place the interface in the wrong network.'
    if 'unknown or unsupported command' in issue_lower:
        return 'Unsupported syntax should be checked before it is copied into a lab or device.'
    if 'snmp' in issue_lower:
        return 'Management access should be explicit so weak or incomplete monitoring settings do not slip through.'
    if severity == 'error':
        return 'This can block a safe deployment until the command is corrected.'
    if severity == 'warning':
        return 'This is not always blocking, but it deserves review before testing.'
    return 'Review this suggested change before using the corrected configuration.'


def build_fix_review(result):
    """Build reviewable fix items from line-level parser output."""
    review_items = []
    for line in result.get('line_details', []):
        actual_fixes = [fix for fix in line.get('fixes', []) if not fix.startswith('#')]
        actual_fix = actual_fixes[-1] if actual_fixes else None
        if not actual_fix or actual_fix == line.get('line'):
            continue

        errors = line.get('errors', [])
        warnings = line.get('warnings', [])
        if errors:
            severity = 'error'
            issue = errors[0]
        elif warnings:
            severity = 'warning'
            issue = warnings[0]
        else:
            severity = 'info'
            issue = 'Suggested syntax correction'

        review_items.append({
            'line_number': line.get('num'),
            'severity': severity,
            'issue': issue,
            'why_it_matters': _issue_explanation(issue, severity),
            'original_line': line.get('line', ''),
            'suggested_line': actual_fix,
        })
    return review_items


def build_config_diff(original_config, corrected_config):
    """Return a compact line-based diff for template rendering."""
    original_lines = original_config.splitlines()
    corrected_lines = corrected_config.splitlines()
    matcher = difflib.SequenceMatcher(None, original_lines, corrected_lines)
    diff = []

    for tag, old_start, old_end, new_start, new_end in matcher.get_opcodes():
        if tag == 'equal':
            for offset, line in enumerate(original_lines[old_start:old_end]):
                diff.append({
                    'type': 'unchanged',
                    'old_line': old_start + offset + 1,
                    'new_line': new_start + offset + 1,
                    'original': line,
                    'corrected': line,
                })
        elif tag == 'delete':
            for offset, line in enumerate(original_lines[old_start:old_end]):
                diff.append({
                    'type': 'removed',
                    'old_line': old_start + offset + 1,
                    'new_line': None,
                    'original': line,
                    'corrected': '',
                })
        elif tag == 'insert':
            for offset, line in enumerate(corrected_lines[new_start:new_end]):
                diff.append({
                    'type': 'added',
                    'old_line': None,
                    'new_line': new_start + offset + 1,
                    'original': '',
                    'corrected': line,
                })
        elif tag == 'replace':
            old_chunk = original_lines[old_start:old_end]
            new_chunk = corrected_lines[new_start:new_end]
            max_len = max(len(old_chunk), len(new_chunk))
            for offset in range(max_len):
                old_line = old_chunk[offset] if offset < len(old_chunk) else ''
                new_line = new_chunk[offset] if offset < len(new_chunk) else ''
                if old_line and new_line:
                    entry_type = 'changed'
                elif old_line:
                    entry_type = 'removed'
                else:
                    entry_type = 'added'
                diff.append({
                    'type': entry_type,
                    'old_line': old_start + offset + 1 if old_line else None,
                    'new_line': new_start + offset + 1 if new_line else None,
                    'original': old_line,
                    'corrected': new_line,
                })

    return diff


SECURITY_BASELINE_RULES = {
    'cisco': [
        {
            'id': 'cisco_enable_secret',
            'severity': 'required',
            'category': 'passwords',
            'title': 'Enable secret is configured',
            'why': 'Protects privileged mode with a hashed secret instead of a weak plain password.',
            'patterns': [r'^enable\s+secret\s+\S+'],
            'command': 'enable secret ChangeMe123!',
        },
        {
            'id': 'cisco_password_encryption',
            'severity': 'recommended',
            'category': 'passwords',
            'title': 'Password encryption is enabled',
            'why': 'Prevents plain-text line passwords from being displayed in the saved config.',
            'patterns': [r'^service\s+password-encryption$'],
            'command': 'service password-encryption',
        },
        {
            'id': 'cisco_no_domain_lookup',
            'severity': 'recommended',
            'category': 'operations',
            'title': 'DNS lookup is disabled for mistyped CLI commands',
            'why': 'Avoids long CLI delays when an operator mistypes a command.',
            'patterns': [r'^no\s+ip\s+domain-lookup$'],
            'command': 'no ip domain-lookup',
        },
        {
            'id': 'cisco_domain_name',
            'severity': 'recommended',
            'category': 'ssh',
            'title': 'Domain name exists for SSH keys',
            'why': 'Cisco SSH key generation expects a domain name on many IOS images.',
            'patterns': [r'^ip\s+domain-name\s+\S+'],
            'command': 'ip domain-name example.local',
        },
        {
            'id': 'cisco_local_user',
            'severity': 'required',
            'category': 'aaa',
            'title': 'Local admin user uses secret',
            'why': 'VTY login should authenticate against an explicit local user.',
            'patterns': [r'^username\s+\S+\s+secret\s+\S+'],
            'command': 'username admin secret ChangeMe123!',
        },
        {
            'id': 'cisco_ssh_key',
            'severity': 'recommended',
            'category': 'ssh',
            'title': 'RSA key generation is configured',
            'why': 'SSH needs device keys before remote secure access can work.',
            'patterns': [r'^crypto\s+key\s+generate\s+rsa'],
            'command': 'crypto key generate rsa modulus 2048',
        },
        {
            'id': 'cisco_ssh_v2',
            'severity': 'required',
            'category': 'ssh',
            'title': 'SSH version 2 is enforced',
            'why': 'SSH v2 avoids legacy SSH protocol behavior.',
            'patterns': [r'^ip\s+ssh\s+version\s+2$'],
            'command': 'ip ssh version 2',
        },
        {
            'id': 'cisco_vty_login_local',
            'severity': 'required',
            'category': 'remote-access',
            'title': 'VTY uses local login',
            'why': 'Remote access should not rely on a shared line password only.',
            'patterns': [r'^login\s+local$'],
            'command': 'line vty 0 4\nlogin local',
        },
        {
            'id': 'cisco_vty_ssh_only',
            'severity': 'required',
            'category': 'remote-access',
            'title': 'VTY allows SSH only',
            'why': 'Telnet sends credentials in clear text and should not be the default remote path.',
            'patterns': [r'^transport\s+input\s+ssh$'],
            'command': 'line vty 0 4\ntransport input ssh',
        },
        {
            'id': 'cisco_ntp',
            'severity': 'recommended',
            'category': 'time',
            'title': 'NTP server is configured',
            'why': 'Accurate time makes logs, alerts, and audits trustworthy.',
            'patterns': [r'^ntp\s+server\s+\S+'],
            'command': 'ntp server 10.0.0.10',
        },
    ],
    'huawei': [
        {
            'id': 'huawei_sysname',
            'severity': 'required',
            'category': 'system',
            'title': 'System name is configured',
            'why': 'A clear sysname makes inventory and troubleshooting reliable.',
            'patterns': [r'^sysname\s+\S+'],
            'command': 'sysname HW-DEVICE',
        },
        {
            'id': 'huawei_aaa',
            'severity': 'required',
            'category': 'aaa',
            'title': 'AAA view is configured',
            'why': 'AAA is the foundation for secure local and remote authentication.',
            'patterns': [r'^aaa$'],
            'command': 'aaa',
        },
        {
            'id': 'huawei_local_user',
            'severity': 'required',
            'category': 'aaa',
            'title': 'Local SSH admin user exists',
            'why': 'Remote management should authenticate against a named local user.',
            'patterns': [r'^local-user\s+\S+\s+password\s+(irreversible-cipher|cipher|simple)\s+\S+'],
            'command': 'local-user admin password irreversible-cipher ChangeMe123!\nlocal-user admin privilege level 15\nlocal-user admin service-type ssh',
        },
        {
            'id': 'huawei_stelnet',
            'severity': 'required',
            'category': 'ssh',
            'title': 'STelnet server is enabled',
            'why': 'Secure remote access needs SSH/STelnet rather than telnet-only access.',
            'patterns': [r'^stelnet\s+server\s+enable$'],
            'command': 'stelnet server enable',
        },
        {
            'id': 'huawei_vty_ssh',
            'severity': 'required',
            'category': 'remote-access',
            'title': 'VTY accepts SSH with AAA',
            'why': 'VTY access should use AAA and avoid telnet-only management.',
            'patterns': [r'^protocol\s+inbound\s+ssh$'],
            'command': 'user-interface vty 0 4\nauthentication-mode aaa\nprotocol inbound ssh',
        },
        {
            'id': 'huawei_ntp',
            'severity': 'recommended',
            'category': 'time',
            'title': 'NTP service is configured',
            'why': 'Reliable timestamps matter for logs, audits, and incident review.',
            'patterns': [r'^ntp-service\s+unicast-server\s+\S+'],
            'command': 'ntp-service unicast-server 10.0.0.10',
        },
    ],
    'juniper': [
        {
            'id': 'juniper_hostname',
            'severity': 'required',
            'category': 'system',
            'title': 'Host name is configured',
            'why': 'A clear hostname keeps inventory and operational output understandable.',
            'patterns': [r'^set\s+system\s+host-name\s+\S+'],
            'command': 'set system host-name JUNIPER-DEVICE',
        },
        {
            'id': 'juniper_root_auth',
            'severity': 'required',
            'category': 'aaa',
            'title': 'Root authentication exists',
            'why': 'JunOS requires explicit authentication before the device is production-ready.',
            'patterns': [r'^set\s+system\s+root-authentication\s+.+'],
            'command': 'set system root-authentication plain-text-password',
        },
        {
            'id': 'juniper_ssh',
            'severity': 'required',
            'category': 'ssh',
            'title': 'SSH service is enabled',
            'why': 'SSH provides secure remote management.',
            'patterns': [r'^set\s+system\s+services\s+ssh'],
            'command': 'set system services ssh protocol-version v2',
        },
        {
            'id': 'juniper_ntp',
            'severity': 'recommended',
            'category': 'time',
            'title': 'NTP server is configured',
            'why': 'Accurate device time is required for useful logs and audits.',
            'patterns': [r'^set\s+system\s+ntp\s+server\s+\S+'],
            'command': 'set system ntp server 10.0.0.10',
        },
    ],
}


SECURITY_TEMPLATES = {
    'cisco': {
        'name': 'Secure Cisco Base',
        'description': 'Base IOS hardening for SSH management, local login, password protection, and NTP.',
    },
    'huawei': {
        'name': 'Huawei Secure Base',
        'description': 'Base VRP hardening for AAA, STelnet, SSH-only VTY, and NTP.',
    },
    'juniper': {
        'name': 'Juniper Secure Base',
        'description': 'Base JunOS hardening for host identity, authentication, SSH, and NTP.',
    },
}


def _config_has_pattern(config_text, pattern):
    return bool(re.search(pattern, config_text, re.IGNORECASE | re.MULTILINE))


def _command_line_exists(config_lines, command_line):
    normalized_command = command_line.strip().lower()
    return any(line.strip().lower() == normalized_command for line in config_lines)


def review_security_baseline(config_text, vendor='auto', device_type='router'):
    """Find missing built-in security baseline commands for a config."""
    detected_vendor = detect_vendor(config_text) if vendor == 'auto' else vendor
    rules = SECURITY_BASELINE_RULES.get(detected_vendor, [])
    present = []
    missing = []

    for rule in rules:
        item = {
            'id': rule['id'],
            'vendor': detected_vendor,
            'device_type': device_type or 'router',
            'severity': rule['severity'],
            'category': rule['category'],
            'title': rule['title'],
            'why': rule['why'],
            'command': rule['command'],
            'default_include': rule['severity'] in ('required', 'recommended'),
        }
        if any(_config_has_pattern(config_text, pattern) for pattern in rule['patterns']):
            present.append(item)
        else:
            missing.append(item)

    total = len(rules)
    score = 100 if total == 0 else round((len(present) / total) * 100)
    default_rule_ids = [item['id'] for item in missing if item['default_include']]

    return {
        'vendor': detected_vendor,
        'device_type': device_type or 'router',
        'template': get_security_templates(detected_vendor, device_type)[0] if detected_vendor in SECURITY_TEMPLATES else None,
        'present': present,
        'missing': missing,
        'default_rule_ids': default_rule_ids,
        'score': score,
        'state': 'secure' if not missing else 'needs_hardening',
    }


def build_security_reviewed_config(config_text, security_review, selected_rule_ids=None):
    """Append selected missing baseline commands without duplicating existing lines."""
    selected = set(selected_rule_ids or security_review.get('default_rule_ids', []))
    config_lines = config_text.splitlines()
    output_lines = list(config_lines)

    for item in security_review.get('missing', []):
        if item['id'] not in selected:
            continue
        for command_line in item['command'].splitlines():
            stripped = command_line.strip()
            if stripped and not _command_line_exists(output_lines, stripped):
                output_lines.append(stripped)

    return '\n'.join(output_lines).strip()


def get_security_templates(vendor='auto', device_type=None):
    """Return built-in secure base template metadata for the selected vendor."""
    if vendor == 'auto':
        vendors = list(SECURITY_TEMPLATES.keys())
    else:
        vendors = [vendor] if vendor in SECURITY_TEMPLATES else []

    templates = []
    for item_vendor in vendors:
        template = dict(SECURITY_TEMPLATES[item_vendor])
        template['vendor'] = item_vendor
        template['device_type'] = device_type or 'router'
        template['commands'] = [
            rule['command']
            for rule in SECURITY_BASELINE_RULES.get(item_vendor, [])
            if rule['severity'] in ('required', 'recommended')
        ]
        templates.append(template)
    return templates


def generate_device_config(vendor, device_type, hostname, interfaces=None, routing=None):
    """Generate a baseline configuration template for a device."""
    interfaces = interfaces or []
    routing = routing or {}

    if vendor == 'cisco':
        config_lines = [
            f'hostname {hostname}',
            'enable secret class',
            'no ip domain-lookup',
            'service password-encryption',
            'ip routing',
        ]
        for iface in interfaces:
            config_lines.append(f'interface {iface["name"]}')
            if iface.get('ip'):
                config_lines.append(f'ip address {iface["ip"]} {iface.get("mask", "255.255.255.0")}')
            config_lines.append('no shutdown')
            if iface.get('description'):
                config_lines.append(f'description {iface["description"]}')
        if routing.get('ospf'):
            config_lines.append(f'router ospf {routing["ospf"]["process_id"]}')
            for net in routing['ospf'].get('networks', []):
                config_lines.append(f'network {net["network"]} {net["wildcard"]} area {net["area"]}')
        config_lines.append('end')
        config_lines.append('write memory')
        return '\n'.join(config_lines)

    elif vendor == 'juniper':
        config_lines = [f'set system host-name {hostname}']
        for iface in interfaces:
            config_lines.append(f'set interfaces {iface["name"]} unit 0 family inet address {iface["ip"]}/{iface.get("prefix", "24")}')
            if iface.get('description'):
                config_lines.append(f'set interfaces {iface["name"]} unit 0 description "{iface["description"]}"')
        if routing.get('ospf'):
            for net in routing['ospf'].get('networks', []):
                config_lines.append(f'set protocols ospf area {net["area"]} interface {net["interface"]}')
        config_lines.append('commit')
        return '\n'.join(config_lines)

    elif vendor == 'huawei':
        config_lines = [f'sysname {hostname}']
        for iface in interfaces:
            config_lines.append(f'interface {iface["name"]}')
            if iface.get('ip'):
                config_lines.append(f'ip address {iface["ip"]} {iface.get("mask", "255.255.255.0")}')
            config_lines.append('undo shutdown')
            if iface.get('description'):
                config_lines.append(f'description {iface["description"]}')
        if routing.get('ospf'):
            config_lines.append(f'ospf {routing["ospf"]["process_id"]}')
            for net in routing['ospf'].get('networks', []):
                config_lines.append(f'network {net["network"]} {net.get("wildcard", "0.0.0.255")} area {net["area"]}')
        config_lines.append('return')
        config_lines.append('save')
        return '\n'.join(config_lines)

    return '# Unsupported vendor'
