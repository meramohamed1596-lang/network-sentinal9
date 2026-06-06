# ==========================================
# SEMANTIC CONFIG VALIDATION ENGINE
# Cross-line validation using ciscoconfparse + netutils
# Supports Cisco IOS, Huawei VRP, Juniper JunOS
# ==========================================
import re
import ipaddress
import logging

logger = logging.getLogger(__name__)

# Use trusted libraries
try:
    from ciscoconfparse import CiscoConfParse
    HAS_CISCOCONFPARSE = True
except ImportError:
    HAS_CISCOCONFPARSE = False
    logger.warning("ciscoconfparse not available; Cisco hierarchical parsing disabled.")

try:
    from netutils.ip import is_ip as _nu_is_ip, is_netmask as _nu_is_netmask
    HAS_NETUTILS = True
except ImportError:
    HAS_NETUTILS = False
    logger.warning("netutils not available; falling back to stdlib IP validation.")


# ---------------------------------------------------------------------------
# Helpers – use netutils when available, fall back to ipaddress stdlib
# ---------------------------------------------------------------------------

def is_valid_ip(ip_str):
    """Validate an IPv4 address using netutils (preferred) or stdlib."""
    ip_str = ip_str.strip()
    if HAS_NETUTILS:
        return _nu_is_ip(ip_str)
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def is_valid_netmask(mask_str):
    """Validate a contiguous subnet mask using netutils or manual check."""
    mask_str = mask_str.strip()
    if HAS_NETUTILS:
        return _nu_is_netmask(mask_str)
    try:
        mask_int = int(ipaddress.IPv4Address(mask_str))
        if mask_int == 0:
            return True
        binary = bin(mask_int)[2:].zfill(32)
        return '01' not in binary
    except ValueError:
        return False


def to_network(ip_str, mask_str):
    """Return an ipaddress.IPv4Network from IP + mask (non-strict)."""
    try:
        return ipaddress.IPv4Network(f'{ip_str}/{mask_str}', strict=False)
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------------------
# ValidationError data structure
# ---------------------------------------------------------------------------

def make_error(line_numbers, error_type, message, severity, fix=None,
               confidence='high', category='general', vendor='auto'):
    """Build a standardised validation error dict."""
    return {
        'line_numbers': line_numbers if isinstance(line_numbers, list) else [line_numbers],
        'error_type': error_type,       # syntax | semantic | security | compliance
        'message': message,
        'severity': severity,           # critical | error | warning | info
        'fix': fix,                     # corrected line text, or None
        'confidence': confidence,       # high | medium | low
        'category': category,           # ip_address | routing | switching | security | interface | management
        'vendor': vendor,
    }


# ===================================================================
#  Cisco IOS Validator  (uses ciscoconfparse)
# ===================================================================

class CiscoValidator:
    """Semantic validator for Cisco IOS / IOS-XE configs."""

    # Section header patterns that start a new indentation level
    _SECTION_RE = re.compile(
        r'^(interface\s|router\s|vlan\s+\d|ip\s+access-list|line\s|'
        r'router\s+ospf|router\s+bgp|router\s+eigrp|class-map|policy-map|'
        r'route-map|prefix-list|crypto\s)', re.IGNORECASE,
    )

    def __init__(self, lines):
        self.raw_lines = lines
        self.parse = None
        if HAS_CISCOCONFPARSE:
            try:
                # Reconstruct indentation for ciscoconfparse
                indented = self._reconstruct_indent(lines)
                self.parse = CiscoConfParse(indented, ignore_blank_lines=True)
            except Exception as exc:
                logger.warning("CiscoConfParse failed: %s", exc)

    @staticmethod
    def _reconstruct_indent(lines):
        """Add indentation so ciscoconfparse can parse parent-child hierarchy."""
        result = []
        in_section = False
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith('!') or stripped.startswith('#'):
                result.append(stripped)
                continue
            # Check if this is a section header
            if CiscoValidator._SECTION_RE.match(stripped) or stripped == 'end':
                result.append(stripped)  # no indent for headers
                in_section = True
            elif in_section and not CiscoValidator._SECTION_RE.match(stripped):
                result.append(' ' + stripped)  # indent child lines
            else:
                result.append(stripped)
        return result

    # ---- public API --------------------------------------------------

    def run_all_checks(self):
        """Return list of ValidationError dicts."""
        errors = []
        errors.extend(self._check_duplicate_ips())
        errors.extend(self._check_subnet_overlaps())
        errors.extend(self._check_shutdown_interfaces())
        errors.extend(self._check_vlan_consistency())
        errors.extend(self._check_ospf_completeness())
        errors.extend(self._check_bgp_neighbors())
        errors.extend(self._check_acl_references())
        errors.extend(self._check_static_routes())
        errors.extend(self._check_security_baseline())
        return errors

    # ---- private checks ----------------------------------------------

    def _extract_interface_ips(self):
        """Return list of (interface_name, ip, mask, line_no)."""
        results = []
        if self.parse:
            for obj in self.parse.find_objects(r'^interface\s+'):
                intf_name = obj.text.strip()
                for child in obj.children:
                    m = re.match(
                        r'^\s*ip\s+address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)',
                        child.text, re.IGNORECASE,
                    )
                    if m:
                        results.append((intf_name, m.group(1), m.group(2), child.linenum))
        else:
            current_intf = None
            for i, line in enumerate(self.raw_lines, 1):
                im = re.match(r'^interface\s+(.+)', line, re.IGNORECASE)
                if im:
                    current_intf = im.group(1).strip()
                elif current_intf:
                    m = re.match(
                        r'^\s*ip\s+address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)',
                        line, re.IGNORECASE,
                    )
                    if m:
                        results.append((current_intf, m.group(1), m.group(2), i))
                    if re.match(r'^(interface|!|hostname|router|vlan)', line, re.IGNORECASE):
                        if not line.strip().startswith('ip '):
                            current_intf = None
        return results

    def _check_duplicate_ips(self):
        errors = []
        ip_map = {}  # ip -> [(intf, line_no)]
        for intf, ip, mask, lno in self._extract_interface_ips():
            ip_map.setdefault(ip, []).append((intf, lno))
        for ip, occurrences in ip_map.items():
            if len(occurrences) > 1:
                intfs = ', '.join(o[0] for o in occurrences)
                lines = [o[1] for o in occurrences]
                errors.append(make_error(
                    lines, 'semantic',
                    f'Duplicate IP {ip} assigned to: {intfs}',
                    'error', confidence='high', category='ip_address', vendor='cisco',
                ))
        return errors

    def _check_subnet_overlaps(self):
        errors = []
        nets = []
        for intf, ip, mask, lno in self._extract_interface_ips():
            net = to_network(ip, mask)
            if net:
                nets.append((intf, net, lno))
        for i in range(len(nets)):
            for j in range(i + 1, len(nets)):
                if nets[i][1].overlaps(nets[j][1]) and nets[i][1] != nets[j][1]:
                    errors.append(make_error(
                        [nets[i][2], nets[j][2]], 'semantic',
                        f'Overlapping subnets: {nets[i][0]} ({nets[i][1]}) overlaps '
                        f'{nets[j][0]} ({nets[j][1]})',
                        'warning', confidence='high', category='ip_address', vendor='cisco',
                    ))
        return errors

    def _check_shutdown_interfaces(self):
        errors = []
        if self.parse:
            for obj in self.parse.find_objects_w_child(
                r'^interface\s+', r'^\s*shutdown\s*$'
            ):
                has_ip = any(
                    re.match(r'^\s*ip\s+address\s+', c.text, re.IGNORECASE)
                    for c in obj.children
                )
                if has_ip:
                    errors.append(make_error(
                        obj.linenum, 'semantic',
                        f'{obj.text.strip()} has IP but is shutdown',
                        'warning',
                        fix=f'no shutdown',
                        confidence='medium', category='interface', vendor='cisco',
                    ))
        return errors

    def _check_vlan_consistency(self):
        errors = []
        defined_vlans = set()
        trunk_vlans = {}  # intf -> set of vlan ids
        for i, line in enumerate(self.raw_lines, 1):
            vm = re.match(r'^vlan\s+(\d+)', line, re.IGNORECASE)
            if vm:
                defined_vlans.add(int(vm.group(1)))
            # vlan list: vlan 10,20,30
            vm2 = re.match(r'^vlan\s+([\d,\s]+)$', line, re.IGNORECASE)
            if vm2:
                for v in vm2.group(1).split(','):
                    v = v.strip()
                    if v.isdigit():
                        defined_vlans.add(int(v))
            # trunk allowed
            tm = re.match(
                r'^\s*switchport\s+trunk\s+allowed\s+vlan\s+(.+)', line, re.IGNORECASE
            )
            if tm:
                vlan_str = tm.group(1).strip()
                allowed = set()
                for part in vlan_str.split(','):
                    part = part.strip()
                    if '-' in part:
                        try:
                            lo, hi = part.split('-')
                            allowed.update(range(int(lo), int(hi) + 1))
                        except ValueError:
                            pass
                    elif part.isdigit():
                        allowed.add(int(part))
                trunk_vlans[i] = allowed
        # Check: trunk allows VLANs that aren't defined
        if defined_vlans:
            for line_no, allowed in trunk_vlans.items():
                undefined = allowed - defined_vlans - {1}  # VLAN 1 always exists
                if undefined:
                    errors.append(make_error(
                        line_no, 'semantic',
                        f'Trunk allows undefined VLANs: {sorted(undefined)}',
                        'warning', confidence='medium', category='switching', vendor='cisco',
                    ))
        return errors

    def _check_ospf_completeness(self):
        errors = []
        ospf_networks = []
        intf_ips = self._extract_interface_ips()
        for i, line in enumerate(self.raw_lines, 1):
            nm = re.match(
                r'^\s*network\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+area\s+(\S+)',
                line, re.IGNORECASE,
            )
            if nm:
                net_addr, wc_mask, area = nm.group(1), nm.group(2), nm.group(3)
                try:
                    wc_int = int(ipaddress.IPv4Address(wc_mask))
                    prefix_len = 32 - bin(wc_int).count('1')
                    network = ipaddress.IPv4Network(
                        f'{net_addr}/{prefix_len}', strict=False
                    )
                    ospf_networks.append((network, area, i))
                except (ValueError, TypeError):
                    errors.append(make_error(
                        i, 'semantic',
                        f'Invalid OSPF wildcard mask: {wc_mask}',
                        'error', confidence='high', category='routing', vendor='cisco',
                    ))
        # Check: interface IPs not covered by any OSPF network statement
        if ospf_networks and intf_ips:
            for intf, ip, mask, lno in intf_ips:
                ip_obj = ipaddress.ip_address(ip)
                covered = any(ip_obj in net for net, _, _ in ospf_networks)
                # Only warn if the interface is in the same router ospf context
                # (simplified: we check all ospf networks)
                if not covered:
                    # Not necessarily an error - might be intentional
                    pass  # informational only, don't flag
        return errors

    def _check_bgp_neighbors(self):
        errors = []
        in_bgp = False
        for i, line in enumerate(self.raw_lines, 1):
            if re.match(r'^router\s+bgp\s+\d+', line, re.IGNORECASE):
                in_bgp = True
                continue
            if in_bgp:
                if re.match(r'^(router\s|interface\s|vlan\s|!|hostname\s)', line, re.IGNORECASE):
                    in_bgp = False
                    continue
                # neighbor with IP but no remote-as on the same or next line
                nm = re.match(
                    r'^\s*neighbor\s+(\d+\.\d+\.\d+\.\d+)\s*$', line, re.IGNORECASE
                )
                if nm:
                    errors.append(make_error(
                        i, 'semantic',
                        f'BGP neighbor {nm.group(1)} missing remote-as',
                        'error', confidence='high', category='routing', vendor='cisco',
                    ))
                # Validate AS number range
                am = re.match(
                    r'^\s*neighbor\s+\S+\s+remote-as\s+(\d+)', line, re.IGNORECASE
                )
                if am:
                    asn = int(am.group(1))
                    if asn < 1 or asn > 4294967295:
                        errors.append(make_error(
                            i, 'semantic',
                            f'Invalid BGP AS number: {asn} (must be 1-4294967295)',
                            'error', confidence='high', category='routing', vendor='cisco',
                        ))
        return errors

    def _check_acl_references(self):
        errors = []
        defined_acls = set()
        applied_acls = {}  # line_no -> acl_name
        for i, line in enumerate(self.raw_lines, 1):
            # Standard/extended named ACL
            am = re.match(r'^ip\s+access-list\s+(?:standard|extended)\s+(\S+)', line, re.IGNORECASE)
            if am:
                defined_acls.add(am.group(1))
            # Numbered ACL
            am2 = re.match(r'^access-list\s+(\d+)', line, re.IGNORECASE)
            if am2:
                defined_acls.add(am2.group(1))
            # ACL applied to interface
            am3 = re.match(r'^\s*ip\s+access-group\s+(\S+)\s+(?:in|out)', line, re.IGNORECASE)
            if am3:
                applied_acls[i] = am3.group(1)
        for lno, acl_name in applied_acls.items():
            if acl_name not in defined_acls:
                errors.append(make_error(
                    lno, 'semantic',
                    f'ACL "{acl_name}" applied but never defined',
                    'error', confidence='high', category='security', vendor='cisco',
                ))
        return errors

    def _check_static_routes(self):
        errors = []
        for i, line in enumerate(self.raw_lines, 1):
            sm = re.match(
                r'^ip\s+route\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)',
                line, re.IGNORECASE,
            )
            if sm:
                dest, mask, nh = sm.group(1), sm.group(2), sm.group(3)
                if nh == '0.0.0.0':
                    errors.append(make_error(
                        i, 'semantic',
                        f'Static route to {dest}/{mask} has next-hop 0.0.0.0 (null route)',
                        'warning', confidence='medium', category='routing', vendor='cisco',
                    ))
                elif re.match(r'^\d+\.\d+\.\d+\.\d+$', nh) and not is_valid_ip(nh):
                    errors.append(make_error(
                        i, 'semantic',
                        f'Static route has invalid next-hop: {nh}',
                        'error', confidence='high', category='routing', vendor='cisco',
                    ))
        return errors

    def _check_security_baseline(self):
        errors = []
        has_enable_secret = False
        has_ssh = False
        has_telnet = False
        has_aaa = False
        snmp_communities = []
        for i, line in enumerate(self.raw_lines, 1):
            ll = line.lower().strip()
            if ll.startswith('enable secret'):
                has_enable_secret = True
            if ll.startswith('ip ssh version'):
                has_ssh = True
            if 'transport input telnet' in ll or ll == 'telnet' and i > 1:
                has_telnet = True
            if ll.startswith('aaa new-model'):
                has_aaa = True
            scm = re.match(r'^snmp-server\s+community\s+(\S+)\s+(ro|rw)', ll)
            if scm:
                community, perm = scm.group(1), scm.group(2)
                if community in ('public', 'private', 'community'):
                    snmp_communities.append((community, perm, i))
        # SNMP weak community
        for community, perm, lno in snmp_communities:
            errors.append(make_error(
                lno, 'security',
                f'Weak SNMP community "{community}" ({perm}) - use SNMPv3 instead',
                'warning', confidence='high', category='security', vendor='cisco',
            ))
        # Telnet without SSH
        if has_telnet and not has_ssh:
            errors.append(make_error(
                None, 'security',
                'Telnet enabled without SSH - use "transport input ssh" on VTY lines',
                'warning', confidence='medium', category='security', vendor='cisco',
            ))
        # No enable secret (only flag for full configs with line/vty sections)
        has_line_config = any(
            re.match(r'^line\s+', l, re.IGNORECASE) for l in self.raw_lines
        )
        if has_line_config and not has_enable_secret:
            errors.append(make_error(
                None, 'security',
                'No "enable secret" configured - privileged mode is unprotected',
                'warning', confidence='medium', category='security', vendor='cisco',
            ))
        return errors


# ===================================================================
#  Huawei VRP Validator
# ===================================================================

class HuaweiValidator:
    """Semantic validator for Huawei VRP configs."""

    def __init__(self, lines):
        self.raw_lines = lines

    def run_all_checks(self):
        errors = []
        errors.extend(self._check_duplicate_ips())
        errors.extend(self._check_vlan_consistency())
        errors.extend(self._check_bgp_peers())
        errors.extend(self._check_ospf_areas())
        errors.extend(self._check_static_routes())
        errors.extend(self._check_security_baseline())
        return errors

    def _parse_sections(self):
        """Parse VRP hierarchical sections. Returns dict of section_type -> list of (header, [(child_line, line_no)])."""
        sections = {}
        current_section = None
        current_header = None
        current_children = []
        current_start = 0
        for i, line in enumerate(self.raw_lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith('#') or stripped.startswith('!'):
                continue
            # Section header detection
            if re.match(r'^interface\s+', stripped, re.IGNORECASE):
                if current_section and current_header:
                    sections.setdefault(current_section, []).append(
                        (current_header, current_children)
                    )
                current_section = 'interface'
                current_header = stripped
                current_children = []
                current_start = i
            elif re.match(r'^(ospf|bgp|vlan|acl|ip\s+route-static)\b', stripped, re.IGNORECASE):
                if current_section and current_header:
                    sections.setdefault(current_section, []).append(
                        (current_header, current_children)
                    )
                sec_type = stripped.split()[0].lower()
                current_section = sec_type
                current_header = stripped
                current_children = []
                current_start = i
            elif stripped.lower() in ('return', 'quit', '#'):
                if current_section and current_header:
                    sections.setdefault(current_section, []).append(
                        (current_header, current_children)
                    )
                current_section = None
                current_header = None
                current_children = []
            elif current_section:
                current_children.append((stripped, i))
        # Flush last section
        if current_section and current_header:
            sections.setdefault(current_section, []).append(
                (current_header, current_children)
            )
        return sections

    def _check_duplicate_ips(self):
        errors = []
        sections = self._parse_sections()
        ip_map = {}
        for header, children in sections.get('interface', []):
            for child_line, lno in children:
                m = re.match(
                    r'^ip\s+address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)',
                    child_line, re.IGNORECASE,
                )
                if m:
                    ip = m.group(1)
                    ip_map.setdefault(ip, []).append((header, lno))
        for ip, occurrences in ip_map.items():
            if len(occurrences) > 1:
                intfs = ', '.join(o[0] for o in occurrences)
                lines = [o[1] for o in occurrences]
                errors.append(make_error(
                    lines, 'semantic',
                    f'Duplicate IP {ip} assigned to: {intfs}',
                    'error', confidence='high', category='ip_address', vendor='huawei',
                ))
        return errors

    def _check_vlan_consistency(self):
        errors = []
        defined_vlans = set()
        trunk_vlans = {}
        sections = self._parse_sections()
        # Defined VLANs
        for header, children in sections.get('vlan', []):
            vm = re.match(r'^vlan\s+(\d+)', header, re.IGNORECASE)
            if vm:
                defined_vlans.add(int(vm.group(1)))
            # vlan batch
            for child_line, lno in children:
                pass  # children under vlan are usually descriptions etc.
        # Also scan top-level vlan batch
        for i, line in enumerate(self.raw_lines, 1):
            vm = re.match(r'^vlan\s+batch\s+(.+)', line, re.IGNORECASE)
            if vm:
                for part in vm.group(1).split():
                    if part.isdigit():
                        defined_vlans.add(int(part))
                    elif 'to' in part:
                        try:
                            lo, hi = part.split('to')
                            defined_vlans.update(range(int(lo), int(hi) + 1))
                        except ValueError:
                            pass
            vm2 = re.match(r'^vlan\s+(\d+)', line, re.IGNORECASE)
            if vm2:
                defined_vlans.add(int(vm2.group(1)))
        # Trunk allowed VLANs
        for header, children in sections.get('interface', []):
            for child_line, lno in children:
                tm = re.match(
                    r'^port\s+trunk\s+allow-pass\s+vlan\s+(.+)', child_line, re.IGNORECASE
                )
                if tm:
                    vlan_str = tm.group(1).strip()
                    allowed = set()
                    if vlan_str.lower() == 'all':
                        continue  # all is always OK
                    for part in vlan_str.split():
                        if 'to' in part:
                            try:
                                lo, hi = part.split('to')
                                allowed.update(range(int(lo.strip()), int(hi.strip()) + 1))
                            except ValueError:
                                pass
                        elif part.isdigit():
                            allowed.add(int(part))
                    if allowed:
                        trunk_vlans[lno] = (header, allowed)
        if defined_vlans:
            for lno, (intf, allowed) in trunk_vlans.items():
                undefined = allowed - defined_vlans - {1}
                if undefined:
                    errors.append(make_error(
                        lno, 'semantic',
                        f'{intf}: trunk allows undefined VLANs: {sorted(undefined)}',
                        'warning', confidence='medium', category='switching', vendor='huawei',
                    ))
        return errors

    def _check_bgp_peers(self):
        errors = []
        sections = self._parse_sections()
        for header, children in sections.get('bgp', []):
            for child_line, lno in children:
                # peer X.X.X.X as-number missing
                pm = re.match(r'^peer\s+(\d+\.\d+\.\d+\.\d+)\s*$', child_line, re.IGNORECASE)
                if pm:
                    errors.append(make_error(
                        lno, 'semantic',
                        f'BGP peer {pm.group(1)} missing as-number',
                        'error', confidence='high', category='routing', vendor='huawei',
                    ))
                # Validate AS number
                am = re.match(r'^peer\s+\S+\s+as-number\s+(\d+)', child_line, re.IGNORECASE)
                if am:
                    asn = int(am.group(1))
                    if asn < 1 or asn > 4294967295:
                        errors.append(make_error(
                            lno, 'semantic',
                            f'Invalid BGP AS number: {asn}',
                            'error', confidence='high', category='routing', vendor='huawei',
                        ))
        return errors

    def _check_ospf_areas(self):
        errors = []
        sections = self._parse_sections()
        for header, children in sections.get('ospf', []):
            has_area = False
            for child_line, lno in children:
                if re.match(r'^area\s+\d+', child_line, re.IGNORECASE):
                    has_area = True
                if re.match(r'^network\s+', child_line, re.IGNORECASE) and not has_area:
                    errors.append(make_error(
                        lno, 'semantic',
                        'OSPF network statement before area definition',
                        'error', confidence='medium', category='routing', vendor='huawei',
                    ))
        return errors

    def _check_static_routes(self):
        errors = []
        for i, line in enumerate(self.raw_lines, 1):
            sm = re.match(
                r'^ip\s+route-static\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)',
                line, re.IGNORECASE,
            )
            if sm:
                nh = sm.group(3)
                if nh == '0.0.0.0':
                    errors.append(make_error(
                        i, 'semantic',
                        f'Static route has null next-hop 0.0.0.0',
                        'warning', confidence='medium', category='routing', vendor='huawei',
                    ))
                elif re.match(r'^\d+\.\d+\.\d+\.\d+$', nh) and not is_valid_ip(nh):
                    errors.append(make_error(
                        i, 'semantic',
                        f'Static route has invalid next-hop: {nh}',
                        'error', confidence='high', category='routing', vendor='huawei',
                    ))
        return errors

    def _check_security_baseline(self):
        errors = []
        has_aaa = False
        snmp_weak = []
        for i, line in enumerate(self.raw_lines, 1):
            ll = line.strip().lower()
            if ll.startswith('aaa'):
                has_aaa = True
            scm = re.match(r'^snmp-agent\s+community\s+(?:read|write)\s+(\S+)', ll)
            if scm:
                community = scm.group(1)
                if community in ('public', 'private', 'community'):
                    snmp_weak.append((community, i))
        for community, lno in snmp_weak:
            errors.append(make_error(
                lno, 'security',
                f'Weak SNMP community "{community}" - use SNMPv3',
                'warning', confidence='high', category='security', vendor='huawei',
            ))
        return errors


# ===================================================================
#  Juniper JunOS Validator
# ===================================================================

class JuniperValidator:
    """Semantic validator for Juniper JunOS set-style configs."""

    def __init__(self, lines):
        self.raw_lines = lines

    def run_all_checks(self):
        errors = []
        errors.extend(self._check_duplicate_ips())
        errors.extend(self._check_bgp_peers())
        errors.extend(self._check_ospf_interfaces())
        errors.extend(self._check_static_routes())
        errors.extend(self._check_firewall_filters())
        errors.extend(self._check_security_baseline())
        return errors

    def _check_duplicate_ips(self):
        errors = []
        ip_map = {}
        for i, line in enumerate(self.raw_lines, 1):
            m = re.match(
                r'^set\s+interfaces\s+(\S+)\s+unit\s+\d+\s+family\s+inet\s+address\s+(\d+\.\d+\.\d+\.\d+)/\d+',
                line, re.IGNORECASE,
            )
            if m:
                intf, ip = m.group(1), m.group(2)
                ip_map.setdefault(ip, []).append((intf, i))
        for ip, occurrences in ip_map.items():
            if len(occurrences) > 1:
                intfs = ', '.join(o[0] for o in occurrences)
                lines = [o[1] for o in occurrences]
                errors.append(make_error(
                    lines, 'semantic',
                    f'Duplicate IP {ip} assigned to: {intfs}',
                    'error', confidence='high', category='ip_address', vendor='juniper',
                ))
        return errors

    def _check_bgp_peers(self):
        errors = []
        bgp_groups = {}  # group_name -> {neighbors: set, type: str}
        for i, line in enumerate(self.raw_lines, 1):
            gm = re.match(r'^set\s+protocols\s+bgp\s+group\s+(\S+)\s+type\s+(\S+)', line, re.IGNORECASE)
            if gm:
                bgp_groups.setdefault(gm.group(1), {}).update(type=gm.group(2))
            nm = re.match(
                r'^set\s+protocols\s+bgp\s+group\s+(\S+)\s+neighbor\s+(\S+)\s*$',
                line, re.IGNORECASE,
            )
            if nm:
                group = nm.group(1)
                bgp_groups.setdefault(group, {})
                bgp_groups[group].setdefault('neighbors_no_peeras', []).append(
                    (nm.group(2), i)
                )
            pm = re.match(
                r'^set\s+protocols\s+bgp\s+group\s+(\S+)\s+neighbor\s+\S+\s+peer-as\s+(\d+)',
                line, re.IGNORECASE,
            )
            if pm:
                group = pm.group(1)
                bgp_groups.setdefault(group, {})
                bgp_groups[group].setdefault('has_peeras', set())
                bgp_groups[group]['has_peeras'].add(i)
        # Check neighbors without peer-as
        for group, data in bgp_groups.items():
            neighbors = data.get('neighbors_no_peeras', [])
            for neighbor, lno in neighbors:
                errors.append(make_error(
                    lno, 'semantic',
                    f'BGP group "{group}" neighbor {neighbor} missing peer-as',
                    'error', confidence='high', category='routing', vendor='juniper',
                ))
        return errors

    def _check_ospf_interfaces(self):
        errors = []
        ospf_interfaces = set()
        defined_interfaces = set()
        for i, line in enumerate(self.raw_lines, 1):
            om = re.match(
                r'^set\s+protocols\s+ospf\s+area\s+\S+\s+interface\s+(\S+)',
                line, re.IGNORECASE,
            )
            if om:
                ospf_interfaces.add(om.group(1))
            im = re.match(r'^set\s+interfaces\s+(\S+)\s+unit\s+\d+\s+family\s+inet', line, re.IGNORECASE)
            if im:
                defined_interfaces.add(im.group(1))
        for ospf_intf in ospf_interfaces:
            if ospf_intf != 'all' and ospf_intf not in defined_interfaces:
                errors.append(make_error(
                    None, 'semantic',
                    f'OSPF references interface "{ospf_intf}" which has no IP config',
                    'warning', confidence='medium', category='routing', vendor='juniper',
                ))
        return errors

    def _check_static_routes(self):
        errors = []
        for i, line in enumerate(self.raw_lines, 1):
            sm = re.match(
                r'^set\s+routing-options\s+static\s+route\s+\S+\s+next-hop\s+(\S+)',
                line, re.IGNORECASE,
            )
            if sm:
                nh = sm.group(1)
                if nh == '0.0.0.0':
                    errors.append(make_error(
                        i, 'semantic',
                        'Static route next-hop is 0.0.0.0 (discard route)',
                        'warning', confidence='medium', category='routing', vendor='juniper',
                    ))
            # Route without next-hop
            sm2 = re.match(
                r'^set\s+routing-options\s+static\s+route\s+\S+\s*$',
                line, re.IGNORECASE,
            )
            if sm2:
                errors.append(make_error(
                    i, 'semantic',
                    'Static route missing next-hop',
                    'error', confidence='high', category='routing', vendor='juniper',
                ))
        return errors

    def _check_firewall_filters(self):
        errors = []
        filter_terms = {}  # filter_name -> [(term_name, line_no, has_then)]
        for i, line in enumerate(self.raw_lines, 1):
            tm = re.match(
                r'^set\s+firewall\s+(?:family\s+inet\s+)?filter\s+(\S+)\s+term\s+(\S+)\s+then\s+(\S+)',
                line, re.IGNORECASE,
            )
            if tm:
                fname, term, action = tm.group(1), tm.group(2), tm.group(3)
                filter_terms.setdefault(fname, []).append((term, i, True))
            tm2 = re.match(
                r'^set\s+firewall\s+(?:family\s+inet\s+)?filter\s+(\S+)\s+term\s+(\S+)\s+from',
                line, re.IGNORECASE,
            )
            if tm2 and not tm:
                fname, term = tm2.group(1), tm2.group(2)
                filter_terms.setdefault(fname, []).append((term, i, False))
        # Check if any term has "from" without "then"
        for fname, terms in filter_terms.items():
            term_thens = {}
            for term, lno, has_then in terms:
                if has_then:
                    term_thens[term] = True
                elif term not in term_thens:
                    term_thens[term] = False
            for term, has_then in term_thens.items():
                if not has_then:
                    errors.append(make_error(
                        None, 'semantic',
                        f'Firewall filter "{fname}" term "{term}" has no "then" action',
                        'error', confidence='medium', category='security', vendor='juniper',
                    ))
        return errors

    def _check_security_baseline(self):
        errors = []
        has_root_auth = False
        has_ssh = False
        for i, line in enumerate(self.raw_lines, 1):
            ll = line.strip().lower()
            if 'root-authentication' in ll and 'encrypted-password' in ll:
                has_root_auth = True
            if ll.startswith('set system services ssh'):
                has_ssh = True
            if ll.startswith('set system services telnet'):
                errors.append(make_error(
                    i, 'security',
                    'Telnet service enabled - use SSH instead',
                    'warning', confidence='high', category='security', vendor='juniper',
                ))
        return errors


# ===================================================================
#  Unified entry point
# ===================================================================

class ConfigValidator:
    """Vendor-aware semantic config validator."""

    VENDOR_MAP = {
        'cisco': CiscoValidator,
        'huawei': HuaweiValidator,
        'juniper': JuniperValidator,
    }

    @classmethod
    def run_semantic_checks(cls, lines, vendor='cisco'):
        """Run all semantic checks for the given vendor.

        Args:
            lines: list of config line strings
            vendor: 'cisco', 'huawei', 'juniper', or 'auto'

        Returns:
            list of ValidationError dicts
        """
        if vendor == 'auto':
            vendor = cls._detect_vendor(lines)

        validator_cls = cls.VENDOR_MAP.get(vendor)
        if not validator_cls:
            logger.warning("No semantic validator for vendor: %s", vendor)
            return []

        validator = validator_cls(lines)
        try:
            return validator.run_all_checks()
        except Exception as exc:
            logger.error("Semantic validation failed: %s", exc)
            return []

    @classmethod
    def _detect_vendor(cls, lines):
        """Simple vendor detection from config lines."""
        for line in lines:
            ll = line.strip().lower()
            if ll.startswith('set ') or ll.startswith('system '):
                return 'juniper'
            if ll.startswith('sysname ') or ll.startswith('undo '):
                return 'huawei'
            if re.match(r'^(hostname|interface\s|router\s|switchport|no\s+shutdown)', ll):
                return 'cisco'
        return 'cisco'

    @classmethod
    def merge_semantic_errors(cls, parse_result, semantic_errors):
        """Merge semantic errors into a parse_network_config result dict.

        Updates parse_result in-place and returns it.
        """
        if not semantic_errors:
            parse_result.setdefault('semantic_errors', [])
            parse_result.setdefault('error_categories', {})
            return parse_result

        # Add semantic errors to the result
        parse_result.setdefault('semantic_errors', [])
        parse_result['semantic_errors'].extend(semantic_errors)

        # Count errors by category
        categories = parse_result.setdefault('error_categories', {})
        for err in semantic_errors:
            cat = err.get('category', 'general')
            sev = err.get('severity', 'error')
            categories[cat] = categories.get(cat, 0) + 1

            # Add to main errors/warnings lists
            line_prefix = ''
            if err.get('line_numbers'):
                lnums = err['line_numbers']
                if lnums and lnums[0] is not None:
                    line_prefix = f'Line {lnums[0]}: '

            formatted = f"{line_prefix}{err['message']}"
            if sev in ('error', 'critical'):
                parse_result['errors'].append(formatted)
                parse_result['error_count'] = parse_result.get('error_count', 0) + 1
            elif sev == 'warning':
                parse_result['warnings'].append(formatted)
                parse_result['warning_count'] = parse_result.get('warning_count', 0) + 1

        return parse_result
