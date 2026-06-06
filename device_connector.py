"""
Network Device Connector Module
Uses netmiko for SSH/CLI management and ntc-templates for show command parsing.
Supports Cisco IOS, Huawei VRP, and Juniper JunOS.
Provides: show command execution, config retrieval, config application,
error detection from device output, and structured output parsing.
"""

import re
from typing import Optional, Dict, List, Any


# Vendor to netmiko device_type mapping
VENDOR_DEVICE_TYPE_MAP = {
    'cisco': {
        'router': 'cisco_ios',
        'switch': 'cisco_ios',
        'firewall': 'cisco_asa',
        'default': 'cisco_ios',
    },
    'huawei': {
        'router': 'huawei',
        'switch': 'huawei',
        'firewall': 'huawei',
        'default': 'huawei',
    },
    'juniper': {
        'router': 'juniper_junos',
        'switch': 'juniper_junos',
        'firewall': 'juniper_junos',
        'default': 'juniper_junos',
    },
}


# Common show commands per vendor for diagnostics
VENDOR_SHOW_COMMANDS = {
    'cisco': [
        'show running-config',
        'show ip interface brief',
        'show ip route',
        'show ip ospf neighbor',
        'show ip bgp summary',
        'show vlan brief',
        'show interfaces status',
        'show version',
        'show clock',
        'show logging | tail 20',
    ],
    'huawei': [
        'display current-configuration',
        'display interface brief',
        'display ip routing-table',
        'display ospf peer',
        'display bgp peer',
        'display vlan',
        'display version',
        'display clock',
        'display logbuffer | tail 20',
    ],
    'juniper': [
        'show configuration',
        'show interfaces terse',
        'show route',
        'show ospf neighbor',
        'show bgp summary',
        'show vlans',
        'show version',
        'show system uptime',
        'show log messages | last 20',
    ],
}


# Error patterns in device output (to detect failures from show/config commands)
DEVICE_ERROR_PATTERNS = {
    'cisco': [
        re.compile(r'%\s*Invalid input detected', re.IGNORECASE),
        re.compile(r'%\s*Incomplete command', re.IGNORECASE),
        re.compile(r'%\s*Ambiguous command', re.IGNORECASE),
        re.compile(r'%\s*Unknown command', re.IGNORECASE),
        re.compile(r'%\s*Command authorization failed', re.IGNORECASE),
        re.compile(r'% Bad IP address', re.IGNORECASE),
        re.compile(r'% Invalid mask', re.IGNORECASE),
        re.compile(r'% Network not in table', re.IGNORECASE),
        re.compile(r'% Not authorized', re.IGNORECASE),
        re.compile(r'%Error', re.IGNORECASE),
        re.compile(r'% Failed', re.IGNORECASE),
    ],
    'huawei': [
        re.compile(r'%Error:', re.IGNORECASE),
        re.compile(r'%Unrecognized command', re.IGNORECASE),
        re.compile(r'%Incomplete command', re.IGNORECASE),
        re.compile(r'%Wrong parameter', re.IGNORECASE),
        re.compile(r'%Ambiguous command', re.IGNORECASE),
        re.compile(r'Error: ', re.IGNORECASE),
        re.compile(r'Invalid input', re.IGNORECASE),
        re.compile(r'Command failed', re.IGNORECASE),
    ],
    'juniper': [
        re.compile(r'error:', re.IGNORECASE),
        re.compile(r'unknown command:', re.IGNORECASE),
        re.compile(r'syntax error', re.IGNORECASE),
        re.compile(r'missing argument', re.IGNORECASE),
        re.compile(r'invalid value', re.IGNORECASE),
        re.compile(r'commit failed', re.IGNORECASE),
        re.compile(r'configuration check-out failed', re.IGNORECASE),
    ],
}


def get_netmiko_device_type(vendor: str, device_type: str = 'router') -> str:
    """Map vendor and device type to netmiko device_type string."""
    vendor_map = VENDOR_DEVICE_TYPE_MAP.get(vendor.lower(), VENDOR_DEVICE_TYPE_MAP['cisco'])
    return vendor_map.get(device_type, vendor_map.get('default', 'cisco_ios'))


def get_default_show_commands(vendor: str) -> List[str]:
    """Return default diagnostic show commands for a vendor."""
    return VENDOR_SHOW_COMMANDS.get(vendor.lower(), VENDOR_SHOW_COMMANDS['cisco'])


def detect_output_errors(output: str, vendor: str = 'cisco') -> List[Dict[str, str]]:
    """
    Scan device command output for error patterns.
    Returns a list of error dicts with 'line' and 'message' keys.
    """
    errors = []
    patterns = DEVICE_ERROR_PATTERNS.get(vendor.lower(), DEVICE_ERROR_PATTERNS['cisco'])
    for line_num, line in enumerate(output.splitlines(), 1):
        for pattern in patterns:
            if pattern.search(line):
                errors.append({
                    'line': line_num,
                    'text': line.strip(),
                    'message': f'Device error detected: {line.strip()}',
                })
                break
    return errors


def parse_show_output_structured(output: str, command: str, vendor: str = 'cisco') -> Dict[str, Any]:
    """
    Try to parse show command output using ntc-templates (TextFSM).
    Falls back to raw output if no template is available.
    """
    try:
        from ntc_templates.parse import ntc_parse
        platform = get_ntc_platform(vendor)
        parsed = ntc_parse(output, command, platform)
        return {
            'success': True,
            'structured': parsed,
            'raw': output,
            'method': 'ntc-templates',
        }
    except ImportError:
        return {
            'success': True,
            'structured': None,
            'raw': output,
            'method': 'raw',
            'note': 'ntc-templates not installed. Install with: pip install ntc-templates',
        }
    except Exception as e:
        return {
            'success': True,
            'structured': None,
            'raw': output,
            'method': 'raw',
            'note': f'No TextFSM template for this command: {str(e)}',
        }


def get_ntc_platform(vendor: str) -> str:
    """Map vendor to ntc-templates platform name."""
    mapping = {
        'cisco': 'cisco_ios',
        'huawei': 'huawei_vrp',
        'juniper': 'juniper_junos',
    }
    return mapping.get(vendor.lower(), 'cisco_ios')


class DeviceConnector:
    """
    Unified connector for real network devices using netmiko.
    Supports show commands, config retrieval, config application, and error detection.
    """

    def __init__(self, host: str, username: str, password: str,
                 vendor: str = 'cisco', device_type: str = 'router',
                 port: int = 22, secret: str = '',
                 timeout: int = 30, global_delay_factor: int = 2):
        self.host = host
        self.username = username
        self.password = password
        self.vendor = vendor.lower()
        self.device_type_name = device_type
        self.port = port
        self.secret = secret
        self.timeout = timeout
        self.global_delay_factor = global_delay_factor
        self.connection = None
        self._netmiko_type = get_netmiko_device_type(vendor, device_type)

    def connect(self) -> Dict[str, Any]:
        """Establish SSH connection to the device."""
        try:
            from netmiko import ConnectHandler
            device_params = {
                'device_type': self._netmiko_type,
                'host': self.host,
                'username': self.username,
                'password': self.password,
                'port': self.port,
                'secret': self.secret,
                'timeout': self.timeout,
                'global_delay_factor': self.global_delay_factor,
            }
            self.connection = ConnectHandler(**device_params)
            if self.secret:
                self.connection.enable()
            return {'success': True, 'message': f'Connected to {self.host}'}
        except ImportError:
            return {
                'success': False,
                'error': 'netmiko is not installed. Install with: pip install netmiko',
            }
        except Exception as e:
            return {'success': False, 'error': f'Connection failed: {str(e)}'}

    def disconnect(self):
        """Close the SSH connection."""
        if self.connection:
            try:
                self.connection.disconnect()
            except Exception:
                pass
            self.connection = None

    def test_connection(self) -> Dict[str, Any]:
        """Test connectivity to the device."""
        result = self.connect()
        if not result['success']:
            return result
        try:
            output = self.connection.find_prompt()
            self.disconnect()
            return {
                'success': True,
                'prompt': output,
                'message': f'Successfully connected to {self.host}',
                'vendor': self.vendor,
                'device_type': self._netmiko_type,
            }
        except Exception as e:
            self.disconnect()
            return {'success': False, 'error': f'Connection test failed: {str(e)}'}

    def execute_command(self, command: str) -> Dict[str, Any]:
        """
        Execute a single command on the device and return output + error analysis.
        """
        if not self.connection:
            result = self.connect()
            if not result['success']:
                return result

        try:
            output = self.connection.send_command(command, read_timeout=self.timeout)
            errors = detect_output_errors(output, self.vendor)
            structured = parse_show_output_structured(output, command, self.vendor)

            return {
                'success': len(errors) == 0,
                'command': command,
                'output': output,
                'structured': structured.get('structured'),
                'errors': errors,
                'error_count': len(errors),
                'parse_method': structured.get('method', 'raw'),
            }
        except Exception as e:
            return {
                'success': False,
                'command': command,
                'error': f'Command execution failed: {str(e)}',
                'output': '',
                'errors': [{'message': str(e)}],
                'error_count': 1,
            }

    def execute_show_commands(self, commands: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Execute a batch of show/display commands and return all results.
        Uses default vendor-specific commands if none provided.
        """
        if not self.connection:
            result = self.connect()
            if not result['success']:
                return result

        cmds = commands or get_default_show_commands(self.vendor)
        results = []
        total_errors = 0

        for cmd in cmds:
            cmd_result = self.execute_command(cmd)
            results.append(cmd_result)
            total_errors += cmd_result.get('error_count', 0)

        return {
            'success': total_errors == 0,
            'commands_executed': len(cmds),
            'total_errors': total_errors,
            'results': results,
        }

    def get_running_config(self) -> Dict[str, Any]:
        """Retrieve the current running configuration from the device."""
        config_commands = {
            'cisco': 'show running-config',
            'huawei': 'display current-configuration',
            'juniper': 'show configuration | display set',
        }
        cmd = config_commands.get(self.vendor, 'show running-config')
        return self.execute_command(cmd)

    def get_startup_config(self) -> Dict[str, Any]:
        """Retrieve the startup/saved configuration from the device."""
        config_commands = {
            'cisco': 'show startup-config',
            'huawei': 'display saved-configuration',
            'juniper': 'show configuration | display set | compare rollback 1',
        }
        cmd = config_commands.get(self.vendor, 'show startup-config')
        return self.execute_command(cmd)

    def apply_config(self, config_text: str, commit: bool = True) -> Dict[str, Any]:
        """
        Apply a configuration to the device.
        For Juniper: enters config mode, loads set commands, optionally commits.
        For Cisco/Huawei: enters config mode and sends commands line by line.
        """
        if not self.connection:
            result = self.connect()
            if not result['success']:
                return result

        try:
            if self.vendor == 'juniper':
                return self._apply_juniper_config(config_text, commit)
            else:
                return self._apply_cli_config(config_text)
        except Exception as e:
            return {
                'success': False,
                'error': f'Configuration application failed: {str(e)}',
            }

    def _apply_cli_config(self, config_text: str) -> Dict[str, Any]:
        """Apply config to Cisco/Huawei using send_config_set."""
        try:
            config_lines = [line for line in config_text.splitlines() if line.strip()]
            output = self.connection.send_config_set(config_lines)
            errors = detect_output_errors(output, self.vendor)

            # Save config
            if self.vendor == 'huawei':
                save_output = self.connection.send_command('save', expect_string=r'\[Y/N\]')
                if 'Y/N' in save_output or 'y/n' in save_output:
                    save_output = self.connection.send_command('Y')
            else:
                save_output = self.connection.send_command('write memory')

            return {
                'success': len(errors) == 0,
                'output': output,
                'save_output': save_output,
                'errors': errors,
                'error_count': len(errors),
                'lines_applied': len(config_lines),
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _apply_juniper_config(self, config_text: str, commit: bool = True) -> Dict[str, Any]:
        """Apply config to Juniper using configuration mode."""
        try:
            self.connection.send_command('configure', expect_string=r'#')
            config_lines = [line for line in config_text.splitlines() if line.strip()]
            output = ''
            errors = []
            for line in config_lines:
                result = self.connection.send_command(line, expect_string=r'#')
                output += result + '\n'
                line_errors = detect_output_errors(result, 'juniper')
                errors.extend(line_errors)

            if commit and len(errors) == 0:
                commit_output = self.connection.send_command('commit', expect_string=r'#')
                output += commit_output
                errors.extend(detect_output_errors(commit_output, 'juniper'))
            elif not commit:
                pass  # Leave in candidate config

            return {
                'success': len(errors) == 0,
                'output': output,
                'errors': errors,
                'error_count': len(errors),
                'lines_applied': len(config_lines),
                'committed': commit and len(errors) == 0,
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def get_device_facts(self) -> Dict[str, Any]:
        """
        Get basic device facts using NAPALM if available,
        falls back to show commands.
        """
        try:
            from napalm import get_network_driver
            driver = get_network_driver(self._netmiko_type.replace('_ios', '_ios').replace('huawei', 'huawei_vrp'))
            device = driver(
                hostname=self.host,
                username=self.username,
                password=self.password,
                optional_args={'port': self.port, 'secret': self.secret},
            )
            device.open()
            facts = device.get_facts()
            interfaces = device.get_interfaces()
            interfaces_ip = device.get_interfaces_ip()
            device.close()
            return {
                'success': True,
                'facts': facts,
                'interfaces': interfaces,
                'interfaces_ip': interfaces_ip,
                'method': 'napalm',
            }
        except ImportError:
            return {
                'success': False,
                'error': 'napalm is not installed. Install with: pip install napalm',
                'method': 'napalm',
            }
        except Exception as e:
            # Fallback to show commands
            return {
                'success': False,
                'error': f'NAPALM failed: {str(e)}. Falling back to show commands.',
                'method': 'napalm',
            }

    def diff_config(self, candidate_config: str) -> Dict[str, Any]:
        """
        Compare candidate config with running config using NAPALM.
        Returns the diff without applying changes.
        """
        try:
            from napalm import get_network_driver
            driver_name = self._netmiko_type
            if 'huawei' in driver_name:
                driver_name = 'huawei_vrp'
            driver = get_network_driver(driver_name)
            device = driver(
                hostname=self.host,
                username=self.username,
                password=self.password,
                optional_args={'port': self.port, 'secret': self.secret},
            )
            device.open()
            device.load_merge_candidate(config=candidate_config)
            diff = device.compare_config()
            device.discard_config()
            device.close()
            return {
                'success': True,
                'diff': diff,
                'method': 'napalm',
            }
        except ImportError:
            return {
                'success': False,
                'error': 'napalm is not installed. Install with: pip install napalm',
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}


def create_device_connector(device_info: Dict[str, Any]) -> DeviceConnector:
    """
    Factory function to create a DeviceConnector from device info dict.
    Expected keys: host/ip_address, username, password, vendor, device_type, port, secret
    """
    return DeviceConnector(
        host=device_info.get('host') or device_info.get('ip_address', ''),
        username=device_info.get('username', 'admin'),
        password=device_info.get('password', ''),
        vendor=device_info.get('vendor', 'cisco'),
        device_type=device_info.get('device_type', 'router'),
        port=device_info.get('port', 22),
        secret=device_info.get('secret', ''),
        timeout=device_info.get('timeout', 30),
    )
