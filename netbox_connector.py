"""
NetBox API Connector Module
Handles all interactions with the NetBox REST API.
NetBox serves as the IPAM/DCIM source of truth and central reference
for all network device information, IP addresses, VLANs, etc.
"""

from ipaddress import ip_address

import requests


def build_auth_header(api_token):
    token = (api_token or '').strip()
    lowered = token.lower()
    if lowered.startswith('bearer ') or lowered.startswith('token '):
        return {'Authorization': token}
    if token.startswith('nbt_') and '.' in token:
        return {'Authorization': f'Bearer {token}'}
    return {'Authorization': f'Token {token}'}


class NetBoxConnector:
    """Connector for NetBox REST API."""
    def __init__(self, netbox_url='http://192.168.163.145:8000', api_token=''):
        self.netbox_url = netbox_url.rstrip('/')
        self.api_base = f'{self.netbox_url}/api'
        self.api_token = api_token
        self.session = requests.Session()
        if api_token:
            self.session.headers.update({
                **build_auth_header(api_token),
                'Content-Type': 'application/json',
                'Accept': 'application/json',
            })
        self.timeout = 10

    def test_connection(self):
        """Test connectivity to NetBox server."""
        try:
            resp = self.session.get(f'{self.api_base}/status/', timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                return {
                    'success': True,
                    'version': data.get('netbox-version', 'unknown'),
                    'python_version': data.get('python-version', 'unknown'),
                    'django_version': data.get('django-version', 'unknown'),
                }
            elif resp.status_code == 401:
                return {'success': False, 'error': 'Authentication failed. Check your API token.'}
            elif resp.status_code == 403:
                return {'success': False, 'error': 'Permission denied. Check your API token permissions.'}
            return {'success': False, 'error': f'HTTP {resp.status_code}'}
        except requests.exceptions.ConnectionError:
            return {'success': False, 'error': 'Cannot connect to NetBox server. Make sure NetBox is running.'}
        except requests.exceptions.Timeout:
            return {'success': False, 'error': 'Connection timeout'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def format_ipam_address(self, address):
        """Format a plain host address for NetBox IPAM."""
        address = (address or '').strip()
        if not address or '/' in address:
            return address
        try:
            parsed = ip_address(address)
        except ValueError:
            return address
        prefix_length = 128 if parsed.version == 6 else 32
        return f'{address}/{prefix_length}'

    # =========================================================================
    # TENANTS (Companies)
    # =========================================================================

    def get_tenants(self):
        """List all tenants."""
        try:
            resp = self.session.get(f'{self.api_base}/tenancy/tenants/', timeout=self.timeout)
            if resp.status_code == 200:
                return {'success': True, 'results': resp.json().get('results', [])}
            return {'success': False, 'error': f'HTTP {resp.status_code}'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def create_tenant(self, name, slug, description='', group=None):
        """Create a new tenant (company)."""
        payload = {
            'name': name,
            'slug': slug,
            'description': description,
        }
        if group:
            payload['group'] = group
        try:
            resp = self.session.post(f'{self.api_base}/tenancy/tenants/', json=payload, timeout=self.timeout)
            if resp.status_code in (200, 201):
                return {'success': True, 'tenant': resp.json()}
            return {'success': False, 'error': f'HTTP {resp.status_code}: {resp.text}'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def get_or_create_tenant(self, name, slug=None):
        """Get or create a tenant by name."""
        slug = slug or name.lower().replace(' ', '-')
        result = self.get_tenants()
        if result['success']:
            for tenant in result['results']:
                if tenant['name'] == name or tenant['slug'] == slug:
                    return {'success': True, 'tenant': tenant, 'created': False}
        # Create new tenant
        create_result = self.create_tenant(name, slug)
        if create_result['success']:
            create_result['created'] = True
        return create_result

    # =========================================================================
    # SITES
    # =========================================================================

    def get_sites(self):
        """List all sites."""
        try:
            resp = self.session.get(f'{self.api_base}/dcim/sites/', timeout=self.timeout)
            if resp.status_code == 200:
                return {'success': True, 'results': resp.json().get('results', [])}
            return {'success': False, 'error': f'HTTP {resp.status_code}'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def create_site(self, name, slug, status='active', tenant_id=None):
        """Create a new site."""
        payload = {
            'name': name,
            'slug': slug,
            'status': status,
        }
        if tenant_id:
            payload['tenant'] = tenant_id
        try:
            resp = self.session.post(f'{self.api_base}/dcim/sites/', json=payload, timeout=self.timeout)
            if resp.status_code in (200, 201):
                return {'success': True, 'site': resp.json()}
            return {'success': False, 'error': f'HTTP {resp.status_code}: {resp.text}'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    # =========================================================================
    # DEVICES
    # =========================================================================

    def get_devices(self, tenant_id=None, site_id=None):
        """List devices, optionally filtered by tenant or site."""
        params = {}
        if tenant_id:
            params['tenant_id'] = tenant_id
        if site_id:
            params['site_id'] = site_id
        try:
            resp = self.session.get(f'{self.api_base}/dcim/devices/', params=params, timeout=self.timeout)
            if resp.status_code == 200:
                return {'success': True, 'results': resp.json().get('results', [])}
            return {'success': False, 'error': f'HTTP {resp.status_code}'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def get_device(self, device_id):
        """Get a specific device."""
        try:
            resp = self.session.get(f'{self.api_base}/dcim/devices/{device_id}/', timeout=self.timeout)
            if resp.status_code == 200:
                return {'success': True, 'device': resp.json()}
            return {'success': False, 'error': f'HTTP {resp.status_code}'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def create_device(self, name, device_role_id, device_type_id, site_id, tenant_id=None,
                      status='active', comments=''):
        """Create a new device in NetBox."""
        payload = {
            'name': name,
            'role': device_role_id,
            'device_type': device_type_id,
            'site': site_id,
            'status': status,
            'comments': comments,
        }
        if tenant_id:
            payload['tenant'] = tenant_id
        try:
            resp = self.session.post(f'{self.api_base}/dcim/devices/', json=payload, timeout=self.timeout)
            if resp.status_code in (200, 201):
                return {'success': True, 'device': resp.json()}
            return {'success': False, 'error': f'HTTP {resp.status_code}: {resp.text}'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def get_device_roles(self):
        """List all device roles."""
        try:
            resp = self.session.get(f'{self.api_base}/dcim/device-roles/', timeout=self.timeout)
            if resp.status_code == 200:
                return {'success': True, 'results': resp.json().get('results', [])}
            return {'success': False, 'error': f'HTTP {resp.status_code}'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def get_device_types(self):
        """List all device types."""
        try:
            resp = self.session.get(f'{self.api_base}/dcim/device-types/', timeout=self.timeout)
            if resp.status_code == 200:
                return {'success': True, 'results': resp.json().get('results', [])}
            return {'success': False, 'error': f'HTTP {resp.status_code}'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    # =========================================================================
    # INTERFACES
    # =========================================================================

    def get_device_interfaces(self, device_id):
        """Get all interfaces for a device."""
        try:
            resp = self.session.get(
                f'{self.api_base}/dcim/interfaces/',
                params={'device_id': device_id},
                timeout=self.timeout
            )
            if resp.status_code == 200:
                return {'success': True, 'results': resp.json().get('results', [])}
            return {'success': False, 'error': f'HTTP {resp.status_code}'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def create_interface(self, device_id, name, iface_type='other', enabled=True,
                         description='', mtu=None, mode=None):
        """Create an interface on a device."""
        payload = {
            'device': device_id,
            'name': name,
            'type': iface_type,
            'enabled': enabled,
            'description': description,
        }
        if mtu:
            payload['mtu'] = mtu
        if mode:
            payload['mode'] = mode
        try:
            resp = self.session.post(f'{self.api_base}/dcim/interfaces/', json=payload, timeout=self.timeout)
            if resp.status_code in (200, 201):
                return {'success': True, 'interface': resp.json()}
            return {'success': False, 'error': f'HTTP {resp.status_code}: {resp.text}'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    # =========================================================================
    # IP ADDRESSES
    # =========================================================================

    def get_ip_addresses(self, device_id=None):
        """List IP addresses, optionally filtered by device."""
        params = {}
        if device_id:
            params['device_id'] = device_id
        try:
            resp = self.session.get(f'{self.api_base}/ipam/ip-addresses/', params=params, timeout=self.timeout)
            if resp.status_code == 200:
                return {'success': True, 'results': resp.json().get('results', [])}
            return {'success': False, 'error': f'HTTP {resp.status_code}'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def create_ip_address(self, address, status='active', tenant_id=None, description='',
                          interface_id=None, role=None):
        """Create a new IP address record."""
        payload = {
            'address': address,
            'status': status,
            'description': description,
        }
        if tenant_id:
            payload['tenant'] = tenant_id
        if interface_id:
            payload['assigned_object_type'] = 'dcim.interface'
            payload['assigned_object_id'] = interface_id
        if role:
            payload['role'] = role
        try:
            resp = self.session.post(f'{self.api_base}/ipam/ip-addresses/', json=payload, timeout=self.timeout)
            if resp.status_code in (200, 201):
                return {'success': True, 'ip_address': resp.json()}
            return {'success': False, 'error': f'HTTP {resp.status_code}: {resp.text}'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    # =========================================================================
    # VLANS
    # =========================================================================

    def get_vlans(self, tenant_id=None, site_id=None):
        """List VLANs."""
        params = {}
        if tenant_id:
            params['tenant_id'] = tenant_id
        if site_id:
            params['site_id'] = site_id
        try:
            resp = self.session.get(f'{self.api_base}/ipam/vlans/', params=params, timeout=self.timeout)
            if resp.status_code == 200:
                return {'success': True, 'results': resp.json().get('results', [])}
            return {'success': False, 'error': f'HTTP {resp.status_code}'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def create_vlan(self, vid, name, status='active', site_id=None, tenant_id=None, description=''):
        """Create a VLAN."""
        payload = {
            'vid': vid,
            'name': name,
            'status': status,
            'description': description,
        }
        if site_id:
            payload['site'] = site_id
        if tenant_id:
            payload['tenant'] = tenant_id
        try:
            resp = self.session.post(f'{self.api_base}/ipam/vlans/', json=payload, timeout=self.timeout)
            if resp.status_code in (200, 201):
                return {'success': True, 'vlan': resp.json()}
            return {'success': False, 'error': f'HTTP {resp.status_code}: {resp.text}'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    # =========================================================================
    # PREFIXES
    # =========================================================================

    def get_prefixes(self, tenant_id=None):
        """List prefixes."""
        params = {}
        if tenant_id:
            params['tenant_id'] = tenant_id
        try:
            resp = self.session.get(f'{self.api_base}/ipam/prefixes/', params=params, timeout=self.timeout)
            if resp.status_code == 200:
                return {'success': True, 'results': resp.json().get('results', [])}
            return {'success': False, 'error': f'HTTP {resp.status_code}'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def create_prefix(self, prefix, status='active', tenant_id=None, description='', site_id=None):
        """Create a prefix."""
        payload = {
            'prefix': prefix,
            'status': status,
            'description': description,
        }
        if tenant_id:
            payload['tenant'] = tenant_id
        if site_id:
            payload['site'] = site_id
        try:
            resp = self.session.post(f'{self.api_base}/ipam/prefixes/', json=payload, timeout=self.timeout)
            if resp.status_code in (200, 201):
                return {'success': True, 'prefix': resp.json()}
            return {'success': False, 'error': f'HTTP {resp.status_code}: {resp.text}'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    # =========================================================================
    # CABLES / CONNECTIONS
    # =========================================================================

    def get_cables(self):
        """List cables (connections between interfaces)."""
        try:
            resp = self.session.get(f'{self.api_base}/dcim/cables/', timeout=self.timeout)
            if resp.status_code == 200:
                return {'success': True, 'results': resp.json().get('results', [])}
            return {'success': False, 'error': f'HTTP {resp.status_code}'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def create_cable(self, termination_a_type, termination_a_id,
                     termination_b_type, termination_b_id, status='connected'):
        """Create a cable connection between two interfaces."""
        payload = {
            'a_terminations': [{'object_type': termination_a_type, 'object_id': termination_a_id}],
            'b_terminations': [{'object_type': termination_b_type, 'object_id': termination_b_id}],
            'status': status,
        }
        try:
            resp = self.session.post(f'{self.api_base}/dcim/cables/', json=payload, timeout=self.timeout)
            if resp.status_code in (200, 201):
                return {'success': True, 'cable': resp.json()}
            return {'success': False, 'error': f'HTTP {resp.status_code}: {resp.text}'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    # =========================================================================
    # SYNC: Push local device data to NetBox
    # =========================================================================

    def sync_device_to_netbox(self, device_name, device_type, vendor, ip_address=None,
                               tenant_name=None, site_name='Main Site'):
        """
        Sync a local device to NetBox - create tenant, site, and device if needed.
        Returns the NetBox device ID.
        """
        # Get or create tenant
        tenant_id = None
        if tenant_name:
            tenant_result = self.get_or_create_tenant(tenant_name)
            if tenant_result['success']:
                tenant_id = tenant_result['tenant']['id']

        # Get or create site
        site_id = None
        sites_result = self.get_sites()
        if sites_result['success']:
            for site in sites_result['results']:
                if site['name'] == site_name:
                    site_id = site['id']
                    break
        if not site_id:
            site_slug = site_name.lower().replace(' ', '-')
            site_result = self.create_site(site_name, site_slug, tenant_id=tenant_id)
            if site_result['success']:
                site_id = site_result['site']['id']

        if not site_id:
            return {'success': False, 'error': 'Could not create or find site'}

        # Get device role (use first available or create)
        device_role_id = None
        roles_result = self.get_device_roles()
        if roles_result['success'] and roles_result['results']:
            device_role_id = roles_result['results'][0]['id']

        # Get device type (use first available)
        device_type_id = None
        types_result = self.get_device_types()
        if types_result['success'] and types_result['results']:
            # Try to find matching type
            for dt in types_result['results']:
                if vendor.lower() in dt.get('model', '').lower() or vendor.lower() in dt.get('manufacturer', {}).get('name', '').lower():
                    device_type_id = dt['id']
                    break
            if not device_type_id and types_result['results']:
                device_type_id = types_result['results'][0]['id']

        if not device_role_id or not device_type_id:
            return {'success': False, 'error': 'No device roles or types configured in NetBox'}

        # Check if device already exists
        devices_result = self.get_devices(tenant_id=tenant_id)
        if devices_result['success']:
            for dev in devices_result['results']:
                if dev['name'] == device_name:
                    return {'success': True, 'device_id': dev['id'], 'created': False}

        # Create device
        create_result = self.create_device(
            name=device_name,
            device_role_id=device_role_id,
            device_type_id=device_type_id,
            site_id=site_id,
            tenant_id=tenant_id,
            comments=f'Auto-synced from Network Sentinel. Vendor: {vendor}, Type: {device_type}'
        )
        if create_result['success']:
            device_id = create_result['device']['id']

            # Add IP address if provided
            if ip_address:
                self.create_ip_address(
                    address=self.format_ipam_address(ip_address),
                    tenant_id=tenant_id,
                    description=f'Management IP for {device_name}'
                )

            return {'success': True, 'device_id': device_id, 'created': True}

        return {'success': False, 'error': create_result.get('error', 'Unknown error')}

    def get_network_overview(self, tenant_name=None):
        """Get a comprehensive network overview from NetBox."""
        overview = {
            'tenants': [],
            'sites': [],
            'devices': [],
            'vlans': [],
            'prefixes': [],
            'ip_addresses': [],
        }

        tenant_id = None
        if tenant_name:
            tenants = self.get_tenants()
            if tenants['success']:
                overview['tenants'] = tenants['results']
                for t in tenants['results']:
                    if t['name'] == tenant_name:
                        tenant_id = t['id']

        sites = self.get_sites()
        if sites['success']:
            overview['sites'] = sites['results']

        devices = self.get_devices(tenant_id=tenant_id)
        if devices['success']:
            overview['devices'] = devices['results']

        vlans = self.get_vlans(tenant_id=tenant_id)
        if vlans['success']:
            overview['vlans'] = vlans['results']

        prefixes = self.get_prefixes(tenant_id=tenant_id)
        if prefixes['success']:
            overview['prefixes'] = prefixes['results']

        ips = self.get_ip_addresses()
        if ips['success']:
            overview['ip_addresses'] = ips['results']

        return {'success': True, 'overview': overview}


def get_netbox_connector(user_settings):
    """Factory function to create a NetBox connector from user settings."""
    return NetBoxConnector(
        netbox_url=user_settings['netbox_url'] if user_settings else 'http://127.0.0.1:8000',
        api_token=user_settings['netbox_token'] if user_settings else ''
    )
