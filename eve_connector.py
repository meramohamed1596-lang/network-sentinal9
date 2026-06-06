"""
EVE-NG API Connector Module
Handles interactions with the EVE-NG REST API for lab, node, topology,
startup-config, and console metadata operations.
"""

from urllib.parse import quote, urlparse

import requests


class EVENGConnector:
    """Connector for EVE-NG REST API."""

    def __init__(
        self,
        server_url='http://127.0.0.1',
        username='admin',
        password='eve',
        lab_path='',
        verify_ssl=False,
        session=None,
    ):
        self.server_url = server_url.rstrip('/')
        self.api_base = f'{self.server_url}/api'
        self.username = username
        self.password = password
        self.lab_path = lab_path
        self.verify_ssl = verify_ssl
        self.session = session or requests.Session()
        self.timeout = 15
        self.authenticated = False
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        })

    def _normalize_lab_path(self, lab_path=None):
        path = (lab_path or self.lab_path or '').strip()
        if not path:
            return ''
        return '/' + quote(path.strip('/'), safe='/')

    def _response_result(self, response, success_key='data'):
        try:
            data = response.json()
        except ValueError:
            return {'success': False, 'error': response.text or f'HTTP {response.status_code}'}

        if 200 <= response.status_code < 300 and data.get('status') != 'fail':
            result = {'success': True}
            if success_key and success_key in data:
                result[success_key] = data.get(success_key)
            if 'message' in data:
                result['message'] = data.get('message')
            if 'code' in data:
                result['code'] = data.get('code')
            return result

        return {
            'success': False,
            'error': data.get('message') or data.get('error') or f'HTTP {response.status_code}',
            'code': data.get('code', response.status_code),
        }

    def _request(self, method, path, **kwargs):
        if not self.authenticated and path != '/auth/login':
            login_result = self.login()
            if not login_result['success']:
                return login_result

        try:
            response = self.session.request(
                method,
                f'{self.api_base}{path}',
                timeout=self.timeout,
                verify=self.verify_ssl,
                **kwargs,
            )
            return self._response_result(response)
        except requests.exceptions.ConnectionError:
            return {'success': False, 'error': 'Cannot connect to EVE-NG. Make sure the EVE-NG VM is running and reachable.'}
        except requests.exceptions.Timeout:
            return {'success': False, 'error': 'Connection timeout'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def login(self):
        payload = {'username': self.username, 'password': self.password}
        try:
            response = self.session.request(
                'POST',
                f'{self.api_base}/auth/login',
                json=payload,
                timeout=self.timeout,
                verify=self.verify_ssl,
            )
            result = self._response_result(response, success_key=None)
            self.authenticated = result['success']
            return result
        except requests.exceptions.ConnectionError:
            return {'success': False, 'error': 'Cannot connect to EVE-NG. Make sure the EVE-NG VM is running and reachable.'}
        except requests.exceptions.Timeout:
            return {'success': False, 'error': 'Connection timeout'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def test_connection(self):
        login_result = self.login()
        if not login_result['success']:
            return login_result

        status_result = self._request('GET', '/status')
        if status_result['success']:
            return {
                'success': True,
                'version': status_result.get('data', {}).get('version', 'EVE-NG'),
                'status': status_result.get('data', {}),
                'message': 'Connected to EVE-NG',
            }
        return status_result

    def get_lab(self, lab_path=None):
        path = self._normalize_lab_path(lab_path)
        if not path:
            return {'success': False, 'error': 'No EVE-NG lab path specified'}
        return self._request('GET', f'/labs{path}')

    def get_nodes(self, lab_path=None):
        path = self._normalize_lab_path(lab_path)
        if not path:
            return {'success': False, 'error': 'No EVE-NG lab path specified'}
        result = self._request('GET', f'/labs{path}/nodes')
        if result['success']:
            nodes = result.get('data') or {}
            result['nodes'] = [self._normalize_node(node_id, node) for node_id, node in nodes.items()]
        return result

    def get_node(self, node_id, lab_path=None):
        path = self._normalize_lab_path(lab_path)
        if not path:
            return {'success': False, 'error': 'No EVE-NG lab path specified'}
        result = self._request('GET', f'/labs{path}/nodes/{node_id}')
        if result['success']:
            result['node'] = self._normalize_node(str(node_id), result.get('data') or {})
        return result

    def start_node(self, node_id, lab_path=None):
        path = self._normalize_lab_path(lab_path)
        if not path:
            return {'success': False, 'error': 'No EVE-NG lab path specified'}
        return self._request('GET', f'/labs{path}/nodes/{node_id}/start')

    def stop_node(self, node_id, lab_path=None):
        path = self._normalize_lab_path(lab_path)
        if not path:
            return {'success': False, 'error': 'No EVE-NG lab path specified'}
        return self._request('GET', f'/labs{path}/nodes/{node_id}/stop')

    def start_all_nodes(self, lab_path=None):
        path = self._normalize_lab_path(lab_path)
        if not path:
            return {'success': False, 'error': 'No EVE-NG lab path specified'}
        return self._request('GET', f'/labs{path}/nodes/start')

    def stop_all_nodes(self, lab_path=None):
        path = self._normalize_lab_path(lab_path)
        if not path:
            return {'success': False, 'error': 'No EVE-NG lab path specified'}
        return self._request('GET', f'/labs{path}/nodes/stop')

    def get_lab_topology(self, lab_path=None):
        path = self._normalize_lab_path(lab_path)
        if not path:
            return {'success': False, 'error': 'No EVE-NG lab path specified'}
        return self._request('GET', f'/labs{path}/topology')

    def get_topology_summary(self, lab_path=None):
        nodes_result = self.get_nodes(lab_path)
        if not nodes_result['success']:
            return nodes_result

        topo_result = self.get_lab_topology(lab_path)
        if not topo_result['success']:
            return topo_result

        nodes = nodes_result.get('nodes', [])
        links = []
        network_nodes = {}
        for item in topo_result.get('data') or []:
            source_id = self._topology_endpoint_id(item.get('source'), item.get('source_type'))
            target_id = self._topology_endpoint_id(item.get('destination'), item.get('destination_type'))
            if not source_id or not target_id:
                continue

            if item.get('source_type') == 'network':
                network_nodes[source_id] = self._network_node(source_id, item.get('source_label'))
            if item.get('destination_type') == 'network':
                network_nodes[target_id] = self._network_node(target_id, item.get('destination_label'))

            links.append({
                'id': f'{source_id}-{target_id}-{len(links) + 1}',
                'source_id': source_id,
                'target_id': target_id,
                'source_port': item.get('source_label', ''),
                'target_port': item.get('destination_label', ''),
                'source_name': source_id,
                'target_name': target_id,
            })

        all_nodes = nodes + list(network_nodes.values())
        return {
            'success': True,
            'topology': {
                'nodes': all_nodes,
                'links': links,
                'node_count': len(nodes),
                'link_count': len(links),
            }
        }

    def upload_node_config(self, node_id, config_text, lab_path=None):
        path = self._normalize_lab_path(lab_path)
        if not path:
            return {'success': False, 'error': 'No EVE-NG lab path specified'}
        payload = {'id': str(node_id), 'data': config_text}
        upload_result = self._request('PUT', f'/labs{path}/configs/{node_id}', json=payload)
        if not upload_result['success']:
            return upload_result

        enable_payload = {'id': str(node_id), 'config': 1}
        enable_result = self._request('PUT', f'/labs{path}/nodes/{node_id}', json=enable_payload)
        if not enable_result['success']:
            return enable_result

        return {
            'success': True,
            'message': 'Startup configuration uploaded and enabled in EVE-NG',
        }

    def get_node_console(self, node_id, lab_path=None):
        result = self.get_node(node_id, lab_path)
        if not result['success']:
            return result
        node = result.get('node') or {}
        return {
            'success': True,
            'host': node.get('console_host'),
            'port': node.get('console_port'),
            'type': node.get('console_type', 'telnet'),
            'command': node.get('console_command'),
        }

    def _normalize_node(self, node_id, node):
        url = node.get('url', '')
        parsed = urlparse(url) if url else None
        console_host = parsed.hostname if parsed else None
        console_port = parsed.port if parsed else None
        console_type = parsed.scheme if parsed else node.get('console', 'telnet')
        console_command = None
        if console_host and console_port:
            console_command = f'{console_type} {console_host} {console_port}' if console_type == 'telnet' else url

        return {
            'id': str(node.get('id', node_id)),
            'name': node.get('name', f'Node {node_id}'),
            'type': node.get('type', node.get('template', 'unknown')),
            'status': self._status_label(node.get('status')),
            'x': node.get('left', 0),
            'y': node.get('top', 0),
            'console': console_port or 0,
            'console_host': console_host,
            'console_port': console_port,
            'console_type': console_type,
            'console_command': console_command,
            'vendor': self._detect_vendor(node),
        }

    def _status_label(self, status):
        if str(status).lower() in ('2', 'running', 'started'):
            return 'running'
        if str(status).lower() in ('0', 'stopped', 'offline'):
            return 'stopped'
        return str(status or 'unknown')

    def _detect_vendor(self, node):
        combined = ' '.join([
            str(node.get('template', '')),
            str(node.get('image', '')),
            str(node.get('type', '')),
            str(node.get('name', '')),
        ]).lower()
        if any(token in combined for token in ('juniper', 'junos', 'vmx', 'vqfx', 'vsrx')):
            return 'juniper'
        if any(token in combined for token in ('huawei', 'vrp', 'usg')):
            return 'huawei'
        return 'cisco'

    def _topology_endpoint_id(self, endpoint, endpoint_type):
        if not endpoint:
            return None
        endpoint = str(endpoint)
        if endpoint_type == 'node' and endpoint.startswith('node'):
            return endpoint.replace('node', '', 1)
        return endpoint

    def _network_node(self, network_id, label=''):
        return {
            'id': network_id,
            'name': label or network_id,
            'type': 'network',
            'status': 'network',
            'x': 0,
            'y': 0,
            'console': 0,
            'vendor': 'network',
        }


def get_eve_connector(user_settings):
    """Factory function to create an EVE-NG connector from user settings."""
    return EVENGConnector(
        server_url=user_settings['eve_url'] if user_settings and 'eve_url' in user_settings.keys() else 'http://127.0.0.1',
        username=user_settings['eve_username'] if user_settings and 'eve_username' in user_settings.keys() else 'admin',
        password=user_settings['eve_password'] if user_settings and 'eve_password' in user_settings.keys() else 'eve',
        lab_path=user_settings['eve_lab_path'] if user_settings and 'eve_lab_path' in user_settings.keys() else '',
    )
