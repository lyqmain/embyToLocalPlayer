"""Match proxy exceptions against URL hosts without DNS lookups."""

import base64
import fnmatch
import ipaddress
import os
import urllib.parse
import urllib.request

try:
    import _scproxy
except ImportError:
    _scproxy = None


def _matches_network(host, pattern):
    try:
        address = ipaddress.ip_address(host)
        network, prefix = pattern.split('/', 1)
        # macOS also accepts abbreviated IPv4 networks, e.g. 169.254/16.
        if ':' not in network:
            pieces = network.split('.')
            if all(piece.isdigit() for piece in pieces) and len(pieces) < 4:
                network = '.'.join(pieces + ['0'] * (4 - len(pieces)))
        return address in ipaddress.ip_network(network + '/' + prefix, strict=False)
    except ValueError:
        return False


def url_bypasses_proxy(url):
    try:
        parts = urllib.parse.urlsplit(url)
        if parts.scheme not in ('http', 'https') or not parts.hostname:
            return False
        host = parts.hostname.lower().rstrip('.')
        port = parts.port
    except ValueError:
        return False
    endpoint = ('[' + host + ']' if ':' in host else host)
    if port is not None:
        endpoint += ':' + str(port)
    settings = _scproxy._get_proxy_settings() if _scproxy else {}
    try:
        ipaddress.ip_address(host)
        literal_ip = True
    except ValueError:
        literal_ip = False
    if not literal_ip and settings.get('exclude_simple') and '.' not in host:
        return True
    for pattern in settings.get('exceptions', []):
        pattern = pattern.strip().lower()
        if not pattern:
            continue
        if '/' in pattern:
            if _matches_network(host, pattern):
                return True
        elif fnmatch.fnmatchcase(host, pattern) or fnmatch.fnmatchcase(endpoint, pattern):
            return True
    # Keep existing environment exceptions as well as macOS exceptions.
    for pattern in os.environ.get('no_proxy', os.environ.get('NO_PROXY', '')).split(','):
        pattern = pattern.strip().lower()
        if not pattern:
            continue
        if pattern == '*':
            return True
        if '/' in pattern:
            if _matches_network(host, pattern):
                return True
        else:
            pattern = pattern.lstrip('.')
            if (host == pattern or endpoint == pattern or host.endswith('.' + pattern)
                    or endpoint.endswith('.' + pattern)):
                return True
    return False


class BypassProxyHandler(urllib.request.ProxyHandler):
    """Apply macOS exceptions even when ETLP explicitly sets a proxy."""

    def proxy_open(self, req, proxy, type):
        if _scproxy is None:
            return super().proxy_open(req, proxy, type)
        if url_bypasses_proxy(req.full_url):
            return None
        # An explicit ETLP proxy has already been applied to this Request.
        if req.has_proxy() or getattr(req, '_tunnel_host', None):
            return None
        # Same forwarding/authentication behavior as urllib's ProxyHandler,
        # without its DNS-based macOS CIDR exception check.
        orig_type = req.type
        proxy_type, user, password, hostport = urllib.request._parse_proxy(proxy)
        proxy_type = proxy_type or orig_type
        if user and password:
            credentials = '{}:{}'.format(urllib.parse.unquote(user), urllib.parse.unquote(password))
            credentials = base64.b64encode(credentials.encode()).decode('ascii')
            req.add_header('Proxy-authorization', 'Basic ' + credentials)
        req.set_proxy(urllib.parse.unquote(hostport), proxy_type)
        if orig_type == proxy_type or orig_type == 'https':
            return None
        return self.parent.open(req, timeout=req.timeout)
