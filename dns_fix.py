import socket
import struct
import random
import os

_orig_getaddrinfo = socket.getaddrinfo
_dns_cache = {}
_DNS_SERVERS = ['8.8.8.8', '8.8.4.4', '1.1.1.1']


def _raw_dns_resolve(hostname, dns_server='8.8.8.8'):
    try:
        tid = random.randint(0, 65535)
        header = struct.pack('!HHHHHH', tid, 0x0100, 1, 0, 0, 0)
        question = b''
        for label in hostname.encode('ascii').split(b'.'):
            question += bytes([len(label)]) + label
        question += b'\x00' + struct.pack('!HH', 1, 1)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        sock.sendto(header + question, (dns_server, 53))
        data, _ = sock.recvfrom(4096)
        sock.close()
        an_count = struct.unpack('!H', data[6:8])[0]
        if an_count == 0:
            return None
        pos = 12
        while data[pos] != 0:
            pos += data[pos] + 1
        pos += 5
        for _ in range(an_count):
            if data[pos] & 0xC0 == 0xC0:
                pos += 2
            else:
                while data[pos] != 0:
                    pos += data[pos] + 1
                pos += 1
            rtype, _, _, rdlen = struct.unpack('!HHIH', data[pos:pos + 10])
            pos += 10
            if rtype == 1 and rdlen == 4:
                return '.'.join(str(b) for b in data[pos:pos + 4])
            pos += rdlen
        return None
    except Exception:
        return None


def _patched_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    try:
        return _orig_getaddrinfo(host, port, family, type, proto, flags)
    except socket.gaierror as e:
        if not isinstance(host, str) or host.replace('.', '').isdigit():
            raise e
        cache_key = f"{host}:{port}"
        if cache_key in _dns_cache:
            ip = _dns_cache[cache_key]
        else:
            ip = None
            for dns in _DNS_SERVERS:
                ip = _raw_dns_resolve(host, dns)
                if ip:
                    _dns_cache[cache_key] = ip
                    break
        if ip:
            results = []
            if type == 0 or type == socket.SOCK_STREAM:
                results.append((socket.AF_INET, socket.SOCK_STREAM, 6, '', (ip, port or 443)))
            if type == 0 or type == socket.SOCK_DGRAM:
                results.append((socket.AF_INET, socket.SOCK_DGRAM, 17, '', (ip, port or 443)))
            if results:
                return results
        raise e


def _fix_resolv_conf():
    dns_content = "nameserver 8.8.8.8\nnameserver 8.8.4.4\nnameserver 1.1.1.1\n"
    try:
        path = '/etc/resolv.conf'
        need_fix = False
        if os.path.exists(path):
            with open(path, 'r') as f:
                content = f.read().strip()
            if not content or 'nameserver' not in content:
                need_fix = True
        else:
            need_fix = True
        if need_fix:
            with open(path, 'w') as f:
                f.write(dns_content)
    except (PermissionError, OSError):
        pass


def apply():
    _fix_resolv_conf()
    socket.getaddrinfo = _patched_getaddrinfo


apply()
