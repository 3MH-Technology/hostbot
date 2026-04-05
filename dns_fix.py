import socket

def patch_dns():
    print("[DNS FIX] Patching socket.getaddrinfo to force IPv4 resolution...")
    _orig_getaddrinfo = socket.getaddrinfo

    def new_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
        # Force AF_INET (IPv4) resolution
        return _orig_getaddrinfo(host, port, socket.AF_INET, type, proto, flags)

    socket.getaddrinfo = new_getaddrinfo

patch_dns()
