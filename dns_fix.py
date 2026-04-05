import socket

def patch_dns():
    print("[DNS FIX] Patching socket.getaddrinfo to force IPv4 resolution...")
    _orig_getaddrinfo = socket.getaddrinfo

    def new_getaddrinfo(*args, **kwargs):
        if len(args) >= 1:
            kwargs['family'] = socket.AF_INET
        return _orig_getaddrinfo(*args, **kwargs)

    socket.getaddrinfo = new_getaddrinfo

patch_dns()
