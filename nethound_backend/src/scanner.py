# src/scanner.py
import socket

def scan_tcp_port(ip: str, port: int) -> str:
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        result = s.connect_ex((ip, port))
        return "open" if result == 0 else "closed"
    return None
