import socket
from pydantic import BaseModel

class PortScanner:
    def __init__(self, ip: str, port: int, timeout: float = 1.0):
        self.ip = ip
        self.port = port
        self.timeout = timeout

    def scan_tcp_port(self) -> str:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(self.timeout)
            result = s.connect_ex((self.ip, self.port))
            return "open" if result == 0 else "closed"
