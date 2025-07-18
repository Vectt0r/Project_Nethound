import socket
from typing import Optional, Dict

class PortScanner:
    def __init__(self, ip: str, port: int, timeout: float = 1.0):
        self.ip = ip
        self.port = port
        self.timeout = timeout

    def scan_tcp_port(self) -> Dict[str, Optional[str]]:
        for proto in ['HTTP', 'SSH', 'FTP', 'SMTP']:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(self.timeout)
                    s.connect((self.ip, self.port))

                    if proto == 'HTTP':
                        s.sendall(b'HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n')
                    elif proto == 'SSH':
                        s.sendall(b'SSH-2.0-Test\r\n')
                    elif proto == 'FTP':
                        s.sendall(b'USER anonymous\r\n')
                    elif proto == 'SMTP':
                        s.sendall(b'HELO localhost\r\n\r\n')

                    banner = s.recv(1024).decode(errors="ignore").strip()
                    if banner:
                        return {'state': 'open', 'banner': banner}
            except Exception:
                continue

        return {'state': 'open', 'banner': None}

    def scan_udp_port(self) -> Dict[str, Optional[str]]:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(self.timeout)
                s.sendto(b'', (self.ip, self.port))
                try:
                    data, _ = s.recvfrom(1024)
                    return {'state': 'open|filtered', 'banner': data.decode(errors="ignore").strip()}
                except socket.timeout:
                    return {'state': 'open|filtered', 'banner': None}
        except Exception:
            return {'state': 'close', 'banner': None}
