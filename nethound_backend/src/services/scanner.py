import socket
import ssl
import OpenSSL
from datetime import datetime
from typing import Optional, Dict, Any

class PortScanner:
    def __init__(self, ip: str, port: int, silent_mode: bool = False, timeout: float = 1.0):
        self.ip = ip
        self.port = port
        self.silent_mode = silent_mode
        self.timeout = timeout

    def scan_tcp_port(self) -> Dict[str, Optional[Any]]:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect((self.ip, self.port))
                result = {'state': 'open', 'banner': None, 'ssl_info': None}

                # Coleta de informações SSL/TLS
                if self.port in [443, 8443] and not self.silent_mode:
                    try:
                        context = ssl.create_default_context()
                        with socket.create_connection((self.ip, self.port), timeout=2) as sock:
                            with context.wrap_socket(sock, server_hostname=self.ip) as ssock:
                                cert = ssock.getpeercert()
                                cert_bin = ssock.getpeercert(binary_form=True)
                                x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_bin)

                                valid_to_str = cert.get("notAfter")
                                valid_to = datetime.strptime(valid_to_str, "%b %d %H:%M:%S %Y %Z")

                                result["ssl_info"] = {
                                    "cn": dict(x[0] for x in cert.get("subject", []))["commonName"],
                                    "issuer": dict(x[0] for x in cert.get("issuer", []))["organizationName"],
                                    "valid_from": cert.get("notBefore"),
                                    "valid_to": valid_to_str,
                                    "is_valid": valid_to > datetime.utcnow()
                                }
                    except Exception:
                        pass

                # Banner grabbing
                if not self.silent_mode:
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

                                result['banner'] = s.recv(1024).decode(errors="ignore").strip()
                                if result['banner']:
                                    break
                        except Exception:
                            continue

                return result
        except Exception:
            return {'state': 'error', 'banner': None, 'ssl_info': None}

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