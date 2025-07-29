import ipaddress
import re
from pydantic import BaseModel
from typing import List, Optional

def validate_ip(ip: str) -> bool:
    if not ip:
        return False
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        pass
    host_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$'
    return bool(re.match(host_pattern, ip))

def parse_ports(port_input: str) -> Optional[List[int]]:

    print("[DEBUG] parse_ports foi chamada com:", port_input)

    ports = set()  # evita duplicatas
    if not port_input:
        return None

    for part in port_input.split(','):
        part = part.strip()
        if '-' in part:
            try:
                start_str, end_str = part.split('-')
                start, end = int(start_str.strip()), int(end_str.strip())
                if 1 <= start <= 65535 and 1 <= end <= 65535 and start <= end:
                    ports.update(range(start, end + 1))
                else:
                    return None
            except ValueError:
                return None
        else:
            try:
                port = int(part)
                if 1 <= port <= 65535:
                    ports.add(port)
                else:
                    return None
            except ValueError:
                return None

    return sorted(ports)


