import ipaddress
import re

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