from fastapi import APIRouter, HTTPException
from typing import List
from utils.validate import validate_ip, parse_ports
from models.scan_models import ScanRequest, ScanResponse, SSLInfo, ScanResults
from services.scanner import PortScanner
import time

router = APIRouter()

@router.post("/", response_model=ScanResults)
async def scan_port(request: ScanRequest):
    if not validate_ip(request.ip):
        raise HTTPException(status_code=400, detail='IP ou Host Inválido')

    if request.protocol not in ['TCP', 'UDP']:
        raise HTTPException(status_code=400, detail='Protocolo inválido, apenas TCP ou UDP')

    ports = parse_ports(request.ports)
    if not ports:
        raise HTTPException(status_code=400, detail='Formato de portas inválido')

    start_time = time.time()
    results = []
    open_ports = 0

    for port in ports:
        scanner = PortScanner(request.ip, port, silent_mode=request.silent_mode)

        if request.protocol.upper() == "TCP":
            result = scanner.scan_tcp_port()
        else:
            result = scanner.scan_udp_port()

        if result['state'] in ['open', 'open|filtered']:
            open_ports += 1

        results.append(ScanResponse(
            ip=request.ip,
            port=port,
            protocol=request.protocol,
            state=result['state'],
            banner=result.get('banner'),
            ssl_info=SSLInfo(**result.get('ssl_info', {})) if result.get('ssl_info') else None,
        ))

    stats = {
        'total_ports': len(ports),
        'open_ports': open_ports,
        'closed_ports': len(ports) - open_ports,
        'scan_duration_seconds': round(time.time() - start_time, 2),
    }

    return ScanResults(results=results, stats=stats)
