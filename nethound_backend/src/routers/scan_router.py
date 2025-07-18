from fastapi import APIRouter, HTTPException
from typing import List
from utils.validate import validate_ip, parse_ports
from models.scan_models import ScanRequest, ScanResponse
from services.scanner import PortScanner

router = APIRouter()

@router.post("/", response_model=List[ScanResponse])
async def scan_port(request: ScanRequest):
    if not validate_ip(request.ip):
        raise HTTPException(status_code=400, detail='IP ou Host Inválido')

    ports = parse_ports(request.ports)
    if not ports:
        raise HTTPException(status_code=400, detail='Formato de portas inválido')

    results = []
    for port in ports:
        scanner = PortScanner(request.ip, port)
        if request.protocol.upper() == "UDP":
            result = scanner.scan_udp_port()
        else:
            result = scanner.scan_tcp_port()

        results.append(ScanResponse(
            ip=request.ip,
            port=port,
            state=result['state'],
            banner=result.get('banner')
        ))

    return results