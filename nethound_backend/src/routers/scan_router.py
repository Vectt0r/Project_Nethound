from fastapi import APIRouter, HTTPException
from typing import List
from utils.validate import validate_ip
from models.scan_models import ScanRequest, ScanResponse
from services.scanner import PortScanner

router = APIRouter()

@router.post("/", response_model=List[ScanResponse])
async def scan_port(request: ScanRequest):
    if not validate_ip(request.ip):
        raise HTTPException(status_code=400, detail='IP ou Host Inválido')

    results = []
    for port in request.ports:
        if not (1 <= port <= 65535):
            raise HTTPException(status_code=400, detail=f'Porta inválida: {port}')
        state = PortScanner.scan_tcp_port(request.ip, port)
        results.append({"ip": request.ip, "port": port, "state": state})

    return results