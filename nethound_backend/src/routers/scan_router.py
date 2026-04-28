from fastapi import APIRouter, HTTPException
from typing import List
from utils.validate import validate_ip, parse_ports
from models.scan_models import ScanRequest, ScanResponse, SSLInfo, ScanResults
from services.scanner import PortScanner
from concurrent.futures import ThreadPoolExecutor
import asyncio
import random
import time
import uuid
from datetime import datetime

router = APIRouter()

_scan_history: List[dict] = []

PORT_PRESETS = {
    "web":      "80,443,8080,8443,8000,8888,3000,4000,5000,9000",
    "common":   "21,22,23,25,53,80,110,143,443,445,3306,3389,5432,6379,8080,8443,27017",
    "database": "1433,1521,3306,5432,5984,6379,7474,9200,27017,28017",
    "remote":   "22,23,3389,5900,5901,5985,5986",
    "mail":     "25,110,143,465,587,993,995",
    "top100":   "7,9,13,21,22,23,25,26,37,53,79,80,81,88,106,110,111,113,119,135,139,143,144,179,199,389,427,443,444,445,465,513,514,515,543,544,548,554,587,631,646,873,990,993,995,1080,1110,1194,1433,1521,1723,1755,1900,2000,2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000,6001,6646,7070,8000,8008,8009,8080,8081,8443,8888,9100,9999,10000,32768,49152,49153,49154,49155,49156,49157",
}


@router.get("/presets")
async def get_presets():
    return PORT_PRESETS


@router.get("/history")
async def get_history():
    return list(reversed(_scan_history[-20:]))


@router.delete("/history")
async def clear_history():
    _scan_history.clear()
    return {"message": "History cleared"}


@router.post("/", response_model=ScanResults)
async def scan_port(request: ScanRequest):
    if not validate_ip(request.ip):
        raise HTTPException(status_code=400, detail="IP ou Host Inválido")

    if request.protocol not in ["TCP", "UDP"]:
        raise HTTPException(status_code=400, detail="Protocolo inválido, apenas TCP ou UDP")

    ports = parse_ports(request.ports)
    if not ports:
        raise HTTPException(status_code=400, detail="Formato de portas inválido")

    if request.randomize:
        random.shuffle(ports)

    start_time = time.time()

    def scan_one(port: int):
        scanner = PortScanner(request.ip, port, silent_mode=request.silent_mode)
        if request.protocol.upper() == "TCP":
            result = scanner.scan_tcp_port()
        else:
            result = scanner.scan_udp_port()
        return port, result

    loop = asyncio.get_event_loop()
    max_workers = min(50, len(ports))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [loop.run_in_executor(executor, scan_one, port) for port in ports]
        raw_results = await asyncio.gather(*futures)

    results = []
    open_ports = 0

    for port, result in raw_results:
        if result["state"] in ["open", "open|filtered"]:
            open_ports += 1
        results.append(ScanResponse(
            ip=request.ip,
            port=port,
            protocol=request.protocol,
            state=result["state"],
            banner=result.get("banner"),
            ssl_info=SSLInfo(**result.get("ssl_info", {})) if result.get("ssl_info") else None,
        ))

    results.sort(key=lambda r: r.port)

    stats = {
        "total_ports": len(ports),
        "open_ports": open_ports,
        "closed_ports": len(ports) - open_ports,
        "scan_duration_seconds": round(time.time() - start_time, 2),
        "randomized": request.randomize,
        "workers": max_workers,
    }

    _scan_history.append({
        "id": str(uuid.uuid4())[:8],
        "ip": request.ip,
        "ports": request.ports,
        "protocol": request.protocol,
        "silent_mode": request.silent_mode,
        "randomize": request.randomize,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "stats": stats,
    })

    return ScanResults(results=results, stats=stats)
