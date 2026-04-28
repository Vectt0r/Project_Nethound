from fastapi import APIRouter, HTTPException
from models.scan_models import PingRequest, PingResult
from utils.validate import validate_ip
from concurrent.futures import ThreadPoolExecutor
import asyncio
import subprocess
import platform
import re
from typing import List

router = APIRouter()

_IS_WINDOWS = platform.system() == "Windows"


def _run_ping(host: str, count: int) -> PingResult:
    try:
        param = ["-n", str(count)] if _IS_WINDOWS else ["-c", str(count), "-W", "2"]
        result = subprocess.run(
            ["ping"] + param + [host],
            capture_output=True,
            text=True,
            timeout=count * 4 + 5,
            encoding="utf-8",
            errors="ignore",
        )

        output = result.stdout + result.stderr
        online = result.returncode == 0

        latency_avg = latency_min = latency_max = None
        packet_loss = 100

        if _IS_WINDOWS:
            # individual times: tempo=Xms or tempo<Xms
            times = re.findall(r"tempo[=<](\d+)ms", output, re.IGNORECASE)
            if times:
                nums = [int(t) for t in times]
                latency_min = float(min(nums))
                latency_max = float(max(nums))
                latency_avg = round(sum(nums) / len(nums), 1)

            # packet loss: Perdidos = N (X%)
            loss_match = re.search(r"Perdidos\s*=\s*\d+\s*\((\d+)%", output, re.IGNORECASE)
            if loss_match:
                packet_loss = int(loss_match.group(1))
            elif online:
                packet_loss = 0
        else:
            times = re.findall(r"time[=<](\d+\.?\d*)\s*ms", output, re.IGNORECASE)
            if times:
                nums = [float(t) for t in times]
                latency_min = round(min(nums), 1)
                latency_max = round(max(nums), 1)
                latency_avg = round(sum(nums) / len(nums), 1)

            loss_match = re.search(r"(\d+)%\s*packet loss", output, re.IGNORECASE)
            if loss_match:
                packet_loss = int(loss_match.group(1))
            elif online:
                packet_loss = 0

        return PingResult(
            host=host,
            online=online,
            latency_avg_ms=latency_avg,
            latency_min_ms=latency_min,
            latency_max_ms=latency_max,
            packet_loss_pct=packet_loss,
        )

    except subprocess.TimeoutExpired:
        return PingResult(host=host, online=False, packet_loss_pct=100, error="timeout")
    except Exception as e:
        return PingResult(host=host, online=False, error=str(e))


@router.post("/ping", response_model=List[PingResult])
async def ping_hosts(request: PingRequest):
    hosts = [h.strip() for h in request.hosts.split(",") if h.strip()]
    if not hosts:
        raise HTTPException(status_code=400, detail="Nenhum host fornecido")
    if len(hosts) > 20:
        raise HTTPException(status_code=400, detail="Máximo de 20 hosts por vez")
    if not (1 <= request.count <= 10):
        raise HTTPException(status_code=400, detail="Count deve ser entre 1 e 10")

    for host in hosts:
        if not validate_ip(host):
            raise HTTPException(status_code=400, detail=f"Host inválido: {host}")

    loop = asyncio.get_event_loop()
    with ThreadPoolExecutor(max_workers=len(hosts)) as executor:
        futures = [loop.run_in_executor(executor, _run_ping, host, request.count) for host in hosts]
        results = await asyncio.gather(*futures)

    return list(results)
