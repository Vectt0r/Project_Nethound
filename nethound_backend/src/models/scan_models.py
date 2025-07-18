from pydantic import BaseModel
from typing import List, Optional

class ScanRequest(BaseModel):
    ip: str
    ports: str
    protocol: str  = "TCP"

class ScanResponse(BaseModel):
    ip: str
    port: int
    state: str
    banner: Optional[str] = None