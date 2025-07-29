from pydantic import BaseModel
from typing import List, Optional, Dict, Any

class ScanRequest(BaseModel):
    ip: str
    ports: str
    protocol: str  = "TCP"
    silent_mode: bool = False

class SSLInfo(BaseModel):
    cn: Optional[str] = None
    issuer: Optional[str] = None
    valid_from: Optional[str] = None
    valid_to: Optional[str] = None
    is_valid: Optional[bool] = None

class ScanResponse(BaseModel):
    ip: str
    port: int
    state: str
    banner: Optional[str] = None
    ssl_info: Optional[SSLInfo] = None

class ScanResults(BaseModel):
    results: List[ScanResponse]
    stats: Dict[str, Any]