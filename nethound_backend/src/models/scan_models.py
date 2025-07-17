from pydantic import BaseModel
from typing import List

class ScanRequest(BaseModel):
    ip: str
    ports: List[int]

class ScanResponse(BaseModel):
    ip: str
    port: int
    state: str