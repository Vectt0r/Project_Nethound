from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
from src.scanner import scan_tcp_port

app = FastAPI(title="Nethound Backend", description="Nethound Backend", version="1.0")

class ScanRequest(BaseModel):
     ip: str
     port: int

class ScanResponse(BaseModel):
     ip: str
     port: int
     state: str

@app.post('/scan', response_model=ScanResponse)
async def scan_port(request: ScanRequest):
 if not (1 <= request.port <= 65535):
    raise HTTPException(status_code=400, detail='Porta inválida. Use um valor entre 1 e 65535.')
 state = scan_tcp_port(request.ip, request.port)
 return ScanResponse(ip=request.ip, port=request.port, state=state)

# Isso só é necessário se você quiser rodar o arquivo diretamente com `python main.py`
# if __name__ == '__main__':
#     import uvicorn
#
#     uvicorn.run("src.main:app", host="0.0.0.0", port=8000, reload=True)
