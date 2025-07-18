from fastapi import FastAPI
from src.routers import scan_router

app = FastAPI(title="Nethound Backend", description="Nethound Backend", version="1.1.0")

# Inclui as rotas de scan
app.include_router(scan_router.router, prefix="/scan", tags=["Scanner"])
