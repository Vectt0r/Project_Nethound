from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from routers import scan_router
from routers import monitor_router

app = FastAPI(title="Nethound", description="Network Reconnaissance Tool", version="1.3.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scan_router.router, prefix="/scan", tags=["Scanner"])
app.include_router(monitor_router.router, prefix="/monitor", tags=["Monitor"])

app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/", include_in_schema=False)
async def root():
    return FileResponse("static/index.html")

@app.get("/health", tags=["Health"])
async def health():
    return {"status": "ok", "version": "1.3.0"}
