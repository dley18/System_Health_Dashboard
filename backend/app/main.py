from collections import deque
import asyncio, time, psutil

from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware


app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"], # Vite dev server
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

cpu_buf = deque(maxlen=900) # 15 minutes @1hz

async def sampler():
    while True:
        cpu = {
            "t": time.time(),
            "total": psutil.cpu_percent(interval=None),
            "per_core": psutil.cpu_percent(interval=None, percpu=True),
        }
        cpu_buf.append(cpu)
        await asyncio.sleep(1)

@app.on_event("startup")
async def _startup():
    asyncio.create_task(sampler())

@app.get("/health")
def health():
    return {"ok": True}

@app.get("/metrics/now")
def metrics_now():
    return {"cpu": cpu_buf[-1] if cpu_buf else None}

@app.websocket("/metrics/stream")
async def stream(ws: WebSocket):
    await ws.accept()
    last_len = 0
    while True:
        if len(cpu_buf) != last_len and cpu_buf:
            await ws.send_json({"cpu": cpu_buf[-1]})
            last_len = len(cpu_buf)
        await asyncio.sleep(0.25)