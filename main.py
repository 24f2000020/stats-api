import time
import uuid

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware

EMAIL = "24f2000020@ds.study.iitm.ac.in"

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://dash-y96dll.example.com"],
    allow_methods=["GET", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["X-Request-ID", "X-Process-Time"],
)


# Added after CORS so it wraps it: rejected preflights get the headers too.
@app.middleware("http")
async def request_headers(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    response.headers["X-Request-ID"] = str(uuid.uuid4())
    response.headers["X-Process-Time"] = f"{time.perf_counter() - start:.6f}"
    return response


@app.get("/stats")
def stats(values: str):
    try:
        nums = [int(v) for v in values.split(",") if v.strip()]
    except ValueError:
        raise HTTPException(400, "values must be comma-separated integers")
    if not nums:
        raise HTTPException(400, "values is empty")
    return {
        "email": EMAIL,
        "count": len(nums),
        "sum": sum(nums),
        "min": min(nums),
        "max": max(nums),
        "mean": sum(nums) / len(nums),
    }
