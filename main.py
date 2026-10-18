import base64
import os
import time
import uuid
from collections import defaultdict, deque
from pathlib import Path

import jwt
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from pydantic import BaseModel

EMAIL = "24f2000020@ds.study.iitm.ac.in"
EXAM_ORIGIN = "https://exam.sanand.workers.dev"
STARTED = time.time()

# Paths with a strict origin list; every other path allows any origin.
STRICT_ORIGINS = {
    "/stats": {"https://dash-y96dll.example.com"},
    "/ping": {"https://app-b0nmg5.example.com", EXAM_ORIGIN},
}
# path -> requests allowed per 10s per X-Client-Id
RATE_LIMITS = {"/ping": 11, "/orders": 15}
WINDOW = 10.0

app = FastAPI()
hits = defaultdict(deque)  # (path, client) -> request timestamps
request_count = 0
logs = deque(maxlen=1000)


def allowed_origin(path, origin):
    if not origin:
        return None
    strict = STRICT_ORIGINS.get(path)
    if strict is None:
        return "*"
    return origin if origin in strict else None


@app.middleware("http")
async def stack(request: Request, call_next):
    global request_count
    start = time.perf_counter()
    path = request.url.path
    request_id = request.headers.get("x-request-id") or str(uuid.uuid4())
    request.state.request_id = request_id
    request_count += 1
    acao = allowed_origin(path, request.headers.get("origin"))

    if request.method == "OPTIONS" and "access-control-request-method" in request.headers:
        if acao:
            response = Response(status_code=200)
            response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
            response.headers["Access-Control-Allow-Headers"] = request.headers.get(
                "access-control-request-headers", "*")
            response.headers["Access-Control-Max-Age"] = "600"
        else:
            response = PlainTextResponse("Disallowed CORS origin", status_code=400)
    else:
        limit = RATE_LIMITS.get(path)
        client = request.headers.get("x-client-id")
        now = time.time()
        bucket = hits[(path, client)]
        while bucket and now - bucket[0] >= WINDOW:
            bucket.popleft()
        if limit and client and len(bucket) >= limit:
            retry = max(1, int(WINDOW - (now - bucket[0])) + 1)
            response = JSONResponse({"detail": "rate limited"}, status_code=429,
                                    headers={"Retry-After": str(retry)})
        else:
            if limit and client:
                bucket.append(now)
            response = await call_next(request)

    if acao:
        response.headers["Access-Control-Allow-Origin"] = acao
        response.headers["Access-Control-Expose-Headers"] = "X-Request-ID, X-Process-Time, Retry-After"
        if acao != "*":
            response.headers["Vary"] = "Origin"
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Process-Time"] = f"{time.perf_counter() - start:.6f}"
    logs.append({"level": "info", "ts": time.time(), "path": path, "request_id": request_id,
                 "method": request.method, "status": response.status_code})
    return response


@app.get("/stats")
def stats(values: str):
    try:
        nums = [int(v) for v in values.split(",") if v.strip()]
    except ValueError:
        raise HTTPException(400, "values must be comma-separated integers")
    if not nums:
        raise HTTPException(400, "values is empty")
    return {"email": EMAIL, "count": len(nums), "sum": sum(nums), "min": min(nums),
            "max": max(nums), "mean": sum(nums) / len(nums)}


# --- JWT verification ---
ISSUER = "https://idp.exam.local"
AUDIENCE = "tds-59ved5kk.apps.exam.local"
PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2okOHspNjgA+2rTLbeuY
cxiP/hG8C6Sb9iwg3yiLAA4HCnpITcbWCSelbvbYGuc3EbNy4xFyf5Cbj5DHJMID
EkryOgyd2giIIIBOUBj8S63uGcnRpOBh9NFatfNwheKuzsPuVNldu6A9cNteNpXc
WyJjG2axVfmq7i6SuKr1JoWYG7xTTAvKPujSl4OtsQfO3h5NepzdfXpr28oNnzfW
ed+zclR6BcmNNo/WVfJ4xyCLSf0BCOgdTgW6PdaChd1l9VDetJZVEgC5tkyvXsfI
SI6iyrYbKR0NEBSqq4XkadEjsCs4F1RncsS4LlgniT7GlkL9Mce3b0wGLs9/7ZIX
dQIDAQAB
-----END PUBLIC KEY-----"""


class TokenIn(BaseModel):
    token: str


@app.post("/verify")
def verify(body: TokenIn):
    try:
        claims = jwt.decode(body.token, PUBLIC_KEY, algorithms=["RS256"], audience=AUDIENCE,
                            issuer=ISSUER, options={"require": ["exp", "iss", "aud"]})
    except jwt.PyJWTError:
        return JSONResponse({"valid": False}, status_code=401)
    return {"valid": True, "email": claims.get("email"), "sub": claims.get("sub"), "aud": claims["aud"]}


# --- Layered config ---
HERE = Path(__file__).parent
DEFAULTS = {"port": 8000, "workers": 1, "debug": False, "log_level": "info", "api_key": "default-secret-000"}
# Assigned OS-level APP_* values; real environment variables override them.
OS_ENV = {"APP_WORKERS": "3", "APP_DEBUG": "false", "APP_LOG_LEVEL": "info"}
ALIASES = {"NUM_WORKERS": "workers"}


def parse_flat(path, sep):
    out = {}
    for line in path.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if sep in line:
            k, v = line.split(sep, 1)
            out[k.strip()] = v.strip().strip("\"'")
    return out


def env_keys(raw):
    out = {}
    for k, v in raw.items():
        if k in ALIASES:
            out[ALIASES[k]] = v
        elif k.startswith("APP_"):
            out[k[4:].lower()] = v
    return out


def coerce(key, value):
    if key in ("port", "workers"):
        return int(value)
    if key == "debug":
        return value if isinstance(value, bool) else str(value).strip().lower() in ("true", "1", "yes", "on")
    return str(value)


@app.get("/effective-config")
def effective_config(request: Request):
    env = os.environ.get("APP_ENV", "development")
    config = dict(DEFAULTS)
    config.update(parse_flat(HERE / f"config.{env}.yaml", ":"))
    config.update(env_keys(parse_flat(HERE / ".env", "=")))
    os_env = {**OS_ENV, **{k: v for k, v in os.environ.items() if k.startswith("APP_") and k != "APP_ENV"}}
    config.update(env_keys(os_env))
    for item in request.query_params.getlist("set"):
        if "=" in item:
            k, v = item.split("=", 1)
            config[k.strip()] = v
    try:
        result = {k: coerce(k, v) for k, v in config.items()}
    except ValueError:
        raise HTTPException(400, "port and workers must be integers")
    result["api_key"] = "****"
    return result


# --- Analytics ---
API_KEY = "ak_u05mhesggk7r42oc8zkbgg7p"


class Event(BaseModel):
    user: str
    amount: float
    ts: int | float | None = None


class Batch(BaseModel):
    events: list[Event]


@app.post("/analytics")
def analytics(batch: Batch, x_api_key: str | None = Header(None)):
    if x_api_key != API_KEY:
        return JSONResponse({"detail": "invalid API key"}, status_code=401)
    totals = defaultdict(float)
    for e in batch.events:
        if e.amount > 0:
            totals[e.user] += e.amount
    return {"email": EMAIL, "total_events": len(batch.events),
            "unique_users": len({e.user for e in batch.events}),
            "revenue": round(sum(totals.values()), 2),
            "top_user": max(totals, key=totals.get) if totals else None}


# --- Observability ---
@app.get("/work")
def work(n: int = 1):
    total = 0
    for i in range(max(0, min(n, 1_000_000))):
        total += i * i
    return {"email": EMAIL, "done": n}


@app.get("/metrics")
def metrics():
    return PlainTextResponse(
        "# HELP http_requests_total Total HTTP requests.\n"
        "# TYPE http_requests_total counter\n"
        f"http_requests_total {request_count}\n",
        media_type="text/plain; version=0.0.4")


@app.get("/healthz")
def healthz():
    return {"status": "ok", "uptime_s": time.time() - STARTED}


@app.get("/logs/tail")
def logs_tail(limit: int = 20):
    return list(logs)[-max(1, min(limit, 1000)):]


# --- Orders ---
TOTAL_ORDERS = 57
orders_by_key = {}


@app.post("/orders", status_code=201)
def create_order(idempotency_key: str | None = Header(None)):
    if idempotency_key and idempotency_key in orders_by_key:
        return orders_by_key[idempotency_key]
    order = {"id": str(uuid.uuid4()), "status": "created", "created_at": time.time()}
    if idempotency_key:
        orders_by_key[idempotency_key] = order
    return order


@app.get("/orders")
def list_orders(limit: int = 10, cursor: str | None = None):
    limit = max(1, min(limit, 100))
    try:
        start = int(base64.urlsafe_b64decode(cursor).decode()) if cursor else 0
    except ValueError:
        raise HTTPException(400, "invalid cursor")
    ids = range(start + 1, min(start + limit, TOTAL_ORDERS) + 1)
    end = start + len(ids)
    next_cursor = base64.urlsafe_b64encode(str(end).encode()).decode() if end < TOTAL_ORDERS else None
    return {"items": [{"id": i} for i in ids], "next_cursor": next_cursor}


# --- Request context ---
@app.get("/ping")
def ping(request: Request):
    return {"email": EMAIL, "request_id": request.state.request_id}


# --- Static answers ---
STREAM_ANSWER = {
    "A": {"text": "Report job-c30de6b7: café\nReady ✓", "complete": True, "error": None},
    "B": {"text": "Partial job-c30de6b7", "complete": False, "error": None},
    "C": {"text": "Draft job-c30de6b7", "complete": False, "error": "model unloaded"},
}
DOCKER_ANSWER = {
    "A": {"steps": ["L3", "L4", "L5"], "seconds": 39},
    "B": {"steps": ["L1", "L2", "L3", "L4", "L5"], "seconds": 102},
    "C": {"steps": [], "seconds": 0},
    "D": {"steps": [], "seconds": 0},
    "E": {"steps": ["L4", "L5"], "seconds": 39},
}


@app.get("/stream-answer")
def stream_answer():
    return STREAM_ANSWER


@app.get("/docker-answer")
def docker_answer():
    return DOCKER_ANSWER
