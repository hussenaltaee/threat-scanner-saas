from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from fastapi.security import HTTPBearer
from pydantic import BaseModel
import requests
import json
import uuid
import asyncio
from datetime import datetime, timedelta
import jwt
import os
from dotenv import load_dotenv
import logging

from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.extension import _rate_limit_exceeded_handler

from db import get_connection, init_db, create_user, verify_user
from analyzer import analyze

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY", "fallback-secret-change-me")
ALGORITHM = "HS256"
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))
JWT_ISSUER = os.getenv("JWT_ISSUER", "threat-scanner-saas")
JWT_AUDIENCE = os.getenv("JWT_AUDIENCE", "threat-scanner-users")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s"
)

logger = logging.getLogger("threat-scanner")
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="Threat Scanner SaaS",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

security = HTTPBearer()

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

# Force HTTPS in production
app.add_middleware(HTTPSRedirectMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

init_db()

scan_jobs = {}
scan_queue = None
queue_worker_task = None


def create_token(data):
    username = data.get("username")

    payload = {
        "sub": username,
        "username": username,
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    }

    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(request: Request):
    auth = request.headers.get("Authorization")

    if not auth or not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="No token")

    try:
        token = auth.split(" ", 1)[1].strip()

        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
            issuer=JWT_ISSUER,
            audience=JWT_AUDIENCE
        )

        if not payload.get("username"):
            raise HTTPException(status_code=401, detail="Invalid token payload")

        return payload

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")

    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


class RegisterRequest(BaseModel):
    username: str
    password: str


class LoginRequest(BaseModel):
    username: str
    password: str


class ScanRequest(BaseModel):
    target: str
    profile: str = "full"


def send_discord_alert(target, risk, score):
    if not DISCORD_WEBHOOK_URL:
        return

    message = {
        "content": f"""
🚨 HIGH RISK ALERT
Target: {target}
Risk: {risk}
Score: {score}
Time: {datetime.now()}
"""
    }

    try:
        requests.post(DISCORD_WEBHOOK_URL, json=message, timeout=5)
    except Exception as e:
        logger.error(f"Discord alert failed: {e}")


def save_scan_result(target, result, username):
    conn = get_connection()
    c = conn.cursor()

    c.execute(
        "INSERT INTO scans (target, risk, score, alerts, report, user) VALUES (?, ?, ?, ?, ?, ?)",
        (
            target,
            result["risk"],
            result["score"],
            json.dumps(result.get("alerts", [])),
            json.dumps(result),
            username
        )
    )

    conn.commit()
    conn.close()


def get_queue_position(job_id):
    if not scan_queue:
        return None

    try:
        queued_items = list(scan_queue._queue)

        for index, item in enumerate(queued_items, start=1):
            if item.get("job_id") == job_id:
                return index

        return None

    except Exception:
        return None


async def scan_worker():
    logger.info("Scan queue worker started")

    while True:
        job = await scan_queue.get()

        job_id = job["job_id"]
        target = job["target"]
        profile = job["profile"]
        username = job["username"]

        try:
            await run_scan_job(job_id, target, profile, username)

        except Exception as e:
            logger.exception(f"Queue worker failed | job_id={job_id}")

            if job_id in scan_jobs:
                scan_jobs[job_id]["status"] = "failed"
                scan_jobs[job_id]["error"] = str(e)
                scan_jobs[job_id]["step"] = "Queue worker failed"

        finally:
            scan_queue.task_done()


@app.on_event("startup")
async def startup_event():
    global scan_queue
    global queue_worker_task

    scan_queue = asyncio.Queue()

    if queue_worker_task is None:
        queue_worker_task = asyncio.create_task(scan_worker())

    logger.info("Application startup complete")


@app.get("/")
@limiter.limit("60/minute")
def home(request: Request):
    queue_size = scan_queue.qsize() if scan_queue else 0

    return {
        "status": "online",
        "queue_size": queue_size
    }


@app.post("/register")
@limiter.limit("5/minute")
def register(request: Request, data: RegisterRequest):
    if not create_user(data.username, data.password):
        logger.warning(f"Register failed: user already exists | username={data.username}")
        raise HTTPException(status_code=400, detail="User exists")

    return {"msg": "User created"}


@app.post("/login")
@limiter.limit("10/minute")
def login(request: Request, data: LoginRequest):
    user = verify_user(data.username, data.password)

    if not user:
        logger.warning(f"Login failed: invalid credentials | username={data.username}")
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_token({"username": data.username})

    return {"access_token": token}


@app.post("/scan")
@limiter.limit("5/minute")
async def scan(
    request: Request,
    data: ScanRequest,
    auth=Depends(security),
    user=Depends(get_current_user)
):
    result = await analyze(data.target, data.profile)

    result["profile"] = data.profile

    save_scan_result(data.target, result, user["username"])

    if result["risk"] == "HIGH":
        send_discord_alert(
            data.target,
            result["risk"],
            result["score"]
        )

    return result


@app.post("/scan-async")
@limiter.limit("5/minute")
async def scan_async(
    request: Request,
    data: ScanRequest,
    auth=Depends(security),
    user=Depends(get_current_user)
):
    if scan_queue is None:
        raise HTTPException(status_code=503, detail="Scan queue is not ready")

    job_id = str(uuid.uuid4())

    scan_jobs[job_id] = {
        "job_id": job_id,
        "status": "queued",
        "progress": 0,
        "step": "Scan queued",
        "target": data.target,
        "profile": data.profile,
        "result": None,
        "error": None,
        "created_at": datetime.utcnow().isoformat(),
        "started_at": None,
        "completed_at": None,
        "queue_position": None
    }

    await scan_queue.put({
        "job_id": job_id,
        "target": data.target,
        "profile": data.profile,
        "username": user["username"]
    })

    position = get_queue_position(job_id)
    scan_jobs[job_id]["queue_position"] = position

    return {
        "job_id": job_id,
        "status": "queued",
        "queue_position": position,
        "queue_size": scan_queue.qsize(),
        "message": "Scan added to queue"
    }


async def run_scan_job(job_id, target, profile, username):
    try:
        scan_jobs[job_id]["status"] = "running"
        scan_jobs[job_id]["started_at"] = datetime.utcnow().isoformat()
        scan_jobs[job_id]["queue_position"] = None
        scan_jobs[job_id]["progress"] = 10
        scan_jobs[job_id]["step"] = "Preparing target"

        await asyncio.sleep(0.3)

        scan_jobs[job_id]["progress"] = 20
        scan_jobs[job_id]["step"] = "Checking DNS"

        await asyncio.sleep(0.3)

        scan_jobs[job_id]["progress"] = 35
        scan_jobs[job_id]["step"] = "Checking SSL / TLS"

        await asyncio.sleep(0.3)

        scan_jobs[job_id]["progress"] = 50
        scan_jobs[job_id]["step"] = "Checking headers and cookies"

        await asyncio.sleep(0.3)

        scan_jobs[job_id]["progress"] = 65
        scan_jobs[job_id]["step"] = "Running Nikto-like checks"

        await asyncio.sleep(0.3)

        scan_jobs[job_id]["progress"] = 80
        scan_jobs[job_id]["step"] = "Checking CVEs and subdomains"

        result = await analyze(target, profile)

        result["profile"] = profile

        scan_jobs[job_id]["progress"] = 95
        scan_jobs[job_id]["step"] = "Saving report"

        save_scan_result(target, result, username)

        if result["risk"] == "HIGH":
            send_discord_alert(
                target,
                result["risk"],
                result["score"]
            )

        scan_jobs[job_id]["status"] = "completed"
        scan_jobs[job_id]["progress"] = 100
        scan_jobs[job_id]["step"] = "Scan completed"
        scan_jobs[job_id]["result"] = result
        scan_jobs[job_id]["completed_at"] = datetime.utcnow().isoformat()

    except Exception as e:
        logger.exception(f"Scan job failed | job_id={job_id} | target={target}")

        scan_jobs[job_id]["status"] = "failed"
        scan_jobs[job_id]["error"] = str(e)
        scan_jobs[job_id]["step"] = "Scan failed"
        scan_jobs[job_id]["completed_at"] = datetime.utcnow().isoformat()


@app.get("/scan-status/{job_id}")
@limiter.limit("120/minute")
def scan_status(
    request: Request,
    job_id: str,
    auth=Depends(security),
    user=Depends(get_current_user)
):
    job = scan_jobs.get(job_id)

    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")

    if job["status"] == "queued":
        job["queue_position"] = get_queue_position(job_id)

    queue_size = scan_queue.qsize() if scan_queue else 0
    job["queue_size"] = queue_size

    return job


@app.get("/queue-status")
@limiter.limit("60/minute")
def queue_status(
    request: Request,
    auth=Depends(security),
    user=Depends(get_current_user)
):
    queue_size = scan_queue.qsize() if scan_queue else 0

    running_jobs = [
        job for job in scan_jobs.values()
        if job.get("status") == "running"
    ]

    queued_jobs = [
        job for job in scan_jobs.values()
        if job.get("status") == "queued"
    ]

    completed_jobs = [
        job for job in scan_jobs.values()
        if job.get("status") == "completed"
    ]

    failed_jobs = [
        job for job in scan_jobs.values()
        if job.get("status") == "failed"
    ]

    return {
        "queue_size": queue_size,
        "running": len(running_jobs),
        "queued": len(queued_jobs),
        "completed": len(completed_jobs),
        "failed": len(failed_jobs)
    }


@app.get("/history")
@limiter.limit("30/minute")
def history(
    request: Request,
    auth=Depends(security),
    user=Depends(get_current_user)
):
    conn = get_connection()
    c = conn.cursor()

    c.execute(
        "SELECT id, target, risk, score, created_at FROM scans WHERE user=? ORDER BY id DESC",
        (user["username"],)
    )

    data = c.fetchall()
    conn.close()

    return {"data": data}


@app.get("/history/{scan_id}")
@limiter.limit("30/minute")
def scan_details(
    request: Request,
    scan_id: int,
    auth=Depends(security),
    user=Depends(get_current_user)
):
    conn = get_connection()
    c = conn.cursor()

    c.execute(
        "SELECT report FROM scans WHERE id=? AND user=?",
        (scan_id, user["username"])
    )

    row = c.fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")

    return json.loads(row[0])