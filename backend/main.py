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

from db import (
    get_connection,
    init_db,
    create_user,
    verify_user,
    save_scan,
    get_scan_details
)

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


def create_token(user):
    payload = {
        "sub": user["username"],
        "user_id": user["id"],
        "username": user["username"],
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

        if not payload.get("username") or not payload.get("user_id"):
            raise HTTPException(status_code=401, detail="Invalid token payload")

        return {
            "id": payload["user_id"],
            "username": payload["username"]
        }

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


def save_scan_result(target, result, user_id):
    save_scan(
        user_id=user_id,
        target=target,
        risk=result.get("risk"),
        score=result.get("score"),
        alerts=json.dumps(result.get("alerts", [])),
        report=json.dumps(result)
    )


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


def remove_job_from_queue(job_id):
    if not scan_queue:
        return False

    try:
        old_items = list(scan_queue._queue)
        new_items = []
        removed = False

        for item in old_items:
            if item.get("job_id") == job_id:
                removed = True
            else:
                new_items.append(item)

        scan_queue._queue.clear()

        for item in new_items:
            scan_queue._queue.append(item)

        return removed

    except Exception as e:
        logger.error(f"Failed to remove job from queue | job_id={job_id} | error={e}")
        return False


async def scan_worker():
    logger.info("Scan queue worker started")

    while True:
        job = await scan_queue.get()

        job_id = job["job_id"]
        target = job["target"]
        profile = job["profile"]
        user_id = job["user_id"]

        try:
            if scan_jobs.get(job_id, {}).get("status") == "cancelled":
                logger.info(f"Skipping cancelled job | job_id={job_id}")
                continue

            await run_scan_job(job_id, target, profile, user_id)

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

    token = create_token(user)

    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user["id"],
            "username": user["username"]
        }
    }


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

    scan_id = save_scan_result(data.target, result, user["id"])
    result["scan_id"] = scan_id

    if result.get("risk") == "HIGH":
        send_discord_alert(data.target, result.get("risk"), result.get("score"))

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
        "queue_position": None,
        "cancel_requested": False,
        "user_id": user["id"]
    }

    await scan_queue.put({
        "job_id": job_id,
        "target": data.target,
        "profile": data.profile,
        "user_id": user["id"]
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


@app.post("/cancel-scan/{job_id}")
@limiter.limit("20/minute")
def cancel_scan(
    request: Request,
    job_id: str,
    auth=Depends(security),
    user=Depends(get_current_user)
):
    job = scan_jobs.get(job_id)

    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")

    if job.get("user_id") != user["id"]:
        raise HTTPException(status_code=403, detail="Not allowed")

    if job["status"] in ["completed", "failed", "cancelled"]:
        return {
            "job_id": job_id,
            "status": job["status"],
            "message": f"Scan already {job['status']}"
        }

    job["cancel_requested"] = True

    if job["status"] == "queued":
        removed = remove_job_from_queue(job_id)

        job["status"] = "cancelled"
        job["progress"] = 0
        job["step"] = "Scan cancelled before running"
        job["completed_at"] = datetime.utcnow().isoformat()
        job["queue_position"] = None

        return {
            "job_id": job_id,
            "status": "cancelled",
            "removed_from_queue": removed,
            "message": "Scan cancelled"
        }

    if job["status"] == "running":
        job["status"] = "cancelled"
        job["step"] = "Cancel requested. Current scan will stop after current operation."
        job["completed_at"] = datetime.utcnow().isoformat()

        return {
            "job_id": job_id,
            "status": "cancelled",
            "message": "Cancel requested"
        }

    return {
        "job_id": job_id,
        "status": job["status"],
        "message": "Cancel request processed"
    }


async def run_scan_job(job_id, target, profile, user_id):
    try:
        if scan_jobs[job_id].get("cancel_requested"):
            scan_jobs[job_id]["status"] = "cancelled"
            scan_jobs[job_id]["step"] = "Scan cancelled"
            scan_jobs[job_id]["completed_at"] = datetime.utcnow().isoformat()
            return

        scan_jobs[job_id]["status"] = "running"
        scan_jobs[job_id]["started_at"] = datetime.utcnow().isoformat()
        scan_jobs[job_id]["queue_position"] = None
        scan_jobs[job_id]["progress"] = 10
        scan_jobs[job_id]["step"] = "Preparing target"

        await asyncio.sleep(0.3)

        if scan_jobs[job_id].get("cancel_requested"):
            scan_jobs[job_id]["status"] = "cancelled"
            scan_jobs[job_id]["step"] = "Scan cancelled"
            scan_jobs[job_id]["completed_at"] = datetime.utcnow().isoformat()
            return

        scan_jobs[job_id]["progress"] = 20
        scan_jobs[job_id]["step"] = "Checking DNS"

        await asyncio.sleep(0.3)

        if scan_jobs[job_id].get("cancel_requested"):
            scan_jobs[job_id]["status"] = "cancelled"
            scan_jobs[job_id]["step"] = "Scan cancelled"
            scan_jobs[job_id]["completed_at"] = datetime.utcnow().isoformat()
            return

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

        if scan_jobs[job_id].get("cancel_requested"):
            scan_jobs[job_id]["status"] = "cancelled"
            scan_jobs[job_id]["step"] = "Scan cancelled before analysis"
            scan_jobs[job_id]["completed_at"] = datetime.utcnow().isoformat()
            return

        result = await analyze(target, profile)

        if scan_jobs[job_id].get("cancel_requested") or scan_jobs[job_id].get("status") == "cancelled":
            scan_jobs[job_id]["status"] = "cancelled"
            scan_jobs[job_id]["step"] = "Scan cancelled after analysis"
            scan_jobs[job_id]["completed_at"] = datetime.utcnow().isoformat()
            return

        result["profile"] = profile

        scan_jobs[job_id]["progress"] = 95
        scan_jobs[job_id]["step"] = "Saving report"

        scan_id = save_scan_result(target, result, user_id)
        result["scan_id"] = scan_id

        if result.get("risk") == "HIGH":
            send_discord_alert(target, result.get("risk"), result.get("score"))

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

    if job.get("user_id") != user["id"]:
        raise HTTPException(status_code=403, detail="Not allowed")

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

    user_jobs = [
        job for job in scan_jobs.values()
        if job.get("user_id") == user["id"]
    ]

    running_jobs = [job for job in user_jobs if job.get("status") == "running"]
    queued_jobs = [job for job in user_jobs if job.get("status") == "queued"]
    completed_jobs = [job for job in user_jobs if job.get("status") == "completed"]
    failed_jobs = [job for job in user_jobs if job.get("status") == "failed"]
    cancelled_jobs = [job for job in user_jobs if job.get("status") == "cancelled"]

    return {
        "queue_size": queue_size,
        "running": len(running_jobs),
        "queued": len(queued_jobs),
        "completed": len(completed_jobs),
        "failed": len(failed_jobs),
        "cancelled": len(cancelled_jobs)
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
        """
        SELECT id, target, risk, score, created_at
        FROM scans
        WHERE user_id=?
        ORDER BY id DESC
        """,
        (user["id"],)
    )

    rows = c.fetchall()
    conn.close()

    return {"data": [dict(row) for row in rows]}


@app.get("/history/{scan_id}")
@limiter.limit("30/minute")
def scan_details(
    request: Request,
    scan_id: int,
    auth=Depends(security),
    user=Depends(get_current_user)
):
    report = get_scan_details(scan_id, user["id"])

    if not report:
        raise HTTPException(status_code=404, detail="Scan not found")

    return report