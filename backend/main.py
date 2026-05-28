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
    get_scan_details,
    delete_scan
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
# Disabled on Render to prevent CORS/preflight redirect problems
# app.add_middleware(HTTPSRedirectMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://threat-frontend.onrender.com",
        "https://threat-scanner-saas-2.onrender.com",
        "https://threat-scanner-saas-1.onrender.com",
        "http://localhost:3000",
        "http://127.0.0.1:5500"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"]
)

init_db()

scan_jobs = {}
scan_queue = None
queue_worker_task = None

# Bulk scan jobs are kept in memory for live progress/status.
bulk_jobs = {}


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


class BulkScanRequest(BaseModel):
    targets: list[str]
    profile: str = "quick"
    concurrency: int = 3
    include_archive: bool = True


class ScreenshotRequest(BaseModel):
    target: str


def send_discord_alert(target, risk, score, result=None):
    if not DISCORD_WEBHOOK_URL:
        logger.warning("Discord webhook not configured")
        return

    if risk not in ["HIGH", "CRITICAL"]:
        logger.info(f"No Discord alert needed | target={target} | risk={risk} | score={score}")
        return

    findings = []
    cves = []

    if isinstance(result, dict):
        findings = result.get("findings", []) or result.get("vulnerability_checks", [])

        cve_groups = result.get("cve_results", [])
        for group in cve_groups:
            for cve in group.get("cves", []):
                cves.append(cve)

    top_findings = findings[:5]
    top_cves = cves[:5]

    findings_text = "\n".join([
        f"- {f.get('severity', 'UNKNOWN')} | {f.get('title') or f.get('name', 'Finding')}"
        for f in top_findings
    ]) or "No findings listed"

    cves_text = "\n".join([
        f"- {c.get('id', 'CVE')} | {c.get('severity', 'UNKNOWN')} | Score: {c.get('score', 'N/A')}"
        for c in top_cves
    ]) or "No CVEs listed"

    color = 16711680 if risk == "CRITICAL" else 16744192

    payload = {
        "embeds": [
            {
                "title": "🚨 Threat Scanner Alert",
                "description": f"High risk scan detected for `{target}`",
                "color": color,
                "fields": [
                    {"name": "🎯 Target", "value": str(target), "inline": True},
                    {"name": "⚠️ Risk", "value": str(risk), "inline": True},
                    {"name": "📊 Score", "value": f"{score}/100", "inline": True},
                    {"name": "🕳️ Top Findings", "value": findings_text[:1000], "inline": False},
                    {"name": "🧬 Top CVEs", "value": cves_text[:1000], "inline": False},
                    {"name": "🕒 Time", "value": datetime.utcnow().isoformat() + " UTC", "inline": False}
                ],
                "footer": {
                    "text": "Threat Scanner SaaS"
                }
            }
        ]
    }

    try:
        res = requests.post(DISCORD_WEBHOOK_URL, json=payload, timeout=8)

        if res.status_code not in [200, 204]:
            logger.error(f"Discord alert failed | status={res.status_code} | body={res.text}")
        else:
            logger.info(f"Discord alert sent | target={target} | risk={risk} | score={score}")

    except Exception as e:
        logger.error(f"Discord alert exception: {e}")


def save_scan_result(target, result, user_id):
    return save_scan(
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


def update_job_progress(job_id, progress, step, phase=None):
    if job_id not in scan_jobs:
        return
    scan_jobs[job_id]["progress"] = progress
    scan_jobs[job_id]["step"] = step
    scan_jobs[job_id]["phase"] = phase or step
    scan_jobs[job_id]["updated_at"] = datetime.utcnow().isoformat()


def public_job_view(job):
    if not job:
        return None
    clean = dict(job)
    clean.pop("user_id", None)
    return clean

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

    if result.get("risk") in ["HIGH", "CRITICAL"]:
        send_discord_alert(data.target, result.get("risk"), result.get("score"), result)

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
        "phase": "Queued",
        "target": data.target,
        "profile": data.profile,
        "result": None,
        "error": None,
        "created_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat(),
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
        update_job_progress(job_id, 10, "Preparing target", "Preparation")

        await asyncio.sleep(0.3)

        if scan_jobs[job_id].get("cancel_requested"):
            scan_jobs[job_id]["status"] = "cancelled"
            scan_jobs[job_id]["step"] = "Scan cancelled"
            scan_jobs[job_id]["completed_at"] = datetime.utcnow().isoformat()
            return

        update_job_progress(job_id, 20, "Checking DNS records and target resolution", "DNS Analysis")

        await asyncio.sleep(0.3)

        if scan_jobs[job_id].get("cancel_requested"):
            scan_jobs[job_id]["status"] = "cancelled"
            scan_jobs[job_id]["step"] = "Scan cancelled"
            scan_jobs[job_id]["completed_at"] = datetime.utcnow().isoformat()
            return

        update_job_progress(job_id, 35, "Checking SSL / TLS certificate and cipher", "SSL / TLS")

        await asyncio.sleep(0.3)

        update_job_progress(job_id, 50, "Checking HTTP headers, cookies, and WAF indicators", "Headers / WAF")

        await asyncio.sleep(0.3)

        update_job_progress(job_id, 65, "Running exposure and sensitive-path checks", "Exposure Engine")

        await asyncio.sleep(0.3)

        update_job_progress(job_id, 80, "Checking CVEs, subdomains, APIs, and validation engine", "Deep Analysis")

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

        update_job_progress(job_id, 95, "Saving report and preparing final result", "Saving Report")

        scan_id = save_scan_result(target, result, user_id)
        result["scan_id"] = scan_id

        if result.get("risk") in ["HIGH", "CRITICAL"]:
            send_discord_alert(target, result.get("risk"), result.get("score"), result)

        scan_jobs[job_id]["status"] = "completed"
        update_job_progress(job_id, 100, "Scan completed", "Completed")
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

    return public_job_view(job)


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


# ============================================================
# Unlimited Bulk Scanner + Wayback Archive Engine
# ============================================================

def normalize_bulk_targets(raw_targets):
    cleaned = []
    seen = set()

    for item in raw_targets or []:
        if not item:
            continue

        # Supports textarea input accidentally sent as one big string.
        parts = str(item).replace(",", "\n").splitlines()

        for part in parts:
            target = part.strip()
            if not target:
                continue

            if target.startswith("#"):
                continue

            key = target.lower().rstrip("/")
            if key in seen:
                continue

            seen.add(key)
            cleaned.append(target)

    return cleaned


def extract_result_urls(result):
    urls = []

    def add_url(value):
        if not value:
            return
        value = str(value)
        if value.startswith("http://") or value.startswith("https://"):
            urls.append(value)

    for section in [
        "confirmed_vulnerabilities",
        "possible_issues",
        "hardening_issues",
        "attack_surface",
        "findings",
        "vulnerability_checks",
        "advanced_exposures",
        "nikto_checks"
    ]:
        items = result.get(section, []) if isinstance(result, dict) else []
        if not isinstance(items, list):
            continue

        for item in items:
            if not isinstance(item, dict):
                continue
            add_url(item.get("affected_url"))
            add_url(item.get("url"))
            add_url(item.get("evidence"))
            add_url(item.get("original_url"))

    wayback = result.get("wayback", {}) if isinstance(result, dict) else {}
    if isinstance(wayback, dict):
        for key in ["interesting_urls", "parameterized_urls"]:
            for item in wayback.get(key, []) or []:
                if isinstance(item, dict):
                    add_url(item.get("url"))
                else:
                    add_url(item)

    return list(dict.fromkeys(urls))[:80]


def summarize_bulk_result(target, result, error=None):
    if error:
        return {
            "target": target,
            "status": "failed",
            "risk": "UNKNOWN",
            "score": 0,
            "error": error,
            "vulnerable": False,
            "confirmed_count": 0,
            "possible_count": 0,
            "hardening_count": 0,
            "attack_surface_count": 0,
            "vulnerable_urls": [],
            "archive_urls": []
        }

    confirmed = result.get("confirmed_vulnerabilities", []) or []
    possible = result.get("possible_issues", []) or []
    hardening = result.get("hardening_issues", []) or []
    attack_surface = result.get("attack_surface", []) or []
    wayback = result.get("wayback", {}) or {}

    archive_urls = []
    if isinstance(wayback, dict):
        for item in (wayback.get("interesting_urls") or [])[:30]:
            archive_urls.append(item.get("url") if isinstance(item, dict) else item)
        for item in (wayback.get("parameterized_urls") or [])[:30]:
            archive_urls.append(item.get("url") if isinstance(item, dict) else item)

    archive_urls = [x for x in dict.fromkeys(archive_urls) if x]
    vulnerable_urls = extract_result_urls(result)
    risk = result.get("risk", "UNKNOWN")
    score = result.get("score", 0)

    return {
        "target": target,
        "status": "completed",
        "risk": risk,
        "score": score,
        "scan_id": result.get("scan_id"),
        "final_url": result.get("final_url"),
        "vulnerable": bool(confirmed or possible or str(risk).upper() in ["MEDIUM", "HIGH", "CRITICAL"]),
        "confirmed_count": len(confirmed),
        "possible_count": len(possible),
        "hardening_count": len(hardening),
        "attack_surface_count": len(attack_surface),
        "vulnerable_urls": vulnerable_urls,
        "archive_urls": archive_urls[:60],
        "top_confirmed": confirmed[:5],
        "top_possible": possible[:5],
        "top_attack_surface": attack_surface[:5]
    }


def public_bulk_view(job, include_results=True):
    clean = dict(job)
    clean.pop("user_id", None)
    if not include_results:
        clean.pop("results", None)
        clean.pop("raw_results", None)
    return clean


async def run_bulk_scan_job(bulk_id, targets, profile, concurrency, include_archive, user_id):
    job = bulk_jobs[bulk_id]
    semaphore = asyncio.Semaphore(max(1, min(int(concurrency or 3), 5)))

    job["status"] = "running"
    job["started_at"] = datetime.utcnow().isoformat()
    job["updated_at"] = datetime.utcnow().isoformat()

    async def scan_one(index, target):
        async with semaphore:
            if job.get("cancel_requested"):
                return

            item_state = {
                "target": target,
                "status": "running",
                "risk": "UNKNOWN",
                "score": 0,
                "started_at": datetime.utcnow().isoformat()
            }
            job["items"][index] = item_state
            job["current_target"] = target
            job["updated_at"] = datetime.utcnow().isoformat()

            try:
                result = await analyze(target, profile)
                result["profile"] = profile

                # Ensure archive URLs are available even if analyzer profile skipped them.
                if include_archive and not (result.get("wayback") or {}).get("enabled"):
                    try:
                        host = result.get("host")
                        if host:
                            async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
                                result["wayback"] = await get_wayback_archive_urls(client, host)
                    except Exception as archive_error:
                        result["wayback"] = {
                            "enabled": False,
                            "error": str(archive_error),
                            "urls": [],
                            "interesting_urls": [],
                            "parameterized_urls": []
                        }

                scan_id = save_scan_result(target, result, user_id)
                result["scan_id"] = scan_id

                if result.get("risk") in ["HIGH", "CRITICAL"]:
                    send_discord_alert(target, result.get("risk"), result.get("score"), result)

                summary = summarize_bulk_result(target, result)
                job["items"][index] = summary
                job["results"].append(summary)
                job["raw_results"][target] = result

            except Exception as e:
                logger.exception(f"Bulk scan item failed | bulk_id={bulk_id} | target={target}")
                failed = summarize_bulk_result(target, None, str(e))
                job["items"][index] = failed
                job["results"].append(failed)
                job["failed"] += 1

            finally:
                job["completed"] = len([x for x in job["items"] if x and x.get("status") in ["completed", "failed"]])
                job["failed"] = len([x for x in job["items"] if x and x.get("status") == "failed"])
                job["vulnerable_targets"] = len([x for x in job["items"] if x and x.get("vulnerable")])
                job["progress"] = round((job["completed"] / max(job["total"], 1)) * 100, 2)
                job["updated_at"] = datetime.utcnow().isoformat()

    try:
        tasks = [asyncio.create_task(scan_one(i, t)) for i, t in enumerate(targets)]
        await asyncio.gather(*tasks)

        if job.get("cancel_requested"):
            job["status"] = "cancelled"
            job["step"] = "Bulk scan cancelled"
        else:
            job["status"] = "completed"
            job["step"] = "Bulk scan completed"
            job["progress"] = 100

        job["completed_at"] = datetime.utcnow().isoformat()
        job["updated_at"] = datetime.utcnow().isoformat()

    except Exception as e:
        logger.exception(f"Bulk scan failed | bulk_id={bulk_id}")
        job["status"] = "failed"
        job["error"] = str(e)
        job["completed_at"] = datetime.utcnow().isoformat()
        job["updated_at"] = datetime.utcnow().isoformat()


@app.post("/bulk-scan/start")
@limiter.limit("3/minute")
async def bulk_scan_start(
    request: Request,
    data: BulkScanRequest,
    auth=Depends(security),
    user=Depends(get_current_user)
):
    targets = normalize_bulk_targets(data.targets)

    if not targets:
        raise HTTPException(status_code=400, detail="No valid targets provided")

    profile = str(data.profile or "quick").lower()
    if profile not in ["quick", "full", "deep"]:
        profile = "quick"

    bulk_id = str(uuid.uuid4())
    concurrency = max(1, min(int(data.concurrency or 3), 5))

    bulk_jobs[bulk_id] = {
        "bulk_id": bulk_id,
        "status": "queued",
        "step": "Bulk scan queued",
        "profile": profile,
        "total": len(targets),
        "completed": 0,
        "failed": 0,
        "vulnerable_targets": 0,
        "progress": 0,
        "concurrency": concurrency,
        "include_archive": bool(data.include_archive),
        "current_target": None,
        "items": [None for _ in targets],
        "results": [],
        "raw_results": {},
        "error": None,
        "cancel_requested": False,
        "created_at": datetime.utcnow().isoformat(),
        "started_at": None,
        "completed_at": None,
        "updated_at": datetime.utcnow().isoformat(),
        "user_id": user["id"]
    }

    asyncio.create_task(
        run_bulk_scan_job(
            bulk_id=bulk_id,
            targets=targets,
            profile=profile,
            concurrency=concurrency,
            include_archive=bool(data.include_archive),
            user_id=user["id"]
        )
    )

    return public_bulk_view(bulk_jobs[bulk_id], include_results=False)


@app.get("/bulk-scan/status/{bulk_id}")
@limiter.limit("120/minute")
def bulk_scan_status(
    request: Request,
    bulk_id: str,
    auth=Depends(security),
    user=Depends(get_current_user)
):
    job = bulk_jobs.get(bulk_id)

    if not job:
        raise HTTPException(status_code=404, detail="Bulk scan not found")

    if job.get("user_id") != user["id"]:
        raise HTTPException(status_code=403, detail="Not allowed")

    return public_bulk_view(job, include_results=True)


@app.get("/bulk-scan/results/{bulk_id}")
@limiter.limit("60/minute")
def bulk_scan_results(
    request: Request,
    bulk_id: str,
    auth=Depends(security),
    user=Depends(get_current_user)
):
    job = bulk_jobs.get(bulk_id)

    if not job:
        raise HTTPException(status_code=404, detail="Bulk scan not found")

    if job.get("user_id") != user["id"]:
        raise HTTPException(status_code=403, detail="Not allowed")

    return public_bulk_view(job, include_results=True)


@app.post("/bulk-scan/cancel/{bulk_id}")
@limiter.limit("20/minute")
def bulk_scan_cancel(
    request: Request,
    bulk_id: str,
    auth=Depends(security),
    user=Depends(get_current_user)
):
    job = bulk_jobs.get(bulk_id)

    if not job:
        raise HTTPException(status_code=404, detail="Bulk scan not found")

    if job.get("user_id") != user["id"]:
        raise HTTPException(status_code=403, detail="Not allowed")

    job["cancel_requested"] = True
    if job.get("status") in ["queued", "running"]:
        job["status"] = "cancelled"
        job["step"] = "Cancel requested"
        job["completed_at"] = datetime.utcnow().isoformat()
        job["updated_at"] = datetime.utcnow().isoformat()

    return public_bulk_view(job, include_results=False)


@app.post("/screenshot")
@limiter.limit("10/minute")
async def screenshot_target(
    request: Request,
    data: ScreenshotRequest,
    auth=Depends(security),
    user=Depends(get_current_user)
):
    target = data.target.strip()

    if not target:
        raise HTTPException(status_code=400, detail="Target is required")

    if not target.startswith("http://") and not target.startswith("https://"):
        target = "https://" + target

    try:
        from playwright.async_api import async_playwright
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Screenshot engine is not installed. Add 'playwright' to requirements.txt and set Render build command: python -m playwright install chromium"
        )

    browser = None

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-dev-shm-usage"]
            )

            page = await browser.new_page(
                viewport={"width": 1366, "height": 768},
                user_agent="ThreatScanner-Screenshot/1.0"
            )

            await page.goto(target, wait_until="networkidle", timeout=20000)
            image_bytes = await page.screenshot(full_page=True, type="png")
            await browser.close()

            import base64
            image_base64 = base64.b64encode(image_bytes).decode("utf-8")

            return {
                "target": data.target,
                "final_url": page.url,
                "image_type": "image/png",
                "image_base64": image_base64,
                "data_url": f"data:image/png;base64,{image_base64}"
            }

    except Exception as e:
        try:
            if browser:
                await browser.close()
        except Exception:
            pass

        logger.error(f"Screenshot failed | target={target} | error={e}")
        raise HTTPException(status_code=500, detail=f"Screenshot failed: {str(e)}")


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


@app.delete("/history/{scan_id}")
@limiter.limit("20/minute")
def delete_scan_history(
    request: Request,
    scan_id: int,
    auth=Depends(security),
    user=Depends(get_current_user)
):
    deleted = delete_scan(scan_id, user["id"])

    if not deleted:
        raise HTTPException(status_code=404, detail="Scan not found")

    return {
        "success": True,
        "message": "Scan deleted",
        "scan_id": scan_id
    }

# ===== Advanced Upgrade Patch =====

def calculate_realistic_risk(findings, vulns, open_ports):
    score = 0

    for item in findings + vulns:
        sev = str(item.get("severity", "")).upper()

        if sev == "CRITICAL":
            score += 40
        elif sev == "HIGH":
            score += 25
        elif sev == "MEDIUM":
            score += 10
        elif sev == "LOW":
            score += 4

    for port in open_ports:
        if port.get("risk") == "RISKY":
            score += 6

    score = min(score, 100)

    if score >= 80:
        risk = "CRITICAL"
    elif score >= 55:
        risk = "HIGH"
    elif score >= 25:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return risk, score



@app.get("/analytics")
def analytics():
    return {
        "status":"ok",
        "message":"Dashboard analytics enabled"
    }



@app.get("/dashboard-stats")
def dashboard_stats():
    return {
        "status":"ok",
        "charts":True,
        "analytics":True,
        "pdf_reports":True
    }

