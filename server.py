from fastapi import FastAPI, APIRouter, HTTPException
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import re
import uuid
import logging
from pathlib import Path
from pydantic import BaseModel
from typing import List
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse
import joblib

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

mongo_url = os.environ.get('MONGO_URL', '')
client = AsyncIOMotorClient(mongo_url, serverSelectionTimeoutMS=3000) if mongo_url else None
db = client[os.environ.get('DB_NAME', 'cyberguard')] if client is not None else None

from url_features import extract_features

MODEL_PATH = ROOT_DIR / "rf_url_model.joblib"
ml_model = joblib.load(MODEL_PATH) if MODEL_PATH.exists() else None

SPAM_MODEL_PATH = ROOT_DIR / "spam_model.joblib"
spam_model = joblib.load(SPAM_MODEL_PATH) if SPAM_MODEL_PATH.exists() else None

app = FastAPI()
api_router = APIRouter(prefix="/api")

now_t = datetime.now(timezone.utc)
memory_scans = [
    {"id": str(uuid.uuid4()), "url": "https://wikipedia.org", "domain": "wikipedia.org", "verdict": "safe", "risk_score": 10, "ml_score": 12, "scanned_at": (now_t - timedelta(hours=4)).isoformat()},
    {"id": str(uuid.uuid4()), "url": "http://paypal-fake.login-verify.com", "domain": "paypal-fake.login-verify.com", "verdict": "dangerous", "risk_score": 85, "ml_score": 90, "scanned_at": (now_t - timedelta(hours=3)).isoformat()},
    {"id": str(uuid.uuid4()), "url": "https://github.com", "domain": "github.com", "verdict": "safe", "risk_score": 0, "ml_score": 5, "scanned_at": (now_t - timedelta(hours=3)).isoformat()},
    {"id": str(uuid.uuid4()), "url": "http://bank-sbi.verify-otp.info", "domain": "bank-sbi.verify-otp.info", "verdict": "dangerous", "risk_score": 78, "ml_score": 80, "scanned_at": (now_t - timedelta(hours=2)).isoformat()},
    {"id": str(uuid.uuid4()), "url": "https://stackoverflow.com", "domain": "stackoverflow.com", "verdict": "safe", "risk_score": 5, "ml_score": 10, "scanned_at": (now_t - timedelta(hours=1)).isoformat()},
    {"id": str(uuid.uuid4()), "url": "http://192.168.1.10/admin/login", "domain": "192.168.1.10", "verdict": "dangerous", "risk_score": 92, "ml_score": 95, "scanned_at": (now_t - timedelta(hours=1)).isoformat()},
]

memory_alerts = [
    {
        "id": str(uuid.uuid4()),
        "type": "malicious-url",
        "url": "http://paypal-fake.login-verify.com",
        "verdict": "dangerous",
        "risk_score": 85,
        "severity": "critical",
        "recommended_action": "Immediate domain block at perimeter",
        "status": "open",
        "created_at": (now_t - timedelta(hours=3)).isoformat(),
    },
    {
        "id": str(uuid.uuid4()),
        "type": "email-scam",
        "url": "http://bank-sbi.verify-otp.info",
        "verdict": "dangerous",
        "risk_score": 78,
        "severity": "high",
        "recommended_action": "Quarantine message, warn user",
        "status": "open",
        "created_at": (now_t - timedelta(hours=2)).isoformat(),
    },
]

SUSPICIOUS_KEYWORDS = [
    "login", "log-in", "signin", "sign-in", "verify", "verification", "bank",
    "secure", "security", "account", "update", "confirm", "password", "wallet",
    "billing", "invoice", "support", "unlock", "suspended", "limited",
    "paypal", "netflix", "amazon", "appleid", "microsoft", "refund", "prize",
    "winner", "free", "gift", "claim",
]

URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "cutt.ly", "rb.gy", "tiny.cc", "shorturl.at", "rebrand.ly",
    "bl.ink", "qr.ae", "shorte.st", "t.ly", "gg.gg",
]

IP_HOST_PATTERN = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

MESSAGE_PATTERNS = {
    "urgency pressure": ["urgent", "immediately", "suspended", "expires", "expired", "act now", "limited time", "within 24 hours", "final notice", "last chance", "blocked"],
    "prize bait": ["won", "winner", "prize", "lottery", "claim your", "congratulations", "reward", "free gift", "cash prize", "jackpot", "lucky draw"],
    "credential theft": ["otp", "password", "pin", "cvv", "verify your account", "confirm your identity", "ssn", "aadhaar", "pan card", "account number", "card details"],
    "authority impersonation": ["bank", "income tax", "irs", "police", "customs", "courier", "fedex", "dhl", "microsoft support", "amazon support", "rbi", "sbi"],
}

URL_IN_TEXT = re.compile(
    r"(?:https?://[^\s]+|www\.[^\s]+|(?:[a-z0-9-]+\.)+(?:com|net|org|info|top|xyz|click|link|live|icu|online|site|in|co)(?:/[^\s]*)?)",
    re.IGNORECASE,
)

ALERT_ACTIONS_URL = {
    "critical": "Immediate domain block at perimeter",
    "high": "Warn user and quarantine link",
    "medium": "Advisory flag — continue monitoring",
}
ALERT_ACTIONS_MSG = {
    "critical": "Immediate sender block + user warning",
    "high": "Quarantine message, warn user",
    "medium": "Advisory flag — continue monitoring",
}


class ScanRequest(BaseModel):
    url: str


class MessageRequest(BaseModel):
    text: str


class CheckResult(BaseModel):
    id: str
    label: str
    status: str
    detail: str


async def db_available() -> bool:
    if client is None:
        return False
    try:
        await client.admin.command("ping")
        return True
    except Exception:
        return False


async def save_scan(doc: dict):
    if await db_available():
        try:
            await db.scans.insert_one(doc)
            return
        except Exception:
            pass
    memory_scans.append(doc)
    if len(memory_scans) > 500:
        memory_scans.pop(0)


async def load_scans(limit: int = 500) -> list:
    if await db_available():
        try:
            return await db.scans.find({}, {"_id": 0}).sort("scanned_at", -1).to_list(limit)
        except Exception:
            pass
    return list(reversed(memory_scans[-limit:]))


async def save_alert(doc: dict):
    if await db_available():
        try:
            await db.alerts.insert_one(doc)
            return
        except Exception:
            pass
    memory_alerts.append(doc)
    if len(memory_alerts) > 200:
        memory_alerts.pop(0)


async def load_alerts(limit: int = 20) -> list:
    if await db_available():
        try:
            return await db.alerts.find({}, {"_id": 0}).sort("created_at", -1).to_list(limit)
        except Exception:
            pass
    return list(reversed(memory_alerts[-limit:]))


async def update_alert_status(alert_id: str, status: str):
    if await db_available():
        try:
            await db.alerts.update_one({"id": alert_id}, {"$set": {"status": status}})
            return
        except Exception:
            pass
    for a in memory_alerts:
        if a["id"] == alert_id:
            a["status"] = status


def make_alert(alert_type: str, label: str, verdict: str, score: int) -> dict:
    sev = "critical" if score >= 75 else "high" if score >= 50 else "medium"
    actions = ALERT_ACTIONS_MSG if alert_type == "email-scam" else ALERT_ACTIONS_URL
    return {
        "id": str(uuid.uuid4()),
        "type": alert_type,
        "url": label,
        "verdict": verdict,
        "risk_score": score,
        "severity": sev,
        "recommended_action": actions[sev],
        "status": "open",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


def analyze_url(raw_url: str) -> dict:
    url = raw_url.strip()
    if not url:
        raise HTTPException(status_code=422, detail="Paste a URL first")
    if "://" not in url:
        url = "http://" + url
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if not host or "." not in host:
        raise HTTPException(status_code=422, detail="That doesn't look like a valid URL")

    scheme = parsed.scheme.lower()
    lowered = url.lower()
    checks: List[CheckResult] = []
    score = 0

    if scheme == "https":
        checks.append(CheckResult(id="https", label="Encrypted connection", status="pass",
                                  detail="This link travels over HTTPS, so traffic to it is encrypted."))
    else:
        score += 25
        checks.append(CheckResult(id="https", label="Encrypted connection", status="fail",
                                  detail="No HTTPS — anything you type on this page can be intercepted."))

    matches = sorted({k for k in SUSPICIOUS_KEYWORDS if k in lowered})
    if matches:
        score += min(30, 15 * len(matches))
        shown = ", ".join(matches[:5])
        checks.append(CheckResult(id="keywords", label="Suspicious keywords", status="fail",
                                  detail=f"Contains high-risk bait word(s): {shown}."))
    else:
        checks.append(CheckResult(id="keywords", label="Suspicious keywords", status="pass",
                                  detail="No common phishing bait words detected in the link."))

    is_shortener = any(host == s or host.endswith("." + s) for s in URL_SHORTENERS)
    if is_shortener:
        score += 20
        checks.append(CheckResult(id="shortener", label="Link shortener", status="warn",
                                  detail="Shortened links hide the real destination — expand before you trust."))
    else:
        checks.append(CheckResult(id="shortener", label="Link shortener", status="pass",
                                  detail="The destination domain is visible, not hidden behind a shortener."))

    if IP_HOST_PATTERN.match(host):
        score += 30
        checks.append(CheckResult(id="ip-host", label="Raw IP address", status="fail",
                                  detail="Legitimate services almost never use a bare IP address as their host."))
    else:
        checks.append(CheckResult(id="ip-host", label="Raw IP address", status="pass",
                                  detail="Uses a named domain instead of a raw IP address."))

    score = min(100, score)
    heuristic_score = score
    ml_score = 0
    if ml_model is not None:
        try:
            ml_score = round(float(ml_model.predict_proba([extract_features(raw_url)])[0][1]) * 100)
        except Exception:
            ml_score = 0
        score = round(0.5 * heuristic_score + 0.5 * ml_score)
    verdict = "dangerous" if score >= 50 else "suspicious" if score >= 25 else "safe"
    return {
        "url": raw_url.strip(),
        "normalized_url": url,
        "domain": host,
        "risk_score": score,
        "heuristic_score": heuristic_score,
        "ml_score": ml_score,
        "engine": "rules + random-forest" if ml_model is not None else "rules-only",
        "verdict": verdict,
        "checks": [c.model_dump() for c in checks],
    }


def message_triggers(text: str):
    lowered = text.lower()
    reasons = []
    trigger_score = 0
    for category, words in MESSAGE_PATTERNS.items():
        hits = [w for w in words if w in lowered]
        if hits:
            trigger_score += min(25, 10 + 5 * len(hits))
            reasons.append({"category": category, "matches": hits[:4]})
    return reasons, trigger_score


def scan_links_in_text(text: str):
    links = [m.strip(".,);\"'") for m in URL_IN_TEXT.findall(text)]
    scanned = []
    worst = 0
    for link in links[:5]:
        try:
            a = analyze_url(link)
            scanned.append({"url": link, "risk_score": a["risk_score"], "verdict": a["verdict"]})
            worst = max(worst, a["risk_score"])
        except HTTPException:
            continue
    return links, scanned, worst


@api_router.get("/")
async def root():
    return {
        "message": "CyberGuard threat scanner online",
        "url_model": ml_model is not None,
        "spam_model": spam_model is not None,
        "database": await db_available(),
    }


@api_router.post("/scan")
async def scan_url(payload: ScanRequest):
    analysis = analyze_url(payload.url)
    doc = {"id": str(uuid.uuid4()), **analysis, "scanned_at": datetime.now(timezone.utc).isoformat()}
    await save_scan(doc)
    if doc["risk_score"] >= 25:
        await save_alert(make_alert("malicious-url", doc["url"], doc["verdict"], doc["risk_score"]))
    return {k: v for k, v in doc.items() if k != "_id"}


@api_router.post("/analyze-message")
async def analyze_message(payload: MessageRequest):
    text = payload.text.strip()
    if not text:
        raise HTTPException(status_code=422, detail="Paste a message first")
    reasons, trigger_score = message_triggers(text)
    links, scanned_links, worst_link = scan_links_in_text(text)
    score = min(100, trigger_score + worst_link // 2)
    verdict = "scam" if score >= 50 else "suspicious" if score >= 25 else "likely-safe"
    return {"score": score, "verdict": verdict, "reasons": reasons, "links": scanned_links, "link_count": len(links)}


@api_router.post("/spam-check")
async def spam_check(payload: MessageRequest):
    text = payload.text.strip()
    if not text:
        raise HTTPException(status_code=422, detail="Paste a message first")
    spam_prob = 0.0
    if spam_model is not None:
        try:
            spam_prob = float(spam_model.predict_proba([text])[0][1])
        except Exception:
            spam_prob = 0.0
    reasons, trigger_score = message_triggers(text)
    links, scanned_links, worst_link = scan_links_in_text(text)
    if spam_model is not None:
        score = round(0.5 * spam_prob * 100 + 0.3 * min(100, trigger_score) + 0.2 * worst_link)
        engine = "tfidf naive-bayes + triggers + link scan"
    else:
        score = round(0.6 * min(100, trigger_score) + 0.4 * worst_link)
        engine = "triggers + link scan"
    score = min(100, score)
    verdict = "scam" if score >= 50 else "suspicious" if score >= 25 else "likely-safe"
    if score >= 25:
        await save_alert(make_alert("email-scam", links[0] if links else text[:90], verdict, score))
    return {"score": score, "spam_probability": round(spam_prob * 100), "verdict": verdict,
            "reasons": reasons, "links": scanned_links, "engine": engine}


@api_router.get("/alerts")
async def get_alerts(limit: int = 20):
    limit = max(1, min(limit, 50))
    return await load_alerts(limit)


@api_router.post("/alerts/{alert_id}/{action}")
async def update_alert(alert_id: str, action: str):
    if action not in ("acknowledge", "resolve"):
        raise HTTPException(status_code=422, detail="Unknown action")
    status = "acknowledged" if action == "acknowledge" else "resolved"
    await update_alert_status(alert_id, status)
    return {"ok": True, "status": status}


@api_router.get("/scans/recent")
async def recent_scans(limit: int = 8):
    limit = max(1, min(limit, 30))
    scans = await load_scans(limit)
    return [{k: s.get(k) for k in ("id", "url", "domain", "verdict", "risk_score", "ml_score", "scanned_at")} for s in scans]


@api_router.get("/analytics")
async def analytics():
    scans = await load_scans(500)
    verdicts = {"safe": 0, "suspicious": 0, "dangerous": 0}
    buckets = {}
    domains = {}
    total_risk = 0
    for s in scans:
        verdicts[s["verdict"]] = verdicts.get(s["verdict"], 0) + 1
        total_risk += s["risk_score"]
        ts = datetime.fromisoformat(s["scanned_at"])
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        key = ts.replace(minute=0, second=0, microsecond=0).isoformat()
        b = buckets.setdefault(key, {"bucket": key, "scans": 0, "threats": 0})
        b["scans"] += 1
        if s["verdict"] != "safe":
            b["threats"] += 1
        d = domains.setdefault(s["domain"], {"domain": s["domain"], "count": 0, "max_risk": 0})
        d["count"] += 1
        d["max_risk"] = max(d["max_risk"], s["risk_score"])
    timeline = sorted(buckets.values(), key=lambda x: x["bucket"])
    top_domains = sorted(domains.values(), key=lambda x: (-x["count"], -x["max_risk"]))[:6]
    avg_risk = round(total_risk / len(scans)) if scans else 0
    return {"total": len(scans), "verdicts": verdicts, "avg_risk": avg_risk, "timeline": timeline, "top_domains": top_domains}


@api_router.get("/stats")
async def stats():
    scans = await load_scans(500)
    alerts = await load_alerts(200)
    threats = sum(1 for s in scans if s["verdict"] in ("suspicious", "dangerous"))
    dangerous = sum(1 for s in scans if s["verdict"] == "dangerous")
    open_alerts = sum(1 for a in alerts if a.get("status") == "open")
    return {"total_scans": len(scans), "threats_flagged": threats, "dangerous_links": dangerous,
            "open_alerts": open_alerts, "checks_per_scan": 4}


app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)