import os
import json
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from urllib.parse import urlencode

import httpx
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import RedirectResponse, JSONResponse, HTMLResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
from dotenv import load_dotenv
from pydantic import BaseModel

load_dotenv()

APP_URL = os.environ.get("APP_URL", "http://localhost:8000").rstrip("/")
SHOPIFY_STORE = os.environ.get("SHOPIFY_STORE", "")
CLIENT_ID = os.environ.get("SHOPIFY_CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("SHOPIFY_CLIENT_SECRET", "")
SCOPES = os.environ.get("SHOPIFY_SCOPES", "read_orders,read_all_orders")
DASHBOARD_USER = os.environ.get("DASHBOARD_USER")
DASHBOARD_PASS = os.environ.get("DASHBOARD_PASS")
API_VERSION = "2025-07"

CLARITY_API_TOKEN = os.environ.get("CLARITY_API_TOKEN", "")

TOKEN_FILE = os.path.join(os.path.dirname(__file__), "tokens.json")
# NOTE: same directory/pattern as tokens.json. If you're on Railway with an
# ephemeral filesystem, mount a persistent volume at /data and point both
# TOKEN_FILE and SESSIONS_FILE there, or this resets on every redeploy.
SESSIONS_FILE = os.path.join(os.path.dirname(__file__), "session_metrics.json")

scheduler = AsyncIOScheduler()


@asynccontextmanager
async def lifespan(app: FastAPI):
    if CLARITY_API_TOKEN:
        # Run once immediately on startup, then every 24 hours.
        scheduler.add_job(
            sync_clarity_sessions,
            "interval",
            hours=24,
            next_run_time=datetime.utcnow(),
            id="clarity_daily_sync",
            replace_existing=True,
        )
        scheduler.start()
    else:
        print("[clarity-sync] CLARITY_API_TOKEN not set — automatic sync disabled, manual entry still works.")
    yield
    if scheduler.running:
        scheduler.shutdown(wait=False)


app = FastAPI(lifespan=lifespan)
security = HTTPBasic()


def load_tokens():
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE, "r") as f:
            return json.load(f)
    return {}


def save_tokens(tokens):
    with open(TOKEN_FILE, "w") as f:
        json.dump(tokens, f)


def get_token_for_shop(shop: str):
    tokens = load_tokens()
    return tokens.get(shop)


def load_session_metrics():
    if os.path.exists(SESSIONS_FILE):
        with open(SESSIONS_FILE, "r") as f:
            return json.load(f)
    return {}


def save_session_metrics(metrics):
    with open(SESSIONS_FILE, "w") as f:
        json.dump(metrics, f, indent=2)


def require_auth(credentials: HTTPBasicCredentials = Depends(security)):
    if not DASHBOARD_USER or not DASHBOARD_PASS:
        return True
    correct_user = secrets.compare_digest(credentials.username, DASHBOARD_USER)
    correct_pass = secrets.compare_digest(credentials.password, DASHBOARD_PASS)
    if not (correct_user and correct_pass):
        raise HTTPException(status_code=401, detail="Invalid credentials", headers={"WWW-Authenticate": "Basic"})
    return True


# ---------------------------------------------------------------------------
# OAuth install flow
# ---------------------------------------------------------------------------

@app.get("/install")
def install(shop: str = None):
    shop = shop or SHOPIFY_STORE
    if not shop:
        raise HTTPException(400, "Missing ?shop=yourstore.myshopify.com")
    if not shop.endswith(".myshopify.com"):
        shop = f"{shop}.myshopify.com"

    state = secrets.token_urlsafe(16)
    redirect_uri = f"{APP_URL}/auth/callback"
    params = {
        "client_id": CLIENT_ID,
        "scope": SCOPES,
        "redirect_uri": redirect_uri,
        "state": state,
    }
    auth_url = f"https://{shop}/admin/oauth/authorize?{urlencode(params)}"
    return RedirectResponse(auth_url)


@app.get("/auth/callback")
async def auth_callback(request: Request):
    params = dict(request.query_params)
    shop = params.get("shop")
    code = params.get("code")
    if not shop or not code:
        raise HTTPException(400, "Missing shop or code in callback")

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"https://{shop}/admin/oauth/access_token",
            json={
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "code": code,
            },
        )
    if resp.status_code != 200:
        raise HTTPException(400, f"Failed to get access token: {resp.text}")

    data = resp.json()
    access_token = data.get("access_token")

    tokens = load_tokens()
    tokens[shop] = access_token
    save_tokens(tokens)

    return HTMLResponse(
        f"""
        <html><body style="font-family: sans-serif; padding: 40px;">
        <h2>✅ App installed on {shop}</h2>
        <p>Access token saved. You can close this tab and view your
        <a href="{APP_URL}/">dashboard</a>.</p>
        </body></html>
        """
    )


# ---------------------------------------------------------------------------
# Order classification
# ---------------------------------------------------------------------------

def classify_order(order: dict) -> str:
    source_name = (order.get("source_name") or "").lower()
    if source_name == "pos":
        return "In-Store (POS)"

    landing_site = order.get("landing_site") or ""
    referring_site = (order.get("referring_site") or "").lower()

    utm = {}
    if "?" in landing_site:
        query = landing_site.split("?", 1)[1]
        for pair in query.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                utm[k.lower()] = v.lower()

    note_attrs = order.get("note_attributes") or []
    note_map = {}
    for attr in note_attrs:
        name = (attr.get("name") or "").lower()
        value = (attr.get("value") or "").lower()
        note_map[name] = value

    for key in ("utm_source", "utm_medium", "utm_campaign", "gclid", "fbclid", "ttclid", "msclkid"):
        if key not in utm and key in note_map and note_map[key]:
            utm[key] = note_map[key]

    utm_medium = utm.get("utm_medium", "").strip()
    utm_source = utm.get("utm_source", "").strip()
    gclid = utm.get("gclid", "")
    fbclid = utm.get("fbclid", "")
    ttclid = utm.get("ttclid", "")
    msclkid = utm.get("msclkid", "")

    def platform_label(src: str) -> str:
        mapping = {
            "google": "Google", "googleads": "Google", "adwords": "Google",
            "facebook": "Meta/Facebook", "instagram": "Meta/Instagram", "meta": "Meta",
            "tiktok": "TikTok", "pinterest": "Pinterest", "bing": "Bing",
            "twitter": "X/Twitter", "x.com": "X/Twitter", "snapchat": "Snapchat",
            "linkedin": "LinkedIn", "yahoo": "Yahoo",
        }
        for key_, label in mapping.items():
            if key_ in src:
                return label
        return src.title() if src else "Unknown"

    if gclid:
        return "Paid Ads (Google)"
    if fbclid:
        return "Paid Ads (Meta/Facebook)"
    if ttclid:
        return "Paid Ads (TikTok)"
    if msclkid:
        return "Paid Ads (Bing/Microsoft)"

    paid_mediums = {"cpc", "ppc", "paid", "ads", "pmax"}
    if any(pm in utm_medium for pm in paid_mediums):
        platform = platform_label(utm_source) if utm_source else "Unknown"
        return f"Paid Ads ({platform})"

    if "organic" in utm_medium:
        platform = platform_label(utm_source) if utm_source else "Unknown"
        return f"Organic Search ({platform})"

    if utm_medium in {"email", "newsletter"}:
        return "Email"

    if "referral" in utm_medium or "affiliate" in utm_medium:
        return "Referral/Affiliate"

    social_sources = {"facebook", "instagram", "tiktok", "pinterest", "twitter", "x.com", "snapchat", "linkedin"}
    if utm_source and any(s in utm_source for s in social_sources) and not utm_medium:
        return f"Organic Social ({platform_label(utm_source)})"

    search_domains = {"google", "bing", "yahoo", "duckduckgo"}
    if utm_source and any(s in utm_source for s in search_domains) and not utm_medium:
        return f"Organic Search ({platform_label(utm_source)})"

    if not landing_site and not referring_site:
        return "Direct"

    if referring_site and not utm:
        if any(s in referring_site for s in search_domains):
            return f"Organic Search ({platform_label(referring_site)})"
        if any(s in referring_site for s in social_sources):
            return f"Organic Social ({platform_label(referring_site)})"
        return "Referral/Affiliate"

    return "Other"


# ---------------------------------------------------------------------------
# Session metrics
#   - Auto-synced from Microsoft Clarity's Data Export API (preferred)
#   - Manual entry stays available as a fallback / for backfilling old dates
#     that predate your Clarity install (Clarity has no history export either)
# ---------------------------------------------------------------------------

class SessionEntry(BaseModel):
    date: str          # "YYYY-MM-DD"
    total_sessions: int
    desktop_sessions: int
    mobile_sessions: int


async def fetch_clarity_device_sessions(num_days: int = 1) -> dict:
    """
    Calls Clarity's Data Export API, grouped by device.
    IMPORTANT: numOfDays is a rolling window of the last N*24 hours from the
    moment of the call — NOT a calendar day. We store the result against
    today's UTC date as a best-effort daily snapshot; it won't line up
    perfectly with midnight-to-midnight if the sync runs mid-day.
    Bot sessions (totalBotSessionCount) are subtracted out.
    """
    if not CLARITY_API_TOKEN:
        raise HTTPException(500, "CLARITY_API_TOKEN is not configured")

    url = "https://www.clarity.ms/export-data/api/v1/project-live-insights"
    params = {"numOfDays": str(num_days), "dimension1": "Device"}
    headers = {
        "Authorization": f"Bearer {CLARITY_API_TOKEN}",
        "Content-Type": "application/json",
    }

    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(url, params=params, headers=headers)

    if resp.status_code == 429:
        raise HTTPException(429, "Clarity API daily rate limit hit (10 requests/project/day). Try again tomorrow.")
    if resp.status_code != 200:
        raise HTTPException(resp.status_code, f"Clarity API error: {resp.text}")

    payload = resp.json()

    total = desktop = mobile = other = 0
    for metric in payload:
        if metric.get("metricName") != "Traffic":
            continue
        for row in metric.get("information", []):
            sessions = int(row.get("totalSessionCount", 0) or 0)
            bots = int(row.get("totalBotSessionCount", 0) or 0)
            real_sessions = max(sessions - bots, 0)
            device = (row.get("Device") or "").strip().lower()

            total += real_sessions
            if device == "desktop":
                desktop += real_sessions
            elif device == "mobile":
                mobile += real_sessions
            else:
                other += real_sessions  # tablet, other, unknown

    return {
        "total_sessions": total,
        "desktop_sessions": desktop,
        "mobile_sessions": mobile,
        "other_sessions": other,
    }


async def sync_clarity_sessions():
    """Background job: pull latest Clarity data and save it under today's date."""
    try:
        data = await fetch_clarity_device_sessions(num_days=1)
    except Exception as e:
        print(f"[clarity-sync] failed: {e}")
        return

    today = datetime.utcnow().strftime("%Y-%m-%d")
    data["source"] = "clarity"
    data["synced_at"] = datetime.utcnow().isoformat() + "Z"

    metrics = load_session_metrics()
    metrics[today] = data
    save_session_metrics(metrics)
    print(f"[clarity-sync] saved sessions for {today}: {data}")


@app.post("/api/sessions/sync-clarity")
async def sync_clarity_now(authorized: bool = Depends(require_auth)):
    """Manual trigger — lets you test the connection without waiting for the daily job."""
    await sync_clarity_sessions()
    today = datetime.utcnow().strftime("%Y-%m-%d")
    metrics = load_session_metrics()
    return {"status": "synced", "date": today, "data": metrics.get(today)}


@app.post("/api/sessions")
async def save_session(entry: SessionEntry, authorized: bool = Depends(require_auth)):
    try:
        datetime.fromisoformat(entry.date)
    except ValueError:
        raise HTTPException(400, "date must be in YYYY-MM-DD format")

    if entry.desktop_sessions + entry.mobile_sessions > entry.total_sessions:
        raise HTTPException(400, "desktop_sessions + mobile_sessions cannot exceed total_sessions")

    metrics = load_session_metrics()
    metrics[entry.date] = {
        "total_sessions": entry.total_sessions,
        "desktop_sessions": entry.desktop_sessions,
        "mobile_sessions": entry.mobile_sessions,
        "other_sessions": entry.total_sessions - entry.desktop_sessions - entry.mobile_sessions,
        "source": "manual",
    }
    save_session_metrics(metrics)
    return {"status": "saved", "date": entry.date, "data": metrics[entry.date]}


@app.get("/api/sessions")
async def get_sessions(authorized: bool = Depends(require_auth)):
    return load_session_metrics()


@app.delete("/api/sessions/{date}")
async def delete_session(date: str, authorized: bool = Depends(require_auth)):
    metrics = load_session_metrics()
    if date in metrics:
        del metrics[date]
        save_session_metrics(metrics)
        return {"status": "deleted", "date": date}
    raise HTTPException(404, f"No session entry for {date}")


# ---------------------------------------------------------------------------
# Data API
# ---------------------------------------------------------------------------

@app.get("/api/orders")
async def api_orders(
    shop: str = None,
    days: int = 60,
    start_date: str = None,   # e.g. "2026-06-01"
    end_date: str = None,     # e.g. "2026-06-30"
    authorized: bool = Depends(require_auth),
):
    shop = shop or SHOPIFY_STORE
    if not shop:
        raise HTTPException(400, "No shop configured")
    if not shop.endswith(".myshopify.com"):
        shop = f"{shop}.myshopify.com"

    token = get_token_for_shop(shop)
    if not token:
        raise HTTPException(
            401,
            f"No access token for {shop}. Visit {APP_URL}/install?shop={shop} to install the app first.",
        )

    # Resolve date window: explicit start_date/end_date takes priority over `days`
    if start_date:
        try:
            since = datetime.fromisoformat(start_date).isoformat() + "Z"
        except ValueError:
            raise HTTPException(400, "start_date must be in YYYY-MM-DD format")
    else:
        since = (datetime.utcnow() - timedelta(days=days)).isoformat() + "Z"

    until = None
    if end_date:
        try:
            until = (datetime.fromisoformat(end_date) + timedelta(days=1)).isoformat() + "Z"
        except ValueError:
            raise HTTPException(400, "end_date must be in YYYY-MM-DD format")

    orders = []
    url = f"https://{shop}/admin/api/{API_VERSION}/orders.json"
    params = {
        "status": "any",
        "limit": 250,
        "created_at_min": since,
        "fields": "id,name,created_at,total_price,currency,source_name,landing_site,referring_site,financial_status,note_attributes",
    }
    if until:
        params["created_at_max"] = until

    headers = {"X-Shopify-Access-Token": token}

    async with httpx.AsyncClient() as client:
        while url:
            resp = await client.get(url, params=params, headers=headers)
            if resp.status_code != 200:
                raise HTTPException(resp.status_code, f"Shopify API error: {resp.text}")
            payload = resp.json()
            orders.extend(payload.get("orders", []))

            link = resp.headers.get("Link", "")
            next_url = None
            if link:
                parts = link.split(",")
                for part in parts:
                    if 'rel="next"' in part:
                        next_url = part.split(";")[0].strip().strip("<>")
            url = next_url
            params = None

    results = []
    channel_totals = {}
    daily_totals = {}  # { "2026-06-01": { "orders": N, "revenue": X, "channels": {...} } }

    for o in orders:
        channel = classify_order(o)
        price = float(o.get("total_price") or 0)
        created_at = o.get("created_at") or ""
        day_key = created_at[:10] if created_at else "unknown"

        channel_totals.setdefault(channel, {"orders": 0, "revenue": 0.0})
        channel_totals[channel]["orders"] += 1
        channel_totals[channel]["revenue"] += price

        day_entry = daily_totals.setdefault(day_key, {"orders": 0, "revenue": 0.0, "channels": {}})
        day_entry["orders"] += 1
        day_entry["revenue"] += price
        day_entry["channels"].setdefault(channel, {"orders": 0, "revenue": 0.0})
        day_entry["channels"][channel]["orders"] += 1
        day_entry["channels"][channel]["revenue"] += price

        results.append({
            "id": o.get("id"),
            "name": o.get("name"),
            "created_at": created_at,
            "total_price": price,
            "currency": o.get("currency"),
            "channel": channel,
        })

    daily_totals_sorted = dict(sorted(daily_totals.items()))

    # Merge in manually-entered session data + derived conversion rate
    session_metrics = load_session_metrics()
    for day, entry in daily_totals_sorted.items():
        sm = session_metrics.get(day)
        entry["sessions"] = sm  # None if not entered yet
        if sm and sm.get("total_sessions"):
            entry["conversion_rate"] = round((entry["orders"] / sm["total_sessions"]) * 100, 2)
        else:
            entry["conversion_rate"] = None

    return JSONResponse({
        "shop": shop,
        "order_count": len(results),
        "date_range": {"start": since, "end": until},
        "channel_totals": channel_totals,
        "daily_totals": daily_totals_sorted,
        "orders": results,
    })


# ---------------------------------------------------------------------------
# Dashboard (static UI)
# ---------------------------------------------------------------------------

@app.get("/")
def dashboard(authorized: bool = Depends(require_auth)):
    index_path = os.path.join(os.path.dirname(__file__), "static", "index.html")
    with open(index_path) as f:
        return HTMLResponse(f.read())


app.mount("/static", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "static")), name="static")
