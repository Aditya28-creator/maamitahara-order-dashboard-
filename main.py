import os
import json
import secrets
import base64
from datetime import datetime, timedelta
from urllib.parse import urlencode

import httpx
from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import RedirectResponse, JSONResponse, HTMLResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
from dotenv import load_dotenv

load_dotenv()

APP_URL = os.environ.get("APP_URL", "http://localhost:8000").rstrip("/")
SHOPIFY_STORE = os.environ.get("SHOPIFY_STORE", "")
CLIENT_ID = os.environ.get("SHOPIFY_CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("SHOPIFY_CLIENT_SECRET", "")
SCOPES = os.environ.get("SHOPIFY_SCOPES", "read_orders,read_all_orders")
DASHBOARD_USER = os.environ.get("DASHBOARD_USER")
DASHBOARD_PASS = os.environ.get("DASHBOARD_PASS")
API_VERSION = "2025-07"

TOKEN_FILE = os.path.join(os.path.dirname(__file__), "tokens.json")

app = FastAPI()
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


def require_auth(credentials: HTTPBasicCredentials = Depends(security)):
    # If no dashboard credentials are configured, skip auth (local dev)
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

    # Parse UTM params out of landing_site query string
    utm = {}
    if "?" in landing_site:
        query = landing_site.split("?", 1)[1]
        for pair in query.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                utm[k.lower()] = v.lower()

    # Fallback: some checkouts (e.g. third-party checkouts like Razorpay
    # Magic Checkout) bypass Shopify's native checkout, so landing_site
    # never gets populated. In that case UTM params are often captured
    # into note_attributes (custom checkout fields) instead.
    note_attrs = order.get("note_attributes") or []
    note_map = {}
    for attr in note_attrs:
        name = (attr.get("name") or "").lower()
        value = (attr.get("value") or "").lower()
        note_map[name] = value

    for key in ("utm_source", "utm_medium", "utm_campaign", "gclid", "fbclid"):
        if key not in utm and key in note_map and note_map[key]:
            utm[key] = note_map[key]

    utm_medium = utm.get("utm_medium", "")
    utm_source = utm.get("utm_source", "")
    gclid = utm.get("gclid", "")
    fbclid = utm.get("fbclid", "")

    # A click ID (gclid/fbclid) is a strong signal the visit came from a
    # paid ad click, regardless of what utm_medium says.
    if gclid or fbclid:
        return "Paid Ads"

    paid_mediums = {"cpc", "ppc", "paid", "ads", "pmax"}
    if any(pm in utm_medium for pm in paid_mediums):
        return "Paid Ads"

    if "organic" in utm_medium:
        return "Organic Search"

    if utm_medium in {"email", "newsletter"}:
        return "Email"

    if "referral" in utm_medium or "affiliate" in utm_medium:
        return "Referral/Affiliate"

    social_sources = {"facebook", "instagram", "tiktok", "pinterest", "twitter", "x.com", "snapchat", "linkedin"}
    if utm_source and any(s in utm_source for s in social_sources) and not utm_medium:
        return "Organic Social"

    search_domains = {"google", "bing", "yahoo", "duckduckgo"}
    if utm_source and any(s in utm_source for s in search_domains) and not utm_medium:
        return "Organic Search"

    if not landing_site and not referring_site:
        return "Direct"

    if referring_site and not utm:
        if any(s in referring_site for s in search_domains):
            return "Organic Search"
        if any(s in referring_site for s in social_sources):
            return "Organic Social"
        return "Referral/Affiliate"

    return "Other"


# ---------------------------------------------------------------------------
# Data API
# ---------------------------------------------------------------------------

@app.get("/api/orders")
async def api_orders(shop: str = None, days: int = 60, authorized: bool = Depends(require_auth)):
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

    since = (datetime.utcnow() - timedelta(days=days)).isoformat() + "Z"

    orders = []
    url = f"https://{shop}/admin/api/{API_VERSION}/orders.json"
    params = {
        "status": "any",
        "limit": 250,
        "created_at_min": since,
        "fields": "id,name,created_at,total_price,currency,source_name,landing_site,referring_site,financial_status,note_attributes",
    }

    headers = {"X-Shopify-Access-Token": token}

    async with httpx.AsyncClient() as client:
        while url:
            resp = await client.get(url, params=params, headers=headers)
            if resp.status_code != 200:
                raise HTTPException(resp.status_code, f"Shopify API error: {resp.text}")
            payload = resp.json()
            orders.extend(payload.get("orders", []))

            # Handle pagination via Link header
            link = resp.headers.get("Link", "")
            next_url = None
            if link:
                parts = link.split(",")
                for part in parts:
                    if 'rel="next"' in part:
                        next_url = part.split(";")[0].strip().strip("<>")
            url = next_url
            params = None  # next_url already has query params baked in

    results = []
    channel_totals = {}
    for o in orders:
        channel = classify_order(o)
        price = float(o.get("total_price") or 0)
        channel_totals[channel] = channel_totals.get(channel, {"orders": 0, "revenue": 0.0})
        channel_totals[channel]["orders"] += 1
        channel_totals[channel]["revenue"] += price
        results.append({
            "id": o.get("id"),
            "name": o.get("name"),
            "created_at": o.get("created_at"),
            "total_price": price,
            "currency": o.get("currency"),
            "channel": channel,
        })

    return JSONResponse({
        "shop": shop,
        "order_count": len(results),
        "channel_totals": channel_totals,
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
