"""
chronospay.main
~~~~~~~~~~~~~~~
Real-time authorization router for the payment orchestration layer.

Routes cardholder authorization requests to the right processor based on
merchant config. Keeps PAN out of logs and validates webhook provenance.

Assumptions baked in:
- Secrets are injected at runtime (see k8s/external-secret.yaml)
- Processors are allowlisted via env — no dynamic routing to arbitrary hosts
- We never store CVV; PAN is masked before it touches any log sink
"""

import hashlib
import hmac
import os
import time
from typing import Optional

import httpx
import structlog
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from pydantic import BaseModel, field_validator

log = structlog.get_logger()

# Runtime-injected. If any of these are missing the pod crashes on startup,
# which is intentional — a misconfigured pod shouldn't serve traffic silently.
PROCESSOR_API_KEY  = os.environ["PROCESSOR_API_KEY"]
WEBHOOK_SECRET     = os.environ["WEBHOOK_SECRET"]
DB_CONNECTION_STR  = os.environ["DB_CONNECTION_STR"]
ALLOWED_PROCESSORS = os.environ.get("ALLOWED_PROCESSORS", "stripe,adyen,conekta").split(",")

app = FastAPI(title="ChronosPay", version="1.0.0", docs_url=None, redoc_url=None)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["*.payments.io", "localhost"])


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class AuthRequest(BaseModel):
    merchant_id:     str
    amount_cents:    int
    currency:        str
    processor:       str
    masked_pan:      str   # 4-digit suffix only — full PAN never crosses this boundary
    expiry_month:    int
    expiry_year:     int
    idempotency_key: str

    @field_validator("processor")
    @classmethod
    def _check_processor(cls, v: str) -> str:
        if v not in ALLOWED_PROCESSORS:
            raise ValueError(f"processor '{v}' not in allowlist")
        return v

    @field_validator("amount_cents")
    @classmethod
    def _check_amount(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("amount must be positive")
        return v


class AuthResponse(BaseModel):
    authorization_id: str
    status:           str   # approved | declined | error
    processor:        str
    latency_ms:       int
    timestamp:        str


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


@app.post("/v1/authorize", response_model=AuthResponse)
async def authorize(
    payload: AuthRequest,
    x_idempotency_key: Optional[str] = Header(None),
):
    t0 = time.monotonic()

    log.info("auth.attempt",
        merchant=payload.merchant_id,
        processor=payload.processor,
        amount=payload.amount_cents,
        currency=payload.currency,
        pan_suffix=payload.masked_pan,
        idem=payload.idempotency_key,
    )

    try:
        result = await _forward(payload)
    except Exception as exc:
        log.error("auth.upstream_error", processor=payload.processor, error=str(exc))
        raise HTTPException(502, "processor unavailable") from exc

    latency = int((time.monotonic() - t0) * 1000)
    log.info("auth.result",
        auth_id=result["id"],
        status=result["status"],
        processor=payload.processor,
        latency_ms=latency,
    )

    return AuthResponse(
        authorization_id=result["id"],
        status=result["status"],
        processor=payload.processor,
        latency_ms=latency,
        timestamp=result["timestamp"],
    )


@app.post("/v1/webhook")
async def webhook(request: Request):
    body = await request.body()
    sig  = request.headers.get("X-Webhook-Signature", "")

    if not _verify_sig(body, sig):
        log.warning("webhook.bad_signature", remote=request.client.host)
        raise HTTPException(401, "invalid signature")

    log.info("webhook.accepted", bytes=len(body))
    return {"status": "accepted"}


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

async def _forward(payload: AuthRequest) -> dict:
    async with httpx.AsyncClient(timeout=5.0) as client:
        r = await client.post(
            f"https://api.{payload.processor}.com/v1/authorize",
            json={
                "amount":          payload.amount_cents,
                "currency":        payload.currency,
                "idempotency_key": payload.idempotency_key,
            },
            headers={
                "Authorization": f"Bearer {PROCESSOR_API_KEY}",
                "Content-Type":  "application/json",
            },
        )
        r.raise_for_status()
        return r.json()


def _verify_sig(body: bytes, signature: str) -> bool:
    # compare_digest instead of == to avoid timing oracle
    expected = hmac.new(WEBHOOK_SECRET.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)
