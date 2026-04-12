"""ACP Reference Server -- FastAPI implementation of the Agent Communication Protocol."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta
from typing import Any, Optional
from urllib.parse import urlparse

import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from acp_crypto import (
    KeyManager,
    canonicalize,
    multibase_decode,
    public_key_from_multibase,
    sign_message,
    verify_signature,
)
from acp_store import IdempotencyStore, PinStore

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

load_dotenv()

AGENT_NAME = os.getenv("ACP_AGENT_NAME", "echo")
DOMAIN = os.getenv("ACP_DOMAIN", "localhost")
PORT = int(os.getenv("ACP_PORT", "3142"))
DATA_DIR = os.getenv("ACP_DATA_DIR", "./data")

MAX_BODY_SIZE = 1_048_576  # 1 MB

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
)
logger = logging.getLogger("acp.server")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _scheme() -> str:
    """Return http for localhost, https otherwise."""
    return "http" if DOMAIN == "localhost" else "https"


def _base_url() -> str:
    """Build the base URL including port when running on localhost."""
    scheme = _scheme()
    if DOMAIN == "localhost":
        return f"{scheme}://{DOMAIN}:{PORT}"
    return f"{scheme}://{DOMAIN}"


def _did() -> str:
    """Return this agent's DID."""
    return f"did:web:{DOMAIN}:{AGENT_NAME}"


def _msg_id() -> str:
    """Generate a unique message ID."""
    return f"msg_{uuid.uuid4().hex}"


def _now_iso() -> str:
    """Current UTC time in ISO-8601 format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _build_response(
    msg_type: str,
    to_did: str,
    body: dict,
    correlation_id: str | None = None,
) -> dict:
    """Build and sign a response envelope."""
    msg: dict[str, Any] = {
        "acp": "1.0",
        "id": _msg_id(),
        "type": msg_type,
        "from": _did(),
        "to": to_did,
        "createdAt": _now_iso(),
        "body": body,
    }
    if correlation_id:
        msg["correlationId"] = correlation_id
    return sign_message(msg, keys.private_key)


def _error_response(
    to_did: str,
    code: str,
    message: str,
    retryable: bool,
    correlation_id: str | None = None,
    status_code: int = 400,
) -> Response:
    """Build a signed ACP error response and wrap it in a FastAPI Response."""
    envelope = _build_response(
        msg_type="error",
        to_did=to_did,
        body={"code": code, "message": message, "retryable": retryable},
        correlation_id=correlation_id,
    )
    return Response(
        content=json.dumps(envelope),
        status_code=status_code,
        media_type="application/acp+json",
    )


# ---------------------------------------------------------------------------
# contentRef validation (ACP v0.3)
# ---------------------------------------------------------------------------

# Regex for private/reserved hostnames
_PRIVATE_HOST_RE = re.compile(
    r"^("
    r"localhost"
    r"|127\.0\.0\.1"
    r"|0\.0\.0\.0"
    r"|::1"
    r"|\[?::1\]?"
    r"|::ffff:127\.0\.0\.1"
    r"|::ffff:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|::ffff:192\.168\.\d{1,3}\.\d{1,3}"
    r"|::ffff:172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|fe80:.*"
    r"|f[cd].*"
    r"|169\.254\.\d{1,3}\.\d{1,3}"
    r"|10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r")$",
    re.IGNORECASE,
)

_HEX64_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def validate_content_refs(body: Any) -> Optional[str]:
    """Recursively walk *body* and validate every ``contentRef`` object.

    Returns an error message string if validation fails, or ``None`` if
    everything is valid.  Only structural checks are performed -- the URL
    is NOT fetched and the hash is NOT verified.
    """

    def _walk(node: Any) -> Optional[str]:
        if isinstance(node, dict):
            if "contentRef" in node:
                ref = node["contentRef"]
                if not isinstance(ref, dict):
                    return "contentRef must be an object"

                # --- url ---
                url = ref.get("url")
                if url is None:
                    return "contentRef.url is required"
                if not isinstance(url, str) or not url.startswith("https://"):
                    return "contentRef.url must start with https://"

                # Check for private/reserved hostnames
                try:
                    parsed = urlparse(url)
                    hostname = parsed.hostname or ""
                    if _PRIVATE_HOST_RE.match(hostname):
                        return f"contentRef.url must not reference private host: {hostname}"
                except Exception:
                    return "contentRef.url is not a valid URL"

                # --- sha256 ---
                sha = ref.get("sha256")
                if sha is None:
                    return "contentRef.sha256 is required"
                if not isinstance(sha, str) or not _HEX64_RE.match(sha):
                    return "contentRef.sha256 must be a 64-character hex string"

                # --- size ---
                size = ref.get("size")
                if size is None:
                    return "contentRef.size is required"
                if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
                    return "contentRef.size must be a positive integer"

            # Recurse into all values
            for v in node.values():
                err = _walk(v)
                if err:
                    return err

        elif isinstance(node, list):
            for item in node:
                err = _walk(item)
                if err:
                    return err

        return None

    return _walk(body)


# ---------------------------------------------------------------------------
# Globals (initialized in lifespan)
# ---------------------------------------------------------------------------

keys: KeyManager
pin_store: PinStore
idempotency: IdempotencyStore


async def _idempotency_cleanup_loop() -> None:
    """Periodically clean up expired idempotency entries."""
    while True:
        await asyncio.sleep(300)  # every 5 minutes
        idempotency.cleanup()


@asynccontextmanager
async def lifespan(app: FastAPI):
    global keys, pin_store, idempotency

    os.makedirs(DATA_DIR, exist_ok=True)
    keys = KeyManager(DATA_DIR)
    pin_store = PinStore(DATA_DIR)
    idempotency = IdempotencyStore()

    logger.info("=== ACP Server Started ===")
    logger.info("  Agent : %s", AGENT_NAME)
    logger.info("  DID   : %s", _did())
    logger.info("  Inbox : %s/%s/inbox", _base_url(), AGENT_NAME)
    logger.info("  PubKey: %s", keys.public_key_multibase)
    logger.info("==========================")

    cleanup_task = asyncio.create_task(_idempotency_cleanup_loop())
    yield
    cleanup_task.cancel()
    try:
        await cleanup_task
    except asyncio.CancelledError:
        pass


app = FastAPI(title="ACP Server", lifespan=lifespan)

# ---------------------------------------------------------------------------
# Routes: Discovery (static paths BEFORE parameterized paths)
# ---------------------------------------------------------------------------


@app.get("/.well-known/acp/index.json")
async def agent_index() -> Response:
    """Serve the agent index for this domain."""
    index = {
        "domain": DOMAIN,
        "protocol": "acp/1.0",
        "agents": [
            {
                "name": AGENT_NAME,
                "url": f"/.well-known/acp/{AGENT_NAME}.json",
                "summary": "Echo agent for testing",
            }
        ],
        "pagination": {"hasMore": False, "total": 1},
    }
    return Response(
        content=json.dumps(index, indent=2),
        media_type="application/json",
    )


@app.get("/.well-known/acp/{name}.json")
async def agent_card(name: str) -> Response:
    """Serve the Agent Card for an agent."""
    if name != AGENT_NAME:
        return Response(status_code=404, content="Agent not found")

    card = {
        "acp": "1.0",
        "name": AGENT_NAME,
        "did": _did(),
        "inbox": f"{_base_url()}/{AGENT_NAME}/inbox",
        "publicKey": keys.public_key_multibase,
        "description": "Echo agent -- returns whatever you send it. For testing ACP message flow.",
        "capabilities": [
            {
                "name": "echo",
                "description": "Echoes back the message body. Useful for testing signing, verification, and message flow.",
                "schema": {"type": "object"},
                "responseSchema": {"type": "object"},
            }
        ],
        "auth": {
            "required": True,
            "methods": ["did-signature"],
            "openAccess": True,
            "allowlist": [],
            "denylist": [],
        },
        "rateLimit": {"requests": 100, "window": "60s"},
        "contact": f"admin@{DOMAIN}",
    }
    return Response(
        content=json.dumps(card, indent=2),
        media_type="application/json",
    )


@app.get("/{name}/did.json")
async def did_document(name: str) -> Response:
    """Serve the DID document for an agent."""
    if name != AGENT_NAME:
        return Response(status_code=404, content="Agent not found")

    did = _did()
    doc = {
        "@context": "https://www.w3.org/ns/did/v1",
        "id": did,
        "verificationMethod": [
            {
                "id": f"{did}#key-1",
                "type": "Ed25519VerificationKey2020",
                "controller": did,
                "publicKeyMultibase": keys.public_key_multibase,
            }
        ],
        "authentication": [f"{did}#key-1"],
        "assertionMethod": [f"{did}#key-1"],
        "service": [
            {
                "id": "#acp",
                "type": "AgentCommunicationProtocol",
                "serviceEndpoint": f"{_base_url()}/{AGENT_NAME}/inbox",
            }
        ],
    }
    return Response(
        content=json.dumps(doc, indent=2),
        media_type="application/json",
    )


# ---------------------------------------------------------------------------
# Route: Inbox
# ---------------------------------------------------------------------------


@app.post("/{name}/inbox")
async def inbox(name: str, request: Request) -> Response:
    """Receive and process ACP messages."""
    if name != AGENT_NAME:
        return Response(status_code=404, content="Agent not found")

    # --- Content-Type check ---
    content_type = request.headers.get("content-type", "")
    if "application/acp+json" not in content_type and "application/json" not in content_type:
        return Response(
            status_code=415,
            content=json.dumps({"error": "Content-Type must be application/acp+json or application/json"}),
            media_type="application/json",
        )

    # --- Size check ---
    raw_body = await request.body()
    if len(raw_body) > MAX_BODY_SIZE:
        return _error_response(
            to_did="unknown",
            code="MESSAGE_TOO_LARGE",
            message=f"Message exceeds maximum size of {MAX_BODY_SIZE} bytes",
            retryable=False,
            status_code=413,
        )

    # --- Parse JSON ---
    try:
        msg = json.loads(raw_body)
    except json.JSONDecodeError:
        return Response(
            status_code=400,
            content=json.dumps({"error": "Invalid JSON"}),
            media_type="application/json",
        )

    # --- Validate required envelope fields ---
    required_fields = ["acp", "id", "type", "from", "to", "createdAt", "body", "signature"]
    missing = [f for f in required_fields if f not in msg]
    if missing:
        sender_did = msg.get("from", "unknown")
        return _error_response(
            to_did=sender_did,
            code="SCHEMA_INVALID",
            message=f"Missing required fields: {', '.join(missing)}",
            retryable=False,
            correlation_id=msg.get("id"),
        )

    sender_did = msg["from"]
    msg_id = msg["id"]
    msg_type = msg["type"]
    correlation_id = msg.get("correlationId", msg_id)

    # --- Check expiration ---
    now = datetime.now(timezone.utc)
    if "expiresAt" in msg and msg["expiresAt"]:
        try:
            expires = datetime.fromisoformat(msg["expiresAt"].replace("Z", "+00:00"))
            if now > expires:
                return _error_response(
                    to_did=sender_did,
                    code="MESSAGE_EXPIRED",
                    message="Message has expired",
                    retryable=False,
                    correlation_id=correlation_id,
                )
        except (ValueError, TypeError):
            pass  # If expiresAt is malformed, skip expiration check
    else:
        # No expiresAt -- reject if createdAt > 24 hours old
        try:
            created = datetime.fromisoformat(msg["createdAt"].replace("Z", "+00:00"))
            if now - created > timedelta(hours=24):
                return _error_response(
                    to_did=sender_did,
                    code="MESSAGE_EXPIRED",
                    message="Message older than 24 hours with no expiresAt",
                    retryable=False,
                    correlation_id=correlation_id,
                )
        except (ValueError, TypeError):
            pass

    # --- Idempotency check ---
    if idempotency.has_message(msg_id):
        return _error_response(
            to_did=sender_did,
            code="SCHEMA_INVALID",
            message=f"Duplicate message ID: {msg_id}",
            retryable=False,
            correlation_id=correlation_id,
            status_code=409,
        )

    # --- Resolve sender's public key ---
    sender_pub_key = None
    is_first_contact = not pin_store.has_pin(sender_did)

    if not is_first_contact:
        # Use pinned key
        pin = pin_store.get_pin(sender_did)
        pinned_multibase = pin["public_key_multibase"]

        # If sender provides a publicKey in body, check it matches pin
        body_key = msg.get("body", {}).get("publicKey")
        if body_key and body_key != pinned_multibase:
            return _error_response(
                to_did=sender_did,
                code="KEY_MISMATCH",
                message="Sender's public key does not match pinned key",
                retryable=False,
                correlation_id=correlation_id,
            )

        try:
            sender_pub_key = public_key_from_multibase(pinned_multibase)
        except Exception:
            return _error_response(
                to_did=sender_did,
                code="AUTH_FAILED",
                message="Failed to load pinned public key",
                retryable=False,
                correlation_id=correlation_id,
            )
    else:
        # First contact -- require negotiate type
        if msg_type != "negotiate":
            return _error_response(
                to_did=sender_did,
                code="FIRST_CONTACT_REQUIRED",
                message="First interaction must be a negotiate message with firstContact: true",
                retryable=True,
                correlation_id=correlation_id,
            )

        # Accept publicKey from body
        body_key = msg.get("body", {}).get("publicKey")
        if not body_key:
            return _error_response(
                to_did=sender_did,
                code="AUTH_FAILED",
                message="First-contact negotiate must include body.publicKey",
                retryable=False,
                correlation_id=correlation_id,
            )

        try:
            sender_pub_key = public_key_from_multibase(body_key)
        except Exception:
            return _error_response(
                to_did=sender_did,
                code="AUTH_FAILED",
                message="Invalid publicKey format",
                retryable=False,
                correlation_id=correlation_id,
            )

    # --- Verify signature ---
    if not verify_signature(msg, sender_pub_key):
        return _error_response(
            to_did=sender_did,
            code="AUTH_FAILED",
            message="Signature verification failed",
            retryable=False,
            correlation_id=correlation_id,
            status_code=401,
        )

    # --- Validate contentRef objects in body (ACP v0.3) ---
    content_ref_err = validate_content_refs(msg.get("body", {}))
    if content_ref_err:
        return _error_response(
            to_did=sender_did,
            code="SCHEMA_INVALID",
            message=content_ref_err,
            retryable=False,
            correlation_id=correlation_id,
        )

    # --- Pin key on first contact ---
    if is_first_contact:
        body_key = msg.get("body", {}).get("publicKey")
        pin_store.set_pin(sender_did, body_key)
        logger.info("First contact from %s -- key pinned", sender_did)

    # --- Record message ID ---
    idempotency.add_message(msg_id)

    # --- Process by message type ---
    if msg_type == "negotiate":
        response_envelope = _build_response(
            msg_type="acknowledge",
            to_did=sender_did,
            body={"accepted": True, "message": "First contact acknowledged, key pinned"},
            correlation_id=correlation_id,
        )
        logger.info("Acknowledged negotiate from %s", sender_did)

    elif msg_type == "request":
        capability = msg.get("capability")
        if capability == "echo":
            response_envelope = _build_response(
                msg_type="response",
                to_did=sender_did,
                body=msg["body"],
                correlation_id=correlation_id,
            )
            logger.info("Echoed request from %s", sender_did)
        else:
            response_envelope = _build_response(
                msg_type="error",
                to_did=sender_did,
                body={
                    "code": "CAPABILITY_UNKNOWN",
                    "message": f"Unknown capability: {capability}",
                    "retryable": False,
                },
                correlation_id=correlation_id,
            )
            logger.warning("Unknown capability '%s' from %s", capability, sender_did)

    elif msg_type == "cancel":
        response_envelope = _build_response(
            msg_type="acknowledge",
            to_did=sender_did,
            body={"cancelled": True},
            correlation_id=correlation_id,
        )
        logger.info("Acknowledged cancel from %s", sender_did)

    else:
        response_envelope = _build_response(
            msg_type="acknowledge",
            to_did=sender_did,
            body={"acknowledged": True},
            correlation_id=correlation_id,
        )
        logger.info("Acknowledged %s from %s", msg_type, sender_did)

    return Response(
        content=json.dumps(response_envelope, indent=2),
        status_code=200,
        media_type="application/acp+json",
    )


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    uvicorn.run(
        "server:app",
        host="0.0.0.0",
        port=PORT,
        log_level="info",
    )
