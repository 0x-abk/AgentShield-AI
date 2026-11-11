from dotenv import load_dotenv
load_dotenv()
from contextlib import asynccontextmanager
import os
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from pathlib import Path
from .models import TransactionRequest, RiskDecision, ApprovalRequest, BlocklistReport
from .risk_engine import RiskEngine
from . import storage
from .near_rpc import account_exists, access_key_list, view_access_key, contract_code, NETWORK
from .near_security import validate_function_call_key, summarize_access_key
from .models import NearFunctionCallCheckRequest, NearFunctionCallExecutionRequest
from .near_signer import submit_function_call, SignerNotConfigured, SignerUnavailable
import secrets
from fastapi.responses import JSONResponse
import json
from .rate_limit import RateLimiter

rate_limiter = RateLimiter(max_requests=60, window_seconds=60)

@asynccontextmanager
async def lifespan(app: FastAPI):
    storage.init_db()
    yield

app = FastAPI(title="AgentShield AI", version="0.2.0", description="Deterministic security gate for AI-agent transactions", lifespan=lifespan)
@app.middleware("http")
async def require_api_key(request, call_next):
    path = request.url.path

    if path.startswith("/v1/"):
        if (
            path.startswith("/v1/approvals/")
            or path.startswith("/v1/audit-logs/")
        ):
            env_name = "AGENTSHIELD_REVIEWER_API_KEY"
            error_message = "Invalid or missing reviewer API key"
        else:
            env_name = "AGENTSHIELD_API_KEY"
            error_message = "Invalid or missing API key"

        expected = os.getenv(env_name, "").strip()

        if not expected:
            return JSONResponse(
                status_code=503,
                content={"detail": "API authentication is not configured"}
            )

        authorization = request.headers.get("Authorization", "")
        scheme, _, supplied = authorization.partition(" ")

        if (
            scheme.lower() != "bearer"
            or not supplied
            or not secrets.compare_digest(supplied, expected)
        ):
            return JSONResponse(
                status_code=401,
                content={"detail": error_message}
            )

    if path.startswith("/v1/"):
        client_id = request.client.host if request.client else "unknown"
        allowed, retry_after = rate_limiter.allow(client_id)

        if not allowed:
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded. Try again later."},
                headers={"Retry-After": str(retry_after)}
            )

    return await call_next(request)
engine = RiskEngine()

@app.get("/", include_in_schema=False)
def dashboard():
    return FileResponse(Path(__file__).resolve().parent.parent / "frontend" / "index.html")

@app.get("/health")
def health():
    return {"status":"ok", "service":"AgentShield AI"}

@app.post("/v1/assess", response_model=RiskDecision)
def assess(tx: TransactionRequest):
    decision, level, score, reasons, evidence = engine.assess(tx)
    payload = tx.model_dump()
    txid = storage.add_decision(payload, decision.value, level.value, score, reasons, evidence)
    return RiskDecision(decision=decision, risk_level=level, risk_score=score,
                        reasons=reasons, evidence=evidence,
                        requires_human_approval=decision.value == "WARN", transaction_id=txid)

@app.post("/v1/approvals/{transaction_id}")
def review(transaction_id: str, request: ApprovalRequest):
    item = storage.get_decision(transaction_id)
    if not item:
        raise HTTPException(404, "Transaction assessment not found")
    if item["decision"] != "WARN":
        raise HTTPException(409, "Only WARN transactions can be reviewed")
    saved = storage.save_approval(
        transaction_id,
        request.approved,
        request.reviewer,
        request.note,
    )

    if not saved:
        raise HTTPException(409, "Transaction has already been reviewed")

    return {
        "transaction_id": transaction_id,
        "approved": request.approved,
        "reviewer": request.reviewer,
    }

@app.get("/v1/audit-logs/{transaction_id}")
def get_transaction_audit_logs(transaction_id: str):
    logs = storage.get_audit_logs(transaction_id)
    return {
        "transaction_id": transaction_id,
        "audit_logs": logs,
    }


@app.get("/v1/blocklist")
def get_blocklist_entries():
    return list(storage.get_blocklist().values())

@app.post("/v1/blocklist")
def add_blocklist(report: BlocklistReport):
    storage.report_block(report.receiver, report.reason, report.evidence_url, report.reporter)
    return {"status":"reported", "receiver":report.receiver.lower()}

@app.get("/v1/history")
def get_history(limit: int = Query(default=50, ge=1, le=200)):
    return storage.history(limit)

@app.get("/v1/near/account/{account_id}")
async def near_account(account_id: str):
    """Optional testnet account existence check; does not infer trustworthiness."""
    try:
        exists = await account_exists(account_id)
        return {"account_id":account_id, "exists":exists, "network":"testnet"}
    except Exception:
        raise HTTPException(502, "NEAR RPC unavailable; please try again later")


@app.get("/v1/near/access-keys/{account_id}")
async def near_access_keys(account_id: str):
    """Read-only inventory of an account's NEAR access keys."""
    try:
        result = await access_key_list(account_id)
        return {"account_id": account_id, "network": NETWORK,
                "keys": [summarize_access_key(item.get("public_key", ""), item)
                         for item in result.get("keys", [])]}
    except Exception:
        raise HTTPException(502, "NEAR RPC unavailable; please try again later")


@app.post("/v1/near/validate-function-call")
async def near_validate_function_call(request: NearFunctionCallCheckRequest):
    """Check an on-chain key's permission before an agent can request signing.

    This endpoint validates permission only. It does not sign or broadcast.
    """
    try:
        onchain_key = await view_access_key(request.account_id, request.public_key)
    except Exception:
        raise HTTPException(502, "Unable to verify access key on NEAR; please try again later")
    allowed_contract = os.getenv("NEAR_ALLOWED_CONTRACT_ID", "").strip().lower()
    if not allowed_contract:
        raise HTTPException(503, "NEAR_ALLOWED_CONTRACT_ID is not configured; refusing to validate an unpinned contract")
    check = validate_function_call_key(
        onchain_key, expected_contract=allowed_contract,
        requested_contract=request.requested_contract.lower(), method_name=request.method_name,
        attached_deposit_yocto=request.attached_deposit_yocto, action_count=request.action_count)
    return {"allowed": check.allowed, "decision": "ALLOW" if check.allowed else "BLOCK",
            "reasons": check.reasons, "permission": check.permission,
            "signing_performed": False, "network": NETWORK}


@app.get("/v1/near/contract/{contract_id}/code")
async def near_contract_code(contract_id: str):
    """Return the deployed code hash for change-monitoring baselines."""
    try:
        result = await contract_code(contract_id)
        return {"contract_id": contract_id, "code_hash": result.get("hash"),
                "block_height": result.get("block_height"), "network": NETWORK}
    except Exception:
        raise HTTPException(502, "NEAR RPC unavailable; please try again later")


@app.post("/v1/near/execute-function-call")
async def near_execute_function_call(request: NearFunctionCallExecutionRequest):
    """Fail-closed Testnet execution endpoint. Only one zero-deposit FunctionCall is supported."""
    assessment = storage.get_decision(request.transaction_id)
    if not assessment:
        raise HTTPException(404, "Transaction assessment not found")
    if assessment["decision"] == "BLOCK":
        raise HTTPException(403, "AgentShield BLOCK: transaction was not signed")
    if assessment["decision"] == "WARN":
        approval = storage.get_approval(request.transaction_id)
        if not approval or not approval.get("approved"):
            raise HTTPException(409, "Human approval is required before signing")
    if assessment["decision"] not in {"ALLOW", "WARN"}:
        raise HTTPException(403, "Unknown decision; refusing to sign")

    try:
        assessed_payload = json.loads(assessment["payload"])
    except (TypeError, json.JSONDecodeError):
        raise HTTPException(409, "Assessment payload is invalid; refusing to sign")

    allowed_contract = os.getenv("NEAR_ALLOWED_CONTRACT_ID", "").strip().lower()
    configured_account = os.getenv("NEAR_SIGNER_ACCOUNT_ID", "").strip()
    configured_public_key = os.getenv("NEAR_SIGNER_PUBLIC_KEY", "").strip()
    if not allowed_contract or not configured_account or not configured_public_key:
        raise HTTPException(503, "Signer account, public key, and allowed contract must be pinned in server configuration")
    if request.account_id != configured_account or request.public_key != configured_public_key:
        raise HTTPException(403, "Signer account or public key does not match server configuration")
    if request.contract_id.lower() != allowed_contract or assessed_payload.get("receiver", "").lower() != allowed_contract:
        raise HTTPException(403, "Contract does not match the contract in the assessment and server policy")
    if assessed_payload.get("action", "").lower() != "function_call":
        raise HTTPException(409, "Assessment was not created for a FunctionCall")
    if assessed_payload.get("function_method") != request.method_name or assessed_payload.get("function_args", {}) != request.args:
        raise HTTPException(409, "Function method or arguments differ from the assessed transaction")
    allowed_methods = {item.strip() for item in os.getenv("NEAR_ALLOWED_METHODS", "").split(",") if item.strip()}
    if not allowed_methods:
        raise HTTPException(503, "NEAR_ALLOWED_METHODS must explicitly list permitted contract methods")
    if request.method_name not in allowed_methods:
        raise HTTPException(403, "Function method is not in AgentShield's server-side allowlist")
    if request.attached_deposit_yocto != "0" or request.action_count != 1:
        raise HTTPException(403, "Only one zero-deposit FunctionCall is permitted")

    try:
        key_data = await view_access_key(request.account_id, request.public_key)
    except Exception as exc:
        raise HTTPException(502, "Unable to verify signer access key on NEAR; refusing to sign") from exc
    check = validate_function_call_key(
        key_data, expected_contract=allowed_contract,
        requested_contract=request.contract_id.lower(), method_name=request.method_name,
        attached_deposit_yocto=request.attached_deposit_yocto, action_count=request.action_count,
    )
    if not check.allowed:
        raise HTTPException(403, {"message": "On-chain FunctionCall key permission check failed", "reasons": check.reasons})

    # Atomic replay guard: only one request may reserve this assessment for signing.
    # The guard is deliberately fail-closed if the process crashes mid-broadcast.
    if not storage.claim_execution(request.transaction_id):
        previous = storage.get_execution(request.transaction_id)
        raise HTTPException(
            409,
            f"Transaction already attempted; execution status={previous['status'] if previous else 'UNKNOWN'}. "
            "Reconcile chain state before any manual recovery.",
        )

    try:
        result = await submit_function_call(
            account_id=request.account_id, contract_id=request.contract_id,
            method_name=request.method_name, args=request.args, gas=request.gas,
            deposit_yocto=0,
        )
    except (SignerNotConfigured, SignerUnavailable) as exc:
        storage.finish_execution(request.transaction_id, status="FAILED", error=str(exc))
        status_code = 503 if isinstance(exc, SignerNotConfigured) else 502
        raise HTTPException(status_code, str(exc)) from exc
    except Exception as exc:
        storage.finish_execution(request.transaction_id, status="FAILED", error="Unexpected signer failure")
        raise HTTPException(502, "Unexpected signer failure; execution is locked pending chain reconciliation") from exc

    tx_hash = result.get("transaction_hash") if isinstance(result, dict) else None
    storage.finish_execution(request.transaction_id, status="SUBMITTED", tx_hash=tx_hash)
    return {"decision": assessment["decision"], "signing_performed": True,
            "network": "testnet", "transaction_id": request.transaction_id, **result}
