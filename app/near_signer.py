"""NEAR Testnet signer adapter.

The application never exposes a generic signing primitive. This adapter only
submits one zero-deposit FunctionCall to the server-pinned contract after the
API has checked the assessment, human approval (if needed), and on-chain key
permissions. The private key is read from the process environment only.
"""
from __future__ import annotations

import os
from typing import Any


class SignerNotConfigured(RuntimeError):
    pass


class SignerUnavailable(RuntimeError):
    pass


def _transaction_hash(result: Any) -> str | None:
    transaction = getattr(result, "transaction", None)
    value = getattr(transaction, "hash", None)
    if value:
        return str(value)
    if isinstance(result, dict):
        tx = result.get("transaction", {})
        if isinstance(tx, dict) and tx.get("hash"):
            return str(tx["hash"])
        if result.get("transaction_hash"):
            return str(result["transaction_hash"])
    return None


async def submit_function_call(*, account_id: str, contract_id: str,
                               method_name: str, args: dict[str, Any],
                               gas: int, deposit_yocto: int = 0) -> dict[str, Any]:
    """Submit exactly one FunctionCall using py-near; never supports transfers."""
    network = os.getenv("NEAR_NETWORK", "testnet").lower()
    if network != "testnet":
        raise SignerNotConfigured("Live signing is restricted to NEAR Testnet in this MVP")
    configured_account = os.getenv("NEAR_SIGNER_ACCOUNT_ID", "").strip()
    private_key = os.getenv("NEAR_SIGNER_PRIVATE_KEY", "").strip()
    if not configured_account or not private_key:
        raise SignerNotConfigured("NEAR_SIGNER_ACCOUNT_ID and NEAR_SIGNER_PRIVATE_KEY must be configured")
    if account_id != configured_account:
        raise SignerNotConfigured("Requested signer account does not match the server-pinned signer account")
    if deposit_yocto != 0:
        raise SignerNotConfigured("AgentShield MVP only permits zero-deposit FunctionCall transactions")

    try:
        from py_near.account import Account
    except ImportError:
        try:
            from pynear.account import Account
        except ImportError as exc:
            raise SignerUnavailable("Install the NEAR SDK with: pip install py-near==1.2.22") from exc

    rpc_url = os.getenv("NEAR_RPC_URL", "https://rpc.testnet.near.org").strip()
    if not rpc_url.startswith("https://"):
        raise SignerNotConfigured("NEAR_RPC_URL must use HTTPS")
    account = Account(configured_account, private_key, rpc_addr=rpc_url)
    try:
        await account.startup()
        result = await account.function_call(
            contract_id,
            method_name,
            args,
            gas=gas,
            amount=0,
            nowait=False,
        )
    except Exception as exc:
        # Do not include key material or raw exception context in API responses.
        raise SignerUnavailable(f"NEAR Testnet transaction failed: {type(exc).__name__}") from exc

    return {
        "submitted": True,
        "network": "testnet",
        "transaction_hash": _transaction_hash(result),
        "result": "submitted_to_near",
    }
