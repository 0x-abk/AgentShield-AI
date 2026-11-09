"""Read-only NEAR JSON-RPC helpers. This module never signs or submits transactions."""
import os
import httpx

NETWORK = os.getenv("NEAR_NETWORK", "testnet").lower()
if NETWORK not in {"testnet", "mainnet"}:
    raise RuntimeError("NEAR_NETWORK must be 'testnet' or 'mainnet'")
DEFAULT_RPC = "https://rpc.testnet.near.org" if NETWORK == "testnet" else "https://rpc.mainnet.near.org"
RPC_URL = os.getenv("NEAR_RPC_URL", DEFAULT_RPC)


async def rpc(method: str, params: dict):
    body = {"jsonrpc": "2.0", "id": "agentshield", "method": method, "params": params}
    async with httpx.AsyncClient(timeout=12.0) as client:
        response = await client.post(RPC_URL, json=body)
        response.raise_for_status()
        data = response.json()
    if "error" in data:
        raise RuntimeError(str(data["error"]))
    if "result" not in data:
        raise RuntimeError("NEAR RPC response did not contain a result")
    return data["result"]


async def account_exists(account_id: str) -> bool:
    try:
        await rpc("query", {"request_type": "view_account", "finality": "final", "account_id": account_id})
        return True
    except RuntimeError as exc:
        # A missing account is a normal negative result; other RPC errors should surface.
        if "UNKNOWN_ACCOUNT" in str(exc) or "does not exist" in str(exc).lower():
            return False
        raise


async def access_key_list(account_id: str) -> dict:
    return await rpc("query", {"request_type": "view_access_key_list", "finality": "final", "account_id": account_id})


async def view_access_key(account_id: str, public_key: str) -> dict:
    return await rpc("query", {"request_type": "view_access_key", "finality": "final",
                                "account_id": account_id, "public_key": public_key})


async def contract_code(contract_id: str) -> dict:
    return await rpc("query", {"request_type": "view_code", "finality": "final", "account_id": contract_id})
