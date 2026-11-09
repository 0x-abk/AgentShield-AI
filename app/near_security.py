"""Policy checks for NEAR FunctionCall access keys; no signing functionality."""
from dataclasses import dataclass
from typing import Any


@dataclass
class FunctionCallCheck:
    allowed: bool
    reasons: list[str]
    permission: dict[str, Any] | None = None


def _function_call_permission(access_key_result: dict) -> dict | None:
    permission = access_key_result.get("permission")
    if isinstance(permission, dict):
        return permission.get("FunctionCall") or permission.get("functionCall")
    return None


def validate_function_call_key(access_key_result: dict, *, expected_contract: str,
                               requested_contract: str, method_name: str,
                               attached_deposit_yocto: str = "0",
                               action_count: int = 1) -> FunctionCallCheck:
    """Fail closed unless the on-chain key is scoped to this exact call.

    NEAR FunctionCall keys are restricted to one receiver contract and allowed
    method names; they cannot authorize transfers or attached deposits. The
    access-key allowance pays gas/fees, not a general transaction spending cap.
    """
    reasons: list[str] = []
    permission = _function_call_permission(access_key_result)
    if permission is None:
        return FunctionCallCheck(False, ["Access key is not a FunctionCall key; FullAccess keys are refused"], None)

    receiver_id = permission.get("receiver_id", permission.get("receiverId"))
    method_names = permission.get("method_names", permission.get("methodNames", []))
    if requested_contract != expected_contract:
        reasons.append("Requested contract does not match AgentShield's configured contract")
    if receiver_id != expected_contract or requested_contract != receiver_id:
        reasons.append("Access key receiver does not match the requested contract")
    if not isinstance(method_names, list):
        reasons.append("Access key method_names field is malformed")
    elif not method_names:
        reasons.append("Wildcard FunctionCall keys are not accepted; explicitly scope allowed methods")
    elif method_name not in method_names:
        reasons.append("Method is not permitted by this FunctionCall key")
    if str(attached_deposit_yocto) != "0":
        reasons.append("FunctionCall key cannot attach a NEAR deposit")
    if action_count != 1:
        reasons.append("FunctionCall key must authorize exactly one FunctionCall action")
    return FunctionCallCheck(not reasons, reasons or ["On-chain FunctionCall permission matches the requested call"], permission)


def summarize_access_key(public_key: str, item: dict) -> dict:
    access_key = item.get("access_key", {})
    permission = access_key.get("permission", "Unknown")
    if isinstance(permission, dict):
        fc = permission.get("FunctionCall") or permission.get("functionCall")
        if fc:
            return {"public_key": public_key, "key_type": "FunctionCall",
                    "receiver_id": fc.get("receiver_id", fc.get("receiverId")),
                    "method_names": fc.get("method_names", fc.get("methodNames", [])),
                    "allowance_yocto": fc.get("allowance"), "nonce": access_key.get("nonce")}
    return {"public_key": public_key, "key_type": "FullAccess" if permission == "FullAccess" else "Unknown",
            "nonce": access_key.get("nonce")}
