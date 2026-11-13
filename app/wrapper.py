"""Fail-closed agent execution gate. Signing is deliberately injected by caller."""
import json

from .models import Decision
from .storage import get_approval, get_decision


class SecurityBlocked(RuntimeError):
    pass


class HumanApprovalRequired(RuntimeError):
    pass


class AgentShieldWrapper:
    def __init__(self, signer):
        self.signer = signer

    def execute(self, assessment: dict, transaction: dict):
        decision = assessment.get("decision")
        txid = assessment.get("transaction_id")

        if decision == Decision.BLOCK.value:
            raise SecurityBlocked("AgentShield BLOCK: transaction was not signed")
        if decision not in {Decision.ALLOW.value, Decision.WARN.value}:
            raise SecurityBlocked("Unknown or missing security decision; refusing to sign")
        if not isinstance(txid, str) or not txid:
            raise SecurityBlocked("Assessment transaction ID is missing; refusing to sign")

        saved = get_decision(txid)
        if not saved or saved.get("decision") != decision:
            raise SecurityBlocked("Assessment does not match the stored security decision")

        try:
            assessed_payload = json.loads(saved["payload"])
        except (KeyError, TypeError, json.JSONDecodeError) as exc:
            raise SecurityBlocked("Stored assessment payload is invalid; refusing to sign") from exc

        if not isinstance(assessed_payload, dict) or transaction != assessed_payload:
            raise SecurityBlocked("Transaction differs from the assessed payload; refusing to sign")

        if decision == Decision.WARN.value:
            approval = get_approval(txid)
            if not approval or not approval.get("approved"):
                raise HumanApprovalRequired("Human approval is required before signing")

        return self.signer(transaction)
