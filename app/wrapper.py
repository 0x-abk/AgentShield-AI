"""Fail-closed agent execution gate. Signing is deliberately injected by caller."""
from .models import Decision
from .storage import get_approval

class SecurityBlocked(RuntimeError): pass
class HumanApprovalRequired(RuntimeError): pass

class AgentShieldWrapper:
    def __init__(self, signer):
        self.signer = signer

    def execute(self, assessment: dict, transaction: dict):
        decision = assessment.get("decision")
        txid = assessment.get("transaction_id")
        if decision == Decision.BLOCK.value:
            raise SecurityBlocked("AgentShield BLOCK: transaction was not signed")
        if decision == Decision.WARN.value:
            approval = get_approval(txid) if txid else None
            if not approval or not approval.get("approved"):
                raise HumanApprovalRequired("Human approval is required before signing")
        if decision != Decision.ALLOW.value and decision != Decision.WARN.value:
            raise SecurityBlocked("Unknown or missing security decision; refusing to sign")
        # signer is called only after all gates pass.
        return self.signer(transaction)
