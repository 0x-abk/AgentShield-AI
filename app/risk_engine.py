from decimal import Decimal, InvalidOperation
from .models import Decision, RiskLevel, TransactionRequest
from .storage import get_blocklist

# Demo-only known bad address. Replace/add verified reports in production.
DEMO_BLOCKLIST = {
    "known-scam.near": {
        "receiver": "known-scam.near",
        "reason": "Address is included in the AgentShield demo blocklist",
        "evidence_url": "https://example.invalid/agentshield-demo-evidence",
        "reporter": "agentshield-demo"
    }
}

class RiskEngine:
    """Deterministic policy engine. LLM output is never used to make decisions."""
    def assess(self, tx: TransactionRequest) -> tuple[Decision, RiskLevel, int, list[str], list[dict]]:
        score, reasons, evidence = 0, [], []
        receiver = tx.receiver
        blocked = {**DEMO_BLOCKLIST, **get_blocklist()}
        if receiver in blocked:
            item = blocked[receiver]
            reasons.append("Receiver is on the shared blocklist")
            evidence.append({"type": "blocklist", "receiver": receiver,
                             "reporter": item.get("reporter"),
                             "evidence_url": item.get("evidence_url"),
                             "reported_reason": item.get("reason")})
            return Decision.BLOCK, RiskLevel.HIGH, 100, reasons, evidence

        try:
            amount = Decimal(tx.amount)
        except InvalidOperation:
            return Decision.BLOCK, RiskLevel.HIGH, 100, ["Invalid transaction amount"], []
        if amount < 0 or (amount == 0 and tx.action.lower() != "function_call"):
            return Decision.BLOCK, RiskLevel.HIGH, 100, ["Transaction amount must be greater than zero for transfers; zero-deposit FunctionCalls are permitted"], []

        if receiver.lower() == "merchant-account.near":
            score += 20
            reasons.append("Receiver requires additional human review")
            evidence.append({
                "type": "policy",
                "signal": "merchant_review_required"
            })

        # Conservative heuristic for unknown accounts. This is not chain-verified age data.
        if receiver.endswith(".near") and len(receiver.split('.')[0]) < 3:
            score += 20
            reasons.append("Receiver account name is unusually short")
            evidence.append({"type": "heuristic", "signal": "short_account_name"})
        if amount >= Decimal("10") and tx.asset.upper() == "NEAR":
            score += 30
            reasons.append("Transfer amount is high for the default demo policy")
            evidence.append({"type": "policy", "signal": "high_demo_amount", "threshold": "10 NEAR"})
        if tx.action.lower() not in {"transfer", "function_call"}:
            score += 40
            reasons.append("Transaction action is not in the approved action list")
            evidence.append({"type": "policy", "signal": "unrecognized_action"})

        if score >= 60:
            return Decision.BLOCK, RiskLevel.HIGH, min(score,100), reasons, evidence
        if score > 0:
            return Decision.WARN, RiskLevel.MEDIUM, score, reasons, evidence
        return Decision.ALLOW, RiskLevel.LOW, 0, ["No configured risk rule was triggered"], [{"type":"policy","signal":"default_allow"}]
