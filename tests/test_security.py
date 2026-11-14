import pytest
import json
import uuid
from fastapi.testclient import TestClient
from app.main import app
from app.wrapper import AgentShieldWrapper, SecurityBlocked, HumanApprovalRequired
from app import storage
import app.main as main_module
from app.rate_limit import RateLimiter
from app.models import BlocklistReviewRequest

client = TestClient(
    app,
    headers={"Authorization": "Bearer test-only-agentshield-key"}
)

@pytest.fixture(autouse=True)
def setup_db(tmp_path, monkeypatch):
    monkeypatch.setenv(
        "AGENTSHIELD_API_KEY",
        "test-only-agentshield-key"
    )
    monkeypatch.setenv(
        "AGENTSHIELD_REVIEWER_API_KEY",
        "test-only-reviewer-key"
    )
    monkeypatch.setattr(
        storage, "DB_PATH", tmp_path / "test-agentshield.db"
    )
    storage.init_db()
    monkeypatch.setattr(main_module, "rate_limiter", RateLimiter())

def assess(receiver, amount="1", action="transfer"):
    return client.post("/v1/assess", json={"agent_id":"test-agent", "receiver":receiver,
      "amount":amount, "asset":"NEAR", "action":action})

def test_safe_receiver_allow():
    assert assess("safe-account.near").json()["decision"] == "ALLOW"

def test_blocklisted_receiver_block():
    result = assess("known-scam.near").json()
    assert result["decision"] == "BLOCK"
    assert result["requires_human_approval"] is False

def test_high_amount_warn():
    assert assess("merchant-account.near", "12").json()["decision"] == "WARN"

def test_block_never_calls_signer():
    result = assess("known-scam.near").json()
    called = []
    wrapper = AgentShieldWrapper(lambda tx: called.append(tx))
    with pytest.raises(SecurityBlocked):
        wrapper.execute(result, {"receiver":"known-scam.near"})
    assert called == []

def test_warn_requires_human_approval():
    result = assess("merchant-account.near", "12").json()
    saved = storage.get_decision(result["transaction_id"])
    transaction = json.loads(saved["payload"])
    called = []
    wrapper = AgentShieldWrapper(lambda tx: called.append(tx) or {"ok": True})

    with pytest.raises(HumanApprovalRequired):
        wrapper.execute(result, transaction)
    assert called == []

    response = client.post(
        f"/v1/approvals/{result['transaction_id']}",
        json={"approved": True, "reviewer": "human-reviewer"},
        headers={"Authorization": "Bearer test-only-reviewer-key"},
    )
    assert response.status_code == 200

    wrapper.execute(result, transaction)
    assert called == [transaction]

def test_invalid_zero_amount_rejected():
    assert assess("safe-account.near", "0").status_code == 200
    assert assess("safe-account.near", "0").json()["decision"] == "BLOCK"

def test_unknown_action_warn_or_block():
    assert assess("safe-account.near", "1", "delete_account").json()["decision"] == "WARN"

from app.near_security import validate_function_call_key


def test_near_function_call_key_allows_scoped_method():
    result = {"permission": {"FunctionCall": {
        "receiver_id": "vault.testnet", "method_names": ["deposit"], "allowance": "1000000000000000000000"
    }}}
    check = validate_function_call_key(result, expected_contract="vault.testnet",
        requested_contract="vault.testnet", method_name="deposit")
    assert check.allowed is True


def test_near_function_call_key_blocks_wrong_contract():
    result = {"permission": {"FunctionCall": {"receiver_id": "vault.testnet", "method_names": ["deposit"]}}}
    check = validate_function_call_key(result, expected_contract="vault.testnet",
        requested_contract="attacker.testnet", method_name="deposit")
    assert check.allowed is False


def test_near_function_call_key_blocks_disallowed_method():
    result = {"permission": {"FunctionCall": {"receiver_id": "vault.testnet", "method_names": ["deposit"]}}}
    check = validate_function_call_key(result, expected_contract="vault.testnet",
        requested_contract="vault.testnet", method_name="withdraw")
    assert check.allowed is False


def test_near_function_call_key_blocks_attached_deposit_and_multiple_actions():
    result = {"permission": {"FunctionCall": {"receiver_id": "vault.testnet", "method_names": []}}}
    check = validate_function_call_key(result, expected_contract="vault.testnet",
        requested_contract="vault.testnet", method_name="deposit",
        attached_deposit_yocto="1", action_count=2)
    assert check.allowed is False


def test_near_function_call_key_refuses_full_access():
    check = validate_function_call_key({"permission": "FullAccess"},
        expected_contract="vault.testnet", requested_contract="vault.testnet", method_name="deposit")
    assert check.allowed is False


def test_near_validate_endpoint_uses_server_pinned_contract(monkeypatch):
    import asyncio
    import app.main as main_module
    monkeypatch.setenv("NEAR_ALLOWED_CONTRACT_ID", "vault.testnet")
    async def fake_view_access_key(account_id, public_key):
        return {"permission": {"FunctionCall": {
            "receiver_id": "vault.testnet", "method_names": ["deposit"], "allowance": "1000"
        }}}
    monkeypatch.setattr(main_module, "view_access_key", fake_view_access_key)
    response = client.post("/v1/near/validate-function-call", json={
        "account_id": "agent.testnet", "public_key": "ed25519:1234567890abcdef",
        "requested_contract": "vault.testnet", "method_name": "deposit"
    })
    assert response.status_code == 200
    assert response.json()["decision"] == "ALLOW"
    assert response.json()["signing_performed"] is False


def test_near_validate_endpoint_fails_closed_without_pinned_contract(monkeypatch):
    import app.main as main_module
    monkeypatch.delenv("NEAR_ALLOWED_CONTRACT_ID", raising=False)
    async def fake_view_access_key(account_id, public_key):
        return {"permission": {"FunctionCall": {"receiver_id": "vault.testnet", "method_names": ["deposit"]}}}
    monkeypatch.setattr(main_module, "view_access_key", fake_view_access_key)
    response = client.post("/v1/near/validate-function-call", json={
        "account_id": "agent.testnet", "public_key": "ed25519:1234567890abcdef",
        "requested_contract": "vault.testnet", "method_name": "deposit"
    })
    assert response.status_code == 503


def test_near_execute_blocks_blocked_assessment_without_calling_signer(monkeypatch):
    import app.main as main_module
    monkeypatch.setenv("NEAR_ALLOWED_CONTRACT_ID", "vault.testnet")
    monkeypatch.setenv("NEAR_SIGNER_ACCOUNT_ID", "agent.testnet")
    monkeypatch.setenv("NEAR_SIGNER_PUBLIC_KEY", "ed25519:1234567890abcdef")
    monkeypatch.setenv("NEAR_ALLOWED_METHODS", "deposit")
    called = []
    async def fake_submit(**kwargs):
        called.append(kwargs)
        return {"submitted": True}
    monkeypatch.setattr(main_module, "submit_function_call", fake_submit)
    blocked = assess("known-scam.near", "1", "function_call").json()
    response = client.post("/v1/near/execute-function-call", json={
        "transaction_id": blocked["transaction_id"], "account_id": "agent.testnet",
        "public_key": "ed25519:1234567890abcdef", "contract_id": "vault.testnet",
        "method_name": "deposit", "args": {"account_id": "known-scam.near"}
    })
    assert response.status_code == 403
    assert called == []


def test_near_execute_requires_warn_approval(monkeypatch):
    import app.main as main_module
    monkeypatch.setenv("NEAR_ALLOWED_CONTRACT_ID", "vault.testnet")
    monkeypatch.setenv("NEAR_SIGNER_ACCOUNT_ID", "agent.testnet")
    monkeypatch.setenv("NEAR_SIGNER_PUBLIC_KEY", "ed25519:1234567890abcdef")
    monkeypatch.setenv("NEAR_ALLOWED_METHODS", "deposit")
    called = []
    async def fake_submit(**kwargs):
        called.append(kwargs)
        return {"submitted": True}
    monkeypatch.setattr(main_module, "submit_function_call", fake_submit)
    # Short receiver triggers a WARN in the deterministic demo policy.
    warning = client.post("/v1/assess", json={"agent_id":"test-agent", "receiver":"ab.near", "amount":"1", "asset":"NEAR", "action":"function_call", "function_method":"deposit", "function_args":{"account_id":"ab.near"}}).json()
    response = client.post("/v1/near/execute-function-call", json={
        "transaction_id": warning["transaction_id"], "account_id": "agent.testnet",
        "public_key": "ed25519:1234567890abcdef", "contract_id": "vault.testnet",
        "method_name": "deposit", "args": {"account_id": "ab.near"}
    })
    assert response.status_code == 409
    assert called == []


def test_near_execute_allows_only_after_policy_and_chain_key_checks(monkeypatch):
    import app.main as main_module
    monkeypatch.setenv("NEAR_ALLOWED_CONTRACT_ID", "vault.testnet")
    monkeypatch.setenv("NEAR_SIGNER_ACCOUNT_ID", "agent.testnet")
    monkeypatch.setenv("NEAR_SIGNER_PUBLIC_KEY", "ed25519:1234567890abcdef")
    monkeypatch.setenv("NEAR_ALLOWED_METHODS", "deposit")
    async def fake_view_access_key(account_id, public_key):
        return {"permission": {"FunctionCall": {
            "receiver_id": "vault.testnet", "method_names": ["deposit"], "allowance": "1000"
        }}}
    called = []
    async def fake_submit(**kwargs):
        called.append(kwargs)
        return {
            "submitted": True,
            "network": "mainnet",
            "transaction_hash": "mock-hash",
            "decision": "BLOCK",
            "signing_performed": False,
            "transaction_id": "attacker-controlled-id",
        }
    monkeypatch.setattr(main_module, "view_access_key", fake_view_access_key)
    monkeypatch.setattr(main_module, "submit_function_call", fake_submit)
    assessment = client.post("/v1/assess", json={"agent_id":"test-agent", "receiver":"vault.testnet", "amount":"0", "asset":"NEAR", "action":"function_call", "function_method":"deposit", "function_args":{"account_id":"alice.testnet"}}).json()
    response = client.post("/v1/near/execute-function-call", json={
        "transaction_id": assessment["transaction_id"], "account_id": "agent.testnet",
        "public_key": "ed25519:1234567890abcdef", "contract_id": "vault.testnet",
        "method_name": "deposit", "args": {"account_id": "alice.testnet"},
        "attached_deposit_yocto": "0", "action_count": 1
    })
    assert response.status_code == 200, response.text
    assert response.json()["signing_performed"] is True
    assert response.json()["decision"] == "ALLOW"
    assert response.json()["network"] == "testnet"
    assert response.json()["transaction_id"] == assessment["transaction_id"]
    assert response.json()["transaction_hash"] == "mock-hash"
    assert len(called) == 1


def test_near_execute_rejects_nonzero_deposit_before_signer(monkeypatch):
    import app.main as main_module
    monkeypatch.setenv("NEAR_ALLOWED_CONTRACT_ID", "vault.testnet")
    monkeypatch.setenv("NEAR_SIGNER_ACCOUNT_ID", "agent.testnet")
    monkeypatch.setenv("NEAR_SIGNER_PUBLIC_KEY", "ed25519:1234567890abcdef")
    monkeypatch.setenv("NEAR_ALLOWED_METHODS", "deposit")
    called = []
    async def fake_submit(**kwargs):
        called.append(kwargs)
        return {"submitted": True}
    monkeypatch.setattr(main_module, "submit_function_call", fake_submit)
    assessment = client.post("/v1/assess", json={"agent_id":"test-agent", "receiver":"vault.testnet", "amount":"0", "asset":"NEAR", "action":"function_call", "function_method":"deposit", "function_args":{"account_id":"alice.testnet"}}).json()
    response = client.post("/v1/near/execute-function-call", json={
        "transaction_id": assessment["transaction_id"], "account_id": "agent.testnet",
        "public_key": "ed25519:1234567890abcdef", "contract_id": "vault.testnet",
        "method_name": "deposit", "args": {"account_id": "alice.testnet"}, "attached_deposit_yocto": "1"
    })
    assert response.status_code == 403
    assert called == []


def test_near_function_call_key_rejects_wildcard_methods():
    result = {"permission": {"FunctionCall": {"receiver_id": "vault.testnet", "method_names": []}}}
    check = validate_function_call_key(result, expected_contract="vault.testnet",
        requested_contract="vault.testnet", method_name="deposit")
    assert check.allowed is False
    assert any("Wildcard" in reason for reason in check.reasons)


def test_near_execute_rejects_tampered_function_arguments(monkeypatch):
    import app.main as main_module
    monkeypatch.setenv("NEAR_ALLOWED_CONTRACT_ID", "vault.testnet")
    monkeypatch.setenv("NEAR_SIGNER_ACCOUNT_ID", "agent.testnet")
    monkeypatch.setenv("NEAR_SIGNER_PUBLIC_KEY", "ed25519:1234567890abcdef")
    monkeypatch.setenv("NEAR_ALLOWED_METHODS", "deposit")
    called = []
    async def fake_submit(**kwargs):
        called.append(kwargs)
        return {"submitted": True}
    monkeypatch.setattr(main_module, "submit_function_call", fake_submit)
    assessment = client.post("/v1/assess", json={"agent_id":"test-agent", "receiver":"vault.testnet", "amount":"0", "asset":"NEAR", "action":"function_call", "function_method":"deposit", "function_args":{"account_id":"alice.testnet"}}).json()
    response = client.post("/v1/near/execute-function-call", json={
        "transaction_id": assessment["transaction_id"], "account_id": "agent.testnet",
        "public_key": "ed25519:1234567890abcdef", "contract_id": "vault.testnet",
        "method_name": "deposit", "args": {"account_id": "attacker.testnet"}
    })
    assert response.status_code == 409
    assert called == []


def test_near_execute_prevents_replay_of_same_assessment(monkeypatch):
    import app.main as main_module
    monkeypatch.setenv("NEAR_ALLOWED_CONTRACT_ID", "vault.testnet")
    monkeypatch.setenv("NEAR_SIGNER_ACCOUNT_ID", "agent.testnet")
    monkeypatch.setenv("NEAR_SIGNER_PUBLIC_KEY", "ed25519:1234567890abcdef")
    monkeypatch.setenv("NEAR_ALLOWED_METHODS", "deposit")

    async def fake_view_access_key(account_id, public_key):
        return {"permission": {"FunctionCall": {
            "receiver_id": "vault.testnet", "method_names": ["deposit"], "allowance": "1000"
        }}}

    called = []
    async def fake_submit(**kwargs):
        called.append(kwargs)
        return {"submitted": True, "network": "testnet", "transaction_hash": "mock-hash"}

    monkeypatch.setattr(main_module, "view_access_key", fake_view_access_key)
    monkeypatch.setattr(main_module, "submit_function_call", fake_submit)

    assessment = client.post("/v1/assess", json={
        "agent_id":"test-agent", "receiver":"vault.testnet", "amount":"0",
        "asset":"NEAR", "action":"function_call", "function_method":"deposit",
        "function_args":{"account_id":"alice.testnet"}
    }).json()
    payload = {
        "transaction_id": assessment["transaction_id"], "account_id": "agent.testnet",
        "public_key": "ed25519:1234567890abcdef", "contract_id": "vault.testnet",
        "method_name": "deposit", "args": {"account_id": "alice.testnet"}
    }
    first = client.post("/v1/near/execute-function-call", json=payload)
    second = client.post("/v1/near/execute-function-call", json=payload)
    assert first.status_code == 200
    assert second.status_code == 409
    assert len(called) == 1
    assert main_module.storage.get_execution(assessment["transaction_id"])["status"] == "SUBMITTED"


def test_signer_failure_locks_assessment_against_automatic_replay(monkeypatch):
    import app.main as main_module
    from app.near_signer import SignerUnavailable
    monkeypatch.setenv("NEAR_ALLOWED_CONTRACT_ID", "vault.testnet")
    monkeypatch.setenv("NEAR_SIGNER_ACCOUNT_ID", "agent.testnet")
    monkeypatch.setenv("NEAR_SIGNER_PUBLIC_KEY", "ed25519:1234567890abcdef")
    monkeypatch.setenv("NEAR_ALLOWED_METHODS", "deposit")

    async def fake_view_access_key(account_id, public_key):
        return {"permission": {"FunctionCall": {
            "receiver_id": "vault.testnet", "method_names": ["deposit"], "allowance": "1000"
        }}}
    calls = []
    async def fake_submit(**kwargs):
        calls.append(kwargs)
        raise SignerUnavailable("simulated RPC timeout")

    monkeypatch.setattr(main_module, "view_access_key", fake_view_access_key)
    monkeypatch.setattr(main_module, "submit_function_call", fake_submit)
    assessment = client.post("/v1/assess", json={
        "agent_id":"test-agent", "receiver":"vault.testnet", "amount":"0",
        "asset":"NEAR", "action":"function_call", "function_method":"deposit",
        "function_args":{"account_id":"alice.testnet"}
    }).json()
    payload = {
        "transaction_id": assessment["transaction_id"], "account_id": "agent.testnet",
        "public_key": "ed25519:1234567890abcdef", "contract_id": "vault.testnet",
        "method_name": "deposit", "args": {"account_id": "alice.testnet"}
    }
    first = client.post("/v1/near/execute-function-call", json=payload)
    second = client.post("/v1/near/execute-function-call", json=payload)
    assert first.status_code == 502
    assert "simulated RPC timeout" not in first.text
    assert second.status_code == 409
    assert len(calls) == 1
    assert main_module.storage.get_execution(assessment["transaction_id"])["status"] == "FAILED"

def test_missing_transaction_hash_fails_closed(monkeypatch):
    import app.main as main_module

    monkeypatch.setenv("NEAR_ALLOWED_CONTRACT_ID", "vault.testnet")
    monkeypatch.setenv("NEAR_SIGNER_ACCOUNT_ID", "agent.testnet")
    monkeypatch.setenv("NEAR_SIGNER_PUBLIC_KEY", "ed25519:1234567890abcdef")
    monkeypatch.setenv("NEAR_ALLOWED_METHODS", "deposit")

    async def fake_view_access_key(account_id, public_key):
        return {"permission": {"FunctionCall": {
            "receiver_id": "vault.testnet",
            "method_names": ["deposit"],
            "allowance": "1000",
        }}}

    calls = []

    async def fake_submit(**kwargs):
        calls.append(kwargs)
        return {
            "submitted": True,
            "network": "testnet",
            "transaction_hash": None,
        }

    monkeypatch.setattr(main_module, "view_access_key", fake_view_access_key)
    monkeypatch.setattr(main_module, "submit_function_call", fake_submit)

    assessment = client.post("/v1/assess", json={
        "agent_id": "test-agent",
        "receiver": "vault.testnet",
        "amount": "0",
        "asset": "NEAR",
        "action": "function_call",
        "function_method": "deposit",
        "function_args": {"account_id": "alice.testnet"},
    }).json()

    payload = {
        "transaction_id": assessment["transaction_id"],
        "account_id": "agent.testnet",
        "public_key": "ed25519:1234567890abcdef",
        "contract_id": "vault.testnet",
        "method_name": "deposit",
        "args": {"account_id": "alice.testnet"},
    }

    first = client.post("/v1/near/execute-function-call", json=payload)
    second = client.post("/v1/near/execute-function-call", json=payload)

    assert first.status_code == 502
    assert "no transaction hash" in first.text
    assert second.status_code == 409
    assert len(calls) == 1
    execution = main_module.storage.get_execution(assessment["transaction_id"])
    assert execution["status"] == "FAILED"
    assert execution["tx_hash"] is None

def test_missing_api_key_rejected():
    response = client.get(
        "/v1/blocklist",
        headers={"Authorization": ""}
    )
    assert response.status_code == 401


def test_invalid_api_key_rejected():
    response = client.get(
        "/v1/blocklist",
        headers={"Authorization": "Bearer wrong-test-key"}
    )
    assert response.status_code == 401


def test_health_is_public():
    response = client.get("/health")
    assert response.status_code == 200
def test_agent_key_cannot_approve_transaction():
    warning = assess("merchant-account.near", "12").json()

    response = client.post(
        f"/v1/approvals/{warning['transaction_id']}",
        json={"approved": True, "reviewer": "human-reviewer"}
    )

    assert response.status_code == 401


def test_reviewer_key_can_approve_transaction(monkeypatch):
    monkeypatch.setenv(
        "AGENTSHIELD_REVIEWER_API_KEY",
        "test-only-reviewer-key"
    )

    warning = assess("merchant-account.near", "12").json()

    response = client.post(
        f"/v1/approvals/{warning['transaction_id']}",
        json={"approved": True, "reviewer": "human-reviewer"},
        headers={"Authorization": "Bearer test-only-reviewer-key"}
    )

    assert response.status_code == 200


def test_reviewer_key_cannot_access_agent_endpoints():
    response = client.get(
        "/v1/blocklist",
        headers={"Authorization": "Bearer test-only-reviewer-key"}
    )

    assert response.status_code == 401


def test_transaction_cannot_be_reviewed_twice():
    warning = assess("merchant-account.near", "12").json()
    url = f"/v1/approvals/{warning['transaction_id']}"
    headers = {"Authorization": "Bearer test-only-reviewer-key"}

    first = client.post(
        url,
        json={"approved": True, "reviewer": "reviewer-one"},
        headers=headers
    )

    second = client.post(
        url,
        json={"approved": False, "reviewer": "reviewer-two"},
        headers=headers
    )

    assert first.status_code == 200
    assert second.status_code == 409

    saved = storage.get_approval(warning["transaction_id"])
    assert saved["approved"] == 1
    assert saved["reviewer"] == "reviewer-one"


def test_approval_creates_audit_log():
    warning = assess("merchant-account.near", "12").json()

    response = client.post(
        f"/v1/approvals/{warning['transaction_id']}",
        json={
            "approved": True,
            "reviewer": "audit-reviewer",
            "note": "Security review completed",
        },
        headers={"Authorization": "Bearer test-only-reviewer-key"},
    )

    assert response.status_code == 200

    logs = storage.get_audit_logs(warning["transaction_id"])

    assert len(logs) == 1
    assert logs[0]["event_type"] == "TRANSACTION_REVIEWED"
    assert logs[0]["actor"] == "audit-reviewer"



def test_approval_rolls_back_when_audit_log_fails(monkeypatch):
    warning = assess("merchant-account.near", "12").json()

    def fail_audit_log(*args, **kwargs):
        raise RuntimeError("Simulated audit log failure")

    monkeypatch.setattr(storage, "add_audit_log", fail_audit_log)

    with pytest.raises(RuntimeError, match="Simulated audit log failure"):
        storage.save_approval(
            warning["transaction_id"],
            True,
            "rollback-reviewer",
            "Testing rollback",
        )

    assert storage.get_approval(warning["transaction_id"]) is None

def test_audit_log_cannot_be_updated_or_deleted():
    warning = assess("merchant-account.near", "12").json()

    client.post(
        f"/v1/approvals/{warning['transaction_id']}",
        json={"approved": True, "reviewer": "audit-reviewer"},
        headers={"Authorization": "Bearer test-only-reviewer-key"},
    )

    with storage.connect() as db:
        with pytest.raises(Exception):
            db.execute(
                "UPDATE audit_logs SET actor='changed' WHERE transaction_id=?",
                (warning["transaction_id"],),
            )

        with pytest.raises(Exception):
            db.execute(
                "DELETE FROM audit_logs WHERE transaction_id=?",
                (warning["transaction_id"],),
            )


def test_reviewer_key_can_access_audit_logs():
    warning = assess("merchant-account.near", "12").json()

    review = client.post(
        f"/v1/approvals/{warning['transaction_id']}",
        json={"approved": True, "reviewer": "audit-reviewer"},
        headers={"Authorization": "Bearer test-only-reviewer-key"},
    )
    assert review.status_code == 200

    response = client.get(
        f"/v1/audit-logs/{warning['transaction_id']}",
        headers={"Authorization": "Bearer test-only-reviewer-key"},
    )

    assert response.status_code == 200
    assert response.json()["transaction_id"] == warning["transaction_id"]
    assert len(response.json()["audit_logs"]) == 1


def test_agent_key_cannot_access_audit_logs():
    response = client.get(
        "/v1/audit-logs/test-transaction",
        headers={"Authorization": "Bearer test-only-agentshield-key"},
    )

    assert response.status_code == 401


def test_missing_reviewer_key_cannot_access_audit_logs():
    response = client.get("/v1/audit-logs/test-transaction")

    assert response.status_code == 401


@pytest.mark.parametrize("endpoint,method_name", [
    ("/v1/near/account/agent.testnet", "account_exists"),
    ("/v1/near/access-keys/agent.testnet", "access_key_list"),
    ("/v1/near/contract/vault.testnet/code", "contract_code"),
])
def test_near_read_endpoints_hide_rpc_errors(monkeypatch, endpoint, method_name):
    import app.main as main_module

    async def fake_rpc(*args, **kwargs):
        raise RuntimeError("private RPC diagnostic: secret-token")

    monkeypatch.setattr(main_module, method_name, fake_rpc)
    response = client.get(endpoint)

    assert response.status_code == 502
    assert "secret-token" not in response.text


def test_near_validate_endpoint_hides_rpc_errors(monkeypatch):
    import app.main as main_module

    async def fake_view_access_key(account_id, public_key):
        raise RuntimeError("private RPC diagnostic: secret-token")

    monkeypatch.setattr(main_module, "view_access_key", fake_view_access_key)

    response = client.post("/v1/near/validate-function-call", json={
        "account_id": "agent.testnet",
        "public_key": "ed25519:1234567890abcdef",
        "requested_contract": "vault.testnet",
        "method_name": "deposit",
    })

    assert response.status_code == 502
    assert "secret-token" not in response.text


def test_missing_agent_key_configuration_returns_503(monkeypatch):
    monkeypatch.delenv("AGENTSHIELD_API_KEY")

    response = client.get("/v1/blocklist")

    assert response.status_code == 503
    assert response.json()["detail"] == "API authentication is not configured"


def test_missing_reviewer_key_configuration_returns_503(monkeypatch):
    monkeypatch.delenv("AGENTSHIELD_REVIEWER_API_KEY")

    response = client.get("/v1/audit-logs/test-transaction")

    assert response.status_code == 503
    assert response.json()["detail"] == "API authentication is not configured"


def test_blocklist_report_waits_for_reviewer():
    response = client.post(
        "/v1/blocklist",
        json={
            "receiver": "scam-account.near",
            "reason": "Suspicious transaction activity",
            "evidence_url": "https://example.com/evidence",
            "reporter": "test-agent",
        },
    )

    assert response.status_code == 202
    assert response.json()["status"] == "pending"
    assert response.json()["report_id"]
    assert "scam-account.near" not in storage.get_blocklist()


def test_reviewer_can_approve_blocklist_report():
    submitted = client.post(
        "/v1/blocklist",
        json={
            "receiver": "approved-scam.near",
            "reason": "Confirmed suspicious activity",
            "reporter": "test-agent",
        },
    )
    report_id = submitted.json()["report_id"]

    reviewed = client.post(
        f"/v1/blocklist/reports/{report_id}/review",
        json={"approved": True, "reviewer": "human-reviewer"},
        headers={"Authorization": "Bearer test-only-reviewer-key"},
    )

    assert reviewed.status_code == 200
    assert reviewed.json()["status"] == "APPROVED"
    assert "approved-scam.near" in storage.get_blocklist()


def test_reviewer_can_reject_blocklist_report():
    submitted = client.post(
        "/v1/blocklist",
        json={
            "receiver": "rejected-scam.near",
            "reason": "Unverified suspicious activity",
            "reporter": "test-agent",
        },
    )
    report_id = submitted.json()["report_id"]

    reviewed = client.post(
        f"/v1/blocklist/reports/{report_id}/review",
        json={"approved": False, "reviewer": "human-reviewer"},
        headers={"Authorization": "Bearer test-only-reviewer-key"},
    )

    assert reviewed.status_code == 200
    assert reviewed.json()["status"] == "REJECTED"
    assert "rejected-scam.near" not in storage.get_blocklist()


def test_agent_key_cannot_review_blocklist_report():
    submitted = client.post(
        "/v1/blocklist",
        json={
            "receiver": "restricted-scam.near",
            "reason": "Suspicious transaction activity",
            "reporter": "test-agent",
        },
    )
    report_id = submitted.json()["report_id"]

    reviewed = client.post(
        f"/v1/blocklist/reports/{report_id}/review",
        json={"approved": True, "reviewer": "unauthorized-agent"},
    )

    assert reviewed.status_code == 401
    assert "restricted-scam.near" not in storage.get_blocklist()


def test_blocklist_report_cannot_be_reviewed_twice():
    submitted = client.post(
        "/v1/blocklist",
        json={
            "receiver": "once-only.near",
            "reason": "Suspicious transaction activity",
            "reporter": "test-agent",
        },
    )
    report_id = submitted.json()["report_id"]
    url = f"/v1/blocklist/reports/{report_id}/review"
    headers = {"Authorization": "Bearer test-only-reviewer-key"}
    payload = {"approved": True, "reviewer": "reviewer-one"}

    first = client.post(url, json=payload, headers=headers)
    second = client.post(url, json=payload, headers=headers)

    assert first.status_code == 200
    assert second.status_code == 409


def test_approved_duplicate_report_does_not_overwrite_active_blocklist():
    receiver = f"duplicate-{uuid.uuid4().hex}.near"

    with storage.connect() as db:
        db.execute(
            """
            INSERT INTO blocklist
            (receiver, reason, evidence_url, reporter)
            VALUES (?, ?, ?, ?)
            """,
            (receiver, "Original reason", None, "original-reporter"),
        )

    submitted = client.post(
        "/v1/blocklist",
        json={
            "receiver": receiver,
            "reason": "New report with different evidence",
            "evidence_url": "https://example.com/evidence",
            "reporter": "new-reporter",
        },
    )
    assert submitted.status_code == 202

    report_id = submitted.json()["report_id"]

    reviewed = client.post(
        f"/v1/blocklist/reports/{report_id}/review",
        json={"approved": True, "reviewer": "human-reviewer"},
        headers={"Authorization": "Bearer test-only-reviewer-key"},
    )
    assert reviewed.status_code == 200

    active = storage.get_blocklist()[receiver]
    assert active["reason"] == "Original reason"
    assert active["reporter"] == "original-reporter"


def test_blocklist_submission_creates_audit_log():
    response = client.post(
        "/v1/blocklist",
        json={
            "receiver": f"audit-{uuid.uuid4().hex}.near",
            "reason": "Suspicious activity reported",
            "evidence_url": None,
            "reporter": "audit-reporter",
        },
    )

    assert response.status_code == 202
    report_id = response.json()["report_id"]

    logs = storage.get_audit_logs(report_id)
    assert len(logs) == 1
    assert logs[0]["event_type"] == "BLOCKLIST_REPORT_SUBMITTED"
    assert logs[0]["actor"] == "audit-reporter"


def test_blocklist_review_creates_audit_log():
    response = client.post(
        "/v1/blocklist",
        json={
            "receiver": f"audit-review-{uuid.uuid4().hex}.near",
            "reason": "Suspicious activity reported",
            "evidence_url": None,
            "reporter": "audit-reporter",
        },
    )

    report_id = response.json()["report_id"]

    reviewed = client.post(
        f"/v1/blocklist/reports/{report_id}/review",
        json={"approved": True, "reviewer": "audit-reviewer"},
        headers={"Authorization": "Bearer test-only-reviewer-key"},
    )

    assert reviewed.status_code == 200

    logs = storage.get_audit_logs(report_id)
    assert len(logs) == 2
    assert logs[1]["event_type"] == "BLOCKLIST_REPORT_REVIEWED"
    assert logs[1]["actor"] == "audit-reviewer"


def test_blocklist_review_rolls_back_when_audit_log_fails(monkeypatch):
    receiver = f"rollback-{uuid.uuid4().hex}.near"

    report_id = storage.submit_blocklist_report(
        receiver,
        "Suspicious activity reported",
        None,
        "rollback-reporter",
    )

    def fail_audit_log(*args, **kwargs):
        raise RuntimeError("Simulated audit log failure")

    monkeypatch.setattr(storage, "add_audit_log", fail_audit_log)

    with pytest.raises(RuntimeError, match="Simulated audit log failure"):
        storage.review_blocklist_report(
            report_id,
            True,
            "rollback-reviewer",
        )

    with storage.connect() as db:
        report = db.execute(
            "SELECT status FROM blocklist_reports WHERE report_id = ?",
            (report_id,),
        ).fetchone()

    assert report["status"] == "PENDING"
    assert receiver not in storage.get_blocklist()


def test_reviewer_key_cannot_submit_blocklist_report():
    response = client.post(
        "/v1/blocklist",
        json={
            "receiver": "reviewer-submit.near",
            "reason": "Suspicious activity reported",
            "reporter": "reviewer-test",
        },
        headers={
            "Authorization": "Bearer test-only-reviewer-key"
        },
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid or missing API key"
    assert "reviewer-submit.near" not in storage.get_blocklist()


def test_missing_reviewer_key_cannot_review_blocklist_report():
    submitted = client.post(
        "/v1/blocklist",
        json={
            "receiver": "missing-reviewer.near",
            "reason": "Suspicious activity reported",
            "reporter": "test-agent",
        },
    )
    report_id = submitted.json()["report_id"]

    reviewed = client.post(
        f"/v1/blocklist/reports/{report_id}/review",
        json={"approved": True, "reviewer": "unauthorized"},
        headers={"Authorization": ""},
    )

    assert reviewed.status_code == 401
    assert "missing-reviewer.near" not in storage.get_blocklist()


def test_blocklist_rejects_invalid_evidence_url():
    response = client.post(
        "/v1/blocklist",
        json={
            "receiver": "invalid-url.near",
            "reason": "Suspicious transaction activity",
            "evidence_url": "not-a-valid-url",
            "reporter": "test-agent",
        },
    )

    assert response.status_code == 422


@pytest.mark.parametrize("field", ["reason", "reporter"])
def test_blocklist_rejects_whitespace_only_text(field):
    payload = {
        "receiver": "whitespace-test.near",
        "reason": "Suspicious transaction activity",
        "reporter": "test-agent",
    }
    payload[field] = "     "

    response = client.post("/v1/blocklist", json=payload)

    assert response.status_code == 422


def test_short_account_name_adds_20_risk_points():
    result = assess("ab.near", "1").json()

    assert result["decision"] == "WARN"
    assert result["risk_score"] == 20
    assert any(
        item.get("signal") == "short_account_name"
        for item in result["evidence"]
    )


def test_high_amount_adds_30_risk_points():
    result = assess("safe-account.near", "12").json()

    assert result["decision"] == "WARN"
    assert result["risk_score"] == 30
    assert any(
        item.get("signal") == "high_demo_amount"
        for item in result["evidence"]
    )


def test_unapproved_action_adds_40_risk_points():
    result = assess(
        "safe-account.near", "1", "delete_account"
    ).json()

    assert result["decision"] == "WARN"
    assert result["risk_score"] == 40
    assert any(
        item.get("signal") == "unrecognized_action"
        for item in result["evidence"]
    )


def test_blocklist_review_rejects_whitespace_reviewer():
    with pytest.raises(ValueError):
        BlocklistReviewRequest(
            approved=True,
            reviewer="   ",
        )


def test_blocklist_review_rejects_whitespace_note():
    with pytest.raises(ValueError):
        BlocklistReviewRequest(
            approved=True,
            reviewer="human-reviewer",
            note="   ",
        )


def test_blocklist_review_allows_missing_note():
    request = BlocklistReviewRequest(
        approved=True,
        reviewer="  human-reviewer  ",
    )

    assert request.reviewer == "human-reviewer"
    assert request.note is None


def test_wrapper_blocks_transaction_tampering_after_allow():
    result = assess("safe-account.near", "1").json()
    saved = storage.get_decision(result["transaction_id"])
    transaction = json.loads(saved["payload"])
    transaction["amount"] = "99"

    called = []
    wrapper = AgentShieldWrapper(lambda tx: called.append(tx))

    with pytest.raises(SecurityBlocked, match="differs from the assessed payload"):
        wrapper.execute(result, transaction)

    assert called == []


def test_near_execute_rejects_gas_above_fixed_limit(monkeypatch):
    import app.main as main_module

    monkeypatch.setenv("NEAR_ALLOWED_CONTRACT_ID", "vault.testnet")
    monkeypatch.setenv("NEAR_SIGNER_ACCOUNT_ID", "agent.testnet")
    monkeypatch.setenv("NEAR_SIGNER_PUBLIC_KEY", "ed25519:1234567890abcdef")
    monkeypatch.setenv("NEAR_ALLOWED_METHODS", "deposit")

    called = []
    async def fake_view_access_key(*args):
        called.append("key_check")
        return {"permission": {"FunctionCall": {
            "receiver_id": "vault.testnet",
            "method_names": ["deposit"],
            "allowance": "1000",
        }}}

    async def fake_submit(**kwargs):
        called.append("signer")
        return {"submitted": True, "transaction_hash": "mock-hash"}

    monkeypatch.setattr(main_module, "view_access_key", fake_view_access_key)
    monkeypatch.setattr(main_module, "submit_function_call", fake_submit)

    assessment = client.post("/v1/assess", json={
        "agent_id": "test-agent",
        "receiver": "vault.testnet",
        "amount": "0",
        "asset": "NEAR",
        "action": "function_call",
        "function_method": "deposit",
        "function_args": {"account_id": "alice.testnet"},
    }).json()

    response = client.post("/v1/near/execute-function-call", json={
        "transaction_id": assessment["transaction_id"],
        "account_id": "agent.testnet",
        "public_key": "ed25519:1234567890abcdef",
        "contract_id": "vault.testnet",
        "method_name": "deposit",
        "args": {"account_id": "alice.testnet"},
        "gas": 300_000_000_000_000,
    })

    assert response.status_code == 403
    assert called == []


def test_near_account_reports_configured_network(monkeypatch):
    import app.main as main_module

    async def fake_account_exists(account_id):
        return True

    monkeypatch.setattr(main_module, "account_exists", fake_account_exists)
    monkeypatch.setattr(main_module, "NETWORK", "mainnet")

    response = client.get("/v1/near/account/agent.testnet")

    assert response.status_code == 200
    assert response.json()["network"] == "mainnet"
    assert response.json()["exists"] is True


def test_approval_request_rejects_whitespace_reviewer():
    from pydantic import ValidationError
    from app.models import ApprovalRequest

    with pytest.raises(ValidationError):
        ApprovalRequest(approved=True, reviewer="   ")


def test_approval_request_rejects_whitespace_note():
    from pydantic import ValidationError
    from app.models import ApprovalRequest

    with pytest.raises(ValidationError):
        ApprovalRequest(approved=True, reviewer="security-reviewer", note="   ")



def test_approved_blocklist_report_blocks_next_assessment():
    receiver = f"verified-scam-{uuid.uuid4().hex}.near"

    submitted = client.post("/v1/blocklist", json={
        "receiver": receiver,
        "reason": "Test evidence for suspicious receiver activity",
        "reporter": "security-test",
    })
    assert submitted.status_code == 202
    report_id = submitted.json()["report_id"]

    pending = client.get(
        "/v1/blocklist/reports/pending",
        headers={"Authorization": "Bearer test-only-reviewer-key"},
    )
    assert pending.status_code == 200
    assert any(r["report_id"] == report_id for r in pending.json())

    reviewed = client.post(
        f"/v1/blocklist/reports/{report_id}/review",
        json={"approved": True, "reviewer": "security-reviewer"},
        headers={"Authorization": "Bearer test-only-reviewer-key"},
    )
    assert reviewed.status_code == 200
    assert reviewed.json()["status"] == "APPROVED"

    assessment = client.post("/v1/assess", json={
        "agent_id": "test-agent",
        "receiver": receiver,
        "amount": "1",
        "asset": "NEAR",
        "action": "transfer",
    })
    assert assessment.status_code == 200
    assert assessment.json()["decision"] == "BLOCK"

def test_agent_key_cannot_view_pending_blocklist_reports():
    response = client.get("/v1/blocklist/reports/pending")
    assert response.status_code == 401


def test_reviewer_key_can_view_pending_blocklist_reports():
    submitted = client.post("/v1/blocklist", json={
        "receiver": "scammer.near",
        "reason": "Demo security test report",
        "reporter": "test-reviewer",
    })
    assert submitted.status_code == 202

    response = client.get(
        "/v1/blocklist/reports/pending",
        headers={"Authorization": "Bearer test-only-reviewer-key"},
    )

    assert response.status_code == 200
    assert len(response.json()) == 1
    assert response.json()[0]["receiver"] == "scammer.near"
    assert response.json()[0]["status"] == "PENDING"
