# AgentShield AI

A Python MVP security gate for AI-agent transactions. It evaluates a recipient and transaction policy before the agent is allowed to call its signer.

## What works in this MVP

- `POST /v1/assess`: deterministic `ALLOW`, `WARN`, or `BLOCK` decision.
- Demo blocklist plus report endpoint with evidence metadata.
- Human approval endpoint for `WARN` assessments.
- Fail-closed execution wrapper: `BLOCK` never calls the signer; `WARN` requires recorded approval.
- SQLite decision history and audit records.
- Optional read-only NEAR Testnet account-existence query.
- Reproducible prompt-injection simulation with a fake signer (no funds, no private key).

## Architecture

`AI agent -> FastAPI -> deterministic RiskEngine -> SQLite audit log -> AgentShieldWrapper -> injected signer`

The language model is not trusted to make security decisions. It can produce explanations, but only the deterministic policy engine controls the decision.

## Install and run

Python 3.11+ is recommended.

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\\Scripts\\activate
pip install -r requirements.txt
cp .env.example .env             # optional; testnet is the default
uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000/docs` for the interactive API.

## Try it

Safe receiver:

```bash
curl -X POST http://127.0.0.1:8000/v1/assess \\
  -H 'Content-Type: application/json' \\
  -d '{"agent_id":"agent-001","receiver":"safe-account.near","amount":"2","asset":"NEAR","action":"transfer"}'
```

Known demo blocklist receiver:

```bash
curl -X POST http://127.0.0.1:8000/v1/assess \\
  -H 'Content-Type: application/json' \\
  -d '{"agent_id":"agent-001","receiver":"known-scam.near","amount":"2","asset":"NEAR","action":"transfer"}'
```

A high amount (12 NEAR or more) produces `WARN` under the default demo policy. Use the returned `transaction_id` to review it:

```bash
curl -X POST http://127.0.0.1:8000/v1/approvals/TRANSACTION_ID \\
  -H 'Content-Type: application/json' \\
  -d '{"approved":true,"reviewer":"human-reviewer","note":"Verified out of band"}'
```

## Prompt-injection attack demonstration

```bash
python scripts/attack_demo.py
```

Expected result: the malicious prompt asks the agent to pay `known-scam.near`; the API returns `BLOCK`; the wrapper raises `SecurityBlocked`; `signer_calls=0` proves that the signer was never called.

## Tests

```bash
pytest -q
```

## NEAR integration status and limitations

The Python implementation includes read-only NEAR Testnet JSON-RPC queries, a FunctionCall signer adapter, and an API execution path with fail-closed security checks. However, the py-near SDK is not installed in the current Termux environment because of Android build compatibility issues. Therefore, live NEAR Testnet signing and transaction broadcasting are not currently available or verified in this environment.

Before enabling live NEAR Testnet execution, install and validate the supported NEAR SDK in a compatible environment, independently audit the signer adapter, and configure a Function-Call Access Key restricted to one contract and the minimum required method names. Keep the key outside this API process where possible. Never use a Full-Access key for the agent.

A Function-Call Access Key is not a universal spending-limit mechanism: it is restricted to a receiver contract and optionally method names, and it cannot attach NEAR tokens to the call. If an account has only Function-Call keys, it cannot transfer NEAR or manage keys through ordinary transactions; exhausting a finite gas allowance can make the key unusable. A contract method may still have application-specific behavior, so validate the contract itself and do not claim the key blocks every economic effect.

## Data sources and evidence

- Shared blocklist: user/community reports stored in SQLite with reporter, reason and optional evidence URL. Reports are unverified until a moderation process is added.
- Account existence: NEAR Testnet JSON-RPC `query/view_account` (optional endpoint). Existence is not a trust score.
- Account age, historical activity, contract code hash/change history and prior agent interactions: **not yet implemented**. Add an indexed chain data source and cache verified observations before using these signals for decisions.
- The short-name and amount thresholds are transparent demo heuristics, not claims of real-world fraud detection.

## Security notes before production

- Separate Agent and Human Reviewer API Keys protect the API. The Agent key protects general `/v1` endpoints; the Reviewer key is required for approval endpoints. These are shared bearer secrets, not individual user identities or full role-based access control.
- Add rate limiting, request signing and immutable/remote audit logs.
- NEAR FunctionCall execution has a SQLite replay guard. It is currently single-instance protection; distributed idempotency and transaction reconciliation are still needed for production.
- Moderate blocklist reports and preserve provenance.
- Add explicit policy versioning and idempotency keys.
- Add chain-derived account age/activity and contract-code-change evidence.
- Have an independent reviewer audit the signer boundary and NEAR contract permissions.
- Run on Testnet first. Do not put private keys in `.env`, source control, or prompts.

## NEAR Testnet integration (read-only verification)

The MVP now includes read-only NEAR JSON-RPC endpoints:

- `GET /v1/near/access-keys/{account_id}` lists access-key types and their FunctionCall scopes.
- `POST /v1/near/validate-function-call` fetches the requested public key's on-chain permission and checks it against the server-pinned contract and requested method.
- `GET /v1/near/contract/{contract_id}/code` returns the deployed code hash and block height, which can be used by a future code-change monitor.

Configure `.env` before running:

```env
NEAR_NETWORK=testnet
NEAR_RPC_URL=https://rpc.testnet.near.org
NEAR_ALLOWED_CONTRACT_ID=your-contract.testnet
```

`NEAR_ALLOWED_CONTRACT_ID` is intentionally server-side. A client cannot choose the trusted contract in its request. If it is missing, the validation endpoint returns `503` and fails closed.

Example FunctionCall permission check:

```bash
curl -X POST http://127.0.0.1:8000/v1/near/validate-function-call \
  -H 'Content-Type: application/json' \
  -d '{"account_id":"agent.testnet","public_key":"ed25519:YOUR_PUBLIC_KEY", "requested_contract":"your-contract.testnet", "method_name":"deposit", "attached_deposit_yocto":"0", "action_count":1}'
```

This check verifies the key's current on-chain permission. It does **not** sign or broadcast a transaction. The next integration step is to connect a separately secured signer that can only use the dedicated FunctionCall key, then make the signer call the AgentShield gate immediately before signing. Never load a FullAccess key into the AI agent process.

### NEAR FunctionCall key limitations

A FunctionCall access key is scoped to one receiver contract and an optional list of method names. It cannot authorize a normal NEAR transfer or an attached deposit. Its allowance is for gas/transaction fees; it is not a general per-transfer spending limit. If `method_names` is empty, the key can call any method on that contract. Use an explicit method allowlist and a small gas allowance. A FunctionCall key also cannot replace AgentShield's own policy checks or human-approval flow.

## Tests

Run:

```bash
pytest -q
```

The test suite covers the original risk/approval wrapper and NEAR FunctionCall permission checks, including FullAccess refusal, wrong contract, disallowed method, attached deposit, multi-action request, and missing server-side contract pin.

> Testnet RPC endpoints are external dependencies. Unit tests mock RPC responses; a successful test run does not claim that a live transaction was signed or broadcast.

## Secure NEAR Testnet FunctionCall signer (MVP)

This build adds `POST /v1/near/execute-function-call`. It is deliberately narrow:

- Testnet only (`NEAR_NETWORK=testnet`); Mainnet signing is refused.
- The contract ID, signer account, signer public key, and allowed method names are pinned in server environment configuration.
- The assessed transaction must have `action=function_call`, and the method plus JSON arguments must exactly match the original assessment. Changing arguments after risk assessment is rejected.
- The signer key is checked against NEAR RPC immediately before execution and must be a FunctionCall key scoped to the configured contract and an explicit method list. FullAccess and wildcard/empty method lists are rejected.
- Exactly one FunctionCall action with zero attached deposit is permitted. Transfers and attached deposits are not supported by this signer.
- `BLOCK` never reaches the signer. `WARN` requires a stored human approval.
- The private key is read only from `NEAR_SIGNER_PRIVATE_KEY`; never commit it or put it in source control.

### Install signer SDK

The signer adapter targets `py-near==1.2.22` (package import: `py_near`).
This SDK is not included in the current `requirements.txt` and could not be
installed in the current Android Termux environment because of build
compatibility issues.

Live signing has therefore not been verified in this environment. SDK
installation and signer integration must first be validated in a compatible
Linux environment before attempting Testnet transactions. Installing the
project requirements alone does not enable live signing.

### Configure Testnet signer

Set these values in your local `.env` (do not commit `.env`):

```dotenv
NEAR_NETWORK=testnet
NEAR_RPC_URL=https://rpc.testnet.near.org
NEAR_ALLOWED_CONTRACT_ID=your-contract.testnet
NEAR_ALLOWED_METHODS=deposit
NEAR_SIGNER_ACCOUNT_ID=your-agent.testnet
NEAR_SIGNER_PUBLIC_KEY=ed25519:YOUR_PUBLIC_KEY
NEAR_SIGNER_PRIVATE_KEY=ed25519:YOUR_TESTNET_PRIVATE_KEY
```

The key must already exist on the signer account as a NEAR FunctionCall access key, scoped to the configured contract and explicit method(s). Provision it with a trusted wallet/CLI using a FullAccess owner key; AgentShield does not create or elevate keys. Use a disposable Testnet account only.

### Assess then execute

First create a risk assessment. The receiver must be the pinned contract and the action must be `function_call`. The method and arguments are part of the assessment and cannot be changed later:

```json
{
  "agent_id": "agent-001",
  "receiver": "your-contract.testnet",
  "amount": "0",
  "asset": "NEAR",
  "action": "function_call",
  "function_method": "deposit",
  "function_args": {"account_id": "alice.testnet"}
}
```

Use the returned `transaction_id` with `POST /v1/near/execute-function-call` and submit the same account, public key, contract, method, and args. For WARN assessments, complete `POST /v1/approvals/{transaction_id}` first.

### Important limitations

A FunctionCall access key limits which contract and methods the key can invoke; it does not automatically enforce every business-level spending rule or make an unsafe contract method safe. A zero attached deposit does not prove the called contract cannot move assets held by that contract. Only allow methods whose contract behavior has been reviewed. The API's method allowlist is an additional policy gate, not a substitute for contract auditing, key custody controls, rate limits, replay protection, or production security review.

The test suite mocks NEAR RPC and the signer adapter. It verifies the fail-closed policy path but does not prove a live Testnet transaction was submitted. Before a hackathon demo, install the SDK, configure a disposable Testnet key/contract, and run a live end-to-end test.

## Dashboard (v0.2)

The project now includes a lightweight browser dashboard served by FastAPI at `/`.
It provides transaction assessment, WARN review actions, recent security history,
blocklist reporting, and read-only NEAR Testnet account/access-key inspection.

Start the API and dashboard:

```bash
uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000/` for the dashboard or `http://127.0.0.1:8000/docs`
for the interactive API documentation. The dashboard uses the same-origin API;
no separate frontend build step is required.

Dashboard counters summarize the latest 100 assessments returned by the history
endpoint. WARN items leave the pending-review queue after a reviewer records a
decision. The dashboard uses a separate Agent API Key for general protected `/v1` API calls and a Human Reviewer API Key for approval actions. Keys are held in browser memory only and must be entered again after a reload.
It remains a prototype and is not production-hardened. Do not expose it publicly
or use it to manage real funds without HTTPS, rate limiting, hardened key custody,
appropriate authorization controls, and an independent security review.


## Security test stage (v0.3)

This stage adds an atomic replay guard to the NEAR execution endpoint:

- Each assessed transaction ID can be submitted for signing at most once.
- The API reserves the ID in SQLite before calling the signer (`SUBMITTING`).
- A successful signer response marks it `SUBMITTED`.
- A signer/RPC error marks it `FAILED` and blocks automatic retry.
- If the process crashes mid-broadcast, the row remains `SUBMITTING`; reconcile the NEAR chain manually before any recovery. This is intentionally fail-closed because an RPC timeout does not prove the chain rejected the transaction.

Run the expanded suite:

```bash
pytest -q
```

The replay tests use mocked RPC/signer responses. They validate duplicate-submission prevention at the API layer; they are not evidence of a live Testnet broadcast. The SQLite guard is suitable for a single-instance prototype. A multi-instance deployment needs a shared transactional database and a carefully designed idempotency/reconciliation strategy.

## Current NEAR Signer Status

The NEAR FunctionCall signer adapter and API execution path are implemented in the codebase, with fail-closed policy checks and mocked security tests.

However, the `py-near` SDK is not installed in the current Termux environment because of Android build compatibility issues. Therefore, live NEAR Testnet signing and transaction broadcasting have not been verified and are not currently available in this environment.

The 27 passing tests validate the tested security logic using mocked signer/RPC behavior. They do not prove that a real transaction was signed or broadcast.

Do not configure real funds or use this prototype on Mainnet. Live Testnet integration remains a future validation step.
