# AgentShield AI — Security Test Report (v0.9)

## 1. Scope

The automated test suite contains 95 passing tests covering:

- ALLOW, WARN, and BLOCK risk decisions.
- Blocklist enforcement and invalid transaction amounts.
- BLOCK never reaching the signer; WARN requiring human approval.
- NEAR FunctionCall contract, method, key-scope, deposit, and action-count restrictions.
- Function argument tampering and replay protection.
- Fail-closed behavior after signer failure.
- Agent and Human Reviewer API authentication and endpoint separation.
- Prevention of duplicate transaction reviews.
- Append-only audit logs and reviewer-only access.
- Rate limiting, window reset, and expired-client cleanup.

## 2. Authentication and authorization

- General protected API endpoints require the Agent API Key.
- Approval and audit-log endpoints require the separate Human Reviewer API Key.
- Tests verify that Agent and Reviewer permissions are separated.
- The health endpoint remains publicly accessible.

These are shared bearer secrets, not individual identities or complete role-based access control.

## 3. Approval and audit logging

- A transaction assessment cannot be reviewed twice.
- Successful reviews create audit records.
- SQLite triggers reject audit-log UPDATE and DELETE operations.
- Audit-log retrieval is restricted to the Reviewer API Key.

SQLite triggers do not protect against direct database-file modification or trigger removal.

## 4. Rate limiting

- Tests verify request limits and reset behavior.
- Invalid API keys do not consume the rate limit.
- Expired client entries are cleaned during subsequent requests.

The current limiter is in-memory and per application process. It is not a distributed production rate-limiting system.

## 5. NEAR integration boundary

The project includes read-only NEAR Testnet RPC checks and a restricted FunctionCall execution path.

Automated tests use local mocks and test doubles for NEAR RPC and signer operations.

**The test suite does not prove that a live NEAR Testnet transaction has been signed or broadcast.**

The py-near==1.2.22 dependency is installed and pinned in requirements.txt. Live Testnet signing and broadcast have not yet been verified.

## 6. Test results

- Latest full test run: 95 passed.
- A Starlette TestClient / AnyIO deprecation warning was reported.
- No claim of live blockchain transaction execution is made.

Run the latest tests with:

    pytest -q

## 7. Production limitations

Before production use:

- Validate live Testnet signing in a compatible Linux environment.
- Independently audit the signer adapter and contract behavior.
- Use a dedicated FunctionCall key with explicit method restrictions.
- Add distributed idempotency and transaction reconciliation.
- Consider a shared rate-limit backend for multiple instances.
- Strengthen audit-log protection and monitoring.
- Review key custody and deployment security.

Never use a Full-Access key for the AI agent. Do not use Mainnet funds for testing.
