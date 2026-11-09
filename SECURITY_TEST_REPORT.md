# AgentShield AI — Security Test Report (v0.3)

## Scope
- Existing risk engine, approval, blocklist and NEAR FunctionCall policy tests.
- BLOCK path must not call signer.
- WARN path must not call signer without approval.
- Contract, method, key scope, attached deposit and action count checks.
- Function argument tampering rejection.
- New replay protection: one assessment ID cannot be submitted twice.
- New fail-closed behavior: signer/RPC failure locks that assessment pending manual chain reconciliation.

## Important boundary
All tests use local test doubles/mocks for NEAR RPC and signer calls. They do not prove that a live NEAR Testnet transaction was signed or broadcast. Do not use real funds or Mainnet credentials.
