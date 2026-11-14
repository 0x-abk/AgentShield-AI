# AgentShield AI — NEAR Hackathon Submission

## Project Overview

AgentShield AI is an AI-agent transaction security gateway built to reduce unsafe and unauthorized blockchain actions.

It evaluates proposed transactions before execution and returns one of three decisions: ALLOW, WARN, or BLOCK.

## Problem

AI agents can misunderstand instructions, receive malicious prompt injections, or attempt transactions that do not match the user's intended action.

Applications need a security layer that checks transactions independently before a signer is allowed to execute them.

## Solution

AgentShield AI provides:
- Deterministic transaction risk decisions.
- A BLOCK decision that prevents signing.
- Human approval for WARN decisions.
- Transaction payload integrity checks.
- Blocklist reporting and moderated review.
- SQLite decision history and audit records.
- A restricted NEAR FunctionCall execution path.

The security decision is made by deterministic policy checks, not by trusting an LLM response.

## NEAR Integration

The project includes:
- Read-only NEAR RPC account and access-key checks.
- Contract code information lookup.
- FunctionCall access-key permission validation.
- A Testnet-only signer adapter using py-near.
- Server-pinned signer account, public key, contract, and allowed methods.
- Zero attached deposit and a fixed 30 TGas execution limit.
- Replay protection to prevent duplicate execution attempts.

The intended NEAR integration uses a restricted Testnet FunctionCall access key. The agent must not use a Full-Access key.

## Security Architecture

AI Agent
  -> AgentShield API
  -> Deterministic Risk Engine
  -> SQLite Decision and Audit Records
  -> Human Approval when required
  -> NEAR Policy and Access-Key Validation
  -> Restricted Testnet Signer

BLOCK decisions never reach the signer. WARN decisions require human approval. The execution endpoint checks that the submitted method and arguments match the assessed transaction.

## Testing

Latest full automated test run:
- 98 passed
- 1 Starlette / AnyIO deprecation warning

Tests use local mocks and test doubles for NEAR RPC and signer operations.

Live NEAR Testnet signing and transaction broadcast have not yet been verified. The project does not claim production readiness or Mainnet execution.

Run tests with:

```bash
pytest -q
```

## Current Limitations

- Live Testnet signing and broadcast still require independent verification.
- Rate limiting is in-memory and per process.
- SQLite audit protections do not prevent direct database-file modification.
- Distributed execution reconciliation is not implemented.
- This is an experimental security prototype, not a production custody system.

## Track

AI Security & Defense

## Hackathon Scope

This project demonstrates a security gateway for AI-agent transactions interacting with NEAR. The submission distinguishes implemented and tested features from integrations that still require live-network verification.
