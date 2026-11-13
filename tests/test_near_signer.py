import asyncio
import sys
import types

import pytest

from app import near_signer


def test_transaction_hash_accepts_string():
    assert near_signer._transaction_hash("test-tx-hash") == "test-tx-hash"


def test_transaction_hash_reads_transaction_object():
    class Transaction:
        hash = "object-tx-hash"

    class Result:
        transaction = Transaction()

    assert near_signer._transaction_hash(Result()) == "object-tx-hash"


def test_transaction_hash_reads_dictionary():
    result = {"transaction": {"hash": "dict-tx-hash"}}
    assert near_signer._transaction_hash(result) == "dict-tx-hash"


def test_signer_shuts_down_after_success(monkeypatch):
    events = []

    class FakeAccount:
        def __init__(self, account_id, private_key, rpc_addr):
            events.append(("init", account_id, rpc_addr))

        async def startup(self):
            events.append("startup")

        async def function_call(self, *args, **kwargs):
            events.append("function_call")
            return "test-transaction-hash"

        async def shutdown(self):
            events.append("shutdown")

    fake_package = types.ModuleType("py_near")
    fake_account_module = types.ModuleType("py_near.account")
    fake_account_module.Account = FakeAccount
    fake_package.account = fake_account_module

    monkeypatch.setitem(sys.modules, "py_near", fake_package)
    monkeypatch.setitem(sys.modules, "py_near.account", fake_account_module)
    monkeypatch.setenv("NEAR_NETWORK", "testnet")
    monkeypatch.setenv("NEAR_SIGNER_ACCOUNT_ID", "agent.testnet")
    monkeypatch.setenv("NEAR_SIGNER_PRIVATE_KEY", "test-only-private-key")
    monkeypatch.setenv("NEAR_RPC_URL", "https://rpc.testnet.near.org")

    result = asyncio.run(near_signer.submit_function_call(
        account_id="agent.testnet",
        contract_id="vault.testnet",
        method_name="record",
        args={"receiver": "safe.testnet"},
        gas=10000000000000,
    ))

    assert result["submitted"] is True
    assert result["transaction_hash"] == "test-transaction-hash"
    assert events[-1] == "shutdown"


def test_signer_shuts_down_after_function_call_failure(monkeypatch):
    events = []

    class FakeAccount:
        def __init__(self, account_id, private_key, rpc_addr):
            pass

        async def startup(self):
            events.append("startup")

        async def function_call(self, *args, **kwargs):
            events.append("function_call")
            raise RuntimeError("simulated failure")

        async def shutdown(self):
            events.append("shutdown")

    fake_package = types.ModuleType("py_near")
    fake_account_module = types.ModuleType("py_near.account")
    fake_account_module.Account = FakeAccount
    fake_package.account = fake_account_module

    monkeypatch.setitem(sys.modules, "py_near", fake_package)
    monkeypatch.setitem(sys.modules, "py_near.account", fake_account_module)
    monkeypatch.setenv("NEAR_NETWORK", "testnet")
    monkeypatch.setenv("NEAR_SIGNER_ACCOUNT_ID", "agent.testnet")
    monkeypatch.setenv("NEAR_SIGNER_PRIVATE_KEY", "test-only-private-key")
    monkeypatch.setenv("NEAR_RPC_URL", "https://rpc.testnet.near.org")

    with pytest.raises(near_signer.SignerUnavailable):
        asyncio.run(near_signer.submit_function_call(
            account_id="agent.testnet",
            contract_id="vault.testnet",
            method_name="record",
            args={"receiver": "safe.testnet"},
            gas=10000000000000,
        ))

    assert events[-1] == "shutdown"


@pytest.mark.parametrize(
    ("overrides", "extra_kwargs"),
    [
        ({"NEAR_NETWORK": "mainnet"}, {}),
        ({"NEAR_SIGNER_ACCOUNT_ID": ""}, {}),
        ({"NEAR_SIGNER_PRIVATE_KEY": ""}, {}),
        ({"NEAR_SIGNER_ACCOUNT_ID": "other.testnet"}, {}),
        ({}, {"deposit_yocto": 1}),
        ({"NEAR_RPC_URL": "http://rpc.testnet.near.org"}, {}),
    ],
)
def test_signer_rejects_unsafe_configuration(
    monkeypatch, overrides, extra_kwargs
):
    class FakeAccount:
        def __init__(self, *args, **kwargs):
            raise AssertionError("Unsafe configuration reached account creation")

    fake_package = types.ModuleType("py_near")
    fake_account_module = types.ModuleType("py_near.account")
    fake_account_module.Account = FakeAccount
    fake_package.account = fake_account_module

    monkeypatch.setitem(sys.modules, "py_near", fake_package)
    monkeypatch.setitem(sys.modules, "py_near.account", fake_account_module)

    monkeypatch.setenv("NEAR_NETWORK", "testnet")
    monkeypatch.setenv("NEAR_SIGNER_ACCOUNT_ID", "agent.testnet")
    monkeypatch.setenv("NEAR_SIGNER_PRIVATE_KEY", "test-only-private-key")
    monkeypatch.setenv("NEAR_RPC_URL", "https://rpc.testnet.near.org")

    for key, value in overrides.items():
        monkeypatch.setenv(key, value)

    kwargs = {
        "account_id": "agent.testnet",
        "contract_id": "vault.testnet",
        "method_name": "record",
        "args": {"receiver": "safe.testnet"},
        "gas": 10000000000000,
        **extra_kwargs,
    }

    with pytest.raises(near_signer.SignerNotConfigured):
        asyncio.run(near_signer.submit_function_call(**kwargs))


def test_signer_rejects_mainnet_rpc_url(monkeypatch):
    class FakeAccount:
        def __init__(self, *args, **kwargs):
            raise AssertionError("Mainnet RPC must be rejected before account creation")

    fake_package = types.ModuleType("py_near")
    fake_account_module = types.ModuleType("py_near.account")
    fake_account_module.Account = FakeAccount
    fake_package.account = fake_account_module

    monkeypatch.setitem(sys.modules, "py_near", fake_package)
    monkeypatch.setitem(sys.modules, "py_near.account", fake_account_module)
    monkeypatch.setenv("NEAR_NETWORK", "testnet")
    monkeypatch.setenv("NEAR_SIGNER_ACCOUNT_ID", "agent.testnet")
    monkeypatch.setenv("NEAR_SIGNER_PRIVATE_KEY", "test-only-private-key")
    monkeypatch.setenv("NEAR_RPC_URL", "https://rpc.mainnet.near.org")

    with pytest.raises(near_signer.SignerNotConfigured):
        asyncio.run(near_signer.submit_function_call(
            account_id="agent.testnet",
            contract_id="vault.testnet",
            method_name="record",
            args={"receiver": "safe.testnet"},
            gas=30_000_000_000_000,
        ))
