import os
import subprocess
import sys


def run_rpc_import(network, rpc_url):
    env = os.environ.copy()
    env["NEAR_NETWORK"] = network
    if rpc_url is None:
        env.pop("NEAR_RPC_URL", None)
    else:
        env["NEAR_RPC_URL"] = rpc_url
    return subprocess.run(
        [
            sys.executable,
            "-c",
            "from app.near_rpc import NETWORK, RPC_URL; print(NETWORK, RPC_URL)",
        ],
        env=env,
        capture_output=True,
        text=True,
    )


def test_testnet_rejects_mainnet_rpc_url():
    result = run_rpc_import("testnet", "https://rpc.mainnet.near.org")
    assert result.returncode != 0
    assert "must match NEAR_NETWORK=testnet" in result.stderr


def test_mainnet_rejects_testnet_rpc_url():
    result = run_rpc_import("mainnet", "https://rpc.testnet.near.org")
    assert result.returncode != 0
    assert "must match NEAR_NETWORK=mainnet" in result.stderr


def test_testnet_uses_official_rpc_by_default():
    result = run_rpc_import("testnet", None)
    assert result.returncode == 0
    assert "testnet https://rpc.testnet.near.org" in result.stdout
