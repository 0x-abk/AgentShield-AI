import pytest

from app import storage


@pytest.fixture(autouse=True)
def isolated_database(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", tmp_path / "test.db")
    storage.init_db()


def test_claim_execution_succeeds_once():
    txid = "test-transaction-1"

    assert storage.claim_execution(txid) is True
    assert storage.claim_execution(txid) is False

    execution = storage.get_execution(txid)
    assert execution["status"] == "SUBMITTING"


def test_finish_execution_marks_submitted():
    txid = "test-transaction-2"

    assert storage.claim_execution(txid) is True

    storage.finish_execution(
        txid,
        status="SUBMITTED",
        tx_hash="fake-testnet-hash",
    )

    execution = storage.get_execution(txid)
    assert execution["status"] == "SUBMITTED"
    assert execution["tx_hash"] == "fake-testnet-hash"


def test_finish_execution_marks_failed():
    txid = "test-transaction-3"

    assert storage.claim_execution(txid) is True

    storage.finish_execution(
        txid,
        status="FAILED",
        error="Test failure",
    )

    execution = storage.get_execution(txid)
    assert execution["status"] == "FAILED"
    assert execution["error"] == "Test failure"


def test_cannot_finish_execution_twice():
    txid = "test-transaction-4"

    assert storage.claim_execution(txid) is True
    storage.finish_execution(txid, status="FAILED")

    with pytest.raises(RuntimeError):
        storage.finish_execution(txid, status="SUBMITTED")


def test_cannot_finish_unknown_execution():
    with pytest.raises(RuntimeError):
        storage.finish_execution(
            "unknown-transaction",
            status="SUBMITTED",
        )


def test_invalid_terminal_status_is_rejected():
    with pytest.raises(ValueError):
        storage.finish_execution(
            "test-transaction-6",
            status="SUBMITTING",
        )
