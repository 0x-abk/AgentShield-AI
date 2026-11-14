import json, sqlite3, uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any

DB_PATH = Path(__file__).resolve().parent.parent / "agentshield.db"

@contextmanager
def connect():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    try:
        with conn:
            yield conn
    finally:
        conn.close()

def init_db():
    with connect() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS decisions (
          transaction_id TEXT PRIMARY KEY, agent_id TEXT NOT NULL, receiver TEXT NOT NULL,
          payload TEXT NOT NULL, decision TEXT NOT NULL, risk_level TEXT NOT NULL,
          risk_score INTEGER NOT NULL, reasons TEXT NOT NULL, evidence TEXT NOT NULL,
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS blocklist (
          receiver TEXT PRIMARY KEY, reason TEXT NOT NULL, evidence_url TEXT,
          reporter TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS blocklist_reports (
          report_id TEXT PRIMARY KEY,
          receiver TEXT NOT NULL,
          reason TEXT NOT NULL,
          evidence_url TEXT,
          reporter TEXT NOT NULL,
          status TEXT NOT NULL CHECK(status IN ('PENDING','APPROVED','REJECTED')),
          reviewer TEXT,
          review_note TEXT,
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          reviewed_at TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_blocklist_reports_receiver
        ON blocklist_reports(receiver);
        CREATE TABLE IF NOT EXISTS approvals (
          transaction_id TEXT PRIMARY KEY, approved INTEGER NOT NULL,
          reviewer TEXT NOT NULL, note TEXT, reviewed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS executions (
          transaction_id TEXT PRIMARY KEY,
          status TEXT NOT NULL CHECK(status IN ('SUBMITTING','SUBMITTED','FAILED')),
          tx_hash TEXT,
          error TEXT,
          updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS audit_logs (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          transaction_id TEXT NOT NULL,
          event_type TEXT NOT NULL,
          actor TEXT NOT NULL,
          details TEXT,
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS idx_audit_logs_transaction
        ON audit_logs(transaction_id);

        CREATE TRIGGER IF NOT EXISTS audit_logs_no_update
        BEFORE UPDATE ON audit_logs
        BEGIN
          SELECT RAISE(ABORT, 'Audit logs cannot be updated');
        END;

        CREATE TRIGGER IF NOT EXISTS audit_logs_no_delete
        BEFORE DELETE ON audit_logs
        BEGIN
          SELECT RAISE(ABORT, 'Audit logs cannot be deleted');
        END;
        """)

def add_decision(payload: dict[str, Any], decision: str, risk_level: str, score: int,
                 reasons: list[str], evidence: list[dict[str, Any]]) -> str:
    txid = str(uuid.uuid4())
    with connect() as db:
        db.execute("INSERT INTO decisions(transaction_id,agent_id,receiver,payload,decision,risk_level,risk_score,reasons,evidence) VALUES(?,?,?,?,?,?,?,?,?)",
          (txid,payload['agent_id'],payload['receiver'],json.dumps(payload),decision,risk_level,score,json.dumps(reasons),json.dumps(evidence)))
    return txid

def get_blocklist():
    with connect() as db:
        return {row['receiver']: dict(row) for row in db.execute("SELECT * FROM blocklist")}

def get_pending_blocklist_reports(limit: int = 100):
    limit = max(1, min(int(limit), 200))
    with connect() as db:
        rows = db.execute(
            """SELECT * FROM blocklist_reports
               WHERE status = 'PENDING'
               ORDER BY created_at DESC
               LIMIT ?""",
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]


def submit_blocklist_report(
    receiver: str,
    reason: str,
    evidence_url: str | None,
    reporter: str,
) -> str:
    report_id = str(uuid.uuid4())
    receiver = receiver.strip().lower()

    with connect() as db:
        db.execute(
            """
            INSERT INTO blocklist_reports
            (report_id, receiver, reason, evidence_url, reporter, status)
            VALUES (?, ?, ?, ?, ?, 'PENDING')
            """,
            (report_id, receiver, reason, evidence_url, reporter),
        )
        add_audit_log(
            report_id,
            "BLOCKLIST_REPORT_SUBMITTED",
            reporter,
            {"receiver": receiver},
            db=db,
        )

    return report_id


def review_blocklist_report(
    report_id: str,
    approved: bool,
    reviewer: str,
    note: str | None = None,
):
    with connect() as db:
        report = db.execute(
            "SELECT * FROM blocklist_reports WHERE report_id = ?",
            (report_id,),
        ).fetchone()

        if not report:
            return None

        if report["status"] != "PENDING":
            return False

        status = "APPROVED" if approved else "REJECTED"

        cursor = db.execute(
            """
            UPDATE blocklist_reports
            SET status = ?, reviewer = ?, review_note = ?,
                reviewed_at = CURRENT_TIMESTAMP
            WHERE report_id = ? AND status = 'PENDING'
            """,
            (status, reviewer, note, report_id),
        )

        if cursor.rowcount != 1:
            return False

        if approved:
            db.execute(
                """
                INSERT OR IGNORE INTO blocklist
                (receiver, reason, evidence_url, reporter)
                VALUES (?, ?, ?, ?)
                """,
                (
                    report["receiver"],
                    report["reason"],
                    report["evidence_url"],
                    report["reporter"],
                ),
            )

        add_audit_log(
            report_id,
            "BLOCKLIST_REPORT_REVIEWED",
            reviewer,
            {
                "receiver": report["receiver"],
                "approved": approved,
                "note": note,
            },
            db=db,
        )

        result = db.execute(
            "SELECT * FROM blocklist_reports WHERE report_id = ?",
            (report_id,),
        ).fetchone()

        return dict(result)

def get_decision(txid: str):
    with connect() as db:
        row = db.execute("SELECT * FROM decisions WHERE transaction_id=?", (txid,)).fetchone()
        return dict(row) if row else None

def save_approval(txid: str, approved: bool, reviewer: str, note: str | None) -> bool:
    with connect() as db:
        cursor = db.execute(
            """
            INSERT INTO approvals(transaction_id, approved, reviewer, note)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(transaction_id) DO NOTHING
            """,
            (txid, int(approved), reviewer, note),
        )

        if cursor.rowcount != 1:
            return False

        add_audit_log(
            txid,
            "TRANSACTION_REVIEWED",
            reviewer,
            {"approved": approved, "note": note},
            db=db,
        )

        return True

def get_approval(txid: str):
    with connect() as db:
        row = db.execute("SELECT * FROM approvals WHERE transaction_id=?", (txid,)).fetchone()
        return dict(row) if row else None

def history(limit: int = 50):
    with connect() as db:
        rows = db.execute("SELECT d.transaction_id,d.agent_id,d.receiver,d.decision,d.risk_level,d.risk_score,d.reasons,d.created_at,a.approved AS approval_status,a.reviewer AS approval_reviewer FROM decisions d LEFT JOIN approvals a ON a.transaction_id=d.transaction_id ORDER BY d.created_at DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]


def claim_execution(txid: str) -> bool:
    """Atomically reserve a transaction ID so it cannot be signed twice.

    A SUBMITTING/FAILED row is intentionally fail-closed. If the process crashes
    during broadcast, an operator must reconcile the chain before any retry.
    """
    try:
        with connect() as db:
            db.execute(
                "INSERT INTO executions(transaction_id,status) VALUES(?, 'SUBMITTING')",
                (txid,),
            )
        return True
    except sqlite3.IntegrityError:
        return False


def finish_execution(txid: str, *, status: str, tx_hash: str | None = None,
                     error: str | None = None) -> None:
    if status not in {"SUBMITTED", "FAILED"}:
        raise ValueError("Invalid terminal execution status")
    with connect() as db:
        cursor = db.execute(
            """UPDATE executions SET status=?, tx_hash=?, error=?,
               updated_at=CURRENT_TIMESTAMP WHERE transaction_id=? AND status='SUBMITTING'""",
            (status, tx_hash, error, txid),
        )
        if cursor.rowcount != 1:
            raise RuntimeError("Execution not found or is no longer SUBMITTING")


def get_execution(txid: str):
    with connect() as db:
        row = db.execute("SELECT * FROM executions WHERE transaction_id=?", (txid,)).fetchone()
        return dict(row) if row else None


def add_audit_log(
    txid: str,
    event_type: str,
    actor: str,
    details: dict[str, Any] | None = None,
    db=None,
):
    if db is not None:
        db.execute(
            """
            INSERT INTO audit_logs(transaction_id, event_type, actor, details)
            VALUES (?, ?, ?, ?)
            """,
            (txid, event_type, actor, json.dumps(details or {})),
        )
        return

    with connect() as conn:
        conn.execute(
            """
            INSERT INTO audit_logs(transaction_id, event_type, actor, details)
            VALUES (?, ?, ?, ?)
            """,
            (txid, event_type, actor, json.dumps(details or {})),
        )


def get_audit_logs(txid: str):
    with connect() as db:
        rows = db.execute(
            """
            SELECT * FROM audit_logs
            WHERE transaction_id = ?
            ORDER BY id ASC
            """,
            (txid,),
        ).fetchall()

        return [dict(row) for row in rows]
