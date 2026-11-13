from enum import Enum
from pydantic import BaseModel, Field, HttpUrl, field_validator
from typing import Any

class Decision(str, Enum):
    ALLOW = "ALLOW"
    WARN = "WARN"
    BLOCK = "BLOCK"

class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

class TransactionRequest(BaseModel):
    agent_id: str = Field(min_length=1, max_length=100)
    receiver: str = Field(min_length=2, max_length=64)
    amount: str = Field(pattern=r"^(0|[1-9]\d*)(\.\d{1,24})?$")
    asset: str = Field(min_length=1, max_length=20)
    action: str = Field(min_length=1, max_length=40)
    function_method: str | None = Field(default=None, min_length=1, max_length=128)
    function_args: dict[str, Any] = Field(default_factory=dict)

    @field_validator("receiver")
    @classmethod
    def normalize_receiver(cls, value: str) -> str:
        value = value.strip().lower()
        if not value or any(ch.isspace() for ch in value):
            raise ValueError("receiver must be a valid account identifier")
        return value

class RiskDecision(BaseModel):
    decision: Decision
    risk_level: RiskLevel
    risk_score: int = Field(ge=0, le=100)
    reasons: list[str]
    evidence: list[dict[str, Any]] = []
    requires_human_approval: bool
    transaction_id: str

class ApprovalRequest(BaseModel):
    approved: bool
    reviewer: str = Field(min_length=1, max_length=100)
    note: str | None = Field(default=None, max_length=500)

    @field_validator("reviewer", "note")
    @classmethod
    def normalize_approval_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if not value:
            raise ValueError("field cannot be empty or whitespace")
        return value

class BlocklistReport(BaseModel):
    receiver: str = Field(min_length=2, max_length=64)
    reason: str = Field(min_length=5, max_length=500)
    evidence_url: HttpUrl | None = None
    reporter: str = Field(min_length=1, max_length=100)

    @field_validator("receiver")
    @classmethod
    def normalize_receiver(cls, value: str) -> str:
        value = value.strip().lower()
        if not value or any(ch.isspace() for ch in value):
            raise ValueError("receiver must be a valid account identifier")
        return value

    @field_validator("reason", "reporter")
    @classmethod
    def normalize_report_text(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("field cannot be empty or whitespace")
        return value


class BlocklistReviewRequest(BaseModel):
    approved: bool
    reviewer: str = Field(min_length=1, max_length=100)
    note: str | None = Field(default=None, max_length=500)

    @field_validator("reviewer", "note")
    @classmethod
    def normalize_review_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if not value:
            raise ValueError("field cannot be empty or whitespace")
        return value

class NearFunctionCallCheckRequest(BaseModel):
    account_id: str = Field(min_length=2, max_length=64)
    public_key: str = Field(min_length=10, max_length=128)
    requested_contract: str = Field(min_length=2, max_length=64)
    method_name: str = Field(min_length=1, max_length=128)
    attached_deposit_yocto: str = Field(default="0", pattern=r"^\d+$")
    action_count: int = Field(default=1, ge=1, le=10)


class NearFunctionCallExecutionRequest(BaseModel):
    transaction_id: str = Field(min_length=1, max_length=64)
    account_id: str = Field(min_length=2, max_length=64)
    public_key: str = Field(min_length=10, max_length=128)
    contract_id: str = Field(min_length=2, max_length=64)
    method_name: str = Field(min_length=1, max_length=128)
    args: dict[str, Any] = Field(default_factory=dict)
    gas: int = Field(default=30_000_000_000_000, ge=1, le=300_000_000_000_000)
    attached_deposit_yocto: str = Field(default="0", pattern=r"^\d+$")
    action_count: int = Field(default=1, ge=1, le=10)
