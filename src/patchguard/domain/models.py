from enum import Enum
from dataclasses import dataclass,field
from datetime import datetime,timezone
from typing import Optional, Dict, Any
import uuid

#==============================================================================
#1. THIS FILE IS FOR ENUMS USED IN THE PATCHGUARD DOMAIN MODELS
#==============================================================================

class ThreatType(str, Enum):
    """Enum representing different types of threats."""
    SQL_INJECTION = "sql_injection"
    PROMPT_INJECTION = "prompt_injection"
    CODE_INJECTION = "code_injection"
    UNKNOWN = "unknown"

class PatchStatus(str, Enum):
    """Enum representing the status of a patch."""
    PENDING = "pending"
    SANDBOX_PASSED = "sandbox_passed"
    SANDBOX_FAILED = "sandbox_failed"
    PR_OPENED = "pr_opened"
    REJECTED = "rejected"

@dataclass(frozen=True)
class RequestPayload:
    """Class representing the payload of a request."""
    path: str
    method: str
    headers: Dict[str, str]=field(default_factory=dict)
    query_params: Dict[str, str]=field(default_factory=dict)
    body: Optional[Any]=None
    client_ip:str="127.0.0.1"
    request_id: str=field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime=field(default_factory=lambda: datetime.now(timezone.utc))

@dataclass(frozen=True)
class AttackEvents:
    """Class representing an attack event."""
    threat_type: ThreatType
    rule_id: str
    payload_snippet: str
    caller_file:str
    caller_route:str
    caller_function:str
    line_number:int
    stack_trace:str
    raw_request: RequestPayload
    event_id: str=field(default_factory=lambda: str(uuid.uuid4()))
    blocked: bool=True
    timestamp: datetime=field(default_factory=lambda: datetime.now(timezone.utc))

@dataclass(frozen=True)
class SecurityPolicy:
    """Class representing a security policy."""
    policy_id: str="default_policy"
    enabled_detectors:list[ThreatType]=field(default_factory=lambda: [ThreatType.SQL_INJECTION, ThreatType.PROMPT_INJECTION, ThreatType.CODE_INJECTION])
    block_mode: bool=True
    max_latency_ms: float=3.0


@dataclass
class PatchResult:
    """Class representing the result of a patch."""
    event_id: str
    branch_name: str
    original_code: str
    patched_code: str
    test_suite_code: str
    sandbox_passed: bool
    diff_summary: str
    patch_id: str=field(default_factory=lambda: str(uuid.uuid4()))
    status: PatchStatus=PatchStatus.PENDING
    pr_url: Optional[str]=None
    created_at: datetime=field(default_factory=lambda: datetime.now(timezone.utc))
