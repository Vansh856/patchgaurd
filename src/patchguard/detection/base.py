import traceback
from abc import ABC, abstractmethod
from patchguard.domain.models import RequestPayload, AttackEvents, ThreatType
from patchguard.domain.ports import BaseDetectorPort



class BaseDetector(BaseDetectorPort, ABC):
    """Abstract base class for all detectors."""

    def _create_attack_event(self, payload: RequestPayload, rule_id: str, payload_snippet: str) -> AttackEvents:

        
        caller_file = payload.caller_file or "unknown"
        caller_function = payload.caller_function or "unknown"
        line_number = payload.caller_line or 0

        stack_trace_str = "".join(traceback.format_stack())  # Convert the stack trace to a string for logging or debugging purposes

        return AttackEvents(
            threat_type=ThreatType(self.threat_type),
            rule_id=rule_id,
            payload_snippet=payload_snippet,
            caller_file=caller_file,
            caller_route=payload.path,
            caller_function=caller_function,
            line_number=line_number,
            stack_trace=stack_trace_str,
            raw_request=payload
        )