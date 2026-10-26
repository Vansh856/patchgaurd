import inspect
import traceback
from abc import ABC, abstractmethod
from typing import Optional
from patchguard.domain.models import RequestPayload, AttackEvents, ThreatType
from patchguard.domain.ports import BaseDetectorPort



class BaseDetector(BaseDetectorPort, ABC):
    """Abstract base class for all detectors."""

    def _create_attack_event(self, payload: RequestPayload, rule_id: str, payload_snippet: str) -> AttackEvents:

        
        caller_file="unknown"
        caller_function="unknown"
        line_number=0

        for frame_info in inspect.stack():  # Iterate through the stack frames to find the caller's information
            filename = frame_info.filename
            if "patchguard" not in filename and not filename.startswith("<"):  # Ignore internal frames and built-in frames
                # Get the caller's file , function, and line number
                caller_file = filename
                caller_function = frame_info.function
                line_number = frame_info.lineno
                break

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