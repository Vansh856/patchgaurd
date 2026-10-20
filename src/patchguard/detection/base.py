import inspect
import traceback
from abc import ABC, abstractmethod
from typing import Optional
from patchguard.domain.models import RequestPayload, AttackEvents, ThreatType
from patchguard.domain.ports import BaseDetectorPort



class BaseDetector(BaseDetectorPort, ABC):
    """
    1. Base class for all detectors in the system.
    2. when a detector detects a threat, it creates an AttackEvents object containing the details of the threat.
    3.it also captures the stack trace and the caller's file, function, and line number for debugging purposes.
    4. it provides a method to create an AttackEvents object with all the necessary information.
    5. it then passes the AttackEvents object to the RemediationEnginePort for patch synthesis.
    """

    def _create_attack_event(self, payload: RequestPayload, rule_id: str, payload_snippet: str) -> AttackEvents:

        stack=inspect.stack()  # Get the current stack trace
        caller_file="unknown"
        caller_function="unknown"
        line_number=0

        for frame_info in stack:  # Iterate through the stack frames to find the caller's information
            filename = frame_info.filename
            if "patchguard" not in filename and not filename.startswith("<"):  # Ignore internal frames and built-in frames
                # Get the caller's file, function, and line number
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