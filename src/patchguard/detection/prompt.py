import re
from typing import Optional
from patchguard.domain.models import RequestPayLoad, AttackEvents
from patchguard.detection.base import BaseDetector



class PromptDetactor(BaseDetector):


    INJECTION_PATTERNS = [ 
        r"ignore\s+(all\s+)?(previous|prior)\s+instructions", 
        r"you\s+are\s+now\s+(a|an|in)\s+([a-z0-9_\-\\s]+)\s+mode", 
        r"disregard\s+(above|previous)\s+rules",
        r"system\s\*:\s\*override", 
        r"do\s+anything\s+now", 
        r"bypass\s+(safety|content)\s+filters", 
        ]  # compiled regex patterns for prompt injection detection

    def __init__(self):
        """it initializes the PromptDetactor class and compiles the regex patterns for prompt injection detection. whiich decreases the time complexity of the detection process."""
        self._compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.INJECTION_PATTERNS]


    @property
    def threat_type(self) -> str:
        """it connacts to the BaseDetector class and returns the threat type as 'prompt_injection'."""
        return "prompt_injection"

    def detect(self, payload: RequestPayLoad) -> Optional[AttackEvents]:

        target_inputs=[]
        if payload.query_params:
            target_inputs.extend(payload.query_params.values())

        if isinstance(payload.body, dict):
            target_inputs.extend(str(v) for v in payload.body.values())

        for input_str in target_inputs:

            if not isinstance(input_str, str):
                continue

            for pattern in self._compiled_patterns:

                if pattern.search(input_str):
                    return self._create_attack_event(payload=payload, rule_id="PROMPT_INJECTION_001", payload_snippet=input_str[:100],)  # Limit snippet length to 100 characters

        return None