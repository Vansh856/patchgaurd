from typing import List, Optional
from patchguard.domain.models import RequestPayload, AttackEvents,ThreatType
from patchguard.domain.ports import BaseDetectorPort





class DetectorRegistry:
    """Registry for managing detectors."""

    def __init__(self)-> None:
        self._detectors: List[BaseDetectorPort] = []


    def register(self, detector: BaseDetectorPort) -> None:
        """
        Register a new detector.

        Args:
            detector (BaseDetectorPort): The detector to register.
        """
        self._detectors.append(detector)

    def evaluate(self, payload: RequestPayload, enabled_detectors: Optional[List[ThreatType]] = None) -> Optional[AttackEvents]:
        """
        Evaluate the payload against all registered detectors.

        Args:
            payload (RequestPayload): The request payload to evaluate.

        Returns:
            Optional[AttackEvents]: The first detected attack event, or None if no attack is detected.
        """
        for detector in self._detectors:
            if (
                enabled_detectors is not None 
                and ThreatType(detector.threat_type) not in enabled_detectors
            ):
                continue
            event = detector.detect(payload)
            if event is not None:
                return event

        return None