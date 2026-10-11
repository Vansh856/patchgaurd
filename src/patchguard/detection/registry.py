from typing import List, Optional
from patchguard.domain.models import RequestPayLoad, AttackEvents
from patchguard.domain.ports import BaseDetectorPort




class DectactorRegistry:
    """Registry for managing detectors."""

    def __init__(self)-> None:
        self._detectors: List[BaseDetectorPort] = []

    def register_detector(self, detector: BaseDetectorPort) -> None:
        """Register a new detector."""
        self._detectors.append(detector)

    def evaluate(self, payload: RequestPayLoad)-> Optional[AttackEvents]:
        """Evaluate the payload against all registered detectors."""
        for detector in self._detectors:
            event = detector.detect(payload)
            if event:
                return event
            return None