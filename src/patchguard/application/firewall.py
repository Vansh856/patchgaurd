import logging # use to track the latency of the evaluation and log a warning if it exceeds the max_latency_ms defined in the SecurityPolicy

import time # USED to measure the time taken for the evaluation of the request payload against the registered detectors. It helps in enforcing the max_latency_ms constraint defined in the SecurityPolicy.

from typing import Optional #USED to indicate that the evaluate method can return either an AttackEvents object or None, depending on whether a threat is detected.

from patchguard.detection.registry import DetectorRegistry
from patchguard.domain.models import SecurityPolicy, AttackEvents,RequestPayLoad



logger = logging.getLogger("patchguard.firewall")


class FireWallEvaluator:

    """
    1. The FireWallEvaluator class is responsible for evaluating incoming request payloads against the registered detectors based on the defined security policy.
    2. It measures the time taken for the evaluation and logs a warning if it exceeds the max_latency_ms defined in the SecurityPolicy.
    3. If a threat is detected and block_mode is enabled, it returns the corresponding AttackEvents object; otherwise, it logs the detection in dry-run mode and returns None.
    """

    def __init__(self,policy: SecurityPolicy, registry: DetectorRegistry)-> None:
        self.policy = policy
        self.registry = registry



    def evaluate(self,payload: RequestPayLoad)-> Optional[AttackEvents]:

        """
        1. The evaluate method takes a RequestPayLoad object as input and evaluates it against the registered detectors.
        2. It measures the time taken for the evaluation and logs a warning if it exceeds the max_latency_ms defined in the SecurityPolicy.
        3. If a threat is detected and block_mode is enabled, it returns the corresponding AttackEvents object; otherwise, it logs the detection in dry-run mode and returns None.
        4. The method returns an AttackEvents object if a threat is detected and block_mode is enabled; otherwise, it returns None.
        """

        start_time = time.perf_counter() # takes the current time in seconds 

        event = self.registry.evaluate(payload) # takes the current request payload and evaluates it against all registered detectors in the DetectorRegistry. If a threat is detected, it returns an AttackEvents object; otherwise, it returns None.


        elapsed_ms=(time.perf_counter() - start_time) * 1000  # calculate the time taken for the evaluation in milliseconds 

        if elapsed_ms > self.policy.max_latency_ms:
            logger.warning(f"PatchGuard evaluation exceeded latency budget: {elapsed_ms:.2f} ms > {self.policy.max_latency_ms} ms")


        if event is None:
            return None

        if not self.policy.block_mode:
            logger.info(f"[Dry-Run] Detected Threat: {event.threat_type} but block_mode = False")# log the detection in dry-run mode and return None
            return None
        
        return event # return the AttackEvents object if a threat is detected and block_mode is enabled