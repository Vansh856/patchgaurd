from patchguard.application.firewall import FirewallEvaluator
from patchguard.domain.policy import get_default_policy
from patchguard.detection.registry import DetectorRegistry
from patchguard.detection.sql import SQLDetector
from patchguard.detection.prompt import PromptDetector
from patchguard.interfaces.middleware import PatchGuardMiddleware

def create_patchguard_middleware(app, policy: None)->PatchGuardMiddleware:
    """Creates a new PatchGuard middleware instance."""
   

    if not policy:   # If no policy is provided, use the default policy
        policy = get_default_policy() 



    registry = DetectorRegistry() # Create a new detector registry
    registry.register(SQLDetector())
    registry.register(PromptDetector()) # Register the PromptDetector with the registry



    evaluator = FirewallEvaluator(policy=policy, registry=registry) # Create a FirewallEvaluator instance with the provided policy and detector registry

    return PatchGuardMiddleware(app=app, evaluator=evaluator)