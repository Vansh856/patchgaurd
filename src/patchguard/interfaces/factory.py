from patchguard.application.firewall import FireWallEvaluator
from patchguard.domain.policy import get_default_policy
from patchguard.detection.registry import DectactorRegistry
from patchguard.detection.sql import SQLDetector
from patchguard.detection.prompt import PromptDetector
from patchguard.interfaces.middleware import PatchGuardMiddleware

def create_patchguard_middleware(app, policy: None)->PatchGuardMiddleware:
    """Creates a new PatchGuard middleware instance."""
   

    if not policy:   # If no policy is provided, use the default policy
        policy = get_default_policy() 



    registry = DectactorRegistry() # Create a new detector registry
    registry.register(SQLDetector())
    registry.register(PromptDetector()) # Register the PromptDetector with the registry



    evaluator = FireWallEvaluator(policy=policy, registry=registry) # Create a FireWallEvaluator instance with the provided policy and detector registry

    return PatchGuardMiddleware(app=app, evaluator=evaluator)