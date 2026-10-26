from patchguard.application.firewall import FirewallEvaluator
from patchguard.application.remediation import RemediationOrchestrator
from patchguard.domain.policy import get_default_policy
from patchguard.detection.registry import DetectorRegistry
from patchguard.detection.sql import SQLDetector
from patchguard.detection.prompt import PromptDetector
from patchguard.interfaces.middleware import PatchGuardMiddleware
from patchguard.infrastructure.queue import AsyncIncidentQueue
from contextlib import asynccontextmanager
import os
from patchguard.infrastructure.github import GitHubRepositoryManager


def create_patchguard_middleware(app, policy: None)->PatchGuardMiddleware:
    """Creates a new PatchGuard middleware instance."""
   

    if not policy:   # If no policy is provided, use the default policy
        policy = get_default_policy() 



    registry = DetectorRegistry() # Create a new detector registry
    registry.register(SQLDetector())
    registry.register(PromptDetector()) # Register the PromptDetector with the registry

    incident_queue = AsyncIncidentQueue(maxsize=1000) # Create an AsyncIncidentQueue with a maximum size of 1000


    evaluator = FirewallEvaluator(policy=policy, registry=registry) # Create a FirewallEvaluator instance with the provided policy and detector registry
    
    
    # Create a RemediationOrchestrator instance for handling remediation tasks
    github_token = os.getenv("GITHUB_TOKEN")
    github_repo=os.getenv("PATCHGUARD_REPO")
    github_manager = None

    if github_token and github_repo:
        github_manager = GitHubRepositoryManager(github_token=github_token, repo_name=github_repo)

    orchestrator = RemediationOrchestrator(github_mgr=github_manager,)
    
    @asynccontextmanager
    async def lifespan(_app):
        """Context manager for managing the lifespan of the application."""
        try:
           yield  # Yield control back to the caller, allowing the application to run
        finally:
            await incident_queue.stop()  # Ensure the incident queue is stopped when the application shuts down
    
    
    # Return a new PatchGuardMiddleware instance with the app, evaluator, and incident queue
    return PatchGuardMiddleware(
        app=app, 
        evaluator=evaluator, 
        incident_queue=incident_queue,
        remediation_handler=orchestrator.process_incident
    ) 
