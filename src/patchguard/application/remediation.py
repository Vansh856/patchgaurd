import logging
from  typing import Optional

from patchguard.domain.models import AttackEvents, PatchResult, PatchStatus
from patchguard.infrastructure.github import GitHubRepositoryManager
from patchguard.infrastructure.llm import LLMRemediationEngine
from patchguard.infrastructure.runtime import RuntimeContextExtractor
from  patchguard.infrastructure.sandbox import PytestSandboxRunner



logger= logging.getLogger("patchguard.remediation")


class RemediationOrchestrator:


    def __init__(self,
            extractor:Optional[RuntimeContextExtractor]=None,
            llm_engine:Optional[LLMRemediationEngine]=None,
            sandbox:Optional[PytestSandboxRunner]=None,
            github_mgr:Optional[GitHubRepositoryManager]=None
    )-> None:

        """
        it initializes the RemediationOrchestrator with optional components for runtime context extraction, LLM-based remediation, sandbox testing, and GitHub repository management. If any of these components are not provided, default implementations will be used.
        """

        self.extractor=extractor or RuntimeContextExtractor()
        self.llm_engine=llm_engine or LLMRemediationEngine()
        self.sandbox=sandbox or PytestSandboxRunner()
        self.github_mgr=github_mgr 




    async def process_incident(self, event: AttackEvents)-> Optional[PatchResult]:

        """
        Processes an incident by extracting the runtime context, generating a patch using the LLM engine, testing the patch in a sandbox, and creating a pull request in GitHub if the patch is valid.

        Args:
            event (AttackEvents): The detected attack event containing information about the incident.

        Returns:
            Optional[PatchResult]: The result of the patching process, or None if no patch is generated.
        """

        logger.info(f"Starting background auto-remediation pipeline for incident {event.incident_id}...")


        context=self.extractor.extract_context(event)


        patch=self.llm_engine.generate_patch(event,context)

        patch=await self.sandbox.verify_patch(patch)



        if patch.status==PatchStatus.VERIFIED:
            patch=self.github_mgr.create_pull_request(patch)

        elif patch.status!=PatchStatus.VERIFIED:
            logger.warning("Patch verification failed for incident {event.incident_id[:8]}. Skipping GitHub PR creation.")

        return patch
