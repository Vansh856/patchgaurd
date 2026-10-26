import logging
from  typing import Optional
import asyncio

from patchguard.domain.models import AttackEvents, PatchResult, PatchStatus
from patchguard.infrastructure.github import GitHubRepositoryManager
from patchguard.infrastructure.llm import (LLMRemediationEngine,LLMProviderError)
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




    async def process_incident(self, event: AttackEvents) -> Optional[PatchResult]:
        logger.info(
            "Starting background auto-remediation pipeline for incident %s",
            event.event_id,
        )

        context = self.extractor.extract_context(event)

        try:
            patch = await asyncio.to_thread(
                self.llm_engine.synthesize_patch,
                event,
                context,
            )
        except LLMProviderError as exc:
            logger.error(
                "LLM remediation unavailable for incident %s: %s",
                event.event_id,
                exc,
            )
            return PatchResult(
                target_file=event.caller_file,
                event_id=event.event_id,
                branch_name=f"patchguard/fix-{event.event_id[:8]}",
                original_code=context.get("full_source", ""),
                patched_code="",
                test_suite_code="",
                sandbox_passed=False,
                diff_summary=str(exc),
                status=PatchStatus.MANUAL_REVIEW,
            )

        patch = await self.sandbox.run_verification(patch)

        if patch.status == PatchStatus.SANDBOX_PASSED:
            if self.github_mgr is not None:
                patch = await asyncio.to_thread(
                    self.github_mgr.create_pull_request,
                    patch,
                )
        else:
            logger.warning(
                "Patch verification failed for incident %s. "
                "Skipping GitHub PR creation.",
                event.event_id,
                )

        return patch
        
