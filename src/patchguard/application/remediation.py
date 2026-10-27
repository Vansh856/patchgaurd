import asyncio
import logging
from typing import Optional

from patchguard.domain.models import AttackEvents, PatchResult, PatchStatus
from patchguard.infrastructure.github import GitHubRepositoryManager
from patchguard.infrastructure.llm_providers import (
    LLMRemediationEngine,
    ProviderAdapterError,
)
from patchguard.infrastructure.runtime import RuntimeContextExtractor
from patchguard.infrastructure.sandbox import PytestSandboxRunner
from patchguard.infrastructure.trusted_tests import get_trusted_test_paths
from patchguard.infrastructure.developer_tests import(
    get_developer_test_paths,
)
from patchguard.infrastructure.failure_feedback import(
    sanitize_failure_output,
)


logger = logging.getLogger("patchguard.remediation")

MAX_PATCH_ATTEMPTS = 3


class RemediationOrchestrator:
    def __init__(
        self,
        extractor: Optional[RuntimeContextExtractor] = None,
        llm_engine: Optional[LLMRemediationEngine] = None,
        sandbox: Optional[PytestSandboxRunner] = None,
        github_mgr: Optional[GitHubRepositoryManager] = None,
    ) -> None:
        self.extractor = extractor or RuntimeContextExtractor()
        self.llm_engine = llm_engine or LLMRemediationEngine()
        self.sandbox = sandbox or PytestSandboxRunner()
        self.github_mgr = github_mgr

    async def process_incident(
        self,
        event: AttackEvents,
    ) -> Optional[PatchResult]:
        logger.info(
            "Starting background auto-remediation pipeline for incident %s",
            event.event_id,
        )

        context = self.extractor.extract_context(event)
        previous_patch = ""
        failure_feedback = ""
        last_result: Optional[PatchResult] = None

        for attempt_number in range(1, MAX_PATCH_ATTEMPTS + 1):
            try:
                provider_response = await asyncio.to_thread(
                    self.llm_engine.generate_patch,
                    event,
                    context,
                    previous_patch,
                    failure_feedback,
                )

                patch = PatchResult(
                    target_file=event.caller_file,
                    event_id=event.event_id,
                    threat_type=event.threat_type,
                    trusted_test_paths=tuple(
                        str(path)
                        for path in get_trusted_test_paths(event.threat_type)
                    ),
                    developer_test_paths=get_developer_test_paths(),
                    branch_name=f"patchguard/fix-{event.event_id[:8]}",
                    original_code=context.get("full_source", ""),
                    patched_code=provider_response.fixed_code,
                    test_suite_code="",
                    sandbox_passed=False,
                    diff_summary=provider_response.explanation,
                    provider_name=provider_response.provider_name,
                    attempt_number=attempt_number,
                )

            except ProviderAdapterError as exc:
                logger.error(
                    "Provider generation failed for incident %s "
                    "on attempt %d: %s",
                    event.event_id,
                    attempt_number,
                    exc,
                )

                last_result = PatchResult(
                    target_file=event.caller_file,
                    event_id=event.event_id,
                    threat_type=event.threat_type,
                    branch_name=f"patchguard/fix-{event.event_id[:8]}",
                    trusted_test_paths=tuple(
                        str(path)
                        for path in get_trusted_test_paths(event.threat_type)
                    ),
                    developer_test_paths=get_developer_test_paths(),
                    original_code=context.get("full_source", ""),
                    patched_code=previous_patch,
                    test_suite_code="",
                    sandbox_passed=False,
                    diff_summary=str(exc),
                    attempt_number=attempt_number,
                    error_code="PROVIDER_UNAVAILABLE",
                    status=PatchStatus.MANUAL_REVIEW,
                )

                failure_feedback = (
                    f"error_code=PROVIDER_UNAVAILABLE\n"
                    f"provider_error={exc}"
                )
                continue

            patch = await self.sandbox.run_verification(patch)
            last_result = patch

            if patch.status == PatchStatus.SANDBOX_PASSED:
                if self.github_mgr is not None:
                    patch = await asyncio.to_thread(
                        self.github_mgr.create_pull_request,
                        patch,
                    )
                return patch

            previous_patch = patch.patched_code
            failure_feedback = self._build_failure_feedback(patch)

        if last_result is not None:
            last_result.status = PatchStatus.MANUAL_REVIEW
            last_result.error_code = (
                last_result.error_code or "MAX_ATTEMPTS_EXCEEDED"
            )
            last_result.diff_summary = (
                f"Remediation failed after {MAX_PATCH_ATTEMPTS} attempts. "
                f"{last_result.diff_summary}"
            )

            if self.github_mgr is not None:
                issue_url = await asyncio.to_thread(
                    self.github_mgr.create_manual_remediation_issue,
                    last_result,
                )

                if issue_url:
                    last_result.diff_summary = (
                        f"{last_result.diff_summary} "
                        f"Manual issue: {issue_url}"
                    )

            return last_result

        return None

    @staticmethod
    def _build_failure_feedback(patch: PatchResult) -> str:
        """Build sanitized, bounded feedback for the next provider attempt."""

        verification_output = sanitize_failure_output(
            patch.verification_output.strip()
        )
        error_code = patch.error_code or "SANDBOX_TEST_FAILED"

        return (
            f"error_code={error_code}\n"
            f"attempt_number={patch.attempt_number}\n"
            f"verification_output={verification_output}"
        )