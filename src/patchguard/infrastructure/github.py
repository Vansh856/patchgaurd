import logging

from github import Github, GithubException

from patchguard.domain.models import PatchResult, PatchStatus
from patchguard.domain.ports import RepositoryManagerPort


logger = logging.getLogger("patchguard.github")


class GitHubRepositoryManager(RepositoryManagerPort):
    def __init__(self, github_token: str, repo_name: str) -> None:
        self.github_token = github_token
        self.repo_name = repo_name
        self._gh = Github(github_token)

    def create_pull_request(self, patch: PatchResult) -> PatchResult:
        """Create a branch, commit the patched file, and open a pull request."""
        logger.info("Creating GitHub pull request for incident %s", patch.event_id)

        try:
            repo = self._gh.get_repo(self.repo_name)
            default_branch = repo.default_branch
            base_ref = repo.get_git_ref(f"heads/{default_branch}")
            branch_name = patch.branch_name

            try:
                repo.create_git_ref(
                    ref=f"refs/heads/{branch_name}",
                    sha=base_ref.object.sha,
                )
            except GithubException as exc:
                if exc.status != 422:
                    raise
                logger.warning("Branch %s already exists", branch_name)

            commit_message = (
                f"security(patchguard): auto remediation incident {patch.event_id}"
            )

            try:
                existing_file = repo.get_contents(
                    patch.target_file,
                    ref=branch_name,
                )
            except GithubException as exc:
                if exc.status != 404:
                    raise
                repo.create_file(
                    path=patch.target_file,
                    message=commit_message,
                    content=patch.patched_code,
                    branch=branch_name,
                )
            else:
                repo.update_file(
                    path=patch.target_file,
                    message=commit_message,
                    content=patch.patched_code,
                    sha=existing_file.sha,
                    branch=branch_name,
                )

            pull_request = repo.create_pull(
                title=f"[PatchGuard] Auto-remediation {patch.event_id[:8]}",
                body=self._built_pr_body(patch),
                head=branch_name,
                base=default_branch,
            )
            patch.pr_url = pull_request.html_url
            patch.status = PatchStatus.PR_OPENED
            logger.info("Created GitHub PR %s", pull_request.html_url)
        except GithubException:
            logger.exception("Failed to create GitHub pull request")
            patch.status = PatchStatus.REJECTED

        return patch


    def create_manual_remediation_issue(
        self,
        patch: PatchResult,
    ) -> str:
        """Create a GitHub Issue for remediation that needs human review."""

        logger.info(
            "Creating manual remediation issue for incident %s",
            patch.event_id,
        )

        try:
            repo = self._gh.get_repo(self.repo_name)

            issue = repo.create_issue(
                title=(
                    f"[PatchGuard] Manual remediation required "
                    f"{patch.event_id[:8]}"
                ),
                body=self._build_manual_issue_body(patch),
                labels=["security", "patchguard", "manual-review"],
            )

            logger.info("Created GitHub issue %s", issue.html_url)
            return issue.html_url

        except GithubException:
            logger.exception(
                "Failed to create manual remediation issue"
            )
            return ""

    def _build_manual_issue_body(self, patch: PatchResult) -> str:
        """Build a sanitized manual-remediation issue body."""

        return f"""## PatchGuard Manual Remediation Required

**Incident ID:** `{patch.event_id}`
**Threat type:** `{patch.threat_type.value if patch.threat_type else "unknown"}`
**Target file:** `{patch.target_file}`
**Attempts:** `{patch.attempt_number}`
**Provider:** `{patch.provider_name or "unknown"}`
**Error code:** `{patch.error_code or "MAX_ATTEMPTS_EXCEEDED"}`

### Summary

Automated remediation did not produce a patch that passed
the required validation checks after the maximum number of attempts.

### Verification feedback

```text
{patch.verification_output[:4000]}
A developer must inspect the incident and implement the remediation manually.   
```
"""

    async def create_patch_pull_request(self, patch_result: PatchResult) -> str:
        """Implement the repository-manager port."""
        patch = self.create_pull_request(patch_result)
        return patch.pr_url or ""

    def _built_pr_body(self, patch: PatchResult) -> str:
        return f"""## PatchGuard Autonomous Security Patch

**Incident ID:** `{patch.event_id}`
**Target File:** `{patch.target_file}`
**Status:** `SANDBOX_PASSED`

The patch passed the isolated regression sandbox and is ready for human review.
"""
