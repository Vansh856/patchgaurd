import asyncio
import logging
import shutil
import tempfile
from pathlib import Path

from patchguard.domain.models import PatchResult, PatchStatus
from patchguard.domain.ports import RegressionSandboxPort


logger = logging.getLogger("patchguard.sandbox")


class PytestSandboxRunner(RegressionSandboxPort):
    async def run_verification(self, patch: PatchResult) -> PatchResult:
        """Run trusted security tests and developer-owned tests."""

        logger.info(
            "Running sandbox verification for incident %s...",
            patch.event_id,
        )

        with tempfile.TemporaryDirectory(
            prefix="patchguard_sandbox_"
        ) as temp_dir:
            sandbox_path = Path(temp_dir)
            patched_file_path = sandbox_path / "patched_code.py"
            patched_file_path.write_text(
                patch.patched_code,
                encoding="utf-8",
            )

            trusted_test_paths = tuple(
                Path(path) for path in patch.trusted_test_paths
            )
            developer_test_paths = tuple(
                Path(path) for path in patch.developer_test_paths
            )

            if not trusted_test_paths:
                return self._fail(
                    patch,
                    "NO_TRUSTED_TESTS",
                    "No trusted PatchGuard tests were registered.",
                )

            trusted_sandbox_paths = self._copy_trusted_tests(
                trusted_test_paths,
                sandbox_path,
                patch,
            )

            if trusted_sandbox_paths is None:
                return patch

            trusted_result, trusted_output = await self._run_pytest(
                trusted_sandbox_paths,
                sandbox_path,
            )

            if not trusted_result:
                return self._fail(
                    patch,
                    "SECURITY_TEST_FAILED",
                    trusted_output,
                )

            developer_sandbox_paths = self._copy_developer_tests(
                developer_test_paths,
                sandbox_path,
            )

            if developer_sandbox_paths:
                developer_result, developer_output = await self._run_pytest(
                    developer_sandbox_paths,
                    sandbox_path,
                )

                if not developer_result:
                    return self._fail(
                        patch,
                        "DEVELOPER_TEST_FAILED",
                        developer_output,
                    )

                patch.verification_output = (
                    "Trusted security tests passed.\n"
                    "Developer tests passed.\n"
                    + developer_output
                )
            else:
                patch.verification_output = (
                    "Trusted security tests passed.\n"
                    "No developer tests were registered."
                )

            patch.status = PatchStatus.SANDBOX_PASSED
            patch.sandbox_passed = True
            patch.error_code = None
            return patch

    @staticmethod
    def _copy_trusted_tests(
        trusted_test_paths: tuple[Path, ...],
        sandbox_path: Path,
        patch: PatchResult,
    ) -> list[str] | None:
        sandbox_paths: list[str] = []

        for index, trusted_test_path in enumerate(trusted_test_paths):
            if not trusted_test_path.is_file():
                patch.status = PatchStatus.SANDBOX_FAILED
                patch.sandbox_passed = False
                patch.error_code = "TRUSTED_TEST_NOT_FOUND"
                patch.verification_output = (
                    f"Trusted test was not found: {trusted_test_path}"
                )
                return None

            destination = (
                sandbox_path
                / f"trusted_test_{index}_{trusted_test_path.name}"
            )
            shutil.copy2(trusted_test_path, destination)
            sandbox_paths.append(str(destination))

        return sandbox_paths

    @staticmethod
    def _copy_developer_tests(
        developer_test_paths: tuple[Path, ...],
        sandbox_path: Path,
    ) -> list[str]:
        sandbox_paths: list[str] = []

        for source_path in developer_test_paths:
            if not source_path.exists():
                continue

            destination = sandbox_path / source_path.name

            if source_path.is_dir():
                shutil.copytree(source_path, destination, dirs_exist_ok=True)
                sandbox_paths.append(str(destination))
            else:
                shutil.copy2(source_path, destination)
                sandbox_paths.append(str(destination))

        return sandbox_paths

    @staticmethod
    async def _run_pytest(
        test_paths: list[str],
        sandbox_path: Path,
    ) -> tuple[bool, str]:
        process = None

        try:
            process = await asyncio.create_subprocess_exec(
                "pytest",
                *test_paths,
                "-q",
                "--no-header",
                cwd=str(sandbox_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await process.communicate()

            output = (
                stdout.decode("utf-8", errors="ignore")
                + "\n"
                + stderr.decode("utf-8", errors="ignore")
            ).strip()

            return process.returncode == 0, output

        except Exception as exc:
            logger.exception("Pytest execution failed: %s", exc)
            return False, f"Sandbox execution error: {exc}"

        finally:
            if process is not None and process.returncode is None:
                process.kill()
                await process.wait()

    @staticmethod
    def _fail(
        patch: PatchResult,
        error_code: str,
        output: str,
    ) -> PatchResult:
        patch.status = PatchStatus.SANDBOX_FAILED
        patch.sandbox_passed = False
        patch.error_code = error_code
        patch.verification_output = output
        return patch