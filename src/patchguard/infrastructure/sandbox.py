import asyncio
import logging
import tempfile
from pathlib import Path

from patchguard.domain.models import PatchResult, PatchStatus
from patchguard.domain.ports import RegressionSandboxPort

logger = logging.getLogger("patchguard.sandbox")

class PytestSandboxRunner(RegressionSandboxPort):



    async def   run_verification(self,patch: PatchResult)->PatchResult:
        """
        Verifies the given patch by running the associated test suite in a sandboxed environment.

        Args:
            patch (PatchResult): The patch result containing the original code, patched code, and test suite code.

        Returns:
            PatchResult: The updated patch result with the verification status.
        """

        logger.info(f"Running sandbox verification for incident {patch.event_id}...")

        with tempfile.TemporaryDirectory(prefix="patchguard_sandbox_")as temp_dir:

            sandbox_path = Path(temp_dir)
            patched_file_path = sandbox_path / "patched_code.py"
            patched_file_path.write_text(patch.patched_code,encoding="utf-8")


            test_file_path = sandbox_path / "test_patch_verification.py"
            combined_test_code =  (
                f"import sys\n"
                f"sys.path.insert(0, {str(sandbox_path)!r})\n\n"
                f"# --- Exploit Regression Tests ---\n"
                f"{patch.test_suite_code}\n\n"
                f"# --- Benign Functionality Tests ---\n"
                f"{patch.test_suite_code}\n"
            )

            test_file_path.write_text(combined_test_code,encoding="utf-8")

            proc=None

            try:

                proc=await asyncio.create_subprocess_exec(
                    "pytest",
                    str(test_file_path),
                    "-q",
                    "--no-header",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=str(sandbox_path)
                )

                stdout,stderr=await proc.communicate()

                if proc.returncode==0:
                    logger.info(f"Sandbox verification passed for incident {patch.event_id}.")
                    patch.status=PatchStatus.SANDBOX_PASSED
                    patch.sandbox_passed=True
                    patch.verification_output=stdout.decode("utf-8")

                else:
                    logger.warning(f"Sandbox verification failed for incident {patch.event_id}.")
                    patch.status=PatchStatus.SANDBOX_FAILED
                    patch.sandbox_passed=False
                    patch.verification_output = (
                        stderr.decode("utf-8", errors="ignore")
                        + "\n"
                        + stdout.decode("utf-8", errors="ignore")
                    )

            except Exception as e:
                logger.exception(f"Error executing pytest in sandbox: {e}")
                patch.status=PatchStatus.SANDBOX_FAILED
                patch.verification_output=f"Sandbox execution error: {e}"

            finally:
                if proc is not None and proc.returncode is None:
                    proc.kill()
                    await proc.wait()

        return patch

    