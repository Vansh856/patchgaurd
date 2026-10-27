from pathlib import Path

import pytest

from patchguard.domain.models import PatchResult, PatchStatus
from patchguard.infrastructure.sandbox import PytestSandboxRunner


@pytest.mark.asyncio
async def test_sandbox_runs_trusted_and_developer_tests(tmp_path):
    trusted_test = tmp_path / "trusted_test.py"
    trusted_test.write_text(
        "def test_trusted_security_check():\n"
        "    assert True\n",
        encoding="utf-8",
    )

    developer_test = tmp_path / "developer_test.py"
    developer_test.write_text(
        "def test_developer_regression_check():\n"
        "    assert True\n",
        encoding="utf-8",
    )

    patch = PatchResult(
        target_file="example.py",
        event_id="test-event",
        branch_name="patchguard/test",
        original_code="",
        patched_code="value = 1",
        test_suite_code=(
            "def test_untrusted_llm_test():\n"
            "    assert False\n"
        ),
        sandbox_passed=False,
        diff_summary="test",
        trusted_test_paths=(str(trusted_test),),
        developer_test_paths=(str(developer_test),),
    )

    result = await PytestSandboxRunner().run_verification(patch)

    assert result.status == PatchStatus.SANDBOX_PASSED
    assert result.sandbox_passed is True
    assert result.error_code is None
    assert "Trusted security tests passed." in result.verification_output
    assert "Developer tests passed." in result.verification_output