from pathlib import Path

from patchguard.domain.models import ThreatType


TRUSTED_TEST_ROOT = Path(__file__).resolve().parents[3] / "tests" / "security"

TRUSTED_TESTS: dict[ThreatType, tuple[str, ...]] = {
    ThreatType.SQL_INJECTION: (
        "test_sql_injection.py",
    ),
    ThreatType.PROMPT_INJECTION: (
        "test_prompt_injection.py",
    ),
}


def get_trusted_test_paths(threat_type: ThreatType) -> tuple[Path, ...]:
    """Return PatchGuard-owned tests for a detected threat type."""

    filenames = TRUSTED_TESTS.get(threat_type, ())

    return tuple(
        TRUSTED_TEST_ROOT / filename
        for filename in filenames
    )