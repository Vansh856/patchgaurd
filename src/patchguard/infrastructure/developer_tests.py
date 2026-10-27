from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEVELOPER_TEST_ROOT = PROJECT_ROOT / "tests"

DEVELOPER_TEST_PATHS: tuple[str, ...] = (
    str(DEVELOPER_TEST_ROOT / "unit"),
    str(DEVELOPER_TEST_ROOT / "integration"),
)


def get_developer_test_paths() -> tuple[str, ...]:
    """Return developer-owned test directories."""

    return tuple(
        path
        for path in DEVELOPER_TEST_PATHS
        if Path(path).exists()
    )