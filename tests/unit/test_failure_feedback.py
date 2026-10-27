from patchguard.infrastructure.failure_feedback import (
    MAX_FEEDBACK_LENGTH,
    sanitize_failure_output,
)


def test_sanitize_failure_output_redacts_common_secrets():
    output = (
        "api_key=secret-value "
        "authorization: Bearer token-value "
        "password=my-password "
        "key=AIzaTestValue"
    )

    sanitized = sanitize_failure_output(output)

    assert "secret-value" not in sanitized
    assert "Bearer" not in sanitized
    assert "token-value" not in sanitized
    assert "my-password" not in sanitized
    assert "AIzaTestValue" not in sanitized
    assert "[REDACTED]" in sanitized


def test_sanitize_failure_output_truncates_long_output():
    sanitized = sanitize_failure_output("x" * (MAX_FEEDBACK_LENGTH + 100))

    assert len(sanitized) > MAX_FEEDBACK_LENGTH
    assert sanitized.endswith("[TRUNCATED]")