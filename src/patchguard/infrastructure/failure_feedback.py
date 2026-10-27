import re


MAX_FEEDBACK_LENGTH = 4000

_SECRET_PATTERNS = (
    re.compile(
    r"(?i)(api[_-]?key|token|password|secret|authorization)"
    r"(\s*[:=]\s*)([^,\r\n;]+)"
    ),
    re.compile(r"(?i)\b(sk-[A-Za-z0-9_-]+)\b"),
    re.compile(r"(?i)\bAIza[A-Za-z0-9_-]+\b"),
)


def sanitize_failure_output(output: str) -> str:
    """Remove common secret formats and bound feedback size."""

    sanitized = output

    for pattern in _SECRET_PATTERNS:
        sanitized = pattern.sub(
            lambda match: (
                f"{match.group(1)}{match.group(2)}[REDACTED]"
                if match.lastindex and match.lastindex >= 3
                else "[REDACTED]"
            ),
            sanitized,
        )

    if len(sanitized) > MAX_FEEDBACK_LENGTH:
        sanitized = sanitized[:MAX_FEEDBACK_LENGTH] + "\n[TRUNCATED]"

    return sanitized