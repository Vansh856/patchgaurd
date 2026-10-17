from patchguard.domain.models import SecurityPolicy,ThreatType

def get_default_policy() -> SecurityPolicy:

    return SecurityPolicy(
        policy_id="default_strict_v1",
        enabled_detectors=[
            ThreatType.SQL_INJECTION,
            ThreatType.PROMPT_INJECTION,
        ],
        block_mode=True,
        max_latency_ms=3.0
    )


def validate_policy(policy: SecurityPolicy) -> bool:

    return policy.max_latency_ms>3.0
