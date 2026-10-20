import pytest 
from patchguard.application.firewall import FirewallEvaluator 
from patchguard.detection.prompt import PromptDetector 
from patchguard.detection.registry import DetectorRegistry 
from patchguard.detection.sql import SQLDetector 
from patchguard.domain import policy
from patchguard.domain.models import RequestPayload, SecurityPolicy, ThreatType 


# this test file is for unit testing the FirewallEvaluator class. It uses pytest fixtures to create instances of the detectors, security policies, and a helper function to create RequestPayload objects for testing. The tests check that the firewall correctly allows clean inputs, blocks malicious inputs when block_mode is enabled, and does not block malicious inputs when block_mode is disabled (dry-run mode).

@pytest.fixture 
def registry(): 
    reg = DetectorRegistry() 
    reg.register(SQLDetector()) 
    reg.register(PromptDetector()) 
    return reg 


@pytest.fixture 
def strict_policy(): 
    return SecurityPolicy( 
        policy_id="test-strict", 
        enabled_detectors=[ThreatType.SQL_INJECTION, ThreatType.PROMPT_INJECTION], 
        block_mode=True, 
        max_latency_ms=3.0, 
        ) 
    
@pytest.fixture 
def dry_run_policy(): 
    return SecurityPolicy( 
        policy_id="test-dry-run", 
        enabled_detectors=[ThreatType.SQL_INJECTION, ThreatType.PROMPT_INJECTION], 
        block_mode=False, 
        max_latency_ms=3.0, 
        ) 

def create_payload(value: str) -> RequestPayload: 
    return RequestPayload( 
        method="POST", 
        path="/api/data", 
        headers={}, 
        query_params={}, 
        body={"input": value}, 
        client_ip="10.0.0.1", 
        ) 

def test_firewall_allows_clean_payload(strict_policy, registry): 
    evaluator = FirewallEvaluator(policy=strict_policy, registry=registry) 
    payload = create_payload("Hello world") 
    event = evaluator.evaluate(payload) 
    assert event is None 

def test_firewall_blocks_sqli_payload(strict_policy, registry): 
    evaluator = FirewallEvaluator(policy=strict_policy, registry=registry) 
    payload = create_payload("admin' OR 1=1 --") 
    event = evaluator.evaluate(payload) 
    assert event is not None 
    assert event.threat_type == ThreatType.SQL_INJECTION 

def test_firewall_dry_run_does_not_block(dry_run_policy, registry): 
    evaluator = FirewallEvaluator(policy=dry_run_policy, registry=registry) 
    payload = create_payload("admin' OR 1=1 --") 
    event = evaluator.evaluate(payload) 
    assert event is None