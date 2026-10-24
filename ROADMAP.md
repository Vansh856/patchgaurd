# PatchGuard Architecture Roadmap

## Current status

PatchGuard has the right high-level architecture, but the implementation is currently split into:

1. A partially working request-time detection path.
2. An incomplete asynchronous remediation path.
3. Infrastructure adapters whose interfaces do not yet match the domain models.

The latest cleanup commit was:

```text
dfac974 - Clean up project naming and spelling
```

Generated `__pycache__` noise was removed and the worktree was clean at the time of the commit.

---

# What has gone wrong

## 1. Naming was inconsistent

Different files used different names for the same concepts:

```text
RequestPayLoad / RequestPayload
PromptDetactor / PromptDetector
DectactorRegistry / DetactorRegistry / DetectorRegistry
FireWallEvaluator / FirewallEvaluator
meathod / method
praser / parser
prased / parsed
```

These were corrected in the cleanup commit.

The main canonical models now live in `src/patchguard/domain/models.py`.

## 2. The project has no packaging configuration

`pyproject.toml` is currently empty.

Because this project uses a `src` layout, imports fail unless `PYTHONPATH` is manually configured.

Current workaround:

```powershell
$env:PYTHONPATH="D:\github\patchgaurd\src"
pytest
```

This should not be required.

## 3. The SQL detector is broken

The SQL detector uses:

```python
token.type
```

However, `sqlparse` tokens expose:

```python
token.ttype
```

This causes SQL detector tests to fail with:

```text
AttributeError: 'Identifier' object has no attribute 'type'
```

The issue is in `src/patchguard/detection/sql.py`.

## 4. The detector registry stops too early

The registry currently returns `None` inside the detector loop. The logic is effectively:

```python
for detector in self._detectors:
    if detector detects something:
        return event

    return None
```

This means only the first registered detector runs.

Correct behavior:

```python
for detector in self._detectors:
    event = detector.detect(payload)

    if event:
        return event

return None
```

## 5. Detector interfaces are inconsistent

`BaseDetectorPort` defines `threat_type` as a property, but `SQLDetector` currently implements it as a method.

Affected files:

- `src/patchguard/domain/ports.py`
- `src/patchguard/detection/sql.py`
- `src/patchguard/detection/prompt.py`

Both detectors should implement the same interface.

Recommended design:

```python
@property
def threat_type(self) -> ThreatType:
    ...
```

Both detectors should return the enum value, not raw strings.

## 6. Security policy is not fully enforced

`SecurityPolicy` contains:

```python
enabled_detectors
```

However, `FirewallEvaluator` currently evaluates every registered detector without checking whether that detector is enabled.

A disabled detector should not run.

## 7. Middleware does not enqueue incidents

The middleware blocks detected requests, but it does not send the event to the asynchronous remediation queue.

Current flow:

```text
Threat detected
    |
    v
403 response
```

Required flow:

```text
Threat detected
    |
    +--> Enqueue AttackEvent for remediation
    |
    +--> Return 403 immediately
```

Relevant files:

- `src/patchguard/interfaces/middleware.py`
- `src/patchguard/infrastructure/queue.py`

## 8. The background queue is not connected to application lifecycle

`src/patchguard/infrastructure/queue.py` defines a worker, but nothing currently starts it during application startup or stops it during shutdown.

Required lifecycle:

```text
Application startup
    |
    v
Create queue and remediation orchestrator
    |
    v
Start worker

Application shutdown
    |
    v
Stop worker cleanly
```

## 9. Domain models and remediation adapters disagree

The domain `PatchResult` is defined with fields such as:

```text
event_id
branch_name
original_code
patched_code
test_suite_code
sandbox_passed
diff_summary
pr_url
```

The infrastructure code uses different fields:

```text
incident_id
target_file
fixed_code
exploit_test_code
benign_test_code
verification_output
pull_request_url
```

Affected files:

- `src/patchguard/domain/models.py`
- `src/patchguard/infrastructure/llm.py`
- `src/patchguard/infrastructure/sandbox.py`
- `src/patchguard/infrastructure/github.py`

One canonical `PatchResult` model must be selected and used everywhere.

Recommended model:

```python
@dataclass
class PatchResult:
    event_id: str
    target_file: str
    original_code: str
    patched_code: str
    exploit_test_code: str
    benign_test_code: str
    diff_summary: str
    status: PatchStatus = PatchStatus.PENDING
    verification_output: str = ""
    pr_url: Optional[str] = None
```

## 10. Remediation port methods do not match implementations

The ports define:

```python
synthesize_patch()
run_verification()
create_patch_pull_request()
```

The implementations use:

```python
generate_patch()
verify_patch()
create_pull_request()
```

The orchestrator also calls methods that do not exist on the concrete classes.

Affected files:

- `src/patchguard/domain/ports.py`
- `src/patchguard/application/remediation.py`
- `src/patchguard/infrastructure/llm.py`
- `src/patchguard/infrastructure/sandbox.py`
- `src/patchguard/infrastructure/github.py`

## 11. Patch status values do not match

The enum defines:

```python
SANDBOX_PASSED
SANDBOX_FAILED
```

The implementation uses:

```python
VERIFIED
FAILED
SYNTHESIZED
```

Those values are not defined consistently.

Recommended status model:

```python
class PatchStatus(str, Enum):
    PENDING = "pending"
    GENERATED = "generated"
    SANDBOX_PASSED = "sandbox_passed"
    SANDBOX_FAILED = "sandbox_failed"
    PR_OPENED = "pr_opened"
    REJECTED = "rejected"
```

## 12. Runtime context extraction uses the wrong event field

`AttackEvents` defines:

```python
caller_file
```

However, `src/patchguard/infrastructure/runtime.py` accesses:

```python
event.file_path
```

This will fail at runtime.

The extractor should consistently use:

```python
event.caller_file
```

## 13. The LLM adapter is only a mock

`src/patchguard/infrastructure/llm.py` returns hard-coded patch data.

It does not currently:

- Call a real provider.
- Validate the response.
- Validate JSON.
- Enforce output size limits.
- Handle timeouts.
- Handle provider errors.
- Redact sensitive source or request data.

The mock is acceptable for early unit tests, but it cannot be considered a working remediation system.

## 14. The sandbox is not sufficiently isolated

`src/patchguard/infrastructure/sandbox.py` creates a temporary directory and runs pytest, but a temporary directory alone is not a security sandbox.

It still needs:

- Timeout enforcement.
- CPU limits.
- Memory limits.
- Network isolation.
- Environment-variable filtering.
- Filesystem restrictions.
- Subprocess cleanup.
- Output-size limits.
- Non-root execution.
- Protection from production secrets.

Generated code must be treated as untrusted.

## 15. GitHub adapter is incomplete

`src/patchguard/infrastructure/github.py` has several issues:

- Uses fields not defined by `PatchResult`.
- Method name does not match `RepositoryManagerPort`.
- Calls `build_pr_body()` but defines `_built_pr_body()`.
- Does not consistently update the patch result.
- Does not clearly prevent PR creation unless sandbox verification passed.
- Needs handling for authentication, permissions, rate limits, existing branches, and existing pull requests.

## 16. Tests are incomplete

Current unit tests cover some detector and firewall behavior:

- `tests/unit/test_detectors.py`
- `tests/unit/test_firewall.py`

The SQL detector tests currently fail.

Missing test coverage includes:

```text
Detector registry ordering
All detectors being evaluated
Enabled detector policy
Firewall latency warnings
Middleware 403 responses
Middleware pass-through responses
Queue behavior
Queue-full behavior
Runtime context extraction
Remediation orchestration
Sandbox success
Sandbox failure
GitHub pull-request creation
GitHub failure handling
```

---

# Exact roadmap

## Phase 1: Make the project installable

### Tasks

- Configure `pyproject.toml`.
- Add package discovery for `src/patchguard`.
- Add runtime dependencies.
- Add pytest configuration.
- Add a CLI entry point.
- Add a Python version requirement.

Expected commands:

```powershell
pip install -e .
pytest
patchguard policy
patchguard scan --payload "hello"
```

## Phase 2: Fix the request-time firewall

### Tasks

- Fix `sqlparse` token access in `src/patchguard/detection/sql.py`.
- Fix the registry return indentation in `src/patchguard/detection/registry.py`.
- Standardize `threat_type`.
- Enforce `SecurityPolicy.enabled_detectors`.
- Confirm strict blocking behavior.
- Confirm dry-run behavior.
- Add latency tests.

Expected flow:

```text
Request
    |
    v
Middleware
    |
    v
RequestPayload
    |
    v
FirewallEvaluator
    |
    v
DetectorRegistry
    |
    +--> Clean request: continue
    |
    +--> Threat: return event
```

## Phase 3: Complete middleware integration

### Tasks

- Add a queue dependency to the middleware.
- Enqueue every blocked `AttackEvent`.
- Return HTTP 403 immediately.
- Do not wait for remediation.
- Add application startup handling.
- Add application shutdown handling.
- Add FastAPI/Starlette integration tests.

Expected behavior:

```text
Threat detected
    |
    +--> Queue event
    |
    +--> Return 403
```

## Phase 4: Standardize domain contracts

### Tasks

Finalize these canonical names:

```python
RequestPayload
AttackEvent
DetectorRegistry
FirewallEvaluator
RemediationOrchestrator
PatchResult
```

Finalize `PatchResult` fields and update all adapters to use those exact names.

Recommended `PatchResult` fields:

```python
event_id: str
target_file: str
original_code: str
patched_code: str
exploit_test_code: str
benign_test_code: str
diff_summary: str
status: PatchStatus
verification_output: str
pr_url: Optional[str]
```

## Phase 5: Implement the remediation pipeline

Make the flow in `src/patchguard/application/remediation.py` exactly:

```text
AttackEvent
    |
    v
RuntimeContextExtractor
    |
    v
LLMRemediationEngine.synthesize_patch()
    |
    v
RegressionSandboxPort.run_verification()
    |
    +--> Failed: stop, do not create PR
    |
    +--> Passed: create GitHub PR
```

Use matching port methods:

```python
synthesize_patch()
run_verification()
create_patch_pull_request()
```

## Phase 6: Fix runtime context extraction

### Tasks

- Replace `event.file_path` with `event.caller_file`.
- Add a typed `RuntimeContext` model.
- Remove silent `except Exception: pass`.
- Return explicit extraction errors.
- Validate source file paths.
- Restrict extraction to approved repository paths.

## Phase 7: Make LLM remediation safe

### Tasks

- Add provider configuration.
- Load API keys from environment variables.
- Add request timeouts.
- Validate response JSON.
- Validate required response fields.
- Reject empty or oversized patches.
- Redact secrets.
- Prevent path traversal.
- Keep LLM calls outside the request path.

## Phase 8: Implement a real sandbox

### Tasks

- Apply generated code in an isolated workspace.
- Run exploit regression tests.
- Run benign behavior tests.
- Add timeouts.
- Restrict network access.
- Restrict filesystem access.
- Restrict environment variables.
- Limit resources.
- Capture stdout and stderr.
- Mark status as `SANDBOX_PASSED` or `SANDBOX_FAILED`.

Required safety rule:

```text
If sandbox verification fails:
    do not create a GitHub pull request
```

## Phase 9: Implement GitHub automation

### Tasks

- Align the GitHub adapter with `RepositoryManagerPort`.
- Create an isolated branch.
- Apply the patch.
- Add generated tests.
- Commit the changes.
- Open a pull request.
- Store the pull-request URL in `PatchResult`.
- Handle existing branches and pull requests.
- Handle authentication and rate-limit failures.
- Never merge automatically.

## Phase 10: Add complete tests

### Unit tests

```text
SQLDetector
PromptDetector
DetectorRegistry
SecurityPolicy
FirewallEvaluator
RuntimeContextExtractor
LLM response validation
Sandbox result handling
GitHub adapter
```

### Integration tests

```text
FastAPI middleware
Clean request flow
Blocked request flow
Dry-run flow
Queue worker
Remediation orchestration
Sandbox pass
Sandbox failure
GitHub pull-request creation with a mocked API
```

### End-to-end flow

Test this complete sequence:

```text
Malicious request
    |
    v
Middleware
    |
    v
AttackEvent
    |
    v
403 response
    |
    v
Queue
    |
    v
Runtime context
    |
    v
Generated patch
    |
    v
Sandbox verification
    |
    v
Mock GitHub pull request
```

---

# Definition of done

```text
[ ] pip install -e . works
[ ] pytest passes without PYTHONPATH changes
[ ] patchguard policy works
[ ] patchguard scan works
[ ] SQL injection detection works
[ ] Prompt injection detection works
[ ] All enabled detectors run
[ ] Disabled detectors do not run
[ ] Clean requests reach the application
[ ] Malicious requests receive HTTP 403
[ ] Threats are queued asynchronously
[ ] Queue worker starts and stops with the application
[ ] Runtime context is extracted correctly
[ ] LLM output is validated
[ ] Generated patches are sandboxed
[ ] Exploit tests pass
[ ] Benign tests pass
[ ] Failed patches do not create pull requests
[ ] Verified patches create pull requests
[ ] GitHub failures are handled safely
[ ] No secrets are logged
[ ] No generated code runs on the request path
[ ] Unit and integration tests pass
```

## Recommended immediate next step

Start with Phase 1 and Phase 2:

1. Configure packaging.
2. Fix the SQL detector.
3. Fix the detector registry loop.
4. Standardize the detector interface.
5. Enforce enabled detectors.
6. Get the existing test suite passing.

Only after the request-time firewall is stable should the asynchronous remediation system be implemented.
