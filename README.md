# PatchGuard

## Autonomous Runtime Defense and Auto-Remediation Engine

PatchGuard is a modular Python security middleware and DevSecOps agent for protecting web applications and AI-backed APIs from runtime attacks.

It is designed to connect three concerns that are usually separated:

1. Detect suspicious input in the application process.
2. Block the request immediately without placing an LLM call on the request path.
3. Capture runtime context and prepare a test-verified code-fix pull request asynchronously.

The project blueprint focuses on FastAPI and Flask applications, SQL injection, prompt injection, runtime context capture, sandbox verification, and GitHub pull-request automation.

> **Current status:** The repository currently contains the modular project structure and documentation foundation. Implementation will be added behind the interfaces described below.

## Why PatchGuard?

Traditional security tools often stop at detection:

- A network WAF can block an attack but usually cannot identify the vulnerable application code path.
- A static analyzer can report a code weakness but does not see the live exploit context.
- Manual remediation leaves a gap between the security alert and a verified code change.

PatchGuard is intended to close that loop by combining in-process detection with runtime evidence and an isolated remediation workflow.

## Core Workflow

```text
Incoming request
	|
	v
PatchGuard middleware
	|
	+--> Clean input --------> Application controller
	|
	+--> Exploit detected ---> Immediate 403 response
				  |
				  v
			  Async remediation queue
				  |
				  v
		      Runtime context extraction
				  |
				  v
		      Patch and test synthesis
				  |
				  v
			  Sandbox verification
				  |
		   Tests pass? --+-- No --> Stop
				  |
				  v
		      Verified GitHub pull request
```

The request path should remain deterministic and lightweight. LLM calls, sandbox execution, and GitHub operations belong to background workers.

## Security Scope

The initial design targets:

- SQL injection and unsafe query construction.
- Prompt injection in AI and RAG application inputs.
- AI tool or agent input poisoning.
- Runtime evidence collection for the vulnerable route, file, function, AST node, and payload.
- Regression verification with both malicious and benign inputs.

Detection is not a substitute for parameterized queries, output encoding, authorization, isolation, or secure application design. PatchGuard is intended as a defense-in-depth layer.

## Modular Architecture

```text
src/patchguard/
├── domain/
│   ├── models.py          # Security events and immutable domain values
│   ├── policy.py          # Detection and remediation policy
│   └── ports.py           # Interfaces for external capabilities
├── detection/
│   ├── base.py            # Detector contract
│   ├── sql.py             # SQL injection detector
│   ├── prompt.py          # Prompt injection detector
│   └── registry.py        # Detector composition and dispatch
├── application/
│   ├── firewall.py        # Synchronous request decision service
│   └── remediation.py     # Asynchronous remediation orchestration
├── infrastructure/
│   ├── runtime.py         # Stack and runtime context extraction
│   ├── queue.py           # Background job delivery
│   ├── llm.py             # Patch and test synthesis adapter
│   ├── sandbox.py         # Isolated regression execution
│   └── github.py          # Branch, commit, and pull-request adapter
└── interfaces/
    ├── middleware.py      # Web framework integration
    ├── factory.py         # Application composition root
    └── cli.py             # Command-line entry point
```

The domain layer should not depend on FastAPI, Flask, GitHub, a specific LLM provider, or a database. Infrastructure implementations are connected through ports, which keeps the detection path testable and replaceable.

## Remediation Safety Model

PatchGuard should never merge generated code directly into production or the default branch. A remediation job must:

1. Create an isolated working branch.
2. Generate a proposed patch and regression tests.
3. Run the tests in a restricted sandbox.
4. Confirm that the exploit is rejected.
5. Confirm that a representative benign request still succeeds.
6. Open a pull request with the diff and verification result.
7. Leave final review and merge approval to the repository’s normal controls.

If sandbox verification fails, the pull request must not be created.

## Project Layout

```text
patchgaurd/
├── docs/                 # Architecture and operations documentation
├── src/patchguard/       # Application package
├── tests/unit/           # Fast isolated component tests
├── tests/integration/    # Framework and adapter integration tests
├── Makefile              # Project command entry points
├── pyproject.toml        # Python packaging and tooling configuration
└── .env.example          # Environment variable template
```

## Planned Integrations

The modular structure leaves room for optional adapters rather than making external services mandatory:

- FastAPI and Starlette middleware.
- Flask middleware.
- An LLM provider for patch and test synthesis.
- A local or containerized sandbox runner.
- GitHub pull requests through the GitHub API.
- In-memory queues for development and durable queues for production.

## Development Principles

- Keep request-time inspection deterministic and dependency-light.
- Keep remediation asynchronous and isolated from the request thread.
- Treat every generated patch as untrusted until tests pass.
- Prefer explicit ports and adapters over provider-specific logic in the domain.
- Preserve auditability through security events, test output, and pull-request metadata.
- Fail closed when detection or policy evaluation cannot safely complete.

## Roadmap

- Define domain models and detector contracts.
- Implement SQL and prompt-injection detectors with unit coverage.
- Add framework middleware for FastAPI/Starlette and Flask.
- Add runtime context extraction and background queue processing.
- Add sandbox verification with exploit and benign regression tests.
- Add GitHub pull-request orchestration and operational controls.
- Add benchmarks for request-path latency and detector accuracy.

## License

No license has been selected for this project yet.
