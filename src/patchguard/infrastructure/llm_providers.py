import json
import os
import httpx
from google import genai
from openai import OpenAI
import logging

from google.genai import errors
from google.genai import types
from dataclasses import dataclass
from typing import Any, Mapping, Protocol

from patchguard.domain.models import AttackEvents

logger = logging.getLogger("patchguard.llm_providers")

def build_remediation_prompt(
    event: AttackEvents,
    context: Mapping[str, Any],
    previous_patch: str = "",
    failure_feedback: str = "",
) -> str:
    """Build the provider-independent remediation prompt."""

    revision_context = ""

    if previous_patch:
        revision_context += f"""
Previous patch attempt:
```python
{previous_patch}```
"""
        if failure_feedback:
            revision_context += f"""
Trusted test feedback:
{failure_feedback}

"""
    return f"""
You are PatchGuard AI, an automated security remediation agent.

A blocked runtime threat was detected with these details:

Threat type: {event.threat_type.value}
Rule ID: {event.rule_id}
Target file: {event.caller_file}
Target line: {event.line_number}
Payload snippet: {event.payload_snippet}
Vulnerable source function:
{context.get("function_source","")}
Full source context:
{context.get("full_source","")}
{revision_context}
Generate only a code patch that fixes the vulnerability.

Do not generate tests.
Do not decide whether the patch is safe.
Do not remove or weaken security checks.

Return valid JSON with exactly these keys:
{{
"fixed_code": "complete corrected source code",
"explanation": "short explanation of the correction"
}}
"""

@dataclass(frozen=True)
class ProviderPatchResponse:
    """Normalized patch response returned by every LLM provider."""

    fixed_code: str
    explanation: str
    provider_name: str


class ProviderAdapterError(RuntimeError):
    """Raised when an LLM provider cannot generate a valid patch."""


class LLMProviderAdapter(Protocol):
    """Common contract implemented by every remediation provider."""

    provider_name: str

    def generate_patch(
        self,
        event: AttackEvents,
        context: Mapping[str, Any],
        previous_patch: str = "",
        failure_feedback: str = "",
    ) -> ProviderPatchResponse:
        """Generate a normalized remediation patch."""
        ...

class GeminiProvider:
    """Gemini implementation of the common remediation provider contract."""

    provider_name = "gemini"

    def __init__(
        self,
        api_key: str | None = None,
        model_name: str = "gemini-2.5-flash",
    ) -> None:
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")
        self.model_name = model_name

        if not self.api_key:
            raise ProviderAdapterError(
                "GEMINI_API_KEY is not configured"
            )

        self.client = genai.Client(
            api_key=self.api_key,
            http_options=types.HttpOptions(
                timeout=10_000,
                retry_options=types.HttpRetryOptions(
                    attempts=1,
                    initial_delay=1.0,
                    max_delay=1.0,
                    exp_base=2.0,
                    jitter=0.0,
                ),
            ),
        )

    def generate_patch(
        self,
        event: AttackEvents,
        context: Mapping[str, Any],
        previous_patch: str = "",
        failure_feedback: str = "",
    ) -> ProviderPatchResponse:
        prompt = build_remediation_prompt(
            event=event,
            context=context,
            previous_patch=previous_patch,
            failure_feedback=failure_feedback,
        )

        try:
            response = self.client.models.generate_content(
                model=self.model_name,
                contents=prompt,
                config=types.GenerateContentConfig(
                    response_mime_type="application/json",
                    temperature=0.1,
                ),
            )

            payload = json.loads(response.text)
            fixed_code = payload.get("fixed_code")
            explanation = payload.get("explanation", "")

            if not isinstance(fixed_code, str) or not fixed_code.strip():
                raise ProviderAdapterError(
                    "Gemini response did not contain valid fixed_code"
                )

            if not isinstance(explanation, str):
                raise ProviderAdapterError(
                    "Gemini response contained an invalid explanation"
                )

            return ProviderPatchResponse(
                fixed_code=fixed_code,
                explanation=explanation,
                provider_name=self.provider_name,
            )

        except ProviderAdapterError:
            raise
        except (
            errors.APIError,
            httpx.TimeoutException,
            TimeoutError,
            json.JSONDecodeError,
        ) as exc:
            raise ProviderAdapterError(
                "Gemini failed to generate a remediation patch"
            ) from exc

class OpenAIProvider:
    """OpenAI implementation of the common remediation provider contract."""

    provider_name = "openai"

    def __init__(
        self,
        api_key: str | None = None,
        model_name: str = "gpt-4o-mini",
    ) -> None:
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        self.model_name = model_name

        if not self.api_key:
            raise ProviderAdapterError(
                "OPENAI_API_KEY is not configured"
            )

        self.client = OpenAI(
            api_key=self.api_key,
            timeout=10.0,
            max_retries=0,
        )

    def generate_patch(
        self,
        event: AttackEvents,
        context: Mapping[str, Any],
        previous_patch: str = "",
        failure_feedback: str = "",
    ) -> ProviderPatchResponse:
        prompt = build_remediation_prompt(
            event=event,
            context=context,
            previous_patch=previous_patch,
            failure_feedback=failure_feedback,
        )

        try:
            response = self.client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are PatchGuard AI. "
                            "Return only valid JSON."
                        ),
                    },
                    {
                        "role": "user",
                        "content": prompt,
                    },
                ],
                response_format={"type": "json_object"},
                temperature=0.1,
            )

            content = response.choices[0].message.content

            if not content:
                raise ProviderAdapterError(
                    "OpenAI returned an empty response"
                )

            payload = json.loads(content)
            fixed_code = payload.get("fixed_code")
            explanation = payload.get("explanation", "")

            if not isinstance(fixed_code, str) or not fixed_code.strip():
                raise ProviderAdapterError(
                    "OpenAI response did not contain valid fixed_code"
                )

            if not isinstance(explanation, str):
                raise ProviderAdapterError(
                    "OpenAI response contained an invalid explanation"
                )

            return ProviderPatchResponse(
                fixed_code=fixed_code,
                explanation=explanation,
                provider_name=self.provider_name,
            )

        except ProviderAdapterError:
            raise
        except (json.JSONDecodeError, TimeoutError) as exc:
            raise ProviderAdapterError(
                "OpenAI returned an invalid remediation response"
            ) from exc
        except Exception as exc:
            raise ProviderAdapterError(
                "OpenAI failed to generate a remediation patch"
            ) from exc



        

class LLMRemediationEngine:
    """Common coordinator for provider selection and fallback."""

    def __init__(
        self,
        providers: list[LLMProviderAdapter] | None = None,
    ) -> None:
        if providers is not None:
            self.providers = providers
            return

        self.providers: list[LLMProviderAdapter] = []

        for provider_factory in (GeminiProvider, OpenAIProvider):
            try:
                self.providers.append(provider_factory())
            except ProviderAdapterError as exc:
                logger.warning(
                    "Skipping unavailable remediation provider: %s",
                    exc,
                )

    def generate_patch(
        self,
        event: AttackEvents,
        context: Mapping[str, Any],
        previous_patch: str = "",
        failure_feedback: str = "",
    ) -> ProviderPatchResponse:
        last_error: Exception | None = None

        for provider in self.providers:
            try:
                return provider.generate_patch(
                    event=event,
                    context=context,
                    previous_patch=previous_patch,
                    failure_feedback=failure_feedback,
                )
            except ProviderAdapterError as exc:
                last_error = exc
                continue

        if last_error is not None:
            raise ProviderAdapterError(
                f"All remediation providers failed: {last_error}"
            )

        raise ProviderAdapterError(
            "No remediation providers are configured and available"
        )
    