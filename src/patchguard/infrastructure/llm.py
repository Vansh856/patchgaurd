import json
import logging
from typing import Any, Dict
import os
from google import genai
from google.genai import types
import httpx
from google.genai import errors

from patchguard.domain.models import AttackEvents,PatchResult,PatchStatus
from patchguard.domain.ports import RemediationEnginePort


logger = logging.getLogger("patchguard.llm")

class LLMProviderError(RuntimeError):
    """Custom exception for LLM provider errors."""
    pass


class LLMRemediationEngine(RemediationEnginePort):


    def __init__(self, api_key: str="mock-key",model_name:str="gemini-3.8-flash")->None:
        """
        Initializes the LLMRemediationEngine with the provided API key and model name.

        Args:
            api_key (str): The API key for accessing the LLM service. Default is "mock-key".
            model_name (str): The name of the LLM model to use. Default is "gemini-2.5-flash".
        returns:
            None
        """
        self.api_key = os.getenv("GEMINI_API_KEY") or api_key
        self.model_name = model_name

        if self.api_key == "mock-key":
            self.client = None
        else:
            self.client = genai.Client(
                api_key=self.api_key,
                http_options=types.HttpOptions(
                    timeout=10_000,
                    retry_options=types.HttpRetryOptions(
                        attempts=3,
                        initial_delay=1.0,
                        max_delay=4.0,
                        exp_base=2.0,
                        jitter=0.2,
                    ),
                ),
            )
        


    def synthesize_patch(self,event: AttackEvents,context: Dict[str, Any])->PatchResult:
        """
        Synthesizes a patch for the given attack event using the provided context.

        Args:
            event (AttackEvents): The attack event for which to synthesize a patch.
            context (Dict[str, Any]): The context information related to the attack event.

        Returns:
            PatchResult: The result of the patch synthesis, including the original code, patched code, test suite code, and other relevant information.
        """

        logger.info(f"Synthesizing patch for rule {event.rule_id} in {event.caller_file}...")

        prompt = self._built_remediation_prompt(event, context)
        response = self._call_llm_provider(prompt)

        return PatchResult(
            target_file=event.caller_file,
            event_id=event.event_id,
            branch_name=f"patchguard/fix-{event.event_id[:8]}",
            original_code=context.get("full_source", ""),
            patched_code=response.get("fixed_code", ""),
            test_suite_code=(
                response.get("exploit_test", "")
                + "\n"
                + response.get("benign_test", "")
            ),
            sandbox_passed=False,
            diff_summary="Patch generated and awaiting sandbox verification",
            
        )




    def _built_remediation_prompt(self,event: AttackEvents,context: Dict[str, Any])->str:
        """
        Builds the prompt for the LLM to synthesize a patch based on the attack event and context.

        Args:
            event (AttackEvents): The attack event for which to build the prompt.
            context (Dict[str, Any]): The context information related to the attack event.

        Returns:
            str: The constructed prompt for the LLM.
        """

        return f"""
            You are PatchGuard AI, an expert automated security remediation agent. 
            A runtime threat was intercepted by PatchGuard Middleware: 
                - Threat Type: {event.threat_type.value} 
                - Rule ID: {event.rule_id} 
                - Target File: {event.caller_file} 
                - Target Line: {event.line_number} 
                - Vulnerable Payload Snippet: {event.payload_snippet} 
            Vulnerable Source Function: 
            ```python 
            {context.get("function_source", "")}
            INSTRUCTIONS:

                1. Rewrite the vulnerable function to eliminate the security risk (e.g. use parameterized query binding or sanitize prompt templates).
                2. Generate a Pytest test case `test_exploit()` that reproduces the malicious payload attempt and verifies it is safely handled.
                3. Generate a Pytest test case `test_benign()` that verifies legitimate non-malicious user requests continue to function normally.

            Return your response strictly as JSON with keys: "fixed_code", "exploit_test", "benign_test". 
            """


    def _call_llm_provider(self,prompt:str)->Dict[str, str]:
        """
        Calls the LLM provider with the given prompt and returns the response.

        Args:
            prompt (str): The prompt to send to the LLM provider.

        Returns:
            Dict[str, str]: The response from the LLM provider, parsed as a dictionary.
        """
        try:
            response = self.client.models.generate_content(
                model=self.model_name,
                contents=prompt,
                config=types.GenerateContentConfig(
                    response_mime_type="application/json",
                    temperature=0.1,
                ),
            )

            return json.loads(response.text)

        except (errors.APIError, httpx.TimeoutException, TimeoutError, json.JSONDecodeError) as exc:
            logger.exception("Gemini remediation request failed: %s", exc)
            raise LLMProviderError("Gemini remediation request failed") from exc


        