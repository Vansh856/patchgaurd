import json
import logging
from typing import Any, Dict

from patchguard.domain.models import AttackEvents,PatchResult,PatchStatus
from patchguard.domain.ports import RemediationEnginePort


logger = logging.getLogger("patchguard.llm")


class LLMRemediationEngine(RemediationEnginePort):


    def __init__(self, api_key: str="mock-key",model_name:str="gemini-2.5-flash")->None:
        """
        Initializes the LLMRemediationEngine with the provided API key and model name.

        Args:
            api_key (str): The API key for accessing the LLM service. Default is "mock-key".
            model_name (str): The name of the LLM model to use. Default is "gemini-2.5-flash".
        returns:
            None
        """
        self.api_key = api_key
        self.model_name = model_name


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
            incident_id=event.event_id,
            status=PatchStatus.SYNTHESIZED,
            target_file=event.caller_file,
            fixed_code=response.get("fixed_code", ""),
            exploit_test_code=response.get("exploit_test", ""),
            benign_test_code=response.get("benign_test", ""),
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
            {context.get("function\_source", "")}
            INSTRUCTIONS:

                1. Rewrite the vulnerable function to eliminate the security risk (e.g. use parameterized query binding or sanitize prompt templates).
                2. Generate a Pytest test case `test_exploit()` that reproduces the malicious payload attempt and verifies it is safely handled.
                3. Generate a Pytest test case `test_benign()` that verifies legitimate non-malicious user requests continue to function normally.

            Return your response strictly as JSON with keys: "fixed\_code", "exploit\_test", "benign\_test". 
            """


    def _call_llm_provider(self,prompt:str)->Dict[str, str]:
        """
        Calls the LLM provider with the given prompt and returns the response.

        Args:
            prompt (str): The prompt to send to the LLM provider.

        Returns:
            Dict[str, str]: The response from the LLM provider, parsed as a dictionary.
        """


        return {
            "fixed_code":"#Auto-generated parameterized fix by PatchGuard AI\n",
            "exploit_test": "def test_exploit():\n     Test payload is neutralized\n     pass\n",
            "benign_test": "def test_benign():\n     Test normal traffic passes\n     pass\n"
        }