import sqlparse
from sqlparse.tokens import  DML,DDL,Keyword

from patchguard.domain.models import RequestPayload, AttackEvents,ThreatType
from patchguard.detection.base import BaseDetector

class SQLDetector(BaseDetector):

    @property
    def threat_type(self) -> ThreatType:
        return ThreatType.SQL_INJECTION


    def detect(self, payload: RequestPayload) -> AttackEvents|None:
        """
        Detects SQL injection attempts in the given payload.

        Args:
            payload (RequestPayload): The request payload to inspect.

        Returns:
            AttackEvents|None: The detected attack event, or None if no attack is detected.
        """

        target_inputs=[]
        if payload.query_params:
            target_inputs.extend(str(v) for v in payload.query_params.values())


        if isinstance(payload.body,dict):
            target_inputs.extend(str(v) for v in payload.body.values())

        elif isinstance(payload.body,str):
            target_inputs.append(payload.body)

        for input_str in target_inputs:

            if self.is_sql_injection(input_str):
                return self._create_attack_event(
                    payload=payload,
                    rule_id="SQLi-AST-001",
                    payload_snippet=input_str[:100],
                )
        return None