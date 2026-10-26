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

        targets=[]

        # Extract potential input sources from the payload
        if payload.query_params:
            targets.extend(str(v) for v in payload.query_params.values())

        # Extract potential input sources from the request body
        if isinstance(payload.body,dict):
            targets.extend(str(v) for v in payload.body.values())

        # If the body is a string, add it directly to the target inputs
        elif isinstance(payload.body,str):
            targets.append(payload.body)


        # Check each input for SQL injection patterns
        for target in targets:

            if not target or not isinstance(target,str):
                continue

            event = self._inspect_sql_tokens(target, payload)
            if event is not None:
                return event

        return None



    def _inspect_sql_tokens(self, input_str: str,payload: RequestPayload)-> AttackEvents|None:
        """
        Inspects the SQL tokens in the input string for potential SQL injection patterns.

        Args:
            input_str (str): The input string to inspect.
            payload (RequestPayload): The request payload associated with the input.

        Returns:
            AttackEvents|None: The detected attack event, or None if no attack is detected.
        """

        lower_input = input_str.lower()

        if any(t in lower_input for t in ["or 1=1","or 1==1","or '1'='1'","or 'a'=='a'"]):

            return self._create_attack_event(
                payload=payload, 
                rule_id="SQLi-TAUTOLOGY-001", 
                payload_snippet=input_str[:100]
            )
        try:
            parsed=sqlparse.parse(input_str)


            for statement in parsed:

                for token in statement.tokens:

                    if token.ttype in (DML,DDL) or (token.ttype == Keyword and token.value.upper() in ("UNION","SELECT","DROP","UPDATE","DELETE")):

                        return self._create_attack_event(
                        payload=payload,
                        rule_id="SQLi-KEYWORD-002",
                        payload_snippet=input_str[:100],
                    )
        except Exception:
            pass

        return None
