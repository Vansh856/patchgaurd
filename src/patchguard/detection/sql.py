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

        # Extract potential input sources from the payload
        if payload.query_params:
            target_inputs.extend(str(v) for v in payload.query_params.values())

        # Extract potential input sources from the request body
        if isinstance(payload.body,dict):
            target_inputs.extend(str(v) for v in payload.body.values())

        # If the body is a string, add it directly to the target inputs
        elif isinstance(payload.body,str):
            target_inputs.append(payload.body)


        # Check each input for SQL injection patterns
        for input_str in target_inputs:


            # Check for SQL injection patterns using the is_sql_injection method
            if self.is_sql_injection(input_str):
                return AttackEvents(
                    threat_type=self.threat_type,
                    rule_id="SQLi-AST-001",
                    payload_snippet=input_str[:100],
                    caller_file="unknown",
                    caller_function="unknown",
                    line_number=0
                )

        return None



    def is_sql_injection(self, text: str)-> bool:
        """
        Determines if the given text contains SQL injection patterns.

        Args:
            text (str): The text to inspect.

        Returns:
            bool: True if SQL injection patterns are detected, False otherwise.
            """


        # Check for common SQL injection patterns in the text
        if not text or not isinstance(text, str):
            return False

        clean_text = text.replace(" ", "").lower()



    # Check for more complex SQL injection patterns
        if "1==1" in clean_text or "'1'='1'" in clean_text or "or1=1" in clean_text:
            return True

        try:
            parsed = sqlparse.parse(text) # Parse the SQL query

            if not parsed:
                return False

            if len(parsed) > 1: # If there are multiple statements
                return True

            for statement in parsed: # Check each statement for SQL injection patterns

                tokens=[t for t in statement.tokens if not t.is_whitespace]

                # Check for UNION and SELECT keywords
                has_union=any(t.ttype is Keyword and t.value.upper() is "UNION" for t in tokens)

                has_select=any(
                    (t.ttype in (DML,DDL) or t.ttype is Keyword) 
                    and t.value.upper() is "SELECT" for t in tokens
                )

                if has_union or (has_union and has_select):
                    return True

        except Exception as e:
            pass

        return False