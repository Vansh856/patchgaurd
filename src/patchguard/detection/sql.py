import sqlparse
from sqlparse.tokens import Keyword, DML
from typing import Optional
from patchguard.domain.models import RequestPayLoad, AttackEvents
from patchguard.detection.base import BaseDetector

class SQLDetector(BaseDetector):

    def threat_type(self) -> str:
        return "sql_injection"

    def detect(self, payload: RequestPayLoad) -> Optional[AttackEvents]:
        # Check for SQL keywords in the request body
        target_inputs=[]
        if payload.query_params:
            target_inputs.extend(payload.query_params.values())
        elif isinstance(payload.body, dict):
            target_inputs.extend(str(v) for v in payload.body.values())

        for input_str in target_inputs:
            if self.is_sql_injection(input_str):
                return self._create_attack_event(payload=payload, rule_id="SQLT_AST_001", payload_snippet=input_str[:100],)  # Limit snippet length to 100 characters
        return None



    def is_sql_injection(self, text: str) -> bool:

        if not text or not isinstance(text, str):
            return False

        prased = sqlparse.parse(text)

        if not prased:
            return False


        for statement in prased:

            if len(prased) > 1:
                return True

            tokens = [token for token in statement.tokens if not token.is_whitespace]

            has_union=any(t.type is Keyword and t.value.upper() == "UNION" for t in tokens)
            has_select=any(t.type is DML and t.value.upper() == "SELECT" for t in tokens)
            clean_text=text.replace(" ","").lower()
            has_tautology= "1==1" in clean_text or "'1'='1'" in clean_text or "or1=1" in clean_text


            if (has_union and has_select) or has_tautology:
                return True
            return False
