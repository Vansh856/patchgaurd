import json # it is used to parse the request body into a JSON object
from typing import Callable,Awaitable 
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from patchguard.application.firewall import FirewallEvaluator
from patchguard.domain.models import RequestPayload
from patchguard.infrastructure.queue import AsyncIncidentQueue
from patchguard.interfaces.starlette_metadata import get_endpoint_metadata



class PatchGuardMiddleware(BaseHTTPMiddleware):
    """
    A middleware for integrating PatchGuard's security features into a Starlette application.
    """



    def __init__(self, app, evaluator: FirewallEvaluator,incident_queue: AsyncIncidentQueue | None = None, remediation_handler=None):
        super().__init__(app)
        self.evaluator = evaluator
        self.incident_queue = incident_queue
        self.remediation_handler = remediation_handler




    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]])-> Response:

        """
        1. The dispatch method is the core of the middleware, responsible for processing each incoming HTTP request.
        2. It extracts the request method, path, headers, query parameters, and body, constructs a RequestPayload object, and passes it to the FirewallEvaluator for security evaluation.
        3. If a threat is detected and block_mode is enabled, it returns a 403 Forbidden response with details about the detected threat; otherwise, it allows the request to proceed to the next middleware or route handler.
        4. The method also handles the parsing of the request body, supporting both JSON and    non-JSON payloads, and ensures that the evaluation process is efficient and does not introduce significant latency to the request processing.
        """

        query_params = dict(request.query_params)
        headers = dict(request.headers)


        body_bytes = await request.body()
        body_str= body_bytes.decode("utf-8", errors="ignore")

        try:
            body_obj = json.loads(body_str) if body_str else None # parse the request body into a JSON object if it is not empty; otherwise, set it to None
        except Exception: # If JSON parsing fails, keep the body as a string
            body_obj = body_str

        endpoint_metadata = get_endpoint_metadata(self.app, request.scope)

        payload = RequestPayload(
            method=request.method,
            path=request.url.path,
            headers=headers,
            query_params=query_params,
            body=body_obj,
            client_ip=request.client.host if request.client else "unknown",
            caller_file=endpoint_metadata["caller_file"],
            caller_function=endpoint_metadata["caller_function"],
            caller_line=endpoint_metadata["caller_line"],
        ) # construct a RequestPayload object with the extracted request details, including method, path, headers, query parameters, body, and client IP address


        attack_event = self.evaluator.evaluate(payload) # checks for any attack events

        if attack_event:
            if self.incident_queue is not None:
                if self.remediation_handler is not None:
                    self.incident_queue.start_worker(self.remediation_handler)
                self.incident_queue.enqueue(attack_event)
            return JSONResponse(
                status_code=403,
                content={
                    "error": "Request blocked by PatchGuard",
                    "details": "Request blocked by PatchGuard Autonomous Security Engine",
                    "threat_type": attack_event.threat_type.value,
                    "rule_id": attack_event.rule_id
                },
            )



        return await call_next(request) # await the next middleware or route handler in the chain, allowing the request to proceed if no threat is detected