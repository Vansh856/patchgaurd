import inspect
from typing import Any, Optional

from starlette.routing import Match


def get_endpoint_metadata(
    app: Any,
    scope: dict[str, Any],
) -> dict[str, Optional[Any]]:
    """Return source metadata for a basic Starlette function route."""

    for route in getattr(app, "routes", ()):
        match, child_scope = route.matches(scope)
        if match is not Match.FULL:
            continue

        endpoint = child_scope.get("endpoint")
        if endpoint is None or not callable(endpoint):
            return _empty_metadata()

        endpoint = inspect.unwrap(endpoint)

        try:
            caller_file = inspect.getsourcefile(endpoint)
            caller_line = inspect.getsourcelines(endpoint)[1]
        except (OSError, TypeError):
            return _empty_metadata()

        if not caller_file:
            return _empty_metadata()

        return {
            "caller_file": caller_file,
            "caller_function": getattr(
                endpoint,
                "__name__",
                endpoint.__class__.__name__,
            ),
            "caller_line": caller_line,
        }

    return _empty_metadata()


def _empty_metadata() -> dict[str, Optional[Any]]:
    return {
        "caller_file": None,
        "caller_function": None,
        "caller_line": None,
    }
