from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route

from patchguard.interfaces.starlette_metadata import get_endpoint_metadata


async def application_endpoint(request):
    return PlainTextResponse("ok")


def test_get_endpoint_metadata_for_basic_route():
    app = Starlette(
        routes=[
            Route(
                "/test",
                application_endpoint,
                methods=["POST"],
            )
        ]
    )
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/test",
        "root_path": "",
    }

    metadata = get_endpoint_metadata(app, scope)

    assert metadata["caller_file"].endswith("test_starlette_metadata.py")
    assert metadata["caller_function"] == "application_endpoint"
    assert isinstance(metadata["caller_line"], int)


def test_get_endpoint_metadata_returns_empty_for_unmatched_route():
    app = Starlette(
        routes=[Route("/test", application_endpoint, methods=["POST"])]
    )
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/missing",
        "root_path": "",
    }

    metadata = get_endpoint_metadata(app, scope)

    assert metadata == {
        "caller_file": None,
        "caller_function": None,
        "caller_line": None,
    }
