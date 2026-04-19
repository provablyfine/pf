import fastapi

from .. import responses


router = fastapi.APIRouter(prefix="/debug")


@router.get("/trigger-error", include_in_schema=False)
def trigger_error_endpoint() -> fastapi.responses.Response:
    raise RuntimeError("Triggered for testing")


@router.get("/{debug_id}")
def debug_endpoint(debug_id: str, request: fastapi.requests.Request) -> fastapi.responses.Response:
    data = request.app.state.debug_store.get(debug_id)
    data = request.app.state.debug_store.get(debug_id)
    if data is None:
        return responses.problem_response(
            status_code=404, title="Debug data could not be found", detail=f"Missing {debug_id}"
        )
    return fastapi.responses.JSONResponse(status_code=200, content=data)
