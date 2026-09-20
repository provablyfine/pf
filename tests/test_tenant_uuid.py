import requests

ROOT_UUID = "00000000-0000-0000-0000-000000000001"
UNKNOWN_UUID = "9f1c0a1e-3b0d-4a55-8f7e-2d6c1b7a4e10"


def _get(api, tenant: str, path: str) -> requests.Response:
    return requests.get(f"http://127.0.0.1:{api.port}/pf/t/{tenant}/{path}", timeout=5)


def test_directory_reports_tenant_name(api) -> None:
    response = _get(api, ROOT_UUID, "directory")
    assert response.status_code == 200
    body = response.json()
    assert body["name"] == "root"
    assert f"/pf/t/{ROOT_UUID}/" in body["ping"]


def test_tenant_names_are_not_addressable(api) -> None:
    by_name = _get(api, "root", "directory")
    assert by_name.status_code == 404
    unknown = _get(api, UNKNOWN_UUID, "directory")
    assert unknown.status_code == 404
    assert by_name.json() == unknown.json()


def test_existing_and_unknown_tenants_answer_the_same_on_every_unauthenticated_endpoint(api) -> None:
    # An uninitialized tenant must not be distinguishable from a missing one without its UUID.
    for name in ("root", "acme", "admin"):
        response = requests.post(f"http://127.0.0.1:{api.port}/pf/t/{name}/initialize", timeout=5)
        assert response.status_code == 404
