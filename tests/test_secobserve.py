import pytest
import responses
from responses import matchers

from trivy_secobserve.secobserve import SecObserveClient, SecObserveError

API = "http://secobserve.test/api"


@pytest.fixture
def client():
    return SecObserveClient(API, "secret-token")


@responses.activate
def test_auth_header_and_exact_name_match(client):
    responses.get(
        f"{API}/products/",
        json={"next": None, "results": [{"id": 1, "name": "Shop Prod Old"}, {"id": 2, "name": "Shop Prod"}]},
        match=[matchers.header_matcher({"Authorization": "APIToken secret-token"})],
    )
    assert client.get_product("Shop Prod")["id"] == 2
    assert client.get_product("Shop Prod")["id"] == 2  # cached
    assert len(responses.calls) == 1


@responses.activate
def test_ensure_product_creates_in_group(client):
    responses.get(f"{API}/products/", json={"next": None, "results": []})
    responses.get(f"{API}/product_groups/", json={"next": None, "results": [{"id": 7, "name": "Pimcore"}]})
    create = responses.post(
        f"{API}/products/",
        json={"id": 11, "name": "Shop Prod"},
        match=[matchers.json_params_matcher({"name": "Shop Prod", "product_group": 7}, strict_match=False)],
    )
    assert client.ensure_product("Shop Prod", "Pimcore")["id"] == 11
    assert create.call_count == 1


@responses.activate
def test_ensure_product_missing_group_fails(client):
    responses.get(f"{API}/products/", json={"next": None, "results": []})
    responses.get(f"{API}/product_groups/", json={"next": None, "results": []})
    with pytest.raises(SecObserveError, match="Product group"):
        client.ensure_product("Shop Prod", "Nope")


@responses.activate
def test_ensure_product_without_auto_create(client):
    responses.get(f"{API}/products/", json={"next": None, "results": []})
    with pytest.raises(SecObserveError, match="AUTO_CREATE"):
        client.ensure_product("Shop Prod", auto_create=False)


@responses.activate
def test_upload_sends_multipart_fields(client):
    upload = responses.post(f"{API}/import/file_upload_observations_by_name/", json={"observations_new": 3})
    result = client.upload_observations(
        product_name="Shop Prod",
        file_name="trivy-operator_c_app.cdx.json",
        content=b'{"bomFormat": "CycloneDX"}',
        service="app",
        docker_image_name_tag="r/app:1",
        kubernetes_cluster="c",
        kubernetes_namespace="ns",
    )
    assert result == {"observations_new": 3}
    body = upload.calls[0].request.body
    for expected in (
        b'name="product_name"',
        b"Shop Prod",
        b'name="service"',
        b'filename="trivy-operator_c_app.cdx.json"',
        b'name="kubernetes_namespace"',
        b'name="docker_image_name_tag"',
    ):
        assert expected in body
    assert b'name="branch_name"' not in body  # empty fields are not sent


@responses.activate
def test_pagination_keeps_configured_base_url(client):
    responses.get(
        f"{API}/vulnerability_checks/",
        match=[matchers.query_param_matcher({"filename": "trivy-operator_", "page_size": "100"})],
        json={
            "next": "http://internal-host:5000/api/vulnerability_checks/?filename=trivy-operator_&page=2",
            "results": [{"id": 1}],
        },
    )
    responses.get(
        f"{API}/vulnerability_checks/",
        match=[matchers.query_param_matcher({"filename": "trivy-operator_", "page": "2"})],
        json={"next": None, "results": [{"id": 2}]},
    )
    assert [c["id"] for c in client.list_vulnerability_checks("trivy-operator_")] == [1, 2]


@responses.activate
def test_http_errors_raise(client):
    responses.post(f"{API}/import/file_upload_observations_by_name/", status=400, json={"message": "bad"})
    with pytest.raises(SecObserveError, match="HTTP 400"):
        client.upload_observations(product_name="p", file_name="f", content=b"{}")
