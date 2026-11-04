"""Minimal SecObserve REST API client (only what the operator needs)."""

from __future__ import annotations

import logging
from collections.abc import Iterator
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)


class SecObserveError(Exception):
    pass


class SecObserveClient:
    def __init__(
        self,
        api_url: str,
        token: str,
        verify_ssl: bool = True,
        timeout: int = 300,
        session: requests.Session | None = None,
    ) -> None:
        self.api_url = api_url.rstrip("/")
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.session = session or requests.Session()
        self.session.headers.update({"Authorization": f"APIToken {token}", "Accept": "application/json"})
        # Retries for idempotent reads only; uploads are retried by the worker with backoff.
        adapter = HTTPAdapter(
            max_retries=Retry(
                total=3,
                backoff_factor=2,
                status_forcelist=(502, 503, 504),
                allowed_methods=frozenset({"GET"}),
            )
        )
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        self._product_cache: dict[str, dict[str, Any]] = {}
        self._product_name_by_id: dict[int, str] = {}

    # --- low level -------------------------------------------------------------------------------------------

    def _url(self, path: str) -> str:
        return f"{self.api_url}/{path.lstrip('/')}"

    def _request(self, method: str, path_or_url: str, **kwargs: Any) -> requests.Response:
        url = path_or_url if path_or_url.startswith("http") else self._url(path_or_url)
        response = self.session.request(method, url, verify=self.verify_ssl, timeout=self.timeout, **kwargs)
        if response.status_code >= 400:
            raise SecObserveError(f"{method} {url} -> HTTP {response.status_code}: {response.text[:500]}")
        return response

    def _paginate(self, path: str, params: dict[str, Any]) -> Iterator[dict[str, Any]]:
        params = {"page_size": 100, **params}
        response = self._request("GET", path, params=params)
        while True:
            data = response.json()
            yield from data.get("results", [])
            next_url = data.get("next")
            if not next_url:
                return
            # The backend builds `next` from its own view of the host; keep our base URL instead.
            query = next_url.split("?", 1)[1] if "?" in next_url else ""
            response = self._request("GET", f"{self._url(path)}?{query}")

    def _find_by_exact_name(self, path: str, name: str) -> dict[str, Any] | None:
        # The `name` filter of SecObserve is "icontains", so filter for the exact name on our side.
        for item in self._paginate(path, {"name": name}):
            if item.get("name") == name:
                return item
        return None

    # --- products --------------------------------------------------------------------------------------------

    def get_product(self, name: str) -> dict[str, Any] | None:
        if name in self._product_cache:
            return self._product_cache[name]
        product = self._find_by_exact_name("products/", name)
        if product:
            self._product_cache[name] = product
            self._product_name_by_id[product["id"]] = name
        return product

    def get_product_name(self, product_id: int) -> str:
        if product_id not in self._product_name_by_id:
            product = self._request("GET", f"products/{product_id}/").json()
            self._product_name_by_id[product_id] = product["name"]
        return self._product_name_by_id[product_id]

    def get_product_group(self, name: str) -> dict[str, Any] | None:
        return self._find_by_exact_name("product_groups/", name)

    def ensure_product(self, name: str, product_group: str = "", auto_create: bool = True) -> dict[str, Any]:
        product = self.get_product(name)
        if product:
            return product
        if not auto_create:
            raise SecObserveError(f"Product '{name}' does not exist and PRODUCT_AUTO_CREATE is disabled")

        payload: dict[str, Any] = {
            "name": name,
            "description": "Created automatically by trivy-secobserve-operator.",
        }
        if product_group:
            group = self.get_product_group(product_group)
            if not group:
                raise SecObserveError(f"Product group '{product_group}' does not exist")
            payload["product_group"] = group["id"]

        try:
            product = self._request("POST", "products/", json=payload).json()
            logger.info("Created SecObserve product '%s' (group '%s')", name, product_group or "-")
        except SecObserveError:
            # Created concurrently by someone else?
            product = self._find_by_exact_name("products/", name)
            if not product:
                raise
        self._product_cache[name] = product
        self._product_name_by_id[product["id"]] = name
        return product

    # --- imports ---------------------------------------------------------------------------------------------

    def upload_observations(
        self,
        product_name: str,
        file_name: str,
        content: bytes,
        branch_name: str = "",
        service: str = "",
        docker_image_name_tag: str = "",
        kubernetes_cluster: str = "",
        kubernetes_namespace: str = "",
        suppress_licenses: bool = False,
    ) -> dict[str, Any]:
        data = {
            "product_name": product_name,
            "branch_name": branch_name,
            "service": service,
            "docker_image_name_tag": docker_image_name_tag,
            "kubernetes_cluster": kubernetes_cluster,
            "kubernetes_namespace": kubernetes_namespace,
        }
        data = {key: value for key, value in data.items() if value}
        if suppress_licenses:
            data["suppress_licenses"] = "true"
        files = {"file": (file_name, content, "application/json")}
        return self._request("POST", "import/file_upload_observations_by_name/", data=data, files=files).json()

    def list_vulnerability_checks(self, filename_contains: str) -> Iterator[dict[str, Any]]:
        yield from self._paginate("vulnerability_checks/", {"filename": filename_contains})
