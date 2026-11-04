"""Summarize what the operator produced in SecObserve (for the e2e test).

usage: SECOBSERVE_API_URL=... SECOBSERVE_API_TOKEN=... python hack/minikube/check_secobserve.py [PRODUCT_PREFIX...]
"""

from __future__ import annotations

import collections
import json
import os
import sys

import requests

API = os.environ["SECOBSERVE_API_URL"].rstrip("/")
S = requests.Session()
S.headers["Authorization"] = f"APIToken {os.environ['SECOBSERVE_API_TOKEN']}"


def get_all(path: str, **params):
    params = {"page_size": 1000, **params}
    page = 1
    while True:
        data = S.get(f"{API}/{path}", params={**params, "page": page}, timeout=120).json()
        yield from data.get("results", [])
        if not data.get("next"):
            return
        page += 1


def main() -> None:
    prefixes = sys.argv[1:] or ["E2E ", "node-app"]
    products = [p for p in get_all("products/") if any(p["name"].startswith(x) for x in prefixes)]
    checks = list(get_all("vulnerability_checks/", filename="trivy-operator_"))
    summary = {}
    for product in sorted(products, key=lambda p: p["name"]):
        obs = list(get_all("observations/", product=product["id"]))
        lic = list(get_all("license_components/", product=product["id"]))
        by_service = collections.defaultdict(collections.Counter)
        for o in obs:
            by_service[o.get("origin_service_name") or "-"][o["current_status"]] += 1
        product_checks = [c for c in checks if c["product"] == product["id"]]
        # the list endpoint omits origin_component_dependencies -> sample the detail endpoint
        sample = obs[:: max(1, len(obs) // 15)][:15]
        with_deps = sum(
            1
            for o in sample
            if S.get(f"{API}/observations/{o['id']}/", timeout=60).json().get("origin_component_dependencies")
        )
        summary[product["name"]] = {
            "group": product.get("product_group_name"),
            "observations": dict(collections.Counter(o["current_status"] for o in obs)),
            "by_service": {k: dict(v) for k, v in sorted(by_service.items())},
            "images": sorted(
                {o.get("origin_docker_image_name_tag_short") or "" for o in obs if o["current_status"] == "Open"}
            ),
            "sample_with_dependency_path": f"{with_deps}/{len(sample)}",
            "licenses": dict(collections.Counter(c["evaluation_result"] for c in lic)),
            "checks": sorted(
                f"{c.get('branch_name') or '-'} | {c.get('service_name')} | {c['filename']}" for c in product_checks
            ),
        }
    print(json.dumps(summary, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
