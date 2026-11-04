"""Synthetic Trivy Operator reports, shaped like the real ones (trivy-operator 0.2x / Trivy 0.60)."""

from __future__ import annotations

import copy
from typing import Any

ROOT_REF = "pkg:oci/app@sha256%3Aaaa?repository_url=registry.example.com%2Fdemo%2Fapp"


def _labels(kind: str, name: str, container: str, namespace: str) -> dict[str, str]:
    return {
        "trivy-operator.container.name": container,
        "trivy-operator.resource.kind": kind,
        "trivy-operator.resource.name": name,
        "trivy-operator.resource.namespace": namespace,
    }


def sbom_report(
    namespace: str = "shop-prod",
    name: str = "replicaset-app-7d9f-app",
    repository: str = "demo/app",
    tag: str = "1.0.0",
    digest: str = "sha256:aaa",
    resource: tuple[str, str] = ("ReplicaSet", "app-7d9f"),
    container: str = "app",
) -> dict[str, Any]:
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:11111111-2222-3333-4444-555555555555",
        "version": 1,
        "metadata": {
            "component": {"bom-ref": ROOT_REF, "type": "container", "name": f"registry.example.com/{repository}:{tag}"},
            "tools": {
                "components": [{"type": "application", "group": "aquasecurity", "name": "trivy", "version": "0.60.0"}]
            },
            "timestamp": "2026-11-03T10:00:00Z",
        },
        "components": [
            {"bom-ref": "os-1", "type": "operating-system", "name": "alpine", "version": "3.21.3"},
            {
                "bom-ref": "pkg:apk/alpine/openssl@3.3.2-r0?arch=x86_64&distro=3.21.3",
                "type": "library",
                "name": "openssl",
                "version": "3.3.2-r0",
                "purl": "pkg:apk/alpine/openssl@3.3.2-r0?arch=x86_64&distro=3.21.3",
                "licenses": [{"license": {"id": "Apache-2.0"}}],
            },
            {"bom-ref": "app-composer", "type": "application", "name": "var/www/html/vendor/composer/installed.json"},
            {
                "bom-ref": "pkg:composer/twig/twig@v3.8.0",
                "type": "library",
                "name": "twig/twig",
                "version": "v3.8.0",
                "purl": "pkg:composer/twig/twig@v3.8.0",
                "licenses": [{"license": {"name": "BSD-3-Clause"}}],
            },
            {"bom-ref": "app-geoip", "type": "application", "name": "var/www/html/vendor/x/geoipupdate"},
            {
                "bom-ref": "geoip-module",
                "type": "library",
                "name": "github.com/maxmind/geoipupdate",
                "purl": "pkg:golang/github.com/maxmind/geoipupdate",
            },
            {
                "bom-ref": "pkg:golang/stdlib@v1.13.4",
                "type": "library",
                "name": "stdlib",
                "version": "v1.13.4",
                "purl": "pkg:golang/stdlib@v1.13.4",
            },
        ],
        "dependencies": [
            {"ref": ROOT_REF, "dependsOn": ["os-1", "app-composer", "app-geoip"]},
            {"ref": "os-1", "dependsOn": ["pkg:apk/alpine/openssl@3.3.2-r0?arch=x86_64&distro=3.21.3"]},
            {"ref": "app-composer", "dependsOn": ["pkg:composer/twig/twig@v3.8.0"]},
            {"ref": "app-geoip", "dependsOn": ["geoip-module"]},
            {"ref": "geoip-module", "dependsOn": ["pkg:golang/stdlib@v1.13.4"]},
        ],
    }
    return {
        "apiVersion": "aquasecurity.github.io/v1alpha1",
        "kind": "SbomReport",
        "metadata": {"name": name, "namespace": namespace, "labels": _labels(*resource, container, namespace)},
        "report": {
            "artifact": {"repository": repository, "tag": tag, "digest": digest},
            "registry": {"server": "registry.example.com"},
            "scanner": {"name": "Trivy", "vendor": "Aqua Security", "version": "0.60.0"},
            "updateTimestamp": "2026-11-03T10:00:00Z",
            "components": bom,
        },
    }


def vulnerability_report(
    namespace: str = "shop-prod",
    name: str = "replicaset-app-7d9f-app",
    repository: str = "demo/app",
    tag: str = "1.0.0",
    digest: str = "sha256:aaa",
    update_ts: str = "2026-11-03T10:00:00Z",
    resource: tuple[str, str] = ("ReplicaSet", "app-7d9f"),
    container: str = "app",
    vulnerabilities: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    if vulnerabilities is None:
        vulnerabilities = default_vulnerabilities()
    return {
        "apiVersion": "aquasecurity.github.io/v1alpha1",
        "kind": "VulnerabilityReport",
        "metadata": {"name": name, "namespace": namespace, "labels": _labels(*resource, container, namespace)},
        "report": {
            "artifact": {"repository": repository, "tag": tag, "digest": digest},
            "registry": {"server": "registry.example.com"},
            "scanner": {"name": "Trivy", "vendor": "Aqua Security", "version": "0.60.0"},
            "updateTimestamp": update_ts,
            "summary": {},
            "vulnerabilities": copy.deepcopy(vulnerabilities),
        },
    }


def default_vulnerabilities() -> list[dict[str, Any]]:
    return [
        {  # exact purl match, OS package
            "vulnerabilityID": "CVE-2026-0001",
            "resource": "openssl",
            "installedVersion": "3.3.2-r0",
            "fixedVersion": "3.3.3-r0",
            "packagePURL": "pkg:apk/alpine/openssl@3.3.2-r0?arch=x86_64&distro=3.21.3",
            "severity": "CRITICAL",
            "score": 9.8,
            "title": "openssl: remote code execution",
            "primaryLink": "https://avd.aquasec.com/nvd/cve-2026-0001",
            "links": ["https://example.com/advisory/1"],
            "publishedDate": "2026-01-01T00:00:00Z",
            "lastModifiedDate": "2026-01-02T00:00:00Z",
            "target": "",
        },
        {  # exact purl match, composer package
            "vulnerabilityID": "CVE-2026-0002",
            "resource": "twig/twig",
            "installedVersion": "v3.8.0",
            "fixedVersion": "3.27.0",
            "packagePURL": "pkg:composer/twig/twig@v3.8.0",
            "severity": "HIGH",
            "score": 8.1,
            "title": "twig: sandbox escape",
            "primaryLink": "https://avd.aquasec.com/nvd/cve-2026-0002",
            "links": [],
            "target": "var/www/html/vendor/composer/installed.json",
        },
        {  # Go stdlib below a vendored binary: needs the dependency graph
            "vulnerabilityID": "CVE-2026-0003",
            "resource": "stdlib",
            "installedVersion": "v1.13.4",
            "fixedVersion": "1.22.1",
            "packagePURL": "pkg:golang/stdlib@v1.13.4",
            "severity": "MEDIUM",
            "score": 5.3,
            "title": "golang: net/http issue",
            "primaryLink": "",
            "links": [],
            "target": "var/www/html/vendor/x/geoipupdate",
        },
        {  # purl only differs in qualifiers -> fuzzy match
            "vulnerabilityID": "CVE-2026-0004",
            "resource": "openssl",
            "installedVersion": "3.3.2-r0",
            "fixedVersion": "",
            "packagePURL": "pkg:apk/alpine/openssl@3.3.2-r0?arch=aarch64",
            "severity": "LOW",
            "score": None,
            "title": "",
            "primaryLink": "",
            "links": [],
        },
        {  # not in the SBOM at all -> synthetic component
            "vulnerabilityID": "GHSA-xxxx-yyyy-zzzz",
            "resource": "left-pad",
            "installedVersion": "1.0.0",
            "fixedVersion": "1.3.0",
            "packagePURL": "pkg:npm/left-pad@1.0.0",
            "severity": "UNKNOWN",
            "score": 0,
            "title": "left-pad: something",
            "primaryLink": "https://github.com/advisories/GHSA-xxxx-yyyy-zzzz",
            "links": [],
        },
    ]
