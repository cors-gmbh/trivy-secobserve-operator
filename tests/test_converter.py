import json

import pytest
from factories import ROOT_REF, sbom_report, vulnerability_report

from trivy_secobserve.converter import combine, empty_bom, merge


def _vuln(bom, vulnerability_id):
    return next(v for v in bom["vulnerabilities"] if v["id"] == vulnerability_id)


def _component(bom, ref):
    return next(c for c in bom["components"] if c["bom-ref"] == ref)


def test_merge_joins_vulnerabilities_to_sbom_components():
    bom, stats = merge(vulnerability_report(), sbom_report())

    assert stats.sbom_used is True
    assert stats.vulnerabilities == 5
    assert (stats.matched_exact, stats.matched_fuzzy, stats.unmatched) == (3, 1, 1)

    assert _vuln(bom, "CVE-2026-0001")["affects"] == [
        {"ref": "pkg:apk/alpine/openssl@3.3.2-r0?arch=x86_64&distro=3.21.3"}
    ]
    assert _vuln(bom, "CVE-2026-0002")["affects"] == [{"ref": "pkg:composer/twig/twig@v3.8.0"}]
    assert _vuln(bom, "CVE-2026-0003")["affects"] == [{"ref": "pkg:golang/stdlib@v1.13.4"}]
    # qualifier-only difference still lands on the SBOM component
    assert _vuln(bom, "CVE-2026-0004")["affects"] == [
        {"ref": "pkg:apk/alpine/openssl@3.3.2-r0?arch=x86_64&distro=3.21.3"}
    ]


def test_dependency_graph_and_licenses_are_kept():
    bom, _ = merge(vulnerability_report(), sbom_report())
    deps = {d["ref"]: d["dependsOn"] for d in bom["dependencies"]}
    assert deps["app-geoip"] == ["geoip-module"]
    assert deps["geoip-module"] == ["pkg:golang/stdlib@v1.13.4"]
    assert _component(bom, "pkg:composer/twig/twig@v3.8.0")["licenses"] == [{"license": {"name": "BSD-3-Clause"}}]


def test_unmatched_vulnerability_gets_synthetic_component_below_root():
    bom, _ = merge(vulnerability_report(), sbom_report())
    ref = _vuln(bom, "GHSA-xxxx-yyyy-zzzz")["affects"][0]["ref"]
    component = _component(bom, ref)
    assert component["name"] == "left-pad"
    assert component["version"] == "1.0.0"
    assert component["purl"] == "pkg:npm/left-pad@1.0.0"
    root_dependency = next(d for d in bom["dependencies"] if d["ref"] == ROOT_REF)
    assert ref in root_dependency["dependsOn"]


def test_root_component_is_container_with_tag_as_version():
    bom, _ = merge(vulnerability_report(), sbom_report())
    root = bom["metadata"]["component"]
    assert root["bom-ref"] == ROOT_REF  # unchanged, the dependency graph points to it
    assert root["type"] == "container"
    assert root["name"] == "registry.example.com/demo/app"
    assert root["version"] == "1.0.0"
    assert bom["metadata"]["tools"]["components"][0]["name"] == "trivy"


def test_ratings_description_recommendation_advisories():
    bom, _ = merge(vulnerability_report(), sbom_report())
    critical = _vuln(bom, "CVE-2026-0001")
    assert critical["description"] == "openssl: remote code execution"
    assert {"severity": "critical", "score": 9.8, "method": "CVSSv31", "vector": ""} in critical["ratings"]
    assert critical["recommendation"] == "Upgrade openssl from 3.3.2-r0 to 3.3.3-r0"
    assert [a["url"] for a in critical["advisories"]] == [
        "https://avd.aquasec.com/nvd/cve-2026-0001",
        "https://example.com/advisory/1",
    ]
    assert critical["published"] == "2026-01-01T00:00:00Z"

    low = _vuln(bom, "CVE-2026-0004")
    assert low["description"] == "CVE-2026-0004"  # SecObserve needs a description
    assert low["ratings"] == [{"source": {"name": "trivy"}, "severity": "low", "method": "other"}]
    assert "recommendation" not in low

    unknown = _vuln(bom, "GHSA-xxxx-yyyy-zzzz")
    assert all(r["method"] == "other" for r in unknown["ratings"])  # score 0 is no score


def test_vulnerability_bom_refs_are_unique():
    bom, _ = merge(vulnerability_report(), sbom_report())
    refs = [v["bom-ref"] for v in bom["vulnerabilities"]]
    assert len(refs) == len(set(refs))


def test_merge_without_sbom_builds_minimal_bom():
    bom, stats = merge(vulnerability_report(), None)
    assert stats.sbom_used is False
    assert stats.unmatched == 5
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["serialNumber"].startswith("urn:uuid:")
    assert bom["metadata"]["component"]["name"] == "registry.example.com/demo/app"
    assert {c["name"] for c in bom["components"]} == {"openssl", "twig/twig", "stdlib", "left-pad"}
    json.dumps(bom)  # serializable


def test_sbom_without_vulnerability_report():
    bom, stats = merge(None, sbom_report())
    assert stats.vulnerabilities == 0
    assert bom["vulnerabilities"] == []
    assert len(bom["components"]) == 7


def test_input_is_not_modified():
    sbom = sbom_report()
    before = json.dumps(sbom, sort_keys=True)
    merge(vulnerability_report(), sbom)
    assert json.dumps(sbom, sort_keys=True) == before


def test_requires_some_input():
    with pytest.raises(ValueError):
        merge(None, None)


def test_empty_bom_has_no_findings():
    bom = empty_bom()
    assert bom["components"] == [] and bom["vulnerabilities"] == []


def _extra_vulnerability(vulnerability_id="CVE-2026-9999"):
    vulnerabilities = vulnerability_report()["report"]["vulnerabilities"]
    return [*vulnerabilities, {**vulnerabilities[0], "vulnerabilityID": vulnerability_id}]


def test_combine_two_images_of_one_service():
    fpm = merge(vulnerability_report(tag="8.1-fpm"), sbom_report(tag="8.1-fpm"))
    cli_sbom = sbom_report(tag="8.1-cli", digest="sha256:cli")
    cli_root_ref = "pkg:oci/app@sha256%3Acli"
    cli_sbom["report"]["components"]["metadata"]["component"]["bom-ref"] = cli_root_ref
    cli_sbom["report"]["components"]["dependencies"][0]["ref"] = cli_root_ref
    cli = merge(
        vulnerability_report(tag="8.1-cli", digest="sha256:cli", vulnerabilities=_extra_vulnerability()), cli_sbom
    )

    bom, stats = combine([fpm, cli])

    assert bom["metadata"]["component"]["version"] == "8.1-fpm"  # primary image
    # the other image's root is a component, so its packages keep a dependency path to their own image
    assert _component(bom, cli_root_ref)["version"] == "8.1-cli"
    assert next(d for d in bom["dependencies"] if d["ref"] == cli_root_ref)["dependsOn"]
    # shared packages and their vulnerabilities once, the cli-only vulnerability added
    assert len(bom["components"]) == len(fpm[0]["components"]) + 1
    assert stats.vulnerabilities == len(fpm[0]["vulnerabilities"]) + 1
    assert _vuln(bom, "CVE-2026-9999")
    refs = [v["bom-ref"] for v in bom["vulnerabilities"]]
    assert len(refs) == len(set(refs))
    images = next(p["value"] for p in bom["metadata"]["properties"] if p["name"] == "trivy-secobserve:images")
    assert images == "registry.example.com/demo/app:8.1-fpm, registry.example.com/demo/app:8.1-cli"
    assert stats.sbom_used


def test_combine_single_part_is_unchanged():
    bom, stats = merge(vulnerability_report(), sbom_report())
    combined, combined_stats = combine([(bom, stats)])
    assert combined == bom and combined_stats == stats
    assert combined is not bom


def test_combine_counts_shared_vulnerabilities_once():
    one = merge(vulnerability_report(), sbom_report())
    other = merge(vulnerability_report(tag="2.0.0", digest="sha256:bbb"), sbom_report(tag="2.0.0", digest="sha256:bbb"))
    _, stats = combine([one, other])
    assert stats.vulnerabilities == one[1].vulnerabilities
    assert stats.matched_exact + stats.matched_fuzzy + stats.unmatched == stats.vulnerabilities
    assert stats.unmatched == one[1].unmatched
