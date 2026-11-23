import copy
import dataclasses
import json
from pathlib import Path

import pytest
import responses
from factories import sbom_report, vulnerability_report
from test_processor import SETTINGS, Clock, FakeClient, FakeSource, feed

from trivy_secobserve.converter import add_php_advisories, merge
from trivy_secobserve.php_advisories import (
    NVD_API_URL,
    PhpAdvisoryFeed,
    VersionRange,
    _ranges,
    advisory_from_nvd,
    parse_version,
    php_version_of,
)
from trivy_secobserve.processor import Processor
from trivy_secobserve.storage import LocalStorage

# Real NVD API 2.0 records of the CNA php.net (trimmed: fewer references, other vendors' products dropped)
NVD = json.loads((Path(__file__).parent / "fixtures" / "nvd_php.json").read_text())
PHP_REF = "pkg:bitnami/php@8.3.36"


def _cve(cve_id):
    return next(v["cve"] for v in NVD["vulnerabilities"] if v["cve"]["id"] == cve_id)


def _feed(records=None):
    feed = PhpAdvisoryFeed()
    advisories = [advisory_from_nvd(r) for r in (records or [v["cve"] for v in NVD["vulnerabilities"]])]
    feed.advisories, feed.loaded = tuple(a for a in advisories if a), True
    return feed


def _php_sbom(version="8.3.36", qualifiers=""):
    report = sbom_report()
    purl = f"pkg:bitnami/php@{version}{qualifiers}"
    report["report"]["components"]["components"].append(
        {"bom-ref": purl, "type": "application", "name": "php", "version": version, "purl": purl}
    )
    return report


# --- version ranges ------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("entry", "inside", "outside"),
    [
        ({"version": "8.3.0", "lessThan": "8.3.37", "status": "affected"}, ["8.3.0", "8.3.36"], ["8.2.99", "8.3.37"]),
        ({"version": "0", "lessThan": "8.2.36", "status": "affected"}, ["7.4.33", "8.1.34", "8.2.35"], ["8.2.36"]),
        ({"version": "8.3.*", "lessThan": "8.3.36", "status": "affected"}, ["8.3.0", "8.3.35"], ["8.2.30", "8.3.36"]),
        ({"version": "8.1.x", "lessThan": "8.1.30", "status": "affected"}, ["8.1.29"], ["8.0.30", "8.1.30"]),
        ({"version": "8.1.X", "lessThan": "8.1.33*", "status": "affected"}, ["8.1.32"], ["8.1.33"]),
        ({"version": "8.1.0", "lessThanOrEqual": "8.1.34", "status": "affected"}, ["8.1.34"], ["8.1.35"]),
        ({"version": "7.3.x below 7.3.8", "status": "affected"}, ["7.3.7"], ["7.3.8", "7.2.1"]),
    ],
)
def test_range_shapes_php_net_used(entry, inside, outside):
    ranges = _ranges(entry)
    assert ranges
    for version in inside:
        assert any(r.contains(parse_version(version)) for r in ranges), version
    for version in outside:
        assert not any(r.contains(parse_version(version)) for r in ranges), version


def test_free_text_with_several_branches():
    ranges = _ranges({"version": "7.1.x below 7.1.31 and 7.2.x below 7.2.21", "status": "affected"})
    assert ranges == [VersionRange((7, 1), (7, 1, 31)), VersionRange((7, 2), (7, 2, 21))]


@pytest.mark.parametrize(
    "entry",
    [
        {"version": "7.1.30", "status": "affected"},  # the fixed version, written as affected (CVE-2019-11039)
        {"version": "8.3.0", "lessThan": "8.3.37", "status": "unaffected"},
        {"version": "0", "lessThan": "*", "status": "affected"},
        {"version": "n/a", "status": "affected"},
    ],
)
def test_entries_that_say_nothing_usable(entry):
    assert _ranges(entry) == []


def test_parse_version():
    assert parse_version("8.3.36") == (8, 3, 36)
    assert parse_version("8.5.0RC1") == (8, 5, 0)
    assert parse_version("") is None
    assert php_version_of({"purl": "pkg:bitnami/php@8.1.34?backport=CVE-2026-109618%2CCVE-2026-109619"}) == (8, 1, 34)
    assert php_version_of({"purl": "pkg:bitnami/blackfire-php@2026.11.0"}) is None
    assert php_version_of({"purl": "pkg:apk/alpine/php83@8.3.36-r0"}) is None


# --- NVD records ---------------------------------------------------------------------------------------------


def test_fresh_record_uses_the_ranges_php_net_published():
    """CVE-2026-115560 is 'Awaiting Analysis': no CPE configurations yet, only php.net's own data."""
    advisory = advisory_from_nvd(_cve("CVE-2026-115560"))
    assert advisory.affects((8, 3, 36)) and advisory.affects((8, 1, 34)) and advisory.affects((8, 5, 12))
    assert not advisory.affects((8, 3, 37)) and not advisory.affects((8, 4, 28))
    assert advisory.fixed_for((8, 3, 36)) == "8.3.37"
    assert advisory.ratings[0].method == "CVSSv4"
    assert advisory.ratings[0].severity == "critical"
    assert advisory.ratings[0].score == 9.2
    assert advisory.description.startswith("Session serializer mismatch")


def test_analysed_record_adds_the_nvd_ranges():
    """php.net lists CVE-2026-109618 for 8.2 and newer only, the NVD's analysis also for 8.1 (end of life)."""
    advisory = advisory_from_nvd(_cve("CVE-2026-109618"))
    assert advisory.affects((8, 1, 34))
    assert advisory.affects((8, 3, 35))
    assert not advisory.affects((8, 3, 36))


def test_wrong_cna_versions_are_covered_by_the_nvd_ranges():
    advisory = advisory_from_nvd(_cve("CVE-2019-11039"))
    assert advisory.affects((7, 1, 29))
    assert not advisory.affects((7, 1, 30))  # php.net wrote the fixed version as affected


def test_other_products_of_php_net_are_ignored():
    assert advisory_from_nvd(_cve("CVE-2019-11037")) is None  # PHP Imagick extension


@responses.activate
def test_refresh_pages_and_reports_changes():
    first = {**NVD, "totalResults": 5, "vulnerabilities": NVD["vulnerabilities"][:3]}
    second = {**NVD, "totalResults": 5, "startIndex": 3, "vulnerabilities": NVD["vulnerabilities"][3:]}
    responses.get(NVD_API_URL, json=first)
    responses.get(NVD_API_URL, json=second)
    feed = PhpAdvisoryFeed(api_key="secret")
    assert feed.refresh() is True
    assert feed.loaded
    assert [a.id for a in feed.advisories] == ["CVE-2019-11039", "CVE-2019-11041", "CVE-2026-109618", "CVE-2026-115560"]
    assert "sourceIdentifier=security%40php.net" in responses.calls[0].request.url
    assert "startIndex=3" in responses.calls[1].request.url
    assert responses.calls[0].request.headers["apiKey"] == "secret"

    responses.get(NVD_API_URL, json=NVD)
    assert feed.refresh() is False  # same records


@responses.activate
def test_refresh_error_keeps_the_previous_advisories():
    feed = _feed()
    before = feed.advisories
    responses.get(NVD_API_URL, status=404)
    with pytest.raises(Exception):  # noqa: B017
        feed.refresh()
    assert feed.advisories == before and feed.loaded
    assert "404" in feed.last_error


# --- converter -----------------------------------------------------------------------------------------------


def test_adds_php_cves_to_the_php_component():
    bom, _ = merge(vulnerability_report(), _php_sbom())
    signatures = add_php_advisories(bom, _feed())

    assert signatures == {"8.3.36": ("CVE-2026-115560",)}
    entry = next(v for v in bom["vulnerabilities"] if v["id"] == "CVE-2026-115560")
    assert entry["affects"] == [{"ref": PHP_REF}]
    assert entry["recommendation"] == "Upgrade php from 8.3.36 to 8.3.37"
    assert entry["ratings"][0]["method"] == "CVSSv4"
    assert entry["ratings"][0]["vector"].startswith("CVSS:4.0/")
    assert entry["advisories"][0] == {"url": "https://nvd.nist.gov/vuln/detail/CVE-2026-115560"}
    assert len(bom["vulnerabilities"]) == 6  # 5 from Trivy
    assert [v["bom-ref"] for v in bom["vulnerabilities"]] == [f"trivy-operator-vuln-{i}" for i in range(6)]


def test_cves_trivy_reports_already_are_not_added_twice():
    trivy = {
        "vulnerabilityID": "CVE-2026-115560",
        "resource": "php",
        "installedVersion": "8.3.36",
        "fixedVersion": "8.3.37",
        "packagePURL": PHP_REF,
        "severity": "CRITICAL",
    }
    bom, _ = merge(vulnerability_report(vulnerabilities=[trivy]), _php_sbom())
    add_php_advisories(bom, _feed())
    assert [v["id"] for v in bom["vulnerabilities"]] == ["CVE-2026-115560"]
    assert bom["vulnerabilities"][0]["ratings"][0]["source"] == {"name": "trivy"}


def test_backported_cves_are_reported_like_trivy_does():
    """pimcore-docker records backports in the purl; a SecObserve rule on the purl marks them, as for Trivy."""
    bom, _ = merge(vulnerability_report(vulnerabilities=[]), _php_sbom("8.1.34", "?backport=CVE-2026-109618"))
    add_php_advisories(bom, _feed())
    assert sorted(v["id"] for v in bom["vulnerabilities"]) == ["CVE-2026-109618", "CVE-2026-115560"]


def test_images_without_php_are_unchanged():
    bom, _ = merge(vulnerability_report(), sbom_report())
    before = copy.deepcopy(bom)
    assert add_php_advisories(bom, _feed()) == {}
    assert bom == before


# --- processor -----------------------------------------------------------------------------------------------


def _other_service():
    """A second service without PHP."""
    args = {"name": "replicaset-other-5f6c-other", "repository": "demo/other", "resource": ("ReplicaSet", "other-5f6c")}
    return vulnerability_report(**args), sbom_report(**args)


@pytest.fixture
def php_env(tmp_path):
    clock, source, client = Clock(), FakeSource(), FakeClient()
    settings = dataclasses.replace(SETTINGS, local_storage_dir=str(tmp_path), php_advisories_startup_wait_seconds=300)
    php_feed = PhpAdvisoryFeed()
    processor = Processor(settings, client, LocalStorage(str(tmp_path)), source, clock=clock, php_feed=php_feed)
    return processor, source, client, clock, php_feed


def test_upload_contains_the_php_cves(php_env):
    processor, source, client, clock, php_feed = php_env
    php_feed.advisories, php_feed.loaded = _feed().advisories, True
    feed(processor, source, vulnerability_report(), _php_sbom())
    assert [r.status for r in processor.run_once()] == ["uploaded"]
    assert "CVE-2026-115560" in [v["id"] for v in client.uploads[0]["bom"]["vulnerabilities"]]
    assert processor.snapshot()[0]["php_versions"] == ["8.3.36"]


def test_services_with_php_wait_for_the_first_load(php_env):
    processor, source, client, clock, php_feed = php_env
    feed(processor, source, vulnerability_report(), _php_sbom())
    feed(processor, source, *_other_service())
    results = processor.run_once()
    # the service without PHP goes right away
    assert sorted((r.target.service, r.status) for r in results) == [("app", "postponed"), ("other", "uploaded")]

    clock.now += 301  # NVD not reachable for too long: upload without
    assert [r.status for r in processor.run_once()] == ["uploaded"]
    assert "CVE-2026-115560" not in [v["id"] for v in client.uploads[-1]["bom"]["vulnerabilities"]]


def test_new_php_cves_upload_the_affected_services_again(php_env):
    processor, source, client, clock, php_feed = php_env
    without_new = [_cve("CVE-2026-109618")]
    php_feed.advisories, php_feed.loaded = _feed(without_new).advisories, True
    feed(processor, source, vulnerability_report(), _php_sbom())
    feed(processor, source, *_other_service())
    processor.run_once()
    assert len(client.uploads) == 2
    assert processor.php_advisories_changed() == []  # nothing new

    php_feed.advisories = _feed().advisories  # CVE-2026-115560 published
    assert [key[2] for key in processor.php_advisories_changed()] == ["app"]
    clock.now += 1  # well within MIN_RESYNC_SECONDS
    assert [r.target.service for r in processor.run_once()] == ["app"]
    assert "CVE-2026-115560" in [v["id"] for v in client.uploads[-1]["bom"]["vulnerabilities"]]
