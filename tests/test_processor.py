import dataclasses
import json
import re

import pytest
from factories import sbom_report, vulnerability_report

from trivy_secobserve.config import Settings
from trivy_secobserve.processor import Processor
from trivy_secobserve.secobserve import SecObserveError
from trivy_secobserve.storage import LocalStorage

SETTINGS = Settings(
    secobserve_api_url="http://secobserve.test/api",
    secobserve_api_token="token",
    cluster_name="test",
    min_resync_seconds=3600,
    sbom_wait_seconds=60,
    reconcile_enabled=True,
    reconcile_grace_seconds=600,
)


class Clock:
    def __init__(self):
        self.now = 1_000_000.0

    def __call__(self):
        return self.now


class FakeSource:
    def __init__(self):
        self.vrs, self.sboms = {}, {}
        self.ns = {}

    def add(self, vr, sbom=None):
        key = (vr["metadata"]["namespace"], vr["metadata"]["name"])
        self.vrs[key] = vr
        if sbom:
            self.sboms[key] = sbom

    def get_vulnerability_report(self, namespace, name):
        return self.vrs.get((namespace, name))

    def get_sbom_report(self, namespace, name):
        return self.sboms.get((namespace, name))

    def get_namespace_meta(self, namespace):
        return self.ns.get(namespace, ({}, {}))


class FakeClient:
    def __init__(self):
        self.uploads = []
        self.products = {}
        self.fail = 0
        self.checks = []

    def ensure_product(self, name, product_group="", auto_create=True):
        self.products.setdefault(name, {"id": len(self.products) + 1, "name": name, "group": product_group})
        return self.products[name]

    def upload_observations(self, **kwargs):
        if self.fail:
            self.fail -= 1
            raise SecObserveError("HTTP 503")
        kwargs["bom"] = json.loads(kwargs.pop("content"))
        self.uploads.append(kwargs)
        return {"observations_new": len(kwargs["bom"]["vulnerabilities"])}

    def list_vulnerability_checks(self, filename_contains):
        return [c for c in self.checks if filename_contains in c["filename"]]

    def get_product_name(self, product_id):
        return next(p["name"] for p in self.products.values() if p["id"] == product_id)


@pytest.fixture
def env(tmp_path):
    clock, source, client = Clock(), FakeSource(), FakeClient()
    settings = dataclasses.replace(SETTINGS, local_storage_dir=str(tmp_path))
    processor = Processor(settings, client, LocalStorage(str(tmp_path)), source, clock=clock)
    return processor, source, client, clock, tmp_path


def feed(processor, source, vr, sbom=None):
    source.add(vr, sbom)
    processor.observe_vulnerability_report("ADDED", vr)
    if sbom:
        processor.observe_sbom_report("ADDED", sbom)


def test_upload_with_sbom_and_storage(env):
    processor, source, client, clock, tmp_path = env
    feed(processor, source, vulnerability_report(), sbom_report())
    results = processor.run_once()

    assert [r.status for r in results] == ["uploaded"]
    upload = client.uploads[0]
    assert upload["product_name"] == "shop-prod"
    assert upload["service"] == "app"
    assert upload["file_name"] == "trivy-operator_test_app.cdx.json"
    assert upload["docker_image_name_tag"] == "registry.example.com/demo/app:1.0.0"
    assert upload["kubernetes_cluster"] == "test"
    assert upload["kubernetes_namespace"] == "shop-prod"
    assert len(upload["bom"]["vulnerabilities"]) == 5
    stored = list(tmp_path.rglob("*.cdx.json"))
    assert len(stored) == 1
    assert re.search(r"test/shop-prod/app/sha256-aaa/20261103T100000Z-[0-9a-f]{12}\.cdx\.json$", str(stored[0]))
    assert processor.run_once() == []  # nothing left to do


def test_archive_is_append_only(env, tmp_path):
    """Restart: same scan -> same object, nothing written. Late SBOM: a second object, the first one stays."""
    processor, source, client, clock, archive = env
    feed(processor, source, vulnerability_report())
    clock.now += 61
    processor.run_once()  # without SBOM
    first = sorted(archive.rglob("*.cdx.json"))
    assert len(first) == 1
    first_content = first[0].read_bytes()

    sbom = sbom_report()
    source.sboms[("shop-prod", "replicaset-app-7d9f-app")] = sbom
    processor.observe_sbom_report("ADDED", sbom)
    processor.run_once()  # with SBOM: different content, new object
    second = sorted(archive.rglob("*.cdx.json"))
    assert len(second) == 2 and first[0] in second
    assert first[0].read_bytes() == first_content  # not overwritten

    # operator restart: everything is uploaded again, but the archive does not change
    restarted = Processor(processor.settings, client, processor.storage, source, clock=clock)
    feed(restarted, source, vulnerability_report(), sbom)
    restarted.run_once()
    assert len(client.uploads) == 3
    assert sorted(archive.rglob("*.cdx.json")) == second


def test_broken_archive_does_not_block_the_upload(env):
    processor, source, client, clock, _ = env

    class BrokenStorage:
        def store(self, path, data):
            raise PermissionError("403 storage.objects.create denied")

    processor.storage = BrokenStorage()
    feed(processor, source, vulnerability_report(), sbom_report())
    assert [r.status for r in processor.run_once()] == ["uploaded"]
    assert len(client.uploads) == 1
    assert "403" in processor.snapshot()[0]["last_archive_error"]


def test_same_image_in_several_workloads_is_uploaded_once(env):
    processor, source, client, clock, _ = env
    for i in range(7):  # e.g. 7 CronJobs with the same php-cli image
        name = f"cronjob-job-{i}-job"
        feed(
            processor,
            source,
            vulnerability_report(name=name, resource=("CronJob", f"job-{i}")),
            sbom_report(name=name, resource=("CronJob", f"job-{i}")),
        )
    processor.run_once()
    assert len(client.uploads) == 1
    assert len(processor.snapshot()[0]["refs"]) == 7


def test_waits_for_sbom_then_falls_back_to_vulnerability_report_only(env):
    processor, source, client, clock, _ = env
    feed(processor, source, vulnerability_report())
    assert [r.status for r in processor.run_once()] == ["postponed"]
    assert processor.run_once() == []  # not due yet
    clock.now += 61
    assert [r.status for r in processor.run_once()] == ["uploaded"]
    assert client.uploads[0]["bom"]["components"]  # synthetic components


def test_late_sbom_forces_reupload_with_full_graph(env):
    processor, source, client, clock, _ = env
    feed(processor, source, vulnerability_report())
    clock.now += 61
    processor.run_once()
    sbom = sbom_report()
    source.sboms[("shop-prod", "replicaset-app-7d9f-app")] = sbom
    processor.observe_sbom_report("ADDED", sbom)
    processor.run_once()
    assert len(client.uploads) == 2
    assert len(client.uploads[1]["bom"]["dependencies"]) >= 5


def test_failed_upload_is_retried_with_backoff(env):
    processor, source, client, clock, _ = env
    client.fail = 2
    feed(processor, source, vulnerability_report(), sbom_report())
    assert [r.status for r in processor.run_once()] == ["failed"]
    assert processor.run_once() == []  # backing off (30s)
    clock.now += 31
    assert [r.status for r in processor.run_once()] == ["failed"]
    clock.now += 31
    assert processor.run_once() == []  # second backoff is 60s
    clock.now += 30
    assert [r.status for r in processor.run_once()] == ["uploaded"]
    assert processor.snapshot()[0]["failures"] == 0


def test_rescan_of_same_digest_is_throttled_new_digest_is_not(env):
    processor, source, client, clock, _ = env
    feed(processor, source, vulnerability_report(), sbom_report())
    processor.run_once()

    clock.now += 60  # re-scan shortly after: throttled
    feed(processor, source, vulnerability_report(update_ts="2026-11-03T11:00:00Z"), sbom_report())
    assert processor.run_once() == []

    clock.now += 3600  # re-scan after MIN_RESYNC_SECONDS
    feed(processor, source, vulnerability_report(update_ts="2026-11-03T12:00:00Z"), sbom_report())
    assert [r.status for r in processor.run_once()] == ["uploaded"]

    clock.now += 10  # new image version: immediately
    feed(
        processor,
        source,
        vulnerability_report(digest="sha256:bbb", tag="1.1.0", update_ts="2026-11-03T12:01:00Z"),
        sbom_report(digest="sha256:bbb", tag="1.1.0"),
    )
    assert [r.status for r in processor.run_once()] == ["uploaded"]
    assert client.uploads[-1]["docker_image_name_tag"].endswith(":1.1.0")


def test_rolling_update_uploads_newest_report(env):
    processor, source, client, clock, _ = env
    feed(
        processor,
        source,
        vulnerability_report(name="rs-old-app", tag="1.0.0", update_ts="2026-11-03T09:00:00Z"),
        sbom_report(name="rs-old-app"),
    )
    feed(
        processor,
        source,
        vulnerability_report(name="rs-new-app", tag="2.0.0", digest="sha256:new", update_ts="2026-11-03T10:00:00Z"),
        sbom_report(name="rs-new-app", tag="2.0.0", digest="sha256:new"),
    )
    processor.run_once()
    assert len(client.uploads) == 1
    assert client.uploads[0]["docker_image_name_tag"].endswith(":2.0.0")


def test_namespace_annotations_map_product_and_change_moves_target(env):
    processor, source, client, clock, _ = env
    source.ns["shop-prod"] = ({}, {"secobserve.io/product": "Shop Prod", "secobserve.io/product-group": "Pimcore"})
    feed(processor, source, vulnerability_report(), sbom_report())
    processor.run_once()
    assert client.uploads[0]["product_name"] == "Shop Prod"
    assert client.products["Shop Prod"]["group"] == "Pimcore"

    processor.on_namespace("shop-prod", {}, {"secobserve.io/product": "Shop Production"})
    processor.run_once()
    assert client.uploads[-1]["product_name"] == "Shop Production"


def test_opted_out_namespace_is_ignored(env):
    processor, source, client, clock, _ = env
    source.ns["shop-prod"] = ({"secobserve.io/enabled": "false"}, {})
    feed(processor, source, vulnerability_report(), sbom_report())
    assert processor.run_once() == []
    assert client.uploads == []


def test_deleted_report_is_not_processed(env):
    processor, source, client, clock, _ = env
    vr = vulnerability_report()
    feed(processor, source, vr, sbom_report())
    processor.observe_vulnerability_report("DELETED", vr)
    assert processor.run_once() == []


def _check(client, product, service, filename):
    return {"product": client.products[product]["id"], "branch_name": "", "service_name": service, "filename": filename}


def test_reconcile_resolves_vanished_service_after_grace(env):
    processor, source, client, clock, _ = env
    feed(processor, source, vulnerability_report(), sbom_report())
    processor.run_once()
    client.checks = [
        _check(client, "shop-prod", "app", "trivy-operator_test_app.cdx.json"),
        _check(client, "shop-prod", "gone", "trivy-operator_test_gone.cdx.json"),
        _check(client, "shop-prod", "other-cluster", "trivy-operator_othercluster_x.cdx.json"),
        _check(client, "shop-prod", "ci", "trivy.cdx.json"),
    ]
    uploads_before = len(client.uploads)

    assert processor.reconcile() == []  # first sighting starts the grace period
    clock.now += 599
    assert processor.reconcile() == []
    clock.now += 2
    assert processor.reconcile() == [("shop-prod", "", "gone")]
    resolve = client.uploads[uploads_before]
    assert resolve["service"] == "gone" and resolve["file_name"] == "trivy-operator_test_gone.cdx.json"
    assert resolve["bom"]["vulnerabilities"] == []
    clock.now += 3600
    assert processor.reconcile() == []  # not resolved twice
    assert len(client.uploads) == uploads_before + 1


def test_reconcile_spares_service_that_comes_back(env):
    processor, source, client, clock, _ = env
    vr, sbom = vulnerability_report(), sbom_report()
    feed(processor, source, vr, sbom)
    processor.run_once()
    client.checks = [_check(client, "shop-prod", "app", "trivy-operator_test_app.cdx.json")]
    processor.observe_vulnerability_report("DELETED", vr)  # trivy-operator re-scan: delete + create
    processor.reconcile()
    clock.now += 300
    processor.observe_vulnerability_report("ADDED", vr)
    clock.now += 400
    assert processor.reconcile() == []


def _php(name, resource, container, tag, digest, update_ts="2026-11-03T10:00:00Z", vulnerabilities=None):
    common = dict(name=name, resource=resource, container=container, repository="library/php", tag=tag, digest=digest)
    return vulnerability_report(**common, update_ts=update_ts, vulnerabilities=vulnerabilities), sbom_report(**common)


def test_different_images_of_one_service_are_combined_not_overwritten(env):
    processor, source, client, clock, _ = env
    extra = [*vulnerability_report()["report"]["vulnerabilities"]]
    extra.append({**extra[0], "vulnerabilityID": "CVE-2026-9999"})
    feed(
        processor,
        source,
        *_php(
            "replicaset-web-844554d697-php",
            ("ReplicaSet", "web-844554d697"),
            "php",
            "8.1.28-fpm",
            "sha256:fpm",
            "2026-11-03T10:05:00Z",
        ),
    )
    for cronjob in ("import-a", "import-b"):  # same cli image twice -> once
        feed(
            processor,
            source,
            *_php(
                f"cronjob-{cronjob}-job", ("CronJob", cronjob), "job", "8.1.28-cli", "sha256:cli", vulnerabilities=extra
            ),
        )

    assert [r.status for r in processor.run_once()] == ["uploaded"]
    assert len(client.uploads) == 1
    upload = client.uploads[0]
    assert upload["service"] == "php"
    assert upload["docker_image_name_tag"].endswith("php:8.1.28-fpm")  # newest report is the primary image
    assert any(v["id"] == "CVE-2026-9999" for v in upload["bom"]["vulnerabilities"])  # from the cli image
    assert processor.snapshot()[0]["last_images"] == ["sha256:cli", "sha256:fpm"]

    # re-scan of one of the images within MIN_RESYNC_SECONDS: no new upload
    clock.now += 60
    processor.observe_vulnerability_report("MODIFIED", source.vrs[("shop-prod", "cronjob-import-a-job")])
    assert processor.run_once() == []

    # the CronJobs are deleted: after REMOVAL_GRACE_SECONDS upload again with the fpm image only, which resolves
    # the cli-only finding
    for cronjob in ("import-a", "import-b"):
        processor.observe_vulnerability_report("DELETED", source.vrs.pop(("shop-prod", f"cronjob-{cronjob}-job")))
    assert processor.run_once() == []
    assert processor.snapshot()[0]["waiting_for"] == ["CronJob/import-b"]  # import-a: import-b has the same image
    clock.now += SETTINGS.removal_grace_seconds
    assert [r.status for r in processor.run_once()] == ["uploaded"]
    assert not any(v["id"] == "CVE-2026-9999" for v in client.uploads[-1]["bom"]["vulnerabilities"])
    assert processor.snapshot()[0]["last_images"] == ["sha256:fpm"]
    assert processor.snapshot()[0]["waiting_for"] == []


def _fpm_and_cli(processor, source, fpm_ts="2026-11-03T10:05:00Z"):
    fpm = _php(
        "replicaset-web-844554d697-php", ("ReplicaSet", "web-844554d697"), "php", "8.1.28-fpm", "sha256:fpm", fpm_ts
    )
    cli = _php("cronjob-import-a-job", ("CronJob", "import-a"), "job", "8.1.28-cli", "sha256:cli")
    feed(processor, source, *fpm)
    feed(processor, source, *cli)
    return fpm, cli


def test_ttl_rescan_of_one_image_of_a_combined_service_does_not_flap(env):
    """Seen in the e2e test: the Trivy Operator deletes the fpm report at the TTL and re-creates it ~30 s later. The
    operator must not upload the cli image alone in between (that resolves the fpm-only findings for a minute)."""
    processor, source, client, clock, _ = env
    (fpm_vr, fpm_sbom), (cli_vr, _) = _fpm_and_cli(processor, source)
    assert [r.status for r in processor.run_once()] == ["uploaded"]

    clock.now += SETTINGS.min_resync_seconds  # throttling over, both images get re-scanned
    processor.observe_vulnerability_report("DELETED", source.vrs.pop(("shop-prod", fpm_vr["metadata"]["name"])))
    cli_vr["report"]["updateTimestamp"] = "2026-11-03T16:00:00Z"
    processor.observe_vulnerability_report("MODIFIED", cli_vr)  # would be due now ...
    assert [(r.status, r.detail) for r in processor.run_once()] == [
        ("postponed", "waiting for the report of Deployment/web to come back")
    ]  # ... but not without the fpm image
    assert len(client.uploads) == 1

    clock.now += 60
    fpm_vr["report"]["updateTimestamp"] = "2026-11-03T16:01:00Z"
    feed(processor, source, fpm_vr, fpm_sbom)
    assert [r.status for r in processor.run_once()] == ["uploaded"]
    assert len(client.uploads) == 2
    assert client.uploads[-1]["docker_image_name_tag"].endswith("php:8.1.28-fpm")
    assert processor.snapshot()[0]["last_images"] == ["sha256:cli", "sha256:fpm"]

    # the same gap without a pending re-sync: nothing to upload at all
    processor.observe_vulnerability_report("DELETED", source.vrs.pop(("shop-prod", fpm_vr["metadata"]["name"])))
    assert processor.run_once() == []
    clock.now += 60
    feed(processor, source, fpm_vr, fpm_sbom)
    clock.now += SETTINGS.removal_grace_seconds
    assert processor.run_once() == []
    assert len(client.uploads) == 2


def test_rolling_update_in_a_combined_service_is_not_delayed(env):
    processor, source, client, clock, _ = env
    (fpm_vr, _), _ = _fpm_and_cli(processor, source)
    processor.run_once()

    # the old ReplicaSet's report is deleted before the new one is scanned
    clock.now += 10
    processor.observe_vulnerability_report("DELETED", source.vrs.pop(("shop-prod", fpm_vr["metadata"]["name"])))
    assert processor.run_once() == []
    clock.now += 60
    feed(
        processor,
        source,
        *_php(
            "replicaset-web-6b8f7d9c5-php",
            ("ReplicaSet", "web-6b8f7d9c5"),
            "php",
            "8.1.29-fpm",
            "sha256:fpm-new",
            "2026-11-03T11:00:00Z",
        ),
    )
    assert [r.status for r in processor.run_once()] == ["uploaded"]
    assert client.uploads[-1]["docker_image_name_tag"].endswith("php:8.1.29-fpm")
    assert processor.snapshot()[0]["last_images"] == ["sha256:cli", "sha256:fpm-new"]


def test_rolling_update_with_real_replicaset_names(env):
    processor, source, client, clock, _ = env
    old = ("ReplicaSet", "web-5d4f8b9c7")
    new = ("ReplicaSet", "web-7c9d6f8b4")
    feed(
        processor,
        source,
        vulnerability_report(name="rs-old", resource=old, tag="1.21.0", digest="sha256:old"),
        sbom_report(name="rs-old", resource=old, tag="1.21.0", digest="sha256:old"),
    )
    processor.run_once()
    clock.now += 30
    feed(
        processor,
        source,
        vulnerability_report(
            name="rs-new", resource=new, tag="1.25.0", digest="sha256:new", update_ts="2026-11-03T11:00:00Z"
        ),
        sbom_report(name="rs-new", resource=new, tag="1.25.0", digest="sha256:new"),
    )
    processor.run_once()
    assert len(client.uploads) == 2
    assert client.uploads[-1]["docker_image_name_tag"].endswith(":1.25.0")
    assert "trivy-secobserve:images" not in json.dumps(client.uploads[-1]["bom"]["metadata"])  # not combined

    # a late re-scan of the old ReplicaSet changes nothing
    clock.now += 30
    feed(
        processor,
        source,
        vulnerability_report(
            name="rs-old", resource=old, tag="1.21.0", digest="sha256:old", update_ts="2026-11-03T11:30:00Z"
        ),
        sbom_report(name="rs-old", resource=old, tag="1.21.0", digest="sha256:old"),
    )
    assert processor.run_once() == []


def test_ttl_rescan_of_old_replicaset_does_not_win(env):
    processor, source, client, clock, _ = env
    old, new = ("ReplicaSet", "web-5d4f8b9c7"), ("ReplicaSet", "web-7c9d6f8b4")
    old_vr = vulnerability_report(name="rs-old", resource=old, tag="1.21.0", digest="sha256:old")
    feed(processor, source, old_vr, sbom_report(name="rs-old", resource=old, tag="1.21.0", digest="sha256:old"))
    clock.now += 30
    feed(
        processor,
        source,
        vulnerability_report(name="rs-new", resource=new, tag="1.25.0", digest="sha256:new"),
        sbom_report(name="rs-new", resource=new, tag="1.25.0", digest="sha256:new"),
    )
    processor.run_once()
    assert client.uploads[-1]["docker_image_name_tag"].endswith(":1.25.0")

    clock.now += 7200  # scannerReportTTL: Trivy deletes and re-creates the old report with a newer scan
    processor.observe_vulnerability_report("DELETED", old_vr)
    rescanned = vulnerability_report(
        name="rs-old", resource=old, tag="1.21.0", digest="sha256:old", update_ts="2026-11-03T13:00:00Z"
    )
    feed(processor, source, rescanned, sbom_report(name="rs-old", resource=old, tag="1.21.0", digest="sha256:old"))
    assert processor.run_once() == []


def test_after_restart_report_creation_time_decides_current_replicaset(env):
    processor, source, client, clock, _ = env
    old, new = ("ReplicaSet", "web-5d4f8b9c7"), ("ReplicaSet", "web-7c9d6f8b4")
    new_vr = vulnerability_report(name="rs-new", resource=new, tag="1.25.0", digest="sha256:new")
    new_vr["metadata"]["creationTimestamp"] = "2026-11-03T10:00:00Z"
    old_vr = vulnerability_report(
        name="rs-old", resource=old, tag="1.21.0", digest="sha256:old", update_ts="2026-11-03T11:00:00Z"
    )  # re-scanned later
    old_vr["metadata"]["creationTimestamp"] = "2026-11-01T10:00:00Z"
    # the initial list after a restart delivers the new ReplicaSet's report first
    feed(processor, source, new_vr, sbom_report(name="rs-new", resource=new, tag="1.25.0", digest="sha256:new"))
    feed(processor, source, old_vr, sbom_report(name="rs-old", resource=old, tag="1.21.0", digest="sha256:old"))
    processor.run_once()
    assert len(client.uploads) == 1
    assert client.uploads[0]["docker_image_name_tag"].endswith(":1.25.0")
