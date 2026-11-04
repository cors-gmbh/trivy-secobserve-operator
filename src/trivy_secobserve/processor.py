"""Core logic, independent of kopf so it can be tested without a cluster.

Event handlers only update an in-memory index (which reports exist and which SecObserve target they map to).
A single worker later fetches the reports fresh from the API, merges them and uploads:

* identical images used by several workloads are uploaded once per target (product, branch, service),
* different images that map to the same target (e.g. php:8.1-fpm in a Deployment and php:8.1-cli in a CronJob,
  both service "php") are combined into one upload instead of overwriting each other,
* failed uploads are retried with exponential backoff (kopf event handlers have no retries),
* re-scans of an unchanged image are throttled by MIN_RESYNC_SECONDS.
"""

from __future__ import annotations

import json
import logging
import re
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

from .config import Settings
from .converter import combine, empty_bom, merge
from .mapping import Target, image_from_report, resolve_target, template_values, upload_filename
from .secobserve import SecObserveClient
from .storage import Storage, content_hash, object_path

logger = logging.getLogger(__name__)

# ReplicaSet name = <deployment>-<pod-template-hash>; the hash uses the alphabet of k8s rand.SafeEncodeString.
_POD_TEMPLATE_HASH = re.compile(r"-[bcdfghjklmnpqrstvwxz2456789]{5,10}$")


class ReportSource(Protocol):
    def get_vulnerability_report(self, namespace: str, name: str) -> dict[str, Any] | None: ...

    def get_sbom_report(self, namespace: str, name: str) -> dict[str, Any] | None: ...

    def get_namespace_meta(self, namespace: str) -> tuple[dict[str, str], dict[str, str]]:
        """Return (labels, annotations) of a namespace."""
        ...


@dataclass
class RefState:
    namespace: str
    name: str
    values: dict[str, str]
    update_ts: str
    digest: str
    first_seen: float  # this report object (reset when Trivy re-creates it): SBOM wait
    known_since: float = 0.0  # this report name, survives delete + re-create: which ReplicaSet is the current one

    @property
    def newness(self) -> tuple[str, float]:
        return self.update_ts, self.first_seen

    @property
    def workload(self) -> tuple[str, str, str]:
        """The workload + container the report belongs to; all ReplicaSets of a Deployment count as one."""
        kind, name = self.values.get("resource_kind", ""), self.values.get("resource_name", "")
        if kind == "ReplicaSet":
            kind, name = "Deployment", _POD_TEMPLATE_HASH.sub("", name)
        return kind, name, self.values.get("container", "")

    @property
    def image(self) -> str:
        return (
            self.digest
            or f"{self.values.get('registry', '')}/{self.values.get('repository', '')}:{self.values.get('tag', '')}"
        )


_LONG_RUNNING = {"Deployment", "StatefulSet", "DaemonSet"}


def select_refs(refs: list[RefState]) -> list[RefState]:
    """The reports to upload for one target, the primary one first.

    Per workload the most recently appeared report wins (during a rolling update both ReplicaSets have reports,
    and a late re-scan of the old one must not win), then identical images are uploaded once with their freshest
    scan (e.g. 7 CronJobs with the same php-cli image). What remains are really different images that run at the
    same time and map to the same service. The primary image (shown as image of the observations) is stable:
    long-running workloads before CronJobs/Jobs, then by image.
    """
    per_workload: dict[tuple[str, str, str], RefState] = {}
    for ref in refs:
        current = per_workload.get(ref.workload)
        if current is None or (ref.known_since, ref.newness) > (current.known_since, current.newness):
            per_workload[ref.workload] = ref
    per_image: dict[str, RefState] = {}
    for ref in per_workload.values():
        if ref.image not in per_image or ref.newness > per_image[ref.image].newness:
            per_image[ref.image] = ref
    return sorted(per_image.values(), key=lambda r: (r.workload[0] not in _LONG_RUNNING, r.image))


def _images(refs: list[RefState]) -> tuple[str, ...]:
    return tuple(sorted(ref.image for ref in refs))


@dataclass
class TargetState:
    target: Target
    refs: dict[str, RefState] = field(default_factory=dict)
    dirty: bool = True
    force: bool = False
    next_attempt: float = 0.0
    failures: int = 0
    last_images: tuple[str, ...] = ()
    last_update_ts: str = ""
    last_upload: float = 0.0
    last_sbom_used: bool = False
    last_error: str = ""
    last_archive_error: str = ""
    # workloads whose report vanished while other images of the service remain (and since when)
    gone: dict[tuple[str, str, str], float] = field(default_factory=dict)


@dataclass
class ProcessResult:
    target: Target
    status: str  # uploaded | postponed | skipped | failed
    detail: str = ""
    response: dict[str, Any] | None = None
    location: str | None = None


def _refkey(namespace: str, name: str) -> str:
    return f"{namespace}/{name}"


def _parse_timestamp(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


class Processor:
    def __init__(
        self,
        settings: Settings,
        client: SecObserveClient,
        storage: Storage,
        source: ReportSource,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.settings = settings
        self.client = client
        self.storage = storage
        self.source = source
        self.clock = clock
        self._lock = threading.RLock()
        self.targets: dict[tuple[str, str, str], TargetState] = {}
        self.ref_target: dict[str, tuple[str, str, str]] = {}
        self.ns_meta: dict[str, tuple[dict[str, str], dict[str, str]]] = {}
        self.missing_since: dict[tuple[str, str, str], float] = {}
        self.resolved_keys: set[tuple[str, str, str]] = set()
        self.known_since: dict[str, float] = {}

    # --- namespace metadata ----------------------------------------------------------------------------------

    def _namespace_meta(self, namespace: str) -> tuple[dict[str, str], dict[str, str]]:
        if namespace not in self.ns_meta:
            self.ns_meta[namespace] = self.source.get_namespace_meta(namespace)
        return self.ns_meta[namespace]

    def on_namespace(
        self, namespace: str, labels: dict[str, str], annotations: dict[str, str], deleted: bool = False
    ) -> None:
        with self._lock:
            if deleted:
                self.ns_meta.pop(namespace, None)
                return
            before = self.ns_meta.get(namespace)
            self.ns_meta[namespace] = (dict(labels or {}), dict(annotations or {}))
            if before is not None and before != self.ns_meta[namespace]:
                # Mapping may have changed: re-resolve all reports of this namespace.
                for refkey in [k for k in self.ref_target if k.startswith(f"{namespace}/")]:
                    target_state = self.targets.get(self.ref_target[refkey])
                    ref = target_state.refs.get(refkey) if target_state else None
                    if ref:
                        self._index_ref(ref, force=True)

    # --- report events ---------------------------------------------------------------------------------------

    def observe_vulnerability_report(self, event_type: str | None, obj: dict[str, Any]) -> None:
        metadata = obj.get("metadata", {})
        namespace, name = metadata.get("namespace", ""), metadata.get("name", "")
        refkey = _refkey(namespace, name)
        with self._lock:
            if event_type == "DELETED":
                self._remove_ref(refkey)
                return
            report = obj.get("report", {}) or {}
            previous_key = self.ref_target.get(refkey)
            previous = self.targets[previous_key].refs.get(refkey) if previous_key in self.targets else None
            ref = RefState(
                namespace=namespace,
                name=name,
                values=template_values(self.settings.cluster_name, obj),
                update_ts=report.get("updateTimestamp", "") or "",
                digest=image_from_report(obj).digest,
                first_seen=previous.first_seen if previous else self.clock(),
                known_since=self._known_since(refkey, metadata.get("creationTimestamp")),
            )
            self._index_ref(ref)

    def _known_since(self, refkey: str, creation_timestamp: str | None) -> float:
        if refkey not in self.known_since:
            if len(self.known_since) > 10_000:  # forget reports that are gone
                self.known_since = {k: v for k, v in self.known_since.items() if k in self.ref_target}
            # after an operator restart, the report's creation time keeps the order of ReplicaSets
            self.known_since[refkey] = _parse_timestamp(creation_timestamp) or self.clock()
        return self.known_since[refkey]

    def observe_sbom_report(self, event_type: str | None, obj: dict[str, Any]) -> None:
        """SBOMs are fetched at processing time. Only an SBOM that arrives after an upload without SBOM forces a
        re-upload (to add the dependency graph); regular re-scans are throttled via the VulnerabilityReport."""
        if event_type == "DELETED":
            return
        metadata = obj.get("metadata", {})
        refkey = _refkey(metadata.get("namespace", ""), metadata.get("name", ""))
        with self._lock:
            key = self.ref_target.get(refkey)
            if key and key in self.targets:
                state = self.targets[key]
                if state.last_upload and not state.last_sbom_used and not state.dirty:
                    state.dirty, state.force = True, True

    def _index_ref(self, ref: RefState, force: bool = False) -> None:
        refkey = _refkey(ref.namespace, ref.name)
        try:
            labels, annotations = self._namespace_meta(ref.namespace)
            target = resolve_target(self.settings, ref.values, labels, annotations)
        except Exception as exc:  # noqa: BLE001 - a broken template must not stop the operator
            logger.error("Cannot map report %s: %s", refkey, exc)
            target = None

        old_key = self.ref_target.get(refkey)
        if target is None:
            self._remove_ref(refkey)
            return
        if old_key and old_key != target.key:
            self._remove_ref(refkey)

        state = self.targets.get(target.key)
        if state is None:
            state = self.targets[target.key] = TargetState(target=target)
        state.target = target
        state.refs[refkey] = ref
        if state.gone.pop(ref.workload, None) is not None:  # back again (re-scan) or replaced (rolling update)
            logger.info("Report of %s/%s is back (%s)", *ref.workload[:2], ref.name)
        self.ref_target[refkey] = target.key
        self.missing_since.pop(target.key, None)
        self.resolved_keys.discard(target.key)

        now = self.clock()
        if force or not state.last_upload:
            state.dirty = True
            state.force = state.force or force
        elif ref not in select_refs(list(state.refs.values())):
            pass  # e.g. the report of an old ReplicaSet, or a duplicate of an image that is already uploaded
        elif ref.image not in state.last_images:
            state.dirty = True  # new image version
        elif ref.update_ts > state.last_update_ts and now - state.last_upload >= self.settings.min_resync_seconds:
            state.dirty = True

    def _remove_ref(self, refkey: str) -> None:
        key = self.ref_target.pop(refkey, None)
        if key and key in self.targets:
            state = self.targets[key]
            removed = state.refs.pop(refkey, None)
            # An image that was part of the last upload is gone, others remain: upload again without it.
            # (No refs left at all is the reconciler's job, after the grace period.)
            if removed and state.refs and state.last_upload and removed.image in state.last_images:
                remaining = list(state.refs.values())
                if _images(select_refs(remaining)) != state.last_images:
                    if any(ref.workload == removed.workload for ref in remaining):
                        state.dirty = True  # replaced, e.g. the old ReplicaSet after a rolling update
                    else:
                        # Trivy Operator re-scans (scannerReportTTL) delete the report and create it again a few
                        # minutes later: dropping the image right away would resolve and re-open its findings.
                        if removed.workload not in state.gone:
                            state.gone[removed.workload] = self.clock()
                            logger.info(
                                "Report %s of service '%s' (%s) vanished, waiting up to %ss for it to come back",
                                removed.name,
                                state.target.service,
                                state.target.product,
                                self.settings.removal_grace_seconds,
                            )

    def _expire_gone(self, state: TargetState, now: float) -> None:
        expired = [w for w, since in state.gone.items() if now - since >= self.settings.removal_grace_seconds]
        for workload in expired:
            del state.gone[workload]
            logger.info("Report of %s/%s did not come back, uploading service without it", *workload[:2])
        if expired and state.refs and _images(select_refs(list(state.refs.values()))) != state.last_images:
            state.dirty = True

    # --- worker ----------------------------------------------------------------------------------------------

    def due_keys(self) -> list[tuple[str, str, str]]:
        now = self.clock()
        with self._lock:
            for state in self.targets.values():
                if state.gone:
                    self._expire_gone(state, now)
            return [k for k, s in self.targets.items() if s.dirty and s.refs and s.next_attempt <= now]

    def run_once(self) -> list[ProcessResult]:
        return [result for key in self.due_keys() if (result := self.process_target(key)) is not None]

    def process_target(self, key: tuple[str, str, str]) -> ProcessResult | None:
        with self._lock:
            state = self.targets.get(key)
            if state is None or not state.refs:
                return None
            target = state.target
            if state.gone:  # do not upload a partial service while a report is being re-created
                now = self.clock()
                state.next_attempt = min(min(state.gone.values()) + self.settings.removal_grace_seconds, now + 60)
                waiting = ", ".join(f"{kind}/{name}" for kind, name, _ in state.gone)
                return ProcessResult(target, "postponed", f"waiting for the report of {waiting} to come back")
            selected = select_refs(list(state.refs.values()))

        try:
            parts, stored = [], []
            for ref in selected:
                vulnerability_report = self.source.get_vulnerability_report(ref.namespace, ref.name)
                if vulnerability_report is None:
                    with self._lock:
                        self._remove_ref(_refkey(ref.namespace, ref.name))
                    return ProcessResult(target, "skipped", f"report {ref.name} vanished")
                sbom_report = self.source.get_sbom_report(ref.namespace, ref.name)
                now = self.clock()
                if sbom_report is None and now - ref.first_seen < self.settings.sbom_wait_seconds:
                    with self._lock:
                        state.next_attempt = ref.first_seen + self.settings.sbom_wait_seconds
                    return ProcessResult(target, "postponed", f"waiting for SbomReport {ref.name}")

                image = image_from_report(vulnerability_report)
                bom, stats = merge(
                    vulnerability_report,
                    sbom_report,
                    extra_properties={
                        "trivy-secobserve:cluster": self.settings.cluster_name,
                        "trivy-secobserve:namespace": ref.namespace,
                        "trivy-secobserve:report": ref.name,
                    },
                )
                # The archive keeps one document per image and scan (path contains digest and content hash).
                timestamp = ref.update_ts or datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
                path = object_path(self.settings, ref.namespace, target, image, timestamp, content_hash(bom))
                stored.append(self._archive(path, json.dumps(bom, separators=(",", ":")).encode(), state))
                parts.append((bom, stats, image))

            primary, image = selected[0], parts[0][2]
            if len(parts) > 1:
                logger.warning(
                    "%s different images map to product '%s' service '%s' (%s); they are uploaded combined. "
                    "Set SERVICE_NAME_TEMPLATE (e.g. '{image_name}-{container}') to get separate services.",
                    len(parts),
                    target.product,
                    target.service,
                    ", ".join(p[2].name_tag for p in parts),
                )
            bom, stats = combine([(p[0], p[1]) for p in parts])
            data = json.dumps(bom, separators=(",", ":")).encode()

            self.client.ensure_product(target.product, target.product_group, self.settings.product_auto_create)
            response = self.client.upload_observations(
                product_name=target.product,
                file_name=upload_filename(self.settings, target),
                content=data,
                branch_name=target.branch,
                service=target.service,
                docker_image_name_tag=image.name_tag,
                kubernetes_cluster=self.settings.cluster_name,
                kubernetes_namespace=primary.namespace,
                suppress_licenses=self.settings.suppress_licenses,
            )
        except Exception as exc:  # noqa: BLE001 - retried with backoff
            with self._lock:
                state.failures += 1
                backoff = min(self.settings.max_backoff_seconds, 30 * 2 ** (state.failures - 1))
                state.next_attempt = self.clock() + backoff
                state.last_error = str(exc)[:500]
            logger.warning("Upload for %s failed (attempt %s, retry in %ss): %s", key, state.failures, backoff, exc)
            return ProcessResult(target, "failed", str(exc))

        location = ", ".join(s for s in stored if s) or None
        with self._lock:
            state.dirty = state.force = False
            state.failures, state.next_attempt, state.last_error = 0, 0.0, ""
            state.last_images = _images(selected)
            state.last_update_ts = max(ref.update_ts for ref in selected)
            state.last_upload = self.clock()
            state.last_sbom_used = stats.sbom_used
        logger.info(
            "Uploaded %s (%s) -> product '%s' service '%s': %s vulnerabilities (%s exact, %s fuzzy, %s unmatched), "
            "sbom=%s, result=%s, stored=%s",
            " + ".join(p[2].name_tag for p in parts),
            ", ".join(ref.name for ref in selected),
            target.product,
            target.service,
            stats.vulnerabilities,
            stats.matched_exact,
            stats.matched_fuzzy,
            stats.unmatched,
            stats.sbom_used,
            response,
            location,
        )
        return ProcessResult(target, "uploaded", response=response, location=location)

    def _archive(self, path: str, data: bytes, state: TargetState) -> str | None:
        """Archive one document. A broken archive (bucket, permissions) must not stop the uploads to SecObserve."""
        try:
            location = self.storage.store(path, data)
        except Exception as exc:  # noqa: BLE001
            logger.error("Archiving %s failed, uploading to SecObserve anyway: %s", path, exc)
            with self._lock:
                state.last_archive_error = str(exc)[:500]
            return None
        with self._lock:
            state.last_archive_error = ""
        return location

    # --- reconciliation --------------------------------------------------------------------------------------

    def reconcile(self) -> list[tuple[str, str, str]]:
        """Resolve findings of services that are not running anymore (after a grace period).

        The source of truth is the list of vulnerability checks in SecObserve whose file name carries this
        operator's prefix (contains the cluster name), so this also works after a restart of the operator.
        """
        if not self.settings.reconcile_enabled:
            return []
        now = self.clock()
        with self._lock:
            active = {key for key, state in self.targets.items() if state.refs}
        resolved: list[tuple[str, str, str]] = []
        prefix = self.settings.filename_prefix
        for check in self.client.list_vulnerability_checks(prefix):
            if not str(check.get("filename", "")).startswith(prefix):
                continue
            key = (
                self.client.get_product_name(check["product"]),
                check.get("branch_name") or "",
                check.get("service_name") or "",
            )
            if key in active:
                self.missing_since.pop(key, None)
                continue
            if key in self.resolved_keys:
                continue
            since = self.missing_since.setdefault(key, now)
            if now - since < self.settings.reconcile_grace_seconds:
                continue
            product, branch, service = key
            try:
                result = self.client.upload_observations(
                    product_name=product,
                    file_name=check["filename"],
                    content=json.dumps(empty_bom()).encode(),
                    branch_name=branch,
                    service=service,
                    kubernetes_cluster=self.settings.cluster_name,
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning("Could not resolve vanished service %s: %s", key, exc)
                continue
            logger.info("Service %s not running anymore, resolved its findings: %s", key, result)
            self.resolved_keys.add(key)
            self.missing_since.pop(key, None)
            resolved.append(key)
        return resolved

    # --- introspection ---------------------------------------------------------------------------------------

    def snapshot(self) -> list[dict[str, Any]]:
        with self._lock:
            return [
                {
                    "product": s.target.product,
                    "branch": s.target.branch,
                    "service": s.target.service,
                    "refs": sorted(s.refs),
                    "dirty": s.dirty,
                    "failures": s.failures,
                    "last_images": list(s.last_images),
                    "waiting_for": sorted(f"{kind}/{name}" for kind, name, _ in s.gone),
                    "last_error": s.last_error,
                    "last_archive_error": s.last_archive_error,
                }
                for s in self.targets.values()
            ]
