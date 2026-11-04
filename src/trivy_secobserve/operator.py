"""kopf wiring. Run with:  kopf run --standalone --all-namespaces -m trivy_secobserve.operator"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from typing import Any

import kopf
import requests
from kubernetes import client as k8s_client
from kubernetes import config as k8s_config
from kubernetes.client.rest import ApiException

from .config import Settings
from .mapping import validate_templates
from .processor import Processor
from .secobserve import SecObserveClient, SecObserveError
from .storage import build_storage

GROUP = "aquasecurity.github.io"
VERSION = "v1alpha1"

logger = logging.getLogger("trivy_secobserve")


class KubernetesReportSource:
    def __init__(self) -> None:
        try:
            k8s_config.load_incluster_config()
        except k8s_config.ConfigException:
            k8s_config.load_kube_config()
        self.custom = k8s_client.CustomObjectsApi()
        self.core = k8s_client.CoreV1Api()

    def _get(self, plural: str, namespace: str, name: str) -> dict[str, Any] | None:
        try:
            return self.custom.get_namespaced_custom_object(GROUP, VERSION, namespace, plural, name)
        except ApiException as exc:
            if exc.status == 404:
                return None
            raise

    def get_vulnerability_report(self, namespace: str, name: str) -> dict[str, Any] | None:
        return self._get("vulnerabilityreports", namespace, name)

    def get_sbom_report(self, namespace: str, name: str) -> dict[str, Any] | None:
        return self._get("sbomreports", namespace, name)

    def get_namespace_meta(self, namespace: str) -> tuple[dict[str, str], dict[str, str]]:
        try:
            ns = self.core.read_namespace(namespace)
        except ApiException as exc:
            if exc.status == 404:
                return {}, {}
            raise
        return dict(ns.metadata.labels or {}), dict(ns.metadata.annotations or {})


def _plain(body: Any) -> dict[str, Any]:
    """kopf bodies are read-only mappings; the processor wants plain dicts."""
    return {key: body[key] for key in body}


async def _worker_loop(processor: Processor, settings: Settings) -> None:
    await asyncio.sleep(min(15, settings.worker_tick_seconds * 3))  # let the initial listing fill the index
    while True:
        try:
            await asyncio.to_thread(processor.run_once)
        except Exception:  # noqa: BLE001
            logger.exception("Worker iteration failed")
        await asyncio.sleep(settings.worker_tick_seconds)


async def _reconcile_loop(processor: Processor, settings: Settings) -> None:
    await asyncio.sleep(settings.reconcile_startup_delay_seconds)
    while True:
        try:
            await asyncio.to_thread(processor.reconcile)
        except (SecObserveError, requests.RequestException) as exc:
            logger.warning("Reconciliation skipped, SecObserve not available: %s", exc)
        except Exception:  # noqa: BLE001
            logger.exception("Reconciliation failed")
        await asyncio.sleep(settings.reconcile_interval_seconds)


@kopf.on.startup()
async def startup(settings: kopf.OperatorSettings, memo: kopf.Memo, **_: Any) -> None:
    config = Settings.from_env()
    logging.getLogger().setLevel(config.log_level)
    logging.getLogger("trivy_secobserve").setLevel(config.log_level)
    if config.log_level != "DEBUG":
        # kopf logs every handled event ("Handler ... succeeded"), far too noisy with thousands of reports
        logging.getLogger("kopf.objects").setLevel(logging.WARNING)
        logging.getLogger("aiohttp.access").setLevel(logging.WARNING)  # liveness probe every 30 s
    config.validate()
    validate_templates(config)

    settings.posting.enabled = False  # no Kubernetes events for every report
    # cluster-wide watches of known resources only: no list/watch on CRDs needed (read-only RBAC stays minimal)
    settings.scanning.disabled = True
    # kopf sometimes stops watching silently, timeouts help (same as trivy-dojo-report-operator).
    settings.watching.connect_timeout = 60
    settings.watching.server_timeout = 600
    settings.watching.client_timeout = 610

    client = SecObserveClient(
        config.secobserve_api_url,
        config.secobserve_api_token,
        verify_ssl=config.secobserve_verify_ssl,
        timeout=config.secobserve_timeout_seconds,
    )
    processor = Processor(config, client, build_storage(config), KubernetesReportSource())
    memo.processor = processor
    memo.tasks = [asyncio.create_task(_worker_loop(processor, config))]
    if config.reconcile_enabled:
        memo.tasks.append(asyncio.create_task(_reconcile_loop(processor, config)))
    logger.info("trivy-secobserve-operator started: %s", config)


@kopf.on.cleanup()
async def cleanup(memo: kopf.Memo, **_: Any) -> None:
    for task in getattr(memo, "tasks", []):
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task


@kopf.on.event("", "v1", "namespaces")
def namespace_event(event: dict[str, Any], body: kopf.Body, memo: kopf.Memo, **_: Any) -> None:
    metadata = body.get("metadata", {})
    memo.processor.on_namespace(
        metadata.get("name", ""),
        dict(metadata.get("labels") or {}),
        dict(metadata.get("annotations") or {}),
        deleted=event.get("type") == "DELETED",
    )


@kopf.on.event(GROUP, VERSION, "vulnerabilityreports")
def vulnerability_report_event(event: dict[str, Any], body: kopf.Body, memo: kopf.Memo, **_: Any) -> None:
    memo.processor.observe_vulnerability_report(event.get("type"), _plain(body))


@kopf.on.event(GROUP, VERSION, "sbomreports")
def sbom_report_event(event: dict[str, Any], body: kopf.Body, memo: kopf.Memo, **_: Any) -> None:
    memo.processor.observe_sbom_report(event.get("type"), _plain(body))
