"""Operator settings, read from environment variables."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field


def _bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None or value == "":
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _int(name: str, default: int) -> int:
    value = os.getenv(name)
    return int(value) if value not in (None, "") else default


def _list(name: str, default: str = "") -> list[str]:
    return [item.strip() for item in os.getenv(name, default).split(",") if item.strip()]


# Namespace annotations override the configured defaults per namespace. Annotations (not labels) because
# SecObserve names like "Shop Prod" contain spaces, which label values do not allow.
ANNOTATION_PRODUCT = "secobserve.io/product"
ANNOTATION_PRODUCT_GROUP = "secobserve.io/product-group"
ANNOTATION_BRANCH = "secobserve.io/branch"
# Namespace label to opt a namespace in ("true") or out ("false").
LABEL_ENABLED = "secobserve.io/enabled"


@dataclass(frozen=True)
class NamespaceRule:
    """Central mapping for groups of namespaces, e.g. all infrastructure namespaces into their own product group.

    The first rule whose regex matches the whole namespace name wins. A field that is not set (None) falls back to
    the global default; namespace annotations still override everything.
    """

    match: str
    product: str | None = None  # template, like PRODUCT_NAME_TEMPLATE
    product_group: str | None = None
    branch: str | None = None  # template, like BRANCH_NAME_TEMPLATE

    def matches(self, namespace: str) -> bool:
        return re.fullmatch(self.match, namespace) is not None


_RULE_KEYS = {"match": "match", "product": "product", "productGroup": "product_group", "branch": "branch"}


def _rules(name: str) -> tuple[NamespaceRule, ...]:
    """NAMESPACE_RULES: JSON list of {"match": regex, "product"?, "productGroup"?, "branch"?}."""
    raw = os.getenv(name, "").strip()
    if not raw:
        return ()
    data = json.loads(raw)
    if not isinstance(data, list):
        raise ValueError(f"{name} must be a JSON list")
    rules = []
    for i, item in enumerate(data):
        if not isinstance(item, dict) or not isinstance(item.get("match"), str) or not item["match"]:
            raise ValueError(f"{name}[{i}] needs a 'match' regex")
        unknown = sorted(set(item) - set(_RULE_KEYS))
        if unknown:
            raise ValueError(f"{name}[{i}]: unknown keys {unknown}, allowed: {sorted(_RULE_KEYS)}")
        for key, value in item.items():
            if value is not None and not isinstance(value, str):
                raise ValueError(f"{name}[{i}].{key} must be a string")
        try:
            re.compile(item["match"])
        except re.error as exc:
            raise ValueError(f"{name}[{i}]: invalid regex {item['match']!r}: {exc}") from exc
        rules.append(NamespaceRule(**{_RULE_KEYS[key]: value for key, value in item.items()}))
    return tuple(rules)


@dataclass(frozen=True)
class Settings:
    # --- SecObserve ---
    secobserve_api_url: str = ""
    secobserve_api_token: str = field(default="", repr=False)
    secobserve_verify_ssl: bool = True
    secobserve_timeout_seconds: int = 300
    # --- Mapping (templates use str.format placeholders, see mapping.py) ---
    cluster_name: str = "default"
    product_name_template: str = "{namespace}"
    product_group: str = ""
    product_auto_create: bool = True
    service_name_template: str = "{image_name}"
    branch_name_template: str = ""
    require_namespace_label: bool = False
    exclude_namespaces: tuple[str, ...] = ("kube-system", "kube-public", "kube-node-lease", "trivy-system")
    namespace_rules: tuple[NamespaceRule, ...] = ()
    suppress_licenses: bool = False
    # --- Processing ---
    min_resync_seconds: int = 6 * 3600
    sbom_wait_seconds: int = 120
    removal_grace_seconds: int = 900
    worker_tick_seconds: int = 5
    # initial listing of the reports in pages of this size instead of all at once (0 = no paging)
    watch_chunk_size: int = 10
    max_backoff_seconds: int = 1800
    # --- Storage ---
    gcs_bucket: str = ""
    gcs_prefix: str = "trivy-secobserve"
    local_storage_dir: str = ""
    # --- Reconciliation of vanished services ---
    reconcile_enabled: bool = False
    reconcile_interval_seconds: int = 3600
    reconcile_grace_seconds: int = 7200
    reconcile_startup_delay_seconds: int = 600
    # --- Misc ---
    log_level: str = "INFO"

    @property
    def filename_prefix(self) -> str:
        """All uploads of this operator instance share this file name prefix (one vulnerability check per service)."""
        return f"trivy-operator_{self.cluster_name}_"

    @classmethod
    def from_env(cls) -> Settings:
        return cls(
            secobserve_api_url=os.getenv("SECOBSERVE_API_URL", "").rstrip("/"),
            secobserve_api_token=os.getenv("SECOBSERVE_API_TOKEN", ""),
            secobserve_verify_ssl=_bool("SECOBSERVE_VERIFY_SSL", True),
            secobserve_timeout_seconds=_int("SECOBSERVE_TIMEOUT_SECONDS", 300),
            cluster_name=os.getenv("CLUSTER_NAME", "default"),
            product_name_template=os.getenv("PRODUCT_NAME_TEMPLATE", "{namespace}"),
            product_group=os.getenv("PRODUCT_GROUP", ""),
            product_auto_create=_bool("PRODUCT_AUTO_CREATE", True),
            service_name_template=os.getenv("SERVICE_NAME_TEMPLATE", "{image_name}"),
            branch_name_template=os.getenv("BRANCH_NAME_TEMPLATE", ""),
            require_namespace_label=_bool("REQUIRE_NAMESPACE_LABEL", False),
            exclude_namespaces=tuple(
                _list("EXCLUDE_NAMESPACES", "kube-system,kube-public,kube-node-lease,trivy-system")
            ),
            namespace_rules=_rules("NAMESPACE_RULES"),
            suppress_licenses=_bool("SUPPRESS_LICENSES", False),
            min_resync_seconds=_int("MIN_RESYNC_SECONDS", 6 * 3600),
            sbom_wait_seconds=_int("SBOM_WAIT_SECONDS", 120),
            removal_grace_seconds=_int("REMOVAL_GRACE_SECONDS", 900),
            worker_tick_seconds=_int("WORKER_TICK_SECONDS", 5),
            watch_chunk_size=_int("WATCH_CHUNK_SIZE", 10),
            max_backoff_seconds=_int("MAX_BACKOFF_SECONDS", 1800),
            gcs_bucket=os.getenv("GCS_BUCKET", ""),
            gcs_prefix=os.getenv("GCS_PREFIX", "trivy-secobserve").strip("/"),
            local_storage_dir=os.getenv("LOCAL_STORAGE_DIR", ""),
            reconcile_enabled=_bool("RECONCILE_ENABLED", False),
            reconcile_interval_seconds=_int("RECONCILE_INTERVAL_SECONDS", 3600),
            reconcile_grace_seconds=_int("RECONCILE_GRACE_SECONDS", 7200),
            reconcile_startup_delay_seconds=_int("RECONCILE_STARTUP_DELAY_SECONDS", 600),
            log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
        )

    def validate(self) -> None:
        missing = [
            name
            for name, value in (
                ("SECOBSERVE_API_URL", self.secobserve_api_url),
                ("SECOBSERVE_API_TOKEN", self.secobserve_api_token),
            )
            if not value
        ]
        if missing:
            raise ValueError(f"Missing required settings: {', '.join(missing)}")
