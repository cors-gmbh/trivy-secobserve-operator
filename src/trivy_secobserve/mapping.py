"""Map Trivy Operator reports to SecObserve product / branch / service."""

from __future__ import annotations

import re
import string
from dataclasses import dataclass
from typing import Any

from .config import (
    ANNOTATION_BRANCH,
    ANNOTATION_PRODUCT,
    ANNOTATION_PRODUCT_GROUP,
    LABEL_ENABLED,
    NamespaceRule,
    Settings,
)

TEMPLATE_FIELDS = (
    "cluster",
    "namespace",
    "registry",
    "repository",
    "image_name",
    "tag",
    "digest",
    "container",
    "resource_kind",
    "resource_name",
)


@dataclass(frozen=True)
class ImageRef:
    registry: str
    repository: str
    tag: str
    digest: str

    @property
    def name(self) -> str:
        return f"{self.registry}/{self.repository}" if self.registry else self.repository

    @property
    def image_name(self) -> str:
        return self.repository.rsplit("/", 1)[-1]

    @property
    def name_tag(self) -> str:
        if self.tag:
            return f"{self.name}:{self.tag}"
        if self.digest:
            return f"{self.name}@{self.digest}"
        return self.name


@dataclass(frozen=True)
class Target:
    """Where a report goes in SecObserve. (product, branch, service) is one vulnerability check."""

    product: str
    product_group: str
    branch: str
    service: str

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.product, self.branch, self.service)


def image_from_report(report_obj: dict[str, Any]) -> ImageRef:
    report = report_obj.get("report", {})
    artifact = report.get("artifact", {}) or {}
    registry = (report.get("registry", {}) or {}).get("server", "") or ""
    return ImageRef(
        registry=registry,
        repository=artifact.get("repository", "") or "",
        tag=artifact.get("tag", "") or "",
        digest=artifact.get("digest", "") or "",
    )


def template_values(cluster: str, report_obj: dict[str, Any]) -> dict[str, str]:
    metadata = report_obj.get("metadata", {})
    labels = metadata.get("labels", {}) or {}
    image = image_from_report(report_obj)
    return {
        "cluster": cluster,
        "namespace": metadata.get("namespace", ""),
        "registry": image.registry,
        "repository": image.repository,
        "image_name": image.image_name,
        "tag": image.tag,
        "digest": image.digest,
        "container": labels.get("trivy-operator.container.name", ""),
        "resource_kind": labels.get("trivy-operator.resource.kind", ""),
        "resource_name": labels.get("trivy-operator.resource.name", ""),
    }


class _StrictFormatter(string.Formatter):
    """str.format without attribute/index access, so templates can never reach into Python objects."""

    def get_field(self, field_name: str, args: Any, kwargs: Any) -> Any:
        if not re.fullmatch(r"[a-z_]+", field_name) or field_name not in TEMPLATE_FIELDS:
            raise ValueError(f"Unknown template field '{field_name}', allowed: {', '.join(TEMPLATE_FIELDS)}")
        return kwargs[field_name], field_name


_FORMATTER = _StrictFormatter()


def render(template: str, values: dict[str, str]) -> str:
    return _FORMATTER.format(template, **values).strip()


def validate_templates(settings: Settings) -> None:
    dummy = dict.fromkeys(TEMPLATE_FIELDS, "x")
    templates = [settings.product_name_template, settings.service_name_template, settings.branch_name_template]
    for rule in settings.namespace_rules:
        templates += [rule.product or "", rule.branch or ""]
    for template in templates:
        if template:
            render(template, dummy)


def namespace_rule(settings: Settings, namespace: str) -> NamespaceRule | None:
    return next((rule for rule in settings.namespace_rules if rule.matches(namespace)), None)


def namespace_enabled(settings: Settings, namespace: str, ns_labels: dict[str, str], ns_annotations: dict[str, str]):
    if namespace in settings.exclude_namespaces:
        return False
    enabled = (ns_labels.get(LABEL_ENABLED) or "").lower()
    if enabled == "false":
        return False
    if settings.require_namespace_label:
        return enabled == "true" or bool(ns_annotations.get(ANNOTATION_PRODUCT))
    return True


def resolve_target(
    settings: Settings,
    values: dict[str, str],
    ns_labels: dict[str, str],
    ns_annotations: dict[str, str],
) -> Target | None:
    """Return the SecObserve target for a report, or None if the namespace is not handled."""
    if not namespace_enabled(settings, values["namespace"], ns_labels, ns_annotations):
        return None

    # precedence: namespace annotation > first matching NAMESPACE_RULES entry > global default
    rule = namespace_rule(settings, values["namespace"])
    product_template = rule.product if rule and rule.product is not None else settings.product_name_template
    default_group = rule.product_group if rule and rule.product_group is not None else settings.product_group
    branch_template = rule.branch if rule and rule.branch is not None else settings.branch_name_template

    product = (ns_annotations.get(ANNOTATION_PRODUCT) or "").strip() or render(product_template, values)
    group = (ns_annotations.get(ANNOTATION_PRODUCT_GROUP) or default_group or "").strip()
    branch = (ns_annotations.get(ANNOTATION_BRANCH) or "").strip()
    if not branch and branch_template:
        branch = render(branch_template, values)
    service = render(settings.service_name_template, values)

    if not product or not service:
        return None
    return Target(product=product[:255], product_group=group, branch=branch[:255], service=service[:255])


def upload_filename(settings: Settings, target: Target) -> str:
    """Stable file name per service: SecObserve resolves findings that vanish between two uploads of it."""
    safe_service = re.sub(r"[^A-Za-z0-9._-]+", "-", target.service).strip("-") or "service"
    return f"{settings.filename_prefix}{safe_service}.cdx.json"[:255]
