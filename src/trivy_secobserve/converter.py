"""Merge a Trivy Operator VulnerabilityReport and SbomReport into one CycloneDX document.

The SbomReport already contains a complete CycloneDX BOM (components, dependency graph, licenses). The
VulnerabilityReport lists the vulnerabilities with the package URL of the affected package. Joining both on
the package URL gives SecObserve what a `trivy image --format cyclonedx` scan gives it: vulnerabilities
*with* dependency paths and licenses.
"""

from __future__ import annotations

import copy
import dataclasses
import uuid
from dataclasses import dataclass
from typing import Any

from .mapping import ImageRef, image_from_report

SEVERITIES = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "NONE": "none",
    "INFO": "info",
    "UNKNOWN": "unknown",
}


@dataclass
class ConversionStats:
    components: int = 0
    vulnerabilities: int = 0
    matched_exact: int = 0
    matched_fuzzy: int = 0
    unmatched: int = 0
    sbom_used: bool = False


class _ComponentIndex:
    def __init__(self, bom: dict[str, Any]) -> None:
        self.by_purl: dict[str, str] = {}
        self.by_purl_base: dict[str, str] = {}
        self.by_name_version: dict[tuple[str, str], str] = {}
        self.ambiguous_name_version: set[tuple[str, str]] = set()
        self.count = 0
        root = bom.get("metadata", {}).get("component")
        if root:
            self.add(root)
        for component in bom.get("components", []) or []:
            self.add(component)

    def add(self, component: dict[str, Any]) -> None:
        bom_ref = component.get("bom-ref")
        if bom_ref:
            self.count += 1
            purl = component.get("purl") or ""
            if purl:
                self.by_purl.setdefault(purl, bom_ref)
                self.by_purl_base.setdefault(purl.split("?", 1)[0], bom_ref)
            key = (component.get("name") or "", component.get("version") or "")
            if key[0]:
                if key in self.by_name_version and self.by_name_version[key] != bom_ref:
                    self.ambiguous_name_version.add(key)
                self.by_name_version.setdefault(key, bom_ref)
        for sub_component in component.get("components", []) or []:
            self.add(sub_component)

    def find(self, vulnerability: dict[str, Any]) -> tuple[str | None, str]:
        purl = vulnerability.get("packagePURL") or ""
        if purl and purl in self.by_purl:
            return self.by_purl[purl], "exact"
        if purl and purl.split("?", 1)[0] in self.by_purl_base:
            return self.by_purl_base[purl.split("?", 1)[0]], "fuzzy"
        key = (vulnerability.get("resource") or "", vulnerability.get("installedVersion") or "")
        if key[0] and key in self.by_name_version and key not in self.ambiguous_name_version:
            return self.by_name_version[key], "fuzzy"
        return None, "none"


def _empty_bom(image: ImageRef, scanner: dict[str, Any]) -> dict[str, Any]:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "component": {
                "bom-ref": f"image:{image.name}@{image.digest or image.tag}",
                "type": "container",
                "name": image.name,
            },
            "tools": _tools(scanner),
        },
        "components": [],
        "dependencies": [],
    }


def _tools(scanner: dict[str, Any]) -> dict[str, Any]:
    tool: dict[str, Any] = {"type": "application", "name": (scanner.get("name") or "Trivy").lower()}
    if scanner.get("version"):
        tool["version"] = scanner["version"]
    return {"components": [tool]}


def _ratings(vulnerability: dict[str, Any]) -> list[dict[str, Any]]:
    severity = SEVERITIES.get((vulnerability.get("severity") or "UNKNOWN").upper(), "unknown")
    ratings: list[dict[str, Any]] = [{"source": {"name": "trivy"}, "severity": severity, "method": "other"}]
    score = vulnerability.get("score")
    if isinstance(score, int | float) and not isinstance(score, bool) and score > 0:
        # The Trivy Operator only reports the CVSS v3 base score, without vector.
        ratings.append({"severity": severity, "score": float(score), "method": "CVSSv31", "vector": ""})
    return ratings


def _vulnerability_entry(vulnerability: dict[str, Any], ref: str, index: int) -> dict[str, Any]:
    vulnerability_id = vulnerability.get("vulnerabilityID") or "UNKNOWN"
    title = vulnerability.get("title") or vulnerability_id
    entry: dict[str, Any] = {
        "bom-ref": f"trivy-operator-vuln-{index}",
        "id": vulnerability_id,
        "description": title,
        "ratings": _ratings(vulnerability),
        "affects": [{"ref": ref}],
    }

    links: list[str] = []
    for link in [vulnerability.get("primaryLink"), *(vulnerability.get("links") or [])]:
        if link and link not in links:
            links.append(link)
    if links:
        entry["advisories"] = [{"url": link} for link in links]
        entry["source"] = {"name": "trivy", "url": links[0]}

    installed = vulnerability.get("installedVersion") or ""
    fixed = vulnerability.get("fixedVersion") or ""
    resource = vulnerability.get("resource") or ""
    if fixed:
        entry["recommendation"] = f"Upgrade {resource} from {installed} to {fixed}".replace("  ", " ")
    if vulnerability.get("publishedDate"):
        entry["published"] = vulnerability["publishedDate"]
    if vulnerability.get("lastModifiedDate"):
        entry["updated"] = vulnerability["lastModifiedDate"]

    properties = []
    if vulnerability.get("target"):
        properties.append({"name": "aquasecurity:trivy:Target", "value": vulnerability["target"]})
    if installed:
        properties.append({"name": "aquasecurity:trivy:InstalledVersion", "value": installed})
    if properties:
        entry["properties"] = properties
    return entry


def _synthetic_component(vulnerability: dict[str, Any], existing_refs: set[str]) -> dict[str, Any]:
    purl = vulnerability.get("packagePURL") or ""
    name = vulnerability.get("resource") or purl or "unknown"
    version = vulnerability.get("installedVersion") or ""
    base_ref = f"trivy-operator-component:{purl or f'{name}@{version}'}"
    bom_ref, counter = base_ref, 1
    while bom_ref in existing_refs:
        counter += 1
        bom_ref = f"{base_ref}#{counter}"
    existing_refs.add(bom_ref)
    component: dict[str, Any] = {"bom-ref": bom_ref, "type": "library", "name": name}
    if version:
        component["version"] = version
    if purl:
        component["purl"] = purl
    return component


def merge(
    vulnerability_report: dict[str, Any] | None,
    sbom_report: dict[str, Any] | None,
    extra_properties: dict[str, str] | None = None,
) -> tuple[dict[str, Any], ConversionStats]:
    """Build one CycloneDX BOM from a VulnerabilityReport and/or an SbomReport (Kubernetes objects as dicts)."""
    if vulnerability_report is None and sbom_report is None:
        raise ValueError("At least one of vulnerability_report or sbom_report is required")

    primary = vulnerability_report if vulnerability_report is not None else sbom_report
    assert primary is not None
    image = image_from_report(primary)
    scanner = primary.get("report", {}).get("scanner", {}) or {}
    stats = ConversionStats()

    sbom_bom = (sbom_report or {}).get("report", {}).get("components")
    if isinstance(sbom_bom, dict) and sbom_bom.get("bomFormat") == "CycloneDX":
        bom = copy.deepcopy(sbom_bom)
        stats.sbom_used = True
    else:
        bom = _empty_bom(image, scanner)

    if not str(bom.get("serialNumber", "")).startswith("urn:uuid:"):
        bom["serialNumber"] = f"urn:uuid:{uuid.uuid4()}"
    bom.setdefault("version", 1)
    bom.setdefault("components", [])
    bom.setdefault("dependencies", [])

    metadata = bom.setdefault("metadata", {})
    root = metadata.setdefault("component", {})
    # Keep the bom-ref: the dependency graph points to it. Name without tag, tag as version, so SecObserve
    # recognizes the container image.
    root.setdefault("bom-ref", f"image:{image.name}@{image.digest or image.tag}")
    root["type"] = "container"
    root["name"] = image.name
    if image.tag:
        root["version"] = image.tag
    elif image.digest:
        root["version"] = image.digest
    if not metadata.get("tools"):
        metadata["tools"] = _tools(scanner)
    timestamp = primary.get("report", {}).get("updateTimestamp")
    if timestamp:
        metadata["timestamp"] = timestamp
    properties = metadata.setdefault("properties", [])
    if image.digest:
        properties.append({"name": "trivy-secobserve:image-digest", "value": image.digest})
    for name, value in (extra_properties or {}).items():
        if value:
            properties.append({"name": name, "value": value})

    index = _ComponentIndex(bom)
    existing_refs = {c.get("bom-ref") for c in bom["components"] if c.get("bom-ref")}
    existing_refs.add(root["bom-ref"])

    vulnerabilities: list[dict[str, Any]] = []
    synthetic_refs: list[str] = []
    for position, vulnerability in enumerate(
        (vulnerability_report or {}).get("report", {}).get("vulnerabilities") or []
    ):
        ref, how = index.find(vulnerability)
        if ref is None:
            component = _synthetic_component(vulnerability, existing_refs)
            bom["components"].append(component)
            bom["dependencies"].append({"ref": component["bom-ref"], "dependsOn": []})
            index.add(component)  # further vulnerabilities of the same package reuse it
            ref = component["bom-ref"]
            synthetic_refs.append(ref)
            stats.unmatched += 1
        elif ref in synthetic_refs:
            stats.unmatched += 1
        elif how == "exact":
            stats.matched_exact += 1
        else:
            stats.matched_fuzzy += 1
        vulnerabilities.append(_vulnerability_entry(vulnerability, ref, position))

    if synthetic_refs:
        # Hang packages that are missing in the SBOM below the image, so they still get a dependency path.
        root_dependency = next((d for d in bom["dependencies"] if d.get("ref") == root["bom-ref"]), None)
        if root_dependency is None:
            root_dependency = {"ref": root["bom-ref"], "dependsOn": []}
            bom["dependencies"].append(root_dependency)
        root_dependency.setdefault("dependsOn", []).extend(synthetic_refs)

    bom["vulnerabilities"] = vulnerabilities
    stats.vulnerabilities = len(vulnerabilities)
    stats.components = index.count
    return bom, stats


def combine(parts: list[tuple[dict[str, Any], ConversionStats]]) -> tuple[dict[str, Any], ConversionStats]:
    """Combine the BOMs of several images that map to the same SecObserve service into one document.

    The first BOM is the primary one: its image becomes ``metadata.component``. The root components of the other
    images are added as components, so the dependency paths of their packages still start at their own image.
    Components with the same bom-ref (same package URL) and vulnerabilities with the same id on the same component
    are kept once.
    """
    if not parts:
        raise ValueError("Nothing to combine")
    bom = copy.deepcopy(parts[0][0])
    stats = dataclasses.replace(parts[0][1])
    if len(parts) == 1:
        return bom, stats

    root = bom["metadata"]["component"]
    known_refs = {c.get("bom-ref") for c in bom["components"]} | {root.get("bom-ref")}
    dependencies = {d.get("ref"): d for d in bom["dependencies"]}
    seen_vulnerabilities = {_vulnerability_key(v) for v in bom["vulnerabilities"]}
    images = [_image_label(root)]

    for other, other_stats in parts[1:]:
        other_root = other["metadata"]["component"]
        images.append(_image_label(other_root))
        for component in [other_root, *(other.get("components") or [])]:
            if component.get("bom-ref") not in known_refs:
                known_refs.add(component.get("bom-ref"))
                bom["components"].append(copy.deepcopy(component))
        for dependency in other.get("dependencies") or []:
            existing = dependencies.get(dependency.get("ref"))
            if existing is None:
                dependencies[dependency.get("ref")] = copy.deepcopy(dependency)
                bom["dependencies"].append(dependencies[dependency.get("ref")])
            else:
                depends_on = existing.setdefault("dependsOn", [])
                depends_on.extend(d for d in dependency.get("dependsOn") or [] if d not in depends_on)
        for vulnerability in other.get("vulnerabilities") or []:
            key = _vulnerability_key(vulnerability)
            if key not in seen_vulnerabilities:
                seen_vulnerabilities.add(key)
                bom["vulnerabilities"].append(copy.deepcopy(vulnerability))
        stats.matched_exact += other_stats.matched_exact
        stats.matched_fuzzy += other_stats.matched_fuzzy
        stats.unmatched += other_stats.unmatched
        stats.sbom_used = stats.sbom_used and other_stats.sbom_used

    for position, vulnerability in enumerate(bom["vulnerabilities"]):
        vulnerability["bom-ref"] = f"trivy-operator-vuln-{position}"
    # match statistics of the combined document (shared vulnerabilities are counted once)
    stats.unmatched = sum(
        1
        for v in bom["vulnerabilities"]
        if any(a.get("ref", "").startswith("trivy-operator-component:") for a in v.get("affects") or [])
    )
    matched = len(bom["vulnerabilities"]) - stats.unmatched
    stats.matched_fuzzy = min(stats.matched_fuzzy, matched)
    stats.matched_exact = matched - stats.matched_fuzzy
    bom["metadata"].setdefault("properties", []).append({"name": "trivy-secobserve:images", "value": ", ".join(images)})
    stats.vulnerabilities = len(bom["vulnerabilities"])
    stats.components = len(known_refs)
    return bom, stats


def _vulnerability_key(vulnerability: dict[str, Any]) -> tuple[str, tuple[str, ...]]:
    return vulnerability.get("id", ""), tuple(sorted(a.get("ref", "") for a in vulnerability.get("affects") or []))


def _image_label(root: dict[str, Any]) -> str:
    return f"{root.get('name', '')}:{root.get('version', '')}".rstrip(":")


def empty_bom(scanner_name: str = "trivy") -> dict[str, Any]:
    """A BOM without components and vulnerabilities. Uploading it resolves all findings of a vulnerability check."""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {"tools": {"components": [{"type": "application", "name": scanner_name}]}},
        "components": [],
        "dependencies": [],
        "vulnerabilities": [],
    }
