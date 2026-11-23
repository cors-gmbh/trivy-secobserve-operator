"""CVEs of PHP itself, straight from the CVE records that php.net publishes (via the NVD API).

Trivy matches the PHP runtime (``pkg:bitnami/php`` from the SBOM that our images carry) against the Bitnami
vulnerability DB, which adds new PHP CVEs by hand, so far 1 to 6 days after php.net published them. php.net, as CNA,
puts the affected version ranges into the CVE record right away (``affected``), and the NVD API serves them
minutes later, long before the NVD's own analysis (CPE configurations). This module reads those ranges and matches
PHP versions against them; the converter adds the matches to the CycloneDX document, unless Trivy reports the CVE
already.
"""

from __future__ import annotations

import logging
import re
import threading
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import unquote

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PHP_CNA = "security@php.net"

Version = tuple[int, ...]

_VERSION = re.compile(r"^\d+(?:\.\d+)*")
# free text ranges of older records: "8.1.x < 8.1.30", "8.1.x below 8.1.30 and 8.2.x below 8.2.25"
_TEXT_RANGE = re.compile(r"(\d+(?:\.\d+)*)\.[x*]\s*(?:<|below)\s*(\d+(?:\.\d+)+)", re.IGNORECASE)


def parse_version(value: str | None) -> Version | None:
    """``8.3.36`` -> (8, 3, 36). Suffixes (``RC1``, ``*``) are ignored; None if there is no leading number."""
    match = _VERSION.match((value or "").strip())
    return tuple(int(part) for part in match.group(0).split(".")) if match else None


def _pad(version: Version) -> Version:
    return version + (0,) * (3 - len(version)) if len(version) < 3 else version


@dataclass(frozen=True)
class VersionRange:
    start: Version  # inclusive
    end: Version | None = None
    end_inclusive: bool = False

    def contains(self, version: Version) -> bool:
        version = _pad(version)
        if version < _pad(self.start):
            return False
        if self.end is None:
            return version == _pad(self.start)
        return version <= _pad(self.end) if self.end_inclusive else version < _pad(self.end)

    @property
    def fixed(self) -> str:
        """The first fixed version (``lessThan``), empty if unknown."""
        return ".".join(map(str, self.end)) if self.end and not self.end_inclusive else ""


def _ranges(entry: dict[str, Any]) -> list[VersionRange]:
    """One entry of ``affectedData[].versions`` in any of the shapes php.net used over the years."""
    if (entry.get("status") or "affected") != "affected":
        return []
    raw_start = str(entry.get("version") or "").strip()
    text_ranges = _TEXT_RANGE.findall(raw_start)
    if text_ranges and not entry.get("lessThan") and not entry.get("lessThanOrEqual"):
        return [VersionRange(parse_version(s) or (0,), parse_version(e)) for s, e in text_ranges]

    # "8.3.*" / "8.3.x" / "8.3.X": from the start of that branch
    start = parse_version(raw_start.rstrip(".*xX"))
    if start is None:
        return []
    less_than = entry.get("lessThan")
    less_equal = entry.get("lessThanOrEqual")
    if less_than not in (None, "", "*"):
        end = parse_version(str(less_than))
        return [VersionRange(start, end)] if end else []
    if less_equal not in (None, "", "*"):
        end = parse_version(str(less_equal))
        return [VersionRange(start, end, end_inclusive=True)] if end else []
    if less_than == "*" or less_equal == "*":
        return []  # "everything from start on" is not a statement about a PHP release we could act on
    if raw_start.endswith(("*", "x", "X")):
        branch = start
        return [VersionRange(branch, branch[:-1] + (branch[-1] + 1,))]
    # A single version without range: in the only records that use it (CVE-2019-11039/-11040) it is the first
    # *fixed* version ("7.1.x below 7.1.30" in the description). The NVD's ranges cover them.
    return []


@dataclass(frozen=True)
class Rating:
    method: str  # CycloneDX: CVSSv4 | CVSSv31 | CVSSv3 | CVSSv2
    score: float
    severity: str
    vector: str


@dataclass(frozen=True)
class Advisory:
    id: str
    description: str
    ranges: tuple[VersionRange, ...]
    published: str = ""
    updated: str = ""
    ratings: tuple[Rating, ...] = ()
    references: tuple[str, ...] = ()

    def affects(self, version: Version) -> bool:
        return any(r.contains(version) for r in self.ranges)

    def fixed_for(self, version: Version) -> str:
        return next((r.fixed for r in self.ranges if r.contains(version) and r.fixed), "")


_CVSS = (("cvssMetricV40", "CVSSv4"), ("cvssMetricV31", "CVSSv31"), ("cvssMetricV30", "CVSSv3"))


def _ratings(metrics: dict[str, Any]) -> tuple[Rating, ...]:
    ratings = []
    for key, method in _CVSS:
        entries = metrics.get(key) or []
        # the CNA's own score first (php.net), then whatever the NVD added
        entries = sorted(entries, key=lambda m: m.get("source") != PHP_CNA)
        for metric in entries[:1]:
            data = metric.get("cvssData") or {}
            score = data.get("baseScore")
            if isinstance(score, int | float):
                severity = str(data.get("baseSeverity") or metric.get("baseSeverity") or "unknown").lower()
                ratings.append(Rating(method, float(score), severity, str(data.get("vectorString") or "")))
    return tuple(ratings)


def _cpe_ranges(cve: dict[str, Any]) -> list[VersionRange]:
    """Ranges of the NVD's analysis (CPE configurations), once there is one. They complete the CNA data at times,
    e.g. CVE-2026-109618: php.net lists 8.2 and newer, the NVD 7.3.0 to 8.2.35 (8.1 is end of life, but affected)."""
    ranges = []
    for configuration in cve.get("configurations") or []:
        for node in configuration.get("nodes") or []:
            if node.get("negate"):
                continue
            for match in node.get("cpeMatch") or []:
                criteria = str(match.get("criteria") or "")
                if not match.get("vulnerable") or not criteria.startswith("cpe:2.3:a:php:php:"):
                    continue
                exact = criteria.split(":")[5] if len(criteria.split(":")) > 5 else "*"
                if exact not in ("*", "-"):
                    if version := parse_version(exact):
                        ranges.append(VersionRange(version))
                    continue
                if match.get("versionStartExcluding"):
                    continue  # not used for PHP so far
                start = parse_version(match.get("versionStartIncluding")) or (0,)
                if end := parse_version(match.get("versionEndExcluding")):
                    ranges.append(VersionRange(start, end))
                elif end := parse_version(match.get("versionEndIncluding")):
                    ranges.append(VersionRange(start, end, end_inclusive=True))
    return ranges


def advisory_from_nvd(cve: dict[str, Any]) -> Advisory | None:
    """An NVD API 2.0 ``cve`` object -> Advisory with the version ranges of PHP itself: those php.net published in
    the CVE record (there right away) plus those of the NVD's analysis (days to weeks later)."""
    ranges: list[VersionRange] = []
    for affected in cve.get("affected") or []:
        if affected.get("source") != PHP_CNA:
            continue
        for data in affected.get("affectedData") or []:
            if str(data.get("product") or "").strip().lower() != "php":
                continue  # e.g. "PHP Imagick extension"
            for entry in data.get("versions") or []:
                ranges.extend(_ranges(entry))
    ranges.extend(r for r in _cpe_ranges(cve) if r not in ranges)
    if not ranges:
        return None
    description = next((d.get("value", "") for d in cve.get("descriptions") or [] if d.get("lang") == "en"), "").strip()
    references = tuple(dict.fromkeys(r["url"] for r in cve.get("references") or [] if r.get("url")))
    return Advisory(
        id=cve.get("id", ""),
        description=description or cve.get("id", ""),
        ranges=tuple(ranges),
        published=cve.get("published", "") or "",
        updated=cve.get("lastModified", "") or "",
        ratings=_ratings(cve.get("metrics") or {}),
        references=references,
    )


def php_version_of(component: dict[str, Any]) -> Version | None:
    """The PHP version of an SBOM component ``pkg:bitnami/php@<version>`` (written by pimcore-docker's
    generate-sbom), None for anything else."""
    purl = str(component.get("purl") or "")
    if not purl.startswith("pkg:bitnami/php@"):
        return None
    return parse_version(unquote(purl.split("@", 1)[1].split("?", 1)[0].split("#", 1)[0]))


def _session() -> requests.Session:
    session = requests.Session()
    # The NVD asks clients to back off (rate limit 5 requests / 30 s without API key) and answers 503 at times.
    retry = Retry(
        total=4,
        backoff_factor=6,
        status_forcelist=(403, 429, 500, 502, 503, 504),
        allowed_methods=frozenset({"GET"}),
    )
    session.mount("https://", HTTPAdapter(max_retries=retry))
    session.mount("http://", HTTPAdapter(max_retries=retry))
    return session


@dataclass
class PhpAdvisoryFeed:
    """All CVE records of the CNA php.net, refreshed periodically. Thread-safe."""

    api_url: str = NVD_API_URL
    api_key: str = field(default="", repr=False)
    # the NVD API is slow at times (60 s were not always enough for the ~120 php.net records)
    timeout: int = 180
    session: requests.Session = field(default_factory=lambda: _session(), repr=False)
    advisories: tuple[Advisory, ...] = ()
    loaded: bool = False
    last_error: str = ""
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def refresh(self) -> bool:
        """Fetch all php.net CVEs. True if the set of advisories (or a range/rating of one) changed.

        On errors the previous advisories stay in place and the exception is raised."""
        headers = {"apiKey": self.api_key} if self.api_key else {}
        advisories: list[Advisory] = []
        start, total = 0, None
        try:
            while total is None or start < total:
                response = self.session.get(
                    self.api_url,
                    params={"sourceIdentifier": PHP_CNA, "startIndex": start, "resultsPerPage": 2000},
                    headers=headers,
                    timeout=self.timeout,
                )
                response.raise_for_status()
                page = response.json()
                total = int(page.get("totalResults") or 0)
                items = page.get("vulnerabilities") or []
                for item in items:
                    advisory = advisory_from_nvd(item.get("cve") or {})
                    if advisory:
                        advisories.append(advisory)
                if not items:
                    break
                start += len(items)
        except Exception as exc:
            with self._lock:
                self.last_error = str(exc)[:500]
            raise
        advisories.sort(key=lambda a: a.id)
        with self._lock:
            changed = self._signature(advisories) != self._signature(self.advisories)
            self.advisories, self.loaded, self.last_error = tuple(advisories), True, ""
        logger.info("Loaded %s PHP advisories from the NVD API (changed: %s)", len(advisories), changed)
        return changed

    @staticmethod
    def _signature(advisories: Any) -> list[tuple[Any, ...]]:
        return [(a.id, a.ranges, a.ratings) for a in advisories]

    def match(self, version: Version) -> list[Advisory]:
        with self._lock:
            advisories = self.advisories
        return [a for a in advisories if a.affects(version)]

    def signature_for(self, version: Version) -> tuple[str, ...]:
        """The CVE ids that affect a version: a re-upload is due when they change."""
        return tuple(a.id for a in self.match(version))
