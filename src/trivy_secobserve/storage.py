"""Archive the generated CycloneDX files (GCS bucket and/or local directory).

The archive is append-only: the file name contains a hash of the content and existing objects are never overwritten.
An operator restart or a re-upload of the same scan therefore writes nothing new, a changed document (e.g. the SBOM
arrived later) is a new object, and the GCS service account only needs `roles/storage.objectCreator` (overwriting
would also need `storage.objects.delete`).
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from pathlib import Path
from typing import Any, Protocol

from .config import Settings
from .mapping import ImageRef, Target

logger = logging.getLogger(__name__)

CONTENT_TYPE = "application/vnd.cyclonedx+json"


class Storage(Protocol):
    def store(self, path: str, data: bytes) -> str | None: ...


def _safe(part: str) -> str:
    return re.sub(r"[^A-Za-z0-9._@:-]+", "_", part).strip("_") or "_"


def content_hash(bom: dict[str, Any]) -> str:
    """Hash of a CycloneDX document without its (random) serial number: same scan, same hash."""
    stable = {k: v for k, v in bom.items() if k != "serialNumber"}
    return hashlib.sha256(json.dumps(stable, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def object_path(
    settings: Settings, namespace: str, target: Target, image: ImageRef, timestamp: str, digest: str = ""
) -> str:
    """<prefix>/<cluster>/<namespace>/<service>/<image-digest-or-tag>/<timestamp>-<content-hash>.cdx.json"""
    version = image.digest.replace("sha256:", "sha256-") if image.digest else (image.tag or "unknown")
    stamp = re.sub(r"[^0-9TZ]", "", timestamp) or "unknown"
    name = f"{stamp}-{digest[:12]}.cdx.json" if digest else f"{stamp}.cdx.json"
    parts = [settings.gcs_prefix, settings.cluster_name, namespace, target.service, version, name]
    return "/".join(_safe(p) for p in parts if p)


class NoopStorage:
    def store(self, path: str, data: bytes) -> str | None:
        return None


class LocalStorage:
    def __init__(self, directory: str) -> None:
        self.directory = Path(directory)

    def store(self, path: str, data: bytes) -> str | None:
        target = (self.directory / path).resolve()
        if not str(target).startswith(str(self.directory.resolve())):
            raise ValueError(f"Refusing to write outside of {self.directory}: {path}")
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.exists():  # append-only, like the GCS backend
            target.write_bytes(data)
        return str(target)


class GCSStorage:
    def __init__(self, bucket: str) -> None:
        from google.cloud import storage  # optional dependency, only needed when GCS_BUCKET is set

        self._bucket = storage.Client().bucket(bucket)
        self.bucket_name = bucket

    def store(self, path: str, data: bytes) -> str | None:
        from google.api_core.exceptions import PreconditionFailed

        blob = self._bucket.blob(path)
        try:
            # create only: never overwrite (needs no storage.objects.delete); the name contains the content hash
            blob.upload_from_string(data, content_type=CONTENT_TYPE, if_generation_match=0)
        except PreconditionFailed:
            logger.debug("gs://%s/%s is already archived", self.bucket_name, path)
        return f"gs://{self.bucket_name}/{path}"


class MultiStorage:
    def __init__(self, backends: list[Storage]) -> None:
        self.backends = backends

    def store(self, path: str, data: bytes) -> str | None:
        locations = [location for backend in self.backends if (location := backend.store(path, data))]
        return ", ".join(locations) if locations else None


def build_storage(settings: Settings) -> Storage:
    backends: list[Storage] = []
    if settings.gcs_bucket:
        backends.append(GCSStorage(settings.gcs_bucket))
    if settings.local_storage_dir:
        backends.append(LocalStorage(settings.local_storage_dir))
    if not backends:
        return NoopStorage()
    return backends[0] if len(backends) == 1 else MultiStorage(backends)
