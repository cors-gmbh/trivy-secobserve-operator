import pytest
from google.api_core.exceptions import PreconditionFailed

from trivy_secobserve.storage import GCSStorage, LocalStorage, content_hash


def test_content_hash_ignores_the_random_serial_number():
    bom = {"bomFormat": "CycloneDX", "serialNumber": "urn:uuid:1", "components": [{"name": "a"}]}
    assert content_hash(bom) == content_hash({**bom, "serialNumber": "urn:uuid:2"})
    assert content_hash(bom) != content_hash({**bom, "components": [{"name": "b"}]})


def test_local_storage_never_overwrites(tmp_path):
    storage = LocalStorage(str(tmp_path))
    location = storage.store("a/b.cdx.json", b"first")
    assert storage.store("a/b.cdx.json", b"second") == location
    assert (tmp_path / "a/b.cdx.json").read_bytes() == b"first"


def test_local_storage_stays_in_its_directory(tmp_path):
    with pytest.raises(ValueError):
        LocalStorage(str(tmp_path)).store("../outside.cdx.json", b"x")


class FakeBlob:
    def __init__(self, bucket, name):
        self.bucket, self.name = bucket, name

    def upload_from_string(self, data, content_type=None, if_generation_match=None):
        self.bucket.calls.append(if_generation_match)
        if if_generation_match == 0 and self.name in self.bucket.objects:
            raise PreconditionFailed("412 conditionNotMet")
        self.bucket.objects[self.name] = data


class FakeBucket:
    def __init__(self):
        self.objects, self.calls = {}, []

    def blob(self, name):
        return FakeBlob(self, name)


def test_gcs_storage_creates_only():
    storage = GCSStorage.__new__(GCSStorage)  # skip the real client (needs credentials)
    storage._bucket, storage.bucket_name = FakeBucket(), "archive"
    assert storage.store("x/y.cdx.json", b"first") == "gs://archive/x/y.cdx.json"
    # second store of the same object (operator restart): precondition fails, treated as already archived
    assert storage.store("x/y.cdx.json", b"first") == "gs://archive/x/y.cdx.json"
    assert storage._bucket.objects == {"x/y.cdx.json": b"first"}
    assert storage._bucket.calls == [0, 0]  # always with ifGenerationMatch=0, never an overwrite
