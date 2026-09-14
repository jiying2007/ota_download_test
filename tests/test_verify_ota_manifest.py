from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import verify_ota_manifest as verifier


def manifest_for(path: Path, data: bytes) -> dict:
    return {
        "schema_version": 1,
        "product_id": "PCR02",
        "artifact_type": "whole-device-ota",
        "version": "v-test",
        "artifact": {
            "path": path.name,
            "size_bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "source_commit": "0123456789abcdef0123456789abcdef01234567",
            "source_blob_sha": "89abcdef0123456789abcdef0123456789abcdef"
        },
        "checksum_file": "SHA256SUMS.txt"
    }


class VerifyOtaManifestTests(unittest.TestCase):
    def test_valid_manifest_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = b"ota-payload"
            artifact = root / "payload.bin"
            artifact.write_bytes(data)
            manifest = manifest_for(artifact, data)
            manifest_path = root / "manifest.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            (root / "SHA256SUMS.txt").write_text(f"{manifest['artifact']['sha256']}  payload.bin\n", encoding="utf-8")
            result = verifier.verify(manifest_path, root)
            self.assertEqual(result["status"], "PASS")
            self.assertEqual(result["sha256"], manifest["artifact"]["sha256"])

    def test_digest_mismatch_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = b"ota-payload"
            artifact = root / "payload.bin"
            artifact.write_bytes(data)
            manifest = manifest_for(artifact, data)
            manifest["artifact"]["sha256"] = "0" * 64
            manifest_path = root / "manifest.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            (root / "SHA256SUMS.txt").write_text(f"{'0' * 64}  payload.bin\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                verifier.verify(manifest_path, root)

    def test_path_traversal_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = b"ota-payload"
            manifest = manifest_for(root / "payload.bin", data)
            manifest["artifact"]["path"] = "../payload.bin"
            manifest_path = root / "manifest.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "path traversal"):
                verifier.verify(manifest_path, root)

    def test_checksum_file_must_match_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = b"ota-payload"
            artifact = root / "payload.bin"
            artifact.write_bytes(data)
            manifest = manifest_for(artifact, data)
            manifest_path = root / "manifest.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            (root / "SHA256SUMS.txt").write_text(f"{'f' * 64}  payload.bin\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "checksum file SHA"):
                verifier.verify(manifest_path, root)


if __name__ == "__main__":
    unittest.main()
