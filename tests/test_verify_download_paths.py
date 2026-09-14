from __future__ import annotations

import unittest

import verify_download_paths as verifier


MANIFEST = {
    "product_id": "PCR02",
    "version": "v1.1.21",
    "artifact": {
        "size_bytes": 10,
        "sha256": "0" * 64,
        "source_commit": "0" * 40,
    },
}


class VerifyDownloadPathsTests(unittest.TestCase):
    def test_valid_http_https_sources_are_accepted(self):
        value = {
            "schema_version": 1,
            "product_id": "PCR02",
            "version": "v1.1.21",
            "sources": [
                {
                    "id": "https",
                    "url": "https://raw.githubusercontent.com/jiying2007/ota_download_test/main/file.bin",
                    "require_final_https": True,
                },
                {
                    "id": "http-redirect",
                    "url": "http://raw.githubusercontent.com/jiying2007/ota_download_test/main/file.bin",
                    "require_final_https": True,
                },
            ],
        }
        self.assertEqual(len(verifier.validate_sources(value, MANIFEST)), 2)

    def test_untrusted_host_is_rejected(self):
        value = {
            "schema_version": 1,
            "product_id": "PCR02",
            "version": "v1.1.21",
            "sources": [
                {"id": "bad", "url": "https://example.com/file.bin", "require_final_https": True}
            ],
        }
        with self.assertRaisesRegex(ValueError, "not allowlisted"):
            verifier.validate_sources(value, MANIFEST)

    def test_duplicate_source_id_is_rejected(self):
        value = {
            "schema_version": 1,
            "product_id": "PCR02",
            "version": "v1.1.21",
            "sources": [
                {"id": "same", "url": "https://raw.githubusercontent.com/a/b/main/x", "require_final_https": True},
                {"id": "same", "url": "https://raw.githubusercontent.com/a/b/main/y", "require_final_https": True},
            ],
        }
        with self.assertRaisesRegex(ValueError, "duplicate download source id"):
            verifier.validate_sources(value, MANIFEST)


if __name__ == "__main__":
    unittest.main()
