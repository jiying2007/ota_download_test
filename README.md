# OTA download test

PCR02 production vehicle OTA package for validating HTTP/HTTPS direct downloads.

- Version: `v1.1.21`
- File: `ota_pkg_v1.1.21.tar.gz`
- Size: `76,778,472` bytes
- SHA-256: `7687d8058f85271e75ff3726957385afa1618aa2078dc0a6b3215d470af4a4bb`
- Original artifact source commit: `eeb926bd1fff75d2a5d5abb9f0ede9c8f582cc6d`

## Machine-verifiable artifact identity

`ota-manifest.v1.json` is the canonical machine-readable identity for the PCR02 OTA package. It binds product/version, file path, byte size, SHA-256, the original package commit and Git blob identity.

Verify the checked-out package with only the Python standard library:

```sh
python verify_ota_manifest.py ota-manifest.v1.json --root . --output ota-verification-receipt.json
```

The verifier fails closed on malformed identity, path traversal, missing artifact, size mismatch, SHA-256 mismatch, or disagreement with `SHA256SUMS.txt`.

For compatibility with existing shell workflows, the traditional checksum path remains supported:

```sh
sha256sum -c SHA256SUMS.txt
```

CI runs both verifier unit tests and the real 76,778,472-byte package identity check on every PR and push to `main`.

## Direct download URLs

- HTTPS: <https://raw.githubusercontent.com/jiying2007/ota_download_test/main/ota_pkg_v1.1.21.tar.gz>
- HTTP (redirects to HTTPS): <http://raw.githubusercontent.com/jiying2007/ota_download_test/main/ota_pkg_v1.1.21.tar.gz>
