#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

ALLOWED_HOSTS = {"raw.githubusercontent.com"}
CHUNK_SIZE = 1024 * 1024


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def validate_sources(value: dict, manifest: dict) -> list[dict]:
    require(isinstance(value, dict), "download sources must be an object")
    require(set(value) == {"schema_version", "product_id", "version", "sources"}, "download source keys mismatch")
    require(value["schema_version"] == 1, "unsupported download source schema")
    require(value["product_id"] == manifest["product_id"], "download source product_id mismatch")
    require(value["version"] == manifest["version"], "download source version mismatch")
    sources = value["sources"]
    require(isinstance(sources, list) and sources, "at least one download source is required")
    ids: set[str] = set()
    for item in sources:
        require(isinstance(item, dict), "download source must be an object")
        require(set(item) == {"id", "url", "require_final_https"}, "download source item keys mismatch")
        require(isinstance(item["id"], str) and item["id"], "download source id is required")
        require(item["id"] not in ids, f"duplicate download source id: {item['id']}")
        ids.add(item["id"])
        parsed = urllib.parse.urlparse(item["url"])
        require(parsed.scheme in {"http", "https"}, f"unsupported URL scheme: {parsed.scheme}")
        require(parsed.hostname in ALLOWED_HOSTS, f"download host is not allowlisted: {parsed.hostname}")
        require(parsed.username is None and parsed.password is None, "URL credentials are forbidden")
        require(parsed.fragment == "", "URL fragments are forbidden")
        require(isinstance(item["require_final_https"], bool), "require_final_https must be boolean")
    return sources


def download_once(url: str, expected_size: int, timeout: int) -> tuple[int, str, str, int]:
    request = urllib.request.Request(url, headers={"User-Agent": "pcr02-ota-download-verifier/1"})
    digest = hashlib.sha256()
    total = 0
    with urllib.request.urlopen(request, timeout=timeout) as response:
        status = int(getattr(response, "status", 200))
        final_url = response.geturl()
        require(status == 200, f"unexpected final HTTP status: {status}")
        while True:
            chunk = response.read(CHUNK_SIZE)
            if not chunk:
                break
            total += len(chunk)
            require(total <= expected_size, f"download exceeded expected size: {total} > {expected_size}")
            digest.update(chunk)
    return total, digest.hexdigest(), final_url, status


def verify_source(source: dict, artifact: dict, retries: int, timeout: int) -> dict:
    last_error: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            size, sha256, final_url, status = download_once(source["url"], artifact["size_bytes"], timeout)
            require(size == artifact["size_bytes"], f"size mismatch: expected={artifact['size_bytes']} actual={size}")
            require(sha256 == artifact["sha256"], f"SHA-256 mismatch: expected={artifact['sha256']} actual={sha256}")
            parsed_final = urllib.parse.urlparse(final_url)
            require(parsed_final.hostname in ALLOWED_HOSTS, f"final download host is not allowlisted: {parsed_final.hostname}")
            if source["require_final_https"]:
                require(parsed_final.scheme == "https", f"final URL is not HTTPS: {final_url}")
            return {
                "id": source["id"],
                "requested_url": source["url"],
                "final_url": final_url,
                "http_status": status,
                "size_bytes": size,
                "sha256": sha256,
                "attempts": attempt,
                "status": "PASS",
            }
        except Exception as exc:
            last_error = exc
            if attempt < retries:
                time.sleep(attempt)
    assert last_error is not None
    raise ValueError(f"download source {source['id']} failed after {retries} attempts: {last_error}")


def verify(manifest_path: Path, sources_path: Path, retries: int, timeout: int) -> dict:
    manifest = load_json(manifest_path)
    artifact = manifest["artifact"]
    require(isinstance(artifact["size_bytes"], int) and artifact["size_bytes"] > 0, "manifest size_bytes invalid")
    require(isinstance(artifact["sha256"], str) and len(artifact["sha256"]) == 64, "manifest sha256 invalid")
    sources = validate_sources(load_json(sources_path), manifest)
    results = [verify_source(item, artifact, retries, timeout) for item in sources]
    return {
        "schema_version": 1,
        "status": "PASS",
        "product_id": manifest["product_id"],
        "version": manifest["version"],
        "artifact_sha256": artifact["sha256"],
        "artifact_size_bytes": artifact["size_bytes"],
        "source_commit": artifact["source_commit"],
        "sources": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify PCR02 OTA direct-download paths against the canonical artifact manifest")
    parser.add_argument("--manifest", type=Path, default=Path("ota-manifest.v1.json"))
    parser.add_argument("--sources", type=Path, default=Path("download-sources.v1.json"))
    parser.add_argument("--output", type=Path)
    parser.add_argument("--retries", type=int, default=3)
    parser.add_argument("--timeout", type=int, default=60)
    args = parser.parse_args()
    try:
        require(1 <= args.retries <= 5, "retries must be between 1 and 5")
        require(5 <= args.timeout <= 300, "timeout must be between 5 and 300 seconds")
        result = verify(args.manifest, args.sources, args.retries, args.timeout)
    except Exception as exc:
        print(f"OTA download verification FAIL: {exc}", file=sys.stderr)
        return 2
    rendered = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
