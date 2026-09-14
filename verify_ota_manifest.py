#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
TOP_LEVEL_KEYS = {"schema_version", "product_id", "artifact_type", "version", "artifact", "checksum_file"}
ARTIFACT_KEYS = {"path", "size_bytes", "sha256", "source_commit", "source_blob_sha"}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def load_manifest(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    require(isinstance(value, dict), "manifest must be an object")
    require(set(value) == TOP_LEVEL_KEYS, f"manifest keys mismatch: {sorted(value)}")
    require(value["schema_version"] == 1, "unsupported schema_version")
    require(isinstance(value["product_id"], str) and value["product_id"], "product_id is required")
    require(value["artifact_type"] == "whole-device-ota", "artifact_type must be whole-device-ota")
    require(isinstance(value["version"], str) and value["version"], "version is required")
    artifact = value["artifact"]
    require(isinstance(artifact, dict) and set(artifact) == ARTIFACT_KEYS, "artifact keys mismatch")
    require(isinstance(artifact["size_bytes"], int) and artifact["size_bytes"] > 0, "size_bytes must be positive integer")
    require(isinstance(artifact["sha256"], str) and SHA256_RE.fullmatch(artifact["sha256"]), "sha256 must be lowercase 64-hex")
    require(isinstance(artifact["source_commit"], str) and GIT_SHA_RE.fullmatch(artifact["source_commit"]), "source_commit must be lowercase 40-hex")
    require(isinstance(artifact["source_blob_sha"], str) and GIT_SHA_RE.fullmatch(artifact["source_blob_sha"]), "source_blob_sha must be lowercase 40-hex")
    require(isinstance(value["checksum_file"], str) and value["checksum_file"], "checksum_file is required")
    return value


def safe_relative(root: Path, raw: str) -> Path:
    relative = Path(raw)
    require(not relative.is_absolute(), f"absolute paths are forbidden: {raw}")
    require(".." not in relative.parts, f"path traversal is forbidden: {raw}")
    root = root.resolve()
    resolved = (root / relative).resolve()
    require(resolved == root or root in resolved.parents, f"path escapes root: {raw}")
    return resolved


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_checksum_file(path: Path, artifact_path: str, expected_sha: str) -> None:
    require(path.is_file(), f"checksum file missing: {path}")
    matches = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        require(len(parts) >= 2, f"malformed checksum line: {raw}")
        sha = parts[0]
        name = parts[-1].lstrip("*")
        if name == artifact_path:
            matches.append(sha)
    require(matches, f"checksum file has no entry for {artifact_path}")
    require(len(matches) == 1, f"checksum file has duplicate entries for {artifact_path}")
    require(matches[0] == expected_sha, "checksum file SHA does not match manifest")


def verify(manifest_path: Path, root: Path) -> dict:
    manifest = load_manifest(manifest_path)
    artifact = manifest["artifact"]
    artifact_path = safe_relative(root, artifact["path"])
    require(artifact_path.is_file(), f"OTA artifact missing: {artifact_path}")
    actual_size = artifact_path.stat().st_size
    require(actual_size == artifact["size_bytes"], f"size mismatch: expected={artifact['size_bytes']} actual={actual_size}")
    actual_sha = file_sha256(artifact_path)
    require(actual_sha == artifact["sha256"], f"SHA-256 mismatch: expected={artifact['sha256']} actual={actual_sha}")
    checksum_path = safe_relative(root, manifest["checksum_file"])
    verify_checksum_file(checksum_path, artifact["path"], artifact["sha256"])
    return {
        "schema_version": 1,
        "status": "PASS",
        "product_id": manifest["product_id"],
        "version": manifest["version"],
        "artifact_path": artifact["path"],
        "size_bytes": actual_size,
        "sha256": actual_sha,
        "source_commit": artifact["source_commit"],
        "source_blob_sha": artifact["source_blob_sha"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify a PCR02 OTA artifact against its machine-readable manifest")
    parser.add_argument("manifest", nargs="?", type=Path, default=Path("ota-manifest.v1.json"))
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        result = verify(args.manifest, args.root)
    except Exception as exc:
        print(f"OTA manifest verification FAIL: {exc}", file=sys.stderr)
        return 2
    rendered = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
