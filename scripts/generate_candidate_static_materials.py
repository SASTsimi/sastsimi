"""Generate or verify the deterministic candidate static-material manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MATERIAL_ROOT = ROOT / "config" / "static-analysis" / "candidate-v1"
MANIFEST = MATERIAL_ROOT / "manifest.json"


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def build_manifest() -> dict[str, object]:
    """Return a timestamp-free manifest for every candidate material file."""

    files: list[dict[str, object]] = []
    paths = sorted(
        MATERIAL_ROOT.rglob("*"),
        key=lambda path: path.relative_to(MATERIAL_ROOT).as_posix(),
    )
    for path in paths:
        if not path.is_file() or path == MANIFEST:
            continue
        relative = path.relative_to(MATERIAL_ROOT).as_posix()
        data = path.read_bytes()
        files.append(
            {
                "path": relative,
                "sha256": hashlib.sha256(data).hexdigest(),
                "size_bytes": len(data),
            }
        )
    return {
        "schema_version": 1,
        "material_set": "sastsimi-static-candidate-v1",
        "status": "CANDIDATE",
        "production_ready": False,
        "files": files,
        "material_set_sha256": hashlib.sha256(_canonical_bytes(files)).hexdigest(),
    }


def _render_manifest() -> bytes:
    return (
        json.dumps(build_manifest(), ensure_ascii=False, sort_keys=True, indent=2)
        + "\n"
    ).encode("utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail instead of rewriting when manifest.json is stale",
    )
    args = parser.parse_args()
    expected = _render_manifest()
    if args.check:
        if not MANIFEST.is_file() or MANIFEST.read_bytes() != expected:
            print(
                "candidate static-material manifest is missing or stale",
                file=sys.stderr,
            )
            return 1
        return 0
    MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST.write_bytes(expected)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
