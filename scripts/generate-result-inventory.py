"""Generate/check the canonical result-owner inventory from the source registry."""

import argparse
import json
import re
from pathlib import Path

from sastsimi.contracts.result_registry import RESULT_REGISTRY


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    args = parser.parse_args()
    architecture = (
        args.root / "docs/architecture-v5/08-lightweight-data-contracts.md"
    ).read_text(encoding="utf-8")
    paragraph = next(
        line for line in architecture.splitlines() if line.startswith("- 핵심 registry")
    )
    expected = {
        kind: (model, owner)
        for kind, model, owner in re.findall(
            r"`(\w+) -> (\w+)(?:\(role=\w+\))? -> (\w+)`", paragraph
        )
    }
    actual = {
        kind: (binding.schema_name, binding.owner.value)
        for kind, binding in RESULT_REGISTRY.items()
    }
    if expected != actual:
        raise SystemExit("Canonical result-owner inventory drift")
    document = {
        "registry_version": 1,
        "results": [
            {
                "result_kind": kind,
                "schema_name": binding.schema_name,
                "source_model": f"{binding.model.__module__}.{binding.model.__name__}",
                "owner": binding.owner.value,
                "schema": f"generated/{kind}/1.schema.json",
            }
            for kind, binding in sorted(RESULT_REGISTRY.items())
        ],
    }
    data = (
        json.dumps(document, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    ).encode("utf-8")
    target = args.root / "schemas/result-owner-inventory.json"
    if args.check:
        if not target.exists() or target.read_bytes() != data:
            raise SystemExit("Generated result-owner inventory drift")
    else:
        target.write_bytes(data)
    print(
        f"Result inventory: {len(actual)} canonical kinds, "
        "source models and unique owners verified"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
