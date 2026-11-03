"""Validate WIDS-AI NDJSON events with an external NanoSIEM schema module."""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from datetime import datetime
from pathlib import Path
from types import ModuleType
from typing import Any


def load_schema(path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location("nanosiem_schema", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to create import spec for {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    if not hasattr(module, "NormalizedEvent"):
        raise RuntimeError("Schema module has no NormalizedEvent")
    return module


def convert_event(payload: dict[str, Any]) -> dict[str, Any]:
    event = dict(payload)
    for key in ("timestamp", "ingested_at"):
        value = event.get(key)
        if isinstance(value, str):
            event[key] = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return event


def get_field(event: Any, schema: ModuleType, field: str) -> Any:
    method = getattr(event, "get_field", None)
    if callable(method):
        return method(field)
    module_method = getattr(schema, "get_field", None)
    if callable(module_method):
        return module_method(event, field)
    if hasattr(event, field):
        return getattr(event, field)
    current: Any = event
    for part in field.split("."):
        current = current[part] if isinstance(current, dict) else getattr(current, part)
    return current


def validate(schema_path: Path, file_path: Path, checks: list[str]) -> int:
    schema = load_schema(schema_path)
    failures = 0
    lines = 0
    with file_path.open("r", encoding="utf-8", newline="") as handle:
        for line_number, line in enumerate(handle, 1):
            lines += 1
            try:
                payload = json.loads(line)
                if not isinstance(payload, dict):
                    raise ValueError("line is not a JSON object")
                event = schema.NormalizedEvent(**convert_event(payload))
                for field in checks:
                    get_field(event, schema, field)
                print(f"PASS line {line_number}")
            except Exception as exc:
                failures += 1
                print(f"FAIL line {line_number}: {type(exc).__name__}: {exc}")
    if lines == 0:
        print("FAIL file contains no events")
        return 1
    print(f"{'PASS' if failures == 0 else 'FAIL'} {lines - failures}/{lines} events")
    return 0 if failures == 0 else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--schema-file", type=Path, required=True)
    parser.add_argument("--file", type=Path, required=True)
    parser.add_argument(
        "--field",
        action="append",
        dest="fields",
        default=None,
        help="Field to resolve with get_field; defaults cover program, family, technique, severity",
    )
    args = parser.parse_args(argv)
    checks = args.fields or [
        "program",
        "fields.wids_family",
        "fields.mitre_technique",
        "severity",
    ]
    return validate(args.schema_file, args.file, checks)


if __name__ == "__main__":
    sys.exit(main())
