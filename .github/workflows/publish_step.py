#!/usr/bin/env python3
"""Publish only the configs that passed verification.

The collector writes every config it scraped to output/, which is then
published verbatim. That makes the verification pipeline decorative: the
expensive four-stage check runs, writes verify-output/, and the result is
never shipped. This rebuilds the published files from the verified subset
instead, keeping the same layout main.py produces so clients see no
difference.

Kept as a script rather than inline in the workflow so it can be tested.
"""
import base64
import json
import sys
from collections import defaultdict
from pathlib import Path

VERIFIED = Path("verify-output/enriched-configs.json")
OUTPUT = Path("output")
UNKNOWN_COUNTRY = "ZZ"


def load_records(path: Path) -> list[dict]:
    data = json.loads(path.read_text())
    records = data["configs"] if isinstance(data, dict) else data
    return [r for r in records if r.get("stages", {}).get("https", {}).get("passed")]


def country_of(record: dict) -> str:
    """Two-letter country code, or ZZ when it is missing or malformed."""
    code = (record.get("country") or "").strip().upper()[:2]
    return code if code.isalpha() else UNKNOWN_COUNTRY


def write_list(name: str, lines: list[str]) -> None:
    """Write plain and base64 mirrors, matching main.py's convention."""
    unique = sorted(set(lines))
    if not unique:
        Path(name).unlink(missing_ok=True)
        return
    Path(name).write_text("\n".join(unique) + "\n", encoding="utf-8")
    Path(name).with_name(Path(name).name.replace(".txt", ".base64.txt")).write_text(
        "\n".join(base64.b64encode(l.encode()).decode() for l in unique) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    if not VERIFIED.exists():
        print(f"missing {VERIFIED}", file=sys.stderr)
        return 1

    records = load_records(VERIFIED)
    if not records:
        # Publishing an empty database would break every consumer, and it
        # also means verification broke, so fail loudly instead.
        print("no config passed verification; refusing to publish an empty database",
              file=sys.stderr)
        return 1

    by_country: dict[str, list[str]] = defaultdict(list)
    for record in records:
        by_country[country_of(record)].append(record["uri"])

    (OUTPUT / "countries").mkdir(parents=True, exist_ok=True)
    write_list(str(OUTPUT / "all.txt"), [r["uri"] for r in records])
    for country, uris in sorted(by_country.items()):
        write_list(str(OUTPUT / "countries" / f"{country}.txt"), uris)

    manifest_path = OUTPUT / "manifest.json"
    manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {}
    manifest.setdefault("stats", {})
    manifest["stats"]["verified_survivors"] = len(records)
    manifest["stats"]["verified_countries"] = len(by_country)
    manifest["files"] = {
        "all": "all.txt",
        "all_base64": "all.base64.txt",
        "countries": "countries/",
        "enriched": "enriched-configs.json",
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")

    # The stage data is the most useful artifact, so ship it too.
    (OUTPUT / "enriched-configs.json").write_text(
        json.dumps(json.loads(VERIFIED.read_text()), indent=2, ensure_ascii=False) + "\n"
    )

    print(f"Published {len(records)} verified configs across {len(by_country)} countries")
    return 0


if __name__ == "__main__":
    sys.exit(main())
