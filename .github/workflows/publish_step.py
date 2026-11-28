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
import math
import os
import shutil
import sys
from collections import defaultdict
from pathlib import Path

VERIFIED = Path("verify-output/enriched-configs.json")
OUTPUT = Path("output")
UNKNOWN_COUNTRY = "ZZ"
PREVIOUS_PUBLISHED_POOL_ENV = "PREVIOUS_PUBLISHED_POOL_PATH"
MIN_POOL_FRACTION_ENV = "PUBLISH_MIN_POOL_FRACTION"
FORCE_SHRINK_ENV = "FORCE_PUBLISH_SHRINK"
DEFAULT_MIN_POOL_FRACTION = 0.5


def load_records(path: Path) -> list[dict]:
    data = json.loads(path.read_text())
    records = data["configs"] if isinstance(data, dict) else data
    # verify.py writes the speed gate under `stages.download` because this
    # stage carries both throughput and latency.
    required_stages = ("tcp", "download", "https")
    return [
        record for record in records
        if all(record.get("stages", {}).get(stage, {}).get("passed") is True for stage in required_stages)
    ]


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
    encoded = base64.b64encode(("\n".join(unique) + "\n").encode("utf-8")).decode("ascii")
    Path(name).with_name(Path(name).name.replace(".txt", ".base64.txt")).write_text(
        encoded + "\n",
        encoding="utf-8",
    )


def passes_shrink_guard(records: list[dict]) -> bool:
    """Reject a major pool shrink against the previous published feed."""
    try:
        minimum_fraction = float(os.environ.get(MIN_POOL_FRACTION_ENV, DEFAULT_MIN_POOL_FRACTION))
    except (TypeError, ValueError):
        print(f"{MIN_POOL_FRACTION_ENV} must be a number from 0 to 1", file=sys.stderr)
        return False
    if not math.isfinite(minimum_fraction) or not 0 <= minimum_fraction <= 1:
        print(f"{MIN_POOL_FRACTION_ENV} must be a number from 0 to 1", file=sys.stderr)
        return False

    previous_path = Path(os.environ.get(PREVIOUS_PUBLISHED_POOL_ENV, "/tmp/proxy-collector-previous-all.txt"))
    if not previous_path.is_file():
        return True
    previous_count = len({line.strip() for line in previous_path.read_text().splitlines() if line.strip()})
    if previous_count == 0:
        return True

    verified_count = len({record["uri"] for record in records if record.get("uri")})
    below_threshold = verified_count / previous_count < minimum_fraction
    forced = os.environ.get(FORCE_SHRINK_ENV, "").strip().lower() in {"1", "true", "yes"}
    if below_threshold and not forced:
        print(
            f"refusing to publish pool shrink: {verified_count} verified vs {previous_count} previous "
            f"(minimum {minimum_fraction:.0%}); set the workflow_dispatch force input to override",
            file=sys.stderr,
        )
        return False
    if below_threshold and forced:
        print(f"force input accepted; publishing {verified_count} verified configs vs {previous_count} previous")
    return True


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
    if not passes_shrink_guard(records):
        return 1

    by_country: dict[str, list[str]] = defaultdict(list)
    for record in records:
        by_country[country_of(record)].append(record["uri"])

    # main.py already wrote a countries/ dir covering every config it
    # scraped, so that dir holds files for countries that verification just
    # eliminated. Publish from a clean directory, or those stale files ship
    # alongside the verified ones and clients read dead configs as live.
    countries_dir = OUTPUT / "countries"
    if countries_dir.exists():
        shutil.rmtree(countries_dir)
    countries_dir.mkdir(parents=True, exist_ok=True)

    write_list(str(OUTPUT / "all.txt"), [r["uri"] for r in records])
    for country, uris in sorted(by_country.items()):
        write_list(str(countries_dir / f"{country}.txt"), uris)

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
