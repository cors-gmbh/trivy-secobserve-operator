"""Command line tools that work without a cluster.

  trivy-secobserve convert --vulnerability-report vr.json [--sbom-report sbom.json] [-o out.cdx.json]
  trivy-secobserve replay --vulnerability-reports vrs.json [--sbom-reports sboms.json] [--namespace-annotation k=v]

`replay` feeds exported reports (`kubectl get vulnerabilityreports -o json` lists) through the same processor
the operator uses, e.g. to backfill SecObserve or to test a configuration.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import logging
import sys
from pathlib import Path
from typing import Any

from .config import Settings
from .converter import merge
from .mapping import validate_templates
from .processor import Processor
from .secobserve import SecObserveClient
from .storage import build_storage


def _load_items(path: str | None) -> list[dict[str, Any]]:
    if not path:
        return []
    data = json.loads(Path(path).read_text())
    return data.get("items", []) if data.get("kind", "").endswith("List") or "items" in data else [data]


class FileReportSource:
    def __init__(
        self,
        vulnerability_reports: list[dict[str, Any]],
        sbom_reports: list[dict[str, Any]],
        namespace_labels: dict[str, str],
        namespace_annotations: dict[str, str],
    ) -> None:
        def key(obj: dict[str, Any]) -> tuple[str, str]:
            return obj["metadata"]["namespace"], obj["metadata"]["name"]

        self.vulnerability_reports = {key(o): o for o in vulnerability_reports}
        self.sbom_reports = {key(o): o for o in sbom_reports}
        self.labels = namespace_labels
        self.annotations = namespace_annotations

    def get_vulnerability_report(self, namespace: str, name: str) -> dict[str, Any] | None:
        return self.vulnerability_reports.get((namespace, name))

    def get_sbom_report(self, namespace: str, name: str) -> dict[str, Any] | None:
        return self.sbom_reports.get((namespace, name))

    def get_namespace_meta(self, namespace: str) -> tuple[dict[str, str], dict[str, str]]:
        return dict(self.labels), dict(self.annotations)


def _pairs(values: list[str]) -> dict[str, str]:
    result = {}
    for value in values:
        if "=" not in value:
            raise SystemExit(f"Expected key=value, got '{value}'")
        k, v = value.split("=", 1)
        result[k] = v
    return result


def cmd_convert(args: argparse.Namespace) -> int:
    vrs, sboms = _load_items(args.vulnerability_report), _load_items(args.sbom_report)
    if args.name:
        vrs = [o for o in vrs if o["metadata"]["name"] == args.name]
        sboms = [o for o in sboms if o["metadata"]["name"] == args.name]
    if len(vrs) > 1 or len(sboms) > 1:
        raise SystemExit("Input contains several reports, select one with --name")
    bom, stats = merge(vrs[0] if vrs else None, sboms[0] if sboms else None)
    output = json.dumps(bom, indent=2)
    if args.output:
        Path(args.output).write_text(output)
    else:
        sys.stdout.write(output + "\n")
    print(json.dumps(dataclasses.asdict(stats)), file=sys.stderr)
    return 0


def cmd_replay(args: argparse.Namespace) -> int:
    settings = Settings.from_env()
    settings = dataclasses.replace(settings, sbom_wait_seconds=0, min_resync_seconds=0)
    settings.validate()
    validate_templates(settings)
    source = FileReportSource(
        _load_items(args.vulnerability_reports),
        _load_items(args.sbom_reports),
        _pairs(args.namespace_label),
        _pairs(args.namespace_annotation),
    )
    client = SecObserveClient(
        settings.secobserve_api_url,
        settings.secobserve_api_token,
        verify_ssl=settings.secobserve_verify_ssl,
        timeout=settings.secobserve_timeout_seconds,
    )
    processor = Processor(settings, client, build_storage(settings), source)
    for report in source.vulnerability_reports.values():
        processor.observe_vulnerability_report("ADDED", report)
    results = processor.run_once()
    failed = 0
    for result in results:
        failed += result.status == "failed"
        print(
            json.dumps(
                {
                    "product": result.target.product,
                    "service": result.target.service,
                    "status": result.status,
                    "detail": result.detail,
                    "response": result.response,
                }
            )
        )
    return 1 if failed else 0


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    parser = argparse.ArgumentParser(prog="trivy-secobserve")
    sub = parser.add_subparsers(dest="command", required=True)

    convert = sub.add_parser("convert", help="Merge a VulnerabilityReport and SbomReport into CycloneDX")
    convert.add_argument("--vulnerability-report")
    convert.add_argument("--sbom-report")
    convert.add_argument("--name", help="Report name, if the input files are lists")
    convert.add_argument("-o", "--output")
    convert.set_defaults(func=cmd_convert)

    replay = sub.add_parser("replay", help="Upload exported reports through the operator logic")
    replay.add_argument("--vulnerability-reports", required=True)
    replay.add_argument("--sbom-reports")
    replay.add_argument("--namespace-label", action="append", default=[], metavar="KEY=VALUE")
    replay.add_argument("--namespace-annotation", action="append", default=[], metavar="KEY=VALUE")
    replay.set_defaults(func=cmd_replay)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
