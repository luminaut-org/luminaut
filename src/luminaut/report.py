import csv
import sys
from dataclasses import asdict
from pathlib import Path
from typing import TextIO

import orjson
from rich.console import Console

from luminaut.models import ScanResult

console = Console(stderr=True, force_terminal=sys.stderr.isatty(), record=True)
timeline_columns = [
    "timestamp",
    "ip",
    "source",
    "event_type",
    "message",
    "resource_id",
    "resource_type",
    "tool",
    "details",
]


def write_json_report(scan_result: ScanResult, output: TextIO):
    json_result = asdict(scan_result)  # type: ignore
    serialized_data = orjson.dumps(json_result)  # type: ignore
    output.write(serialized_data.decode("utf-8"))


def write_jsonl_report(scan_results: list[ScanResult], output: TextIO):
    for scan_result in scan_results:
        write_json_report(scan_result, output)
        output.write("\n")


def write_html_report(output_file: Path) -> None:
    console.save_html(str(output_file))


def write_csv_timeline(scan_results: list[ScanResult], output: TextIO):
    events = []
    for scan_result in scan_results:
        for finding in scan_result.findings:
            for event in finding.events:
                event_as_dict = asdict(event)  # type: ignore
                event_as_dict["ip"] = scan_result.ip
                event_as_dict["tool"] = finding.tool
                event_as_dict["timestamp"] = event.timestamp.isoformat()
                events.append(event_as_dict)

    sorted_events = sorted(events, key=lambda x: x["timestamp"])

    if sorted_events:
        writer = csv.DictWriter(output, fieldnames=timeline_columns)  # type: ignore
        writer.writeheader()
        writer.writerows(sorted_events)
