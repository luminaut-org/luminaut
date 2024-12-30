import sys
from dataclasses import asdict
from typing import TextIO

import orjson
from rich.console import Console

from luminaut.models import ScanResult

console = Console(stderr=True, force_terminal=sys.stderr.isatty())


def write_json_report(scan_result: ScanResult, output: TextIO):
    json_result = asdict(scan_result)  # type: ignore
    serialized_data = orjson.dumps(json_result)  # type: ignore
    output.write(serialized_data.decode("utf-8"))


def write_jsonl_report(scan_results: list[ScanResult], output: TextIO):
    for scan_result in scan_results:
        write_json_report(scan_result, output)
        output.write("\n")
