from dataclasses import asdict
from typing import TextIO

import orjson
from rich.console import Console
from rich.progress import Progress

from luminaut.models import ScanResult

console = Console()


class TaskProgress:
    def __init__(
        self, task_progress: Progress | None = None, description: str = "", **kwargs
    ):
        self.task_progress = task_progress
        self.description = description
        self.task_id = None
        self.progress_kwargs = kwargs

    def __enter__(self):
        if self.task_progress:
            self.task_id = self.task_progress.add_task(
                description=self.description, **self.progress_kwargs
            )
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.task_progress and self.task_id:
            self.task_progress.stop_task(self.task_id)


def write_json_report(scan_result: ScanResult, output: TextIO):
    json_result = asdict(scan_result)  # type: ignore
    serialized_data = orjson.dumps(json_result)  # type: ignore
    output.write(serialized_data.decode("utf-8"))


def write_jsonl_report(scan_results: list[ScanResult], output: TextIO):
    for scan_result in scan_results:
        write_json_report(scan_result, output)
        output.write("\n")
