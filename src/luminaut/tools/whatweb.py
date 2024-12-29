import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import orjson as json

from luminaut import models


class Whatweb:
    def __init__(self, config: models.LuminautConfig | None = None):
        self.config = config
        self.brief_file = Path(tempfile.NamedTemporaryFile(delete=False).name)
        self.json_file = Path(tempfile.NamedTemporaryFile(delete=False).name)

    def __del__(self):
        # Clean up files when the object is deleted.
        self.brief_file.unlink()
        self.json_file.unlink()

    def run(self, target: str) -> models.Whatweb:
        if not self.exists():
            raise RuntimeError("Whatweb is not found on path.")

        command = self.build_command(target)
        timeout = self.config.whatweb.timeout if self.config else None
        subprocess.run(
            command,
            check=True,
            timeout=timeout,
            capture_output=True,
        )

        return self.build_data_class()

    def exists(self) -> bool:
        if self.config and self.config.whatweb.enabled:
            return shutil.which("whatweb") is not None
        return False

    def build_data_class(self) -> models.Whatweb:
        return models.Whatweb(
            summary_text=self.read_brief(self.brief_file),
            json_data=self.read_json(self.json_file),
        )

    def build_command(self, target: str) -> list[str | Path]:
        return [
            "whatweb",
            target,
            "--log-brief",
            str(self.brief_file),
            "--log-json",
            str(self.json_file),
        ]

    @staticmethod
    def read_json(json_result: Path) -> dict[str, Any]:
        with json_result.open("rb") as f:
            return json.loads(f.read())

    @staticmethod
    def read_brief(brief_result: Path) -> str:
        with brief_result.open("r") as f:
            return f.read()
