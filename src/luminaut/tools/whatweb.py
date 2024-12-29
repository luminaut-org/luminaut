import shutil
import tempfile
from pathlib import Path
from typing import Any

import orjson as json

from luminaut import LuminautConfig


class Whatweb:
    def __init__(self, config: LuminautConfig | None = None):
        self.config = config
        self.brief_file = Path(tempfile.NamedTemporaryFile(delete=False).name)
        self.json_file = Path(tempfile.NamedTemporaryFile(delete=False).name)

    def __del__(self):
        # Clean up files when the object is deleted.
        self.brief_file.unlink()
        self.json_file.unlink()

    def exists(self) -> bool:
        if self.config and self.config.whatweb.enabled:
            return shutil.which("whatweb") is not None
        return False

    def build_command(self, target: str) -> list[str | Path]:
        return [
            "whatweb",
            target,
            "--log-brief",
            self.brief_file,
            "--log-json",
            self.json_file,
        ]

    @staticmethod
    def read_json(json_result: Path) -> dict[str, Any]:
        with json_result.open("rb") as f:
            return json.loads(f.read())

    @staticmethod
    def read_brief(brief_result: Path) -> str:
        with brief_result.open("r") as f:
            return f.read()
