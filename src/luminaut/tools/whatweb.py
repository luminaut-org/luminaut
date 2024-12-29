import shutil
from pathlib import Path
from typing import Any

import orjson as json

from luminaut import LuminautConfig


class Whatweb:
    def __init__(self, config: LuminautConfig | None = None):
        self.config = config

    def exists(self) -> bool:
        if self.config and self.config.whatweb.enabled:
            return shutil.which("whatweb") is not None
        return False

    @staticmethod
    def read_json(json_result: Path) -> dict[str, Any]:
        with json_result.open("rb") as f:
            return json.loads(f.read())
