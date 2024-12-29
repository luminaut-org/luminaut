import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import orjson as json

from luminaut.models import LuminautConfig, LuminautConfigTool
from luminaut.tools.whatweb import Whatweb


class TestWhatweb(unittest.TestCase):
    def test_tool_found(self):
        config = LuminautConfig(whatweb=LuminautConfigTool(enabled=True))

        with patch("shutil.which") as mock:
            mock.return_value = "/usr/bin/whatweb"
            self.assertTrue(Whatweb(config).exists())

        self.assertFalse(Whatweb(config).exists())

        self.assertFalse(Whatweb(config).exists())

    def test_read_json(self):
        content = {"key": "value"}
        with tempfile.NamedTemporaryFile("wb", delete=False) as json_file:
            json_file.write(json.dumps(content))

        json_file_path = Path(json_file.name)

        result = Whatweb.read_json(json_file_path)
        self.assertEqual(result, content)
        json_file_path.unlink()

    def test_read_brief(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as brief_file:
            content = "foo"
            brief_file.write(content)

        file_path = Path(brief_file.name)

        result = Whatweb.read_brief(file_path)
        self.assertEqual(result, content)
        file_path.unlink()


if __name__ == "__main__":
    unittest.main()
