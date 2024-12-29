import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import orjson as json

from luminaut.models import LuminautConfig, LuminautConfigTool
from luminaut.tools.whatweb import Whatweb


class TestWhatweb(unittest.TestCase):
    def setUp(self):
        self.config = LuminautConfig(whatweb=LuminautConfigTool(enabled=True))
        self.whatweb = Whatweb(config=self.config)

    def test_tool_found(self):
        with patch("shutil.which") as mock:
            mock.return_value = "/usr/bin/whatweb"
            self.assertTrue(self.whatweb.exists())

        self.assertFalse(self.whatweb.exists())

        self.assertFalse(Whatweb().exists())

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

    def test_build_command(self):
        target = "10.0.0.1"
        expected_command_components = [
            "whatweb",
            target,
            "--log-brief",
            self.whatweb.brief_file,
            "--log-json",
            self.whatweb.json_file,
        ]

        command = self.whatweb.build_command(target)

        self.assertEqual(expected_command_components, command)

    def test_temporary_files_removed_on_deletion(self):
        brief_file = self.whatweb.brief_file
        json_file = self.whatweb.json_file

        del self.whatweb

        self.assertFalse(brief_file.exists())
        self.assertFalse(json_file.exists())


if __name__ == "__main__":
    unittest.main()
