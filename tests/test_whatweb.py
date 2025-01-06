import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import orjson as json

from luminaut import models
from luminaut.tools.whatweb import Whatweb


class TestWhatweb(unittest.TestCase):
    def setUp(self):
        self.config = models.LuminautConfig(
            whatweb=models.LuminautConfigTool(enabled=True)
        )
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
            str(self.whatweb.brief_file),
            "--log-json",
            str(self.whatweb.json_file),
        ]

        command = self.whatweb.build_command(target)

        self.assertEqual(expected_command_components, command)

    def test_temporary_files_removed_on_deletion(self):
        brief_file = self.whatweb.brief_file
        json_file = self.whatweb.json_file

        del self.whatweb

        self.assertFalse(brief_file.exists())
        self.assertFalse(json_file.exists())

    def test_build_data_class(self):
        json_data = {"key": "value"}
        brief_data = "foo"

        with self.whatweb.json_file.open("wb") as f:
            f.write(json.dumps(json_data))

        with self.whatweb.brief_file.open("w") as f:
            f.write(brief_data)

        self.assertIsInstance(self.whatweb.build_data_class(), models.Whatweb)
        self.assertEqual(self.whatweb.build_data_class().summary_text, brief_data)
        self.assertEqual(self.whatweb.build_data_class().json_data, json_data)

    def test_format_text(self):
        whatweb_model = models.Whatweb(
            summary_text="foo",
            json_data=[
                {
                    "target": "target1",
                    "plugins": {
                        "Cookies": {"string": ["foo1"]},
                        "Unittest1": {"string": ["bar1a", "baz1a"]},
                        "Unittest2": {"version": ["bar1b", "baz1b"]},
                    },
                },
                {
                    "target": "target2",
                    "plugins": {
                        "Cookies": {"string": ["foo2"]},
                        "Unittest": {"string": ["bar2", "baz2"]},
                    },
                },
            ],
        )
        formatted_text = whatweb_model.build_rich_text()
        self.assertIn("target1", formatted_text)
        self.assertIn("target2", formatted_text)
        self.assertNotIn("foo1", formatted_text)
        self.assertNotIn("foo2", formatted_text)
        self.assertIn("Unittest1", formatted_text)
        self.assertIn("Unittest2", formatted_text)
        self.assertIn("Unittest", formatted_text)
        self.assertIn("bar1a, baz1a", formatted_text)
        self.assertIn("bar1b, baz1b", formatted_text)
        self.assertIn("bar2, baz2", formatted_text)


if __name__ == "__main__":
    unittest.main()
