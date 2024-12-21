import unittest
from io import BytesIO

from luminaut import LuminautConfig

sample_toml_config = b"""
[report]
console = true
json = false

[tool.aws]
enabled = true
aws_profile = "default"
aws_regions = ['us-east-1']

[tool.aws.config]
enabled = false

[tool.nmap]
enabled = true
timeout = 300
"""


class TestLuminautConfig(unittest.TestCase):
    def test_load_config(self):
        loaded_config = LuminautConfig.from_toml(BytesIO(sample_toml_config))

        self.assertTrue(loaded_config.report.console)
        self.assertFalse(loaded_config.report.json)

        self.assertTrue(loaded_config.aws.enabled)
        self.assertFalse(loaded_config.aws.config.enabled)
        self.assertTrue(loaded_config.nmap.enabled)

        self.assertEqual(loaded_config.aws.aws_profile, "default")
        self.assertEqual(loaded_config.aws.aws_regions, ["us-east-1"])

        self.assertTrue(loaded_config.nmap.enabled)
        self.assertEqual(loaded_config.nmap.timeout, 300)


if __name__ == "__main__":
    unittest.main()
