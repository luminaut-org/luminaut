import json
import unittest
from io import StringIO

from luminaut import models
from luminaut.report import write_json_report


class JsonReport(unittest.TestCase):
    def test_generate_json_report(self):
        result = models.ScanResult(
            ip="10.0.0.1",
            findings=[
                models.ScanFindings(
                    tool="nmap",
                    services=[
                        models.NmapPortServices(
                            port=80,
                            protocol=models.Protocol.TCP,
                            name="http",
                            product="nginx",
                            version="1.2.3",
                            state="open",
                        )
                    ],
                ),
            ],
        )
        output_file = StringIO()
        write_json_report(result, output_file)

        output_file.seek(0)
        json_result = json.load(output_file)

        self.assertIsInstance(json_result, dict)
        self.assertEqual("nginx", json_result["findings"][0]["services"][0]["product"])
