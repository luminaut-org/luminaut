import copy
import json
import unittest
from io import StringIO

from luminaut import models
from luminaut.report import write_json_report, write_jsonl_report


class JsonReport(unittest.TestCase):
    def setUp(self):
        self.scan_result = models.ScanResult(
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

    def test_generate_json_report(self):
        output_file = StringIO()
        write_json_report(self.scan_result, output_file)

        output_file.seek(0)
        json_result = json.load(output_file)

        self.assertIsInstance(json_result, dict)
        self.assertEqual("nginx", json_result["findings"][0]["services"][0]["product"])

    def test_generate_jsonl_report(self):
        second_result = copy.deepcopy(self.scan_result)
        second_result.ip = "10.1.1.1"

        scan_results = [self.scan_result, second_result]

        output_file = StringIO()
        write_jsonl_report(scan_results, output_file)

        output_file.seek(0)
        for scan_result, line in zip(scan_results, output_file, strict=True):
            json_result = json.loads(line)

            self.assertIsInstance(json_result, dict)
            self.assertEqual(scan_result.ip, json_result["ip"])
