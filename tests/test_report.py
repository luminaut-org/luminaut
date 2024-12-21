import copy
import unittest
from datetime import datetime
from io import StringIO

import orjson

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
                models.ScanFindings(
                    tool="aws-config",
                    resources=[
                        models.ConfigItem(
                            resource_type=models.ResourceType.EC2_Instance,
                            resource_id="i-1234567890abcdef0",
                            account="123456789012",
                            region="us-east-1",
                            arn="bar",
                            configuration="foo",
                            config_status="OK",
                            config_capture_time=datetime.today(),
                            tags={"Name": "test"},
                        )
                    ],
                ),
            ],
        )

    def test_generate_json_report(self):
        output_file = StringIO()
        write_json_report(self.scan_result, output_file)

        output_file.seek(0)
        json_result = orjson.loads(output_file.read())

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
            json_result = orjson.loads(line)

            self.assertIsInstance(json_result, dict)
            self.assertEqual(scan_result.ip, json_result["ip"])
