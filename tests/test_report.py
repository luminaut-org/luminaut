import copy
import csv
import unittest
from datetime import UTC, datetime
from io import StringIO

import orjson

from luminaut import models
from luminaut.report import (
    timeline_columns,
    write_csv_timeline,
    write_json_report,
    write_jsonl_report,
)


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
                        models.AwsConfigItem(
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

    def test_generate_timeline_report(self):
        first_date = datetime(2025, 1, 1, 0, 0, 0, 0, UTC)
        second_date = datetime(2025, 1, 1, 0, 0, 1, 0, UTC)
        third_date = datetime(2025, 1, 1, 0, 0, 2, 0, UTC)
        finding1 = models.ScanFindings(
            tool="foo",
            events=[
                models.TimelineEvent(
                    timestamp=second_date,
                    source="foo",
                    event_type=models.TimelineEventType.COMPUTE_INSTANCE_CREATED,
                    resource_id="i-0",
                    resource_type=models.ResourceType.EC2_Instance,
                    message="foo message",
                    details={"foo details": "bar"},
                ),
                models.TimelineEvent(
                    timestamp=third_date,
                    source="unittest",
                    event_type=models.TimelineEventType.COMPUTE_INSTANCE_TERMINATED,
                    resource_id="i-0",
                    resource_type=models.ResourceType.EC2_Instance,
                ),
            ],
        )
        finding2 = models.ScanFindings(
            tool="bar",
            events=[
                models.TimelineEvent(
                    timestamp=first_date,
                    source="bar",
                    event_type=models.TimelineEventType.COMPUTE_INSTANCE_CREATED,
                    resource_id="i-1",
                    resource_type=models.ResourceType.EC2_Instance,
                ),
            ],
        )
        scan = models.ScanResult(ip="10.0.0.1", findings=[finding1, finding2])

        timeline = StringIO("r+")
        write_csv_timeline([scan], timeline)

        timeline.seek(0)
        reader = csv.DictReader(timeline)
        lines = list(reader)
        headers = list(lines[0])
        self.assertEqual(len(lines), 3)
        for column in timeline_columns:
            self.assertIn(column, headers)

        self.assertIn(first_date.isoformat(), lines[0]["timestamp"])
        self.assertIn(second_date.isoformat(), lines[1]["timestamp"])
        self.assertIn(third_date.isoformat(), lines[2]["timestamp"])
