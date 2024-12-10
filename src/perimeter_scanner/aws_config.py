from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any

import boto3


class ResourceType(StrEnum):
    EC2_Instance = "AWS::EC2::Instance"
    EC2_NetworkInterface = "AWS::EC2::NetworkInterface"


@dataclass
class ConfigItem:
    resource_type: ResourceType
    resource_id: str
    resource_creation_time: datetime
    account: str
    region: str
    arn: str
    config_capture_time: datetime
    config_status: str
    configuration: dict[str, Any]
    tags: dict[str, str]


class AwsConfig:
    def __init__(self):
        self.aws_client = boto3.client("config")

    def get_current_config_for_resource(self, resource_type: str, resource_id: str) -> ConfigItem | None:
        resp = self.aws_client.get_resource_config_history(
            resourceType=resource_type,
            resourceId=resource_id,
        )

        # get the first item, if any
        config_items = resp.get('configurationItems')
        if not config_items or len(config_items) == 0:
            return None

        config_item = config_items[0]

        return ConfigItem(
            resource_type=ResourceType(config_item['resourceType']),
            resource_id=config_item['resourceId'],
            resource_creation_time=config_item['resourceCreationTime'],
            account=config_item['accountId'],
            region=config_item['awsRegion'],
            arn=config_item['arn'],
            config_capture_time=config_item['configurationItemCaptureTime'],
            config_status=config_item['configurationItemStatus'],
            configuration=config_item['configuration'],
            tags=config_item['tags'],
        )
