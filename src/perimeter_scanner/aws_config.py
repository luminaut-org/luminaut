import argparse
from pprint import pprint

import boto3

from perimeter_scanner import models


class AwsConfig:
    def __init__(self):
        self.aws_client = boto3.client("config")

    def get_config_history_for_resource(
        self,
        resource_type: models.ResourceType,
        resource_id: str,
    ) -> models.ConfigItem | None:
        pagination_client = self.aws_client.get_paginator("get_resource_config_history")
        pages = pagination_client.paginate(
            resourceType=str(resource_type),
            resourceId=resource_id,
        )

        for page in pages:
            # get the first item, if any
            config_items = page.get("configurationItems")
            if not config_items or len(config_items) == 0:
                return None

            for config_item in config_items:
                yield models.ConfigItem.from_aws_config(config_item)


if __name__ == "__main__":
    cli_args = argparse.ArgumentParser()
    cli_args.add_argument(
        "RESOURCE_TYPE",
        type=models.ResourceType,
        choices=list(models.ResourceType),
    )
    cli_args.add_argument(
        "RESOURCE_ID",
        type=str,
    )
    args = cli_args.parse_args()

    aws_config = AwsConfig()
    config_history = config_item = aws_config.get_config_history_for_resource(
        args.RESOURCE_TYPE,
        args.RESOURCE_ID,
    )
    for config_item in config_history:
        pprint(config_item)
