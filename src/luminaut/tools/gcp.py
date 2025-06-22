import argparse

from google.cloud import compute_v1

from luminaut import models


class Gcp:
    def __init__(
        self,
        config: models.LuminautConfig,
        *,
        gcp_client: compute_v1.InstancesClient | None = None,
    ):
        self.config = config
        self.gcp_client = gcp_client or compute_v1.InstancesClient()

    @staticmethod
    def fetch_instances(
        gcp_computev1_client, project_id: str, zone_id: str
    ) -> list[models.GcpInstance]:
        instances = gcp_computev1_client.list(project=project_id, zone=zone_id)
        return [models.GcpInstance.from_gcp(instance) for instance in instances]


if __name__ == "__main__":
    args = argparse.ArgumentParser(description="GCP Instance Manager")
    args.add_argument(
        "project",
        type=str,
        help="GCP project ID",
    )
    args.add_argument(
        "zone",
        type=str,
        help="GCP zone",
    )
    cli_args = args.parse_args()

    client = compute_v1.InstancesClient()
    instances = Gcp.fetch_instances(
        client,
        project_id=cli_args.project,
        zone_id=cli_args.zone,
    )
    for instance in instances:
        print(f"Instance Name: {instance.name}")
        print(f"Instance ID: {instance.resource_id}")
        print(f"Status: {instance.status}")
        print(f"Zone: {instance.zone}")
        print(f"Created Time: {instance.creation_time}")
        print(f"External IP: {instance.network_interfaces[0].public_ip}")
