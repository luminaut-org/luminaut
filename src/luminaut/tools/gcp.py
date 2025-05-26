import argparse

from google.cloud import compute_v1

from luminaut import models


def fetch_network_interfaces(
    gcp_computev1_client, project_id: str, zone_id: str
) -> list[models.GcpNetworkInterface]:
    instances = gcp_computev1_client.list(project=project_id, zone=zone_id)
    interfaces = []
    for instance in instances:
        interfaces.append(models.GcpNetworkInterface.from_gcp_computev1_list(instance))
    return interfaces


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
    instances = client.list(project=cli_args.project, zone=cli_args.zone)
    for instance in instances:
        print(f"Instance Name: {instance.name}")
        print(
            f"External IP: {instance.network_interfaces[0].access_configs[0].nat_i_p}"
        )
