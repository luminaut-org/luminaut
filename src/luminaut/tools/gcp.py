import argparse

from google.cloud import compute_v1

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
