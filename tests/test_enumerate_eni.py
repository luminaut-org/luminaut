import boto3
import moto

from perimeter_scanner.enumerate_eni import ENI


@moto.mock_aws
def create_new_eni(ec2, subnet):
    eni = ec2.create_network_interface(SubnetId=subnet["Subnet"]["SubnetId"])
    ec2.assign_private_ip_addresses(
        NetworkInterfaceId=eni["NetworkInterface"]["NetworkInterfaceId"],
        PrivateIpAddresses=["10.0.1.10"],
    )
    return eni


@moto.mock_aws
def setup_eni_for_test():
    # Create a mocked EC2 client
    ec2 = boto3.client("ec2", region_name="us-east-1")

    # Create a VPC and Subnet
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
    subnet = ec2.create_subnet(
        VpcId=vpc["Vpc"]["VpcId"],
        CidrBlock="10.0.1.0/24",
    )

    # Create a Network Interface with an associated public IP
    private_eni = create_new_eni(ec2, subnet)
    public_eni = create_new_eni(ec2, subnet)

    # Mock a public IP association
    ec2.associate_address(
        AllocationId=ec2.allocate_address(Domain="vpc")["AllocationId"],
        NetworkInterfaceId=public_eni["NetworkInterface"]["NetworkInterfaceId"],
    )
    return [public_eni, private_eni]


@moto.mock_aws
def test_list_enis_with_public_ips():
    enis = setup_eni_for_test()

    count = 0
    for public_eni in ENI().fetch_enis_with_public_ips():
        assert public_eni[0] == enis[0]["NetworkInterface"]["NetworkInterfaceId"]
        assert len(public_eni[1]) > 0
        assert public_eni[1] is not None
        count += 1

    assert count == 0  # only 1 iteration of the loop
