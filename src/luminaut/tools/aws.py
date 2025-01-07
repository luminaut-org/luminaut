import logging
from collections.abc import Generator
from dataclasses import asdict
from datetime import UTC
from typing import Any

import boto3
import orjson as json

from luminaut import models

logger = logging.getLogger(__name__)


class Aws:
    def __init__(self, config: models.LuminautConfig | None = None):
        config = config if config else models.LuminautConfig()
        self.config = config
        self.ec2_client = boto3.client("ec2")
        self.elb_client = boto3.client("elbv2")
        self.config_client = boto3.client("config")

    def explore_region(self, region: str) -> list[models.ScanResult]:
        if not self.config.aws.enabled:
            return []

        self.setup_client_region(region)
        logger.info("Exploring region %s", region)

        enis_with_public_ips = self._fetch_enis_with_public_ips()

        aws_exploration_results = []
        for eni in enis_with_public_ips:
            findings = []
            eni_finding = models.ScanFindings(
                tool="AWS Elastic Network Interfaces",
                emoji_name="cloud",
                resources=[eni],
            )
            if self.skip_resource(eni):
                logger.info("Skipping resource %s", eni.resource_id)
                continue

            findings.append(eni_finding)

            security_group_finding = self.explore_security_groups(eni.security_groups)
            findings.append(security_group_finding)

            elb_attachment = self.detect_elb_attachment(eni)
            if elb_attachment:
                findings.append(elb_attachment)

            if self.config.aws.config.enabled:
                logger.info(
                    "Fetching AWS Config history for resources associated with %s. This can take some time to run.",
                    eni.resource_id,
                )
                findings.append(self.explore_config_history(eni))

            if self.config.aws.cloudtrail.enabled:
                if cloudtrail_finding := self.add_cloudtrail(
                    eni, security_group_finding, region, elb_findings=elb_attachment
                ):
                    findings.append(cloudtrail_finding)

            eni_exploration = models.ScanResult(
                ip=eni.public_ip,
                region=region,
                eni_id=eni.resource_id,
                findings=findings,
            )
            aws_exploration_results.append(eni_exploration)

        logger.info("Completed exploration of AWS region %s", region)

        return aws_exploration_results

    def describe_elb_listeners(
        self, load_balancer_arn: str
    ) -> list[models.AwsLoadBalancerListener]:
        paginator = self.elb_client.get_paginator("describe_listeners")
        results = paginator.paginate(LoadBalancerArn=load_balancer_arn)
        listeners = []
        for result in results:
            for listener in result["Listeners"]:
                listeners.append(
                    models.AwsLoadBalancerListener.from_describe_listener(listener)
                )

        return listeners

    def detect_elb_attachment(
        self, eni: models.AwsNetworkInterface
    ) -> models.ScanFindings | None:
        """This detects if the ELB name found in the ENI description matches an existing load balancer."""
        if not eni.description or not eni.description.startswith("ELB "):
            return None

        try:
            elb_name = eni.description[3:].split("/")[1]
        except IndexError:
            logger.warning("Could not extract ELB name from ENI description")
            return None

        paginator = self.elb_client.get_paginator("describe_load_balancers")
        results = paginator.paginate(Names=[elb_name])
        elb_finding = models.ScanFindings(
            tool="AWS Elastic Load Balancers",
            emoji_name="cloud",
        )

        for elb in results:
            for load_balancer in elb["LoadBalancers"]:
                lb_model = models.AwsLoadBalancer.from_describe_elb(load_balancer)
                listeners = self.describe_elb_listeners(lb_model.arn)
                lb_model.listeners = listeners
                elb_finding.resources.append(lb_model)

        return elb_finding

    @staticmethod
    def add_cloudtrail(
        eni: models.AwsNetworkInterface,
        security_group_finding: models.ScanFindings,
        region: str,
        elb_findings: models.ScanFindings | None = None,
    ) -> models.ScanFindings | None:
        cloudtrail = CloudTrail(region)
        cloudtrail_events = cloudtrail.lookup_events(eni.resource_id, eni.resource_type)
        if eni.ec2_instance_id:
            cloudtrail_events += cloudtrail.lookup_events(
                eni.ec2_instance_id, models.ResourceType.EC2_Instance
            )
        if security_group_finding.resources:
            for security_group in security_group_finding.resources:
                cloudtrail_events += cloudtrail.lookup_events(
                    security_group.group_id,
                    models.ResourceType.EC2_SecurityGroup,
                )
        if elb_findings:
            for load_balancer in elb_findings.resources:
                cloudtrail_events += cloudtrail.lookup_events(
                    load_balancer.arn, models.ResourceType.ELB_LoadBalancer
                )
        if cloudtrail_events:
            sorted_events = sorted(cloudtrail_events, key=lambda x: x.timestamp)
            return models.ScanFindings(
                tool=cloudtrail.source_name,
                emoji_name="cloud",
                events=sorted_events,
            )

        return None

    def explore_security_groups(
        self, security_groups: list[models.SecurityGroup]
    ) -> models.ScanFindings:
        sg_finding = models.ScanFindings(
            tool="AWS Security Groups",
            emoji_name="lock",
        )
        for security_group in security_groups:
            security_group = self.populate_permissive_ingress_security_group_rules(
                security_group
            )
            sg_finding.resources.append(security_group)

        return sg_finding

    def explore_config_history(
        self, eni: models.AwsNetworkInterface
    ) -> models.ScanFindings:
        resource_history, events = self.get_config_history_for_resource(
            models.ResourceType.EC2_NetworkInterface, eni.resource_id
        )
        if eni.ec2_instance_id:
            ec2_instance_history, ec2_events = self.get_config_history_for_resource(
                models.ResourceType.EC2_Instance, eni.ec2_instance_id
            )
            resource_history += ec2_instance_history
            events += ec2_events

        return models.ScanFindings(
            tool="AWS Config",
            emoji_name="gear",
            resources=resource_history,
            events=events,
        )

    def skip_resource(self, resource: Any) -> bool:
        if hasattr(resource, "get_aws_tags"):
            if self._should_skip_by_tags(resource):
                return True

        if hasattr(resource, "resource_id") and hasattr(resource, "resource_type"):
            if self._should_skip_by_id(resource):
                return True
        return False

    def _should_skip_by_id(self, resource) -> bool:
        should_skip = False
        for allowed_resource in self.config.aws.allowed_resources:
            if (
                resource.resource_type == allowed_resource.type
                and resource.resource_id == allowed_resource.id
            ):
                should_skip = True
        return should_skip

    def _should_skip_by_tags(self, resource) -> bool:
        resource_tags = resource.get_aws_tags()
        for allowed_resource in self.config.aws.allowed_resources:
            for (
                allowed_tag_name,
                allowed_tag_value,
            ) in allowed_resource.tags.items():
                if resource_tag_value := resource_tags.get(allowed_tag_name):
                    if resource_tag_value == allowed_tag_value:
                        return True
        return False

    def setup_client_region(self, region: str) -> None:
        self.ec2_client = boto3.client("ec2", region_name=region)
        self.elb_client = boto3.client("elbv2", region_name=region)
        self.config_client = boto3.client("config", region_name=region)

    def _fetch_enis_with_public_ips(self) -> list[models.AwsNetworkInterface]:
        paginator = self.ec2_client.get_paginator("describe_network_interfaces")
        results = paginator.paginate(
            Filters=[
                {
                    "Name": "association.public-ip",
                    "Values": ["*"],
                },
            ],
        )
        scan_results = []

        for enis in results:
            for eni in enis["NetworkInterfaces"]:
                eni_model = self._build_eni_scan_finding(eni)
                scan_results.append(eni_model)

        num_enis_with_public_ips = len(scan_results)
        logger.info("Found %s ENIs with public IPs", num_enis_with_public_ips)
        if num_enis_with_public_ips:
            logger.info("Gathering additional details from AWS about these ENIs...")

        return scan_results

    @staticmethod
    def _build_eni_scan_finding(eni: dict[str, Any]) -> models.AwsNetworkInterface:
        association = eni.get("Association", {})
        public_ip = association.get("PublicIp")
        attachment = eni.get("Attachment", {})
        security_groups = [
            models.SecurityGroup(x["GroupId"], x["GroupName"])
            for x in eni.get("Groups", [])
        ]
        tags = models.convert_tag_set_to_dict(eni.get("TagSet", []))

        return models.AwsNetworkInterface(
            resource_id=eni["NetworkInterfaceId"],
            public_ip=public_ip,
            private_ip=eni["PrivateIpAddress"],
            ec2_instance_id=attachment.get("InstanceId"),
            public_dns_name=association.get("PublicDnsName"),
            private_dns_name=eni.get("PrivateDnsName"),
            attachment_id=attachment.get("AttachmentId"),
            attachment_time=attachment.get("AttachTime"),
            attachment_status=attachment.get("Status"),
            availability_zone=eni["AvailabilityZone"],
            security_groups=security_groups,
            status=eni["Status"],
            vpc_id=eni["VpcId"],
            tags=tags,
            description=eni.get("Description"),
            interface_type=eni.get("InterfaceType"),
        )

    def get_config_history_for_resource(
        self,
        resource_type: models.ResourceType,
        resource_id: str,
    ) -> (list[models.AwsConfigItem], list[models.TimelineEvent]):
        pagination_client = self.config_client.get_paginator(
            "get_resource_config_history"
        )
        pages = pagination_client.paginate(
            resourceType=str(resource_type),
            resourceId=resource_id,
            chronologicalOrder="Forward",
        )

        resources = []
        events = []
        for page in pages:
            for config_item in page.get("configurationItems", []):
                config_entry = models.AwsConfigItem.from_aws_config(config_item)

                self._diff_against_prior(resources, config_entry)
                if config_entry.diff_to_prior:
                    events += (
                        ExtractEventsFromConfigDiffs.generate_events_from_aws_config(
                            resource_type, resource_id, config_entry
                        )
                    )

                resources.append(config_entry)

        return resources, events

    @staticmethod
    def _diff_against_prior(
        resources: list[models.AwsConfigItem], config_entry: models.AwsConfigItem
    ) -> None:
        if len(resources) > 0:
            prior_configuration = resources[-1].configuration
            new_configuration = config_entry.configuration
            # Cannot compare strings at this time.
            if not (
                isinstance(prior_configuration, str)
                or isinstance(new_configuration, str)
            ):
                if diff_to_prior := models.generate_config_diff(
                    prior_configuration, new_configuration
                ):
                    config_entry.diff_to_prior = diff_to_prior

    def populate_permissive_ingress_security_group_rules(
        self, security_group: models.SecurityGroup
    ) -> models.SecurityGroup:
        aws_client = self.ec2_client.get_paginator("describe_security_group_rules")

        paginator = aws_client.paginate(
            Filters=[{"Name": "group-id", "Values": [security_group.group_id]}]
        )

        for page in paginator:
            for rule in page["SecurityGroupRules"]:
                sg_rule = models.SecurityGroupRule.from_describe_rule(rule)
                if (
                    sg_rule.direction == models.Direction.INGRESS
                    and sg_rule.is_permissive()
                ):
                    security_group.rules.append(sg_rule)

        return security_group


class ExtractEventsFromConfigDiffs:
    @classmethod
    def generate_events_from_aws_config(
        cls,
        resource_type: models.ResourceType,
        resource_id: str,
        config_item: models.AwsConfigItem,
    ) -> list[models.TimelineEvent]:
        events = []
        if not config_item.diff_to_prior:
            return events

        diff_as_dict = asdict(config_item.diff_to_prior)
        if resource_type == models.ResourceType.EC2_Instance:
            cls.process_ec2_instance(
                config_item.config_capture_time,
                diff_as_dict,
                events,
                resource_id,
                resource_type,
            )
        return events

    @classmethod
    def process_ec2_instance(
        cls, config_capture_time, diff_as_dict, events, resource_id, resource_type
    ):
        changes = diff_as_dict["changed"]
        for key, value in changes.items():
            event_type = None
            message = None

            match key:
                case "state":
                    event_type = models.TimelineEventType.COMPUTE_INSTANCE_STATE_CHANGE
                    message = cls._format_ec2_state_change_message("changed", value)
                case "security_groups":
                    event_type = (
                        models.TimelineEventType.SECURITY_GROUP_ASSOCIATION_CHANGE
                    )
                    message = cls._format_ec2_sg_change_message(value)
                case "launch_time":
                    event_type = (
                        models.TimelineEventType.COMPUTE_INSTANCE_LAUNCH_TIME_UPDATED
                    )
                    message = cls._format_ec2_string_field_change_message(
                        "Launch time", value
                    )
                case "public_dns_name":
                    event_type = (
                        models.TimelineEventType.COMPUTE_INSTANCE_NETWORKING_CHANGE
                    )
                    message = cls._format_ec2_string_field_change_message(
                        "Public DNS name", value
                    )
                case "public_ip_address":
                    event_type = (
                        models.TimelineEventType.COMPUTE_INSTANCE_NETWORKING_CHANGE
                    )
                    message = cls._format_ec2_string_field_change_message(
                        "Public IP address", value
                    )

            if event_type and message:
                events.append(
                    models.TimelineEvent(
                        timestamp=config_capture_time.astimezone(UTC),
                        source="AWS Config",
                        event_type=event_type,
                        resource_type=resource_type,
                        resource_id=resource_id,
                        message=message,
                        details=diff_as_dict,
                    )
                )

    @staticmethod
    def _format_ec2_state_change_message(action: str, value: Any) -> str:
        message = f"State {action}"
        if action == "changed":
            message += f" from {value['old']['name']} to {value['new']['name']}"
        elif action in ["added", "removed"]:
            logger.warning(
                "Unexpected action %s for EC2 instance state. Please report.",
                action,
            )
            message += f" state {value['name']}"
        return message + "."

    @staticmethod
    def _format_ec2_sg_change_message(value: dict[str, list[dict[str, Any]]]) -> str:
        old_sg_ids = {x["groupId"]: x["groupName"] for x in value["old"]}
        new_sg_ids = {x["groupId"]: x["groupName"] for x in value["new"]}

        added_to_new = set(new_sg_ids) - set(old_sg_ids)
        removed_from_new = set(old_sg_ids) - set(new_sg_ids)

        message = ""
        if added_to_new:
            added_sg = [
                f"{sg_name} ({sg_id})"
                for sg_id, sg_name in new_sg_ids.items()
                if sg_id in added_to_new
            ]
            message += f"Added {', '.join(added_sg)}. "
        if removed_from_new:
            removed_sg = [
                f"{sg_name} ({sg_id})"
                for sg_id, sg_name in old_sg_ids.items()
                if sg_id in removed_from_new
            ]
            message += f"Removed {', '.join(removed_sg)}."

        return message

    @staticmethod
    def _format_ec2_string_field_change_message(
        field_name: str, changes: dict[str, str]
    ) -> str:
        return f"{field_name} changed from {changes['old']} to {changes['new']}."


class CloudTrailEventMessageFormatter:
    @staticmethod
    def format_sg_ingress_rule_added(event: dict[str, Any]) -> str:
        added_rules = []
        for items in (
            event.get("requestParameters", {}).get("ipPermissions", {}).get("items", [])
        ):
            for ip_range in items.get("ipRanges", {}).get("items", []):
                rule_summary = CloudTrailEventMessageFormatter.build_rule_summary(
                    ip_range.get("cidrIp"), items
                )
                added_rules.append(rule_summary)
            for ip_range in items.get("ipv6Ranges", {}).get("items", []):
                rule_summary = CloudTrailEventMessageFormatter.build_rule_summary(
                    ip_range.get("cidrIpv6"), items
                )
                added_rules.append(rule_summary)

        return ". Allow: " + ", ".join(added_rules)

    @staticmethod
    def build_rule_summary(target: str, items: dict[str, Any]) -> str:
        from_port = items.get("fromPort")
        to_port = items.get("toPort")
        port_range = f"{from_port}-{to_port}" if from_port != to_port else from_port
        rule_summary = f"{target}:{port_range} over {items.get('ipProtocol')}"
        return rule_summary

    @staticmethod
    def format_eni_attribute_modification(event: dict[str, Any]) -> str:
        summary = ""
        request_parameters = event.get("requestParameters", {})
        summary += CloudTrailEventMessageFormatter.summarize_sg_from_request_params(
            request_parameters
        )
        return ". Security groups: " + summary

    @staticmethod
    def summarize_sg_from_request_params(request_parameters):
        security_groups = []
        summary = ""
        if groups_set := request_parameters.get("groupSet", {}):
            for security_group in groups_set.get("items", []):
                if security_group.get("groupId"):
                    security_groups.append(security_group["groupId"])
        if security_groups:
            summary += ", ".join(security_groups)
        return summary

    @staticmethod
    def format_ec2_run_instance(event: dict[str, Any]) -> str:
        summary = ""
        network_interface_items = (
            event.get("requestParameters", {})
            .get("networkInterfaceSet", {})
            .get("items", [])
        )
        if network_interface_items:
            for item in network_interface_items:
                summary += (
                    CloudTrailEventMessageFormatter.summarize_sg_from_request_params(
                        item
                    )
                )
            summary = ". Security groups: " + summary
        return summary


class CloudTrail:
    source_name = "AWS CloudTrail"
    supported_ec2_instance_events = {
        "RunInstances": {
            "event_type": models.TimelineEventType.COMPUTE_INSTANCE_CREATED,
            "message": "Instance created",
            "formatter": CloudTrailEventMessageFormatter.format_ec2_run_instance,
        },
        "RebootInstances": {
            "event_type": models.TimelineEventType.COMPUTE_INSTANCE_STATE_CHANGE,
            "message": "Instance rebooted",
        },
        "StartInstances": {
            "event_type": models.TimelineEventType.COMPUTE_INSTANCE_STATE_CHANGE,
            "message": "Instance started",
        },
        "StopInstances": {
            "event_type": models.TimelineEventType.COMPUTE_INSTANCE_STATE_CHANGE,
            "message": "Instance stopped",
        },
        "TerminateInstances": {
            "event_type": models.TimelineEventType.COMPUTE_INSTANCE_TERMINATED,
            "message": "Instance terminated",
        },
    }
    supported_ec2_eni_events = {
        "RunInstances": {
            "event_type": models.TimelineEventType.COMPUTE_INSTANCE_CREATED,
            "message": "Instance created",
        },
        "ModifyNetworkInterfaceAttribute": {
            "event_type": models.TimelineEventType.COMPUTE_INSTANCE_NETWORKING_CHANGE,
            "message": "Network interface modified",
            "formatter": CloudTrailEventMessageFormatter.format_eni_attribute_modification,
        },
    }
    supported_ec2_sg_events = {
        "AuthorizeSecurityGroupIngress": {
            "event_type": models.TimelineEventType.SECURITY_GROUP_RULE_CHANGE,
            "message": "Ingress rule added",
            "formatter": CloudTrailEventMessageFormatter.format_sg_ingress_rule_added,
        },
        "RevokeSecurityGroupIngress": {
            "event_type": models.TimelineEventType.SECURITY_GROUP_RULE_CHANGE,
            "message": "Ingress rule removed",
        },
    }
    supported_elb_events = {
        "CreateLoadBalancer": {
            "event_type": models.TimelineEventType.RESOURCE_CREATED,
            "message": "Load balancer created",
        },
    }

    def __init__(self, region: str):
        self.cloudtrail_client = boto3.client("cloudtrail", region_name=region)

    def _fetch_context(self, resource_type):
        context = {}
        if resource_type == models.ResourceType.EC2_Instance:
            context = self.supported_ec2_instance_events
        elif resource_type == models.ResourceType.EC2_NetworkInterface:
            context = self.supported_ec2_eni_events
        elif resource_type == models.ResourceType.EC2_SecurityGroup:
            context = self.supported_ec2_sg_events
        elif resource_type == models.ResourceType.ELB_LoadBalancer:
            context = self.supported_elb_events
        else:
            logger.warning(
                "CloudTrail lookup for %s not supported", resource_type.value
            )
        return context

    def _lookup(
        self, resource_id: str, supported_events: dict[str, dict[str, Any]]
    ) -> Generator[tuple[dict[str, Any], dict[str, Any]], None, None]:
        paginator = self.cloudtrail_client.get_paginator("lookup_events")
        for page in paginator.paginate(
            LookupAttributes=[
                {"AttributeKey": "ResourceName", "AttributeValue": resource_id}
            ]
        ):
            for event in page["Events"]:
                if event.get("EventName") in supported_events:
                    yield event, supported_events[event["EventName"]]

    def lookup_events(
        self, resource_id: str, resource_type: models.ResourceType
    ) -> list[models.TimelineEvent]:
        context = self._fetch_context(resource_type)
        if not context:
            return []

        events = []
        for event, event_context in self._lookup(resource_id, context):
            event_details = event.get("CloudTrailEvent", "")
            try:
                event_details = json.loads(event_details)
                event["CloudTrailEvent"] = event_details
            except json.JSONDecodeError:
                logger.warning(
                    "Could not parse CloudTrail event details. The event detail is stored as a string."
                )

            message = event_context["message"]
            if username := event.get("Username"):
                message += f" by {username}"

            if event_details and (formatter := event_context.get("formatter")):
                if formatted_message := formatter(event_details):
                    message += formatted_message

            events.append(
                models.TimelineEvent(
                    timestamp=event["EventTime"].astimezone(UTC),
                    source=self.source_name,
                    event_type=event_context["event_type"],
                    resource_type=resource_type,
                    resource_id=resource_id,
                    message=message + ".",
                    details=event,
                )
            )
        return events
