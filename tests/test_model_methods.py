import unittest
from datetime import UTC, datetime

from luminaut import models


class TestModels(unittest.TestCase):
    def test_scan_finding_bool(self):
        self.assertFalse(bool(models.ScanFindings(tool="foo")))
        self.assertTrue(bool(models.ScanFindings(tool="foo", resources=["bar"])))  # type: ignore
        self.assertTrue(bool(models.ScanFindings(tool="foo", services=["bar"])))  # type: ignore
        self.assertTrue(bool(models.ScanFindings(tool="foo", events=["bar"])))  # type: ignore

    def test_load_timeframes_for_aws(self):
        config = {
            "enabled": True,
            "start_time": datetime(2025, 1, 1, 0, 0, 0, 0, UTC),
            "end_time": datetime(2025, 1, 2, 0, 0, 0, 0, UTC),
        }
        config_model = models.LuminautConfigtoolAwsEvents.from_dict(config)
        self.assertIsInstance(config_model.start_time, datetime)
        self.assertIsInstance(config_model.end_time, datetime)

    def test_gcp_firewall_rules_scan_target_generation(self):
        # Create a GCP firewall rule allowing HTTP and HTTPS from anywhere
        firewall_rule = models.GcpFirewallRule(
            resource_id="fw-rule-123",
            name="allow-web-traffic",
            direction=models.Direction.INGRESS,
            priority=1000,
            action=models.FirewallAction.ALLOW,
            source_ranges=["0.0.0.0/0"],
            allowed_protocols=[
                {"IPProtocol": "tcp", "ports": ["80", "443"]},
                {"IPProtocol": "tcp", "ports": ["8080-8082"]},
            ],
            disabled=False,
        )

        # Test that the rule is considered permissive
        self.assertTrue(firewall_rule.is_permissive())

        # Create firewall rules collection
        firewall_rules = models.GcpFirewallRules(rules=[firewall_rule])

        # Create scan findings with the firewall rules
        scan_findings = models.ScanFindings(tool="gcp", resources=[firewall_rules])

        # Create scan result
        scan_result = models.ScanResult(ip="10.0.0.1", findings=[scan_findings])

        # Test getting GCP firewall rules
        gcp_rules = scan_result.get_gcp_firewall_rules()
        self.assertEqual(len(gcp_rules), 1)
        self.assertEqual(gcp_rules[0].name, "allow-web-traffic")

        # Test scan target generation
        scan_targets = scan_result.generate_scan_targets()
        target_ports = {target.port for target in scan_targets}

        # Should include ports 80, 443, and the range 8080-8082
        expected_ports = {80, 443, 8080, 8081, 8082}
        self.assertEqual(target_ports, expected_ports)

    def test_gcp_firewall_rules_disabled_rule_ignored(self):
        # Create a disabled firewall rule
        firewall_rule = models.GcpFirewallRule(
            resource_id="fw-rule-disabled",
            name="disabled-rule",
            direction=models.Direction.INGRESS,
            priority=1000,
            action=models.FirewallAction.ALLOW,
            source_ranges=["0.0.0.0/0"],
            allowed_protocols=[{"IPProtocol": "tcp", "ports": ["22"]}],
            disabled=True,  # This rule is disabled
        )

        # Test that the rule is not considered permissive when disabled
        self.assertFalse(firewall_rule.is_permissive())

        firewall_rules = models.GcpFirewallRules(rules=[firewall_rule])
        scan_result = models.ScanResult(
            ip="10.0.0.1",
            findings=[models.ScanFindings(tool="gcp", resources=[firewall_rules])],
        )

        # Test scan target generation - should use default ports since disabled rule is ignored
        scan_targets = scan_result.generate_scan_targets()
        target_ports = {target.port for target in scan_targets}

        # Should use default ports since the firewall rule is disabled
        expected_default_ports = {80, 443, 3000, 5000, 8000, 8080, 8443, 8888}
        self.assertEqual(target_ports, expected_default_ports)

    def test_gcp_firewall_rules_deny_rule_ignored(self):
        # Create a DENY firewall rule
        firewall_rule = models.GcpFirewallRule(
            resource_id="fw-rule-deny",
            name="deny-rule",
            direction=models.Direction.INGRESS,
            priority=1000,
            action=models.FirewallAction.DENY,  # This is a DENY rule
            source_ranges=["0.0.0.0/0"],
            allowed_protocols=[{"IPProtocol": "tcp", "ports": ["22"]}],
            disabled=False,
        )

        # Test that the rule is not considered permissive when it's a DENY rule
        self.assertFalse(firewall_rule.is_permissive())

        firewall_rules = models.GcpFirewallRules(rules=[firewall_rule])
        scan_result = models.ScanResult(
            ip="10.0.0.1",
            findings=[models.ScanFindings(tool="gcp", resources=[firewall_rules])],
        )

        # Test scan target generation - should use default ports since DENY rule is ignored
        scan_targets = scan_result.generate_scan_targets()
        target_ports = {target.port for target in scan_targets}

        # Should use default ports since the firewall rule is DENY
        expected_default_ports = {80, 443, 3000, 5000, 8000, 8080, 8443, 8888}
        self.assertEqual(target_ports, expected_default_ports)

    def test_firewall_timeline_event_types(self):
        """Test that firewall timeline event types are properly defined."""
        # Test that the new firewall event types exist and can be used
        self.assertEqual(
            models.TimelineEventType.FIREWALL_RULE_CREATED, "Firewall rule created"
        )
        self.assertEqual(
            models.TimelineEventType.FIREWALL_RULE_UPDATED, "Firewall rule updated"
        )
        self.assertEqual(
            models.TimelineEventType.FIREWALL_RULE_DELETED, "Firewall rule deleted"
        )


if __name__ == "__main__":
    unittest.main()
