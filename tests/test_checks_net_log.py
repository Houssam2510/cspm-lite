"""Tests des controles reseau et journalisation.

Les trois pieges classiques sont testes explicitement : IPv6, protocole -1, plages
de ports.
"""

from __future__ import annotations

import unittest

from cspm_lite.engine.checks.log_checks import (
    log_cloudwatch_integration,
    log_file_validation,
    log_kms_encryption,
    log_multiregion_trail,
    log_trail_is_logging,
)
from cspm_lite.engine.checks.net_checks import (
    is_overly_broad,
    is_world_open,
    net_all_ports_open,
    net_default_sg_restricted,
    net_ebs_encrypted,
    net_imdsv2_required,
    net_sensitive_ports,
    net_vpc_flow_logs,
    open_sensitive_ports,
    permission_covers_port,
    permission_world_open,
)
from cspm_lite.engine.models import Status
from helpers import instance, inventaire, permission, security_group, trail, volume, vpc


class TestCidr(unittest.TestCase):
    def test_monde_ipv4(self):
        self.assertTrue(is_world_open("0.0.0.0/0"))

    def test_monde_ipv6(self):
        """Piege le plus frequent : ::/0 est aussi ouvert que 0.0.0.0/0."""
        self.assertTrue(is_world_open("::/0"))

    def test_restreint(self):
        for c in ("10.0.0.0/8", "192.168.1.0/24", "203.0.113.5/32", "2001:db8::/32"):
            self.assertFalse(is_world_open(c), c)

    def test_cidr_invalide_ne_leve_pas(self):
        self.assertFalse(is_world_open("pas-un-cidr"))
        self.assertFalse(is_overly_broad("pas-un-cidr"))

    def test_plage_large(self):
        self.assertTrue(is_overly_broad("10.0.0.0/8"))
        self.assertFalse(is_overly_broad("10.0.0.0/16"), "un /16 fait exactement 65536")


class TestPermissions(unittest.TestCase):
    def test_port_exact(self):
        self.assertTrue(permission_covers_port(permission("tcp", 22), 22))
        self.assertFalse(permission_covers_port(permission("tcp", 22), 23))

    def test_plage(self):
        p = permission("tcp", 20, 25)
        self.assertTrue(permission_covers_port(p, 22))
        self.assertFalse(permission_covers_port(p, 26))

    def test_tous_protocoles_sans_ports(self):
        """Piege : IpProtocol -1 n'a ni FromPort ni ToPort et ouvre tout."""
        p = permission("-1")
        self.assertNotIn("FromPort", p)
        self.assertTrue(permission_covers_port(p, 22))
        self.assertTrue(permission_covers_port(p, 65535))

    def test_tcp_numerique(self):
        self.assertTrue(permission_covers_port(permission("6", 22), 22))

    def test_udp_non_couvert(self):
        self.assertFalse(permission_covers_port(permission("udp", 3306), 3306))

    def test_reference_de_groupe_non_publique(self):
        self.assertFalse(permission_world_open(permission("tcp", 22, sgrefs=("sg-9",))))

    def test_ipv6_ouverte(self):
        self.assertTrue(permission_world_open(permission("tcp", 22, v6=("::/0",))))


class TestPortsSensibles(unittest.TestCase):
    def test_ssh_ouvert(self):
        sg = security_group("web", [permission("tcp", 22, v4=("0.0.0.0/0",))])
        self.assertEqual(open_sensitive_ports(sg.raw), {22})

    def test_plage_totale(self):
        sg = security_group("web", [permission("tcp", 0, 65535, v4=("0.0.0.0/0",))])
        self.assertIn(22, open_sensitive_ports(sg.raw))
        self.assertIn(27017, open_sensitive_ports(sg.raw))

    def test_port_non_sensible(self):
        sg = security_group("web", [permission("tcp", 443, v4=("0.0.0.0/0",))])
        self.assertEqual(open_sensitive_ports(sg.raw), set())

    def test_check_details_lisibles(self):
        sg = security_group(
            "web",
            [
                permission("tcp", 22, v4=("0.0.0.0/0",)),
                permission("tcp", 3306, v4=("0.0.0.0/0",)),
            ],
        )
        finding = net_sensitive_ports(inventaire(sg))[0]
        self.assertEqual(finding.status, Status.FAIL)
        self.assertEqual(finding.details, "22 (SSH), 3306 (MySQL)")

    def test_sg_sain(self):
        sg = security_group("interne", [permission("tcp", 22, v4=("10.0.0.0/16",))])
        self.assertEqual(net_sensitive_ports(inventaire(sg))[0].status, Status.PASS)


class TestAutresControlesReseau(unittest.TestCase):
    def test_tous_ports_ouverts(self):
        sg = security_group("ouvert", [permission("-1", v4=("0.0.0.0/0",))])
        self.assertEqual(net_all_ports_open(inventaire(sg))[0].status, Status.FAIL)

    def test_tous_ports_via_groupe_tolere(self):
        sg = security_group("interne", [permission("-1", sgrefs=("sg-1",))])
        self.assertEqual(net_all_ports_open(inventaire(sg))[0].status, Status.PASS)

    def test_sg_default_permissif(self):
        sg = security_group("default", [permission("tcp", 22, v4=("10.0.0.0/8",))])
        self.assertEqual(net_default_sg_restricted(inventaire(sg))[0].status, Status.FAIL)

    def test_sg_default_vide(self):
        self.assertEqual(
            net_default_sg_restricted(inventaire(security_group("default")))[0].status, Status.PASS
        )

    def test_seul_le_sg_default_est_concerne(self):
        sg = security_group("web", [permission("tcp", 22, v4=("10.0.0.0/8",))])
        self.assertEqual(net_default_sg_restricted(inventaire(sg)), [])

    def test_flow_logs(self):
        inv = inventaire(vpc("ok", flow_logs=True), vpc("ko", flow_logs=False))
        self.assertEqual([f.status for f in net_vpc_flow_logs(inv)], [Status.PASS, Status.FAIL])

    def test_ebs(self):
        inv = inventaire(volume("ok", encrypted=True), volume("ko", encrypted=False))
        self.assertEqual([f.status for f in net_ebs_encrypted(inv)], [Status.PASS, Status.FAIL])

    def test_imdsv2(self):
        inv = inventaire(instance("ok", "required"), instance("ko", "optional"))
        findings = net_imdsv2_required(inv)
        self.assertEqual([f.status for f in findings], [Status.PASS, Status.FAIL])
        self.assertIn("optional", findings[1].details)


class TestCloudTrail(unittest.TestCase):
    def test_multiregion_present(self):
        self.assertEqual(log_multiregion_trail(inventaire(trail()))[0].status, Status.PASS)

    def test_multiregion_absent(self):
        inv = inventaire(trail("local", IsMultiRegionTrail=False))
        finding = log_multiregion_trail(inv)[0]
        self.assertEqual(finding.status, Status.FAIL)
        self.assertIn("aucun multi-region", finding.details)

    def test_trail_arrete_ne_compte_pas(self):
        """Un trail multi-region mais arrete ne protege rien."""
        inv = inventaire(trail("stoppe", IsLogging=False))
        self.assertEqual(log_multiregion_trail(inv)[0].status, Status.FAIL)

    def test_aucun_trail(self):
        finding = log_multiregion_trail(inventaire())[0]
        self.assertEqual(finding.status, Status.FAIL)
        self.assertEqual(finding.resource.id, "111122223333")

    def test_validation_integrite(self):
        inv = inventaire(trail("ok"), trail("ko", LogFileValidationEnabled=False))
        self.assertEqual([f.status for f in log_file_validation(inv)], [Status.PASS, Status.FAIL])

    def test_kms(self):
        inv = inventaire(trail("ok"), trail("ko", KmsKeyId=None))
        self.assertEqual([f.status for f in log_kms_encryption(inv)], [Status.PASS, Status.FAIL])

    def test_cloudwatch(self):
        inv = inventaire(trail("ok"), trail("ko", CloudWatchLogsLogGroupArn=None))
        self.assertEqual(
            [f.status for f in log_cloudwatch_integration(inv)], [Status.PASS, Status.FAIL]
        )

    def test_is_logging(self):
        inv = inventaire(trail("ok"), trail("ko", IsLogging=False))
        self.assertEqual([f.status for f in log_trail_is_logging(inv)], [Status.PASS, Status.FAIL])


if __name__ == "__main__":
    unittest.main(verbosity=2)
