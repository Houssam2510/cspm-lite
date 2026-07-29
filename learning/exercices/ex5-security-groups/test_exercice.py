"""Tests de l'exercice 5. Ne modifie pas ce fichier."""

import unittest

from commun import Severity, Status
from exercice import (
    check_security_groups,
    is_overly_broad,
    is_world_open,
    open_sensitive_ports,
    permission_covers_port,
    permission_world_open,
)


def perm(proto="tcp", frm=None, to=None, v4=(), v6=(), sgrefs=()):
    p = {
        "IpProtocol": proto,
        "IpRanges": [{"CidrIp": c} for c in v4],
        "Ipv6Ranges": [{"CidrIpv6": c} for c in v6],
        "UserIdGroupPairs": [{"GroupId": g} for g in sgrefs],
    }
    if frm is not None:
        p["FromPort"] = frm
        p["ToPort"] = to if to is not None else frm
    return p


def sg(gid="sg-1", name="test", perms=(), region="eu-west-3"):
    return {
        "GroupId": gid,
        "GroupName": name,
        "region": region,
        "IpPermissions": list(perms),
    }


class TestCidr(unittest.TestCase):
    def test_ipv4_monde(self):
        self.assertTrue(is_world_open("0.0.0.0/0"))

    def test_ipv6_monde(self):
        """Piege classique : ::/0 est aussi ouvert au monde."""
        self.assertTrue(is_world_open("::/0"))

    def test_prive(self):
        for c in ("10.0.0.0/8", "192.168.1.0/24", "203.0.113.5/32", "2001:db8::/32"):
            self.assertFalse(is_world_open(c), f"{c} n'est pas ouvert au monde")

    def test_large(self):
        self.assertTrue(is_overly_broad("10.0.0.0/8"))
        self.assertTrue(is_overly_broad("0.0.0.0/0"))
        self.assertTrue(is_overly_broad("::/0"))

    def test_pas_large(self):
        self.assertFalse(is_overly_broad("10.0.0.0/16"), "un /16 fait exactement 65536")
        self.assertFalse(is_overly_broad("192.168.1.0/24"))
        self.assertFalse(is_overly_broad("203.0.113.5/32"))


class TestCouverturePort(unittest.TestCase):
    def test_port_exact(self):
        self.assertTrue(permission_covers_port(perm("tcp", 22), 22))
        self.assertFalse(permission_covers_port(perm("tcp", 22), 23))

    def test_plage(self):
        p = perm("tcp", 20, 25)
        self.assertTrue(permission_covers_port(p, 22))
        self.assertTrue(permission_covers_port(p, 20))
        self.assertTrue(permission_covers_port(p, 25))
        self.assertFalse(permission_covers_port(p, 26))

    def test_plage_totale(self):
        self.assertTrue(permission_covers_port(perm("tcp", 0, 65535), 3306))

    def test_tous_protocoles_sans_ports(self):
        """Piege : IpProtocol -1 n'a ni FromPort ni ToPort, et ouvre tout."""
        p = perm("-1")
        self.assertNotIn("FromPort", p)
        for port in (22, 3389, 65535, 0):
            self.assertTrue(permission_covers_port(p, port), "-1 doit couvrir tous les ports")

    def test_protocole_numerique_tcp(self):
        self.assertTrue(permission_covers_port(perm("6", 22), 22))

    def test_udp_non_couvert(self):
        """Piege : UDP 3306 n'est pas une exposition MySQL."""
        self.assertFalse(permission_covers_port(perm("udp", 3306), 3306))

    def test_icmp_non_couvert(self):
        self.assertFalse(permission_covers_port(perm("icmp", -1, -1), 22))


class TestOuvertureMonde(unittest.TestCase):
    def test_ipv4(self):
        self.assertTrue(permission_world_open(perm("tcp", 22, v4=["0.0.0.0/0"])))

    def test_ipv6(self):
        self.assertTrue(permission_world_open(perm("tcp", 22, v6=["::/0"])))

    def test_restreint(self):
        self.assertFalse(permission_world_open(perm("tcp", 22, v4=["10.0.0.0/8"])))

    def test_reference_de_groupe(self):
        """Piege : autoriser un autre SG n'est pas une exposition Internet."""
        self.assertFalse(permission_world_open(perm("tcp", 22, sgrefs=["sg-9"])))

    def test_melange(self):
        p = perm("tcp", 22, v4=["10.0.0.0/8", "0.0.0.0/0"])
        self.assertTrue(permission_world_open(p))

    def test_aucune_plage(self):
        self.assertFalse(permission_world_open(perm("tcp", 22)))


class TestPortsSensibles(unittest.TestCase):
    def test_ssh_ouvert(self):
        s = sg(perms=[perm("tcp", 22, v4=["0.0.0.0/0"])])
        self.assertEqual(open_sensitive_ports(s), {22})

    def test_ssh_restreint(self):
        s = sg(perms=[perm("tcp", 22, v4=["10.0.0.0/8"])])
        self.assertEqual(open_sensitive_ports(s), set())

    def test_ipv6_seul(self):
        s = sg(perms=[perm("tcp", 3389, v6=["::/0"])])
        self.assertEqual(open_sensitive_ports(s), {3389})

    def test_tous_ports_tous_protocoles(self):
        s = sg(perms=[perm("-1", v4=["0.0.0.0/0"])])
        self.assertEqual(open_sensitive_ports(s), {22, 3389, 3306, 5432, 6379, 27017})

    def test_plage_large(self):
        s = sg(perms=[perm("tcp", 0, 65535, v4=["0.0.0.0/0"])])
        self.assertEqual(open_sensitive_ports(s), {22, 3389, 3306, 5432, 6379, 27017})

    def test_plusieurs_permissions(self):
        s = sg(perms=[
            perm("tcp", 443, v4=["0.0.0.0/0"]),
            perm("tcp", 3306, v4=["0.0.0.0/0"]),
            perm("tcp", 22, v4=["10.0.0.0/16"]),
        ])
        self.assertEqual(open_sensitive_ports(s), {3306})

    def test_port_non_sensible(self):
        s = sg(perms=[perm("tcp", 443, v4=["0.0.0.0/0"])])
        self.assertEqual(open_sensitive_ports(s), set())

    def test_sg_vide(self):
        self.assertEqual(open_sensitive_ports(sg()), set())


class TestCheck(unittest.TestCase):
    def setUp(self):
        self.sgs = [
            sg("sg-ok", "interne", [perm("tcp", 22, v4=["10.0.0.0/16"])]),
            sg("sg-bad", "web", [
                perm("tcp", 22, v4=["0.0.0.0/0"]),
                perm("tcp", 3306, v4=["0.0.0.0/0"]),
            ]),
        ]
        self.res = check_security_groups(self.sgs)

    def test_un_finding_par_sg(self):
        self.assertEqual(len(self.res), 2)

    def test_statuts(self):
        self.assertEqual([f.status for f in self.res], [Status.PASS, Status.FAIL])

    def test_metadonnees(self):
        f = self.res[1]
        self.assertEqual(f.check_id, "NET-001")
        self.assertEqual(f.title, "Port sensible expose sur Internet")
        self.assertEqual(f.severity, Severity.CRITICAL)
        self.assertEqual(f.resource.id, "sg-bad")
        self.assertEqual(f.resource.type, "AWS::EC2::SecurityGroup")
        self.assertEqual(f.resource.name, "web")
        self.assertEqual(f.resource.region, "eu-west-3")
        self.assertTrue(f.remediation.strip(), "ecris un texte de remediation")

    def test_details_tries(self):
        self.assertEqual(self.res[1].details, "22 (SSH), 3306 (MySQL)")
        self.assertEqual(self.res[0].details, "")

    def test_region_absente(self):
        s = {"GroupId": "sg-x", "GroupName": "n", "IpPermissions": []}
        self.assertEqual(check_security_groups([s])[0].resource.region, "")

    def test_liste_vide(self):
        self.assertEqual(check_security_groups([]), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
