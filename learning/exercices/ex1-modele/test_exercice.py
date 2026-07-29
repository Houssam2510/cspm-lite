"""Tests de l'exercice 1. Ne modifie pas ce fichier."""

import json
import unittest

from exercice import Finding, Resource, Severity, Status, posture_score


def mk(status, severity=None, rid="arn:aws:s3:::b"):
    # Severity.HIGH est resolu ici, pas a l'import : sans cela, tant que l'enum n'est
    # pas ecrit, unittest afficherait une seule erreur de collecte au lieu des 18 tests.
    return Finding(
        check_id="X-001",
        title="titre",
        severity=Severity.HIGH if severity is None else severity,
        status=status,
        resource=Resource(id=rid),
    )


class TestSeverity(unittest.TestCase):
    def test_membres(self):
        for n in ("INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"):
            self.assertTrue(hasattr(Severity, n), f"Severity.{n} manquant")

    def test_comparaison(self):
        self.assertLess(Severity.LOW, Severity.CRITICAL)
        self.assertLess(Severity.MEDIUM, Severity.HIGH)
        self.assertFalse(Severity.CRITICAL < Severity.LOW)

    def test_tri(self):
        ordre = sorted([Severity.HIGH, Severity.INFORMATIONAL, Severity.CRITICAL, Severity.LOW])
        self.assertEqual(
            ordre, [Severity.INFORMATIONAL, Severity.LOW, Severity.HIGH, Severity.CRITICAL]
        )

    def test_poids(self):
        attendu = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 3, "LOW": 1, "INFORMATIONAL": 0}
        for nom, poids in attendu.items():
            self.assertEqual(getattr(Severity, nom).weight, poids, f"poids de {nom}")


class TestStatus(unittest.TestCase):
    def test_valeurs(self):
        for n in ("PASS", "FAIL", "WARNING", "NOT_AVAILABLE"):
            self.assertEqual(getattr(Status, n).value, n)


class TestResource(unittest.TestCase):
    def test_defauts(self):
        r = Resource(id="arn:aws:s3:::x")
        self.assertEqual(r.type, "")
        self.assertEqual(r.region, "")
        self.assertEqual(r.name, "")
        self.assertEqual(r.tags, {})

    def test_tags_non_partages(self):
        """Piege du defaut mutable : deux Resource ne doivent pas partager le dict."""
        a, b = Resource(id="a"), Resource(id="b")
        a.tags["env"] = "prod"
        self.assertEqual(b.tags, {}, "les tags sont partages entre instances")


class TestFinding(unittest.TestCase):
    def test_defauts(self):
        f = mk(Status.FAIL)
        self.assertEqual(f.remediation, "")
        self.assertEqual(f.details, "")

    def test_to_dict_serialisable(self):
        d = mk(Status.FAIL, Severity.CRITICAL, "arn:aws:s3:::leaky").to_dict()
        json.dumps(d)  # ne doit pas lever
        self.assertEqual(d["severity"], "CRITICAL")
        self.assertEqual(d["status"], "FAIL")
        self.assertEqual(d["check_id"], "X-001")

    def test_to_dict_resource_imbriquee(self):
        d = mk(Status.PASS, rid="arn:aws:s3:::b").to_dict()
        self.assertIsInstance(d["resource"], dict)
        self.assertEqual(d["resource"]["id"], "arn:aws:s3:::b")
        for cle in ("id", "type", "region", "name", "tags"):
            self.assertIn(cle, d["resource"])


class TestScore(unittest.TestCase):
    def test_vide(self):
        self.assertEqual(posture_score([]), 100.0)

    def test_tout_pass(self):
        self.assertEqual(posture_score([mk(Status.PASS), mk(Status.PASS)]), 100.0)

    def test_tout_fail(self):
        self.assertEqual(posture_score([mk(Status.FAIL), mk(Status.FAIL)]), 0.0)

    def test_ponderation(self):
        # PASS LOW (1) + FAIL CRITICAL (10) -> 100 * 1/11 = 9.1
        f = [mk(Status.PASS, Severity.LOW), mk(Status.FAIL, Severity.CRITICAL)]
        self.assertAlmostEqual(posture_score(f), 9.1, places=1)

    def test_ponderation_inverse(self):
        # PASS CRITICAL (10) + FAIL LOW (1) -> 100 * 10/11 = 90.9
        f = [mk(Status.PASS, Severity.CRITICAL), mk(Status.FAIL, Severity.LOW)]
        self.assertAlmostEqual(posture_score(f), 90.9, places=1)

    def test_ignore_les_autres_statuts(self):
        """Un NOT_AVAILABLE CRITICAL ne doit pas peser sur le score."""
        f = [mk(Status.PASS, Severity.HIGH), mk(Status.NOT_AVAILABLE, Severity.CRITICAL)]
        self.assertEqual(posture_score(f), 100.0)

    def test_denominateur_nul(self):
        """Que des INFORMATIONAL (poids 0) : division par zero a eviter."""
        f = [mk(Status.FAIL, Severity.INFORMATIONAL)]
        self.assertEqual(posture_score(f), 100.0)

    def test_arrondi(self):
        f = [mk(Status.PASS, Severity.MEDIUM), mk(Status.FAIL, Severity.HIGH)]
        s = posture_score(f)  # 100 * 3/8 = 37.5
        self.assertEqual(s, 37.5)
        self.assertIsInstance(s, float)


if __name__ == "__main__":
    unittest.main(verbosity=2)
