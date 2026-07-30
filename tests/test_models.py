"""Tests du modele de donnees : enums, serialisation, score de posture."""

from __future__ import annotations

import json
import unittest

from cspm_lite.engine.models import (
    Finding,
    Inventory,
    Resource,
    ScanResult,
    Severity,
    Status,
)


def finding(status=Status.FAIL, severity=None, rid="arn:r", check="X-1") -> Finding:
    return Finding(
        check_id=check,
        title="titre",
        severity=Severity.HIGH if severity is None else severity,
        status=status,
        resource=Resource(id=rid, type="T", region="eu-west-3"),
    )


class TestSeverity(unittest.TestCase):
    def test_comparaison(self):
        self.assertLess(Severity.LOW, Severity.CRITICAL)
        self.assertLess(Severity.MEDIUM, Severity.HIGH)
        self.assertFalse(Severity.CRITICAL < Severity.LOW)

    def test_tri(self):
        ordre = sorted([Severity.HIGH, Severity.INFORMATIONAL, Severity.CRITICAL])
        self.assertEqual(ordre, [Severity.INFORMATIONAL, Severity.HIGH, Severity.CRITICAL])

    def test_poids(self):
        self.assertEqual(Severity.CRITICAL.weight, 10)
        self.assertEqual(Severity.INFORMATIONAL.weight, 0)

    def test_from_name(self):
        self.assertIs(Severity.from_name("high"), Severity.HIGH)
        self.assertIs(Severity.from_name("CRITICAL"), Severity.CRITICAL)

    def test_from_name_invalide(self):
        with self.assertRaises(ValueError) as ctx:
            Severity.from_name("URGENT")
        self.assertIn("CRITICAL", str(ctx.exception), "le message doit lister les valeurs valides")

    def test_comparaison_avec_autre_type(self):
        with self.assertRaises(TypeError):
            _ = Severity.HIGH < 5


class TestResource(unittest.TestCase):
    def test_defauts_non_partages(self):
        a, b = Resource(id="a"), Resource(id="b")
        a.tags["env"] = "prod"
        a.raw["x"] = 1
        self.assertEqual(b.tags, {})
        self.assertEqual(b.raw, {})

    def test_to_dict_masque_le_brut(self):
        """`raw` peut contenir des donnees volumineuses : il ne sort pas du rapport."""
        r = Resource(id="a", raw={"secret_interne": "x" * 1000})
        self.assertNotIn("raw", r.to_dict())


class TestFinding(unittest.TestCase):
    def test_serialisable(self):
        d = finding(severity=Severity.CRITICAL).to_dict()
        json.dumps(d)
        self.assertEqual(d["severity"], "CRITICAL")
        self.assertEqual(d["status"], "FAIL")
        self.assertIsInstance(d["resource"], dict)
        self.assertIn("detected_at", d)


class TestInventory(unittest.TestCase):
    def test_indexation_par_type(self):
        inv = Inventory()
        inv.add(Resource(id="a", type="T1"))
        inv.add(Resource(id="b", type="T1"))
        inv.add(Resource(id="c", type="T2"))
        self.assertEqual(len(inv.by_type("T1")), 2)
        self.assertEqual(inv.count, 3)

    def test_type_absent(self):
        self.assertEqual(Inventory().by_type("inexistant"), [])
        self.assertIsNone(Inventory().one("inexistant"))

    def test_one(self):
        inv = Inventory()
        inv.add(Resource(id="a", type="T"))
        self.assertIsNotNone(inv.one("T"))


class TestScanResult(unittest.TestCase):
    def test_vide(self):
        r = ScanResult(account_id="1")
        self.assertEqual(r.score, 100.0)
        self.assertEqual(r.pass_rate, 100.0)
        self.assertEqual(r.counts_by_severity, {})

    def test_score_pondere(self):
        r = ScanResult(
            "1", [finding(Status.PASS, Severity.LOW), finding(Status.FAIL, Severity.CRITICAL)]
        )
        self.assertAlmostEqual(r.score, 9.1, places=1)

    def test_not_available_ignore(self):
        """Ne pas avoir pu verifier n'est pas un echec."""
        r = ScanResult(
            "1",
            [finding(Status.PASS, Severity.HIGH), finding(Status.NOT_AVAILABLE, Severity.CRITICAL)],
        )
        self.assertEqual(r.score, 100.0)

    def test_denominateur_nul(self):
        r = ScanResult("1", [finding(Status.FAIL, Severity.INFORMATIONAL)])
        self.assertEqual(r.score, 100.0)

    def test_counts_ordonnes_par_gravite(self):
        r = ScanResult(
            "1",
            [
                finding(Status.FAIL, Severity.LOW),
                finding(Status.FAIL, Severity.CRITICAL),
                finding(Status.FAIL, Severity.CRITICAL),
            ],
        )
        self.assertEqual(list(r.counts_by_severity), ["CRITICAL", "LOW"])
        self.assertEqual(r.counts_by_severity["CRITICAL"], 2)

    def test_top_offenders_deterministe(self):
        r = ScanResult(
            "1",
            [
                finding(Status.FAIL, rid="z"),
                finding(Status.FAIL, rid="a"),
                finding(Status.FAIL, rid="a"),
            ],
        )
        self.assertEqual(r.top_offenders(), [("a", 2), ("z", 1)])

    def test_to_dict(self):
        r = ScanResult("1", [finding(Status.FAIL)], regions=["eu-west-3"])
        d = r.to_dict()
        json.dumps(d)
        self.assertEqual(d["schema_version"], "1.0")
        self.assertEqual(d["summary"]["fail"], 1)
        self.assertEqual(d["regions"], ["eu-west-3"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
