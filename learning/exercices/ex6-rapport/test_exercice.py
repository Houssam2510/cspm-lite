"""Tests de l'exercice 6. Ne modifie pas ce fichier."""

import unittest

from commun import Finding, Resource, Severity, Status
from exercice import render_markdown, summarize, top_offenders


def f(check_id="X-1", title="titre", sev=Severity.HIGH, status=Status.FAIL, rid="arn:r"):
    return Finding(
        check_id=check_id, title=title, severity=sev, status=status,
        resource=Resource(id=rid, type="T"),
    )


JEU = [
    f("S3-002", "Bucket public", Severity.CRITICAL, Status.FAIL, "arn:aws:s3:::leaky"),
    f("IAM-004", "Cle ancienne", Severity.HIGH, Status.FAIL, "arn:aws:iam::1:user/bob"),
    f("S3-004", "Chiffrement", Severity.MEDIUM, Status.PASS, "arn:aws:s3:::leaky"),
    f("LOG-001", "CloudTrail", Severity.HIGH, Status.NOT_AVAILABLE, "-"),
]


class TestSummarize(unittest.TestCase):
    def setUp(self):
        self.s = summarize(JEU)

    def test_cles(self):
        for k in ("total", "pass", "fail", "by_severity", "score", "pass_rate"):
            self.assertIn(k, self.s, f"cle {k} manquante")

    def test_comptes(self):
        self.assertEqual(self.s["total"], 4)
        self.assertEqual(self.s["pass"], 1)
        self.assertEqual(self.s["fail"], 2)

    def test_by_severity_fail_seulement(self):
        """MEDIUM est en PASS : il ne doit pas apparaitre."""
        self.assertEqual(self.s["by_severity"], {"CRITICAL": 1, "HIGH": 1})

    def test_score(self):
        # PASS MEDIUM (3) ; FAIL CRITICAL (10) + HIGH (5) -> 100 * 3/18 = 16.7
        self.assertAlmostEqual(self.s["score"], 16.7, places=1)

    def test_pass_rate(self):
        # 1 pass / 3 evalues -> 33.3
        self.assertAlmostEqual(self.s["pass_rate"], 33.3, places=1)

    def test_vide(self):
        s = summarize([])
        self.assertEqual(s["total"], 0)
        self.assertEqual(s["by_severity"], {})
        self.assertEqual(s["score"], 100.0)
        self.assertEqual(s["pass_rate"], 100.0)

    def test_not_available_ignore_du_score(self):
        s = summarize([f(status=Status.PASS), f(status=Status.NOT_AVAILABLE,
                                                sev=Severity.CRITICAL)])
        self.assertEqual(s["score"], 100.0)
        self.assertEqual(s["total"], 2)


class TestTopOffenders(unittest.TestCase):
    def test_tri_par_nombre(self):
        data = [
            f(rid="a", status=Status.FAIL), f(rid="a", status=Status.FAIL),
            f(rid="b", status=Status.FAIL),
        ]
        self.assertEqual(top_offenders(data), [("a", 2), ("b", 1)])

    def test_egalite_tri_par_id(self):
        """Determinisme : a egalite, l'identifiant croissant tranche."""
        data = [f(rid="z", status=Status.FAIL), f(rid="a", status=Status.FAIL)]
        self.assertEqual(top_offenders(data), [("a", 1), ("z", 1)])

    def test_limite(self):
        data = [f(rid=c, status=Status.FAIL) for c in "abcde"]
        self.assertEqual(len(top_offenders(data, n=2)), 2)

    def test_pass_ignore(self):
        data = [f(rid="a", status=Status.PASS), f(rid="b", status=Status.FAIL)]
        self.assertEqual(top_offenders(data), [("b", 1)])

    def test_vide(self):
        self.assertEqual(top_offenders([]), [])


class TestMarkdown(unittest.TestCase):
    def setUp(self):
        self.md = render_markdown(JEU)
        self.lignes = self.md.splitlines()

    def test_titre(self):
        self.assertEqual(self.lignes[0], "# Rapport de posture cspm-lite")

    def test_ligne_de_score(self):
        attendu = "**Score : 16.7 / 100** — 1 conformes, 2 en echec"
        self.assertIn(attendu, self.md, f"ligne de score attendue : {attendu}")

    def test_entete_de_tableau(self):
        self.assertIn("| Severite | Echecs |", self.md)
        self.assertIn("| --- | --- |", self.md)

    def test_lignes_de_tableau(self):
        self.assertIn("| CRITICAL | 1 |", self.md)
        self.assertIn("| HIGH | 1 |", self.md)

    def test_severite_sans_echec_absente_du_tableau(self):
        self.assertNotIn("| MEDIUM |", self.md)
        self.assertNotIn("| LOW |", self.md)

    def test_ordre_des_severites(self):
        self.assertLess(self.md.index("| CRITICAL |"), self.md.index("| HIGH |"),
                        "les severites vont de la plus grave a la moins grave")

    def test_sections(self):
        self.assertIn("## Findings en echec", self.md)
        self.assertIn("### CRITICAL", self.md)
        self.assertIn("### HIGH", self.md)

    def test_puces(self):
        self.assertIn("- **S3-002** — Bucket public — `arn:aws:s3:::leaky`", self.md)
        self.assertIn("- **IAM-004** — Cle ancienne — `arn:aws:iam::1:user/bob`", self.md)

    def test_pass_absent(self):
        self.assertNotIn("S3-004", self.md, "un finding PASS ne doit pas apparaitre")

    def test_not_available_absent(self):
        self.assertNotIn("LOG-001", self.md,
                         "un finding NOT_AVAILABLE ne doit pas apparaitre en echec")

    def test_ordre_dans_une_section(self):
        data = [
            f("A-1", "un", Severity.HIGH, Status.FAIL, "r1"),
            f("A-2", "deux", Severity.HIGH, Status.FAIL, "r2"),
        ]
        md = render_markdown(data)
        self.assertLess(md.index("A-1"), md.index("A-2"), "ordre d'entree preserve")

    def test_aucun_echec(self):
        md = render_markdown([f(status=Status.PASS)])
        self.assertIn("Aucun finding en echec.", md)
        self.assertNotIn("### ", md)

    def test_liste_vide(self):
        md = render_markdown([])
        self.assertEqual(md.splitlines()[0], "# Rapport de posture cspm-lite")
        self.assertIn("Aucun finding en echec.", md)

    def test_renvoie_une_chaine(self):
        self.assertIsInstance(self.md, str)


if __name__ == "__main__":
    unittest.main(verbosity=2)
