"""Tests de l'historisation : persistance, diff, MTTR, taux de recidive."""

from __future__ import annotations

import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cspm_lite.engine.models import Finding, Resource, ScanResult, Severity, Status
from cspm_lite.history import compute_metrics, diff_scans, list_scans, save_scan
from cspm_lite.reporters.history_reporter import render_history_html, render_history_markdown

T0 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


def finding(check="S3-002", rid="arn:b", status=Status.FAIL, sev=Severity.HIGH, subject=""):
    return Finding(
        check_id=check,
        title="titre",
        severity=sev,
        status=status,
        resource=Resource(id=rid),
        subject=subject,
    )


def scan(findings, jours=0):
    debut = T0 + timedelta(days=jours)
    return ScanResult(
        account_id="111122223333",
        findings=findings,
        regions=["eu-west-3"],
        started_at=debut,
        finished_at=debut + timedelta(seconds=5),
    )


class BaseTemporaire(unittest.TestCase):
    def setUp(self):
        self.db = str(Path(tempfile.mkdtemp()) / "historique.db")


class TestPersistance(BaseTemporaire):
    def test_enregistrement_et_relecture(self):
        save_scan(self.db, scan([finding()]))
        scans = list_scans(self.db)
        self.assertEqual(len(scans), 1)
        self.assertEqual(scans[0].account_id, "111122223333")
        self.assertEqual(scans[0].fail_count, 1)
        self.assertEqual(scans[0].score, 0.0)

    def test_ordre_chronologique(self):
        for i in range(3):
            save_scan(self.db, scan([finding()], jours=i))
        self.assertEqual([s.id for s in list_scans(self.db)], [1, 2, 3])

    def test_limite_garde_les_plus_recents(self):
        for i in range(5):
            save_scan(self.db, scan([finding()], jours=i))
        self.assertEqual([s.id for s in list_scans(self.db, limit=2)], [4, 5])

    def test_deux_cles_du_meme_utilisateur(self):
        """Sans `subject`, les deux cles partageraient la meme cle primaire."""
        findings = [
            finding("IAM-004", "arn:user/bob", subject="access_key_1"),
            finding("IAM-004", "arn:user/bob", subject="access_key_2"),
        ]
        save_scan(self.db, scan(findings))
        self.assertEqual(list_scans(self.db)[0].fail_count, 2)

    def test_base_vide(self):
        self.assertEqual(list_scans(self.db), [])

    def test_creation_du_dossier_parent(self):
        chemin = str(Path(tempfile.mkdtemp()) / "sous" / "dossier" / "h.db")
        save_scan(chemin, scan([finding()]))
        self.assertTrue(Path(chemin).exists())


class TestDiff(BaseTemporaire):
    def test_nouveaux_resolus_persistants(self):
        a = save_scan(self.db, scan([finding("A", "r1"), finding("B", "r1")], jours=0))
        b = save_scan(self.db, scan([finding("B", "r1"), finding("C", "r1")], jours=7))
        diff = diff_scans(self.db, a, b)
        self.assertEqual([f["check_id"] for f in diff.nouveaux], ["C"])
        self.assertEqual([f["check_id"] for f in diff.resolus], ["A"])
        self.assertEqual([f["check_id"] for f in diff.persistants], ["B"])
        self.assertFalse(diff.vide)

    def test_aucun_changement(self):
        a = save_scan(self.db, scan([finding("A", "r1")], jours=0))
        b = save_scan(self.db, scan([finding("A", "r1")], jours=7))
        self.assertTrue(diff_scans(self.db, a, b).vide)

    def test_un_pass_compte_comme_resolu(self):
        a = save_scan(self.db, scan([finding("A", "r1", Status.FAIL)], jours=0))
        b = save_scan(self.db, scan([finding("A", "r1", Status.PASS)], jours=7))
        self.assertEqual(len(diff_scans(self.db, a, b).resolus), 1)

    def test_finding_supprime_exclu_du_diff(self):
        f = finding("A", "r1")
        f.suppressed = True
        a = save_scan(self.db, scan([f], jours=0))
        b = save_scan(self.db, scan([finding("A", "r1")], jours=7))
        diff = diff_scans(self.db, a, b)
        self.assertEqual(len(diff.nouveaux), 1, "sortir d'une exclusion est un nouvel echec")


class TestMetriques(BaseTemporaire):
    def test_mttr(self):
        save_scan(self.db, scan([finding("A", "r1", Status.FAIL)], jours=0))
        save_scan(self.db, scan([finding("A", "r1", Status.FAIL)], jours=5))
        save_scan(self.db, scan([finding("A", "r1", Status.PASS)], jours=10))
        m = compute_metrics(self.db)
        self.assertEqual(m.mttr_global, 10.0)
        self.assertEqual(m.mttr_par_severite["HIGH"], 10.0)
        self.assertEqual(m.corriges, 1)
        self.assertEqual(m.ouverts, 0)

    def test_mttr_par_severite_ordonne(self):
        save_scan(
            self.db,
            scan(
                [
                    finding("A", "r1", Status.FAIL, Severity.LOW),
                    finding("B", "r2", Status.FAIL, Severity.CRITICAL),
                ],
                jours=0,
            ),
        )
        save_scan(
            self.db,
            scan(
                [
                    finding("A", "r1", Status.PASS, Severity.LOW),
                    finding("B", "r2", Status.PASS, Severity.CRITICAL),
                ],
                jours=4,
            ),
        )
        m = compute_metrics(self.db)
        self.assertEqual(list(m.mttr_par_severite), ["CRITICAL", "LOW"])

    def test_recidive(self):
        """FAIL -> PASS -> FAIL -> PASS : deux episodes fermes, donc une recidive."""
        etapes = ((0, Status.FAIL), (5, Status.PASS), (10, Status.FAIL), (15, Status.PASS))
        for jour, statut in etapes:
            save_scan(self.db, scan([finding("A", "r1", statut)], jours=jour))
        m = compute_metrics(self.db)
        self.assertEqual(m.corriges, 2)
        self.assertEqual(m.taux_de_recidive, 50.0)

    def test_findings_ouverts(self):
        save_scan(self.db, scan([finding("A", "r1")], jours=0))
        save_scan(self.db, scan([finding("A", "r1")], jours=30))
        m = compute_metrics(self.db)
        self.assertEqual(m.ouverts, 1)
        self.assertEqual(m.plus_anciens[0], ("A", "r1", 30))

    def test_base_vide(self):
        m = compute_metrics(self.db)
        self.assertEqual(m.corriges, 0)
        self.assertEqual(m.mttr_global, 0.0)
        self.assertEqual(m.taux_de_recidive, 0.0)


class TestRendu(BaseTemporaire):
    def setUp(self):
        super().setUp()
        for jour, statut in ((0, Status.FAIL), (7, Status.FAIL), (14, Status.PASS)):
            save_scan(self.db, scan([finding("A", "r1", statut)], jours=jour))
        self.scans = list_scans(self.db)
        self.diff = diff_scans(self.db, self.scans[-2].id, self.scans[-1].id)
        self.metrics = compute_metrics(self.db)

    def test_markdown(self):
        md = render_history_markdown(self.scans, self.diff, self.metrics)
        self.assertTrue(md.startswith("# Historique de posture"))
        self.assertIn("Score actuel", md)
        self.assertIn("Tendance", md)
        self.assertIn("Metriques de pilotage", md)

    def test_markdown_sans_scan(self):
        from cspm_lite.history import Diff, Metrics

        md = render_history_markdown([], Diff(), Metrics())
        self.assertIn("Aucun scan", md)

    def test_html_autonome(self):
        html = render_history_html(self.scans, self.diff, self.metrics)
        for interdit in ("<script src", '<link rel="stylesheet"', "https://", "http://"):
            self.assertNotIn(interdit, html, interdit)

    def test_html_courbe(self):
        html = render_history_html(self.scans, self.diff, self.metrics)
        self.assertIn('<svg id="chart"', html)
        self.assertIn('role="img"', html)
        self.assertIn("prefers-color-scheme", html)
        self.assertIn("Vue tableau", html, "une vue tableau accompagne toujours la courbe")

    def test_html_un_seul_scan_pas_de_courbe(self):
        html = render_history_html(self.scans[:1], self.diff, self.metrics)
        self.assertNotIn("<svg", html)
        self.assertIn("deux scans", html)

    def test_html_sans_scan(self):
        from cspm_lite.history import Diff, Metrics

        self.assertIn("Aucun scan", render_history_html([], Diff(), Metrics()))


class TestIntegrationDemo(BaseTemporaire):
    def test_historique_de_demonstration(self):
        from cspm_lite.demo import seed_demo_history

        # 8 scans minimum : la regression simulee au scan 5 doit avoir le temps
        # d'etre corrigee a nouveau pour compter comme une recidive (un episode
        # n'est comptabilise que lorsqu'il se referme).
        ecrits = seed_demo_history(self.db, scans=8)
        self.assertEqual(ecrits, 8)
        scans = list_scans(self.db)
        self.assertEqual(len(scans), 8)
        self.assertGreater(scans[-1].score, scans[0].score, "la posture doit s'ameliorer")
        m = compute_metrics(self.db)
        self.assertGreater(m.corriges, 0)
        self.assertGreater(m.taux_de_recidive, 0, "une regression est simulee au scan 5")

    def test_regression_non_refermee_ne_compte_pas(self):
        """Un finding reapparu mais pas encore recorrige n'est pas une recidive."""
        from cspm_lite.demo import seed_demo_history

        seed_demo_history(self.db, scans=6)
        self.assertEqual(compute_metrics(self.db).taux_de_recidive, 0.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
