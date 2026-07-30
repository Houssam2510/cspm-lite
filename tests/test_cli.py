"""Tests de la CLI : codes de sortie, filtres, formats.

Ces tests utilisent `--demo`, donc aucun appel AWS. Ils verifient surtout le contrat
qui compte pour une CI : le code de sortie.
"""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from cspm_lite.cli import EXIT_ERREUR, EXIT_FINDINGS, EXIT_OK, main


def lancer(*args: str) -> tuple[int, str, str]:
    sortie, erreur = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(sortie), contextlib.redirect_stderr(erreur):
        code = main(list(args))
    return code, sortie.getvalue(), erreur.getvalue()


class TestListChecks(unittest.TestCase):
    def test_table(self):
        code, out, _ = lancer("list-checks")
        self.assertEqual(code, EXIT_OK)
        self.assertIn("S3-002", out)
        self.assertIn("controles.", out)

    def test_json(self):
        code, out, _ = lancer("list-checks", "--format", "json")
        data = json.loads(out)
        self.assertEqual(code, EXIT_OK)
        self.assertGreaterEqual(len(data), 25)
        self.assertTrue(all({"id", "title", "severity", "service"} <= set(d) for d in data))

    def test_markdown(self):
        _, out, _ = lancer("list-checks", "--format", "markdown")
        self.assertIn("| ID | Service | Severite | CIS | Titre |", out)

    def test_filtre_service(self):
        _, out, _ = lancer("list-checks", "--service", "s3")
        self.assertIn("S3-001", out)
        self.assertNotIn("IAM-001", out)

    def test_service_inconnu(self):
        code, _, err = lancer("list-checks", "--service", "inexistant")
        self.assertEqual(code, EXIT_ERREUR)
        self.assertIn("aucun check", err)


class TestScanDemo(unittest.TestCase):
    def test_code_1_par_defaut(self):
        """Le labo de demonstration contient des findings HIGH : la CI doit echouer."""
        code, _, _ = lancer("scan", "--demo", "--format", "json")
        self.assertEqual(code, EXIT_FINDINGS)

    def test_fail_on_none(self):
        code, _, _ = lancer("scan", "--demo", "--fail-on", "NONE", "--format", "json")
        self.assertEqual(code, EXIT_OK)

    def test_fail_on_seuil_haut(self):
        code, _, err = lancer("scan", "--demo", "--fail-on", "CRITICAL", "--format", "json")
        self.assertEqual(code, EXIT_FINDINGS)
        self.assertIn("CRITICAL", err)

    def test_severite_invalide(self):
        code, _, err = lancer("scan", "--demo", "--fail-on", "URGENT")
        self.assertEqual(code, EXIT_ERREUR)
        self.assertIn("severite inconnue", err)

    def test_sortie_json_valide(self):
        _, out, _ = lancer("scan", "--demo", "--format", "json", "--fail-on", "NONE")
        data = json.loads(out)
        self.assertEqual(data["account_id"], "111122223333")
        self.assertGreater(len(data["findings"]), 20)

    def test_filtre_service(self):
        _, out, _ = lancer(
            "scan", "--demo", "--service", "s3", "--format", "json", "--fail-on", "NONE"
        )
        ids = {f["check_id"] for f in json.loads(out)["findings"]}
        self.assertTrue(all(i.startswith("S3-") for i in ids), ids)

    def test_filtre_check(self):
        _, out, _ = lancer(
            "scan", "--demo", "--check", "S3-002", "--format", "json", "--fail-on", "NONE"
        )
        ids = {f["check_id"] for f in json.loads(out)["findings"]}
        self.assertEqual(ids, {"S3-002"})

    def test_severity_min(self):
        _, out, _ = lancer(
            "scan", "--demo", "--severity-min", "CRITICAL", "--format", "json", "--fail-on", "NONE"
        )
        severites = {f["severity"] for f in json.loads(out)["findings"]}
        self.assertEqual(severites, {"CRITICAL"})

    def test_ecriture_fichier(self):
        with tempfile.TemporaryDirectory() as tmp:
            chemin = Path(tmp) / "sous-dossier" / "rapport.html"
            code, _, err = lancer(
                "scan", "--demo", "--format", "html", "-o", str(chemin), "--fail-on", "NONE"
            )
            self.assertEqual(code, EXIT_OK)
            self.assertTrue(chemin.exists(), "le dossier parent doit etre cree")
            self.assertIn("<!doctype html>", chemin.read_text(encoding="utf-8"))
            self.assertIn("score", err)

    def test_tous_les_formats(self):
        for fmt in ("json", "markdown", "html", "asff"):
            code, out, _ = lancer("scan", "--demo", "--format", fmt, "--fail-on", "NONE")
            self.assertEqual(code, EXIT_OK, fmt)
            self.assertGreater(len(out), 100, fmt)


class TestDeterminisme(unittest.TestCase):
    def test_deux_scans_identiques(self):
        """Sans determinisme, le diff entre deux scans serait inexploitable."""
        _, a, _ = lancer("scan", "--demo", "--format", "json", "--fail-on", "NONE")
        _, b, _ = lancer("scan", "--demo", "--format", "json", "--fail-on", "NONE")
        ids_a = [f["check_id"] + f["resource"]["id"] for f in json.loads(a)["findings"]]
        ids_b = [f["check_id"] + f["resource"]["id"] for f in json.loads(b)["findings"]]
        self.assertEqual(ids_a, ids_b)


if __name__ == "__main__":
    unittest.main(verbosity=2)
