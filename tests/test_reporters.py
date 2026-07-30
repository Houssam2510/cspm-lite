"""Tests des reporters : JSON, Markdown, HTML et ASFF."""

from __future__ import annotations

import json
import unittest

from cspm_lite.engine.models import Finding, Resource, ScanResult, Severity, Status
from cspm_lite.reporters import RENDERERS
from cspm_lite.reporters.asff_reporter import finding_to_asff, render_asff
from cspm_lite.reporters.html_reporter import render_html
from cspm_lite.reporters.json_reporter import render_json
from cspm_lite.reporters.markdown_reporter import render_markdown


def finding(check="S3-002", status=Status.FAIL, sev=Severity.CRITICAL, rid="arn:aws:s3:::b"):
    return Finding(
        check_id=check,
        title="Bucket public",
        severity=sev,
        status=status,
        resource=Resource(id=rid, type="AWS::S3::Bucket", region="eu-west-3"),
        remediation="Activer Block Public Access.",
        details="acl-allusers",
        cis="2.1.4",
        references=["https://docs.aws.amazon.com/"],
    )


def resultat(findings=None):
    return ScanResult(
        account_id="111122223333",
        findings=findings
        if findings is not None
        else [
            finding(),
            finding("IAM-004", Status.FAIL, Severity.HIGH, "arn:aws:iam::1:user/bob"),
            finding("S3-003", Status.PASS, Severity.MEDIUM),
        ],
        regions=["eu-west-3"],
    )


class TestJson(unittest.TestCase):
    def test_valide_et_versionne(self):
        d = json.loads(render_json(resultat()))
        self.assertEqual(d["schema_version"], "1.0")
        self.assertEqual(d["summary"]["fail"], 2)
        self.assertEqual(len(d["findings"]), 3)

    def test_vide(self):
        d = json.loads(render_json(resultat([])))
        self.assertEqual(d["summary"]["score"], 100.0)


class TestMarkdown(unittest.TestCase):
    def setUp(self):
        self.md = render_markdown(resultat())

    def test_titre(self):
        self.assertTrue(self.md.startswith("# Rapport de posture cspm-lite"))

    def test_resume(self):
        self.assertIn("**Score :", self.md)
        self.assertIn("| CRITICAL | 1 |", self.md)
        self.assertIn("| HIGH | 1 |", self.md)

    def test_ordre_des_severites(self):
        self.assertLess(self.md.index("| CRITICAL |"), self.md.index("| HIGH |"))

    def test_pass_absent_du_detail(self):
        self.assertNotIn("S3-003", self.md)

    def test_remediation_presente(self):
        self.assertIn("Activer Block Public Access.", self.md)

    def test_pipes_echappes(self):
        """Un pipe dans un titre casserait le tableau Markdown."""
        f = finding()
        f.title = "titre | piege"
        self.assertIn("titre \\| piege", render_markdown(resultat([f])))

    def test_aucun_echec(self):
        md = render_markdown(resultat([finding(status=Status.PASS)]))
        self.assertIn("Aucun finding en echec.", md)


class TestHtml(unittest.TestCase):
    def setUp(self):
        self.html = render_html(resultat())

    def test_autonome(self):
        """Aucune ressource externe : ouvrir le rapport ne doit rien exfiltrer."""
        for interdit in ("<script src", '<link rel="stylesheet"', "cdn."):
            self.assertNotIn(interdit, self.html, interdit)

    def test_theme_sombre(self):
        self.assertIn("prefers-color-scheme", self.html)

    def test_contenu(self):
        self.assertIn("111122223333", self.html)
        self.assertIn("arn:aws:s3:::b", self.html)
        self.assertEqual(self.html.count('class="row"'), 3)

    def test_echappement(self):
        f = finding()
        f.title = '<script>alert("xss")</script>'
        rendu = render_html(resultat([f]))
        self.assertNotIn("<script>alert", rendu)
        self.assertIn("&lt;script&gt;", rendu)

    def test_vide(self):
        self.assertIn("Rapport de posture", render_html(resultat([])))


class TestAsff(unittest.TestCase):
    def test_champs_obligatoires(self):
        doc = finding_to_asff(finding(), "111122223333", "eu-west-3")
        for cle in (
            "SchemaVersion",
            "Id",
            "ProductArn",
            "GeneratorId",
            "AwsAccountId",
            "Types",
            "CreatedAt",
            "UpdatedAt",
            "Severity",
            "Title",
            "Resources",
        ):
            self.assertIn(cle, doc, cle)

    def test_severite_normalisee(self):
        doc = finding_to_asff(finding(), "1", "eu-west-3")
        self.assertEqual(doc["Severity"], {"Label": "CRITICAL", "Normalized": 90})

    def test_conformite(self):
        doc = finding_to_asff(finding(), "1", "eu-west-3")
        self.assertEqual(doc["Compliance"]["Status"], "FAILED")
        self.assertIn("CIS AWS Foundations 2.1.4", doc["Compliance"]["RelatedRequirements"])

    def test_pass_devient_passed(self):
        doc = finding_to_asff(finding(status=Status.PASS), "1", "eu-west-3")
        self.assertEqual(doc["Compliance"]["Status"], "PASSED")

    def test_remediation_bornee(self):
        f = finding()
        f.remediation = "x" * 900
        doc = finding_to_asff(f, "1", "eu-west-3")
        self.assertLessEqual(len(doc["Remediation"]["Recommendation"]["Text"]), 512)

    def test_rendu_global(self):
        docs = json.loads(render_asff(resultat()))
        self.assertEqual(len(docs), 3)
        self.assertTrue(all(d["AwsAccountId"] == "111122223333" for d in docs))


class TestTousLesFormats(unittest.TestCase):
    def test_chaque_format_produit_du_texte(self):
        for nom, fonction in RENDERERS.items():
            sortie = fonction(resultat())
            self.assertIsInstance(sortie, str, nom)
            self.assertGreater(len(sortie), 50, nom)

    def test_chaque_format_supporte_le_vide(self):
        for nom, fonction in RENDERERS.items():
            self.assertIsInstance(fonction(resultat([])), str, nom)


if __name__ == "__main__":
    unittest.main(verbosity=2)
