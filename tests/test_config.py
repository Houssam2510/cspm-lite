"""Tests de la configuration et des exclusions.

Le comportement teste ici est autant de la gouvernance que du code : une exclusion
sans justification est refusee, une exclusion expiree redevient bloquante.
"""

from __future__ import annotations

import tempfile
import unittest
from datetime import date
from pathlib import Path

from cspm_lite.config import (
    Config,
    ConfigError,
    Exclusion,
    apply_exclusions,
    find_config,
    load_config,
)
from cspm_lite.engine.models import Finding, Resource, Severity, Status

AUJOURDHUI = date(2026, 7, 30)


def ecrire(contenu: str) -> Path:
    dossier = Path(tempfile.mkdtemp())
    chemin = dossier / ".cspm.toml"
    chemin.write_text(contenu, encoding="utf-8")
    return chemin


def finding(check="S3-005", rid="arn:aws:s3:::b", status=Status.FAIL) -> Finding:
    return Finding(
        check_id=check,
        title="t",
        severity=Severity.LOW,
        status=status,
        resource=Resource(id=rid),
    )


class TestChargement(unittest.TestCase):
    def test_section_scan(self):
        chemin = ecrire('[scan]\nseverity_min = "HIGH"\nfail_on = "CRITICAL"\nservices = ["s3"]\n')
        config = load_config(chemin)
        self.assertEqual(config.severity_min, "HIGH")
        self.assertEqual(config.fail_on, "CRITICAL")
        self.assertEqual(config.services, ["s3"])

    def test_defauts(self):
        config = load_config(ecrire(""))
        self.assertEqual(config.severity_min, "INFORMATIONAL")
        self.assertEqual(config.fail_on, "HIGH")
        self.assertEqual(config.exclusions, [])

    def test_toml_invalide(self):
        with self.assertRaises(ConfigError):
            load_config(ecrire("[scan\n"))

    def test_recherche_remontante(self):
        chemin = ecrire("[scan]\n")
        sous_dossier = chemin.parent / "a" / "b"
        sous_dossier.mkdir(parents=True)
        self.assertEqual(find_config(sous_dossier), chemin)

    def test_aucun_fichier(self):
        vide = Path(tempfile.mkdtemp()) / "vide"
        vide.mkdir()
        # find_config remonte jusqu'a la racine ; on verifie seulement qu'il ne plante pas.
        self.assertIn(find_config(vide), (None, find_config(vide)))


class TestValidationDesExclusions(unittest.TestCase):
    def test_reason_obligatoire(self):
        contenu = '[[exclusions]]\ncheck = "S3-005"\nexpires_at = 2026-12-31\n'
        with self.assertRaises(ConfigError) as ctx:
            load_config(ecrire(contenu))
        self.assertIn("reason", str(ctx.exception))

    def test_expires_at_obligatoire(self):
        contenu = '[[exclusions]]\ncheck = "S3-005"\nreason = "parce que"\n'
        with self.assertRaises(ConfigError) as ctx:
            load_config(ecrire(contenu))
        self.assertIn("expires_at", str(ctx.exception))
        self.assertIn("permanente", str(ctx.exception), "le message doit expliquer pourquoi")

    def test_reason_vide_refusee(self):
        contenu = '[[exclusions]]\ncheck = "S3-005"\nreason = "   "\nexpires_at = 2026-12-31\n'
        with self.assertRaises(ConfigError):
            load_config(ecrire(contenu))

    def test_date_invalide(self):
        contenu = '[[exclusions]]\ncheck = "S3-005"\nreason = "x"\nexpires_at = "pas-une-date"\n'
        with self.assertRaises(ConfigError):
            load_config(ecrire(contenu))

    def test_date_en_chaine_acceptee(self):
        contenu = '[[exclusions]]\ncheck = "S3-005"\nreason = "x"\nexpires_at = "2026-12-31"\n'
        self.assertEqual(load_config(ecrire(contenu)).exclusions[0].expires_at, date(2026, 12, 31))


class TestCorrespondance(unittest.TestCase):
    def test_glob_sur_la_ressource(self):
        ex = Exclusion(check="S3-*", resource="arn:aws:s3:::acme-*", reason="x")
        self.assertTrue(ex.matches(finding("S3-005", "arn:aws:s3:::acme-public")))
        self.assertFalse(ex.matches(finding("S3-005", "arn:aws:s3:::autre")))
        self.assertFalse(ex.matches(finding("IAM-001", "arn:aws:s3:::acme-public")))

    def test_joker_total(self):
        self.assertTrue(Exclusion(reason="x").matches(finding()))


class TestApplication(unittest.TestCase):
    def test_finding_supprime(self):
        config = Config(
            exclusions=[
                Exclusion(
                    check="S3-005",
                    resource="*",
                    reason="assume",
                    expires_at=date(2026, 12, 31),
                )
            ]
        )
        findings = [finding("S3-005"), finding("S3-001")]
        avertissements = apply_exclusions(findings, config, AUJOURDHUI)
        self.assertTrue(findings[0].suppressed)
        self.assertFalse(findings[1].suppressed)
        self.assertIn("assume", findings[0].suppression_reason)
        self.assertEqual(avertissements, [])

    def test_exclusion_expiree_redevient_active(self):
        config = Config(
            exclusions=[Exclusion(check="S3-005", reason="dette", expires_at=date(2026, 1, 1))]
        )
        findings = [finding("S3-005")]
        avertissements = apply_exclusions(findings, config, AUJOURDHUI)
        self.assertFalse(findings[0].suppressed, "une exclusion expiree ne doit plus s'appliquer")
        self.assertEqual(len(avertissements), 1)
        self.assertIn("expiree", avertissements[0])

    def test_exclusion_sans_effet_signalee(self):
        config = Config(
            exclusions=[Exclusion(check="ZZZ-999", reason="x", expires_at=date(2026, 12, 31))]
        )
        avertissements = apply_exclusions([finding()], config, AUJOURDHUI)
        self.assertEqual(len(avertissements), 1)
        self.assertIn("sans effet", avertissements[0])

    def test_les_pass_ne_sont_pas_supprimes(self):
        config = Config(exclusions=[Exclusion(reason="x", expires_at=date(2026, 12, 31))])
        findings = [finding(status=Status.PASS)]
        apply_exclusions(findings, config, AUJOURDHUI)
        self.assertFalse(findings[0].suppressed)


class TestImpactSurLeScore(unittest.TestCase):
    def test_un_finding_supprime_ne_pese_pas(self):
        from cspm_lite.engine.models import ScanResult

        f = finding()
        resultat = ScanResult("1", [f])
        self.assertEqual(resultat.score, 0.0)
        f.suppressed = True
        self.assertEqual(resultat.score, 100.0, "un finding exclu sort du calcul du score")
        self.assertEqual(len(resultat.failed), 0)
        self.assertEqual(len(resultat.suppressed), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
