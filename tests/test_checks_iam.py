"""Tests des controles IAM : dates tz-aware, cles inactives, root."""

from __future__ import annotations

import unittest

from cspm_lite.engine.checks.iam_checks import (
    age_in_days,
    iam_console_users_mfa,
    iam_key_rotation,
    iam_no_direct_admin,
    iam_no_wildcard_policy,
    iam_password_policy,
    iam_root_mfa,
    iam_root_no_access_key,
    iam_unused_credentials,
    to_bool,
)
from cspm_lite.engine.models import Status
from helpers import NOW, il_y_a, inventaire, password_policy, policy_iam, root, utilisateur

ADMIN = "arn:aws:iam::aws:policy/AdministratorAccess"


class TestOutils(unittest.TestCase):
    def test_to_bool(self):
        self.assertTrue(to_bool("true"))
        self.assertTrue(to_bool("TRUE"))
        for v in ("false", "N/A", "not_supported", "", "no_information"):
            self.assertFalse(to_bool(v), v)

    def test_age(self):
        self.assertEqual(age_in_days(il_y_a(120), NOW), 120)

    def test_age_valeurs_sentinelles(self):
        for v in ("N/A", "not_supported", "no_information", ""):
            self.assertIsNone(age_in_days(v, NOW), v)

    def test_age_date_invalide(self):
        self.assertIsNone(age_in_days("pas une date", NOW))

    def test_fuseau_horaire(self):
        """Les dates du rapport sont tz-aware : aucun datetime naif ne doit s'immiscer."""
        self.assertEqual(age_in_days("2026-07-20T12:00:00+00:00", NOW), 10)


class TestRoot(unittest.TestCase):
    def test_cle_root_detectee(self):
        inv = inventaire(root(access_key_1_active="true", access_key_1_last_rotated=il_y_a(10)))
        finding = iam_root_no_access_key(inv)[0]
        self.assertEqual(finding.status, Status.FAIL)
        self.assertIn("1", finding.details)

    def test_root_sans_cle(self):
        self.assertEqual(iam_root_no_access_key(inventaire(root()))[0].status, Status.PASS)

    def test_mfa_root(self):
        self.assertEqual(iam_root_mfa(inventaire(root(mfa_active="false")))[0].status, Status.FAIL)
        self.assertEqual(iam_root_mfa(inventaire(root()))[0].status, Status.PASS)

    def test_root_absent_du_rapport(self):
        """Sans ligne root, on ne produit rien plutot qu'un faux PASS."""
        self.assertEqual(iam_root_mfa(inventaire(utilisateur())), [])


class TestMFAConsole(unittest.TestCase):
    def test_utilisateur_console_sans_mfa(self):
        inv = inventaire(utilisateur("bob", password_enabled="true", mfa_active="false"))
        self.assertEqual(iam_console_users_mfa(inv)[0].status, Status.FAIL)

    def test_utilisateur_sans_console_ignore(self):
        """Pas d'acces console = hors perimetre, pas un echec."""
        inv = inventaire(utilisateur("svc", password_enabled="false", mfa_active="false"))
        self.assertEqual(iam_console_users_mfa(inv), [])

    def test_root_exclu(self):
        inv = inventaire(root(password_enabled="true", mfa_active="false"))
        self.assertEqual(iam_console_users_mfa(inv), [], "le root est couvert par IAM-002")


class TestRotationDesCles(unittest.TestCase):
    def test_cle_recente(self):
        inv = inventaire(
            utilisateur(access_key_1_active="true", access_key_1_last_rotated=il_y_a(10))
        )
        self.assertEqual(iam_key_rotation(inv)[0].status, Status.PASS)

    def test_cle_ancienne(self):
        inv = inventaire(
            utilisateur(access_key_1_active="true", access_key_1_last_rotated=il_y_a(200))
        )
        self.assertEqual(iam_key_rotation(inv)[0].status, Status.FAIL)

    def test_limite_90_jours(self):
        for jours, attendu in ((90, Status.PASS), (91, Status.FAIL)):
            inv = inventaire(
                utilisateur(access_key_1_active="true", access_key_1_last_rotated=il_y_a(jours))
            )
            self.assertEqual(iam_key_rotation(inv)[0].status, attendu, f"{jours} jours")

    def test_cle_inactive_ignoree(self):
        inv = inventaire(
            utilisateur(access_key_1_active="false", access_key_1_last_rotated=il_y_a(999))
        )
        self.assertEqual(iam_key_rotation(inv), [])

    def test_deux_cles(self):
        inv = inventaire(
            utilisateur(
                access_key_1_active="true",
                access_key_1_last_rotated=il_y_a(10),
                access_key_2_active="true",
                access_key_2_last_rotated=il_y_a(400),
            )
        )
        findings = iam_key_rotation(inv)
        self.assertEqual([f.status for f in findings], [Status.PASS, Status.FAIL])
        self.assertIn("access_key_2", findings[1].details)

    def test_date_indisponible(self):
        inv = inventaire(utilisateur(access_key_1_active="true", access_key_1_last_rotated="N/A"))
        self.assertEqual(iam_key_rotation(inv)[0].status, Status.NOT_AVAILABLE)


class TestCredentialsDormantes(unittest.TestCase):
    def test_mot_de_passe_dormant(self):
        inv = inventaire(utilisateur(password_enabled="true", password_last_used=il_y_a(200)))
        self.assertEqual(iam_unused_credentials(inv)[0].status, Status.FAIL)

    def test_mot_de_passe_recent(self):
        inv = inventaire(utilisateur(password_enabled="true", password_last_used=il_y_a(2)))
        self.assertEqual(iam_unused_credentials(inv)[0].status, Status.PASS)

    def test_jamais_utilise_se_rabat_sur_la_creation(self):
        """password_last_used vaut N/A si jamais utilise : on mesure depuis la creation."""
        inv = inventaire(
            utilisateur(
                password_enabled="true", password_last_used="N/A", user_creation_time=il_y_a(300)
            )
        )
        self.assertEqual(iam_unused_credentials(inv)[0].status, Status.FAIL)

    def test_cle_dormante(self):
        inv = inventaire(
            utilisateur(
                access_key_1_active="true",
                access_key_1_last_rotated=il_y_a(300),
                access_key_1_last_used_date=il_y_a(300),
            )
        )
        self.assertEqual(iam_unused_credentials(inv)[0].status, Status.FAIL)


class TestPrivileges(unittest.TestCase):
    def test_admin_direct(self):
        inv = inventaire(utilisateur("bob", attached_policies=[ADMIN]))
        self.assertEqual(iam_no_direct_admin(inv)[0].status, Status.FAIL)

    def test_policy_lecture_seule(self):
        lecture = ["arn:aws:iam::aws:policy/ReadOnlyAccess"]
        inv = inventaire(utilisateur("bob", attached_policies=lecture))
        self.assertEqual(iam_no_direct_admin(inv)[0].status, Status.PASS)

    def test_wildcard(self):
        doc = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
        self.assertEqual(
            iam_no_wildcard_policy(inventaire(policy_iam("p", doc)))[0].status, Status.FAIL
        )

    def test_wildcard_en_liste(self):
        doc = {"Statement": [{"Effect": "Allow", "Action": ["s3:*", "*"], "Resource": ["*"]}]}
        self.assertEqual(
            iam_no_wildcard_policy(inventaire(policy_iam("p", doc)))[0].status, Status.FAIL
        )

    def test_wildcard_action_seule_toleree(self):
        """Action '*' sur une ressource precise reste borne : pas de FAIL ici."""
        doc = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::b/*"}]}
        self.assertEqual(
            iam_no_wildcard_policy(inventaire(policy_iam("p", doc)))[0].status, Status.PASS
        )

    def test_deny_wildcard_non_signale(self):
        doc = {"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}
        self.assertEqual(
            iam_no_wildcard_policy(inventaire(policy_iam("p", doc)))[0].status, Status.PASS
        )

    def test_statement_dictionnaire(self):
        doc = {"Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}}
        self.assertEqual(
            iam_no_wildcard_policy(inventaire(policy_iam("p", doc)))[0].status, Status.FAIL
        )


class TestPolitiqueMotDePasse(unittest.TestCase):
    def test_conforme(self):
        self.assertEqual(iam_password_policy(inventaire(password_policy()))[0].status, Status.PASS)

    def test_trop_courte(self):
        inv = inventaire(password_policy(MinimumPasswordLength=8))
        finding = iam_password_policy(inv)[0]
        self.assertEqual(finding.status, Status.FAIL)
        self.assertIn("longueur", finding.details)

    def test_reutilisation_autorisee(self):
        inv = inventaire(password_policy(PasswordReusePrevention=0))
        self.assertEqual(iam_password_policy(inv)[0].status, Status.FAIL)

    def test_aucune_politique(self):
        inv = inventaire(password_policy())
        inv.by_type("AWS::IAM::PasswordPolicy")[0].raw = {}
        self.assertEqual(iam_password_policy(inv)[0].status, Status.FAIL)

    def test_absente_de_l_inventaire(self):
        self.assertEqual(iam_password_policy(inventaire()), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
