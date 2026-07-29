"""Tests de l'exercice 4. Ne modifie pas ce fichier."""

import unittest
from datetime import datetime, timedelta, timezone

from commun import Severity, Status
from exercice import (
    check_old_keys,
    check_root_mfa,
    key_age_days,
    parse_credential_report,
    to_bool,
)

NOW = datetime(2026, 7, 29, 12, 0, 0, tzinfo=timezone.utc)

ENTETE = (
    "user,arn,user_creation_time,password_enabled,password_last_used,mfa_active,"
    "access_key_1_active,access_key_1_last_rotated,"
    "access_key_2_active,access_key_2_last_rotated"
)

CSV = ENTETE + "\n" + "\n".join([
    "<root_account>,arn:aws:iam::111122223333:root,2020-01-01T00:00:00+00:00,"
    "not_supported,2026-07-01T09:00:00+00:00,false,false,N/A,false,N/A",
    "alice,arn:aws:iam::111122223333:user/alice,2023-03-10T12:00:00+00:00,"
    "true,2026-07-20T08:00:00+00:00,true,true,2024-01-05T10:00:00+00:00,false,N/A",
    "bob,arn:aws:iam::111122223333:user/bob,2025-01-01T00:00:00+00:00,"
    "false,no_information,false,true,2026-07-01T00:00:00+00:00,"
    "true,2023-02-02T00:00:00+00:00",
])


def iso(jours_avant):
    return (NOW - timedelta(days=jours_avant)).isoformat()


def row(user="u", arn="arn:aws:iam::1:user/u", mfa="false",
        k1="false", k1r="N/A", k2="false", k2r="N/A"):
    return {
        "user": user, "arn": arn, "mfa_active": mfa,
        "access_key_1_active": k1, "access_key_1_last_rotated": k1r,
        "access_key_2_active": k2, "access_key_2_last_rotated": k2r,
    }


class TestParsing(unittest.TestCase):
    def test_nombre_de_lignes(self):
        self.assertEqual(len(parse_credential_report(CSV)), 3)

    def test_colonnes(self):
        rows = parse_credential_report(CSV)
        self.assertEqual(rows[1]["user"], "alice")
        self.assertEqual(rows[1]["arn"], "arn:aws:iam::111122223333:user/alice")
        self.assertEqual(rows[1]["access_key_1_last_rotated"], "2024-01-05T10:00:00+00:00")

    def test_ordre_preserve(self):
        self.assertEqual([r["user"] for r in parse_credential_report(CSV)],
                         ["<root_account>", "alice", "bob"])

    def test_entete_seule(self):
        self.assertEqual(parse_credential_report(ENTETE + "\n"), [])


class TestToBool(unittest.TestCase):
    def test_vrai(self):
        self.assertTrue(to_bool("true"))
        self.assertTrue(to_bool("TRUE"))
        self.assertTrue(to_bool("True"))

    def test_faux(self):
        for v in ("false", "N/A", "not_supported", "", "no_information", "oui"):
            self.assertFalse(to_bool(v), f"to_bool({v!r}) devrait etre False")


class TestAge(unittest.TestCase):
    def test_valeurs_nulles(self):
        for v in ("N/A", "not_supported", "no_information", ""):
            self.assertIsNone(key_age_days(v, NOW), f"{v!r} doit donner None")

    def test_age_simple(self):
        self.assertEqual(key_age_days(iso(120), NOW), 120)

    def test_age_zero(self):
        self.assertEqual(key_age_days(NOW.isoformat(), NOW), 0)

    def test_fuseau_horaire(self):
        """Les dates du rapport sont tz-aware : ne construis pas de datetime naif."""
        self.assertEqual(key_age_days("2026-07-19T12:00:00+00:00", NOW), 10)

    def test_entier(self):
        self.assertIsInstance(key_age_days(iso(45), NOW), int)


class TestVieillesCles(unittest.TestCase):
    def test_cle_recente_pass(self):
        r = [row(k1="true", k1r=iso(10))]
        res = check_old_keys(r, NOW)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0].status, Status.PASS)

    def test_cle_ancienne_fail(self):
        res = check_old_keys([row(k1="true", k1r=iso(200))], NOW)
        self.assertEqual(res[0].status, Status.FAIL)

    def test_limite_exacte_90_jours(self):
        """Strictement superieur : 90 jours pile passe, 91 echoue."""
        self.assertEqual(check_old_keys([row(k1="true", k1r=iso(90))], NOW)[0].status,
                         Status.PASS)
        self.assertEqual(check_old_keys([row(k1="true", k1r=iso(91))], NOW)[0].status,
                         Status.FAIL)

    def test_cle_inactive_ignoree(self):
        """Piege : une cle inactive ne produit aucun finding."""
        res = check_old_keys([row(k1="false", k1r=iso(999))], NOW)
        self.assertEqual(res, [])

    def test_deux_cles(self):
        r = [row(k1="true", k1r=iso(10), k2="true", k2r=iso(400))]
        res = check_old_keys(r, NOW)
        self.assertEqual(len(res), 2)
        self.assertEqual(res[0].details, "access_key_1 : 10 jours")
        self.assertEqual(res[1].details, "access_key_2 : 400 jours")
        self.assertEqual([f.status for f in res], [Status.PASS, Status.FAIL])

    def test_seuil_personnalise(self):
        res = check_old_keys([row(k1="true", k1r=iso(45))], NOW, max_age_days=30)
        self.assertEqual(res[0].status, Status.FAIL)

    def test_date_indisponible(self):
        res = check_old_keys([row(k1="true", k1r="N/A")], NOW)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0].status, Status.NOT_AVAILABLE)
        self.assertEqual(res[0].details, "access_key_1 : date indisponible")

    def test_metadonnees(self):
        r = [row(user="alice", arn="arn:aws:iam::1:user/alice", k1="true", k1r=iso(200))]
        f = check_old_keys(r, NOW)[0]
        self.assertEqual(f.check_id, "IAM-004")
        self.assertEqual(f.title, "Cle d'acces de plus de 90 jours")
        self.assertEqual(f.severity, Severity.HIGH)
        self.assertEqual(f.resource.id, "arn:aws:iam::1:user/alice")
        self.assertEqual(f.resource.type, "AWS::IAM::User")
        self.assertEqual(f.resource.name, "alice")
        self.assertTrue(f.remediation.strip(), "ecris un texte de remediation")

    def test_ordre_global(self):
        rows = [
            row(user="a", k1="true", k1r=iso(1)),
            row(user="b", k1="false", k1r="N/A", k2="true", k2r=iso(2)),
        ]
        res = check_old_keys(rows, NOW)
        self.assertEqual([(f.resource.name, f.details) for f in res],
                         [("a", "access_key_1 : 1 jours"), ("b", "access_key_2 : 2 jours")])

    def test_rapport_reel(self):
        res = check_old_keys(parse_credential_report(CSV), NOW)
        # root : aucune cle active. alice : cle 1 active (ancienne). bob : cles 1 et 2.
        self.assertEqual(len(res), 3)
        self.assertEqual([f.resource.name for f in res], ["alice", "bob", "bob"])
        self.assertEqual([f.status for f in res], [Status.FAIL, Status.PASS, Status.FAIL])


class TestRootMFA(unittest.TestCase):
    def test_mfa_absent(self):
        f = check_root_mfa(parse_credential_report(CSV))
        self.assertEqual(f.status, Status.FAIL)
        self.assertEqual(f.check_id, "IAM-002")
        self.assertEqual(f.title, "MFA active sur le compte root")
        self.assertEqual(f.severity, Severity.CRITICAL)
        self.assertEqual(f.resource.id, "arn:aws:iam::111122223333:root")

    def test_mfa_present(self):
        rows = [row(user="<root_account>", arn="arn:aws:iam::1:root", mfa="true")]
        self.assertEqual(check_root_mfa(rows).status, Status.PASS)

    def test_root_absent(self):
        f = check_root_mfa([row(user="alice")])
        self.assertEqual(f.status, Status.NOT_AVAILABLE)
        self.assertEqual(f.resource.id, "-")

    def test_renvoie_un_finding_pas_une_liste(self):
        self.assertFalse(isinstance(check_root_mfa(parse_credential_report(CSV)), list))


if __name__ == "__main__":
    unittest.main(verbosity=2)
