"""Tests de l'exercice 3. Ne modifie pas ce fichier."""

import unittest

from commun import Severity, Status
from exercice import (
    ALL_USERS,
    AUTHENTICATED_USERS,
    acl_public_reasons,
    bucket_public_reasons,
    check_s3_public,
    is_effectively_public,
    is_pab_effective,
    policy_allows_anyone,
)

PAB_ON = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}


def grant(uri=None, gtype="Group", perm="READ"):
    g = {"Type": gtype}
    if uri:
        g["URI"] = uri
    return {"Grantee": g, "Permission": perm}


def policy(statements):
    return {"Version": "2012-10-17", "Statement": statements}


def bucket(name="b", **kw):
    base = {
        "name": name,
        "region": "eu-west-3",
        "public_access_block": None,
        "acl_grants": [],
        "policy": None,
    }
    base.update(kw)
    return base


class TestPAB(unittest.TestCase):
    def test_tout_actif(self):
        self.assertTrue(is_pab_effective(PAB_ON))

    def test_none(self):
        self.assertFalse(is_pab_effective(None), "aucun PAB configure = non protege")

    def test_partiel(self):
        p = dict(PAB_ON, RestrictPublicBuckets=False)
        self.assertFalse(is_pab_effective(p), "3 drapeaux sur 4 ne protegent pas")

    def test_drapeau_manquant(self):
        p = {k: True for k in ("BlockPublicAcls", "IgnorePublicAcls")}
        self.assertFalse(is_pab_effective(p))

    def test_dict_vide(self):
        self.assertFalse(is_pab_effective({}))


class TestACL(unittest.TestCase):
    def test_aucun_grant(self):
        self.assertEqual(acl_public_reasons([]), set())
        self.assertEqual(acl_public_reasons(None), set())

    def test_allusers(self):
        self.assertEqual(acl_public_reasons([grant(ALL_USERS)]), {"acl-allusers"})

    def test_authenticatedusers(self):
        """Piege : AuthenticatedUsers = tout titulaire d'un compte AWS, donc public."""
        self.assertEqual(
            acl_public_reasons([grant(AUTHENTICATED_USERS)]), {"acl-authenticatedusers"}
        )

    def test_les_deux(self):
        g = [grant(ALL_USERS), grant(AUTHENTICATED_USERS, perm="WRITE")]
        self.assertEqual(acl_public_reasons(g), {"acl-allusers", "acl-authenticatedusers"})

    def test_canonical_user_non_public(self):
        g = [{"Grantee": {"Type": "CanonicalUser", "ID": "abc123"}, "Permission": "FULL_CONTROL"}]
        self.assertEqual(acl_public_reasons(g), set())

    def test_groupe_log_delivery_non_public(self):
        uri = "http://acs.amazonaws.com/groups/s3/LogDelivery"
        self.assertEqual(acl_public_reasons([grant(uri)]), set())

    def test_doublons(self):
        g = [grant(ALL_USERS, perm="READ"), grant(ALL_USERS, perm="READ_ACP")]
        self.assertEqual(acl_public_reasons(g), {"acl-allusers"})


class TestPolicy(unittest.TestCase):
    def test_none(self):
        self.assertFalse(policy_allows_anyone(None))

    def test_principal_etoile_chaine(self):
        p = policy([{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}])
        self.assertTrue(policy_allows_anyone(p))

    def test_principal_aws_etoile(self):
        p = policy([{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "s3:*"}])
        self.assertTrue(policy_allows_anyone(p))

    def test_principal_aws_liste(self):
        p = policy(
            [{"Effect": "Allow", "Principal": {"AWS": ["*", "arn:aws:iam::1:root"]},
              "Action": "s3:*"}]
        )
        self.assertTrue(policy_allows_anyone(p))

    def test_statement_dictionnaire_unique(self):
        """Piege : Statement peut etre un dict et pas une liste."""
        p = policy({"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"})
        self.assertTrue(policy_allows_anyone(p), "Statement sous forme de dict non gere")

    def test_deny_nest_pas_public(self):
        """Piege : un Deny sur * est une protection, pas un risque."""
        p = policy([{"Effect": "Deny", "Principal": "*", "Action": "s3:*"}])
        self.assertFalse(policy_allows_anyone(p))

    def test_condition_restreint(self):
        p = policy(
            [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
              "Condition": {"StringEquals": {"aws:SourceVpce": "vpce-1a2b"}}}]
        )
        self.assertFalse(policy_allows_anyone(p), "une Condition restreint l'acces")

    def test_principal_nomme(self):
        p = policy([{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123:root"},
                     "Action": "s3:*"}])
        self.assertFalse(policy_allows_anyone(p))

    def test_principal_service(self):
        p = policy([{"Effect": "Allow", "Principal": {"Service": "cloudtrail.amazonaws.com"},
                     "Action": "s3:PutObject"}])
        self.assertFalse(policy_allows_anyone(p))

    def test_plusieurs_statements(self):
        p = policy([
            {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::1:root"}, "Action": "s3:*"},
            {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"},
        ])
        self.assertTrue(policy_allows_anyone(p))

    def test_sans_statement(self):
        self.assertFalse(policy_allows_anyone({"Version": "2012-10-17"}))


class TestRaisons(unittest.TestCase):
    def test_aucune(self):
        self.assertEqual(bucket_public_reasons(bucket()), [])

    def test_triees_et_completes(self):
        b = bucket(
            acl_grants=[grant(AUTHENTICATED_USERS), grant(ALL_USERS)],
            policy=policy([{"Effect": "Allow", "Principal": "*", "Action": "s3:*"}]),
        )
        self.assertEqual(
            bucket_public_reasons(b),
            ["acl-allusers", "acl-authenticatedusers", "policy-principal-wildcard"],
        )

    def test_raisons_independantes_du_pab(self):
        """Les raisons decrivent ce que le bucket expose, meme si le PAB bloque."""
        b = bucket(public_access_block=PAB_ON, acl_grants=[grant(ALL_USERS)])
        self.assertEqual(bucket_public_reasons(b), ["acl-allusers"])


class TestEffectivementPublic(unittest.TestCase):
    def test_acl_publique_sans_pab(self):
        self.assertTrue(is_effectively_public(bucket(acl_grants=[grant(ALL_USERS)])))

    def test_pab_neutralise(self):
        b = bucket(public_access_block=PAB_ON, acl_grants=[grant(ALL_USERS)])
        self.assertFalse(is_effectively_public(b))

    def test_pab_partiel_ne_neutralise_pas(self):
        b = bucket(
            public_access_block=dict(PAB_ON, BlockPublicPolicy=False),
            acl_grants=[grant(ALL_USERS)],
        )
        self.assertTrue(is_effectively_public(b))

    def test_bucket_sain(self):
        self.assertFalse(is_effectively_public(bucket(public_access_block=PAB_ON)))

    def test_bucket_sans_pab_mais_sans_exposition(self):
        self.assertFalse(is_effectively_public(bucket()))


class TestCheck(unittest.TestCase):
    def setUp(self):
        self.buckets = [
            bucket("sain", public_access_block=PAB_ON),
            bucket("fuite", acl_grants=[grant(ALL_USERS)]),
            bucket("policy-ouverte",
                   policy=policy([{"Effect": "Allow", "Principal": "*", "Action": "s3:*"}])),
        ]
        self.res = check_s3_public(self.buckets)

    def test_un_finding_par_bucket(self):
        self.assertEqual(len(self.res), 3)

    def test_ordre_preserve(self):
        self.assertEqual([f.resource.name for f in self.res],
                         ["sain", "fuite", "policy-ouverte"])

    def test_statuts(self):
        self.assertEqual([f.status for f in self.res],
                         [Status.PASS, Status.FAIL, Status.FAIL])

    def test_metadonnees(self):
        f = self.res[1]
        self.assertEqual(f.check_id, "S3-002")
        self.assertEqual(f.title, "Bucket S3 accessible publiquement")
        self.assertEqual(f.severity, Severity.CRITICAL)
        self.assertEqual(f.resource.id, "arn:aws:s3:::fuite")
        self.assertEqual(f.resource.type, "AWS::S3::Bucket")
        self.assertEqual(f.resource.region, "eu-west-3")
        self.assertTrue(f.remediation.strip(), "ecris un texte de remediation")

    def test_details(self):
        self.assertEqual(self.res[1].details, "acl-allusers")
        self.assertEqual(self.res[2].details, "policy-principal-wildcard")
        self.assertEqual(self.res[0].details, "")

    def test_liste_vide(self):
        self.assertEqual(check_s3_public([]), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
