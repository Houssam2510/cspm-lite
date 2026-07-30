"""Tests des controles S3, y compris les pieges du langage de policy."""

from __future__ import annotations

import unittest

from cspm_lite.engine.checks.s3_checks import (
    acl_public_reasons,
    bucket_public_reasons,
    is_pab_effective,
    policy_allows_anyone,
    policy_enforces_tls,
    s3_access_logging,
    s3_block_public_access,
    s3_bucket_public,
    s3_encryption,
    s3_tls_only,
    s3_versioning,
)
from cspm_lite.engine.models import Status
from helpers import ALL_USERS, AUTHENTICATED_USERS, PAB_ON, bucket, grant, inventaire


def policy(statements):
    return {"Version": "2012-10-17", "Statement": statements}


class TestPublicAccessBlock(unittest.TestCase):
    def test_complet(self):
        self.assertTrue(is_pab_effective(PAB_ON))

    def test_absent(self):
        self.assertFalse(is_pab_effective(None))

    def test_partiel(self):
        self.assertFalse(
            is_pab_effective(dict(PAB_ON, RestrictPublicBuckets=False)),
            "trois drapeaux sur quatre ne protegent pas",
        )

    def test_check(self):
        inv = inventaire(bucket("ok"), bucket("ko", public_access_block=None))
        statuts = [f.status for f in s3_block_public_access(inv)]
        self.assertEqual(statuts, [Status.PASS, Status.FAIL])

    def test_details_listent_les_drapeaux_manquants(self):
        inv = inventaire(bucket("ko", public_access_block=dict(PAB_ON, BlockPublicPolicy=False)))
        self.assertIn("BlockPublicPolicy", s3_block_public_access(inv)[0].details)


class TestACL(unittest.TestCase):
    def test_allusers(self):
        self.assertEqual(acl_public_reasons([grant(ALL_USERS)]), {"acl-allusers"})

    def test_authenticatedusers_est_public(self):
        """Piege : AuthenticatedUsers designe tout titulaire d'un compte AWS."""
        self.assertEqual(
            acl_public_reasons([grant(AUTHENTICATED_USERS)]), {"acl-authenticatedusers"}
        )

    def test_canonical_user_non_public(self):
        g = [{"Grantee": {"Type": "CanonicalUser", "ID": "abc"}, "Permission": "FULL_CONTROL"}]
        self.assertEqual(acl_public_reasons(g), set())

    def test_log_delivery_non_public(self):
        uri = "http://acs.amazonaws.com/groups/s3/LogDelivery"
        self.assertEqual(acl_public_reasons([grant(uri)]), set())

    def test_none(self):
        self.assertEqual(acl_public_reasons(None), set())


class TestPolicyPublique(unittest.TestCase):
    def test_principal_chaine(self):
        self.assertTrue(policy_allows_anyone(policy([{"Effect": "Allow", "Principal": "*"}])))

    def test_principal_aws_liste(self):
        p = policy([{"Effect": "Allow", "Principal": {"AWS": ["*", "arn:aws:iam::1:root"]}}])
        self.assertTrue(policy_allows_anyone(p))

    def test_statement_dictionnaire_unique(self):
        """Piege : Statement peut etre un dict au lieu d'une liste."""
        self.assertTrue(policy_allows_anyone(policy({"Effect": "Allow", "Principal": "*"})))

    def test_deny_est_une_protection(self):
        self.assertFalse(policy_allows_anyone(policy([{"Effect": "Deny", "Principal": "*"}])))

    def test_condition_restreint(self):
        p = policy(
            [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Condition": {"StringEquals": {"aws:SourceVpce": "vpce-1"}},
                }
            ]
        )
        self.assertFalse(policy_allows_anyone(p))

    def test_principal_service(self):
        p = policy([{"Effect": "Allow", "Principal": {"Service": "cloudtrail.amazonaws.com"}}])
        self.assertFalse(policy_allows_anyone(p))

    def test_none(self):
        self.assertFalse(policy_allows_anyone(None))


class TestBucketPublic(unittest.TestCase):
    def test_raisons_triees(self):
        raw = bucket(
            "x",
            acl_grants=[grant(AUTHENTICATED_USERS), grant(ALL_USERS)],
            policy=policy([{"Effect": "Allow", "Principal": "*"}]),
        ).raw
        self.assertEqual(
            bucket_public_reasons(raw),
            ["acl-allusers", "acl-authenticatedusers", "policy-principal-wildcard"],
        )

    def test_pab_neutralise_mais_signale(self):
        inv = inventaire(bucket("x", acl_grants=[grant(ALL_USERS)]))
        finding = s3_bucket_public(inv)[0]
        self.assertEqual(finding.status, Status.PASS)
        self.assertIn("neutralise", finding.details)

    def test_sans_pab_echoue(self):
        inv = inventaire(bucket("x", public_access_block=None, acl_grants=[grant(ALL_USERS)]))
        self.assertEqual(s3_bucket_public(inv)[0].status, Status.FAIL)

    def test_bucket_sain(self):
        self.assertEqual(s3_bucket_public(inventaire(bucket()))[0].status, Status.PASS)


class TestTLS(unittest.TestCase):
    def test_deny_secure_transport(self):
        p = policy(
            [
                {
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "s3:*",
                    "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                }
            ]
        )
        self.assertTrue(policy_enforces_tls(p))

    def test_bool_if_exists(self):
        p = policy(
            [
                {
                    "Effect": "Deny",
                    "Condition": {"BoolIfExists": {"aws:SecureTransport": "false"}},
                }
            ]
        )
        self.assertTrue(policy_enforces_tls(p))

    def test_allow_ne_compte_pas(self):
        p = policy(
            [
                {
                    "Effect": "Allow",
                    "Condition": {"Bool": {"aws:SecureTransport": "true"}},
                }
            ]
        )
        self.assertFalse(policy_enforces_tls(p))

    def test_check(self):
        inv = inventaire(bucket("nu"))
        self.assertEqual(s3_tls_only(inv)[0].status, Status.FAIL)


class TestAutresControles(unittest.TestCase):
    def test_chiffrement(self):
        inv = inventaire(bucket("ok"), bucket("ko", encryption=None))
        self.assertEqual([f.status for f in s3_encryption(inv)], [Status.PASS, Status.FAIL])

    def test_chiffrement_details(self):
        self.assertEqual(s3_encryption(inventaire(bucket()))[0].details, "AES256")

    def test_versioning(self):
        inv = inventaire(bucket("ok"), bucket("ko", versioning={"Status": "Suspended"}))
        self.assertEqual([f.status for f in s3_versioning(inv)], [Status.PASS, Status.FAIL])

    def test_versioning_absent(self):
        self.assertEqual(
            s3_versioning(inventaire(bucket("x", versioning={})))[0].status, Status.FAIL
        )

    def test_logging(self):
        inv = inventaire(bucket("ok"), bucket("ko", logging={}))
        self.assertEqual([f.status for f in s3_access_logging(inv)], [Status.PASS, Status.FAIL])

    def test_inventaire_vide(self):
        for fonction in (s3_encryption, s3_versioning, s3_access_logging, s3_tls_only):
            self.assertEqual(fonction(inventaire()), [], fonction.__name__)


if __name__ == "__main__":
    unittest.main(verbosity=2)
