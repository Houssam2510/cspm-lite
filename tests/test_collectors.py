"""Tests des collecteurs avec moto (AWS simule en memoire).

Ces tests sont les seuls a avoir besoin de boto3 et moto ; ils se sautent proprement
si les dependances ne sont pas installees, pour que la suite reste executable avec la
seule bibliotheque standard.

C'est la pyramide de tests en action : beaucoup de tests rapides sur la logique pure
(les checks), peu de tests lents sur la couche d'integration. Cette repartition n'est
possible que parce que collecte et evaluation sont separees.
"""

from __future__ import annotations

import unittest

try:
    import boto3
    from moto import mock_aws

    DEPENDANCES = True
except ImportError:  # pragma: no cover
    DEPENDANCES = False

from cspm_lite.engine import resource_types as rt
from cspm_lite.engine.models import Inventory

pytestmark = []


@unittest.skipUnless(DEPENDANCES, "boto3 et moto requis : pip install -e '.[dev]'")
class TestCollecteS3(unittest.TestCase):
    def test_bucket_nu_est_collecte(self):
        from cspm_lite.collectors.scan_s3 import collect_s3

        with mock_aws():
            s3 = boto3.client("s3", region_name="us-east-1")
            s3.create_bucket(Bucket="bucket-nu")
            session = boto3.Session(region_name="us-east-1")
            resources = collect_s3(session, "us-east-1", Inventory())

        self.assertEqual(len(resources), 1)
        bucket = resources[0]
        self.assertEqual(bucket.type, rt.S3_BUCKET)
        self.assertEqual(bucket.id, "arn:aws:s3:::bucket-nu")
        # Les absences de configuration doivent etre des None, pas des exceptions.
        self.assertIsNone(bucket.raw["policy"])
        self.assertIsNone(bucket.raw["encryption"])

    def test_bucket_configure(self):
        from cspm_lite.collectors.scan_s3 import collect_s3

        with mock_aws():
            s3 = boto3.client("s3", region_name="us-east-1")
            s3.create_bucket(Bucket="bucket-sain")
            s3.put_bucket_versioning(
                Bucket="bucket-sain", VersioningConfiguration={"Status": "Enabled"}
            )
            s3.put_public_access_block(
                Bucket="bucket-sain",
                PublicAccessBlockConfiguration={
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                },
            )
            session = boto3.Session(region_name="us-east-1")
            resources = collect_s3(session, "us-east-1", Inventory())

        raw = resources[0].raw
        self.assertEqual(raw["versioning"]["Status"], "Enabled")
        self.assertTrue(raw["public_access_block"]["BlockPublicAcls"])


@unittest.skipUnless(DEPENDANCES, "boto3 et moto requis : pip install -e '.[dev]'")
class TestCollecteEc2(unittest.TestCase):
    def test_security_group_par_defaut(self):
        from cspm_lite.collectors.scan_ec2 import collect_ec2

        with mock_aws():
            session = boto3.Session(region_name="eu-west-3")
            resources = collect_ec2(session, "eu-west-3", Inventory(account_id="123456789012"))

        sgs = [r for r in resources if r.type == rt.EC2_SECURITY_GROUP]
        self.assertGreaterEqual(len(sgs), 1)
        self.assertTrue(any(sg.name == "default" for sg in sgs))

    def test_instance_terminee_ignoree(self):
        from cspm_lite.collectors.scan_ec2 import collect_ec2

        with mock_aws():
            ec2 = boto3.client("ec2", region_name="eu-west-3")
            images = ec2.describe_images()["Images"]
            instance = ec2.run_instances(ImageId=images[0]["ImageId"], MinCount=1, MaxCount=1)[
                "Instances"
            ][0]
            ec2.terminate_instances(InstanceIds=[instance["InstanceId"]])
            session = boto3.Session(region_name="eu-west-3")
            resources = collect_ec2(session, "eu-west-3", Inventory(account_id="123456789012"))

        self.assertEqual([r for r in resources if r.type == rt.EC2_INSTANCE], [])


@unittest.skipUnless(DEPENDANCES, "boto3 et moto requis : pip install -e '.[dev]'")
class TestCollecteIam(unittest.TestCase):
    def test_politique_de_mot_de_passe_absente(self):
        """NoSuchEntity est un constat, pas une panne : le collecteur doit continuer."""
        from cspm_lite.collectors.scan_iam import collect_iam

        with mock_aws():
            session = boto3.Session(region_name="us-east-1")
            resources = collect_iam(session, "us-east-1", Inventory(account_id="123456789012"))

        politiques = [r for r in resources if r.type == rt.IAM_PASSWORD_POLICY]
        self.assertEqual(len(politiques), 1)
        self.assertEqual(politiques[0].raw, {})


@unittest.skipUnless(DEPENDANCES, "boto3 et moto requis : pip install -e '.[dev]'")
class TestSafeCall(unittest.TestCase):
    def test_erreur_inattendue_remonte(self):
        """safe_call n'absorbe que les codes "non configure", pas les vraies pannes."""
        from botocore.exceptions import ClientError

        from cspm_lite.collectors.base import safe_call

        def appel_qui_echoue():
            raise ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "refuse"}}, "GetBucketPolicy"
            )

        with self.assertRaises(ClientError):
            safe_call(appel_qui_echoue)

    def test_absence_absorbee(self):
        from botocore.exceptions import ClientError

        from cspm_lite.collectors.base import safe_call

        def sans_policy():
            raise ClientError(
                {"Error": {"Code": "NoSuchBucketPolicy", "Message": "absent"}}, "GetBucketPolicy"
            )

        self.assertIsNone(safe_call(sans_policy))


if __name__ == "__main__":
    unittest.main(verbosity=2)
