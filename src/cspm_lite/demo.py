"""Inventaire de demonstration, sans aucun appel AWS.

Sert a trois choses :

1. `cspm-lite scan --demo` fonctionne sans compte AWS ni credentials - n'importe qui
   peut cloner le depot et voir un rapport reel en trente secondes ;
2. il alimente le rapport d'exemple publie dans `docs/` ;
3. il documente, par l'exemple, la forme exacte que les collecteurs doivent produire.

Les ressources decrites reproduisent celles du labo Terraform de `lab/`.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from cspm_lite.engine import resource_types as rt
from cspm_lite.engine.models import Inventory, Resource

COMPTE = "111122223333"
REGION = "eu-west-3"

_MAINTENANT = datetime(2026, 7, 30, 12, 0, 0, tzinfo=UTC)


def _il_y_a(jours: int) -> str:
    return (_MAINTENANT - timedelta(days=jours)).isoformat()


def build_demo_inventory() -> Inventory:
    inv = Inventory(account_id=COMPTE, regions=[REGION], scanned_at=_MAINTENANT)

    # --- S3 : un bucket sain, un bucket qui fuit ---------------------------- #
    inv.add(
        Resource(
            id="arn:aws:s3:::acme-data-prod",
            type=rt.S3_BUCKET,
            region=REGION,
            name="acme-data-prod",
            tags={"Env": "prod"},
            raw={
                "name": "acme-data-prod",
                "public_access_block": {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                },
                "acl_grants": [],
                "policy": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Deny",
                            "Principal": "*",
                            "Action": "s3:*",
                            "Resource": "arn:aws:s3:::acme-data-prod/*",
                            "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                        }
                    ],
                },
                "encryption": {
                    "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]
                },
                "versioning": {"Status": "Enabled"},
                "logging": {"LoggingEnabled": {"TargetBucket": "acme-logs"}},
            },
        )
    )
    inv.add(
        Resource(
            id="arn:aws:s3:::acme-public-assets",
            type=rt.S3_BUCKET,
            region=REGION,
            name="acme-public-assets",
            raw={
                "name": "acme-public-assets",
                "public_access_block": None,
                "acl_grants": [
                    {
                        "Grantee": {
                            "Type": "Group",
                            "URI": "http://acs.amazonaws.com/groups/global/AllUsers",
                        },
                        "Permission": "READ",
                    }
                ],
                "policy": {
                    "Version": "2012-10-17",
                    "Statement": {
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::acme-public-assets/*",
                    },
                },
                "encryption": None,
                "versioning": {},
                "logging": {},
            },
        )
    )

    # --- IAM ---------------------------------------------------------------- #
    inv.add(
        Resource(
            id=f"arn:aws:iam::{COMPTE}:root",
            type=rt.IAM_USER,
            region="global",
            name="<root_account>",
            raw={
                "user": "<root_account>",
                "arn": f"arn:aws:iam::{COMPTE}:root",
                "user_creation_time": _il_y_a(900),
                "password_enabled": "not_supported",
                "password_last_used": _il_y_a(3),
                "mfa_active": "false",
                "access_key_1_active": "true",
                "access_key_1_last_rotated": _il_y_a(700),
                "access_key_2_active": "false",
                "access_key_2_last_rotated": "N/A",
            },
        )
    )
    inv.add(
        Resource(
            id=f"arn:aws:iam::{COMPTE}:user/alice",
            type=rt.IAM_USER,
            region="global",
            name="alice",
            raw={
                "user": "alice",
                "arn": f"arn:aws:iam::{COMPTE}:user/alice",
                "user_creation_time": _il_y_a(400),
                "password_enabled": "true",
                "password_last_used": _il_y_a(2),
                "mfa_active": "true",
                "access_key_1_active": "true",
                "access_key_1_last_rotated": _il_y_a(20),
                "access_key_1_last_used_date": _il_y_a(1),
                "access_key_2_active": "false",
                "access_key_2_last_rotated": "N/A",
                "attached_policies": ["arn:aws:iam::aws:policy/ReadOnlyAccess"],
            },
        )
    )
    inv.add(
        Resource(
            id=f"arn:aws:iam::{COMPTE}:user/ci-deployer",
            type=rt.IAM_USER,
            region="global",
            name="ci-deployer",
            raw={
                "user": "ci-deployer",
                "arn": f"arn:aws:iam::{COMPTE}:user/ci-deployer",
                "user_creation_time": _il_y_a(600),
                "password_enabled": "true",
                "password_last_used": _il_y_a(310),
                "mfa_active": "false",
                "access_key_1_active": "true",
                "access_key_1_last_rotated": _il_y_a(430),
                "access_key_1_last_used_date": _il_y_a(300),
                "access_key_2_active": "false",
                "access_key_2_last_rotated": "N/A",
                "attached_policies": ["arn:aws:iam::aws:policy/AdministratorAccess"],
            },
        )
    )
    inv.add(
        Resource(
            id=f"arn:aws:iam::{COMPTE}:policy/legacy-full-access",
            type=rt.IAM_POLICY,
            region="global",
            name="legacy-full-access",
            raw={
                "document": {
                    "Version": "2012-10-17",
                    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
                },
                "attachment_count": 1,
            },
        )
    )
    inv.add(
        Resource(
            id=f"arn:aws:iam::{COMPTE}:account-password-policy",
            type=rt.IAM_PASSWORD_POLICY,
            region="global",
            name="password-policy",
            raw={"MinimumPasswordLength": 8, "RequireSymbols": False},
        )
    )

    # --- Reseau ------------------------------------------------------------- #
    inv.add(
        Resource(
            id=f"arn:aws:ec2:{REGION}:{COMPTE}:security-group/sg-0bastion",
            type=rt.EC2_SECURITY_GROUP,
            region=REGION,
            name="bastion",
            raw={
                "GroupId": "sg-0bastion",
                "GroupName": "bastion",
                "IpPermissions": [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 22,
                        "ToPort": 22,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                        "UserIdGroupPairs": [],
                    },
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 3306,
                        "ToPort": 3306,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        "Ipv6Ranges": [],
                        "UserIdGroupPairs": [],
                    },
                ],
                "IpPermissionsEgress": [],
            },
        )
    )
    inv.add(
        Resource(
            id=f"arn:aws:ec2:{REGION}:{COMPTE}:security-group/sg-0default",
            type=rt.EC2_SECURITY_GROUP,
            region=REGION,
            name="default",
            raw={
                "GroupId": "sg-0default",
                "GroupName": "default",
                "IpPermissions": [
                    {
                        "IpProtocol": "-1",
                        "IpRanges": [],
                        "Ipv6Ranges": [],
                        "UserIdGroupPairs": [{"GroupId": "sg-0default"}],
                    }
                ],
                "IpPermissionsEgress": [
                    {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
                ],
            },
        )
    )
    inv.add(
        Resource(
            id=f"arn:aws:ec2:{REGION}:{COMPTE}:instance/i-0web01",
            type=rt.EC2_INSTANCE,
            region=REGION,
            name="web-01",
            tags={"Name": "web-01", "Env": "prod"},
            raw={
                "InstanceId": "i-0web01",
                "State": {"Name": "running"},
                "MetadataOptions": {"HttpTokens": "optional"},
            },
        )
    )
    inv.add(
        Resource(
            id=f"arn:aws:ec2:{REGION}:{COMPTE}:volume/vol-0data",
            type=rt.EC2_VOLUME,
            region=REGION,
            name="vol-0data",
            raw={"VolumeId": "vol-0data", "Encrypted": False},
        )
    )
    inv.add(
        Resource(
            id=f"arn:aws:ec2:{REGION}:{COMPTE}:vpc/vpc-0main",
            type=rt.EC2_VPC,
            region=REGION,
            name="main",
            raw={"VpcId": "vpc-0main", "flow_logs": []},
        )
    )

    # --- CloudTrail --------------------------------------------------------- #
    inv.add(
        Resource(
            id=f"arn:aws:cloudtrail:{REGION}:{COMPTE}:trail/audit",
            type=rt.CLOUDTRAIL_TRAIL,
            region=REGION,
            name="audit",
            raw={
                "Name": "audit",
                "IsMultiRegionTrail": False,
                "IncludeGlobalServiceEvents": True,
                "LogFileValidationEnabled": False,
                "KmsKeyId": None,
                "CloudWatchLogsLogGroupArn": None,
                "IsLogging": True,
            },
        )
    )

    return inv


def seed_demo_history(db_path: str, scans: int = 8) -> int:
    """Fabrique un historique de demonstration dans une base SQLite.

    La commande `history` n'a d'interet qu'avec plusieurs scans espaces dans le
    temps. Plutot que d'attendre des semaines pour la decouvrir, cette fonction
    simule une equipe qui corrige progressivement sa posture - avec une regression
    volontaire au milieu, pour que le taux de recidive ne soit pas artificiellement
    nul.

    Renvoie le nombre de scans ecrits.
    """
    import copy
    from datetime import timedelta

    from cspm_lite.engine.models import ScanResult, Status
    from cspm_lite.engine.registry import load_all_checks, run_checks
    from cspm_lite.history import save_scan

    load_all_checks()
    base = run_checks(build_demo_inventory())
    echecs = [f.key for f in base if f.status is Status.FAIL]
    # On corrige environ deux findings par scan, du plus grave au moins grave.
    ordre = [
        k
        for k in sorted(
            echecs,
            key=lambda k: -next(f.severity.weight for f in base if f.key == k),
        )
    ]

    ecrits = 0
    for i in range(scans):
        corriges = set(ordre[: min(len(ordre), i * 2)])
        # Regression volontaire : au scan 5, un finding deja corrige reapparait.
        if i == 5 and ordre:
            corriges.discard(ordre[0])

        findings = []
        for f in base:
            copie = copy.copy(f)
            copie.resource = f.resource
            if copie.key in corriges and copie.status is Status.FAIL:
                copie.status = Status.PASS
                copie.details = ""
            findings.append(copie)

        debut = _MAINTENANT - timedelta(days=7 * (scans - 1 - i))
        resultat = ScanResult(
            account_id=COMPTE,
            findings=findings,
            regions=[REGION],
            started_at=debut,
            finished_at=debut + timedelta(seconds=12),
        )
        save_scan(db_path, resultat)
        ecrits += 1
    return ecrits
