"""Constructeurs de ressources pour les tests.

Chaque fabrique produit une ressource **saine** par defaut ; chaque test la degrade
sur le seul point qu'il verifie. On lit ainsi immediatement ce qui est teste, et
ajouter un champ au modele ne casse pas quarante tests.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from typing import Any

os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

from cspm_lite.engine import resource_types as rt  # noqa: E402
from cspm_lite.engine.models import Inventory, Resource  # noqa: E402

COMPTE = "111122223333"
REGION = "eu-west-3"
NOW = datetime(2026, 7, 30, 12, 0, 0, tzinfo=UTC)

PAB_ON = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}

ALL_USERS = "http://acs.amazonaws.com/groups/global/AllUsers"
AUTHENTICATED_USERS = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"


def il_y_a(jours: int) -> str:
    return (NOW - timedelta(days=jours)).isoformat()


def inventaire(*resources: Resource) -> Inventory:
    inv = Inventory(account_id=COMPTE, regions=[REGION], scanned_at=NOW)
    inv.extend(list(resources))
    return inv


def bucket(nom: str = "b", **raw: Any) -> Resource:
    base: dict[str, Any] = {
        "name": nom,
        "public_access_block": dict(PAB_ON),
        "acl_grants": [],
        "policy": None,
        "encryption": {
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
        },
        "versioning": {"Status": "Enabled"},
        "logging": {"LoggingEnabled": {"TargetBucket": "logs"}},
    }
    base.update(raw)
    return Resource(
        id=f"arn:aws:s3:::{nom}", type=rt.S3_BUCKET, region=REGION, name=nom, raw=base
    )


def grant(uri: str | None = None, gtype: str = "Group", perm: str = "READ") -> dict[str, Any]:
    grantee: dict[str, Any] = {"Type": gtype}
    if uri:
        grantee["URI"] = uri
    return {"Grantee": grantee, "Permission": perm}


def utilisateur(nom: str = "alice", **raw: Any) -> Resource:
    base: dict[str, Any] = {
        "user": nom,
        "arn": f"arn:aws:iam::{COMPTE}:user/{nom}",
        "user_creation_time": il_y_a(300),
        "password_enabled": "false",
        "password_last_used": "N/A",
        "mfa_active": "false",
        "access_key_1_active": "false",
        "access_key_1_last_rotated": "N/A",
        "access_key_2_active": "false",
        "access_key_2_last_rotated": "N/A",
        "attached_policies": [],
    }
    base.update(raw)
    return Resource(id=str(base["arn"]), type=rt.IAM_USER, region="global", name=nom, raw=base)


def root(**raw: Any) -> Resource:
    defauts: dict[str, Any] = {
        "arn": f"arn:aws:iam::{COMPTE}:root",
        "password_enabled": "not_supported",
        "mfa_active": "true",
    }
    defauts.update(raw)
    return utilisateur("<root_account>", **defauts)


def policy_iam(nom: str = "p", document: dict[str, Any] | None = None) -> Resource:
    return Resource(
        id=f"arn:aws:iam::{COMPTE}:policy/{nom}",
        type=rt.IAM_POLICY,
        region="global",
        name=nom,
        raw={"document": document or {"Statement": []}},
    )


def password_policy(**raw: Any) -> Resource:
    base: dict[str, Any] = {"MinimumPasswordLength": 14, "PasswordReusePrevention": 24}
    base.update(raw)
    return Resource(
        id=f"arn:aws:iam::{COMPTE}:account-password-policy",
        type=rt.IAM_PASSWORD_POLICY,
        region="global",
        name="password-policy",
        raw=base,
    )


def permission(
    proto: str = "tcp",
    frm: int | None = None,
    to: int | None = None,
    v4: tuple[str, ...] = (),
    v6: tuple[str, ...] = (),
    sgrefs: tuple[str, ...] = (),
) -> dict[str, Any]:
    perm: dict[str, Any] = {
        "IpProtocol": proto,
        "IpRanges": [{"CidrIp": c} for c in v4],
        "Ipv6Ranges": [{"CidrIpv6": c} for c in v6],
        "UserIdGroupPairs": [{"GroupId": g} for g in sgrefs],
    }
    if frm is not None:
        perm["FromPort"] = frm
        perm["ToPort"] = to if to is not None else frm
    return perm


def security_group(nom: str = "web", permissions: list[dict[str, Any]] | None = None,
                   egress: list[dict[str, Any]] | None = None) -> Resource:
    return Resource(
        id=f"arn:aws:ec2:{REGION}:{COMPTE}:security-group/sg-{nom}",
        type=rt.EC2_SECURITY_GROUP,
        region=REGION,
        name=nom,
        raw={
            "GroupId": f"sg-{nom}",
            "GroupName": nom,
            "IpPermissions": permissions or [],
            "IpPermissionsEgress": egress or [],
        },
    )


def instance(nom: str = "web-01", http_tokens: str = "required") -> Resource:
    return Resource(
        id=f"arn:aws:ec2:{REGION}:{COMPTE}:instance/i-{nom}",
        type=rt.EC2_INSTANCE,
        region=REGION,
        name=nom,
        raw={"InstanceId": f"i-{nom}", "MetadataOptions": {"HttpTokens": http_tokens}},
    )


def volume(nom: str = "vol-1", encrypted: bool = True) -> Resource:
    return Resource(
        id=f"arn:aws:ec2:{REGION}:{COMPTE}:volume/{nom}",
        type=rt.EC2_VOLUME,
        region=REGION,
        name=nom,
        raw={"VolumeId": nom, "Encrypted": encrypted},
    )


def vpc(nom: str = "vpc-1", flow_logs: bool = True) -> Resource:
    return Resource(
        id=f"arn:aws:ec2:{REGION}:{COMPTE}:vpc/{nom}",
        type=rt.EC2_VPC,
        region=REGION,
        name=nom,
        raw={"VpcId": nom, "flow_logs": [{"FlowLogId": "fl-1"}] if flow_logs else []},
    )


def trail(nom: str = "audit", **raw: Any) -> Resource:
    base: dict[str, Any] = {
        "Name": nom,
        "IsMultiRegionTrail": True,
        "IncludeGlobalServiceEvents": True,
        "LogFileValidationEnabled": True,
        "KmsKeyId": f"arn:aws:kms:{REGION}:{COMPTE}:key/abc",
        "CloudWatchLogsLogGroupArn": f"arn:aws:logs:{REGION}:{COMPTE}:log-group:ct",
        "IsLogging": True,
    }
    base.update(raw)
    return Resource(
        id=f"arn:aws:cloudtrail:{REGION}:{COMPTE}:trail/{nom}",
        type=rt.CLOUDTRAIL_TRAIL,
        region=REGION,
        name=nom,
        raw=base,
    )
