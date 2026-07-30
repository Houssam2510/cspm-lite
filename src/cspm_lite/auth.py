"""Sessions AWS et identite de l'appelant.

Seul ce module et `collectors/` importent boto3. Tout le reste de l'outil manipule
le modele de donnees et reste testable sans compte AWS ni reseau.

Principe applique ici : **moindre privilege**. cspm-lite est un outil de lecture ; il
doit tourner avec la policy manageee `SecurityAudit`, jamais avec
`AdministratorAccess`. Si un appel echoue en AccessDenied, on remonte un
avertissement, on ne demande pas plus de droits.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

if TYPE_CHECKING:  # pragma: no cover
    from boto3.session import Session

# Retries adaptatifs : l'API AWS renvoie du throttling en rafale sur un scan
# multi-region. Le mode "adaptive" ralentit automatiquement au lieu d'echouer.
BOTO_CONFIG = Config(
    retries={"mode": "adaptive", "max_attempts": 10},
    user_agent_extra="cspm-lite/0.1.0",
    connect_timeout=10,
    read_timeout=30,
)

DEFAULT_REGION = "us-east-1"


@dataclass(frozen=True)
class Identity:
    """Qui sommes-nous, du point de vue d'AWS."""

    account_id: str
    arn: str
    user_id: str

    @property
    def is_root(self) -> bool:
        return self.arn.endswith(":root")


def get_session(
    profile: str | None = None,
    role_arn: str | None = None,
    external_id: str | None = None,
    region: str | None = None,
    session_name: str = "cspm-lite",
) -> Session:
    """Cree une session boto3, eventuellement apres un AssumeRole.

    Le couple `role_arn` + `external_id` est le mecanisme standard d'acces d'un outil
    tiers a un compte client. L'ExternalId protege du *confused deputy* : sans lui, un
    autre client du meme prestataire pourrait deviner l'ARN du role et se faire
    acceder au compte par le prestataire lui-meme.
    """
    session = boto3.Session(profile_name=profile, region_name=region or DEFAULT_REGION)
    if not role_arn:
        return session

    sts = session.client("sts", config=BOTO_CONFIG)
    params: dict[str, Any] = {"RoleArn": role_arn, "RoleSessionName": session_name}
    if external_id:
        params["ExternalId"] = external_id
    creds = sts.assume_role(**params)["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=region or DEFAULT_REGION,
    )


def whoami(session: Session) -> Identity:
    """Identite de l'appelant via STS. Premier appel de tout scan : sans lui on ne
    sait meme pas quel compte on audite."""
    data = session.client("sts", config=BOTO_CONFIG).get_caller_identity()
    return Identity(account_id=data["Account"], arn=data["Arn"], user_id=data["UserId"])


def list_regions(session: Session, only_enabled: bool = True) -> list[str]:
    """Regions a scanner.

    Par defaut on ne garde que les regions activees sur le compte : scanner les 30+
    regions AWS quand 3 sont utilisees triple la duree du scan pour rien.
    """
    ec2 = session.client("ec2", region_name=DEFAULT_REGION, config=BOTO_CONFIG)
    try:
        filtres = (
            [{"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}]
            if only_enabled
            else []
        )
        reponse = ec2.describe_regions(Filters=filtres, AllRegions=not only_enabled)
    except ClientError:
        # Sans droit ec2:DescribeRegions, on se rabat sur les regions connues du SDK.
        return sorted(session.get_available_regions("ec2"))
    return sorted(r["RegionName"] for r in reponse["Regions"])
