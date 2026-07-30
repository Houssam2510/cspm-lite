"""Controles S3.

Un bucket peut devenir public par quatre chemins independants (ACL, bucket policy,
Block Public Access absent, hebergement de site). Un outil qui n'en verifie qu'un
donne une fausse assurance - c'est pire que pas d'outil du tout.
"""

from __future__ import annotations

from typing import Any

from cspm_lite.engine import resource_types as rt
from cspm_lite.engine.models import Finding, Inventory, Severity
from cspm_lite.engine.registry import check, make_finding

ALL_USERS = "http://acs.amazonaws.com/groups/global/AllUsers"
AUTHENTICATED_USERS = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"

PAB_FLAGS = (
    "BlockPublicAcls",
    "IgnorePublicAcls",
    "BlockPublicPolicy",
    "RestrictPublicBuckets",
)

DOC_S3_PUBLIC = (
    "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"
)


# --------------------------------------------------------------------------- #
# Fonctions d'analyse, publiques pour etre testables independamment des checks
# --------------------------------------------------------------------------- #


def is_pab_effective(pab: dict[str, Any] | None) -> bool:
    """True seulement si les quatre drapeaux du Block Public Access sont actifs.

    Exiger les quatre est un choix : BlockPublicAcls ne neutralise que les ACL et
    BlockPublicPolicy que les policies. Un blocage partiel est une fausse securite.
    """
    if not isinstance(pab, dict):
        return False
    return all(pab.get(flag) is True for flag in PAB_FLAGS)


def acl_public_reasons(grants: list[dict[str, Any]] | None) -> set[str]:
    """Raisons d'exposition provenant des ACL.

    Piege du metier : `AuthenticatedUsers` ne designe pas "mes utilisateurs" mais
    n'importe quel titulaire d'un compte AWS dans le monde. C'est donc public.
    """
    raisons: set[str] = set()
    for grant in grants or []:
        uri = (grant.get("Grantee") or {}).get("URI")
        if uri == ALL_USERS:
            raisons.add("acl-allusers")
        elif uri == AUTHENTICATED_USERS:
            raisons.add("acl-authenticatedusers")
    return raisons


def _principal_est_generique(principal: Any) -> bool:
    if principal == "*":
        return True
    if isinstance(principal, dict):
        aws = principal.get("AWS")
        if aws == "*":
            return True
        if isinstance(aws, list) and "*" in aws:
            return True
    return False


def _statements(policy: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Normalise Statement, qui peut etre une liste OU un dictionnaire unique."""
    if not isinstance(policy, dict):
        return []
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        return [statements]
    return [s for s in statements if isinstance(s, dict)]


def policy_allows_anyone(policy: dict[str, Any] | None) -> bool:
    """True si une declaration Allow ouvre a un Principal generique sans Condition.

    Un `Deny` sur `*` est une protection, pas un risque. Une `Condition`
    (aws:SourceVpce, aws:PrincipalOrgID...) restreint l'acces : motif legitime tres
    repandu qu'il ne faut pas signaler.
    """
    for st in _statements(policy):
        if st.get("Effect") != "Allow" or st.get("Condition"):
            continue
        if _principal_est_generique(st.get("Principal")):
            return True
    return False


def policy_enforces_tls(policy: dict[str, Any] | None) -> bool:
    """True si la policy refuse explicitement les requetes non chiffrees."""
    for st in _statements(policy):
        if st.get("Effect") != "Deny":
            continue
        condition = st.get("Condition") or {}
        for operateur in ("Bool", "BoolIfExists"):
            valeur = (condition.get(operateur) or {}).get("aws:SecureTransport")
            if str(valeur).lower() in {"false", "['false']"}:
                return True
    return False


def bucket_public_reasons(raw: dict[str, Any]) -> list[str]:
    """Toutes les raisons d'exposition, triees et sans doublon."""
    raisons = acl_public_reasons(raw.get("acl_grants"))
    if policy_allows_anyone(raw.get("policy")):
        raisons.add("policy-principal-wildcard")
    return sorted(raisons)


# --------------------------------------------------------------------------- #
# Controles
# --------------------------------------------------------------------------- #


@check(
    id="S3-001",
    title="Block Public Access active sur le bucket",
    severity=Severity.HIGH,
    service="s3",
    cis="2.1.4",
    remediation="Activer les quatre drapeaux de Block Public Access, de preference au "
    "niveau du compte : aws s3api put-public-access-block --bucket <nom> "
    "--public-access-block-configuration "
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
    references=(DOC_S3_PUBLIC,),
)
def s3_block_public_access(inv: Inventory) -> list[Finding]:
    findings = []
    for bucket in inv.by_type(rt.S3_BUCKET):
        pab = bucket.raw.get("public_access_block")
        actif = is_pab_effective(pab)
        if pab is None:
            details = "aucune configuration Block Public Access"
        elif actif:
            details = ""
        else:
            manquants = [f for f in PAB_FLAGS if pab.get(f) is not True]
            details = "drapeaux inactifs : " + ", ".join(manquants)
        findings.append(make_finding("S3-001", bucket, actif, details))
    return findings


@check(
    id="S3-002",
    title="Bucket S3 accessible publiquement",
    severity=Severity.CRITICAL,
    service="s3",
    cis="2.1.4",
    remediation="Retirer les grants ACL vers AllUsers/AuthenticatedUsers, supprimer les "
    "declarations de policy avec Principal '*' sans Condition, puis activer "
    "Block Public Access.",
    references=(DOC_S3_PUBLIC,),
)
def s3_bucket_public(inv: Inventory) -> list[Finding]:
    findings = []
    for bucket in inv.by_type(rt.S3_BUCKET):
        raisons = bucket_public_reasons(bucket.raw)
        bloque = is_pab_effective(bucket.raw.get("public_access_block"))
        public = bool(raisons) and not bloque
        details = ", ".join(raisons)
        if raisons and bloque:
            details += " (neutralise par Block Public Access, a corriger malgre tout)"
        findings.append(make_finding("S3-002", bucket, not public, details))
    return findings


@check(
    id="S3-003",
    title="Chiffrement par defaut active",
    severity=Severity.MEDIUM,
    service="s3",
    cis="2.1.1",
    remediation="Activer le chiffrement par defaut (SSE-S3 gratuit, ou SSE-KMS si la "
    "tracabilite des acces a la cle est requise).",
)
def s3_encryption(inv: Inventory) -> list[Finding]:
    findings = []
    for bucket in inv.by_type(rt.S3_BUCKET):
        config = bucket.raw.get("encryption") or {}
        regles = config.get("Rules", [])
        algos = [
            str(algo)
            for regle in regles
            if (algo := (regle.get("ApplyServerSideEncryptionByDefault") or {}).get("SSEAlgorithm"))
        ]
        findings.append(
            make_finding("S3-003", bucket, bool(algos), ", ".join(algos) if algos else "aucun")
        )
    return findings


@check(
    id="S3-004",
    title="Versioning active",
    severity=Severity.MEDIUM,
    service="s3",
    remediation="Activer le versioning : il permet de recuperer des objets apres une "
    "suppression accidentelle ou un chiffrement par rancongiciel.",
)
def s3_versioning(inv: Inventory) -> list[Finding]:
    findings = []
    for bucket in inv.by_type(rt.S3_BUCKET):
        statut = (bucket.raw.get("versioning") or {}).get("Status", "Disabled")
        findings.append(make_finding("S3-004", bucket, statut == "Enabled", statut))
    return findings


@check(
    id="S3-005",
    title="Journalisation des acces activee",
    severity=Severity.LOW,
    service="s3",
    remediation="Activer l'access logging vers un bucket dedie : sans lui, aucune trace "
    "d'acces n'est disponible en cas d'incident.",
)
def s3_access_logging(inv: Inventory) -> list[Finding]:
    findings = []
    for bucket in inv.by_type(rt.S3_BUCKET):
        logging = (bucket.raw.get("logging") or {}).get("LoggingEnabled")
        cible = (logging or {}).get("TargetBucket", "")
        findings.append(
            make_finding("S3-005", bucket, bool(logging), f"cible : {cible}" if cible else "")
        )
    return findings


@check(
    id="S3-006",
    title="Policy imposant le chiffrement en transit (TLS)",
    severity=Severity.MEDIUM,
    service="s3",
    cis="2.1.2",
    remediation="Ajouter une declaration Deny sur toutes les actions quand "
    "aws:SecureTransport vaut false, pour interdire l'acces en HTTP.",
)
def s3_tls_only(inv: Inventory) -> list[Finding]:
    findings = []
    for bucket in inv.by_type(rt.S3_BUCKET):
        ok = policy_enforces_tls(bucket.raw.get("policy"))
        findings.append(
            make_finding("S3-006", bucket, ok, "" if ok else "aucune condition aws:SecureTransport")
        )
    return findings
