"""Exercice 3 — Detecter un bucket S3 public.

Lis enonce.md. Verifie avec :  python3 -m unittest discover -v
"""

from __future__ import annotations

from commun import Finding, Resource, Severity, Status  # noqa: F401

ALL_USERS = "http://acs.amazonaws.com/groups/global/AllUsers"
AUTHENTICATED_USERS = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"

PAB_FLAGS = (
    "BlockPublicAcls",
    "IgnorePublicAcls",
    "BlockPublicPolicy",
    "RestrictPublicBuckets",
)


def is_pab_effective(pab: dict | None) -> bool:
    """True seulement si les quatre drapeaux du Public Access Block valent True."""
    raise NotImplementedError


def acl_public_reasons(grants: list | None) -> set[str]:
    """{"acl-allusers"} et/ou {"acl-authenticatedusers"} selon les grants.

    Un grant vers un CanonicalUser vise un compte precis : ce n'est pas public.
    """
    raise NotImplementedError


def policy_allows_anyone(policy: dict | None) -> bool:
    """True si au moins une declaration Allow ouvre a un Principal generique sans Condition.

    Rappel : Statement peut etre une liste OU un dictionnaire unique.
    """
    raise NotImplementedError


def bucket_public_reasons(bucket: dict) -> list[str]:
    """Toutes les raisons d'exposition, triees, sans doublon."""
    raise NotImplementedError


def is_effectively_public(bucket: dict) -> bool:
    """Au moins une raison ET Public Access Block non pleinement actif."""
    raise NotImplementedError


def check_s3_public(buckets: list) -> list:
    """Un Finding S3-002 par bucket. Voir le tableau de l'enonce."""
    raise NotImplementedError
