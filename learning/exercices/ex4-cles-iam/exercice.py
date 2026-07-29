"""Exercice 4 — Cles IAM anciennes et MFA du root.

Lis enonce.md. Verifie avec :  python3 -m unittest discover -v
"""

from __future__ import annotations

from datetime import datetime

from commun import Finding, Resource, Severity, Status  # noqa: F401

ROOT_USER = "<root_account>"
VALEURS_NULLES = {"N/A", "not_supported", "no_information", ""}


def parse_credential_report(csv_text: str) -> list[dict]:
    """Parse le CSV du credential report. Utilise le module csv."""
    raise NotImplementedError


def to_bool(value: str) -> bool:
    """"true" (insensible a la casse) -> True, tout le reste -> False."""
    raise NotImplementedError


def key_age_days(last_rotated: str, now: datetime) -> int | None:
    """Age en jours entiers, ou None si la date est inexploitable."""
    raise NotImplementedError


def check_old_keys(rows: list[dict], now: datetime, max_age_days: int = 90) -> list:
    """Un Finding IAM-004 par cle ACTIVE. Voir le tableau de l'enonce."""
    raise NotImplementedError


def check_root_mfa(rows: list[dict]):
    """Un Finding IAM-002 unique sur la ligne <root_account>."""
    raise NotImplementedError
