"""Controles IAM.

Les cles d'acces statiques sont le premier vecteur de compromission cloud : elles
fuient dans un depot Git, un fichier de configuration, une capture d'ecran, et
contrairement a un mot de passe elles ne perimet jamais et n'ont pas de second
facteur.

La source de donnees principale est le *credential report* : un CSV que l'IAM genere
a la demande et qui contient, pour chaque principal, l'etat du MFA, des cles et des
dernieres utilisations. Une seule requete plutot que N appels par utilisateur.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from cspm_lite.engine import resource_types as rt
from cspm_lite.engine.models import Finding, Inventory, Resource, Severity, Status
from cspm_lite.engine.registry import check, make_finding

ROOT_USER = "<root_account>"

# Valeurs sentinelles du credential report : ce ne sont pas des dates.
VALEURS_NULLES = {"N/A", "not_supported", "no_information", ""}

MAX_KEY_AGE_DAYS = 90
MAX_UNUSED_DAYS = 45
MIN_PASSWORD_LENGTH = 14


def to_bool(value: Any) -> bool:
    """Le credential report encode les booleens en chaines."""
    return str(value).strip().lower() == "true"


def parse_report_date(value: str) -> datetime | None:
    """Date ISO 8601 du rapport, ou None pour les valeurs sentinelles.

    Les dates du rapport portent un fuseau (+00:00) : tout `datetime` naif compare
    a celles-ci leverait une TypeError. On reste donc tz-aware de bout en bout.
    """
    texte = (value or "").strip()
    if texte in VALEURS_NULLES:
        return None
    try:
        return datetime.fromisoformat(texte)
    except ValueError:
        return None


def age_in_days(value: str, now: datetime) -> int | None:
    date = parse_report_date(value)
    return None if date is None else (now - date).days


def _users(inv: Inventory) -> list[Resource]:
    return inv.by_type(rt.IAM_USER)


def _now(inv: Inventory) -> datetime:
    """Reference temporelle du scan (voir Inventory.scanned_at)."""
    return inv.scanned_at


@check(
    id="IAM-001",
    title="Le compte root n'a pas de cle d'acces",
    severity=Severity.CRITICAL,
    service="iam",
    cis="1.4",
    remediation="Supprimer les cles d'acces du compte root. Le root ne peut etre "
    "restreint par aucune policy : qui detient sa cle detient tout le compte.",
)
def iam_root_no_access_key(inv: Inventory) -> list[Finding]:
    for user in _users(inv):
        if user.name != ROOT_USER:
            continue
        actives = [
            n for n in (1, 2) if to_bool(user.raw.get(f"access_key_{n}_active", "false"))
        ]
        details = f"cles actives : {', '.join(str(n) for n in actives)}" if actives else ""
        return [make_finding("IAM-001", user, not actives, details)]
    return []


@check(
    id="IAM-002",
    title="MFA active sur le compte root",
    severity=Severity.CRITICAL,
    service="iam",
    cis="1.5",
    remediation="Activer un MFA materiel sur le compte root et stocker le peripherique "
    "hors ligne.",
)
def iam_root_mfa(inv: Inventory) -> list[Finding]:
    for user in _users(inv):
        if user.name == ROOT_USER:
            actif = to_bool(user.raw.get("mfa_active", "false"))
            return [make_finding("IAM-002", user, actif, "" if actif else "MFA absent")]
    return []


@check(
    id="IAM-003",
    title="MFA active pour tous les utilisateurs a acces console",
    severity=Severity.HIGH,
    service="iam",
    cis="1.10",
    remediation="Activer le MFA pour chaque utilisateur disposant d'un mot de passe "
    "console, ou supprimer l'acces console s'il est inutile.",
)
def iam_console_users_mfa(inv: Inventory) -> list[Finding]:
    findings = []
    for user in _users(inv):
        if user.name == ROOT_USER:
            continue  # couvert par IAM-002
        if not to_bool(user.raw.get("password_enabled", "false")):
            continue  # pas d'acces console : hors perimetre de ce controle
        actif = to_bool(user.raw.get("mfa_active", "false"))
        findings.append(make_finding("IAM-003", user, actif, "" if actif else "MFA absent"))
    return findings


@check(
    id="IAM-004",
    title="Aucune cle d'acces de plus de 90 jours",
    severity=Severity.HIGH,
    service="iam",
    cis="1.14",
    remediation="Faire tourner la cle puis desactiver l'ancienne. A terme, remplacer les "
    "cles statiques par des roles IAM ou des identites federees.",
)
def iam_key_rotation(inv: Inventory) -> list[Finding]:
    now = _now(inv)
    findings = []
    for user in _users(inv):
        for n in (1, 2):
            if not to_bool(user.raw.get(f"access_key_{n}_active", "false")):
                continue  # une cle inactive n'est pas un risque de rotation
            age = age_in_days(user.raw.get(f"access_key_{n}_last_rotated", ""), now)
            if age is None:
                findings.append(
                    Finding(
                        check_id="IAM-004",
                        title="Aucune cle d'acces de plus de 90 jours",
                        severity=Severity.HIGH,
                        status=Status.NOT_AVAILABLE,
                        resource=user,
                        cis="1.14",
                        details=f"access_key_{n} : date de rotation indisponible",
                    )
                )
                continue
            findings.append(
                make_finding(
                    "IAM-004", user, age <= MAX_KEY_AGE_DAYS, f"access_key_{n} : {age} jours"
                )
            )
    return findings


@check(
    id="IAM-005",
    title="Aucune credential inutilisee depuis 45 jours",
    severity=Severity.MEDIUM,
    service="iam",
    cis="1.12",
    remediation="Desactiver les mots de passe et cles non utilises : ce sont des acces "
    "dormants dont la compromission passerait inapercue.",
)
def iam_unused_credentials(inv: Inventory) -> list[Finding]:
    now = _now(inv)
    findings = []
    for user in _users(inv):
        if user.name == ROOT_USER:
            continue
        dormants = []
        if to_bool(user.raw.get("password_enabled", "false")):
            age = age_in_days(user.raw.get("password_last_used", ""), now)
            # jamais utilise (None) est aussi un dormant : on se rabat sur la creation
            if age is None:
                age = age_in_days(user.raw.get("user_creation_time", ""), now)
            if age is not None and age > MAX_UNUSED_DAYS:
                dormants.append(f"mot de passe : {age} jours")
        for n in (1, 2):
            if not to_bool(user.raw.get(f"access_key_{n}_active", "false")):
                continue
            age = age_in_days(user.raw.get(f"access_key_{n}_last_used_date", ""), now)
            if age is None:
                age = age_in_days(user.raw.get(f"access_key_{n}_last_rotated", ""), now)
            if age is not None and age > MAX_UNUSED_DAYS:
                dormants.append(f"access_key_{n} : {age} jours")
        findings.append(make_finding("IAM-005", user, not dormants, ", ".join(dormants)))
    return findings


@check(
    id="IAM-006",
    title="Politique de mot de passe conforme",
    severity=Severity.MEDIUM,
    service="iam",
    cis="1.8",
    remediation="Imposer une longueur minimale de 14 caracteres et interdire la "
    "reutilisation des 24 derniers mots de passe.",
)
def iam_password_policy(inv: Inventory) -> list[Finding]:
    policy = inv.one(rt.IAM_PASSWORD_POLICY)
    if policy is None:
        return []
    raw = policy.raw
    if not raw:
        return [make_finding("IAM-006", policy, False, "aucune politique de mot de passe")]
    problemes = []
    longueur = raw.get("MinimumPasswordLength", 0)
    if longueur < MIN_PASSWORD_LENGTH:
        problemes.append(f"longueur minimale {longueur} < {MIN_PASSWORD_LENGTH}")
    if not raw.get("PasswordReusePrevention"):
        problemes.append("reutilisation non bloquee")
    return [make_finding("IAM-006", policy, not problemes, ", ".join(problemes))]


@check(
    id="IAM-007",
    title="Aucun utilisateur avec AdministratorAccess attache directement",
    severity=Severity.HIGH,
    service="iam",
    cis="1.16",
    remediation="Attacher les permissions a des groupes ou des roles, jamais "
    "directement a un utilisateur, et remplacer AdministratorAccess par une policy "
    "au perimetre reduit.",
)
def iam_no_direct_admin(inv: Inventory) -> list[Finding]:
    findings = []
    for user in _users(inv):
        if user.name == ROOT_USER:
            continue
        attachees = user.raw.get("attached_policies") or []
        admin = [p for p in attachees if p.endswith("AdministratorAccess")]
        findings.append(make_finding("IAM-007", user, not admin, ", ".join(admin)))
    return findings


@check(
    id="IAM-008",
    title="Aucune policy client n'accorde Action '*' sur Resource '*'",
    severity=Severity.HIGH,
    service="iam",
    cis="1.16",
    remediation="Restreindre les actions et les ressources. Une policy '*' sur '*' "
    "permet a son porteur d'escalader jusqu'aux droits d'administration.",
)
def iam_no_wildcard_policy(inv: Inventory) -> list[Finding]:
    findings = []
    for policy in inv.by_type(rt.IAM_POLICY):
        document = policy.raw.get("document") or {}
        statements = document.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]
        risque = False
        for st in statements:
            if not isinstance(st, dict) or st.get("Effect") != "Allow":
                continue
            actions = st.get("Action", [])
            ressources = st.get("Resource", [])
            actions = [actions] if isinstance(actions, str) else list(actions)
            ressources = [ressources] if isinstance(ressources, str) else list(ressources)
            if "*" in actions and "*" in ressources:
                risque = True
                break
        findings.append(
            make_finding("IAM-008", policy, not risque, "Action '*' sur Resource '*'" if risque else "")
        )
    return findings
