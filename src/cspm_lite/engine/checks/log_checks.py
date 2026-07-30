"""Controles de journalisation (CloudTrail).

Sans CloudTrail, une intrusion est invisible et non investigable : c'est le journal
de tous les appels d'API du compte. Les controles portent moins sur "est-ce active"
que sur "est-ce contournable" - un trail mono-region laisse un angle mort, un trail
sans validation d'integrite laisse un attaquant effacer ses traces.
"""

from __future__ import annotations

from cspm_lite.engine import resource_types as rt
from cspm_lite.engine.models import Finding, Inventory, Resource, Severity
from cspm_lite.engine.registry import check, make_finding


def _compte(inv: Inventory) -> Resource:
    """Ressource representant le compte, pour les controles sans objet porteur."""
    existante = inv.one(rt.ACCOUNT)
    if existante is not None:
        return existante
    return Resource(id=inv.account_id or "-", type=rt.ACCOUNT, name=inv.account_id or "compte")


def _trails_actifs(inv: Inventory) -> list[Resource]:
    return [t for t in inv.by_type(rt.CLOUDTRAIL_TRAIL) if t.raw.get("IsLogging")]


@check(
    id="LOG-001",
    title="Au moins un trail CloudTrail multi-region est actif",
    severity=Severity.CRITICAL,
    service="cloudtrail",
    cis="3.1",
    remediation="Creer un trail avec IsMultiRegionTrail et IncludeGlobalServiceEvents "
    "actives : un trail mono-region laisse un attaquant operer depuis une region non "
    "surveillee.",
)
def log_multiregion_trail(inv: Inventory) -> list[Finding]:
    compte = _compte(inv)
    multiregion = [
        t
        for t in _trails_actifs(inv)
        if t.raw.get("IsMultiRegionTrail") and t.raw.get("IncludeGlobalServiceEvents")
    ]
    details = (
        f"trail : {multiregion[0].name}"
        if multiregion
        else f"{len(inv.by_type(rt.CLOUDTRAIL_TRAIL))} trail(s), aucun multi-region actif"
    )
    return [make_finding("LOG-001", compte, bool(multiregion), details)]


@check(
    id="LOG-002",
    title="Validation d'integrite des fichiers de log activee",
    severity=Severity.HIGH,
    service="cloudtrail",
    cis="3.2",
    remediation="Activer LogFileValidationEnabled : CloudTrail signe alors les fichiers, "
    "ce qui permet de detecter apres coup un attaquant ayant efface ses traces.",
)
def log_file_validation(inv: Inventory) -> list[Finding]:
    findings = []
    for trail in inv.by_type(rt.CLOUDTRAIL_TRAIL):
        actif = bool(trail.raw.get("LogFileValidationEnabled"))
        details = "" if actif else "validation absente"
        findings.append(make_finding("LOG-002", trail, actif, details))
    return findings


@check(
    id="LOG-003",
    title="Logs CloudTrail chiffres avec KMS",
    severity=Severity.MEDIUM,
    service="cloudtrail",
    cis="3.5",
    remediation="Associer une cle KMS au trail (KmsKeyId) pour chiffrer les logs au "
    "repos et tracer les acces a la cle.",
)
def log_kms_encryption(inv: Inventory) -> list[Finding]:
    findings = []
    for trail in inv.by_type(rt.CLOUDTRAIL_TRAIL):
        cle = trail.raw.get("KmsKeyId")
        details = "" if cle else "chiffrement SSE-S3 par defaut"
        findings.append(make_finding("LOG-003", trail, bool(cle), details))
    return findings


@check(
    id="LOG-004",
    title="Trail integre a CloudWatch Logs",
    severity=Severity.MEDIUM,
    service="cloudtrail",
    cis="3.4",
    remediation="Associer le trail a un groupe CloudWatch Logs : sans cela, les logs "
    "sont archives mais aucune alerte temps reel n'est possible.",
)
def log_cloudwatch_integration(inv: Inventory) -> list[Finding]:
    findings = []
    for trail in inv.by_type(rt.CLOUDTRAIL_TRAIL):
        groupe = trail.raw.get("CloudWatchLogsLogGroupArn")
        details = "" if groupe else "aucun groupe CloudWatch"
        findings.append(make_finding("LOG-004", trail, bool(groupe), details))
    return findings


@check(
    id="LOG-005",
    title="Le trail est effectivement en train de journaliser",
    severity=Severity.HIGH,
    service="cloudtrail",
    cis="3.1",
    remediation="Un trail configure mais arrete ne protege rien : relancer la "
    "journalisation (StartLogging) et surveiller son arret via une alarme.",
)
def log_trail_is_logging(inv: Inventory) -> list[Finding]:
    findings = []
    for trail in inv.by_type(rt.CLOUDTRAIL_TRAIL):
        actif = bool(trail.raw.get("IsLogging"))
        findings.append(
            make_finding("LOG-005", trail, actif, "" if actif else "journalisation arretee")
        )
    return findings
