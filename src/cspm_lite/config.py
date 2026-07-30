"""Fichier de configuration et exclusions documentees.

Format TOML, lu par `tomllib` de la bibliotheque standard (Python 3.11+). Le choix
de TOML plutot que YAML est deliberate : YAML imposerait une dependance
supplementaire a un outil de securite, et son analyseur a un historique de failles
(execution de code a la deserialisation). TOML se lit avec la stdlib, sans risque.

La regle de gouvernance appliquee ici compte autant que le code : **toute exclusion
doit porter une justification et une date d'expiration**. Une exception de securite
sans date devient permanente et personne ne se souvient pourquoi elle existe. Passee
sa date, l'exclusion cesse de s'appliquer et le finding redevient bloquant.
"""

from __future__ import annotations

import fnmatch
import tomllib
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

from cspm_lite.engine.models import Finding, Status

NOM_PAR_DEFAUT = ".cspm.toml"


class ConfigError(ValueError):
    """Configuration invalide. Volontairement fatale : une exclusion mal formee
    doit arreter le scan plutot que d'etre ignoree en silence."""


@dataclass(frozen=True)
class Exclusion:
    check: str = "*"
    resource: str = "*"
    reason: str = ""
    expires_at: date | None = None
    owner: str = ""

    def expired(self, today: date) -> bool:
        return self.expires_at is not None and self.expires_at < today

    def matches(self, finding: Finding) -> bool:
        return fnmatch.fnmatch(finding.check_id, self.check) and fnmatch.fnmatch(
            finding.resource.id, self.resource
        )

    def label(self) -> str:
        return f"{self.check} / {self.resource}"


@dataclass
class Config:
    severity_min: str = "INFORMATIONAL"
    fail_on: str = "HIGH"
    services: list[str] = field(default_factory=list)
    regions: list[str] = field(default_factory=list)
    exclusions: list[Exclusion] = field(default_factory=list)
    source: Path | None = None


def find_config(depart: Path | None = None) -> Path | None:
    """Cherche .cspm.toml dans le dossier courant puis ses parents, comme git."""
    courant = (depart or Path.cwd()).resolve()
    for dossier in [courant, *courant.parents]:
        candidat = dossier / NOM_PAR_DEFAUT
        if candidat.is_file():
            return candidat
    return None


def _parse_date(valeur: Any, contexte: str) -> date:
    if isinstance(valeur, date):
        return valeur
    if isinstance(valeur, str):
        try:
            return date.fromisoformat(valeur)
        except ValueError as exc:
            raise ConfigError(
                f"{contexte} : date invalide {valeur!r} (attendu AAAA-MM-JJ)"
            ) from exc
    raise ConfigError(f"{contexte} : expires_at doit etre une date")


def load_config(chemin: Path) -> Config:
    try:
        donnees = tomllib.loads(chemin.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{chemin} : TOML invalide — {exc}") from exc

    scan = donnees.get("scan", {})
    config = Config(
        severity_min=str(scan.get("severity_min", "INFORMATIONAL")),
        fail_on=str(scan.get("fail_on", "HIGH")),
        services=list(scan.get("services", [])),
        regions=list(scan.get("regions", [])),
        source=chemin,
    )

    for i, brut in enumerate(donnees.get("exclusions", []), start=1):
        contexte = f"{chemin} : exclusion #{i}"
        if not str(brut.get("reason", "")).strip():
            raise ConfigError(f"{contexte} : le champ 'reason' est obligatoire")
        if "expires_at" not in brut:
            raise ConfigError(
                f"{contexte} : le champ 'expires_at' est obligatoire — une exception "
                "de securite sans date d'expiration devient permanente"
            )
        config.exclusions.append(
            Exclusion(
                check=str(brut.get("check", "*")),
                resource=str(brut.get("resource", "*")),
                reason=str(brut["reason"]).strip(),
                expires_at=_parse_date(brut["expires_at"], contexte),
                owner=str(brut.get("owner", "")),
            )
        )
    return config


def apply_exclusions(
    findings: list[Finding], config: Config, today: date | None = None
) -> list[str]:
    """Marque les findings couverts par une exclusion valide.

    Renvoie la liste des avertissements : exclusions expirees et exclusions qui ne
    correspondent a rien. Les deux meritent d'etre signalees - une exclusion morte
    est de la dette de configuration qui masque peut-etre autre chose.
    """
    aujourdhui = today or date.today()
    avertissements: list[str] = []
    utilisees: set[int] = set()

    for i, exclusion in enumerate(config.exclusions):
        if exclusion.expired(aujourdhui):
            avertissements.append(
                f"exclusion expiree le {exclusion.expires_at} et de nouveau active : "
                f"{exclusion.label()} ({exclusion.reason})"
            )
            continue
        for finding in findings:
            if finding.status is Status.FAIL and exclusion.matches(finding):
                finding.suppressed = True
                finding.suppression_reason = f"{exclusion.reason} (jusqu'au {exclusion.expires_at})"
                utilisees.add(i)

    for i, exclusion in enumerate(config.exclusions):
        if i not in utilisees and not exclusion.expired(aujourdhui):
            avertissements.append(f"exclusion sans effet, a supprimer : {exclusion.label()}")
    return avertissements


EXEMPLE = """\
# Configuration cspm-lite. Deposez ce fichier a la racine du depot.

[scan]
severity_min = "LOW"      # ne pas evaluer les controles informatifs
fail_on      = "HIGH"     # code de sortie 1 a partir de HIGH
services     = []         # vide = tous
regions      = []         # vide = toutes les regions activees

# Toute exclusion exige une justification et une date d'expiration.
# Passee cette date, le finding redevient bloquant automatiquement.
[[exclusions]]
check      = "S3-005"
resource   = "arn:aws:s3:::*-public-assets"
reason     = "bucket de contenus publics : la journalisation d'acces est assumee"
expires_at = 2026-12-31
owner      = "equipe-web"
"""
