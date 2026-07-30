"""Modele de donnees partage par tout l'outil.

Ce module est volontairement pur : aucune dependance a boto3, aucun appel reseau.
C'est la frontiere entre la collecte (qui parle a AWS) et l'evaluation (qui ne parle
qu'a ce modele). Tout ce qui est en aval est testable sans compte AWS.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

SCHEMA_VERSION = "1.0"


class Severity(Enum):
    """Severite d'un finding.

    Les valeurs sont les poids utilises par le score de posture : un controle
    critique en echec doit peser dix fois plus qu'un controle informatif.
    Les libelles sont alignes sur ceux d'ASFF (AWS Security Finding Format).
    """

    INFORMATIONAL = 0
    LOW = 1
    MEDIUM = 3
    HIGH = 5
    CRITICAL = 10

    @property
    def weight(self) -> int:
        return self.value

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.value < other.value

    @classmethod
    def from_name(cls, name: str) -> Severity:
        try:
            return cls[name.upper()]
        except KeyError as exc:
            valides = ", ".join(s.name for s in cls)
            raise ValueError(f"severite inconnue : {name!r} (valeurs : {valides})") from exc


class Status(Enum):
    """Resultat d'evaluation d'un controle sur une ressource."""

    PASS = "PASS"
    FAIL = "FAIL"
    WARNING = "WARNING"
    NOT_AVAILABLE = "NOT_AVAILABLE"


@dataclass
class Resource:
    """Une ressource cloud normalisee.

    `raw` conserve la reponse brute de l'API : les checks y puisent les details
    specifiques au service sans que le modele ait a connaitre chaque champ AWS.
    """

    id: str
    type: str = ""
    region: str = ""
    name: str = ""
    tags: dict[str, str] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "region": self.region,
            "name": self.name,
            "tags": dict(self.tags),
        }


@dataclass
class Finding:
    """Le resultat d'un controle sur une ressource."""

    check_id: str
    title: str
    severity: Severity
    status: Status
    resource: Resource
    remediation: str = ""
    details: str = ""
    cis: str = ""
    references: list[str] = field(default_factory=list)
    detected_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    #: Sous-objet du controle quand une meme ressource en porte plusieurs
    #: (les deux cles d'acces d'un utilisateur IAM, par exemple). Sans lui, deux
    #: findings distincts partageraient la meme identite et l'historique les
    #: confondrait.
    subject: str = ""
    #: Exclusion documentee via .cspm.toml : le finding reste visible mais ne
    #: compte ni dans le score ni dans le code de sortie.
    suppressed: bool = False
    suppression_reason: str = ""

    @property
    def key(self) -> tuple[str, str, str]:
        """Identite stable d'un finding a travers les scans successifs."""
        return (self.check_id, self.resource.id, self.subject)

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "severity": self.severity.name,
            "status": self.status.value,
            "resource": self.resource.to_dict(),
            "subject": self.subject,
            "remediation": self.remediation,
            "details": self.details,
            "cis": self.cis,
            "references": list(self.references),
            "detected_at": self.detected_at.isoformat(),
            "suppressed": self.suppressed,
            "suppression_reason": self.suppression_reason,
        }


@dataclass
class Inventory:
    """L'ensemble des ressources collectees pour un compte.

    Indexe par type de ressource ("AWS::S3::Bucket", ...) : un check demande le type
    qui l'interesse et ignore le reste. Les erreurs de collecte sont conservees pour
    etre remontees a l'utilisateur plutot que silencieusement perdues.
    """

    account_id: str = ""
    regions: list[str] = field(default_factory=list)
    resources: dict[str, list[Resource]] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    # Horodatage de la collecte. Les checks qui raisonnent sur l'age (rotation de
    # cles, credentials dormantes) s'y referent au lieu d'appeler datetime.now() :
    # tous les findings d'un scan partagent ainsi la meme reference temporelle, et
    # les tests deviennent deterministes.
    scanned_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def add(self, resource: Resource) -> None:
        self.resources.setdefault(resource.type, []).append(resource)

    def extend(self, resources: list[Resource]) -> None:
        for r in resources:
            self.add(r)

    def by_type(self, resource_type: str) -> list[Resource]:
        return self.resources.get(resource_type, [])

    def one(self, resource_type: str) -> Resource | None:
        """La ressource unique d'un type (password policy, resume de compte...)."""
        items = self.by_type(resource_type)
        return items[0] if items else None

    @property
    def count(self) -> int:
        return sum(len(v) for v in self.resources.values())


@dataclass
class ScanResult:
    """Le resultat complet d'un scan, pret a etre serialise par un reporter."""

    account_id: str
    findings: list[Finding] = field(default_factory=list)
    regions: list[str] = field(default_factory=list)
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    finished_at: datetime | None = None
    errors: list[str] = field(default_factory=list)

    @property
    def failed(self) -> list[Finding]:
        """Echecs actifs. Les findings explicitement exclus en sont retires : ils
        restent visibles dans le rapport mais ne pesent ni sur le score ni sur le
        code de sortie."""
        return [f for f in self.findings if f.status is Status.FAIL and not f.suppressed]

    @property
    def suppressed(self) -> list[Finding]:
        return [f for f in self.findings if f.suppressed]

    @property
    def passed(self) -> list[Finding]:
        return [f for f in self.findings if f.status is Status.PASS and not f.suppressed]

    @property
    def counts_by_severity(self) -> dict[str, int]:
        """Nombre d'echecs par severite, de la plus grave a la moins grave."""
        counts: dict[str, int] = {}
        for f in self.failed:
            counts[f.severity.name] = counts.get(f.severity.name, 0) + 1
        return {
            s.name: counts[s.name]
            for s in sorted(Severity, key=lambda x: x.weight, reverse=True)
            if s.name in counts
        }

    @property
    def score(self) -> float:
        """Score de posture pondere par severite, entre 0 et 100.

        On pondere plutot que de compter : reussir dix controles informatifs ne doit
        pas compenser un controle critique en echec. Les statuts autres que PASS et
        FAIL sont ignores (on n'a pas pu conclure, ce n'est pas un echec).
        """
        gagne = sum(f.severity.weight for f in self.passed)
        total = gagne + sum(f.severity.weight for f in self.failed)
        if total == 0:
            return 100.0
        return round(100 * gagne / total, 1)

    @property
    def pass_rate(self) -> float:
        evalues = len(self.passed) + len(self.failed)
        if evalues == 0:
            return 100.0
        return round(100 * len(self.passed) / evalues, 1)

    @property
    def duration_seconds(self) -> float:
        if self.finished_at is None:
            return 0.0
        return round((self.finished_at - self.started_at).total_seconds(), 2)

    def top_offenders(self, n: int = 5) -> list[tuple[str, int]]:
        """Ressources cumulant le plus d'echecs, triees de facon deterministe."""
        counts: dict[str, int] = {}
        for f in self.failed:
            counts[f.resource.id] = counts.get(f.resource.id, 0) + 1
        return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:n]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "account_id": self.account_id,
            "regions": list(self.regions),
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "duration_seconds": self.duration_seconds,
            "summary": {
                "total": len(self.findings),
                "pass": len(self.passed),
                "fail": len(self.failed),
                "suppressed": len(self.suppressed),
                "score": self.score,
                "pass_rate": self.pass_rate,
                "by_severity": self.counts_by_severity,
            },
            "errors": list(self.errors),
            "findings": [f.to_dict() for f in self.findings],
        }
