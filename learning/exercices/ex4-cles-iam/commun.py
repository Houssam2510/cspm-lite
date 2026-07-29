"""Modele de donnees partage par les exercices 2 a 6.

Tu ecriras ta propre version dans l'exercice 1. A partir de l'exercice 2, on utilise
celle-ci pour que chaque exercice reste independant des precedents.

Ne modifie pas ce fichier : les tests s'appuient dessus.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    INFORMATIONAL = 0
    LOW = 1
    MEDIUM = 3
    HIGH = 5
    CRITICAL = 10

    @property
    def weight(self) -> int:
        return self.value

    def __lt__(self, other: "Severity") -> bool:
        return self.value < other.value


class Status(Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARNING = "WARNING"
    NOT_AVAILABLE = "NOT_AVAILABLE"


@dataclass
class Resource:
    id: str
    type: str = ""
    region: str = ""
    name: str = ""
    tags: dict[str, str] = field(default_factory=dict)


@dataclass
class Finding:
    check_id: str
    title: str
    severity: Severity
    status: Status
    resource: Resource
    remediation: str = ""
    details: str = ""

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "severity": self.severity.name,
            "status": self.status.value,
            "resource": {
                "id": self.resource.id,
                "type": self.resource.type,
                "region": self.resource.region,
                "name": self.resource.name,
                "tags": dict(self.resource.tags),
            },
            "remediation": self.remediation,
            "details": self.details,
        }
