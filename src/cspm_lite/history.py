"""Historisation des scans et metriques de posture.

Un scan isole repond a "ou en suis-je". La question qui interesse reellement une
equipe est "est-ce que ca s'ameliore" - et elle exige de l'historique.

Deux notions distinctes sont modelisees, et les confondre est l'erreur classique :

- l'**etat** : un instantane, ce que contient un scan ;
- l'**evenement** : l'apparition ou la disparition d'un finding entre deux scans.

Le score se lit sur l'etat ; le MTTR et le taux de recidive se calculent sur les
evenements. C'est la distinction de base de la modelisation temporelle.

Stockage en SQLite (`sqlite3`, bibliotheque standard) : un fichier unique,
versionnable, interrogeable en SQL, aucune dependance.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from cspm_lite.engine.models import ScanResult, Severity, Status

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id       TEXT    NOT NULL,
    started_at       TEXT    NOT NULL,
    finished_at      TEXT,
    score            REAL    NOT NULL,
    pass_count       INTEGER NOT NULL,
    fail_count       INTEGER NOT NULL,
    suppressed_count INTEGER NOT NULL DEFAULT 0,
    regions          TEXT    NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS findings (
    scan_id     INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    check_id    TEXT    NOT NULL,
    resource_id TEXT    NOT NULL,
    subject     TEXT    NOT NULL DEFAULT '',
    status      TEXT    NOT NULL,
    severity    TEXT    NOT NULL,
    title       TEXT    NOT NULL DEFAULT '',
    details     TEXT    NOT NULL DEFAULT '',
    suppressed  INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (scan_id, check_id, resource_id, subject)
);

CREATE INDEX IF NOT EXISTS idx_findings_identite ON findings(check_id, resource_id, subject);
CREATE INDEX IF NOT EXISTS idx_scans_date ON scans(started_at);
"""


@contextmanager
def connect(db_path: str | Path) -> Iterator[sqlite3.Connection]:
    chemin = Path(db_path)
    chemin.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(chemin)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.executescript(SCHEMA)
        yield conn
        conn.commit()
    finally:
        conn.close()


def save_scan(db_path: str | Path, result: ScanResult) -> int:
    """Enregistre un scan et renvoie son identifiant."""
    with connect(db_path) as conn:
        curseur = conn.execute(
            "INSERT INTO scans (account_id, started_at, finished_at, score, "
            "pass_count, fail_count, suppressed_count, regions) VALUES (?,?,?,?,?,?,?,?)",
            (
                result.account_id,
                result.started_at.isoformat(),
                result.finished_at.isoformat() if result.finished_at else None,
                result.score,
                len(result.passed),
                len(result.failed),
                len(result.suppressed),
                ",".join(result.regions),
            ),
        )
        scan_id = int(curseur.lastrowid or 0)
        conn.executemany(
            "INSERT OR REPLACE INTO findings (scan_id, check_id, resource_id, subject, "
            "status, severity, title, details, suppressed) VALUES (?,?,?,?,?,?,?,?,?)",
            [
                (
                    scan_id,
                    f.check_id,
                    f.resource.id,
                    f.subject,
                    f.status.value,
                    f.severity.name,
                    f.title,
                    f.details,
                    int(f.suppressed),
                )
                for f in result.findings
            ],
        )
        return scan_id


@dataclass
class ScanRow:
    id: int
    account_id: str
    started_at: datetime
    score: float
    pass_count: int
    fail_count: int
    suppressed_count: int


def list_scans(db_path: str | Path, limit: int = 50) -> list[ScanRow]:
    """Scans du plus ancien au plus recent (ordre de lecture d'une courbe)."""
    with connect(db_path) as conn:
        lignes = conn.execute(
            "SELECT * FROM (SELECT * FROM scans ORDER BY id DESC LIMIT ?) ORDER BY id ASC",
            (limit,),
        ).fetchall()
    return [
        ScanRow(
            id=ligne["id"],
            account_id=ligne["account_id"],
            started_at=datetime.fromisoformat(ligne["started_at"]),
            score=ligne["score"],
            pass_count=ligne["pass_count"],
            fail_count=ligne["fail_count"],
            suppressed_count=ligne["suppressed_count"],
        )
        for ligne in lignes
    ]


@dataclass
class Diff:
    """Evenements entre deux scans."""

    nouveaux: list[dict[str, Any]] = field(default_factory=list)
    resolus: list[dict[str, Any]] = field(default_factory=list)
    persistants: list[dict[str, Any]] = field(default_factory=list)

    @property
    def vide(self) -> bool:
        return not (self.nouveaux or self.resolus)


def _echecs(conn: sqlite3.Connection, scan_id: int) -> dict[tuple[str, str, str], dict[str, Any]]:
    lignes = conn.execute(
        "SELECT * FROM findings WHERE scan_id = ? AND status = 'FAIL' AND suppressed = 0",
        (scan_id,),
    ).fetchall()
    return {(r["check_id"], r["resource_id"], r["subject"]): dict(r) for r in lignes}


def diff_scans(db_path: str | Path, avant: int, apres: int) -> Diff:
    """Compare deux scans : ce qui est apparu, ce qui a ete corrige, ce qui traine."""
    with connect(db_path) as conn:
        a, b = _echecs(conn, avant), _echecs(conn, apres)
    return Diff(
        nouveaux=[b[k] for k in sorted(b.keys() - a.keys())],
        resolus=[a[k] for k in sorted(a.keys() - b.keys())],
        persistants=[b[k] for k in sorted(b.keys() & a.keys())],
    )


@dataclass
class Metrics:
    """Metriques de pilotage.

    On ne pilote pas la securite au nombre brut de vulnerabilites - ce chiffre
    depend surtout du perimetre scanne. On la pilote au **delai de correction**
    et au **taux de recidive**, qui mesurent le processus et non l'inventaire.
    """

    mttr_par_severite: dict[str, float] = field(default_factory=dict)
    mttr_global: float = 0.0
    corriges: int = 0
    ouverts: int = 0
    taux_de_recidive: float = 0.0
    plus_anciens: list[tuple[str, str, int]] = field(default_factory=list)


def compute_metrics(db_path: str | Path) -> Metrics:
    with connect(db_path) as conn:
        scans = conn.execute("SELECT id, started_at FROM scans ORDER BY id ASC").fetchall()
        if not scans:
            return Metrics()
        dates = {s["id"]: datetime.fromisoformat(s["started_at"]) for s in scans}
        lignes = conn.execute(
            "SELECT scan_id, check_id, resource_id, subject, status, severity, suppressed "
            "FROM findings ORDER BY scan_id ASC"
        ).fetchall()

    # Reconstruction des episodes : un episode s'ouvre au premier FAIL et se ferme
    # au premier PASS qui suit. Un finding qui reapparait ouvre un nouvel episode.
    par_identite: dict[tuple[str, str, str], list[sqlite3.Row]] = {}
    for ligne in lignes:
        cle = (ligne["check_id"], ligne["resource_id"], ligne["subject"])
        par_identite.setdefault(cle, []).append(ligne)

    durees: dict[str, list[float]] = {}
    corriges = ouverts = recidives = 0
    ages_ouverts: list[tuple[str, str, int]] = []
    dernier_scan = scans[-1]["id"]

    for cle, historique in par_identite.items():
        ouvert_depuis: datetime | None = None
        severite = historique[-1]["severity"]
        episodes_fermes = 0
        for ligne in historique:
            if ligne["suppressed"]:
                continue
            instant = dates[ligne["scan_id"]]
            if ligne["status"] == "FAIL" and ouvert_depuis is None:
                ouvert_depuis = instant
            elif ligne["status"] == "PASS" and ouvert_depuis is not None:
                jours = (instant - ouvert_depuis).total_seconds() / 86400
                durees.setdefault(severite, []).append(jours)
                corriges += 1
                episodes_fermes += 1
                ouvert_depuis = None
        if episodes_fermes >= 2:
            recidives += 1
        if ouvert_depuis is not None:
            ouverts += 1
            age = (dates[dernier_scan] - ouvert_depuis).days
            ages_ouverts.append((cle[0], cle[1], age))

    mttr = {sev: round(sum(v) / len(v), 2) for sev, v in durees.items()}
    toutes = [d for v in durees.values() for d in v]
    ordre = {s.name: s.weight for s in Severity}
    return Metrics(
        mttr_par_severite=dict(
            sorted(mttr.items(), key=lambda kv: ordre.get(kv[0], 0), reverse=True)
        ),
        mttr_global=round(sum(toutes) / len(toutes), 2) if toutes else 0.0,
        corriges=corriges,
        ouverts=ouverts,
        taux_de_recidive=round(100 * recidives / corriges, 1) if corriges else 0.0,
        plus_anciens=sorted(ages_ouverts, key=lambda t: -t[2])[:5],
    )


def result_from_rows(account_id: str, rows: list[sqlite3.Row]) -> ScanResult:  # pragma: no cover
    """Utilitaire de relecture, utile pour rejouer un scan archive."""
    from cspm_lite.engine.models import Finding, Resource

    findings = [
        Finding(
            check_id=r["check_id"],
            title=r["title"],
            severity=Severity[r["severity"]],
            status=Status(r["status"]),
            resource=Resource(id=r["resource_id"]),
            subject=r["subject"],
            details=r["details"],
            suppressed=bool(r["suppressed"]),
        )
        for r in rows
    ]
    return ScanResult(account_id=account_id, findings=findings)
