"""Registre de checks et moteur d'execution.

Un check est une fonction pure `(Inventory) -> list[Finding]`, enregistree par un
decorateur. Ajouter un controle = ecrire une fonction ; le moteur n'est jamais
modifie. C'est le meme mecanisme que `@app.route` dans Flask ou `@pytest.fixture`.
"""

from __future__ import annotations

import importlib
import pkgutil
from collections.abc import Callable
from dataclasses import dataclass

from cspm_lite.engine.models import Finding, Inventory, Resource, Severity, Status

CheckFunc = Callable[[Inventory], list[Finding]]


@dataclass(frozen=True)
class CheckMeta:
    """Les metadonnees declaratives d'un controle."""

    id: str
    title: str
    severity: Severity
    service: str
    func: CheckFunc
    cis: str = ""
    remediation: str = ""
    references: tuple[str, ...] = ()


REGISTRY: dict[str, CheckMeta] = {}


def check(
    *,
    id: str,  # noqa: A002 - "id" est le vocabulaire du domaine (identifiant de controle)
    title: str,
    severity: Severity,
    service: str,
    cis: str = "",
    remediation: str = "",
    references: tuple[str, ...] = (),
) -> Callable[[CheckFunc], CheckFunc]:
    """Enregistre un check et renvoie la fonction inchangee.

    La fonction est renvoyee telle quelle (pas de wrapper) pour rester directement
    appelable et testable en isolation, sans passer par le registre.
    """

    def decorateur(func: CheckFunc) -> CheckFunc:
        if id in REGISTRY:
            raise ValueError(f"check deja enregistre : {id}")
        REGISTRY[id] = CheckMeta(
            id=id,
            title=title,
            severity=severity,
            service=service,
            func=func,
            cis=cis,
            remediation=remediation,
            references=references,
        )
        return func

    return decorateur


def load_all_checks() -> None:
    """Importe tous les modules de `cspm_lite.engine.checks` pour peupler le registre.

    Sans cet import, un check jamais importe n'existe pas : le decorateur ne
    s'execute qu'au chargement du module qui le contient.
    """
    from cspm_lite.engine import checks as package

    for module in pkgutil.iter_modules(package.__path__):
        importlib.import_module(f"{package.__name__}.{module.name}")


def get_checks(
    service: str | None = None,
    severity_min: Severity | None = None,
    ids: list[str] | None = None,
) -> list[CheckMeta]:
    """Checks enregistres, dans l'ordre d'enregistrement, filtres."""
    metas = list(REGISTRY.values())
    if service is not None:
        metas = [m for m in metas if m.service.lower() == service.lower()]
    if severity_min is not None:
        metas = [m for m in metas if not (m.severity < severity_min)]
    if ids is not None:
        voulus = {i.upper() for i in ids}
        metas = [m for m in metas if m.id.upper() in voulus]
    return metas


def run_checks(inventory: Inventory, checks: list[CheckMeta] | None = None) -> list[Finding]:
    """Execute les checks et concatene leurs findings.

    Isolation des pannes : un check qui leve une exception produit un finding
    NOT_AVAILABLE et l'execution continue. En production, un bucket supprime pendant
    le scan ou un champ d'API modifie ne doit jamais interrompre les 24 autres
    controles.

    On capture `Exception` et non `BaseException` : un Ctrl+C (KeyboardInterrupt) ou
    un SystemExit doivent bien interrompre le scan.
    """
    metas = list(REGISTRY.values()) if checks is None else list(checks)
    findings: list[Finding] = []
    for meta in metas:
        try:
            findings.extend(meta.func(inventory) or [])
        except Exception as exc:  # noqa: BLE001 - isolation volontaire, voir docstring
            findings.append(
                Finding(
                    check_id=meta.id,
                    title=meta.title,
                    severity=meta.severity,
                    status=Status.NOT_AVAILABLE,
                    resource=Resource(id="-"),
                    cis=meta.cis,
                    remediation=meta.remediation,
                    details=f"erreur pendant l'evaluation : {type(exc).__name__}: {exc}",
                )
            )
    return findings


def clear_registry() -> None:
    """Vide le registre. Utilise par les tests pour repartir d'un etat connu."""
    REGISTRY.clear()


def make_finding(
    meta_id: str,
    resource: Resource,
    ok: bool,
    details: str = "",
) -> Finding:
    """Construit un finding a partir des metadonnees declarees du check.

    Evite de repeter titre / severite / CIS / remediation dans chaque branche de
    chaque check : la source de verite reste le decorateur.
    """
    meta = REGISTRY[meta_id]
    return Finding(
        check_id=meta.id,
        title=meta.title,
        severity=meta.severity,
        status=Status.PASS if ok else Status.FAIL,
        resource=resource,
        remediation=meta.remediation,
        cis=meta.cis,
        references=list(meta.references),
        details=details,
    )
