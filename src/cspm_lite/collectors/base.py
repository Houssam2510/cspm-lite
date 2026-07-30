"""Socle commun des collecteurs.

Un collecteur ne sait rien de la securite : il interroge l'API AWS et produit des
`Resource` normalisees. C'est cette ignorance qui rend les checks testables sans
compte AWS - on leur injecte un inventaire fabrique a la main.

Deux problemes recurrents sont traites ici une fois pour toutes :

- **les erreurs qui n'en sont pas** : `NoSuchBucketPolicy`,
  `ServerSideEncryptionConfigurationNotFoundError`... signifient "non configure",
  pas "panne". Les traiter comme fatales rend l'outil inutilisable ;
- **AccessDenied** : un droit manquant doit produire un avertissement visible, pas
  un crash ni un silence.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol

from botocore.exceptions import BotoCoreError, ClientError

from cspm_lite.engine.models import Inventory, Resource

if TYPE_CHECKING:  # pragma: no cover
    from boto3.session import Session

log = logging.getLogger("cspm_lite.collectors")

# Codes d'erreur signifiant "cette option n'est pas configuree sur la ressource".
CODES_ABSENCE = {
    "NoSuchBucketPolicy",
    "NoSuchPublicAccessBlockConfiguration",
    "NoSuchTagSet",
    "NoSuchLifecycleConfiguration",
    "NoSuchWebsiteConfiguration",
    "NoSuchCORSConfiguration",
    "ServerSideEncryptionConfigurationNotFoundError",
    "ObjectLockConfigurationNotFoundError",
    "ReplicationConfigurationNotFoundError",
}

CODES_ACCES = {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "AuthFailure"}


class Collector(Protocol):
    """Contrat d'un collecteur."""

    name: str
    service: str
    #: True si le service est global (IAM, S3 ListBuckets) et ne doit etre
    #: interroge qu'une fois, pas une fois par region.
    global_service: bool

    def collect(self, session: Session, region: str, inv: Inventory) -> list[Resource]: ...


@dataclass
class CollectorMeta:
    name: str
    service: str
    global_service: bool
    func: Callable[[Any, str, Inventory], list[Resource]]


COLLECTORS: list[CollectorMeta] = []


def collector(
    *, name: str, service: str, global_service: bool = False
) -> Callable[[Callable[..., list[Resource]]], Callable[..., list[Resource]]]:
    """Enregistre un collecteur, sur le meme principe que le registre de checks."""

    def decorateur(func: Callable[..., list[Resource]]) -> Callable[..., list[Resource]]:
        COLLECTORS.append(
            CollectorMeta(name=name, service=service, global_service=global_service, func=func)
        )
        return func

    return decorateur


def safe_call(fn: Callable[..., Any], *args: Any, default: Any = None, **kwargs: Any) -> Any:
    """Appelle une API AWS en absorbant les erreurs "non configure".

    Renvoie `default` si l'option n'existe pas, releve l'exception sinon : une erreur
    inattendue doit rester visible, seule l'absence de configuration est normale.
    """
    try:
        return fn(*args, **kwargs)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code in CODES_ABSENCE:
            return default
        raise


def is_access_denied(exc: BaseException) -> bool:
    return (
        isinstance(exc, ClientError)
        and exc.response.get("Error", {}).get("Code", "") in CODES_ACCES
    )


def collect_all(
    session: Session,
    regions: list[str],
    inv: Inventory,
    max_workers: int = 12,
) -> Inventory:
    """Execute tous les collecteurs, les regionaux en parallele.

    Pourquoi des threads et pas des processus : le scan est *I/O bound*, on attend
    l'API AWS. Le GIL n'est pas un obstacle puisqu'il est relache pendant l'attente
    reseau, et les threads evitent le cout de serialisation entre processus.
    """
    taches: list[tuple[CollectorMeta, str]] = []
    for meta in COLLECTORS:
        if meta.global_service:
            taches.append((meta, regions[0] if regions else "us-east-1"))
        else:
            taches.extend((meta, region) for region in regions)

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futurs = {
            pool.submit(_run_one, meta, session, region, inv): (meta, region)
            for meta, region in taches
        }
        for futur in as_completed(futurs):
            resources, erreur = futur.result()
            if erreur:
                inv.errors.append(erreur)
            inv.extend(resources)

    # Ordre stable malgre le parallelisme : sans cela, deux scans identiques
    # produiraient des rapports differents et le diff entre scans serait inutilisable.
    for liste in inv.resources.values():
        liste.sort(key=lambda r: (r.region, r.id))
    return inv


def _run_one(
    meta: CollectorMeta, session: Session, region: str, inv: Inventory
) -> tuple[list[Resource], str | None]:
    """Execute un collecteur en isolant ses pannes, comme le moteur de checks."""
    try:
        return meta.func(session, region, inv), None
    except Exception as exc:
        if is_access_denied(exc):
            message = f"{meta.name} ({region}) : droits insuffisants, controles incomplets"
        elif isinstance(exc, ClientError | BotoCoreError):
            message = f"{meta.name} ({region}) : {type(exc).__name__}: {exc}"
        else:
            message = f"{meta.name} ({region}) : erreur inattendue {type(exc).__name__}: {exc}"
        log.warning(message)
        return [], message
