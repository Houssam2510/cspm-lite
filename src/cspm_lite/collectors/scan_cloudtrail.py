"""Collecte CloudTrail.

`describe_trails` renvoie la configuration, mais pas l'etat : un trail parfaitement
configure peut avoir ete arrete par un attaquant. Il faut donc appeler `get_trail_status`
en plus, et c'est exactement ce que le controle LOG-005 verifie.

Un trail multi-region apparait dans chaque region : on le dedoublonne par ARN pour
ne pas compter dix fois le meme objet.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from cspm_lite.auth import BOTO_CONFIG
from cspm_lite.collectors.base import collector, safe_call
from cspm_lite.engine import resource_types as rt
from cspm_lite.engine.models import Inventory, Resource

if TYPE_CHECKING:  # pragma: no cover
    from boto3.session import Session


@collector(name="cloudtrail", service="cloudtrail")
def collect_cloudtrail(session: Session, region: str, inv: Inventory) -> list[Resource]:
    client = session.client("cloudtrail", region_name=region, config=BOTO_CONFIG)
    deja_vus = {r.id for r in inv.by_type(rt.CLOUDTRAIL_TRAIL)}
    resources: list[Resource] = []

    for trail in client.describe_trails(includeShadowTrails=False).get("trailList", []):
        arn = trail["TrailARN"]
        if arn in deja_vus:
            continue
        brut = dict(trail)
        statut = safe_call(client.get_trail_status, Name=arn, default={}) or {}
        brut["IsLogging"] = bool(statut.get("IsLogging"))
        brut["LatestDeliveryTime"] = str(statut.get("LatestDeliveryTime", ""))
        selecteurs = safe_call(client.get_event_selectors, TrailName=arn, default={}) or {}
        brut["EventSelectors"] = selecteurs.get("EventSelectors", [])
        brut["AdvancedEventSelectors"] = selecteurs.get("AdvancedEventSelectors", [])

        resources.append(
            Resource(
                id=arn,
                type=rt.CLOUDTRAIL_TRAIL,
                region=trail.get("HomeRegion", region),
                name=trail.get("Name", ""),
                raw=brut,
            )
        )
    return resources
