"""Collecte EC2 / VPC : security groups, instances, volumes, VPC et flow logs.

Collecteur regional : il est appele une fois par region activee, en parallele. Toutes
les listes passent par un paginateur - `describe_*` plafonne a quelques centaines
d'elements et lire seulement la premiere page est le bug silencieux classique.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from cspm_lite.auth import BOTO_CONFIG
from cspm_lite.collectors.base import collector
from cspm_lite.engine import resource_types as rt
from cspm_lite.engine.models import Inventory, Resource

if TYPE_CHECKING:  # pragma: no cover
    from boto3.session import Session


def _tags(objet: dict[str, Any]) -> dict[str, str]:
    return {t["Key"]: t["Value"] for t in objet.get("Tags", [])}


def _nom(objet: dict[str, Any], defaut: str = "") -> str:
    return _tags(objet).get("Name", defaut)


def _pages(client: Any, operation: str, cle: str, **kwargs: Any) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for page in client.get_paginator(operation).paginate(**kwargs):
        items += page.get(cle, [])
    return items


@collector(name="ec2", service="ec2")
def collect_ec2(session: Session, region: str, inv: Inventory) -> list[Resource]:
    client = session.client("ec2", region_name=region, config=BOTO_CONFIG)
    compte = inv.account_id
    resources: list[Resource] = []

    for sg in _pages(client, "describe_security_groups", "SecurityGroups"):
        resources.append(
            Resource(
                id=f"arn:aws:ec2:{region}:{compte}:security-group/{sg['GroupId']}",
                type=rt.EC2_SECURITY_GROUP,
                region=region,
                name=sg.get("GroupName", ""),
                tags=_tags(sg),
                raw=sg,
            )
        )

    for reservation in _pages(client, "describe_instances", "Reservations"):
        for instance in reservation.get("Instances", []):
            if instance.get("State", {}).get("Name") == "terminated":
                continue  # une instance detruite n'a plus de posture
            resources.append(
                Resource(
                    id=f"arn:aws:ec2:{region}:{compte}:instance/{instance['InstanceId']}",
                    type=rt.EC2_INSTANCE,
                    region=region,
                    name=_nom(instance, instance["InstanceId"]),
                    tags=_tags(instance),
                    raw=instance,
                )
            )

    for volume in _pages(client, "describe_volumes", "Volumes"):
        resources.append(
            Resource(
                id=f"arn:aws:ec2:{region}:{compte}:volume/{volume['VolumeId']}",
                type=rt.EC2_VOLUME,
                region=region,
                name=_nom(volume, volume["VolumeId"]),
                tags=_tags(volume),
                raw=volume,
            )
        )

    # Les flow logs sont rattaches au VPC : on les indexe pour eviter un appel par VPC.
    flow_logs_par_vpc: dict[str, list[dict[str, Any]]] = {}
    for fl in _pages(client, "describe_flow_logs", "FlowLogs"):
        flow_logs_par_vpc.setdefault(fl.get("ResourceId", ""), []).append(fl)

    for vpc in _pages(client, "describe_vpcs", "Vpcs"):
        brut = dict(vpc)
        brut["flow_logs"] = flow_logs_par_vpc.get(vpc["VpcId"], [])
        resources.append(
            Resource(
                id=f"arn:aws:ec2:{region}:{compte}:vpc/{vpc['VpcId']}",
                type=rt.EC2_VPC,
                region=region,
                name=_nom(vpc, vpc["VpcId"]),
                tags=_tags(vpc),
                raw=brut,
            )
        )

    return resources
