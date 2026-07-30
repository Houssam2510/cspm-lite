"""Collecte S3.

`ListBuckets` est global, mais chaque appel par bucket (policy, chiffrement...) doit
etre adresse a la region du bucket. On resout donc la region de chaque bucket avant
de l'interroger : c'est la source d'erreur numero un des scripts S3 amateurs.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING, Any

from cspm_lite.auth import BOTO_CONFIG
from cspm_lite.collectors.base import collector, safe_call
from cspm_lite.engine import resource_types as rt
from cspm_lite.engine.models import Inventory, Resource

if TYPE_CHECKING:  # pragma: no cover
    from boto3.session import Session


def _region_du_bucket(client: Any, nom: str) -> str:
    """LocationConstraint vaut None pour us-east-1 : bizarrerie historique de l'API."""
    contrainte = client.get_bucket_location(Bucket=nom).get("LocationConstraint")
    return contrainte or "us-east-1"


def _detail_bucket(session: Session, nom: str, region: str) -> Resource:
    client = session.client("s3", region_name=region, config=BOTO_CONFIG)

    pab = safe_call(client.get_public_access_block, Bucket=nom)
    acl = safe_call(client.get_bucket_acl, Bucket=nom, default={})
    policy_brute = safe_call(client.get_bucket_policy, Bucket=nom)
    chiffrement = safe_call(client.get_bucket_encryption, Bucket=nom)
    versioning = safe_call(client.get_bucket_versioning, Bucket=nom, default={})
    logging_conf = safe_call(client.get_bucket_logging, Bucket=nom, default={})
    tags = safe_call(client.get_bucket_tagging, Bucket=nom, default={})

    policy: dict[str, Any] | None = None
    if policy_brute and policy_brute.get("Policy"):
        import json

        policy = json.loads(policy_brute["Policy"])

    return Resource(
        id=f"arn:aws:s3:::{nom}",
        type=rt.S3_BUCKET,
        region=region,
        name=nom,
        tags={t["Key"]: t["Value"] for t in (tags or {}).get("TagSet", [])},
        raw={
            "name": nom,
            "public_access_block": (pab or {}).get("PublicAccessBlockConfiguration"),
            "acl_grants": (acl or {}).get("Grants", []),
            "policy": policy,
            "encryption": (chiffrement or {}).get("ServerSideEncryptionConfiguration"),
            "versioning": versioning,
            "logging": logging_conf,
        },
    )


@collector(name="s3", service="s3", global_service=True)
def collect_s3(session: Session, region: str, inv: Inventory) -> list[Resource]:
    client = session.client("s3", region_name=region, config=BOTO_CONFIG)
    noms = [b["Name"] for b in client.list_buckets().get("Buckets", [])]

    def traiter(nom: str) -> Resource | None:
        try:
            return _detail_bucket(session, nom, _region_du_bucket(client, nom))
        except Exception as exc:
            inv.errors.append(f"s3 : bucket {nom} ignore ({type(exc).__name__})")
            return None

    with ThreadPoolExecutor(max_workers=8) as pool:
        resultats = list(pool.map(traiter, noms))
    return [r for r in resultats if r is not None]
