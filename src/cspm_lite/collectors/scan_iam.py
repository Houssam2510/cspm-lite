"""Collecte IAM.

Source principale : le *credential report*. C'est une API asynchrone - on demande la
generation, on attend qu'elle soit prete, on recupere un CSV encode en base64. Peu
elegant, mais c'est une seule requete pour l'etat MFA, les cles et les dernieres
utilisations de tous les principaux, root compris.
"""

from __future__ import annotations

import csv
import io
import time
from typing import TYPE_CHECKING, Any

from botocore.exceptions import ClientError

from cspm_lite.auth import BOTO_CONFIG
from cspm_lite.collectors.base import collector, safe_call
from cspm_lite.engine import resource_types as rt
from cspm_lite.engine.models import Inventory, Resource

if TYPE_CHECKING:  # pragma: no cover
    from boto3.session import Session

ATTENTE_MAX_SECONDES = 30
INTERVALLE_SECONDES = 2


def credential_report(client: Any) -> list[dict[str, str]]:
    """Genere puis lit le credential report, avec attente bornee."""
    debut = time.monotonic()
    while True:
        etat = client.generate_credential_report()["State"]
        if etat == "COMPLETE":
            break
        if time.monotonic() - debut > ATTENTE_MAX_SECONDES:
            raise TimeoutError("credential report non genere dans le delai imparti")
        time.sleep(INTERVALLE_SECONDES)

    contenu = client.get_credential_report()["Content"].decode("utf-8")
    return list(csv.DictReader(io.StringIO(contenu)))


def _policies_attachees(client: Any, utilisateur: str) -> list[str]:
    arns: list[str] = []
    paginateur = client.get_paginator("list_attached_user_policies")
    for page in paginateur.paginate(UserName=utilisateur):
        arns += [p["PolicyArn"] for p in page.get("AttachedPolicies", [])]
    for page in client.get_paginator("list_groups_for_user").paginate(UserName=utilisateur):
        for groupe in page.get("Groups", []):
            for sous_page in client.get_paginator("list_attached_group_policies").paginate(
                GroupName=groupe["GroupName"]
            ):
                arns += [p["PolicyArn"] for p in sous_page.get("AttachedPolicies", [])]
    return sorted(set(arns))


@collector(name="iam", service="iam", global_service=True)
def collect_iam(session: Session, region: str, inv: Inventory) -> list[Resource]:
    client = session.client("iam", config=BOTO_CONFIG)
    resources: list[Resource] = []

    for ligne in credential_report(client):
        nom = ligne["user"]
        arn = ligne["arn"]
        raw: dict[str, Any] = dict(ligne)
        if nom != "<root_account>":
            try:
                raw["attached_policies"] = _policies_attachees(client, nom)
            except ClientError:
                raw["attached_policies"] = []
        resources.append(Resource(id=arn, type=rt.IAM_USER, region="global", name=nom, raw=raw))

    # Politique de mot de passe : absente si jamais configuree, ce qui est en soi un
    # constat (le check IAM-006 le traite), pas une panne.
    try:
        politique = client.get_account_password_policy()["PasswordPolicy"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise
        politique = {}
    resources.append(
        Resource(
            id=f"arn:aws:iam::{inv.account_id}:account-password-policy",
            type=rt.IAM_PASSWORD_POLICY,
            region="global",
            name="password-policy",
            raw=politique,
        )
    )

    # Policies gerees par le client uniquement : les policies AWS ne sont pas
    # modifiables et les auditer serait du bruit.
    paginateur = client.get_paginator("list_policies")
    for page in paginateur.paginate(Scope="Local", OnlyAttached=False):
        for policy in page.get("Policies", []):
            document = safe_call(
                client.get_policy_version,
                PolicyArn=policy["Arn"],
                VersionId=policy["DefaultVersionId"],
                default={},
            )
            resources.append(
                Resource(
                    id=policy["Arn"],
                    type=rt.IAM_POLICY,
                    region="global",
                    name=policy["PolicyName"],
                    raw={
                        "document": (document or {}).get("PolicyVersion", {}).get("Document", {}),
                        "attachment_count": policy.get("AttachmentCount", 0),
                    },
                )
            )

    return resources
