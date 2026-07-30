"""Sortie ASFF : AWS Security Finding Format, le schema d'AWS Security Hub.

L'interet n'est pas cosmetique. Un outil de securite qui produit un format
proprietaire finit ignore ; produire de l'ASFF signifie que les findings remontent
dans le meme flux que ceux de GuardDuty, Inspector ou Macie, avec le meme tri, les
memes regles de suppression et les memes integrations de ticketing.

Reference : docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html
"""

from __future__ import annotations

import json
from typing import Any

from cspm_lite.engine.models import Finding, ScanResult, Status

PRODUCT_NAME = "cspm-lite"
GENERATOR_PREFIX = "cspm-lite"

# ASFF impose une echelle numerique en plus du libelle.
SEVERITY_NORMALIZED = {
    "INFORMATIONAL": 0,
    "LOW": 20,
    "MEDIUM": 40,
    "HIGH": 70,
    "CRITICAL": 90,
}

COMPLIANCE_STATUS = {
    Status.PASS: "PASSED",
    Status.FAIL: "FAILED",
    Status.WARNING: "WARNING",
    Status.NOT_AVAILABLE: "NOT_AVAILABLE",
}


def _product_arn(account_id: str, region: str) -> str:
    return f"arn:aws:securityhub:{region}:{account_id}:product/{account_id}/default"


def finding_to_asff(finding: Finding, account_id: str, region: str) -> dict[str, Any]:
    horodatage = finding.detected_at.isoformat()
    ressource: dict[str, Any] = {
        "Type": finding.resource.type or "Other",
        "Id": finding.resource.id,
    }
    if finding.resource.region:
        ressource["Region"] = finding.resource.region
    if finding.resource.tags:
        ressource["Tags"] = dict(finding.resource.tags)

    document: dict[str, Any] = {
        "SchemaVersion": "2018-10-08",
        "Id": f"{finding.check_id}/{finding.resource.id}",
        "ProductArn": _product_arn(account_id, region),
        "GeneratorId": f"{GENERATOR_PREFIX}/{finding.check_id}",
        "AwsAccountId": account_id,
        "Types": ["Software and Configuration Checks/Industry and Regulatory Standards"],
        "CreatedAt": horodatage,
        "UpdatedAt": horodatage,
        "Severity": {
            "Label": finding.severity.name,
            "Normalized": SEVERITY_NORMALIZED[finding.severity.name],
        },
        "Title": finding.title,
        "Description": finding.details or finding.title,
        "ProductFields": {"cspm-lite/check-id": finding.check_id},
        "Resources": [ressource],
        "Compliance": {"Status": COMPLIANCE_STATUS[finding.status]},
        "RecordState": "ACTIVE",
        "Workflow": {"Status": "NEW"},
    }
    if finding.remediation:
        document["Remediation"] = {"Recommendation": {"Text": finding.remediation[:512]}}
        if finding.references:
            document["Remediation"]["Recommendation"]["Url"] = finding.references[0]
    if finding.cis:
        document["Compliance"]["RelatedRequirements"] = [f"CIS AWS Foundations {finding.cis}"]
    return document


def render_asff(result: ScanResult) -> str:
    region = result.regions[0] if result.regions else "us-east-1"
    documents = [finding_to_asff(f, result.account_id, region) for f in result.findings]
    return json.dumps(documents, indent=2, ensure_ascii=False)
