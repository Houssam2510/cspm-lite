"""Sortie JSON : le format machine, destine a l'automatisation.

Le champ `schema_version` est volontaire : un consommateur en aval (script, tableau
de bord, base de donnees) doit pouvoir detecter une rupture de format plutot que
d'echouer silencieusement.
"""

from __future__ import annotations

import json

from cspm_lite.engine.models import ScanResult


def render_json(result: ScanResult, *, indent: int = 2) -> str:
    return json.dumps(result.to_dict(), indent=indent, ensure_ascii=False, sort_keys=False)
