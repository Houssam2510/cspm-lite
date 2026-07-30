# Contribuer

## Mise en route

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

## Ajouter un contrôle

C'est la contribution la plus utile. Un contrôle est une fonction pure dans
`src/cspm_lite/engine/checks/` :

```python
@check(
    id="S3-007",
    title="Titre court et affirmatif de l'etat souhaite",
    severity=Severity.MEDIUM,
    service="s3",
    cis="2.1.x",  # si le controle existe au benchmark
    remediation="Comment corriger, concretement.",
)
def s3_mon_controle(inv: Inventory) -> list[Finding]:
    return [
        make_finding("S3-007", bucket, ok=condition, details="ce qui a ete constate")
        for bucket in inv.by_type(rt.S3_BUCKET)
    ]
```

Exigences, non négociables :

1. **Fonction pure.** Aucun import de `boto3`. Si la donnée manque, ajoutez-la au
   collecteur — voir [ADR-001](docs/adr/001-separation-collecte-evaluation.md).
2. **Titre affirmatif** décrivant l'état *souhaité* (« Versioning activé »), pas le
   problème. Un `PASS` doit se lire naturellement.
3. **Remédiation actionnable.** Pas « corriger la configuration » mais la commande ou
   le réglage précis.
4. **Deux tests minimum** : un `PASS`, un `FAIL`. Plus un test par cas limite que
   vous avez identifié — c'est là qu'est la valeur.
5. **Type de ressource depuis `resource_types`**, jamais une chaîne littérale.

## Ajouter un collecteur

Décorez avec `@collector(name=..., service=..., global_service=...)` et renvoyez des
`Resource`. Utilisez toujours un paginateur (`get_paginator`) et `safe_call()` pour
les appels dont l'absence de configuration est normale.

## Style

- `ruff check .` et `ruff format .` avant de pousser ; `mypy src` doit passer.
- Commentaires et docstrings en français, identifiants en anglais.
- Un commentaire explique **pourquoi**, jamais **quoi**. Le code dit déjà quoi.

## Workflow

Une issue → une branche → une pull request.

```
feat/15-s3-tls-check
fix/22-ipv6-non-detecte
```

Messages de commit conventionnels : `feat(checks): ajouter le controle TLS S3`.

Dans la description de la PR, trois lignes : ce que ça fait, pourquoi, comment vous
l'avez testé. Fermez l'issue avec `Closes #15`.

## Ce qui bloque une PR

- un contrôle sans test de cas limite ;
- un `except` nu ou un `except Exception` sans commentaire justifiant l'isolation ;
- une dépendance runtime supplémentaire (voir [ADR-002](docs/adr/002-une-seule-dependance.md)) —
  ouvrez une issue de discussion d'abord ;
- un rapport HTML qui charge une ressource externe ;
- un identifiant de compte AWS réel dans un test ou une capture d'écran.
