# Exercice 2 — Le registre de checks

**Phase du projet** : 1 · **Durée visée** : 1 h 30 · **Difficulté** : 3/5

## Contexte

Tu vas écrire 30+ checks. Il est hors de question que `run_checks()` contienne 30
appels écrits à la main : ajouter un check doit se limiter à écrire une fonction et
la décorer. C'est le **pattern registry** — le même mécanisme que `@app.route` dans
Flask ou `@pytest.fixture`.

Deuxième enjeu, plus important : en production, un check plantera. Peut-être parce
qu'AWS a changé un champ, peut-être parce qu'un bucket a été supprimé pendant le
scan. Si un seul check qui tombe interrompt les 29 autres, ton outil est inutilisable.
C'est l'**isolation des pannes**.

`commun.py` te fournit `Severity`, `Status`, `Resource` et `Finding` — ne le modifie
pas.

## À implémenter dans `exercice.py`

### 1. `CheckMeta`

Une dataclass décrivant un check enregistré : `id`, `title`, `severity`, `service`,
`func`.

### 2. `REGISTRY`

Un dictionnaire `{id: CheckMeta}` au niveau du module. L'ordre d'insertion doit être
préservé (c'est le cas des dict Python depuis 3.7).

### 3. `check(...)` — le décorateur

```python
@check(id="S3-001", title="Block Public Access", severity=Severity.HIGH, service="s3")
def s3_block_public_access(inventory: dict) -> list[Finding]:
    ...
```

Exigences :
- il **enregistre** la fonction et la **renvoie inchangée** (appeler
  `s3_block_public_access(inv)` directement doit continuer à marcher) ;
- enregistrer deux fois le même `id` lève une `ValueError`.

### 4. `get_checks(service=None, severity_min=None) -> list[CheckMeta]`

Renvoie les checks enregistrés dans l'ordre d'enregistrement, filtrés :
- `service` — ne garde que ce service (comparaison insensible à la casse) ;
- `severity_min` — ne garde que les sévérités **supérieures ou égales**.

Sans filtre, renvoie tout.

### 5. `run_checks(inventory, checks=None) -> list[Finding]`

Exécute les checks (ceux passés, sinon tous ceux du registre) et concatène leurs
findings, dans l'ordre.

**Le point central** : si une fonction de check lève une exception, `run_checks` ne
doit **pas** propager l'erreur. Elle produit à la place un finding unique :

- `check_id` = l'id du check
- `title` = le titre du check
- `severity` = la sévérité du check
- `status` = `Status.NOT_AVAILABLE`
- `resource` = `Resource(id="-")`
- `details` contient le **message de l'exception**

Puis elle continue avec les checks suivants.

### 6. `clear_registry()`

Vide le registre. Utilisé par les tests entre chaque cas.

## Vérifier ton travail

```bash
cd learning/exercices/ex2-registre
python3 -m unittest discover -v
```

## Questions à te poser avant de coder

1. `@check(...)` prend des arguments : ton décorateur a donc **trois** niveaux
   (fonction qui prend les arguments → fonction qui prend la fonction → …). Combien
   exactement, et pourquoi ?
2. Pourquoi renvoyer la fonction inchangée plutôt qu'un wrapper ?
3. Pourquoi capturer `Exception` et pas `BaseException` ? (réfléchis à ce qui se
   passe si l'utilisateur fait Ctrl+C pendant un scan)

## Indices (en cas de blocage)

<details>
<summary>Indice 1 — décorateur paramétré</summary>

```python
def check(*, id, title, severity, service):
    def decorateur(func):
        # enregistrer ici
        return func
    return decorateur
```
Deux niveaux de fonctions imbriquées, parce que `@check(...)` est d'abord *appelé*,
et c'est son résultat qui décore.
</details>

<details>
<summary>Indice 2 — récupérer le message d'une exception</summary>

`except Exception as exc:` puis `str(exc)`. Pense aussi à
`f"{type(exc).__name__}: {exc}"` — plus utile en débogage.
</details>

## Auto-évaluation

- Si un check renvoie `None` au lieu d'une liste, que fait ton `run_checks` ?
- Comment testerais-tu que l'isolation des pannes fonctionne, sans les tests fournis ?
- Quel est l'inconvénient d'un registre global au niveau du module ?
