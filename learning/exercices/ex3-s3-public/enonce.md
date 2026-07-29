# Exercice 3 — Détecter un bucket S3 public

**Phase du projet** : 3 · **Durée visée** : 2 h · **Difficulté** : 4/5

## Contexte

C'est **le** check qui justifie l'existence des CSPM. Capital One, Accenture,
Verizon, Booz Allen Hamilton : toutes ces fuites ont la même cause racine.

Le piège, c'est qu'un bucket peut devenir public par **quatre chemins différents**,
et qu'un outil qui n'en vérifie qu'un donne une fausse assurance — pire que pas
d'outil du tout.

> **Avant de coder**, si tu ne l'as pas fait : va faire les 2 premiers niveaux de
> **flaws.cloud**. Une heure. Tu écriras un bien meilleur check après avoir lu toi-même
> le contenu d'un bucket qui ne t'appartient pas.

## Le format d'entrée

Chaque bucket est un dictionnaire produit par le collector (exercice hors périmètre
ici) :

```python
{
    "name": "mon-bucket",
    "region": "eu-west-3",
    "public_access_block": {          # ou None si aucun n'est configuré
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": True,
    },
    "acl_grants": [                   # tel que renvoye par get_bucket_acl
        {"Grantee": {"Type": "Group",
                     "URI": "http://acs.amazonaws.com/groups/global/AllUsers"},
         "Permission": "READ"}
    ],
    "policy": {                       # ou None si aucune policy
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": "*",
             "Action": "s3:GetObject", "Resource": "arn:aws:s3:::mon-bucket/*"}
        ],
    },
}
```

## À implémenter dans `exercice.py`

### 1. `is_pab_effective(pab) -> bool`

`True` uniquement si `pab` est un dictionnaire dont les **quatre** drapeaux
(`BlockPublicAcls`, `IgnorePublicAcls`, `BlockPublicPolicy`,
`RestrictPublicBuckets`) valent `True`. `None` ou un drapeau manquant → `False`.

> *Simplification assumée* : dans la réalité, `BlockPublicAcls` ne neutralise que les
> ACL et `BlockPublicPolicy` que les policies. On exige les quatre parce que c'est la
> configuration recommandée et que « partiellement bloqué » est une fausse sécurité.

### 2. `acl_public_reasons(grants) -> set[str]`

Parcourt les grants et renvoie un ensemble contenant :

- `"acl-allusers"` si un grant vise le groupe
  `http://acs.amazonaws.com/groups/global/AllUsers` ;
- `"acl-authenticatedusers"` si un grant vise
  `http://acs.amazonaws.com/groups/global/AuthenticatedUsers`.

⚠️ **Le piège du métier** : `AuthenticatedUsers` ne veut **pas** dire « mes
utilisateurs ». Cela veut dire *n'importe quel titulaire d'un compte AWS dans le
monde*. C'est-à-dire public, avec une étape de plus. Beaucoup de développeurs
expérimentés se trompent là-dessus.

Un grant vers un `Type: "CanonicalUser"` désigne un compte précis : ce n'est pas
public.

### 3. `policy_allows_anyone(policy) -> bool`

`True` si la policy contient au moins une déclaration qui :

- a `"Effect": "Allow"` (un `Deny` sur `*` est une protection, pas un risque), **et**
- a un `Principal` générique, sous l'une de ces formes : `"*"`, `{"AWS": "*"}`,
  `{"AWS": ["*", ...]}`, **et**
- n'a **aucune** clé `Condition` (une condition — `aws:SourceVpce`, `aws:SourceIp`,
  `aws:PrincipalOrgID` — restreint l'accès ; c'est un motif légitime très répandu).

Attention : `Statement` peut être **soit une liste, soit un dictionnaire unique**.
C'est autorisé par le langage de policy IAM, et c'est un bug classique.

### 4. `bucket_public_reasons(bucket) -> list[str]`

Toutes les raisons, **triées par ordre alphabétique et sans doublon**. Ajoute
`"policy-principal-wildcard"` si `policy_allows_anyone` est vrai.

Cette fonction décrit ce que le bucket **expose**, indépendamment du blocage.

### 5. `is_effectively_public(bucket) -> bool`

`True` si le bucket a au moins une raison **et** que le Public Access Block n'est pas
pleinement actif.

### 6. `check_s3_public(buckets) -> list[Finding]`

Un `Finding` par bucket, dans l'ordre reçu :

| Champ | Valeur |
|---|---|
| `check_id` | `"S3-002"` |
| `title` | `"Bucket S3 accessible publiquement"` |
| `severity` | `Severity.CRITICAL` |
| `status` | `FAIL` si `is_effectively_public`, sinon `PASS` |
| `resource.id` | `f"arn:aws:s3:::{nom}"` |
| `resource.type` | `"AWS::S3::Bucket"` |
| `resource.name` | le nom du bucket |
| `resource.region` | la région du bucket |
| `remediation` | une phrase non vide (à toi de l'écrire) |
| `details` | `", ".join(raisons)` |

## Vérifier ton travail

```bash
cd learning/exercices/ex3-s3-public
python3 -m unittest discover -v
```

## Auto-évaluation

- Un bucket avec PAB complet **et** une ACL `AllUsers` : ton check dit PASS. Est-ce
  la bonne réponse ? Que dirais-tu à l'équipe qui possède ce bucket ?
- Pourquoi une policy avec `Condition` n'est-elle pas comptée comme publique ?
  Trouve un contre-exemple où c'est faux (une condition qui ne restreint rien).
- Quel cinquième mécanisme d'exposition n'est pas couvert par cet exercice ?
