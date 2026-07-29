# Exercice 4 — Clés IAM anciennes et MFA du root

**Phase du projet** : 3 · **Durée visée** : 1 h 30 · **Difficulté** : 3/5

## Contexte

Les clés d'accès IAM statiques sont le premier vecteur de compromission cloud. Elles
fuient dans un dépôt Git, dans un fichier de configuration, dans une capture d'écran,
dans un log. Contrairement à un mot de passe, elles ne périment jamais toutes seules
et n'ont pas de second facteur. Une clé de trois ans qui fuit reste valide trois ans.

D'où le contrôle **CIS 1.14** : aucune clé d'accès de plus de 90 jours.

Et le contrôle **CIS 1.5**, le plus critique de tous : le compte **root** doit avoir
le MFA activé. Le root ne peut être restreint par aucune policy, aucun SCP, aucune
permission boundary. Qui a le root a tout, définitivement.

## Le credential report

AWS expose un rapport unique et complet via `generate_credential_report` puis
`get_credential_report`. C'est une API **asynchrone** qui renvoie un CSV encodé en
base64 — inélégant, et typique de ce qu'on rencontre en entreprise.

Format (réduit ici aux colonnes utiles) :

```
user,arn,user_creation_time,password_enabled,password_last_used,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_2_active,access_key_2_last_rotated
<root_account>,arn:aws:iam::111122223333:root,2020-01-01T00:00:00+00:00,not_supported,2026-07-01T09:00:00+00:00,false,false,N/A,false,N/A
alice,arn:aws:iam::111122223333:user/alice,2023-03-10T12:00:00+00:00,true,2026-07-20T08:00:00+00:00,true,true,2024-01-05T10:00:00+00:00,false,N/A
```

Trois valeurs spéciales à connaître : `N/A` (sans objet), `not_supported` (la notion
n'existe pas pour ce principal), `no_information` (jamais utilisé).

## À implémenter dans `exercice.py`

### 1. `parse_credential_report(csv_text) -> list[dict]`

Parse le CSV et renvoie une liste de dictionnaires, une par ligne, dans l'ordre.
Utilise le module `csv` de la bibliothèque standard — pas de découpage manuel sur les
virgules.

### 2. `to_bool(value) -> bool`

`"true"` → `True`, tout le reste (`"false"`, `"N/A"`, `"not_supported"`, `""`) →
`False`. Insensible à la casse.

### 3. `key_age_days(last_rotated, now) -> int | None`

Âge en jours entiers d'une clé.

- `"N/A"`, `"not_supported"`, `"no_information"` ou chaîne vide → `None` ;
- sinon, parse la date ISO 8601 et renvoie le nombre de jours entiers écoulés.

`now` est un `datetime` **conscient du fuseau** (tz-aware). Les dates du rapport le
sont aussi (`+00:00`). Si tu construis un `datetime` naïf quelque part, la
soustraction lèvera une `TypeError` — c'est voulu, c'est le piège classique des dates
en Python.

### 4. `check_old_keys(rows, now, max_age_days=90) -> list[Finding]`

Un `Finding` par **clé active**, dans l'ordre des lignes, la clé 1 avant la clé 2.
Une clé inactive n'est pas évaluée du tout (pas de finding).

| Champ | Valeur |
|---|---|
| `check_id` | `"IAM-004"` |
| `title` | `"Cle d'acces de plus de 90 jours"` |
| `severity` | `Severity.HIGH` |
| `status` | `FAIL` si l'âge est **strictement supérieur** à `max_age_days`, sinon `PASS` |
| `resource.id` | l'`arn` de la ligne |
| `resource.type` | `"AWS::IAM::User"` |
| `resource.name` | le `user` de la ligne |
| `details` | exactement `f"access_key_{n} : {age} jours"` avec `n` valant 1 ou 2 |
| `remediation` | une phrase non vide |

Une clé active dont la date de rotation est inexploitable (`None`) produit un finding
`Status.NOT_AVAILABLE` avec `details` valant `f"access_key_{n} : date indisponible"`.

### 5. `check_root_mfa(rows) -> Finding`

Cherche la ligne dont `user` vaut `<root_account>`.

- trouvée et `mfa_active` vrai → `PASS` ;
- trouvée et faux → `FAIL` ;
- absente → `Status.NOT_AVAILABLE`, avec `resource.id` valant `"-"`.

`check_id` = `"IAM-002"`, `title` = `"MFA active sur le compte root"`,
`severity` = `Severity.CRITICAL`.

## Vérifier ton travail

```bash
cd learning/exercices/ex4-cles-iam
python3 -m unittest discover -v
```

## Auto-évaluation

- Pourquoi 90 jours et pas 30 ou 365 ? Que se passe-t-il si tu forces la rotation
  toutes les semaines ?
- Une clé de 400 jours **jamais utilisée** est-elle plus ou moins dangereuse qu'une
  clé de 100 jours utilisée quotidiennement ? Comment ton check pourrait-il faire la
  différence ?
- Quelle est la vraie solution au problème des clés statiques, celle qui rend ce
  check inutile ?
