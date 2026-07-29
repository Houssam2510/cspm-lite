# Exercice 1 — Le modèle de données

**Phase du projet** : 1 · **Durée visée** : 1 h 15 · **Difficulté** : 2/5

## Contexte

C'est la fondation de tout l'outil. Chaque collector produira des `Resource`, chaque
check produira des `Finding`, chaque reporter consommera des `Finding`. Si ce modèle
est bancal, les neuf phases suivantes le paieront.

## À implémenter dans `exercice.py`

### 1. `Severity`

Une énumération : `INFORMATIONAL`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.

Deux exigences :
- **comparable** — `Severity.LOW < Severity.CRITICAL` doit être vrai, et
  `sorted(liste_de_severites)` doit fonctionner ;
- **pondérée** — une propriété `weight` : `CRITICAL`=10, `HIGH`=5, `MEDIUM`=3,
  `LOW`=1, `INFORMATIONAL`=0. C'est ce qui servira au score de posture.

### 2. `Status`

Une énumération : `PASS`, `FAIL`, `WARNING`, `NOT_AVAILABLE`. La valeur de chaque
membre est la chaîne correspondante (`Status.PASS.value == "PASS"`).

### 3. `Resource`

Une dataclass : `id` (obligatoire), puis `type`, `region`, `name` (chaînes vides par
défaut) et `tags` (dictionnaire vide par défaut).

### 4. `Finding`

Une dataclass : `check_id`, `title`, `severity`, `status`, `resource` (obligatoires),
puis `remediation` et `details` (chaînes vides par défaut).

Plus une méthode `to_dict()` renvoyant un dictionnaire **directement sérialisable par
`json.dumps`**. Contraintes :
- `severity` devient le **nom** de l'énumération : `"CRITICAL"` ;
- `status` devient sa **valeur** : `"FAIL"` ;
- `resource` devient un sous-dictionnaire avec les clés `id`, `type`, `region`,
  `name`, `tags`.

### 5. `posture_score(findings) -> float`

Le score de posture, entre 0.0 et 100.0, arrondi à une décimale.

```
score = 100 * (somme des poids des PASS) / (somme des poids des PASS et des FAIL)
```

Trois règles à respecter :
- une liste vide renvoie `100.0` (rien à reprocher) ;
- les findings dont le statut n'est ni `PASS` ni `FAIL` sont **ignorés**
  (`NOT_AVAILABLE` signifie « je n'ai pas pu vérifier », pas « c'est un échec ») ;
- si le dénominateur est nul, renvoie `100.0`.

## Vérifier ton travail

```bash
cd learning/exercices/ex1-modele
python3 -m unittest discover -v
```

## Pièges volontaires

Les tests en contiennent plusieurs. Cherche-les avant de lancer :

1. Que se passe-t-il si deux `Resource` créées sans tags partagent le même
   dictionnaire ? (le piège du paramètre par défaut mutable en Python)
2. `Severity.HIGH < Severity.CRITICAL` ne marche pas tout seul sur un `Enum`
   classique. Deux solutions existent — laquelle et pourquoi ?
3. Un finding `NOT_AVAILABLE` de sévérité `CRITICAL` doit-il faire baisser le score ?

## Indices (à ne lire qu'en cas de blocage)

<details>
<summary>Indice 1 — comparaison de sévérités</summary>

Soit `class Severity(IntEnum)`, soit un `Enum` classique avec `__lt__` défini. La
seconde est plus explicite ; la première expose accidentellement l'arithmétique
(`Severity.HIGH + 1` devient valide, ce qui n'a aucun sens).
</details>

<details>
<summary>Indice 2 — dataclass et valeurs par défaut mutables</summary>

`tags: dict = {}` lève une erreur. Regarde `dataclasses.field(default_factory=...)`.
</details>

## Auto-évaluation

Une fois les tests verts, réponds sans regarder ton code :
- Pourquoi `to_dict()` plutôt que de laisser le reporter accéder aux attributs ?
- Pourquoi le score pondère-t-il par sévérité au lieu de compter les findings ?
- Que se passerait-il si tu ajoutais un membre `Severity.URGENT` demain ?
