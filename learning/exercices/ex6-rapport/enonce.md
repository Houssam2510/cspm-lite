# Exercice 6 — Agrégation et rapport Markdown

**Phase du projet** : 4 · **Durée visée** : 1 h 30 · **Difficulté** : 3/5

## Contexte

Tu as maintenant des centaines de findings. Un rapport qui les liste tous sans les
ordonner est **inutile** : personne ne le lira. Un rapport utile répond à une seule
question — *qu'est-ce que je corrige en premier ?*

Le format Markdown est celui qu'on colle en commentaire de pull request : c'est ce
qui fait qu'un outil de sécurité est lu par les développeurs plutôt qu'ignoré.

## À implémenter dans `exercice.py`

### 1. `summarize(findings) -> dict`

Un dictionnaire avec exactement ces clés :

| Clé | Contenu |
|---|---|
| `total` | nombre total de findings, tous statuts confondus |
| `pass` | nombre de `PASS` |
| `fail` | nombre de `FAIL` |
| `by_severity` | `{nom_de_severite: nombre de FAIL}` — **uniquement les sévérités ayant au moins un FAIL** |
| `score` | le score de posture (même formule qu'à l'exercice 1), arrondi à une décimale |
| `pass_rate` | `100 * pass / (pass + fail)`, arrondi à une décimale, `100.0` si le dénominateur est nul |

Rappel de la formule du score : `100 * somme(poids des PASS) / somme(poids des PASS
et FAIL)`, les autres statuts ignorés, `100.0` si le dénominateur est nul.

### 2. `top_offenders(findings, n=3) -> list[tuple[str, int]]`

Les ressources qui accumulent le plus d'échecs : une liste de couples
`(resource.id, nombre de FAIL)`, triée par **nombre décroissant**, puis par
**identifiant croissant** en cas d'égalité. Limitée à `n` éléments. Seuls les `FAIL`
comptent.

Ce tri à deux critères est ce qui rend la sortie **déterministe** — sans lui, ton
rapport change à chaque exécution et devient impossible à comparer d'un scan à
l'autre.

### 3. `render_markdown(findings) -> str`

Structure exacte attendue :

```markdown
# Rapport de posture cspm-lite

**Score : 37.5 / 100** — 1 conformes, 2 en echec

| Severite | Echecs |
| --- | --- |
| CRITICAL | 1 |
| HIGH | 1 |

## Findings en echec

### CRITICAL

- **S3-002** — Bucket S3 accessible publiquement — `arn:aws:s3:::leaky`

### HIGH

- **IAM-004** — Cle d'acces de plus de 90 jours — `arn:aws:iam::1:user/bob`
```

Règles :

- la première ligne est exactement `# Rapport de posture cspm-lite` ;
- la ligne de score suit le gabarit
  `**Score : {score} / 100** — {pass} conformes, {fail} en echec` ;
- le tableau ne contient **que** les sévérités ayant au moins un échec, de la plus
  grave à la moins grave ;
- chaque section `### {SEVERITE}` liste ses findings **dans l'ordre d'entrée**, au
  format `- **{check_id}** — {title} — \`{resource.id}\`` ;
- les findings `PASS`, `WARNING` et `NOT_AVAILABLE` n'apparaissent **jamais** dans la
  section des échecs ;
- s'il n'y a aucun échec, la ligne `Aucun finding en echec.` remplace les sections.

## Vérifier ton travail

```bash
cd learning/exercices/ex6-rapport
python3 -m unittest discover -v
```

## Auto-évaluation

- Pourquoi trier par identifiant en cas d'égalité plutôt que de laisser l'ordre
  naturel ?
- Ton rapport affiche le score. Un score de 85/100 est-il bon ? Que manque-t-il pour
  répondre à cette question ? (indice : c'est l'objet de la phase 9)
- Un développeur reçoit ce rapport en commentaire de PR. Qu'est-ce qui lui manque
  pour corriger sans poser de question ?
