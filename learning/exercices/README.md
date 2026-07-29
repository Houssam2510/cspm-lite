# 8. Les exercices — protocole étape par étape

Six exercices progressifs. Tu codes, un jeu de tests te dit immédiatement si c'est
juste, puis je relis ton code et je corrige ce que les tests ne voient pas :
la lisibilité, la structure, les cas non gérés, les réflexes de sécurité.

**Aucune installation nécessaire.** Ni `pip`, ni `pytest`, ni `boto3`, ni compte AWS.
Uniquement le Python 3.12 déjà présent sur ta machine. Les exercices travaillent sur
des dictionnaires qui reproduisent fidèlement les réponses de l'API AWS — ce qui est
aussi la bonne façon de construire l'outil, puisque les checks doivent être des
fonctions pures.

## Les six exercices

| # | Dossier | Sujet | Phase | Durée | Difficulté |
|---|---|---|---|---|---|
| 1 | `ex1-modele` | Le modèle de données, enums, dataclasses, score | 1 | 1 h 15 | 2/5 |
| 2 | `ex2-registre` | Décorateur, registre, isolation des pannes | 1 | 1 h 30 | 3/5 |
| 3 | `ex3-s3-public` | Les 4 chemins d'exposition d'un bucket S3 | 3 | 2 h | 4/5 |
| 4 | `ex4-cles-iam` | Credential report, dates, MFA root | 3 | 1 h 30 | 3/5 |
| 5 | `ex5-security-groups` | CIDR, IPv6, protocole `-1`, plages de ports | 3 | 2 h | 4/5 |
| 6 | `ex6-rapport` | Agrégation, tri déterministe, rendu Markdown | 4 | 1 h 30 | 3/5 |

Environ **10 heures** au total. Fais-les **dans l'ordre** : chacun suppose acquis ce
que le précédent t'a appris.

## Le protocole, étape par étape

### Étape 1 — Voir où tu en es

```bash
bash learning/exercices/verifier.sh
```

Tout est marqué `A FAIRE` au départ. C'est normal.

### Étape 2 — Lire l'énoncé en entier

```bash
cat learning/exercices/ex1-modele/enonce.md
```

Lis-le **complètement** avant d'écrire une ligne, y compris la section « pièges » —
elle décrit les cas que les tests vérifient. Les indices sont repliés : ne les ouvre
qu'après avoir vraiment essayé.

### Étape 3 — Lire les tests

```bash
cat learning/exercices/ex1-modele/test_exercice.py
```

Ce n'est pas de la triche : c'est la spécification exécutable. En entreprise, lire
les tests avant d'écrire le code est un réflexe recommandé. Les noms de tests
français t'indiquent précisément ce qui est attendu.

### Étape 4 — Coder

Remplis `exercice.py`. Remplace chaque `raise NotImplementedError` par ton
implémentation. Ne modifie ni `test_exercice.py`, ni `commun.py`.

### Étape 5 — Faire tourner les tests, en boucle

```bash
cd learning/exercices/ex1-modele
python3 -m unittest discover -v
```

Ou depuis la racine du projet, avec le détail :

```bash
bash learning/exercices/verifier.sh ex1
```

Boucle jusqu'au vert. **Ne passe pas à l'exercice suivant tant qu'un test échoue.**

### Étape 6 — Demander la correction

C'est l'étape que la plupart des gens sautent, et c'est celle qui fait progresser.

Écris-moi :

> **« corrige mon ex1 »**

Je lis ton `exercice.py` et je te réponds sur cinq axes :

1. **Justesse au-delà des tests** — les cas qu'ils ne couvrent pas
2. **Lisibilité** — nommage, longueur des fonctions, commentaires utiles ou inutiles
3. **Idiomes Python** — ce qu'un relecteur expérimenté écrirait autrement, et pourquoi
4. **Réflexe sécurité** — ce qui manquerait dans un vrai outil de production
5. **Une question ouverte** — pour vérifier que tu as compris, pas seulement réussi

Tu peux aussi demander une correction partielle : *« je bloque sur
`policy_allows_anyone`, explique-moi sans me donner le code »*. Je le ferai
volontiers — c'est souvent plus utile que la solution.

### Étape 7 — Consigner

Une entrée dans `learning/journal/`. Trois lignes suffisent, dont la plus importante :
**ce que tu ne savais pas avant**.

### Étape 8 — Reporter dans le projet

Une fois l'exercice validé et corrigé, transpose-le dans le vrai code du projet :

| Exercice | Destination |
|---|---|
| 1 | `src/cspm_lite/engine/models.py` |
| 2 | `src/cspm_lite/engine/registry.py` |
| 3 | `src/cspm_lite/engine/checks/s3_checks.py` |
| 4 | `src/cspm_lite/engine/checks/iam_checks.py` |
| 5 | `src/cspm_lite/engine/checks/net_checks.py` |
| 6 | `src/cspm_lite/reporters/markdown_reporter.py` |

Une branche, une PR, `Closes #<numéro d'issue>`. Après les six exercices, la moitié
du cœur de cspm-lite existe déjà — écrite par toi, testée, et relue.

## Règles

**Ne me demande pas la solution avant d'avoir essayé.** Tu as le droit de bloquer
30 minutes ; c'est même là que l'apprentissage se produit. Après 30 minutes réelles
sur le même point, demande une explication — pas le code.

**Ne modifie jamais les tests.** Si un test te paraît faux, dis-le-moi : soit tu as
trouvé une vraie erreur (ça arrive, et c'est un bon signe), soit l'écart entre ta
compréhension et le test est exactement ce qu'il faut creuser.

**Fais-les dans l'ordre.** L'exercice 5 suppose que tu as intégré la structure de
finding vue en 3 et 4.

## Que faire quand un test échoue

Le message d'`unittest` te donne le fichier, la ligne et la valeur attendue. Trois
réflexes, dans cet ordre :

1. **Lis le nom du test.** `test_authenticatedusers` t'indique le concept en jeu,
   pas seulement la ligne fautive.
2. **Reproduis en isolation.** Ouvre `python3` et appelle ta fonction avec l'entrée
   du test. Regarde ce qu'elle renvoie réellement.
3. **Relis la section de l'énoncé** correspondant à cette fonction. Neuf fois sur
   dix, la règle exacte y est écrite et tu l'as lue trop vite.

Pour ne lancer qu'un seul test :

```bash
cd learning/exercices/ex3-s3-public
python3 -m unittest test_exercice.TestPolicy.test_statement_dictionnaire_unique -v
```
