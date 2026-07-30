# Guide d'apprentissage — cspm-lite

Ce dossier est ton compagnon de route pour construire **cspm-lite** en comprenant
chaque étape, pas en la copiant.

## Contenu

| Fichier | Contenu |
|---|---|
| [01-le-projet.md](01-le-projet.md) | Ce qu'est un CSPM, l'architecture, le glossaire, les règles de sécurité du projet |
| [02-roadmap.md](02-roadmap.md) | Les 10 phases : étapes, ce que tu apprends, définition de « fini » |
| [03-issues.md](03-issues.md) | 30 issues GitHub prêtes à créer, avec labels et DoD |
| [04-concepts-cles.md](04-concepts-cles.md) | Les fiches à savoir expliquer sans notes |
| [05-competences-et-valorisation.md](05-competences-et-valorisation.md) | CV, entretien, certifications, extensions, planning 12 semaines |
| [06-journal-de-bord.md](06-journal-de-bord.md) | Modèle de journal, checklist de progression, ressources |
| [07-maximiser-le-bagage.md](07-maximiser-le-bagage.md) | Comment convertir 80 h de travail en compétence durable et démontrable |
| [09-fiche-entretien.md](09-fiche-entretien.md) | **La synthèse à relire avant un entretien** — chiffres, décisions, pièges, histoires |
| [exercices/](exercices/README.md) | **6 exercices à coder toi-même**, 153 tests automatiques, protocole de correction |
| [08-pitch-entretien.md](08-pitch-entretien.md) | Pitchs 30 s / 2 min, tableau blanc, 5 histoires, questions de relance |
| [scripts/create_issues.sh](scripts/create_issues.sh) | Crée les labels et les 30 issues via `gh` |
| [tools/build_pdf.py](tools/build_pdf.py) | Génère le PDF complet du guide |
| `cspm-lite-entretien.pdf` | **La fiche d'entretien en 7 pages** |
| `cspm-lite-guide.pdf` | Le guide entier en un seul PDF (47 pages) |

## Par où commencer

1. Lis [01-le-projet.md](01-le-projet.md) en entier (15 min).
2. Survole [02-roadmap.md](02-roadmap.md) pour avoir la carte, sans tout retenir.
3. Lis [07-maximiser-le-bagage.md](07-maximiser-le-bagage.md) **avant** de commencer à
   coder : les pistes parallèles se mènent pendant le projet, pas après.
4. Crée les issues : `bash learning/scripts/create_issues.sh` (nécessite `gh`).
5. Attaque la phase 0. Une issue, une branche, une PR.
6. **Fais les exercices** au fur et à mesure des phases correspondantes :
   `bash learning/exercices/verifier.sh` pour voir où tu en es. Demande-moi
   « corrige mon ex1 » quand les tests sont verts.
7. Après chaque session, remplis une entrée de journal.

## Régénérer le PDF

```bash
python3 learning/tools/build_pdf.py
```

Aucune dépendance externe : le script écrit le PDF directement.

## Trois principes pour ne pas te perdre

**Comprendre avant d'écrire.** Pour chaque check, tu dois pouvoir dire ce qu'un
attaquant ferait de la misconfiguration. Si tu ne peux pas, ne code pas le check
encore — lis d'abord.

**Fini vaut mieux que parfait.** Ne repars pas améliorer la phase 2 alors que tu es
en phase 5. La phase 10 est ce qui donne sa valeur au projet.

**Rien de sensible dans Git.** Pas de clé, pas de `.tfstate`, pas de capture d'écran
avec un ARN de compte réel. Vérifie avec `git diff --cached` avant chaque commit.
