# ADR-002 — Une seule dépendance runtime : boto3

**Statut** : accepté · **Date** : 2026-07-30

## Contexte

La roadmap initiale prévoyait Typer pour la CLI, Rich pour l'affichage, pydantic
pour le modèle et Jinja pour le HTML. Quatre dépendances, plus leurs dépendances
transitives — soit une trentaine de paquets.

Pour un **outil de sécurité**, cet arbre est un problème en soi : chaque paquet est
un vecteur de compromission de la chaîne d'approvisionnement. Les incidents
`event-stream`, `ua-parser-js`, `xz-utils` et `PyTorch/torchtriton` ont tous suivi
le même schéma — un mainteneur compromis, du code malveillant livré à tout le monde.

## Décision

Une seule dépendance runtime : **boto3**, incontournable pour parler à AWS.

- CLI : `argparse` (stdlib)
- Modèle : `dataclasses` (stdlib)
- Configuration : `tomllib` (stdlib depuis 3.11)
- Historique : `sqlite3` (stdlib)
- HTML : f-strings et `html.escape` (stdlib)

## Conséquences

**Positives.** `cspm-lite list-checks` et `cspm-lite scan --demo` fonctionnent sur un
Python nu — un évaluateur peut essayer l'outil sans rien installer. La surface
d'attaque se réduit à un paquet, maintenu par AWS. Le SBOM tient en quelques lignes.

**Négatives.** La sortie terminal est moins jolie qu'avec Rich. `argparse` est plus
verbeux que Typer. Le rendu HTML est écrit à la main, donc l'échappement est notre
responsabilité — d'où un test dédié à l'injection.

**Note sur TOML plutôt que YAML.** YAML aurait imposé PyYAML, et son analyseur a un
historique de failles d'exécution de code à la désérialisation (`yaml.load` sans
`SafeLoader`). TOML se lit avec la stdlib, sans risque.
