# Architecture Decision Records

Un ADR consigne **une décision, son contexte et ses conséquences**. Ce n'est pas de
la documentation d'usage : c'est la mémoire du *pourquoi*.

L'intérêt est double. Dans six mois, on ne se demande pas « pourquoi diable ai-je
fait ça » — et en entretien, on peut défendre chaque choix au lieu de dire « c'est
ce que faisait le tutoriel ».

Un ADR n'est jamais modifié une fois accepté. S'il devient faux, on en écrit un
nouveau qui le remplace (`Statut : remplacé par ADR-00X`).

| # | Décision | Statut |
|---|---|---|
| [001](001-separation-collecte-evaluation.md) | Séparer collecte et évaluation | Accepté |
| [002](002-une-seule-dependance.md) | Une seule dépendance runtime | Accepté |
| [003](003-isolation-des-pannes.md) | Isoler les pannes de checks | Accepté |
| [004](004-score-pondere.md) | Pondérer le score par sévérité | Accepté |
| [005](005-exclusions-datees.md) | Exiger une date d'expiration sur les exclusions | Accepté |
| [006](006-pas-d-actions-pour-les-outils-de-securite.md) | Lancer Trivy et Syft depuis leur image, pas via leur action | Accepté |
