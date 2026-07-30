# ADR-003 — Un check qui plante n'interrompt pas le scan

**Statut** : accepté · **Date** : 2026-07-30

## Contexte

En production, un check finira par lever une exception : un champ d'API renommé par
AWS, une ressource supprimée pendant le scan, une réponse au format inattendu.

Si l'exception remonte, le scan complet échoue et l'utilisateur n'obtient **aucun**
résultat — y compris pour les 24 contrôles qui fonctionnaient parfaitement.

## Décision

`run_checks()` capture `Exception` autour de chaque check et produit un `Finding` de
statut `NOT_AVAILABLE` portant le message d'erreur, puis continue.

`BaseException` n'est **pas** capturée : un `KeyboardInterrupt` (Ctrl+C) ou un
`SystemExit` doivent bien interrompre le scan. Un test le vérifie explicitement.

Le même principe s'applique aux collecteurs (`_run_one`), avec une distinction : un
`AccessDenied` produit un message explicite sur les droits manquants plutôt qu'une
trace technique.

## Conséquences

**Positives.** L'outil dégrade au lieu de s'effondrer. `NOT_AVAILABLE` est
sémantiquement distinct de `FAIL` — ne pas avoir pu vérifier n'est pas un échec — et
sort du calcul du score.

**Négatives.** Un bug de check peut passer inaperçu dans le bruit d'un gros rapport.
Mitigation : les findings `NOT_AVAILABLE` remontent dans les avertissements du
rapport, et la CI échoue sur toute exception en mode `-v`.

**Risque accepté.** Capturer largement peut masquer une erreur de programmation.
C'est un compromis délibéré : pour un outil d'audit, un résultat partiel vaut mieux
que pas de résultat.
