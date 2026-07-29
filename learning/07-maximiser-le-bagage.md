# 7. Maximiser le bagage

Construire cspm-lite et **capitaliser** dessus sont deux choses différentes. Beaucoup
d'étudiants finissent un projet solide et en ressortent avec trois lignes de CV
qu'ils ne savent pas défendre. Cette partie traite uniquement de la conversion :
comment transformer 80 heures de travail en compétence durable, démontrable et
transférable.

## 7.1 Les quatre leviers

Le bagage réel ne vient pas du volume de code écrit. Il vient de quatre choses :

**Profondeur.** Un check S3 écrit en 10 minutes t'apprend une syntaxe boto3. Le même
check, avec 30 minutes de plus pour comprendre les quatre mécanismes de publication
d'un bucket et écrire la commande de remédiation, t'apprend la sécurité S3 pour dix
ans. Le rendement de la profondeur est très supérieur à celui de la quantité.

**Contraste attaque/défense.** Tu n'écris un bon détecteur que si tu sais ce que
l'attaquant en fait. Chaque contrôle que tu implémentes doit être accompagné d'un
scénario d'exploitation que tu as compris — idéalement exécuté toi-même sur ton labo.

**Restitution.** Ce que tu n'as jamais expliqué à voix haute, tu ne le possèdes pas.
La restitution (journal, article, présentation, revue de code) est ce qui transforme
une information consultée en connaissance mobilisable sous pression, c'est-à-dire en
entretien.

**Preuve.** Une compétence non prouvable ne se vend pas. Chaque compétence de ton CV
doit être adossée à un lien (commit, PR, rapport, article) et à une anecdote de trois
phrases. C'est l'objet du carnet de preuves (section 7.7).

## 7.2 L'extra mile, phase par phase

Pour chaque phase, voici le petit surinvestissement dont le rendement est
disproportionné. Ce sont environ 25 heures supplémentaires au total, réparties sur
tout le projet, qui changent la nature de ce que tu en retires.

| Phase | Investissement supplémentaire | Ce que ça débloque |
|---|---|---|
| 0 | +2 h — écrire un **ADR** (Architecture Decision Record) justifiant tes choix : layout `src/`, pydantic ou dataclasses, ruff plutôt que flake8+black | Tu sais défendre chaque choix technique au lieu de dire « c'est ce que le tutoriel faisait » |
| 1 | +2 h — ajouter des **tests de propriété** avec `hypothesis` sur la sérialisation du modèle | Le property-based testing est rare chez un junior et impressionne en entretien technique |
| 2 | +3 h — construire la **policy IAM minimale exacte** de ton scanner, empiriquement : tourne avec une policy vide, note chaque `AccessDenied`, ajoute l'action, recommence | Tu pratiques le moindre privilège pour de vrai. C'est exactement la méthode des équipes sécurité en entreprise |
| 3 | +30 min par check — pour chaque contrôle, écrire la **commande AWS CLI de vérification manuelle** et la **commande de remédiation** | Tu produis un runbook opérationnel. Tu passes de « je détecte » à « je sais corriger », ce qui est le vrai métier |
| 4 | +2 h — pousser réellement tes findings dans un **AWS Security Hub** (le premier mois est gratuit) et les voir apparaître | Boucle fermée avec un service AWS réel. Très peu d'étudiants sont allés jusque-là |
| 5 | +2 h — faire tester ta CLI par un camarade **sans aucune explication**, noter chaque friction, corriger | Tu apprends l'UX développeur et la valeur du retour utilisateur brut |
| 6 | +3 h — écrire et exécuter un **scénario d'attaque complet** sur ton labo (clé exposée → `AssumeRole` → exfiltration S3), puis vérifier que ton scanner l'aurait empêché | C'est ton anecdote d'entretien la plus forte. Tu as attaqué et défendu la même infrastructure |
| 7 | +2 h — **mutation testing** avec `mutmut` : il modifie ton code et vérifie que tes tests échouent | Tu découvres que 80 % de couverture ne veut pas dire 80 % de tests utiles. Concept de niveau senior |
| 8 | +3 h — **signer tes images** avec `cosign` et générer une **provenance SLSA** | Sécurité de la supply chain au niveau de l'état de l'art 2024-2026, sujet très demandé |
| 9 | +3 h — définir des **SLO de sécurité** (« 100 % des findings CRITICAL corrigés sous 7 jours ») et les mesurer | Tu passes du technique au pilotage. C'est le langage des responsables sécurité |
| 10 | +4 h — enregistrer une **présentation de 10 minutes** de ton projet, la réécouter, la refaire | La compétence la plus sous-estimée. Tu répètes ton entretien avant de le passer |

## 7.3 Les trois pistes parallèles

À mener **pendant** le projet, pas après. Elles coûtent 2 à 3 heures par semaine et
doublent le rendement du temps passé à coder.

### Piste 1 — Offensive (2 h toutes les deux semaines)

L'ordre compte :

1. **flaws.cloud** — 6 niveaux, gratuit, aucune installation. À faire **avant** la
   phase 3. Tu y découvres un bucket public, un rôle sur-privilégié, l'IMDS. Tes
   checks auront un sens après.
2. **flaws2.cloud** — deux pistes, attaquant et défenseur. Fais les deux.
3. **CloudGoat** (Rhino Security Labs) — scénarios déployés en Terraform dans ton
   propre compte. Fais au minimum `iam_privesc_by_rollback` et `ec2_ssrf`. C'est là
   que tu comprends physiquement l'escalade de privilèges IAM.
4. **Pacu** — le framework d'exploitation AWS. Lance-le contre ton propre labo
   Terraform. Regarder un outil offensif énumérer tes ressources change ta façon
   d'écrire des détections.

Après chaque scénario, une entrée de journal en trois lignes : ce que l'attaquant a
fait, quel check de cspm-lite l'aurait bloqué, et si ce check n'existe pas, crée
l'issue.

### Piste 2 — Lecture de code réel (1 h par semaine)

Lire du code d'outil professionnel vaut dix tutoriels. Programme :

- **Semaines 1-4** — Prowler, dossier `prowler/providers/aws/services/s3/`. Compare
  leur structure de check à la tienne. Note trois différences et demande-toi
  pourquoi.
- **Semaines 5-6** — Prowler, le moteur : `prowler/lib/check/check.py`. Comment ils
  chargent les checks dynamiquement, comment ils gèrent les erreurs.
- **Semaines 7-8** — Scout Suite, les rulesets JSON. Une approche déclarative plutôt
  qu'impérative : quels compromis ?
- **Semaines 9-10** — Cartography (Lyft) : le modèle de graphe Neo4j de
  l'infrastructure. Prépare l'extension attack-path.
- **Semaines 11-12** — Checkov : l'analyse statique de Terraform.

Note dans ton journal chaque idée volée et chaque idée rejetée avec sa raison. Ce
carnet devient une matière d'entretien exceptionnelle : « j'ai lu comment Prowler
gère X, j'ai fait différemment parce que… ».

### Piste 3 — Restitution (30 min par phase terminée)

Un post court à chaque phase finie. Douze posts sur douze semaines, c'est une
présence professionnelle construite sans effort concentré.

Format qui fonctionne : **un problème concret, une explication, une leçon**. Par
exemple : « Pourquoi `AuthenticatedUsers` dans une ACL S3 ne veut pas dire ce que
vous croyez » — 300 mots, un exemple, une capture. Ce type de post est lu ; « j'ai
terminé la phase 4 de mon projet » ne l'est pas.

Le dernier post de la série est l'article long de la phase 10.

## 7.4 Contribuer à un vrai projet open source

C'est le levier de bagage le plus fort de toute cette liste, et le plus négligé.
Faire relire ton code par les mainteneurs d'un outil utilisé par des milliers
d'entreprises vaut plusieurs mois de développement solitaire.

Cible naturelle : **Prowler**. Après ta phase 3, tu connais le domaine assez bien
pour contribuer.

Démarche, dans cet ordre :

1. Trouve un check AWS **manquant** dans Prowler, ou un check dont la logique a un
   angle mort (par exemple un CIDR IPv6 non traité, une région non couverte). Ton
   travail sur cspm-lite te donne exactement cet œil.
2. Ouvre une **issue** décrivant le problème avant d'écrire du code. Attends le
   retour d'un mainteneur. Cette étape évite le travail jeté et t'apprend la
   négociation technique.
3. Soumets une **PR** avec test. Réponds aux commentaires de revue sans te braquer.
4. Alternative si tu es intimidé : commence par la **documentation** ou la traduction.
   Une PR de doc acceptée ouvre la porte, et personne ne te demandera plus tard si
   c'était du code ou de la doc.

Le bagage réel : une revue de code par un professionnel, l'expérience du workflow
open source, et ton nom dans l'historique d'un outil que ton futur employeur utilise
peut-être déjà.

## 7.5 Les quatre extensions multiplicatrices

Après la v1, ces extensions ne sont pas « plus de la même chose » : chacune ouvre un
domaine entier.

### A. Analyse de chemins d'attaque (attack path analysis)

Construis un graphe des relations IAM : qui peut assumer quel rôle, quel rôle accède
à quelle donnée, quelle instance porte quel rôle. Cherche ensuite les chemins entre
une entrée exposée (instance publique, utilisateur sans MFA) et une ressource
sensible.

- Effort : 15-20 h avec `networkx`.
- Bagage : théorie des graphes appliquée, évaluation des policies IAM en profondeur,
  et le concept qui a fait la valorisation de Wiz. C'est le sujet le plus
  intellectuellement dense du domaine.
- Argument d'entretien : « un finding isolé est du bruit ; ce qui compte c'est le
  chemin entre l'extérieur et la donnée ». Cette phrase te distingue immédiatement.

### B. Shift-left : analyse du Terraform avant déploiement

Réutilise tes checks contre les fichiers `.tf` plutôt que contre l'API AWS. Bloque la
PR au lieu de constater la faille en production.

- Effort : 12-15 h (parsing HCL avec `python-hcl2`).
- Bagage : tu couvres alors les deux moitiés du marché — sécurité runtime **et**
  sécurité du code d'infrastructure. Tu comprends pourquoi les deux sont nécessaires
  et non redondantes (le drift, les ressources créées hors IaC).

### C. Detection engineering

Le CSPM est **préventif**. Ajoute le volet **détection** : consomme les événements
CloudTrail et écris des règles qui alertent sur un comportement suspect —
`ConsoleLogin` sans MFA, `CreateAccessKey` sur le root, `DeleteTrail`,
`PutBucketPolicy` rendant un bucket public, énumération massive.

- Effort : 15-20 h.
- Bagage : c'est le métier **blue team / SOC**, un marché entier distinct. Tu
  apprends le format **Sigma**, la notion de faux positif, le tuning des règles. Et
  tu peux enfin dire en entretien que tu comprends la différence entre posture et
  détection.

### D. Multi-cloud ou Kubernetes

Deux directions au choix :

- **Azure ou GCP** : ajouter un second provider. L'intérêt principal est la preuve
  que ton architecture était bonne — si le moteur n'a pas besoin d'être réécrit, ton
  design de la phase 1 tenait. Le marché est massivement multi-cloud.
- **EKS / Kubernetes** : posture des clusters (RBAC trop permissif, conteneurs
  privilégiés, absence de NetworkPolicy). Kubernetes est le sujet de sécurité le plus
  demandé après le cloud lui-même, et le moins bien couvert par les candidats.

Choisis-en **une seule**. Une extension finie vaut mieux que quatre commencées.

## 7.6 Retenir ce que tu apprends

Sans système, tu auras oublié 70 % des phases 1 à 3 au moment des entretiens. Trois
mécanismes suffisent :

**Revue espacée.** Chaque fiche de la partie 4 est relue à J+1, J+7 et J+30 après
sa première lecture. Cinq minutes à chaque fois. Note les dates dans ton journal, ou
mets trois rappels de calendrier. C'est peu coûteux et c'est ce qui fait la
différence entre « j'ai déjà vu ça » et « je sais l'expliquer ».

**Auto-évaluation orale.** Toutes les deux semaines, prends la liste 6.4 et réponds
**à voix haute**, sans notes, chronomètre à 2 minutes. Les questions que tu rates
définissent tes prochaines lectures. Répondre dans sa tête ne compte pas : c'est
précisément l'articulation qui manque en entretien.

**Enseigner.** Explique un concept à un camarade, dans un club, ou en post. La
technique de Feynman est fiable : si tu ne peux pas l'expliquer simplement, tu ne le
sais pas. C'est aussi le meilleur détecteur de compréhension superficielle.

## 7.7 Le carnet de preuves

Crée `learning/preuves.md`. Pour chaque compétence revendiquée, trois éléments :

```markdown
### Sécurité IAM et moindre privilège

**Preuve** : PR #14 — policy IAM minimale du scanner, dérivée empiriquement
(lien vers le commit)

**Anecdote (3 phrases)** :
Mon scanner tournait avec ReadOnlyAccess, ce qui était plus large que nécessaire.
J'ai lancé avec une policy vide et ajouté une par une les 23 actions signalées
par les AccessDenied. Résultat : une policy de 23 actions au lieu des ~2000 de
ReadOnlyAccess, et la certitude que l'outil ne peut rien faire d'autre.

**Question à laquelle ça répond** : « Comment appliques-tu le moindre privilège
concrètement ? »
```

Vise 10 à 12 entrées à la fin du projet. Ce fichier est ce que tu relis la veille
d'un entretien — pas ton code.

Une règle : **ne revendique jamais une compétence sans entrée dans ce carnet.** Le
CV qui promet plus que le carnet ne contient est ce qui fait échouer les entretiens
techniques.

## 7.8 Ce qui détruit le bagage

Les erreurs qui annulent le travail fourni, par ordre de fréquence :

1. **Coller du code sans le comprendre** — qu'il vienne d'un tutoriel, de Stack
   Overflow ou d'une IA. Test simple : peux-tu réécrire cette fonction de mémoire
   demain ? Sinon, tu n'as rien appris, tu as seulement avancé. Utilise l'assistance
   pour *comprendre plus vite*, jamais pour *sauter la compréhension*.
2. **Ne pas finir.** Un projet abandonné en phase 6 vaut moins qu'un projet plus
   modeste terminé, parce qu'il n'a ni rapport présentable, ni article, ni release.
3. **Perfectionner une phase terminée.** Réécrire le collecteur S3 une troisième fois
   pendant que les phases 8, 9 et 10 n'existent pas est la forme la plus courante de
   procrastination technique.
4. **Ne jamais montrer.** Un dépôt privé sans README ne produit aucun bagage social.
   Le projet doit être public, lisible, et lié depuis ton profil.
5. **Confondre activité et progression.** 200 commits de renommage ne valent pas un
   check bien compris. Ton indicateur est la ligne « Appris » de ton journal, pas le
   graphe de contributions.
6. **Oublier `terraform destroy`.** Une facture AWS surprise à 300 € est la
   principale cause d'abandon de ce type de projet. Budget avec alerte, et destruction
   systématique en fin de session.

## 7.9 Après cspm-lite : les 12 mois suivants

| Période | Objectif | Pourquoi |
|---|---|---|
| Mois 1-3 | Finir cspm-lite jusqu'à la release v1.0.0, article publié | Le socle et la preuve |
| Mois 4 | **AWS Solutions Architect – Associate** | Passe les filtres RH ; le projet couvre déjà la moitié du programme |
| Mois 4-6 | **Une** extension de la section 7.5 (recommandé : attack path ou detection engineering) | La profondeur qui te distingue des autres candidats |
| Mois 5-7 | Première contribution acceptée sur Prowler ou équivalent | Validation externe par des professionnels |
| Mois 7-9 | **AWS Security – Specialty** | La certification la plus alignée avec ton profil |
| Mois 8-12 | Candidatures stage/alternance en Cloud Security, DevSecOps ou SOC | Tu arrives avec un projet, une extension, une contribution et deux certifications |

Ce parcours te place, à la fin, devant la quasi-totalité des candidats juniors sur ce
créneau — non pas parce que tu auras plus travaillé, mais parce que tu auras
travaillé de façon cumulative : chaque élément renforce les autres.

## 7.10 Checklist finale : ai-je vraiment capitalisé ?

À la fin du projet, tu devrais pouvoir cocher :

- [ ] Le dépôt est **public**, avec un README qu'un inconnu comprend en 5 minutes
- [ ] Une **release v1.0.0** taguée
- [ ] Un **rapport HTML d'exemple** consultable sans installer quoi que ce soit
- [ ] Un **article publié** expliquant un contrôle en profondeur
- [ ] Un **carnet de preuves** de 10 entrées minimum
- [ ] Une **présentation de 10 minutes** que tu as enregistrée et réécoutée
- [ ] Les **19 questions de la section 6.4** répondues à l'oral, sans notes
- [ ] Au moins **un scénario d'attaque** exécuté par toi sur ton propre labo
- [ ] Au moins **une contribution** à un projet open source, même documentaire
- [ ] Une **extension** de la section 7.5 commencée ou finie
- [ ] Un **journal** de 30+ entrées, relu au moins une fois
- [ ] La **facture AWS** du projet inférieure à 20 €

Si tu coches dix de ces douze cases, tu ne sors pas de ce projet avec une ligne de
CV. Tu en sors avec un domaine.
