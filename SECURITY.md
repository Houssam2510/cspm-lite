# Politique de sécurité

## Signaler une vulnérabilité

N'ouvrez **pas** d'issue publique pour une vulnérabilité.

Utilisez l'onglet *Security → Report a vulnerability* du dépôt (GitHub Private
Vulnerability Reporting). Réponse sous 7 jours, correctif visé sous 30 jours pour
les vulnérabilités confirmées de sévérité haute.

Merci d'inclure : version affectée, étapes de reproduction, impact estimé.

## Périmètre

Sont dans le périmètre :

- exécution de code arbitraire via un fichier de configuration ou un inventaire ;
- injection dans les rapports générés (HTML, Markdown, ASFF) ;
- fuite de credentials dans les rapports, les logs ou les messages d'erreur ;
- élévation de privilèges dans l'image Docker.

Sont hors périmètre : les faux positifs et faux négatifs des contrôles (ouvrez une
issue normale), et les vulnérabilités des dépendances déjà signalées par Dependabot.

## Modèle de sécurité de l'outil

**Lecture seule.** `cspm-lite` n'appelle aucune API de modification. La policy
managée `SecurityAudit` suffit. Ne lui accordez jamais `AdministratorAccess` : un
outil d'audit sur-privilégié devient lui-même le risque principal.

**Aucune donnée ne sort de votre machine.** Aucune télémétrie, aucun appel réseau
autre que vers les endpoints AWS. Les rapports HTML sont autonomes : ils
n'effectuent aucune requête vers un CDN ou un tiers, précisément pour que le nom de
vos ressources n'apparaisse pas dans les logs de quelqu'un d'autre.

**Contenu des rapports.** Un rapport contient des identifiants de ressources, des
ARN et votre identifiant de compte. Traitez-le comme un document interne : ne le
publiez pas tel quel, ne le joignez pas à une candidature.

**Dépendances.** Une seule dépendance runtime (`boto3`), par choix — voir
[ADR-002](docs/adr/002-une-seule-dependance.md). L'image Docker est scannée par
Trivy à chaque build et un SBOM est publié.

## Usage autorisé

Cet outil est destiné à l'audit de comptes dont vous êtes propriétaire ou pour
lesquels vous disposez d'une **autorisation écrite**. Scanner l'infrastructure d'un
tiers sans autorisation est illégal dans la plupart des juridictions.

Le dossier `lab/` provisionne délibérément des ressources non sécurisées. Utilisez un
compte dédié, sans donnée réelle, avec un budget et une alerte, et détruisez tout
après usage.
