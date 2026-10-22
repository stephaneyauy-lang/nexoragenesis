# ADR 0008 — Nexora Genesis comme base commune des futurs OS

- **Statut :** Accepté
- **Date :** 2026-09-02

## Contexte

Nexora Genesis doit devenir la base technique de tous les prochains systèmes
d'exploitation de l'utilisateur. Sans règle d'architecture commune, chaque
nouvel OS risquerait de recopier le noyau, la toolchain, les ABI ou les formats,
puis de diverger silencieusement. Cette duplication multiplierait les correctifs
de sécurité, les migrations, les tests de compatibilité et les chaînes de
bootstrap sans créer de valeur produit distincte.

Les futurs OS peuvent avoir des objectifs, interfaces, politiques, publics et
cycles de livraison très différents. Cette diversité doit vivre au-dessus d'un
socle Genesis explicite et versionné, sans transformer chaque produit en fork
indépendant par défaut.

## Décision

Tous les futurs OS sont construits comme des **profils**, **distributions** ou
**produits** au-dessus de Nexora Genesis.

L'architecture sépare trois niveaux :

1. **Genesis Core** : noyau et composants fondamentaux partagés, toolchain NX /
   Cnuva / Nova / NTASM, ABI, formats binaires, contrats de boot, sécurité et
   compatibilité. Chaque interface consommable est versionnée.
2. **Platform packages** : pilotes, services, runtimes, bibliothèques, politiques
   et capacités optionnelles assemblables au-dessus du core par dépendances
   déclarées.
3. **Product profiles** : sélection et configuration des packages, identité,
   UX, applications, réglages, politiques de mise à jour et critères produit
   propres à chaque OS.

Un nouveau produit référence les versions du core, de la toolchain, des ABI et
des formats qu'il consomme. Il ne copie pas ces composants dans une arborescence
indépendante et ne maintient pas une variante privée non déclarée. Les
évolutions réutilisables remontent dans Genesis Core ou dans un platform package
partagé ; les différences produit restent dans le profil.

Un fork du core, de la toolchain, d'une ABI ou d'un format est une exception. Il
exige avant sa création une décision explicite et documentée indiquant le motif,
le propriétaire, la portée, les incompatibilités, la stratégie de synchronisation
ou de séparation définitive, les tests et le coût de maintenance accepté. Sans
cette décision, la copie et la divergence sont interdites.

## Conséquences

- Les correctifs du core, de la toolchain et des formats peuvent bénéficier à
  tous les produits sans réimplémentation parallèle.
- La compatibilité devient un contrat versionné et testable, plutôt qu'une
  ressemblance supposée entre copies.
- Un produit peut évoluer rapidement par son profil et ses packages sans
  affaiblir les invariants du socle.
- Les dépôts, builds et manifests doivent rendre visibles la version du core,
  les packages sélectionnés et le profil produit.
- Une modification incompatible du socle demande une nouvelle version de
  contrat, une matrice de migration et des tests pour les profils concernés.
- La gouvernance du core devient plus exigeante : une commodité locale ne doit
  pas imposer une dépendance ou une politique à tous les produits.
- Les exceptions coûtent volontairement cher à autoriser et à maintenir ; ce
  coût empêche la divergence accidentelle sans interdire une rupture réellement
  nécessaire.

## Non-objectifs

- Imposer la même interface, la même marque, les mêmes applications ou le même
  public à tous les futurs OS.
- Transformer chaque idée produit en fonctionnalité obligatoire de Genesis
  Core.
- Garantir qu'un profil reste compatible avec toutes les versions passées ou
  futures sans migration explicite.
- Présenter une simple copie de fichiers comme une distribution supportée.
- Interdire toute expérimentation locale ; une expérience peut rester jetable,
  mais elle ne devient pas un OS produit ni un fork durable sans décision
  explicite.
- Fusionner artificiellement des exigences incompatibles dans le core pour
  éviter de documenter une exception légitime.

## Preuves et gates

- **Gate de structure :** tout nouveau projet d'OS identifie son profil produit,
  ses platform packages et les versions exactes de Genesis Core, de la
  toolchain, des ABI et des formats consommés. Aucun composant partagé copié et
  modifié n'est présent sans exception approuvée.
- **Gate de build :** le produit est construit depuis les dépendances déclarées
  et un profil reproductible ; le manifeste de build consigne versions, hashes
  et options activées.
- **Gate de compatibilité :** les tests de conformance du core et des ABI
  versionnées passent avant les tests propres au produit. Une incompatibilité
  attendue pointe vers une migration ou une exception explicite.
- **Gate de changement du core :** toute rupture de contrat inventorie les
  profils consommateurs, fournit une version nouvelle et prouve la migration
  des profils maintenus avant promotion.
- **Gate d'exception :** aucun fork durable n'est créé avant un ADR dédié avec
  justification, limites, propriétaire, stratégie de synchronisation ou de
  séparation, budget de maintenance et critères de sortie.
- Les gates techniques déjà définies pour Genesis restent les autorités du
  socle. Un profil produit ne peut pas renommer un tracer partiel ou une preuve
  locale en gate core GREEN.

Cette ADR constitue une décision d'architecture et de gouvernance. Sa première
preuve opérationnelle sera le premier futur OS décrit et construit comme profil
au-dessus des contrats Genesis versionnés ; aucune preuve d'un tel produit
n'est revendiquée ici.
