# ADR 0001 — Développement entièrement neuf

- **Statut :** Accepté
- **Date :** 2026-09-02

## Contexte

Nexora Genesis vise un ordinateur personnel programmable dont la chaîne de démarrage, les langages, le noyau et l'atelier sont compréhensibles de bout en bout. Des projets antérieurs et des systèmes existants peuvent fournir des leçons d'architecture ou des critères de test, mais leur code, leurs assets et leur identité créeraient une provenance ambiguë et empêcheraient de démontrer que Genesis est réellement neuf.

## Décision

Le projet est développé **greenfield** dans `C:\NexoraGenesis`.

- Aucun code, fragment, table générée, binaire, asset, texte d'interface ou fichier de build n'est importé depuis NexoraOS, TempleOS, AstraOS ou un autre système.
- Une idée générale, une norme publique ou une expérience acquise peut guider une décision si elle est reformulée et réimplémentée de manière originale.
- Toute donnée normative externe indispensable, telle qu'une constante d'ISA ou une structure UEFI, doit être accompagnée de sa provenance documentaire et transcrite dans un format maison; elle ne devient jamais du code exécutable copié.
- Toute contribution doit être explicable à partir des ADR, spécifications et preuves propres à Genesis.
- L'absence de dépôt Git est conservée tant que l'utilisateur n'autorise pas explicitement son initialisation.

## Conséquences

- La vitesse initiale est volontairement inférieure à celle d'un port ou d'un fork.
- Les composants familiers doivent être respécifiés, testés et écrits à neuf.
- La provenance est plus facile à auditer et les promesses d'originalité restent défendables.
- L'expérience antérieure reste utile pour éviter des erreurs, mais ne constitue jamais une source de fichiers.

## Non-objectifs

- Réinventer les normes matérielles publiques ou prétendre que l'ISA x86_64, UEFI et OVMF sont des créations Genesis.
- Obtenir une compatibilité source ou binaire avec NexoraOS, TempleOS ou un autre OS.
- Reproduire l'apparence, les noms, les textes, les symboles, la religion ou la personnalité visuelle de TempleOS.
- Accélérer le projet en important temporairement du code qui serait réécrit plus tard.

## Preuves et gates

- Avant tout premier octet exécutable, revue des sept ADR et inventaire de l'arbre ne montrant que le socle documentaire attendu.
- Pour chaque futur artefact, manifeste de provenance indiquant son producteur et ses entrées.
- Toute ressemblance substantielle détectée déclenche une revue et bloque le gate concerné jusqu'à réécriture originale.
- Gate B5 : la trace de build doit démontrer qu'aucun producteur ni fichier source étranger n'a participé.

