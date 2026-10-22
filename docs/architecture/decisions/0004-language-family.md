# ADR 0004 — Une famille de langages, quatre profils, une chaîne commune

- **Statut :** Accepté
- **Date :** 2026-09-02

## Contexte

NX, Cnuva, Nova et NTASM servent des domaines différents mais partagent des besoins fondamentaux : lexèmes, modules, diagnostics, types primitifs, effets, capacités, représentations intermédiaires et encodage machine. Quatre compilateurs indépendants multiplieraient les divergences et rendraient la pureté du build beaucoup plus difficile à prouver.

Un **pilote** est le composant hôte qui découvre, configure et contrôle un périphérique, gère ses ressources, files, interruptions, erreurs et reset. Un pilote peut être Cnuva pour une plateforme générique ou Nova Host pour le domaine GPU; le fait qu'il tourne sur le CPU ne change pas son domaine.

Un **kernel GPU** est un programme Nova Device destiné à être exécuté par les unités de calcul d'un GPU ou par Nova Sim. Ce n'est ni le noyau de l'OS, ni le pilote hôte, ni un firmware constructeur.

## Décision

Les quatre profils forment une seule famille et convergent vers une chaîne commune :

| Profil | Responsabilité | Autorisations structurantes | Sorties principales |
|---|---|---|---|
| NX | Orbit, applications, services, outils et NexShell | aucune opération privilégiée implicite | NXO, NXK, JIT natif |
| Cnuva | boot, noyau, CPU, mémoire, plateforme et pilotes génériques | effets explicites `irq`, `mmio`, `dma`, `msr`, `page_table` | NXO, NXK, PE32+ |
| Nova Host | contrôle hôte du domaine GPU | capacité GPU précise, sans périphérique arbitraire | NXO, NXK |
| Nova Device | kernels GPU | espaces et opérations device, sans pointeur hôte ni mémoire physique CPU | NVO |
| NTASM | bootstrap et niveau machine typé | ABI, registres, clobbers, privilèges et postconditions déclarés | NXO, PE32+ |

Le frontend est paramétré par profil et produit une HIR typée commune. Les chemins System IR, Machine IR, Device IR et Micro IR restent spécialisés, mais réutilisent le cœur, les diagnostics et les encodeurs appropriés. Aucun profil ne reçoit un backend CPU dupliqué.

Les appels entre profils traversent une ABI versionnée. Aucun cast libre ni renommage de profil ne peut contourner un effet, une capacité ou un espace mémoire.

NexShell (`nsh`) est le mode interactif et d'automatisation de NX, pas un cinquième langage. Les scripts sauvegardés restent des sources `.nx` ordinaires.

## Conséquences

- Le compilateur commun coûte davantage à concevoir au départ, mais réduit les encodeurs et règles dupliqués.
- Les frontières de privilèges sont vérifiables dans les types, effets et capacités.
- Nova Host peut réutiliser le backend x86_64 sans devenir Cnuva.
- Une modification du cœur exige une matrice de tests croisés pour les quatre profils.

## Non-objectifs

- Rendre les quatre syntaxes identiques ou interchangeables.
- Autoriser NX à accéder directement au matériel.
- Présenter Nova Device comme un noyau d'OS ou Nova Host comme un kernel GPU.
- Fournir quatre toolchains autonomes ou quatre encodeurs x86 concurrents.
- Faire de NexShell un langage de script distinct.

## Preuves et gates

- Gate B2 : NTASM atteint son point fixe bit-identique et fournit l'encodeur initial.
- Livraison B2.1 : NTASM v0 complet selon ADR 0011 et
  `docs/status/ntasm-completion.md`; ce résultat précède la livraison des autres
  frontends et de l'OS.
- Gate B3 : Cnuva-S0 accepte et refuse un corpus borné avec diagnostics stables.
- Gate B4 : le compilateur commun est auto-hébergé, déterministe et produit les outils maison.
- Gate dialectes : matrice positive/négative prouvant les refus MMIO/DMA/MSR en NX, les capacités Cnuva/Nova et l'isolement Nova Device.
- Gate V0 : les kernels Nova Device produisent les mêmes résultats dans le modèle CPU et Nova Sim sur 10 000 cas déterministes.
