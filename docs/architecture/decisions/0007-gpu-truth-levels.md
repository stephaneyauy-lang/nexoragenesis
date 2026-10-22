# ADR 0007 — Niveaux de vérité et labels GPU

- **Statut :** Accepté
- **Date :** 2026-09-02

## Contexte

« Support GPU », « pilote maison » et « kernel GPU » peuvent recouvrir des réalités très différentes : framebuffer firmware, simulation, périphérique virtuel, appel à un pilote officiel ou contrôle physique direct. Sans vocabulaire normatif, une démo fonctionnelle sur RTX pourrait être présentée à tort comme une pile souveraine.

Un **pilote GPU** est le composant Nova Host qui contrôle le périphérique ou l'interface virtuelle côté CPU : découverte, BAR/MMIO, mémoire, DMA, queues, synchronisation, interruptions, reset, watchdog et affichage. Un **kernel GPU** est un programme Nova Device exécuté par les unités de calcul du device ou par Nova Sim; ce n'est ni le noyau Genesis, ni le pilote hôte, ni le firmware du GPU.

## Décision

Chaque preuve et chaque interface GPU affiche exactement son niveau :

| Niveau | Nom | Réalité autorisée | Revendication interdite |
|---:|---|---|---|
| 1 | GOP | framebuffer fourni par le firmware | pilote accéléré Genesis |
| 2 | Nova Sim | simulateur déterministe sous contrôle Genesis | exécution sur GPU physique |
| 3 | Nova VirtIO 2D | pilote Nova Host d'un GPU virtuel pour affichage 2D | compute GPU natif |
| 4 | Nova Hosted | NVO ou SPIR-V remis au pilote officiel de l'OS hôte | pile GPU souveraine |
| 5 | Nova Bridge | Genesis appelle un service hôte par transport paravirtualisé | pilote physique interne à Genesis |
| 6 | Nova Native | pilote physique expérimental sur carte secondaire documentée et sacrifiable | support de la RTX principale |
| 7 | RTX 5070 native | recherche future indéterminée | promesse produit ou jalon du chemin critique |

Les labels normatifs sont :

- **souverain** : le producteur, le format, l'exécution de référence et le composant revendiqué sont contrôlés par Genesis; toute dépendance firmware constructeur restante est nommée séparément;
- **hébergé** : le code ou module Genesis est remis à un OS, runtime, JIT ou pilote externe qui réalise une partie indispensable de l'exécution;
- **paravirtualisé** : Genesis communique avec un périphérique ou service hôte par une interface virtuelle explicite; la couche hôte demeure externe;
- **constructeur** : firmware, pilote, JIT ou blob fourni, signé ou contrôlé par le fabricant du matériel.

Ces labels sont cumulatifs si nécessaire. Par exemple, Nova Hosted sur RTX porte au minimum `hébergé` et `constructeur`; Nova Bridge porte `paravirtualisé` et annonce le pilote constructeur situé côté hôte. Aucun résultat hébergé ou paravirtualisé ne peut être résumé par « pilote RTX maison ».

Le rail Hosted/Bridge est optionnel et non souverain. Tout accès MMIO/DMA physique est interdit sur la carte principale sans autorisation explicite, IOMMU, reset, watchdog et banc dédié. Nova Native cible d'abord une carte secondaire remplaçable et documentée.

## Conséquences

- Les démonstrations peuvent progresser sans attendre un pilote physique, tout en restant honnêtes sur leurs dépendances.
- Les rapports, logs, UI et benchmarks doivent conserver le label de vérité jusque dans leur résumé.
- Les résultats de Nova Sim servent de référence différentielle; Hosted mesure le langage sur le matériel mais pas la souveraineté de la pile.
- Le support physique requiert une stratégie de récupération et un matériel sacrifiable.

## Non-objectifs

- Promettre un pilote RTX 5070 natif ou totalement maison.
- Appeler GOP un pilote accéléré, VirtIO 2D du compute natif, ou SPIR-V une exécution souveraine.
- Masquer le firmware GSP, le pilote officiel, son JIT ou les composants userspace constructeur.
- Autoriser PCI passthrough, MMIO ou DMA expérimental sur le matériel principal par défaut.

## Preuves et gates

- Toute preuve GPU indique niveau, labels, producteur du module, device, pilote, firmware et environnement d'exécution.
- Gate V0 : Nova Sim réussit 10 000 comparaisons différentielles déterministes, incluant bornes et divergence.
- Gate V1 : Nova VirtIO 2D affiche 1 000 frames à CRC stable et récupère des réponses invalides; la preuve reste étiquetée `paravirtualisé`.
- Gate V2 : Nova Hosted obtient des résultats dans la tolérance face à la référence, avec canaris OOB et benchmark reproductible; la preuve reste étiquetée `hébergé` et `constructeur`.
- Nova Native exige séparément une carte secondaire, IOMMU, reset, watchdog et une progression PCI/BAR sans DMA puis buffers canaris; aucun test physique automatique n'est permis sur la machine principale.

