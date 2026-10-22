# ADR 0013 — Image unique, initialisation sélective des pilotes

- **Statut :** Proposé — en attente de la décision de l'utilisateur
- **Date :** 2026-10-04
- **Dépend de :** ADR 0004 (famille de langages), ADR 0005 (racine de confiance), ADR 0007 (niveaux de vérité GPU)

## Contexte

L'utilisateur veut que le noyau et tous ses pilotes forment **une seule image**,
pour n'avoir qu'un objet à démarrer et démarrer plus vite.

Deux faits encadrent l'idée :

- **Ce qui coûte au démarrage n'est généralement pas le nombre de fichiers.** Dans les
  systèmes existants, l'essentiel du temps part dans la détection et l'initialisation
  des périphériques, et dans les attentes et délais qui les accompagnent. C'est une
  connaissance générale, **pas une mesure faite dans cet arbre** : la promesse « plus
  rapide » ne sera retenue qu'une fois mesurée (voir les preuves ci-dessous).
- **Nexora a un atout que les autres systèmes n'ont pas.** Les profils Cnuva et Nova
  Host déclarent leurs effets (`irq`, `mmio`, `dma`, `msr`, `page_table`) et leurs
  capacités (ADR 0004), et NTASM déclare registres écrasés et privilèges. Si tout est
  lié dans une seule image, **tous ces contrats peuvent être vérifiés ensemble, à la
  construction**, et aucun code non vérifié n'arrive plus tard.

## Décision

1. **Une seule image.** Le noyau, les pilotes génériques (Cnuva) et le pilote GPU
   côté hôte (Nova Host) sont liés dans une image noyau unique. Son format n'est pas
   choisi ici ; il est fixé par la chaîne commune.
2. **Chaque pilote déclare, dans son propre source :**
   - les périphériques qu'il gère (identifiants PCI fabricant et modèle, classe PCI,
     ou identifiant ACPI) ;
   - ses dépendances d'initialisation (par exemple : le pilote d'affichage après la
     mémoire et les interruptions) ;
   - ses effets et capacités, déjà exigés par l'ADR 0004 ;
   - sa priorité : **essentiel** (nécessaire avant le shell) ou **différé**.
3. **La construction produit et vérifie :**
   - la table « périphérique → pilote », générée depuis les déclarations, jamais écrite
     à la main ;
   - le graphe d'initialisation, refusé s'il contient un cycle ;
   - la vérification croisée des contrats sur l'image entière : un pilote qui utilise
     un effet ou une capacité qu'il ne déclare pas est refusé.
4. **Au démarrage :**
   - le noyau énumère le matériel **une seule fois** (PCI, ACPI) ;
   - il n'initialise **que** les pilotes dont un périphérique est présent ;
   - il les initialise en parallèle quand le graphe le permet ;
   - les pilotes différés démarrent après l'affichage du shell ;
   - le code des pilotes sans périphérique est libéré, ou jamais placé en mémoire.
5. **Pas de chargement de module à l'exécution** dans cette version. Mettre à jour un
   pilote, c'est reconstruire l'image, de façon déterministe.
6. **Une seule empreinte.** L'image entière porte une empreinte inscrite dans le
   registre auditable qui part de `seed0.efi` (ADR 0005). Un gestionnaire de démarrage
   Genesis n'a qu'un objet à charger et une empreinte à vérifier.

## Conséquences

| Gain attendu | Coût ou risque |
|---|---|
| Aucun chargement de module ni édition de liens au démarrage | L'image grossit avec les pilotes de tous les matériels pris en charge |
| Tous les contrats de tous les pilotes vérifiés en une fois | Une erreur de pilote peut faire tomber tout le noyau si le langage ne l'empêche pas |
| Une seule empreinte à auditer depuis `seed0.efi` | Mettre à jour un pilote oblige à reconstruire et redémarrer |
| Seuls les pilotes utiles sont initialisés, en parallèle | La table et le graphe deviennent des artefacts à tester comme du code |
| Démarrage reproductible à l'octet près | Le parallélisme d'initialisation demande un ordonnancement déterministe |

## Non-objectifs

- Charger des modules à l'exécution (hors de cette version).
- Revendiquer un gain de vitesse sans mesure avant/après.
- Initialiser un pilote physique sur la carte graphique principale : l'ADR 0007
  s'applique sans changement (QEMU d'abord, matériel sacrifiable ensuite).
- Remplacer le gestionnaire de démarrage : cet ADR ne décrit que l'image qu'il charge.

## Preuves et gates

Aucune de ces portes n'existe encore ; elles définissent ce que « livré » voudra dire.

- **G1 — table générée :** la table « périphérique → pilote » est identique, octet pour
  octet, à celle reconstruite depuis les déclarations ; un pilote sans déclaration de
  périphérique est refusé à la construction.
- **G2 — graphe :** un graphe d'initialisation contenant un cycle est refusé avec un
  diagnostic qui nomme le cycle.
- **G3 — contrats croisés :** un pilote qui utilise un effet non déclaré est refusé ;
  le même pilote, déclaration ajoutée, est accepté (paire négative et positive).
- **G4 — sélection sous QEMU :** avec un périphérique retiré de la machine virtuelle,
  le journal série prouve que son pilote n'est pas initialisé ; remis, il l'est.
- **G5 — reproductibilité :** deux constructions propres donnent la même empreinte
  d'image.
- **G6 — vitesse, mesurée :** temps jusqu'au shell sous QEMU, image unique contre
  référence, mesuré et publié. La promesse « plus rapide » de cet ADR n'est retenue
  que si G6 la montre.

## Ordre

Cet ADR ne passe pas avant B2.1. Il devient constructible avec Cnuva (gate B3) et le
compilateur commun (gate B4), et son premier essai porte sur les périphériques
virtuels de QEMU.
