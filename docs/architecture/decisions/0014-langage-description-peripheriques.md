# ADR 0014 — Langage de description de périphériques

- **Statut :** Accepté sur décision explicite de l'utilisateur, **option B retenue**
  (« option B pour l'ADR 0014 », 2026-10-04)
- **Date :** 2026-10-04
- **Touche :** ADR 0004 (le frontend commun gagne les blocs `device`), ADR 0007
  (niveaux de vérité GPU), ADR 0013 (image unique) ; ne modifie pas l'ADR 0002 (aucune
  nouvelle extension de source)

## Contexte

L'utilisateur veut des langages spécialisés pour les pilotes et pour le pilote GPU.
L'ADR 0004 couvre déjà la **programmation** des pilotes : Cnuva pour les pilotes
génériques, Nova Host pour le contrôle du GPU, Nova Device pour les kernels GPU. Un
langage de plus pour programmer des pilotes ferait doublon avec eux.

Ce qui manque, c'est la **description** du matériel. Aujourd'hui, un registre, un bit
ou un offset est un nombre écrit à la main dans le code, et ces nombres sont une source
d'erreurs mesurée dans cet arbre et dans le clone de la toolchain :

- le noyau du cube (`os/cube/cube.ntasm` du clone, 3 octobre 2026) contient **235**
  accès `[r15+nombre]` écrits à la main, et son pilote PS/2 manipule les bits de statut
  du contrôleur (`0x01`, `0x02`, `0x20`) et ses commandes (`0xa8`, `0xd4`) en clair ;
- un des dix défauts trouvés dans le runtime Nova de Nexora OS était un offset oublié
  (`NRT_SCR` absent dans `cb_literal`) qui faisait **écrire des drapeaux à une adresse
  arbitraire** ; le rapport et le correctif sont dans `out/nexoros-test-20261003/`.

Des systèmes de recherche ont déjà séparé description et programmation, avec des
résultats techniques solides : Devil (langage de description de matériel pour les
pilotes) et Mackerel dans Barrelfish (description des registres de périphériques).

## Décision

Créer un langage **déclaratif** de description de périphériques. Il **décrit** le
matériel ; il ne le **programme** pas.

### Ce qu'il décrit

- l'identité du périphérique : identifiants PCI ou ACPI, ce qui alimente aussi la table
  de l'ADR 0013 ;
- ses régions : ports d'entrée-sortie, zones MMIO et BAR ;
- ses registres : position, largeur, accès (lecture seule, écriture seule,
  lecture-écriture, effacement par écriture d'un 1) ;
- les champs de bits de chaque registre : position, largeur, valeurs nommées ;
- la disposition des descripteurs DMA et des anneaux de commandes ;
- ses interruptions.

### Ce qu'il produit

À partir d'une description, la chaîne commune génère pour Cnuva, Nova Host et NTASM :

- des constantes et des accesseurs **typés** : lire le champ `from_mouse` du registre
  `status`, au lieu de tester `0x20` ;
- l'**effet** et la **capacité** de chaque accès, automatiquement (`io_port`, `mmio`,
  `dma`, capacité du périphérique décrit), pour que les vérifications de l'ADR 0004
  s'appliquent sans rien écrire à la main ;
- des refus à la compilation : écrire un registre en lecture seule, lire un registre en
  écriture seule, un champ qui dépasse son registre, deux champs qui se chevauchent.

### Esquisse de syntaxe (non normative)

Uniquement pour fixer les idées ; la grammaire réelle reste à spécifier.

```
device i8042 {
    port data    0x60 : u8 read_write
    port status  0x64 : u8 read_only {
        output_full : bit 0
        input_full  : bit 1
        from_mouse  : bit 5
    }
    port command 0x64 : u8 write_only {
        enable_aux  = 0xa8
        to_mouse    = 0xd4
    }
}
```

### Forme retenue : option B, un profil déclaratif dans Cnuva et Nova Host

Les descriptions s'écrivent dans des blocs `device`, à l'intérieur des sources
`.cnuva` et `.nova` (côté Nova Host). Il n'y a **pas de nouvelle extension de
fichier** : les ADR 0002 et 0004 et la liste des langages de `AGENTS.md` restent
inchangés. La grammaire des blocs `device` s'ajoute au frontend commun, passe par la
chaîne commune (NTIR) et ne crée pas de toolchain autonome, conformément à l'ADR 0004.

| Option | Forme | Décision |
|---|---|---|
| A | Un langage à part, avec sa propre extension de fichier | Écartée : elle aurait demandé d'amender les ADR 0002 et 0004 et d'ajouter une cinquième extension |
| B | Un profil déclaratif à l'intérieur de Cnuva et Nova Host (blocs `device`) | **Retenue** le 2026-10-04 |

## Conséquences

- Les nombres magiques sortent du code des pilotes : un registre, un bit et un offset
  ont un nom vérifié.
- Les effets et capacités des accès matériels sont dérivés, donc ne peuvent plus être
  oubliés.
- La table « périphérique → pilote » de l'ADR 0013 peut être générée depuis les
  descriptions.
- Le langage ajoute une grammaire, des diagnostics et une matrice de tests à maintenir.
- Une description fausse produit des accesseurs faux mais cohérents : la description
  devient une pièce à vérifier contre la documentation du matériel et sous QEMU.

## Non-objectifs

- Un langage de programmation : pas de boucles, pas de conditions, pas de séquences.
  Les séquences d'initialisation et de reset restent écrites en Cnuva, Nova Host ou
  NTASM.
- Remplacer Cnuva ou Nova Host.
- Recopier des en-têtes de registres d'un autre système d'exploitation : les
  descriptions sont écrites depuis la documentation publique du matériel, conformément
  aux règles de l'arbre.
- Autoriser un accès au matériel réel : l'ADR 0007 et les règles de sécurité de
  `AGENTS.md` s'appliquent sans changement.

## Preuves et gates

Aucune de ces portes n'existe encore.

- **D1 — grammaire :** corpus positif et négatif avec diagnostics stables.
- **D2 — refus :** champ hors registre, chevauchement, écriture d'un registre en
  lecture seule et lecture d'un registre en écriture seule sont refusés à la
  compilation.
- **D3 — effets dérivés :** un accesseur généré porte l'effet et la capacité attendus,
  et un appelant qui ne les déclare pas est refusé.
- **D4 — premier témoin :** le contrôleur PS/2 (`i8042`) est décrit, et un pilote
  souris et clavier écrit avec les accesseurs générés se comporte sous QEMU comme le
  pilote écrit à la main du cube.
- **D5 — premier périphérique GPU :** VirtIO GPU 2D (niveau 3 de l'ADR 0007) est
  décrit et piloté sous QEMU.

## Ordre

Après B2.1. La description peut être spécifiée tôt, mais la génération d'accesseurs
a besoin du frontend commun (gate B4).
