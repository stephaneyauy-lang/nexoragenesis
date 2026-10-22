# NXOV0001 — objet relogeable du bootstrap C

État : format implémenté par `object.c`, version de bootstrap 1. Cette
spécification décrit les octets actuels; elle ne clôt pas le contrat A7
NTIR/Machine IR ni la vérification sémantique des contrats importés.

Tous les entiers sont little-endian. Les offsets de tables sont absolus;
ceux des symboles et relocations sont relatifs à leur section. La taille
totale maximale est 64 MiB, avec 65 536 symboles et 1 048 576 relocations.

## En-tête — 96 octets

| Offset | Type | Valeur / signification |
| --- | --- | --- |
| 0 | octets[8] | `NXOV0001` |
| 8 | u32 | version du format : 1 |
| 12 | u32 | cible : 1 UEFI x86_64, 2 bare x86_64 |
| 16 | u32 | version des contrats : 1 |
| 20 | u32 | nombre de sections : 3 |
| 24 | u32 | nombre de symboles N |
| 28 | u32 | nombre de relocations R |
| 32 | u64 | début des sections : 96 |
| 40 | u64 | début des symboles : 240 |
| 48 | u64 | début des relocations : 240 + 64 × N |
| 56 | u64 | début des chaînes : offset précédent + 40 × R |
| 64 | u64 | taille des chaînes |
| 72 | u64 | début des données : fin des chaînes arrondie à 16 |
| 80 | u64 | taille exacte du fichier |
| 88 | u32 | index de symbole d'entrée, base 1; 0 pour bibliothèque |
| 92 | u32 | réservé, zéro |

## Sections — trois enregistrements de 48 octets

Chaque enregistrement contient l'identifiant u32 à +0, les permissions u32
à +4, l'alignement u64 à +8, la taille u64 à +16 et l'offset fichier u64
à +24. Les 16 octets restants sont nuls. Ordre obligatoire : `.text` id1,
permissions5 RX, alignement16; `.rdata` id2, permissions1 R, alignement8;
`.data` id3, permissions3 RW, alignement8.

Chaque payload commence à la prochaine frontière de 16 octets, même pour
une section vide. Tous les bourrages sont nuls. Aucune donnée supplémentaire
ne suit le dernier payload. Les données `.rdata` excluent l'ancre PE de
8 octets que le writer ajoute lors de la matérialisation.

## Charge utile des sections de données — ordre et alignement

Ces deux règles gouvernent l'octetisation des variables de données et rien
d'autre ne les complète. Le producteur de référence est `codegen.c`
(`emit_static_data`), et le texte d'un lien n'est pas un argument de sortie.

1. **Ordre.** Les variables de données sont émises par nom de module croissant,
   puis par nom croissant, puis par index de déclaration croissant. Les noms se
   comparent octet par octet en non signé, un nom plus court préfixant le
   suivant d'abord. L'ordre de déclaration de la source ne joue que le rôle
   d'égalité finale. Comme chaque variable appartient à une seule section,
   l'ordre relatif des variables d'une section donnée est leur ordre de nom.
   La table des symboles est triée de la même façon, donc l'offset d'une
   variable dans son payload est fonction de son nom et non de sa position
   source. Deux linkages de la même unité donnent donc les mêmes octets quel
   que soit l'ordre des déclarations.
2. **Alignement.** Avant d'écrire une variable de largeur `w`, le producteur
   avance la taille courante de la section de zéro jusqu'à ce qu'elle soit un
   multiple de `min(w, 8)`, puis écrit les `w` octets de la valeur en ordre
   petit-boutiste et n'avance que de `w`. Les octets de bourrage sont nuls et
   appartiennent à la section, pas au symbole. Une largeur supérieure à 8 se
   borne donc à 8 ; un tableau de `u8` de `n` éléments s'aligne sur 1 et
   occupe `n` octets contigus.

Les deux règles sont indépendantes de `.text` : un offset de données ne dépend
que des déclarations de données et de leur nom. Un producteur qui n'émet pas
le même `.text` que le frontend C doit donc émettre exactement les mêmes
`.rdata` et `.data` pour les mêmes déclarations.

## Symboles — 64 octets

| Offset relatif | Type | Signification |
| --- | --- | --- |
| 0, 4 | u32, u32 | offset dans les chaînes et longueur du nom |
| 8, 12 | u32, u32 | section et flags |
| 16, 24 | u64, u64 | offset en section et taille |
| 32, 36 | u32, u32 | offset et longueur du contrat |
| 40 | u32 | version de contrat : 1 |
| 44 | octets[20] | réservés, zéros |

Flags : export1, fonction2, variable4, import8. Exactement un rôle fonction
ou variable. Un import a section/offset/taille nuls et ne peut être exporté.
Une fonction définie appartient à `.text` et a une taille non nulle. L'entrée
désigne une fonction définie. Les noms sont strictement triés par octets,
sans doublons; le producteur source emploie des noms qualifiés par module.

La table des chaînes contient, pour chaque symbole, son nom puis son
contrat, sans terminateur ni octets inutilisés. ASCII non NUL obligatoire;
nom de 1 à 512 octets, contrat de 1 à 65 536 octets. Le writer source encode
types, ABI, paramètres, effets, clobbers et prédicats dans un texte canonique.
Le reader valide la structure, pas la vérité sémantique de ce texte : un
objet externe n'acquiert aucune confiance par sa seule désérialisation.

L'offset d'un symbole de donnée est l'offset de la variable dans le payload de
sa section, et sa taille est la largeur de la variable. Un symbole de
fonction a pour taille la longueur de son corps dans `.text`.

## Relocations — 40 octets

Section source u32 à +0; type u32 à +4; offset du site u64 à +8; index cible
u32 base1 à +16; réservé u32 zéro à +20; addend i64 à +24; réservé u64 zéro
à +32. Les sites sont triés par section puis offset, sans chevauchement;
chaque site entier doit tenir dans son payload.

Type1 REL32 occupe 4 octets et calcule `S + A - (P + 4)`, signé32.
Type2 DIR64 occupe 8 octets et calcule `S + A`, adresse virtuelle64.
S est l'adresse du symbole cible, P celle du site et A l'addend signé.
Les dépassements sont refusés. La matérialisation PE ajoute chaque site
DIR64 à la table des relocations de base; REL32 ne dépend pas de cette base.

## Commandes et limites actuelles

`ntasm object SOURCE... -o UNIT.nxo` compile une unité source relogeable;
les imports déclarés peuvent rester non résolus et une bibliothèque n'a pas
besoin d'entrée. Les signatures et appels sont vérifiés avant émission.
`ntasm link UNIT.nxo [MORE.nxo ...] -o PROGRAM.efi` combine jusqu'à 64 objets
de même cible. Les imports exigent un nom qualifié, un rôle et un contrat
textuel identiques à une définition exportée. Les définitions dupliquées,
imports restants et entrées multiples sont refusés. Le résultat doit être
UEFI et posséder une entrée pour la sortie PE. `ntasm inspect UNIT.nxo`
valide la structure et affiche les comptes. Les sorties existantes sont
refusées. Le lecteur CLI limite chaque fichier à 16 MiB et l'unité à 64 MiB.

Le frontend et le linker relient de vrais modules compilés séparément.
Le mode normal `assemble` continue d'exiger une unité fermée avec main.
Les schémas sérialisés NTIR/Machine IR restent à compléter. Un objet bare ne devient pas implicitement
un programme UEFI. Les adaptateurs des probes QEMU sont des outils de test.
