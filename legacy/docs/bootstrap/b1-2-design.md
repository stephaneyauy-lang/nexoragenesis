# B1.2 — conception et résultat de l’enveloppe physique

Statut : **implémenté et vérifié — tracer B1.2 GREEN, Gate B1 RED**.

Ce document a borné le tracer B1.2 avant son RED et consigne désormais son résultat. Il complète
[`b1-implementation-map.md`](b1-implementation-map.md) pour la seule acquisition
physique de `\NTASM1.NTASM`. Il n'a modifié ni le binaire B1.1-r1, ni son ledger,
ni les spécifications normatives. L'implémentation exécutée est un candidat
NASM externe soumis à l'ADR 0009, pas une sortie de NTASM.

Les autorités restent, dans cet ordre :

1. [`../../spec/ntasm-s0.md`](../../../spec/ntasm/ntasm-s0.md) pour les octets source,
   les limites et les diagnostics ;
2. [`../../spec/seed-pe32.md`](../../../spec/formats/seed-pe32.md) pour PE32+, UEFI et
   l’ABI x64 ;
3. [`b1-implementation-map.md`](b1-implementation-map.md) pour les pools, le
   cycle de vie et la progression des tracers ;
4. [`../../bootstrap/seed/b1-token-r1-bytes.md`](../../bootstrap-seeds/b1-token-r1-bytes.md)
   comme preuve du **comportement** déjà vert de B1.1-r1, jamais comme source
   d’octets pour B1.2.

## 1. Frontière exacte du tracer

B1.2 doit :

- retrouver le volume de sa propre image et ouvrir `\NTASM1.NTASM` en lecture
  seule ;
- allouer exactement trois pools `EfiLoaderData` de tailles constantes ;
- lire par appels répétés jusqu’à EOF ou jusqu’à la sentinelle `0x10000` ;
- accepter une taille source de `1..0xFFFF` octets ;
- valider tout l’enveloppe physique : ASCII autorisé, LF/CRLF, EOL final,
  `4 096` lignes au plus et `255` octets hors EOL par ligne ;
- conserver le prédicat B1.1 « première ligne exactement `format pe64` » après
  validation physique complète ;
- contrôler ses canaris avant tout succès ;
- fermer tous les handles acquis et libérer tous les pools ;
- afficher exactement une fois `NG_B1_2_PHYSICAL_OK\r\n` sur le chemin vert ;
- ne jamais ouvrir, créer, écrire, vider ou supprimer `\NTASM1.EFI`.

B1.2 ne tokenise pas, ne construit pas de symbole, ne réalise aucune passe
d’assemblage et ne construit aucune image dans `OUT`. Le marqueur
`NG_NTASM_S0_OK` reste réservé à B1.26. Le marqueur B1.1
`NG_B1_1_FORMAT_OK` n'est plus présent dans l'image B1.2 vérifiée.

## 2. Continuité comportementale avec B1.1-r1

La réutilisation de B1.1 est exclusivement comportementale :

| Observation B1.1-r1 | Contrat B1.2 |
|---|---|
| même volume que l’image chargée | conservé |
| source ouverte avec `READ`, attributs zéro | conservé |
| protocole, volume ou source indisponible | `E001` conservé |
| erreur de `Read` ou fermeture source/racine fautive | `E002` conservé si aucune erreur antérieure |
| LF et CRLF après `format pe64` | conservés, puis toute la source est scannée |
| première ligne incompatible | `E200 L0001 C0001 O00000000` conservé |
| aucun `\NTASM1.EFI` | invariant renforcé |
| restauration ABI et appel de `Exit` | conservés |

Le GREEN n'a modifié ni `seed-b1.1-r1.efi` ni `b1-token-r1-bytes.md`.
B1.2 possède une nouvelle implémentation complète dans
`legacy/nasm/seed-b1.2-r1.asm` et une sortie quarantainée propre.
Aucun intervalle du dump B1.1 n'a été importé ou patché. Le prototype
`legacy/bootstrap-seeds/b1-physical-r1-bytes.md` décrit un autre hash : il est obsolète,
non matérialisé et n'est l'autorité d'aucun test GREEN.

## 3. Pools, ownership et canaris

Les tailles `0x1D000`, `0x10000` et `0x10000` désignent les **payloads
utilisables**. B1.2 ajoute une garde forte de 16 octets avant et après chaque
payload. Les trois appels `AllocatePool` utilisent
`MemoryType = EfiLoaderData = 2` et ont cet ordre immuable :

| Ordre | Pool logique | Payload | Taille réellement demandée | Pointeur exposé |
|---:|---|---:|---:|---|
| 1 | `WORK` | `0x1D000` | `0x1D020` | `work_raw + 0x10` |
| 2 | `SRC` | `0x10000` | `0x10020` | `src_raw + 0x10` |
| 3 | `OUT` | `0x10000` | `0x10020` | `out_raw + 0x10` |
| **Total** |  | **`0x3D000`** | **`0x3D060`** |  |

Le pointeur brut et le pointeur payload sont deux valeurs distinctes. Seul le
pointeur brut est transmis à `FreePool`; tout code métier reçoit le pointeur
intérieur. Les additions `raw + 0x10` et `payload + payload_size` sont vérifiées
avant calcul.

Le masque d’ownership et les six pointeurs `raw/payload` ont une autorité unique :
des slots bornés du cadre pile, conservés jusqu’au retour de chaque `FreePool`.
`WORK` n’en reçoit aucune copie autoritative et le cleanup ne lit jamais WORK
pour décider quelle ressource fermer ou libérer. Tant que le bit est posé, les
deux slots raw/payload restent autoritatifs. Après un `FreePool` réussi, le bit
et le slot raw sont effacés; le slot payload peut rester comme valeur stale mais
n’a plus aucune autorité. Après un échec, bit et pointeurs restent présents pour
décrire honnêtement la ressource encore possédée. Une allocation échouée ne
change pas l’ordre de cleanup : seuls les bits d’ownership de pile déjà posés
sont consultés.

Dans B1.2, la table `WORK[0x14400..0x1C3FF]` contient au plus `4 096` records
physiques de huit octets. Chaque record représente logiquement :

- l’offset 32 bits du premier octet hors EOL ;
- la longueur hors EOL sur 16 bits ;
- la largeur d’EOL, `1` pour LF ou `2` pour CRLF ;
- un champ réservé nul.

Cette table n’est pas encore une signature de pass 1. Une révision ultérieure
pourra enrichir sa sémantique sans modifier ses bornes.

Les valeurs exactes des canaris ont pour autorité
[`b1-2-test-protocol.md`](../../../docs/testing/b1-2-test-protocol.md); toute
implémentation source ou tout ledger doit les recopier sans les choisir ni les réinterpréter. Le présent
document fixe seulement leur topologie. Chaque bande fait exactement 16 octets.
Les six bandes sont distinctes par allocation et par côté et comparées à leurs
constantes immuables :

| Allocation | Garde basse | Payload autorisé | Garde haute |
|---|---|---|---|
| `WORK` | `work_raw[0x00..0x0F]` | `WORK[0..0x1CFFF]` | `work_raw[0x1D010..0x1D01F]` |
| `SRC` | `src_raw[0x00..0x0F]` | `SRC[0..0xFFFF]` | `src_raw[0x10010..0x1001F]` |
| `OUT` | `out_raw[0x00..0x0F]` | `OUT[0..0xFFFF]` | `out_raw[0x10010..0x1001F]` |

Les gardes sont hors payload : une source sentinelle de `0x10000` octets peut
remplir tout `SRC` sans écraser la garde haute. `OUT` n’est jamais utilisé comme
garde de `SRC`, et aucune hypothèse de contiguïté entre allocations n’existe.
La table de lignes reste protégée par son index vérifié
`completed_lines < 4096`; les gardes externes protègent les bornes réelles de
l’allocation.

Les deux bandes d’une allocation sont initialisées immédiatement après son
succès, avant l’allocation suivante. Les bandes des allocations possédées sont
contrôlées après leur initialisation ; lorsque les trois pools existent, les six
bandes sont contrôlées après acquisition/lecture, après le scanner, puis une
dernière fois juste avant le premier `FreePool`. Un
échec devient le diagnostic interne `E603` sans position et interdit le
marqueur. Il domine un diagnostic source provisoire, car l’intégrité de l’état
nécessaire pour formater ce diagnostic n’est alors plus démontrée. Aucun octet
source ne peut activer, désactiver ou corrompre volontairement un canari.

L’observation runtime est volontairement unique :
`NG_B1_2_PHYSICAL_OK` n’est atteignable que si toutes les comparaisons de canari
ont réussi. Le source producteur et le désassemblage doivent montrer que chaque
branche de canari postdomine le scanner et domine le site du marqueur. Aucun
second marqueur « canary ok » n’est ajouté.

## 4. Acquisition UEFI et lecture sentinelle

Avant la première allocation, l’entrée valide `SystemTable`, `ConOut`,
`BootServices`, `AllocatePool`, `FreePool`, `HandleProtocol` et `Exit`. Les
méthodes de protocoles sont validées avant leur appel. Les GUID, offsets UEFI et
constantes de modes de fichier déjà présents restent ceux de `seed-pe32.md`.

B1.2 ajoute `EFI_FILE_PROTOCOL.GetInfo` à l’offset x64 `0x40` et le GUID
`EFI_FILE_INFO_ID` canonique `09576e92-6d3f-11d2-8e39-00a0c969723b`. Le source
producteur encode ce GUID selon la représentation mémoire UEFI. Le buffer
fixe `EFI_FILE_INFO` occupe
`WORK[0x1CA00..0x1CBFF]` (`0x200` octets). La zone
`WORK[0x00000..0x001FF]` est réservée à l’état de traitement futur; dans B1.2,
elle ne contient aucun ownership ni pointeur raw/payload autoritatif.
`WORK[0x00200..0x003FF]` demeure une réserve nulle.
`GetInfo` est appelé avec une capacité
initiale `0x200`; un statut en erreur, `EFI_BUFFER_TOO_SMALL`, une taille rendue
supérieure à `0x200` ou inférieure à `0x50` devient `E002`. Le champ
`Attribute` est le qword à l’offset `0x48`; `EFI_FILE_DIRECTORY = 0x10`.
Si ce bit de `Attribute` est posé, le handle est fermé et
le résultat est `E002` **avant tout appel à `Read`**. La valeur `FileSize` n’est
pas utilisée pour accepter la source : seule la lecture sentinelle fait foi.

Le flux machine abstrait est :

```text
ENTRY
  sauvegarder ImageHandle, SystemTable et les non-volatils modifiés
  établir pile alignée + shadow space
  mettre à zéro phase, ownership, pointeurs et diagnostic primaire
  valider les services indispensables

ALLOCATE
  AllocatePool(EfiLoaderData, 0x1D020, &work_raw) ; poser gardes WORK
  WORK := work_raw + 0x10
  AllocatePool(EfiLoaderData, 0x10020, &src_raw)  ; poser gardes SRC
  SRC := src_raw + 0x10
  AllocatePool(EfiLoaderData, 0x10020, &out_raw)  ; poser gardes OUT
  OUT := out_raw + 0x10
  poser les ownerships après chaque succès
  conserver raw/payload et ownership uniquement dans le cadre pile
  zéroter le payload WORK ; vérifier les six gardes

DISCOVER
  HandleProtocol(ImageHandle, LoadedImage, &loaded)
  HandleProtocol(loaded.DeviceHandle, SimpleFS, &simple_fs)
  OpenVolume(simple_fs, &root)                 ; poser OWN_ROOT
  Open(root, &source, source_name, READ, 0)    ; poser OWN_SOURCE

CLASSIFY_SOURCE
  WORK_INFO := WORK + 0x1CA00
  GetInfo(source, EFI_FILE_INFO_ID, &info_size, WORK_INFO)
  valider taille et champ Attribute
  si Attribute contient EFI_FILE_DIRECTORY     -> E002, aucun Read

READ_SENTINEL
  source_len := 0
  tant que source_len < 0x10000 :
    remaining := 0x10000 - source_len          ; vérifié, jamais nul
    returned := remaining
    Read(source, &returned, SRC + source_len)
    si statut EFI en erreur                    -> E002
    si returned > remaining                    -> E002
    si returned = 0                            -> EOF
    next := checked_add(source_len, returned)
    si next = 0x10000                          -> E500 sans position
    source_len := next
  EOF : si source_len = 0                      -> E100 sans position

CLOSE_SOURCE
  Close(source) ; effacer OWN_SOURCE
  toute erreur de fermeture sans erreur primaire -> E002
  SRC devient immuable

SCAN_PHYSICAL
  scanner SRC[0..source_len)
  contrôler les canaris
  vérifier la première ligne exacte "format pe64"

CLEANUP_AND_REPORT
  fermer les handles encore possédés ; sélectionner toute erreur Close
  contrôler les canaris ; E603 remplace tout diagnostic antérieur
  si E603 est sélectionné :
    OutputString(E603_statique_rdata) sans consulter WORK ; poser ligne_tentée
  sinon, si un diagnostic existe :
    le formater et l’afficher pendant que WORK existe ; poser ligne_tentée
  FreePool(out_raw), FreePool(src_raw), FreePool(work_raw), sans arrêter le cleanup
  si aucun diagnostic antérieur et au moins un FreePool a échoué :
    sélectionner E604 et afficher sa chaîne statique depuis .rdata
  sinon, si aucun diagnostic et tous les FreePool ont réussi :
    afficher le marqueur succès
  ne jamais afficher une seconde ligne après un diagnostic antérieur
  Exit(ImageHandle, ExitStatus, 0, NULL)
  si Exit rend la main, restaurer l’ABI et retourner son statut
```

Le pointeur `SRC + source_len` n’est calculé que lorsque
`source_len < 0x10000`. Une taille rendue n’est ajoutée qu’après le contrôle
`returned <= remaining`. Une lecture partielle non nulle relance la boucle ;
seule une taille rendue nulle signifie EOF. Ainsi :

- `0xFFFF` octets exigent obligatoirement un appel `Read` final de capacité `1` :
  un retour nul prouve EOF et accepte la taille ;
- le prochain octet remplit la fenêtre jusqu’à `0x10000` et déclenche `E500` ;
- un fichier plus grand que `0x10000` est refusé au même point sans tentative
  de lecture hors de `SRC`.

Cette lecture finale, et non `EFI_FILE_INFO.FileSize`, distingue donc réellement
`65 535` de `65 536` octets. Un device qui rend `0` avant son EOF déclaré est
accepté selon le contrat de `Read`; aucune supposition de lecture complète en un
appel n’est faite.

La fermeture de la source précède le scanner. Aucun handle fichier ne peut donc
modifier `SRC` pendant sa validation.

## 5. Machine du scanner physique

État initial :

```text
offset := 0
line_number := 1
line_start := 0
line_length := 0
completed_lines := 0
```

À chaque itération, l’accès courant est autorisé seulement si
`offset < source_len`. L’ordre des gardes est normatif pour B1.2 :

1. si `completed_lines = 4096`, tout octet supplémentaire commence une 4 097e
   ligne : produire `E500` à cet octet sans écrire de record ;
2. en tête seulement, calculer `remaining := source_len - offset`; comparer les
   trois octets du BOM UTF-8 uniquement si `remaining >= 3`; avec moins de trois
   octets, ne faire aucun lookahead et laisser le premier octet non ASCII
   produire `E100`; un BOM exact produit `E100` à l’offset zéro ;
3. si l’octet est CR, vérifier d’abord que `offset + 1 < source_len`, puis que
   l’octet suivant est LF ; sinon produire `E100` sur le CR ;
4. si l’octet est LF, terminer une ligne d’EOL largeur 1 ;
5. sinon accepter uniquement TAB ou `0x20..0x7E` ; NUL et tout autre octet
   produisent `E100` ;
6. avant d’ajouter un octet hors EOL, si `line_length = 255`, produire `E101`
   sur ce 256e octet ; sinon incrémenter `line_length` et `offset`.

Terminer une ligne LF ou CRLF effectue, dans cet ordre :

1. vérifier que `completed_lines < 4096` ;
2. écrire exactement un record à l’indice `completed_lines` ;
3. incrémenter `completed_lines` ;
4. avancer `offset` de la largeur EOL ;
5. fixer `line_start := offset`, `line_length := 0` et incrémenter
   `line_number`.

À EOF, `line_length` doit être nul. Une ligne non vide sans EOL produit `E100`
à la position virtuelle EOF : `O = source_len`, `L = line_number` et
`C = line_length + 1`. Un CR terminal a déjà échoué sur la position du CR.
L’EOF situé immédiatement après un EOL ne crée pas de ligne vide fantôme.

Une source faite de lignes vides est physiquement valide, mais échoue ensuite au
prédicat de compatibilité B1.1. Après succès physique, le premier record doit
décrire exactement les onze octets ASCII `format pe64`; seule la largeur EOL
peut être 1 ou 2. Toute autre première ligne produit
`E200 L0001 C0001 O00000000`.

La validation physique est un prérequis de la comparaison B1.1 : une source
physiquement invalide produit donc son `E100`, `E101` ou `E500` avant tout
`E200`. Au sein du scanner, la première erreur au plus petit offset gagne. À un
même offset, la limite de lignes est testée avant l’octet, puis la validité de
l’octet avant la longueur de ligne ; cette précédence rend les diagnostics
byte-stables.

## 6. Diagnostics et statuts

Le format reste :

```text
NGS0 Eddd Lhhhh Chhhh Ohhhhhhhh\r\n
```

Les positions sont 1-based pour ligne et colonne, 0-based pour l’offset. Les
erreurs sans position mettent les trois champs à zéro.

| Cause B1.2 | Diagnostic | Position |
|---|---|---|
| source vide | `E100` | zéro |
| BOM, NUL ou octet hors alphabet | `E100` | octet fautif |
| CR non suivi de LF | `E100` | position du CR |
| ligne non vide sans EOL | `E100` | EOF virtuel |
| 256e octet hors EOL | `E101` | octet excédentaire, colonne `0x0100` |
| taille atteignant `0x10000` | `E500` | zéro, car le scanner n’est pas lancé |
| premier octet d’une 4 097e ligne | `E500` | ligne `0x1001`, colonne `1` |
| allocation épuisée | `E500` | zéro |
| corruption d’une bande canari | `E603` | zéro |
| échec de cleanup `FreePool` sans diagnostic antérieur | `E604` | zéro |
| erreur de protocole/ouverture | `E001` | zéro |
| `GetInfo`, répertoire, lecture ou fermeture fautifs | `E002` | zéro |
| première ligne différente de `format pe64` | `E200` | `L1 C1 O0` |

Les erreurs source et capacité utilisent `EFI_LOAD_ERROR`. Une allocation
échouée affiche `E500` mais utilise `EFI_OUT_OF_RESOURCES`. Un statut fichier en
erreur est conservé comme `ExitStatus`; une incohérence de compte sans statut
EFI en erreur utilise `EFI_DEVICE_ERROR`. Le code de diagnostic et le statut EFI
sont donc deux champs distincts.

`E603` est un diagnostic interne. Il utilise `EFI_LOAD_ERROR`, ne désigne jamais
une faute de la source et emploie une chaîne UTF-16 statique en
`.rdata` : aucun scratch de `WORK` suspect n’est consulté pour l’afficher.
`E604` est également statique et sans position. Il est sélectionné uniquement
si aucun diagnostic antérieur n’existe et qu’au moins un `FreePool` échoue. Le
premier statut EFI en erreur de `FreePool` devient `ExitStatus`; un statut
incohérent non erreur devient `EFI_DEVICE_ERROR`.

Le diagnostic primaire est write-once. Une erreur de `Close` ne remplace pas un
diagnostic antérieur. Une corruption de canari est l’unique exception : elle
invalide la fiabilité de l’état, force `E603` sans position et remplace tout
diagnostic antérieur. Un échec `FreePool` après un diagnostic ne le remplace pas
et n’ajoute jamais une seconde ligne.

## 7. États de cycle de vie et cleanup unique

La phase logique est monotone ; l’ownership est un masque séparé. Cette
séparation évite d’inférer la validité d’un pointeur depuis une simple phase.

| Phase | Fait acquis |
|---|---|
| `INIT` | ABI sauvée, aucun ownership |
| `SERVICES_VALID` | pointeurs UEFI requis non nuls |
| `POOLS_READY` | trois allocations possédées; masque et pointeurs autoritatifs dans le cadre pile, WORK initialisé |
| `ROOT_OPEN` | racine possédée |
| `SOURCE_OPEN` | source possédée |
| `SOURCE_CLOSED` | source fermée, SRC immuable |
| `PHYSICAL_VALID` | taille, scanner et canaris verts |
| `FORMAT_COMPATIBLE` | prédicat B1.1 vert |
| `ROOT_CLOSED` | aucun handle fichier possédé |
| `POOLS_FREED` | aucun pool possédé; bits et slots raw effacés, payloads résiduels non autoritatifs permis |
| `REPORTED` | une seule ligne succès ou erreur tentée |
| `EXITED` | `Exit` appelé |

Tout échec saute vers un seul épilogue. Celui-ci :

1. ferme `source` si `OWN_SOURCE` est posé et sélectionne E002 sur échec
   seulement si aucun diagnostic antérieur n’existe ;
2. ferme `root` si `OWN_ROOT` est posé avec la même règle de priorité ;
3. contrôle les canaris accessibles tant que les pools existent; E603 remplace
   tout diagnostic antérieur ;
4. si E603 est sélectionné, appelle directement `OutputString` sur sa chaîne
   statique `.rdata`, sans formateur ni lecture de `WORK`, puis pose le flag
   « ligne tentée »; sinon, si un autre diagnostic existe, le formate et tente
   de l’afficher pendant que le scratch de `WORK` est valide, puis pose le même
   flag ;
5. appelle `FreePool(out_raw)`, puis `FreePool(src_raw)`, puis
   `FreePool(work_raw)`, seulement pour les bits d’ownership posés ; aucun
   pointeur intérieur n’est jamais libéré; le cleanup continue après un échec ;
6. conserve dans le cadre pile pendant les trois appels le masque, tous les
   pointeurs raw/payload, le flag « diagnostic antérieur », le premier statut
   `FreePool` en erreur et tout statut nécessaire; aucun de ces champs n’est lu
   depuis `WORK` ;
7. après les trois tentatives `FreePool`, si aucune ligne antérieure n’a été
   tentée et qu’un échec a été observé, sélectionne E604 et appelle
   `OutputString` sur sa chaîne statique `.rdata`; son statut est le premier
   statut EFI en erreur, ou `EFI_DEVICE_ERROR` pour un retour incohérent non
   erreur ;
8. si une ligne antérieure a déjà été tentée, n’affiche rien après `FreePool`,
   même si celui-ci échoue ;
9. si handles, canaris et `FreePool` sont tous verts, affiche seulement
   `NG_B1_2_PHYSICAL_OK\r\n` ;
10. appelle `Exit` avec zéro octet de données d’exit.

Chaque bit d’ownership et son slot raw sont effacés seulement après un retour
sans erreur de la méthode correspondante. Le slot payload associé perd alors
son autorité même si sa valeur n’est pas zérotée. En cas d’échec, bit, raw et
payload restent autoritatifs dans le cadre pile; le cleanup continue afin de
tenter les autres ressources, mais aucune ressource n’est fermée ou libérée
deux fois.

## 8. Invariants ABI et PE du binaire vérifié

L'image B1.2 vérifiée respecte sans exception :

- PE32+ AMD64, sous-système `EFI_APPLICATION`, quatre sections `.text`,
  `.rdata`, `.data`, `.reloc` et relocation `DIR64` non vide ;
- aucune importation, aucun overlay et aucune section W+X ;
- `rcx = ImageHandle`, `rdx = SystemTable` à l’entrée ; résultat dans `rax` ;
- `rax`, `rcx`, `rdx`, `r8..r11` considérés volatils après chaque appel ;
- sauvegarde/restauration de `rbx`, `rbp`, `rdi`, `rsi`, `r12..r15` et `rsp`
  lorsqu’ils sont modifiés ;
- `rsp` aligné sur 16 immédiatement avant `call`, 32 octets de shadow space et
  aucune red zone ;
- profondeur privée maximale 8 et pile privée cumulée au plus `0x1000` ;
- aucun drapeau ou registre volatil utilisé comme état à travers un appel UEFI ;
- tous les out-slots mis à zéro et lus seulement après un statut admissible ;
- aucun pointeur de pool, protocole, handle ou méthode déréférencé avant preuve
  de validité ;
- aucune décision de lifecycle ou de cleanup ne dépend d’une copie dans WORK;
  le cadre pile est l’unique autorité pour ownership et pointeurs raw/payload ;
- toute soustraction de capacité, addition d’offset et formation de pointeur
  vérifiée avant l’opération ;
- aucun accès à `SRC`, `WORK` ou `OUT` hors de leur intervalle alloué ;
- `SRC` immuable après `Close(source)` ;
- aucun opcode de chaîne dépendant de DF et aucune dépendance SIMD/flottante ;
- `Exit(ImageHandle, ExitStatus, 0, NULL)` sur tous les chemins après entrée
  valide ; si `Exit` retourne, son propre statut devient le retour de l’image.

## 9. Preuve d’absence de sortie

Dans B1.2, `OUT` signifie seulement « pool futur déjà réservé ». Les propriétés
suivantes sont obligatoires :

- la chaîne UTF-16 `\NTASM1.EFI` est absente de l’image ;
- aucun chemin ne charge ni n’appelle `EFI_FILE_PROTOCOL.Write` ou `Flush` ;
- aucun appel `Open` ne porte `CREATE` ou `WRITE` ;
- le seul `Open` de fichier après `OpenVolume` cible `\NTASM1.NTASM` en `READ` ;
- hors initialisation et canaris, `OUT` reste inchangé ;
- le test inspecte le volume jetable après retour firmware et exige l’absence
  réelle de `\NTASM1.EFI`, même vide.

Une capture console ne suffit donc jamais à démontrer « aucun output ».

## 10. Budget planifié et mesure réelle

Ce budget historique estimait le fichier PE, pas les `0x3D000` octets de pools runtime.
Il ne constitue ni un dump ni un ledger d’octets.

| Sous-ensemble B1.2 | Estimation |
|---|---:|
| enveloppe PE, sections et alignements fixes | `0x0400` |
| entrée, lifecycle, UEFI, `GetInfo`, fichiers et pools | `0x0B00` |
| arithmétique vérifiée et lecteur sentinelle | `0x0600` |
| scanner physique et records de lignes | `0x0700` |
| compatibilité `format pe64` | `0x0200` |
| diagnostics, positions, canaris et cleanup | `0x0600` |
| GUID, chemins, chaînes UTF-16 et ancre de relocation | `0x0700` |
| `.data`, `.reloc`, padding imputé et contingence | `0x0800` |
| **centre estimé** | **`0x3300` (13 056 octets)** |

La sortie réelle fait `0x1E00` (7 680) octets. Sa `.text` utile fait `0x0CDF`
octets dans une zone brute `0x1200`; `.rdata` fait `0x0308`, `.data` `0x0008`
et `.reloc` `0x000C`. La marge jusqu'au plafond `0x10000` ne justifie aucune
duplication. Les valeurs, hashes et inspections mesurés sont dans le manifeste
GREEN canonique.

## 11. RED exécuté et matrice de promotion B1.2

Avant tout nouvel octet, B1.1-r1 a été exécuté sur les fixtures B1.2 et le RED
archivé montre au minimum l’absence de `NG_B1_2_PHYSICAL_OK` et l’absence de la
nouvelle sémantique. Le RED ne doit ni modifier B1.1-r1 ni être masqué par son
ancien marqueur.

Le GREEN a rejoué chaque cas avec un magasin OVMF frais :

| Cas | Résultat attendu |
|---|---|
| `format pe64` + LF | marqueur unique, sortie absente |
| `format pe64` + CRLF | marqueur unique, sortie absente |
| taille exacte `0xFFFF` physiquement valide | marqueur unique |
| taille `0x10000` | `E500` unique, aucun marqueur |
| source vide | `E100` unique |
| ligne de 255 octets hors EOL | acceptée si le préambule reste valide |
| ligne de 256 octets | `E101` au 256e octet |
| exactement 4 096 lignes | accepté si le préambule reste valide |
| 4 097e ligne | `E500` au premier octet de cette ligne |
| NUL, BOM et octet non ASCII séparément | `E100` à l’octet fautif |
| CR isolé et CR terminal séparément | `E100` sur le CR |
| dernière ligne non vide sans EOL | `E100` à EOF virtuel |
| première ligne physiquement valide mais incorrecte | `E200 L0001 C0001 O00000000` |
| source absente | `E001` |
| répertoire nommé `NTASM1.NTASM` | `GetInfo` détecte `DIRECTORY`, `E002`, aucun `Read` |
| erreur réelle de `GetInfo`/lecture/fermeture | `E002` |

Pour chaque cas, le manifeste consigne la taille et le hash exacts de la
fixture, le diagnostic ou marqueur compté, le retour firmware, l’absence de
sortie, l’intégrité des canaris atteignables et les trois appels `FreePool` sur
un chemin où les trois allocations ont réussi.

B1.2 n’exige aucune injection runtime de corruption canari. À ce tracer, E603
est prouvé statiquement par le source NASM quarantainé, le désassemblage, les six comparaisons et
la domination du site du marqueur. L’injection contrôlée d’une corruption canari
et les fautes `FreePool` appartiennent au device de test de B1.25.

La revue statique associée a en outre établi (preuves sous
`out/b1/step-2/20260902-172215-65d1b7dcff08475a974763b49f036e46/static-audit/`) :

- exactement trois sites `AllocatePool` avec l’ordre et les tailles brutes
  `0x1D020`, `0x10020`, `0x10020` ;
- un cleanup inverse `out_raw → src_raw → work_raw` sur chaque chemin applicable ;
- exactement un site `GetInfo`, dominé par les contrôles de taille et du bit
  `EFI_FILE_DIRECTORY`, et aucun `Read` atteignable pour un répertoire ;
- un seul site machine `Read`, éventuellement exécuté plusieurs fois ;
- aucune référence à `Write`, `Flush`, `CREATE`, `WRITE` ou au chemin de sortie ;
- chaque branche relative sur une frontière d’instruction et chaque référence
  RIP dans sa section déclarée ;
- le marqueur B1.2 dominé par fermeture des handles, contrôle des canaris et
  libération réussie des pools ;
- la branche E603 statique remplace tout diagnostic antérieur, tandis que la
  branche E604 n’est sélectionnable qu’en l’absence de diagnostic antérieur ;
- aucune occurrence de `NG_B1_1_FORMAT_OK` ou `NG_NTASM_S0_OK`.

B1.2 vert ne promeut pas la Gate B1. Il prouve seulement que l’acquisition, les
bornes physiques et le cycle de vie mémoire sont assez solides pour commencer
le lexer B1.3.

La preuve canonique est
`out/b1/step-2/20260902-172215-65d1b7dcff08475a974763b49f036e46/manifest.md`.
Le producteur reste externe et quarantainé jusqu'à reproduction bit-identique
par NTASM; cette réussite ne ferme donc pas l'ADR 0009.
