# Gate B1 — carte d’implémentation de NTASM-S0

Statut : plan d’exécution; tracers B1.1 à B1.10 GREEN, Gate B1 RED.

Cette carte transforme le seed B0 validé en un assembleur NTASM-S0 complet,
borné et auditable. Elle ne modifie ni la spécification normative
[`spec/ntasm/ntasm-s0.md`](../../../spec/ntasm/ntasm-s0.md), ni le profil PE
[`spec/formats/seed-pe32.md`](../../../spec/formats/seed-pe32.md). En cas de conflit, la première
spécification décide de la syntaxe et des encodages; la seconde décide du
conteneur PE32+ et de l’ABI UEFI.

Le langage machine typé final est spécifié séparément dans
[`spec/ntasm/ntasm.md`](../../../spec/ntasm/ntasm.md). Modules, fonctions typées, contrats,
pointeurs par espace, intrinsics, comptime et macros de NTASM v0 n’entrent jamais
dans S0 par ce renvoi.

## 1. Résultat visé et frontière du gate

À la fin seulement, `bootstrap/seed/seed0.efi` doit :

- rester inférieur ou égal à `0x10000` octets et posséder un ledger couvrant
  chaque octet;
- ouvrir `\NTASM1.NTASM` sur le volume de sa propre image;
- accepter exactement NTASM-S0 `S0.1`, sans extension implicite;
- effectuer deux passes déterministes sur les mêmes octets source;
- construire entièrement en mémoire un PE `B1-PE-v1` de taille maximale
  `0x10000`;
- refuser toute sortie préexistante et ne créer `\NTASM1.EFI` qu’après la
  validation et l’émission complètes;
- écrire la taille exacte, faire `Flush`, fermer tous les handles, libérer les
  pools, afficher une seule fois `NG_NTASM_S0_OK\r\n`, puis appeler
  `BootServices.Exit`;
- ne jamais produire d’import, d’overlay, de section W+X ou d’octet dépendant
  d’un timestamp, d’un chemin hôte ou d’un ordre de hachage.

B1 ne prouve pas encore l’auto-hébergement. L’égalité `ntasm2 == ntasm3` est la
Gate B2. La livraison **B2.1** exige ensuite NTASM v0 complet suivant
`docs/status/ntasm-completion.md`; elle n'attend plus NX/Nova/OS.
Le seed B1 ne prend en charge ni macro, include, expression générale,
objet relogeable, linker, debug/unwind, SIMD, atomique, instruction privilégiée,
réseau, plugin ou chemin choisi par la source.

Décision d’implémentation : la révision manuelle finale de `seed0.efi` utilise
elle-même l’enveloppe `B1-PE-v1`, avec une relocation `DIR64` non vide. C’est la
seule forme que NTASM-S0 sait produire et donc la seule compatible avec la
future reconstruction bit-identique depuis `seed0.ntasm`. Conserver l’enveloppe
provisoire `B0-PE-v0` au-delà du Hello exigerait une révision normative explicite
avant toute saisie d’octets.

## 2. Discipline RED → GREEN commune à tous les tracers

Chaque tracer ci-dessous est une promotion indépendante et ordonnée.

1. Écrire d’abord une fixture positive minimale, une fixture négative minimale,
   les octets ou le diagnostic attendus, le statut EFI attendu et la règle
   « sortie absente ou inchangée ».
2. Exécuter le seed du tracer précédent sans le modifier. Le nouveau test doit
   être RED pour la raison attendue; un échec de banc ou une fixture invalide ne
   compte pas.
3. Ajouter uniquement les octets nécessaires au comportement courant. Aucun
   élargissement opportuniste de grammaire n’est permis.
4. Rejouer le test nouveau, tous les tracers déjà verts et les contrôles de
   sécurité transversaux. Tout doit être GREEN.
5. Mettre à jour l'autorité productrice du tracer — ledger byte-exact ou source
   NASM temporaire soumise à l'ADR 0009 —, le hash, la taille réelle par module
   et le manifeste de preuve avant de passer au tracer suivant.
6. Un refactor n’est autorisé qu’après le GREEN et doit conserver les hashes de
   sortie des goldens. Si un attendu doit changer, réviser d’abord la
   spécification et son golden; ne jamais affaiblir le test pour suivre le code.

Les marqueurs temporaires servent uniquement à observer les tracers
intermédiaires. B1.1 emploie exactement `NG_B1_1_FORMAT_OK`; B1.2 emploie
exactement `NG_B1_2_PHYSICAL_OK`; les éventuels marqueurs suivants emploient
`NG_S0_Tnn_OK`. Ils ne signifient jamais « B1 » et
doivent tous être absents du seed final. Le marqueur normatif `NG_NTASM_S0_OK` est réservé à
**B1.26**, après fermeture et libération réussies. Aucun tracer B1.1 à B1.25 ne
peut annoncer Gate B1.

Les tests utilisent uniquement des volumes FAT jetables sous QEMU/OVMF. L’hôte
peut transporter une fixture, calculer un hash et observer un désassemblage. La
seule génération externe admise pendant les tracers est NASM `-f bin` dans la
quarantaine de l'ADR 0009; elle ne peut ni assembler NTASM, ni remplacer le
writer final et doit être éliminée avant la Gate B1.

## 3. Architecture interne raw x86_64

### 3.1 Flux unique

Le seed suit un seul pipeline, sans récursion et sans AST :

`entrée EFI → protocoles → lecture bornée → pass 1 → layout PE → pass 2 →
auto-vérification → contrôle d’existence → création/écriture/Flush/Close →
diagnostic ou succès → nettoyage → Exit`.

Chaque ligne est tokenisée dans au plus 16 descripteurs qui pointent dans le
buffer source immuable. Le parseur est une machine d’états de lignes. Les
instructions sont envoyées au même planificateur x86_64 en mode mesure pendant
la pass 1, puis en mode émission pendant la pass 2. Les labels et références
sont conservés dans des tables linéaires; aucune table de hachage n’est admise.

### 3.2 ABI privée et discipline machine

- L’entrée conserve `ImageHandle` et `SystemTable` avant tout appel firmware.
- Les appels privés emploient l’ABI EFI/Microsoft x64 : arguments dans `rcx`,
  `rdx`, `r8`, `r9`, résultat dans `rax`.
- `rax`, `rcx`, `rdx`, `r8..r11` sont volatils. `rbx`, `rbp`, `rdi`, `rsi`,
  `r12..r15` et `rsp` sont sauvegardés s’ils sont modifiés.
- Avant chaque `call`, `rsp` est aligné sur 16 octets et 32 octets de shadow
  space sont réservés. Aucune red zone n’est supposée.
- Chaque routine possède dans le ledger un contrat `entrées / sortie / clobbers
  / taille de pile / erreurs`. Aucun résultat ne dépend de drapeaux conservés à
  travers un appel.
- La profondeur d’appel privée est bornée à 8; pile privée cumulée, shadow space
  inclus, inférieure ou égale à `0x1000`. La récursion est interdite.
- Les pointeurs firmware, de protocoles, de méthodes et de pools sont vérifiés
  non nuls avant leur premier déréférencement. Les additions d’adresses sont
  vérifiées avant calcul.
- Les accès multioctets sont explicitement little-endian. Aucune structure PE ou
  UEFI n’est copiée par cast implicite.

### 3.3 Modules logiques

| Module | Responsabilité | Interface interne minimale |
|---|---|---|
| `entry/lifecycle` | sauvegarde ABI, ownership/pointeurs autoritatifs sur pile, cleanup, `Exit` | `efi_main`, `fail`, `cleanup_exit` |
| `uefi/file` | découverte du volume, `Open`, `Read`, `Write`, `Flush`, `Close` | wrappers à statut unique, aucun pointeur non validé |
| `checked` | additions, multiplications, alignements, conversions | variantes `u32`, `u64`, `i8`, `i32`, `i64` sans wrap |
| `source` | lecture sentinelle, lignes, positions | curseur byte, ligne/colonne 1-based |
| `lexer` | 16 tokens par ligne, chaînes et nombres | descripteurs vers source, scratch chaîne |
| `parser` | préambule, sections, statements et catégories | machine d’états, aucune récursion |
| `symbols` | constantes, labels, références et entrée | recherche linéaire sensible à la casse |
| `x64` | mesure et émission canonique des 30 mnémoniques | `plan_instruction`, `emit8/16/32/64` |
| `reloc` | collecte et blocs `DIR64` | ordre RVA croissant, padding `ABSOLUTE` |
| `pe` | layout, headers, sections, contrôles finaux | writer `B1-PE-v1` uniquement |
| `diag` | premier diagnostic stable et statut EFI | format UTF-16 fixe, sans texte variable |

## 4. Zones mémoire bornées

Le seed ne tente jamais plus de trois allocations `EfiLoaderData`; sur le chemin
normal, les trois réussissent. Leur taille ne dépend jamais du contenu de la
source. Une allocation échouée mène au cleanup et à `EFI_OUT_OF_RESOURCES`.
Aucun `ReallocatePool` n’est utilisé.

Chaque taille logique est un payload entouré de deux bandes canari de 16 octets.
Le pointeur brut est conservé pour `FreePool`; seul `raw + 0x10` est exposé aux
modules internes.

| Pool | Payload | Demande brute | Pointeur exposé | Rôle et invariant |
|---|---:|---:|---|---|
| `WORK` | `0x1D000` | `0x1D020` | `work_raw + 0x10` | état, tables et scratch détaillés ci-dessous |
| `SRC` | `0x10000` | `0x10020` | `src_raw + 0x10` | reçoit au plus 65 536 octets; seuls `0..source_len-1` sont lus par le parseur |
| `OUT` | `0x10000` | `0x10020` | `out_raw + 0x10` | image PE complète; aucun write si `cursor >= final_size` ou `final_size > 0x10000` |
| **Total** | **`0x3D000`** | **`0x3D060`** |  | **249 952 octets bruts, constants** |

Pour chaque allocation, la garde basse est `raw[0x00..0x0F]`, le payload
commence à `raw+0x10`, et la garde haute occupe les 16 octets immédiatement
après le payload. Les valeurs exactes des six bandes ont pour autorité exclusive
[`b1-2-test-protocol.md`](../../../docs/testing/b1-2-test-protocol.md); l'implémentation
source ou son ledger les recopie sans les choisir. Les six bandes sont distinctes et contrôlées après lecture,
après traitement et juste avant libération. Une corruption de canari produit
`E603 L0000 C0000 O00000000`; le cleanup utilise les pointeurs bruts conservés
sur pile et ne libère jamais un pointeur intérieur.

Plan interne du payload `WORK` :

| Intervalle | Taille | Contenu |
|---|---:|---|
| `0x00000..0x001FF` | `0x0200` | état de traitement futur; aucun ownership ni pointeur raw/payload autoritatif en B1.2 |
| `0x00200..0x003FF` | `0x0200` | réserve nulle; ne contient aucun état global |
| `0x00400..0x063FF` | `0x6000` | 512 symboles × 48 octets |
| `0x06400..0x123FF` | `0xC000` | 2 048 fixups branche/RIP × 24 octets |
| `0x12400..0x143FF` | `0x2000` | 512 références `addr`/relocations × 16 octets |
| `0x14400..0x1C3FF` | `0x8000` | 4 096 lignes × 8 octets de signature pass 1 |
| `0x1C400..0x1C4FF` | `0x0100` | 16 descripteurs de token × 16 octets |
| `0x1C500..0x1C8FF` | `0x0400` | chaîne décodée, maximum 1 024 octets |
| `0x1C900..0x1C9FF` | `0x0100` | ligne de diagnostic UTF-16 |
| `0x1CA00..0x1CBFF` | `0x0200` | buffer fixe `EFI_FILE_INFO` pendant l’acquisition |
| `0x1CC00..0x1CFFF` | `0x0400` | réserve nulle |

Un symbole de 48 octets contient `name[32]`, une valeur 64 bits, l’offset source
32 bits, la ligne 16 bits et un champ 16 bits `kind/section/flags`. Le nom est
terminé par zéro dans le record et sa longueur reste au plus 31. Une constante
stocke les bits `u64` et un flag de signe séparé : les positifs peuvent atteindre
`u64::MAX`, les négatifs doivent tenir dans `i64`. Un label stocke son offset
relatif de section et le bit « premier octet d’une instruction ».

Un fixup conserve les offsets source et de site, l’offset de l’octet suivant,
la tranche de nom dans `SRC`, sa catégorie et sa section. Une référence `addr`
conserve de même le site et le nom sans recopier l’identifiant. Les records de
ligne mémorisent fin de ligne, taille émise, nombre de tokens et type de
statement. Le buffer source est immuable après fermeture du fichier, ce qui rend
les tranches stables pendant les deux passes.

Avant utilisation, `WORK` est mis à zéro. `OUT[0..final_size)` est mis à zéro
avant tout champ PE afin de rendre déterministes les champs réservés et paddings.
Le reste de `OUT` n’est ni écrit au fichier ni inclus dans un hash de sortie.
Les bandes externes encadrent les trois payloads pendant tout le runtime; elles
sont contrôlées avant l’ouverture de la sortie. Les index des tables internes
sont en plus vérifiés avant chaque accès.

Limites sémantiques contrôlées avant incrément :

| Ressource | Maximum accepté |
|---|---:|
| source | `65 535` octets |
| lignes physiques | `4 096` |
| ligne hors EOL | `255` octets |
| tokens par ligne | `16` |
| identifiant | `31` octets |
| chaîne décodée | `1 024` octets |
| constantes + labels | `512` |
| fixups branche/RIP | `2 048` |
| relocations `DIR64` | `512` |
| instructions | `8 192` |
| `.text` utile | `32 768` octets |
| `.rdata` utile | `16 384` octets |
| `.data` utile | `8 192` octets |
| `.reloc` utile | `4 096` octets |
| fichier PE final | `65 536` octets |

Atteindre exactement une limite est valide, sauf la sentinelle source
`65 536`. Les maxima de sections doivent encore donner le fichier `0xF400` et
`SizeOfImage=0x10000`; ces deux valeurs sont des goldens de borne.

## 5. Acquisition UEFI et cycle de vie des handles

L’ordre d’acquisition est figé :

`EFI_FILE_INFO_ID` est représenté en mémoire par les 16 octets exacts
`92 6E 57 09 3F 6D D2 11 8E 39 00 A0 C9 69 72 3B`.

1. valider `SystemTable`, `ConOut`, `BootServices` et les méthodes nécessaires;
2. allouer `WORK`, `SRC`, puis `OUT` avec les tailles brutes `0x1D020`,
   `0x10020`, `0x10020`; initialiser les gardes et conserver sur la pile chaque
   pointeur brut, chaque pointeur intérieur `raw+0x10` et son bit d’ownership;
   ces slots restent l’unique autorité jusqu’après le retour de `FreePool` et ne
   sont jamais recopiés comme autorité dans WORK;
3. appeler `HandleProtocol(ImageHandle, LoadedImageProtocol, &loaded)`;
4. valider `loaded`, lire `DeviceHandle`, puis appeler `HandleProtocol` avec
   `SimpleFileSystemProtocol`;
5. valider le protocole et appeler `OpenVolume` pour obtenir `root`;
6. ouvrir `\NTASM1.NTASM` avec `EFI_FILE_MODE_READ` et attributs zéro;
7. appeler `GetInfo` (`EFI_FILE_PROTOCOL+0x40`) avec `EFI_FILE_INFO_ID`, un
   buffer `WORK[0x1CA00..0x1CBFF]` et une capacité `0x200`; exiger une taille
   rendue `0x50..0x200`, puis lire le qword `Attribute` à `+0x48`; le bit
   `EFI_FILE_DIRECTORY=0x10`, une erreur ou un compte incohérent devient E002
   avant tout `Read`;
8. lire en boucle. Chaque appel reçoit la capacité restante; un retour de taille
   zéro marque EOF et une taille rendue supérieure à la capacité devient E002;
9. après un cumul de `0xFFFF`, effectuer obligatoirement un `Read` final de
   capacité `1`: zéro confirme EOF, un octet atteint `0x10000` et devient E500;
   refuser aussi zéro octet avec E100; la taille acceptée est `1..0xFFFF`;
10. fermer la source avant la pass 1 et ne plus modifier `SRC`;
11. garder `root` ouvert pendant l’assemblage, mais n’ouvrir aucune sortie;
12. après validation complète, tenter `Open(READ)` sur `\NTASM1.EFI` : un succès
    est fermé puis devient E700; seul `EFI_NOT_FOUND` autorise la création;
13. créer avec `READ | WRITE | CREATE`, attributs zéro, faire un seul `Write`
    de `final_size` et exiger statut non erreur et taille rendue identique;
14. appeler `Flush`, puis `Close`. Le succès reste interdit si l’un échoue;
15. fermer `root`, sélectionner les erreurs `Close`, contrôler les six bandes
    canari; E603 remplace tout diagnostic antérieur, contourne le formateur et
    appelle directement `OutputString` sur sa chaîne statique `.rdata` sans lire
    `WORK`; tout autre diagnostic est formaté/affiché pendant que le scratch
    `WORK` existe; dans les deux cas, poser le flag « ligne tentée »;
16. appeler `FreePool(out_raw)`, `FreePool(src_raw)`, `FreePool(work_raw)` dans
    cet ordre en tentant les trois libérations et en conservant sur pile le
    premier statut fautif;
17. après les tentatives `FreePool`, si aucun diagnostic antérieur n’existait,
    qu’aucune ligne n’a été tentée et qu’une libération a échoué, sélectionner
    E604 et afficher sa
    chaîne statique `.rdata` avant `Exit`; propager le premier statut EFI en
    erreur ou utiliser `EFI_DEVICE_ERROR` pour un retour incohérent non erreur;
    si un diagnostic antérieur existait ou a été tenté, ne jamais produire une seconde
    ligne; si tout est vert, afficher le succès statique, puis appeler `Exit`.

L’état de cleanup est monotone : `INIT`, `ROOT_OPEN`, `SOURCE_OPEN`,
`SOURCE_CLOSED`, `IMAGE_VALID`, `OUTPUT_OPEN`, `OUTPUT_WRITTEN`,
`OUTPUT_FLUSHED`, `OUTPUT_CLOSED`, `DONE`. Un seul épilogue consulte cet état;
aucun chemin d’erreur ne saute directement hors du seed.

Le masque d’ownership et les pointeurs raw/payload sont séparés de cette phase
et résident exclusivement dans le cadre pile. Tant que le bit est posé, les deux
slots sont autoritatifs. Close/FreePool efface le bit et le slot raw seulement
après succès; le payload peut rester stale mais devient non autoritatif. Un
échec laisse ownership, raw et payload intacts. Le cleanup reste donc opérable
si WORK est corrompu, suspect ou déjà libéré.

Une erreur de source ne crée jamais de sortie. Une erreur d’écriture peut laisser
un nouveau fichier partiel : le seed ne le supprime ni ne le renomme, n’affiche
pas le succès et il restera refusé comme « sortie existante » au run suivant.

## 6. Lexer, parseur et sélection du premier diagnostic

### 6.1 Lexer pur par ligne

Le scanner physique valide d’abord ASCII, LF/CRLF, CR isolé, NUL, BOM, EOL final,
4 096 lignes et 255 octets par ligne. Le lexer reçoit ensuite uniquement une
tranche de ligne valide. Il :

- ne compare la signature BOM de trois octets que si la capacité restante est
  supérieure ou égale à `3`; sinon aucun octet de lookahead n’est lu;

- ignore espaces/tabulations périphériques et transforme `;` hors chaîne en fin
  sémantique de ligne;
- produit au plus 16 tokens parmi identifiant, entier, chaîne, section et
  ponctuation `: , = [ ] + - * ( )`;
- exige les mots-clés, registres et sections en minuscules exactes, mais compare
  les symboles utilisateur avec leur casse exacte;
- analyse l’entier non signé avec une accumulation `u64` vérifiée avant chaque
  `×10/+digit` ou `×16/+digit`;
- applique le signe seulement après validation de la magnitude et de la plage
  `i64`; le `+` unaire, les zéros décimaux initiaux, suffixes et `_` sont refusés;
- décode uniquement `\\`, `\"`, `\r`, `\n`, `\t`, `\0`, `\xHH` dans le scratch
  de 1 024 octets, sans lire après la fin de ligne.

Le lexer est une fonction pure de `(SRC, début, fin)`. Il n’a aucun état propre à
la pass 1 ou 2. À source et bornes de ligne identiques, la suite de tokens est
donc identique par construction.

Les positions de frontière physique sont normatives : source vide donne
`E100 L0000 C0000 O00000000`; la sentinelle `65 536` donne
`E500 L0000 C0000 O00000000` avant scanner; une ligne non vide sans EOL donne
E100 à l’EOF virtuel (`L` courant, `C=longueur+1`, `O=source_len`); le 256e octet
hors EOL donne E101 sur cet octet à la colonne `0x0100`; le premier octet d’une
4 097e ligne donne E500 avec `L=0x1001`, `C=1` et son offset réel.

### 6.2 Parseur de lignes

Le parseur possède les états `EXPECT_FORMAT`, `EXPECT_ABI`, `CONSTS_OR_ENTRY`,
`EXPECT_TEXT`, `IN_TEXT`, `IN_RDATA`, `IN_DATA`, `DONE`. Chaque ligne produit au
plus un statement. Un label partageant une ligne avec une instruction est
refusé. Les trois sections doivent apparaître une fois, dans l’ordre et être non
vides; `.reloc` n’est jamais un token source valide.

Il n’existe pas d’arbre syntaxique. La pass 1 enregistre symboles, fixups,
relocations et tailles. La pass 2 reparse et émet immédiatement. Une récupération
bornée saute à l’EOL après une ligne invalide afin de continuer la collecte des
définitions et de pouvoir choisir réellement l’erreur au plus petit offset.

### 6.3 Premier diagnostic

Chaque erreur candidate porte `(code, line, column, offset)`. La pass 1 conserve
la candidate de plus petit offset source, y compris après résolution finale des
références avant. À offset égal, la priorité fixe est lexicale, syntaxique,
sémantique, capacité, puis interne. Les erreurs sans position utilisent zéro et
sont émises immédiatement lorsqu’aucune source exploitable n’existe.

Le format exact est `NGS0 Eddd Lhhhh Chhhh Ohhhhhhhh\r\n`, en UTF-16, sans nom de
fichier ou texte localisé. Les familles sont figées :

- E001–E002 : acquisition et lecture;
- E100–E102 : octets, limites lexicales locales, entier ou échappement;
- E200–E202 : ordre, syntaxe et section;
- E300–E302 : doublon, résolution/catégorie et entrée;
- E400–E402 : mnémonique/forme, plage et adressage/alignement;
- E500 : toute limite de ressource globale;
- E600–E604 : incohérence entre passes, PE non représentable, relocation absente,
  corruption interne d’un canari, échec interne de `FreePool`;
- E700–E702 : sortie existante, création, write/Flush/Close.

Les erreurs de source/capacité utilisent `EFI_LOAD_ERROR`; une allocation utilise
`EFI_OUT_OF_RESOURCES`; un statut fichier en erreur est propagé, sinon converti
en `EFI_DEVICE_ERROR`. Si `Exit` rend la main, son statut devient le retour de
l’application.

Une limite locale à une unité lexicale — ligne, tokens de ligne, identifiant ou
chaîne décodée — produit E101 au premier élément excédentaire. Une limite globale
— source, lignes physiques, symboles, fixups, relocations, instructions ou taille
utile d’une section — produit E500. Le PE final non représentable reste E601.
E603 utilise toujours `L0000 C0000 O00000000`, ne désigne jamais une faute de la
source, remplace tout diagnostic antérieur et interdit tout marqueur de succès.
E604 utilise aussi une position nulle, mais n’est retenu que si aucun diagnostic
antérieur n’existe et qu’au moins un `FreePool` échoue. Le premier statut EFI en
erreur de `FreePool` est propagé; un statut incohérent non erreur devient
`EFI_DEVICE_ERROR`.

## 7. Pass 1, layout et pass 2

### 7.1 Pass 1 — mesure et tables

- Repartir du byte zéro et valider toute la grammaire.
- Insérer constantes et labels dans l’ordre de définition; recherche linéaire,
  aucun ordre variable.
- Pour chaque instruction, appeler le planificateur x86_64 en mode mesure. Les
  branches et références RIP ont toujours un champ `rel32/disp32`; aucune
  relaxation n’existe.
- Enregistrer au plus 2 048 fixups branche/RIP et 512 références `addr`.
- Compter au plus 8 192 instructions et les tailles utiles `.text`, `.rdata`,
  `.data` sans émettre dans `OUT`.
- Enregistrer par ligne fin, token count, statement kind et taille mesurée.
- Après la dernière définition, résoudre catégories, `entry`, références avant,
  sections cibles et plages qui sont déjà décidables.
- Exiger au moins un `qword addr(label)` correctement aligné.

### 7.2 Layout intermédiaire

Calculer avec les helpers checked, sans choix d’implémentation : headers
`0x0400`, `.text` à RVA `0x1000`/raw `0x0400`, puis chaque RVA alignée sur
`0x1000` et chaque raw size sur `0x0200`. Les quatre sections sont `.text`,
`.rdata`, `.data`, `.reloc`. Les sites `addr` sont convertis en RVA croissantes;
l’ordre des sections et des offsets doit déjà les rendre triés et sans doublon.
Les changements de page déterminent la taille virtuelle exacte de `.reloc`.

Refuser avant la pass 2 si une taille dépasse son maximum, si un champ PE ne
tient pas, si `file_size > 0x10000` ou si `.reloc` serait vide.

### 7.3 Pass 2 — émission

- Repartir du byte zéro avec tous les compteurs de section à zéro.
- Pour chaque ligne, vérifier la signature enregistrée en pass 1. Comme `SRC` est
  immuable et le lexer pur, une différence de bornes, nombre de tokens, statement
  ou taille devient E600.
- Émettre les données et les 30 instructions avec des sinks bornés. Chaque
  `emit8/16/32/64` vérifie la capacité avant le premier store.
- Résoudre les branches par `RVA(cible) - RVA(octet_suivant)` et les références
  RIP depuis la fin de l’instruction complète; exiger `i32`.
- Émettre `ImageBase + RVA(label)` pour `addr(label)` et construire les blocs
  `DIR64` par page croissante, avec une entrée `ABSOLUTE` seulement pour
  l’alignement à quatre octets.
- Comparer tailles, nombres de fixups/relocations/instructions et offsets finaux
  à la pass 1 avant d’écrire les headers.

## 8. Encodeur x86_64 canonique

Le planificateur produit un descripteur temporaire : opcode, présence et bits
REX, ModRM, SIB, largeur et valeur du déplacement, immédiat, taille totale et
type de fixup. La mesure et l’émission utilisent ce même descripteur.

Invariants d’encodage :

- un seul opcode par forme, exactement celui de `ntasm-s0.md`;
- `REX.W` lorsque prescrit; REX toujours présent pour load/store 8, 16 et 32;
  aucun REX neutre pour `push`, `pop`, `call rs`;
- `load16` n’émet jamais `66`; `store16` émet `66` avant REX;
- index `rsp`/`r12` interdit; base `rsp`/`r12` impose SIB;
- base `rbp`/`r13` sans déplacement devient obligatoirement `disp8=0`;
- déplacement base : aucun si possible, sinon `disp8`, sinon `disp32`;
- branche/call label toujours `rel32`; RIP toujours `mod=00,r/m=101,disp32`;
- `mov rd, imm64` reste toujours sur huit octets d’immédiat;
- `shl`/`shr` acceptent seulement `0..63`; aucune troncature d’immédiat;
- aucun préfixe, opcode court ou optimisation non spécifié.

Les 14 vecteurs d’encodage de la spécification sont testés byte pour byte avant
le golden PE complet. Un désassembleur externe peut observer les octets, mais ne
constitue jamais l’oracle de génération.

## 9. Relocations et writer PE

Le writer commence par zéroter `OUT[0..file_size)`, puis écrit chaque champ par
offset explicite. Il n’utilise ni template binaire opaque ni copie de structure.

Contrat PE final :

- DOS `MZ`, `e_lfanew=0x80`, zone `0x40..0x7F` nulle;
- machine `0x8664`, quatre sections, timestamp et checksum nuls;
- Optional Header PE32+ de `0xF0`, ImageBase `0x0000000140000000`, alignements
  section/fichier `0x1000/0x0200`, subsystem EFI Application;
- `DllCharacteristics=0x0140`, tailles stack/heap normatives;
- 16 data directories, seul l’index 5 Base Relocation non nul;
- caractéristiques exactes `.text=0x60000020`, `.rdata=0x40000040`,
  `.data=0xC0000040`, `.reloc=0x42000040`;
- paddings de raw sections nuls; `90` existe seulement pour `align` dans
  `.text`; fin du fichier au dernier octet raw de `.reloc`, sans overlay.

Chaque `qword addr(label)` naturellement aligné dans `.rdata` ou `.data` émet une
valeur absolue préférée et une relocation de type 10. Pages et offsets sont
strictement croissants; doublons, bloc vide ou bloc terminal sont interdits.

Le golden minimal doit rester exactement : `.text` utile `0x8`, `.rdata`
`0xE`, `.data` `0x8`, `.reloc` `0xC`, fichier `0xC00`, `SizeOfImage=0x5000`,
entrée `0x1000`. Les payloads et tous les champs sont comparés à la spécification,
pas seulement au résultat d’un parseur PE externe.

## 10. Budget des octets du seed B1

Ce budget porte sur le fichier `seed0.efi` final, pas sur les pools runtime. Les
plafonds incluent code, tables et padding imputables au module. La somme vaut
exactement `0x10000`; le seed doit rester en dessous et garder si possible la
réserve intacte.

| Module binaire | Plafond hex | Plafond décimal |
|---|---:|---:|
| enveloppe PE, section headers et alignements fixes | `0x0400` | 1 024 |
| entrée, ABI, lifecycle et wrappers UEFI | `0x1000` | 4 096 |
| arithmétique checked, accès mémoire et sinks | `0x0800` | 2 048 |
| lecteur source et positions | `0x0800` | 2 048 |
| lexer et validation de lignes | `0x1C00` | 7 168 |
| parseur et machine d’états | `0x1C00` | 7 168 |
| symboles, fixups et validations sémantiques | `0x1400` | 5 120 |
| planificateur/encodeur x86_64 | `0x3000` | 12 288 |
| constructeur `.reloc` | `0x0C00` | 3 072 |
| layout, writer PE et auto-contrôles | `0x1000` | 4 096 |
| diagnostics, statuts et cleanup | `0x0C00` | 3 072 |
| GUID, mots-clés, registres et chaînes UTF-16 | `0x1000` | 4 096 |
| padding/alignement imputé et ledger | `0x0800` | 2 048 |
| réserve de contingence non assignée | `0x2000` | 8 192 |
| **Total dur** | **`0x10000`** | **65 536** |

La réserve n’est pas un overlay ou un padding obligatoire : les octets non
utilisés ne sont pas ajoutés au fichier. Après chaque GREEN, le manifeste donne
taille réelle et delta par module. Le dépassement d’un plafond local impose une
revue; le dépassement total interdit la promotion. La réponse normale est de
simplifier le module ou de réduire S0 par révision normative. L'exception NASM
de l'ADR 0009 peut seulement accélérer un candidat intermédiaire quarantainé;
elle ne relève aucun plafond et ne peut devenir une dépendance du résultat.

## 11. Tracer bullets RED → GREEN

### B1.1 — lire la source et valider `format pe64`

- **RED :** avec `\NTASM1.NTASM` absent, le seed B0 affiche encore son Hello;
  avec une fixture `format pe32` ou sans EOL, il ne produit pas E001/E200. Capturer
  ces échecs et confirmer qu’aucun `\NTASM1.EFI` n’existe.
- **GREEN minimal :** ajouter validation des pointeurs UEFI, découverte du volume,
  ouverture/lecture bornée de `\NTASM1.NTASM`, fermeture source et reconnaissance
  de la toute première ligne sémantique exacte `format pe64`. Le scanner utilisé
  ici devient le début du lexer final; il n’est pas jetable.
- **Preuve :** la fixture temporaire `format pe64\n` atteint exactement
  `NG_B1_1_FORMAT_OK`; source absente → E001, mauvaise ligne → E200 avec position
  stable, EOL absent → E100; aucune sortie n’est créée. Ce GREEN est seulement
  celui du tracer B1.1.

### B1.2 — enveloppe physique et bornes de lecture — **GREEN**

- **RED :** figer vide, 65 535, 65 536 octets, NUL, BOM, non-ASCII, CR isolé,
  ligne 256, 4 097 lignes et dernière ligne sans EOL.
- **GREEN minimal :** allouer les trois payloads gardés, classifier la source par
  `GetInfo`, achever la lecture sentinelle avec le `Read` final de capacité `1`
  et scanner l’enveloppe physique; accepter exactement `1..65 535`, les lignes
  de 255 octets et 4 096 lignes; refuser le reste avec E100/E101/E500 sans accès
  hors `SRC`. Un répertoire est E002 avant `Read`; un canari corrompu est E603.
- **Preuve :** vide et 65 536 ont une position nulle; EOF virtuel, ligne 256 et
  ligne 4 097 ont les positions figées de 6.1; les payloads et leurs six bandes
  restent intacts, les trois pointeurs bruts sont libérés dans l’ordre inverse,
  et la sortie est absente. Le marqueur unique est
  `NG_B1_2_PHYSICAL_OK`, seulement après compatibilité `format pe64`, canaris
  intacts et cleanup vert. B1.2 prouve E603 par le source NASM quarantainé, le désassemblage et la
  domination du marqueur; il n’injecte aucune corruption runtime.
- **Résultat vérifié :** candidat externe de 7 680 octets, SHA-256
  `19b302389215f8377823e1577c1263dbba6e7a39b78b0cb628462c5e025bbddd`;
  24/24 oracles et 4/4 non-régressions passent, sans `NTASM1.EFI`. Preuve :
  `out/b1/step-2/20260902-172215-65d1b7dcff08475a974763b49f036e46/manifest.md`.
  Ce statut ne promeut pas la Gate B1 et ne rend pas le candidat souverain.

### B1.3 — whitespace, commentaires et `abi efi_x64` — **GREEN**

- **RED :** commentaire après `format`, ligne vide, tabs, `abi efi_x64`,
  `ABI efi_x64` et `abi sysv` n’ont pas encore les résultats attendus.
- **GREEN minimal :** ajouter espaces/tabs, commentaire `;` hors chaîne et
  seconde ligne sémantique exacte; tout autre ordre devient E200.
- **Preuve :** LF et CRLF donnent la même suite sémantique; casse et ABI erronées
  sont refusées à la première position fautive.
- **Résultat vérifié :** source externe SHA-256
  `144da0a41ba8f272708e81dcc61f48fe55466c5f52661fe1e0fce7da7b435b0c`,
  PE 7 680 octets SHA-256
  `f6e4022ccd1938b680e6eb69f6ecb06518680b9455c940fde2d1bc0b9a082eb2`;
  10/10 cas cœur et 34/34 régressions/frontières passent, sans sortie. Preuve :
  `out/b1/step-3/20260902-185633-f6ba2d902cf048a6a51633dfb7651f77/manifest.md`.
  Ce GREEN ne promeut pas la Gate B1 et ne rend pas NASM souverain.

### B1.4 — identifiant et ponctuation de constante — **GREEN**

- **RED :** `const A = 0`, identifiant de 32 octets, début numérique et caractères
  hors classe ne sont pas distingués.
- **GREEN minimal livré :** sonder optionnellement la prochaine ligne sémantique
  et valider directement dans `SRC` le préfixe `const WS+ IDENT WS? =`, sans
  créer encore de token, descripteur ou symbole. Toute valeur reste B1.5.
- **Preuve :** longueur 31 acceptée, 32 → E101; nom invalide, mot-clé et `=`
  absent → E201; zéro constante et suffixe après `=` restent valides. La limite
  16/17 tokens est déplacée au premier tracer qui tokenise réellement la valeur.
- **Résultat vérifié :** source externe SHA-256
  `9677a83f4ef97ad41d572226dbcfa1b6b231f92f8b79cfe0feadfaaeab460c07`,
  PE 7 680 octets SHA-256
  `f994f31fa718a4ca2456c01ac4320fab1cd828945ad9dd7527c8f3aa08349b70`;
  corpus 12/12, cœur B1.3 10/10 et régressions 34/34. Preuve :
  `out/b1/step-4/20260902-215921-b48ac1a7b2c04c4ea9b9d922948bd75d/manifest.md`.

### B1.5 — entier non signé décimal et hexadécimal — **GREEN**

- **RED :** figer `0`, maximum `u64`, dépassement `u64`, `00`, `0x`, `_`, suffixe
  et chiffre hexadécimal invalide.
- **GREEN minimal :** accumulation checked base 10/16 et insertion d’une constante
  64 bits dans la table linéaire.
- **Preuve :** valeurs limites exactes; aucune troncature; formes interdites →
  E102 au premier octet responsable.
- **Résultat vérifié :** source SHA-256
  `4bd49f49ef29aec677d160e2edb3cb0e7d288d6347430d7280eb3cb69ce943c9`,
  PE SHA-256 `657b3d41dd541cf8630b2b659a29a48c222fc28038516e9e93d176b8db9cadd1`,
  corpus 22/22, snapshot interne et régressions 56/56.

### B1.6 — signe, plage `i64` et doublons — **GREEN**

- **RED :** `-1`, minimum `i64`, magnitude trop grande, `+1`, espace après `-` et
  deux définitions de même casse.
- **GREEN minimal :** appliquer le signe après la magnitude; refuser hors `i64`,
  `+` unaire et doublon constant/constant.
- **Preuve :** complément à deux conservé comme valeur, sans émission; doublon →
  E300 sur la seconde définition.
- **Résultat vérifié :** source SHA-256
  `faa4725d1217d83491cad2c5c0cf8b0db2dc1c6fd8c42b7698bd1c97d696f293`,
  PE SHA-256 `f1246ec2a1922616f9a6031444cb7dde5a8d09083b18effb11cec5ac7bd4f30e`,
  cœur 14/14, snapshots 4/4, B1.5 22/22 et héritage 56/56.

### B1.7 — directive `entry`

- **RED :** `entry start` absent, doublé, avant une constante ou après une section
  ne donne pas encore E200/E302.
- **GREEN minimal :** fermer la phase constantes à l’unique `entry ident` et
  conserver sa tranche de nom pour résolution ultérieure.
- **Preuve :** ordre exact accepté; absence/doublon/mauvais ordre refusés sans
  sortie.
- **État vérifié : GREEN (2026-09-04).** Source SHA-256
  `17c296087c471dda1bbd6bf31a6e03fbac11215802b6bfd2a35990bd28d1c625`,
  PE SHA-256
  `169a362b036edce895c1bf4d523f35ce3966d56e0ba6059c0ba3a2a4571f6702`,
  cœur 19/19, snapshots 7/7 et régressions 14/14 + 22/22 + 56/56.

### B1.8 — section `.text rx`

- **RED :** `.text`, droits `rw`, section dupliquée et statement de donnée dans
  `.text` ne sont pas catégorisés.
- **GREEN minimal :** ajouter tokens de section et état `IN_TEXT`; initialiser
  l'offset de code à zéro et refuser les directives de données avec E202.
  L'avancement de cet offset attend les tracers `align` et instructions.
- **Preuve :** section exacte acceptée; droits ou ordre incorrects → E200;
  mnémonique encore non pris en charge → E400, pas acceptation silencieuse.
- **État vérifié : GREEN (2026-09-04).** Cœur 30/30, cas limites 5/5,
  régressions 111/111, snapshot 2/2; PE 11 264 octets SHA-256
  `dafb0aff3407f48e782599475b8ca7a20727767892561dee0ab419852d61ab3e`,
  reproductible 3/3. Preuve : `out/b1/step-8/promotion-r1/manifest.md`.

### B1.9 — section `.rdata r`

État vérifié : GREEN, cœur 43/43 et régressions 146/146.
Preuve : `out/b1/step-9/promotion-r1/manifest.md`.

- **RED :** transition `.text → .rdata`, droits et duplication ne sont pas
  vérifiés.
- **GREEN minimal :** fermer l'en-tête `.text`, ouvrir `.rdata`, interdire toute
  instruction dans les données.
- **Preuve :** transition et droits exacts; instruction en `.rdata` → E202.
  La non-vacuité du payload texte ne devient vérifiable qu'avec les premiers
  encodeurs : B1.9 accepte encore des préfixes vides sous marqueur temporaire.
  L'exigence normative de sections non vides reste obligatoire avant Gate B1.

### B1.10 — section `.data rw` et fin de grammaire

État vérifié : GREEN, cœur 12/12 et régressions 189/189.
Preuve : `out/b1/step-10/promotion-r1/manifest.md`.

- **RED :** `.data` absente, avant `.rdata`, vide, dupliquée ou suivie d’une
  quatrième section.
- **GREEN minimal :** achever l’automate de sections et contrôler le dernier
  en-tête `.data rw`. Les payloads vides restent provisoires jusqu'aux
  encodeurs, comme dans B1.9; la non-vacuité reste exigée avant Gate B1.
- **Preuve :** chaque section existe exactement une fois et dans l’ordre;
  `.reloc` source est refusée.

### B1.11 — labels et table des symboles

- **RED :** label seul, label+instruction sur la même ligne, label dupliqué et
  collision label/constante ne sont pas résolus.
- **GREEN minimal :** ajouter `ident:` seul, offset relatif de section et bit
  « début d’instruction »; recherche linéaire sensible à la casse.
- **Preuve :** 512 symboles cumulés acceptés, 513e → E500; toute seconde
  définition → E300; aucun octet n’est émis.

### B1.12 — `align`

- **RED :** valeurs 2/4/8/16, 1/32 et alignement débordant n’ont pas de golden.
- **GREEN minimal :** calcul checked du padding minimal; mesure `90` en `.text`,
  zéro dans les données.
- **Preuve :** offsets et padding byte pour byte; directive invalide → E201;
  dépassement de section → E500.

### B1.13 — directive `byte`

- **RED :** liste séparée par virgules, constante, valeurs `255`, `256`, `-128`,
  `-129`, virgule finale et nom de label nu.
- **GREEN minimal :** ajouter `byte` et la liste scalaire; résoudre seulement les
  constantes et appliquer les plages signée/non signée sans troncature.
- **Preuve :** octets exacts; mauvaise catégorie → E301; plage → E401; syntaxe →
  E201.

### B1.14 — `word`, `dword`, `qword` et alignement naturel

- **RED :** maxima/minima de largeur et départs non alignés n’ont pas leurs
  diagnostics.
- **GREEN minimal :** réutiliser le scalaire pour 2/4/8 octets little-endian;
  vérifier l’alignement naturel avant mesure et émission.
- **Preuve :** limites signées et non signées exactes; mauvais alignement → E402;
  aucun alignement implicite.

### B1.15 — chaînes et `ascii`

- **RED :** guillemet non fermé, `;` dans une chaîne, échappements permis,
  `\xHH` incomplet/invalide et chaîne décodée trop longue.
- **GREEN minimal :** lexer chaîne sur une ligne, scratch borné et émission
  `ascii` sans terminaison.
- **Preuve :** chaque échappement produit les octets normatifs; inconnu → E102;
  longueur 1 024 acceptée et 1 025 → E101.

### B1.16 — `utf16z` et `zero`

- **RED :** ASCII 0x7F/0x80 décodé, terminaison, `zero 0`, frontière de section et
  multiplication de taille ne sont pas contrôlés.
- **GREEN minimal :** élargir chaque byte ASCII en code unit UTF-16LE, ajouter
  zéro terminal et ajouter exactement `n` zéros avec calcul checked.
- **Preuve :** payload UTF-16 exact; `\x80` dans `utf16z` → E201;
  `zero 0` → E201; dépassement → E500.

### B1.17 — registres et adressage base/index

- **RED :** 16 GPR, SIB obligatoire, `rbp/r13+0`, index `rsp/r12`, échelles et
  déplacements limites n’ont pas de descripteur canonique.
- **GREEN minimal :** mapper les registres 0..15 et produire un plan mémoire
  base/index/scale/disp sans opcode. RIP reste volontairement rouge ici.
- **Preuve :** goldens ModRM/SIB/REX pour toutes les bases; `i8` puis `i32`
  choisis canoniquement; index ou forme interdite → E402.

### B1.18 — noyau d’instructions registre/immédiat

- **RED :** goldens de `mov`, `push`, `pop`, `call rs`, `ret`, `nop` et formes
  d’opérandes invalides.
- **GREEN minimal :** ajouter ces mnémoniques au planificateur commun mesure/emit,
  dont `mov rd,imm64` toujours long et REX.B conditionnel sur pile/appel indirect.
- **Preuve :** octets exacts, nombre d’opérandes strict, mnémonique inconnu → E400.

### B1.19 — `lea`, loads et stores

- **RED :** vecteurs `lea`, `load8/16/32/64`, `store8/16/32/64`, dont les cas
  `rsp`, `r13`, registres étendus et mauvais ordre d’opérandes.
- **GREEN minimal :** connecter le plan mémoire aux opcodes et règles REX; RIP
  reste rouge jusqu’à B1.22.
- **Preuve :** notamment `load16 r9,[r13] = 45 0F B7 4D 00`, sans `66`, et
  `store16` avec `66 REX 89`; aucun opcode équivalent accepté.

### B1.20 — ALU, test, shifts et multiplication

- **RED :** chaque forme registre/immédiat de `add`, `sub`, `and`, `or`, `xor`,
  `cmp`, plus `test`, `shl`, `shr`, `imul`, plages et arités invalides.
- **GREEN minimal :** ajouter une sous-famille à la fois, chaque sous-famille
  faisant son propre micro-cycle RED → GREEN avant la suivante.
- **Preuve :** opcodes/extensions ModRM exacts; imm32 signé, shift 0..63;
  aucun raccourci imm8 ou encodage heuristique.

### B1.21 — branches, `call label` et fixups

- **RED :** références avant/arrière, symbole absent, constante utilisée comme
  label, cible hors `.text`, 2 049e fixup et `rel32` hors plage.
- **GREEN minimal :** ajouter `call`, `jmp`, `je`, `jne`, `jb`, `jae` label,
  enregistrements pass 1 et résolution `rel32` pass 2.
- **Preuve :** branche à l’octet suivant et boucle golden exactes; catégorie →
  E301, plage → E401, limite → E500.

### B1.22 — RIP, `addr(label)` et `.reloc`

- **RED :** `[rip + label]` avant/arrière, `addr` ailleurs que qword aligné,
  absence de relocation, changement de page, doublon et 513e relocation.
- **GREEN minimal :** ajouter fixup RIP toutes sections, qword absolu préféré et
  blocs `DIR64` triés; émettre le padding `ABSOLUTE` seulement si requis.
- **Preuve :** relocation minimale exacte
  `00 20 00 00 0C 00 00 00 00 A0 00 00`; absence → E602, alignement → E402,
  limite → E500.

### B1.23 — deux passes complètes et limites globales

- **RED :** instrumenter les compteurs pour provoquer une divergence de taille,
  token count, fixups et sections; figer chaque maximum de ressource et son
  premier octet excédentaire.
- **GREEN minimal :** intégrer signatures de lignes, remise à zéro complète de
  pass 2, comparaisons finales et tous les helpers checked.
- **Preuve :** divergence → E600; chaque limite exacte est acceptée sauf source
  65 536; chaque `+1` → E500/E601; canaris intacts.

### B1.24 — writer `B1-PE-v1` en mémoire

- **RED :** le golden minimal n’a pas encore un fichier `0xC00` exact; chaque
  mutation d’un offset d’en-tête doit être détectée par le comparatif attendu.
- **GREEN minimal :** zéroter la taille finale, écrire DOS/COFF/Optional Header,
  directories, section headers, payloads et paddings par offsets checked; lancer
  l’auto-vérification avant toute I/O de sortie.
- **Preuve :** comparaison byte pour byte du golden, inspection PE à `0x80`,
  quatre sections, seul directory 5 non nul, aucune W+X/import/overlay;
  `SizeOfImage` et fichier maximaux respectent `0x10000`/`0xF400`.

### B1.25 — commit fichier, diagnostics et fautes I/O

- **RED :** sortie préexistante sentinelle, média sans espace pour un write
  complet, erreur Flush/Close observable et succès prématuré.
- **GREEN minimal :** ajouter probe READ, création exclusive logique, Write exact,
  Flush, Close, cleanup central et table complète E001..E702. Le succès normatif
  reste désactivé.
- **Preuve :** préexistante → E700 et hash inchangé; impossibilité de créer →
  E701; taille rendue courte ou Write/Flush/Close en erreur → E702, aucun marqueur
  de succès. La courte écriture est provoquée sur un volume FAT jetable à espace
  libre borné et le `UINTN` retourné est consigné; aucun disque utilisateur n’est
  exposé. Les injections contrôlées de corruption canari et de faute
  `FreePool` sont réservées à ce tracer : elles prouvent respectivement E603
  prioritaire et E604 seulement en l’absence de diagnostic antérieur.

### B1.26 — conformance complète et promotion Gate B1

- **RED :** avant promotion, au moins un élément de la checklist finale manque;
  le marqueur `NG_NTASM_S0_OK` est absent par conception.
- **GREEN minimal :** supprimer tous les marqueurs temporaires, activer le seul
  succès final après `OUTPUT_CLOSED`, `root` fermé, pools libérés et
  auto-vérification verte; appeler `Exit(ImageHandle, EFI_SUCCESS, 0, NULL)`.
- **Preuve :** corpus complet, goldens, deux runs reproductibles sur volumes et
  variables OVMF frais, chargement relogé réel, ledger/hash/manifest concordants.
  **Ce tracer est le seul autorisé à annoncer “Gate B1 GREEN”.**

## 12. Invariants continus

Ces propriétés sont rejouées à chaque tracer, pas ajoutées à la fin :

- aucun accès à `SRC`, `WORK` ou `OUT` hors intervalle;
- aucun module ne reçoit les pointeurs bruts des pools et `FreePool` ne reçoit
  jamais un pointeur intérieur;
- WORK ne contient aucune copie autoritative du masque d’ownership ou des
  pointeurs raw/payload; le cleanup consulte exclusivement les slots de pile;
- les six bandes canari sont intactes avant libération; toute corruption est
  E603 à position nulle;
- un échec `FreePool` sans diagnostic antérieur est E604 à position nulle; un
  diagnostic antérieur reste prioritaire sauf si E603 est détecté;
- toute addition, multiplication, négation, conversion et `align_up` vérifiée
  avant l’opération;
- aucun pointeur UEFI déréférencé avant test non nul;
- aucun handle perdu et aucun pool dépendant de données source;
- aucune sortie ouverte avant pass 1, layout, pass 2 et auto-vérification verts;
- première erreur au plus petit offset source et diagnostic byte-stable;
- aucune troncature d’entier, déplacement ou taille;
- symboles en ordre de définition, relocations en ordre RVA, aucune source de
  non-déterminisme;
- `.text` RX, `.rdata` R, `.data` RW, `.reloc` R/discardable; aucune W+X;
- aucun import, overlay, réseau, MMIO, DMA, port I/O, variable d’environnement,
  ligne de commande ou chemin fourni par la source;
- aucune écriture sur matériel réel; QEMU/OVMF et images jetables seulement;
- aucun producteur externe dans le résultat final; l'exception NASM active de
  l'ADR 0009 est limitée aux candidats intermédiaires quarantainés et doit être
  fermée avant la Gate B1;
- seed final et image produite inférieurs ou égaux à 64 Kio;
- tout octet du seed final appartient à un module et à une ligne du ledger.

## 13. Critères de promotion de B1

B1 est GREEN si et seulement si toutes les preuves suivantes existent dans un
manifeste canonique unique :

1. le seed final fait au plus `65 536` octets; son SHA-256 correspond au ledger,
   qui couvre `0..taille-1` sans trou, chevauchement ni rôle « inconnu »;
2. le budget réel par module est consigné et le total respecte le plafond;
3. inventaire des producteurs : aucun compilateur, assembleur, linker ou
   générateur PE étranger n’a créé un octet du seed ou des sorties attendues;
4. source vide, 65 535, 65 536 octets, 4 096/4 097 lignes, 255/256 octets par
   ligne et toutes les limites de tables ont leurs preuves frontière et `+1`;
5. le corpus négatif minimal complet et un fuzz manuel déterministe par mutations
   d’un octet retournent le code, la position et le statut attendus sans créer de
   sortie; chaque mutation et son résultat sont consignés;
6. les 30 mnémoniques, toutes leurs formes, les adressages et les directives ont
   des goldens positifs et des contre-exemples;
7. les vecteurs d’encodage normatifs et le golden PE minimal sont identiques
   byte pour byte aux spécifications;
8. les deux passes relisent le même buffer, leurs signatures et compteurs sont
   égaux, et une divergence injectée produit E600;
9. sortie préexistante inchangée, création impossible, write court, Flush et
   Close en erreur sont exercés sans faux succès;
10. une inspection indépendante du seed final et de la sortie confirme PE à
    `0x80`, quatre sections, seul le répertoire Base Relocation non nul, aucune
    importation, W+X ou overlay;
11. une sortie B1 est chargée par OVMF à une adresse différente de
    `0x0000000140000000`; une fixture compare à l’exécution son ancre relogée avec
    une adresse RIP réelle avant d’afficher son marqueur, et la trace du loader
    consigne la base effective;
12. deux boots à froid avec deux magasins de variables et deux volumes de sortie
    frais produisent le même hash de `NTASM1.EFI`, exactement une ligne
    `NG_NTASM_S0_OK`, puis rendent proprement la main au firmware via `Exit`;
13. aucun marqueur temporaire (`NG_B1_1_FORMAT_OK` ou `NG_S0_Tnn_OK`) ne subsiste et le succès apparaît
    seulement après `Flush`, fermeture de tous les handles et libération des
    pools;
14. `MEM.md` n’est mis à jour vers B1 GREEN qu’après revue du manifeste, du
    ledger, des hashes, des transcripts, de l’inspection PE et des deux runs.

Si un seul point manque, le résultat reste « tracer B1.x GREEN, Gate B1 RED ».
La prochaine étape demeure ce point manquant; B2 ne commence pas.
