# B1.7 — directive `entry`

Statut : **tracer B1.7 GREEN, Gate B1 RED**. Le contrat a été figé avant
code et sa campagne RED reste conservée. Le source final du tracer fait 51 602
octets, SHA-256
`17c296087c471dda1bbd6bf31a6e03fbac11215802b6bfd2a35990bd28d1c625`;
son PE externe quarantainé fait 9 728 octets, SHA-256
`169a362b036edce895c1bf4d523f35ce3966d56e0ba6059c0ba3a2a4571f6702`.

## Portée exacte

Après `format pe64`, `abi efi_x64` et zéro ou plusieurs lignes `const` B1.6,
B1.7 exige exactement une ligne sémantique :

```text
entry WS+ IDENT
```

`IDENT` vaut `[A-Za-z_][A-Za-z0-9_]{0,30}`. Sa casse et ses octets source
sont conservés exactement. `entry` est obligatoire, unique et ferme
définitivement la phase des constantes.

À ce tracer, `entry` est une référence, jamais une définition :

- elle n'est pas insérée dans la table des constantes et ne consomme pas le
  quota de 512 symboles ;
- aucune recherche de cible ou vérification de catégorie n'est exécutée ;
- `const start = 0` suivi de `entry start` est donc accepté ;
- la résolution vers un label `.text` placé au premier octet d'une instruction
  reste explicitement différée aux tracers de labels/instructions ;
- aucun E301 ni E302 de mauvaise catégorie/cible n'est produit à B1.7.

Les lignes vides, commentaires, LF/CRLF et SP/TAB conservent le sens B1.6. Les
mots-clés exacts `const` et `entry` ne sont pas acceptés comme identifiants
cibles ; ils produisent E201 au début du second token.

## Automate de lignes

```text
EXPECT_FORMAT -> EXPECT_ABI -> CONST_OR_ENTRY -> AFTER_ENTRY
```

Dans `CONST_OR_ENTRY` :

- `const` exact est analysé par le contrat B1.6 et l'état reste inchangé ;
- `entry` exact est analysé, sa tranche est conservée, puis l'état devient
  `AFTER_ENTRY` ;
- EOF produit E302 à l'EOF virtuel ;
- toute autre ligne sémantique, dont `section`, produit E200 sur son premier
  octet sémantique.

Dans `AFTER_ENTRY` :

- EOF produit le succès temporaire T07 ;
- une nouvelle ligne `entry` ou `const` produit E200 au premier octet
  sémantique ;
- toute autre ligne est la frontière du tracer et produit T07 sans être
  interprétée. Ainsi `section .text rw` après l'entrée reste volontairement
  accepté par B1.7 ; les sections et leurs droits commencent à B1.8.

La première erreur dans l'ordre des octets gagne. Une section avant l'entrée
est donc E200 à la section, jamais E302 à l'EOF.

## État d'entrée implémenté

Le descripteur reste séparé des records de constantes. Il recycle cinq slots
contigus du cadre B1.6 devenus morts une fois la phase des constantes fermée ;
tous les champs sont des qwords little-endian :

| Offset cadre | Champ | Domaine |
|---:|---|---|
| `+0x0E8` (`F_CONST_NAME_PACK`) | `ENTRY_SEEN` | `0` ou `1` |
| `+0x0F0` (`F_TOKEN_START`) | `ENTRY_NAME_OFF` | offset absolu 0-based dans `SRC` |
| `+0x0F8` (`F_TOKEN_END`) | `ENTRY_NAME_LEN` | `1..31` |
| `+0x100` (`F_EXTRA_START`) | `ENTRY_LINE` | ligne physique 1-based |
| `+0x108` (`F_AFTER_START`) | `ENTRY_LINE_START` | offset du premier octet de la ligne |

`F_CONST_META` à `+0x110` reste libre et `FRAME_SIZE` reste exactement `0x118` :
cette conservation maintient l'alignement Win64 existant après les huit pushes
du prologue B1.6. La tranche autoritative est exclusivement
`SRC[ENTRY_NAME_OFF .. ENTRY_NAME_OFF + ENTRY_NAME_LEN)`. Elle n'est jamais
recopiée dans un buffer NUL-terminal. Avant T07 :

```text
ENTRY_SEEN == 1
1 <= ENTRY_NAME_LEN <= 31
ENTRY_NAME_OFF < SOURCE_LEN
ENTRY_NAME_OFF + ENTRY_NAME_LEN <= SOURCE_LEN
ENTRY_NAME_OFF >= ENTRY_LINE_START
```

Les 40 octets attendus du descripteur sur les six cas positifs sont :

| Cas | `off,len,line,line_start` | SHA-256 des 40 octets |
|---|---|---|
| C00 | `30,5,3,24` | `63b591b19a9108385e29c113dd8e671153fd2783a350f48af8a5ac9f0635d255` |
| C01 | `60,5,5,54` | `43f061353d87f907c9a171240d025ccf31bfeb67ed86a3a8b394c41f1c8ecacd` |
| C02 | `30,31,3,24` | `e17d495fd14678c4d5df7431ef1382417a140a123bf3421a5601260597286f57` |
| C03 | `45,8,4,39` | `d441297ed1a0134743b4299492170866f8b0ab82f71a18f524da1918b130488c` |
| C04 | `46,5,4,40` | `2f21dd1b188cf0b6215dfbc83148bf32cb2374d4952ffb84251ed565b4057611` |
| C05 | `30,5,3,24` | `63b591b19a9108385e29c113dd8e671153fd2783a350f48af8a5ac9f0635d255` |

Chaque hash porte sur la concaténation qword LE
`seen=1, off, len, line, line_start`. La campagne RED ne revendiquait pas cette
preuve mémoire; les snapshots du GREEN final la vérifient.

Correction contractuelle du 4 septembre 2026 : la première table comptait par
erreur un octet de trop pour `C01`. La fixture byte-figée n'a pas changé : sa
ligne `entry` commence à l'offset 54 et `start` à l'offset 60. Le premier boot
du probe snapshot a détecté ce décalage par E603 avant toute correction du
golden.

## Diagnostics et résultat observable

- entrée absente à EOF : E302 à `L=lignes_physiques+1`, `C=1`,
  `O=taille_source` ;
- doublon, constante après l'entrée ou section avant l'entrée : E200 au premier
  octet sémantique fautif ;
- syntaxe `entry`, identifiant invalide ou token supplémentaire : E201 au
  premier octet responsable ;
- 17e token d'une ligne `entry` : E101 sur le début de ce token, avant E201 ;
- 32e octet d'un identifiant : E101 sur cet octet ;
- faux mot-clé `entrystart` : E200 au début de la ligne.

Le succès temporaire exact est `NG_S0_T07_OK\r\n`, une fois, seulement après
validation du descripteur, canaris intacts et cleanup réussi. Aucun ancien T04,
T05 ou T06 ne peut accompagner T07. Succès et erreurs ne créent ni ne sondent
`NTASM1.EFI`.

## Non-objectifs

Sections, labels, résolution de symboles, directives, instructions, émission PE
et toute modification ASM sont hors périmètre. Le corpus byte-exact est défini
par [`b1-7-fixtures.md`](../../ntasm-s0/b1-7-fixtures.md), et son
exécution par [`b1-7-test-protocol.md`](../../../docs/testing/b1-7-test-protocol.md).

## Exécution GREEN vérifiée — 2026-09-04

Le cœur final passe 19/19, les six descripteurs et le contrôle canonique
passent 7/7, B1.6 passe 14/14, B1.5 passe 22/22 et l'héritage passe 56/56.
Les trois reconstructions NASM 2.16.01 sont bit-identiques. L'audit confirme
PE32+ AMD64 EFI, quatre sections, import/W+X/overlay nuls et relocation DIR64.
La preuve canonique est
`out/b1/step-7/20260904-204749-9790129aa52c4ec2995080290bf5a7d7/manifest.md`.

Ce GREEN ne prouve ni sections, labels, instructions, émission d'un PE de
sortie, auto-hébergement ou OS. La prochaine étape est B1.8.
