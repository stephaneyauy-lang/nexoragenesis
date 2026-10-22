# B1.6 — signe, plage négative et doublons de constantes

Statut : **tracer B1.6 GREEN**. Gate B1 reste RED.

## Portée

B1.6 conserve intégralement B1.5 et ajoute uniquement :

```text
signed-integer = unsigned-integer | "-", unsigned-integer ;
```

Le `-` doit être immédiatement suivi du premier octet de l'entier non signé.
SP ou TAB après `-` produit E102 sur ce whitespace. Un `-` suivi de la fin
logique de ligne produit E102 à cette fin. Le `+` unaire reste interdit et
produit E201 sur `+`, qui demeure un token de ponctuation.

La grammaire interne de la magnitude reste celle de B1.5. Les formes décimales
et hexadécimales invalides conservent E102 sur le premier octet responsable.

## Valeur et plage

Les constantes sans signe conservent la plage complète `0..u64::MAX`. Pour une
forme avec `-`, la magnitude doit être inférieure ou égale à
`0x8000000000000000`. La valeur stockée est :

```text
bits = (0 - magnitude) modulo 2^64
```

Donc `-1` stocke `0xFFFFFFFFFFFFFFFF` et le minimum `i64` stocke
`0x8000000000000000`. `-0` est accepté : ses bits valent zéro, mais son flag
NEGATIVE reste présent afin de conserver le signe lexical.

La borne est appliquée pendant l'accumulation de magnitude afin de positionner
E102 sur le premier chiffre qui dépasse `2^63`, jamais sur le signe.

## Record de symbole

Le layout B1.5 reste inchangé :

| Offset | Taille | Champ |
|---:|---:|---|
| `+0x00` | 32 | nom, NUL terminal puis zero-fill |
| `+0x20` | 8 | bits de valeur `u64` little-endian |
| `+0x28` | 4 | offset source du début de l'identifiant |
| `+0x2C` | 2 | ligne 1-based |
| `+0x2E` | 2 | kind/section/flags little-endian |

La constante positive utilise meta `0x0001`. Une forme avec `-`, y compris
`-0`, utilise meta `0x0011`, où le bit 4 est NEGATIVE. La table reste à
`WORK+0x400`, 512 records de 48 octets, et `symbol_count u32` reste à
`WORK+0x000`.

## Doublons et atomicité

La recherche est linéaire sur les records déjà validés. Elle compare exactement
la longueur et les octets ASCII du nom, sans normalisation de casse.

- `A` puis `A` produit E300 au début du second identifiant ;
- `A` puis `a` insère deux records distincts ;
- la valeur ou le signe ne participent pas à l'identité du symbole.

L'ordre d'une définition valide est : validation complète, recherche de doublon,
contrôle de capacité, écriture complète du record, puis incrément du compteur.
La recherche de doublon précède le contrôle 512/513 : une redéfinition parmi 512
records reste E300, tandis qu'un 513e nom nouveau reste E500. Toute erreur laisse
le compteur et le slot suivant inchangés.

## Contrat observable

Le succès temporaire devient exactement `NG_S0_T06_OK\r\n`, une seule fois,
après canaris et cleanup, avec `EFI_SUCCESS`. Les diagnostics sont uniques et
retournent `EFI_LOAD_ERROR`. Le tracer ne crée, ne sonde et n'émet jamais
`NTASM1.EFI`.

## Non-objectifs

`entry`, sections, labels, résolution, directives, instructions, émission PE et
NTASM v0 général restent hors de B1.6.

## Promotion exécutée

Le contrat est validé sur le candidat de 9 216 octets, SHA-256
`f1246ec2a1922616f9a6031444cb7dde5a8d09083b18effb11cec5ac7bd4f30e`.
La campagne B16 passe 14/14, les quatre snapshots pré-cleanup passent 4/4,
le corpus B1.5 remappé passe 22/22 et les régressions héritées passent 56/56.
NASM 2.16.01 reproduit le PE bit pour bit 3/3. L'audit source et PE est
approuvé : imports nuls, aucune section W+X, aucun overlay et relocation DIR64.

Preuve canonique :
`out/b1/step-6/20260902-232720-a7d45bf179a546f4a03691f6f2cdde34/manifest.md`.
La prochaine étape est B1.7 ; cette promotion ne termine pas la Gate B1.
