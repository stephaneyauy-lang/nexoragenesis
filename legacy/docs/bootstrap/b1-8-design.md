# B1.8 — ouverture de la section `.text rx`

Statut : **tracer B1.8 GREEN** (4 septembre 2026). Ce tracer ouvre
la section texte, mais n'implémente encore ni label, ni `align`, ni instruction,
ni émission d'octet. La Gate B1 reste RED.

## Portée exacte

Après le préambule B1.7 terminé par l'unique `entry IDENT`, B1.8 exige la
prochaine ligne sémantique exacte :

```text
section WS+ .text WS+ rx
```

Les trois tokens sont sensibles à la casse. Il n'existe aucun quatrième token.
Les lignes vides et commentaires avant ou après cette ligne restent ignorés.
Un EOF avant l'en-tête est une erreur; un EOF après l'en-tête donne le succès
temporaire B1.8.

Cette acceptation d'une `.text` sans payload est volontairement provisoire. Le
profil final exige les trois sections non vides, mais aucun statement capable de
mesurer ou d'émettre du code n'existe à B1.8. Le tracer ne prétend donc pas
valider une source NTASM-S0 complète.

## Automate de lignes

Les états logiques sont :

```text
EXPECT_FORMAT(0) -> EXPECT_ABI(1) -> CONST_OR_ENTRY(2)
                 -> EXPECT_TEXT(3) -> IN_TEXT(4)
```

`EXPECT_TEXT` remplace l'ancien état terminal `AFTER_ENTRY` de B1.7 :

- EOF produit E200 à l'EOF virtuel;
- `section .text rx` exact initialise `TEXT_OFFSET` à zéro et entre dans
  `IN_TEXT`;
- tout mauvais mot d'ordre ou de valeur produit E200 au début du premier token
  faux;
- un token obligatoire absent ou un token supplémentaire produit E201;
- un séparateur `WS+` absent mais reconnaissable produit E201 à l'octet où le
  séparateur devait commencer.

Dans `IN_TEXT` :

- EOF produit T08;
- `section`, `format`, `abi`, `const` ou `entry` au premier identifiant exact
  produit E200 au début de la ligne; cela couvre la duplication `.text`, la
  transition `.rdata` encore prématurée et `.reloc` interdite dans la source;
- `byte`, `word`, `dword`, `qword`, `ascii`, `utf16z` ou `zero` au premier
  identifiant exact produit E202 au début de la ligne;
- tout autre premier identifiant, dont un label, `align` ou un mnémonique,
  produit provisoirement E400 au début de la ligne.

E400 sur un label ou `align` est une classification locale au tracer : B1.11 et
B1.12 la remplaceront par leur comportement normatif. B1.8 ne consomme ni ne
valide les opérandes du corps. Il n'accepte silencieusement aucun statement.

## Lexer borné de l'en-tête

Seule la ligne d'en-tête `.text` reçoit à B1.8 la tokenisation complète :

- au plus 16 tokens;
- identifiant au plus 31 octets;
- les tokens sont des tranches du buffer `SRC`, sans copie autoritative;
- le lexer parcourt la ligne entière avant le parseur, donc le 17e token ou le
  32e octet d'un identifiant produit E101 avant un éventuel E200/E201.

Une ligne avec exactement 16 tokens atteint le parseur et produit E201 au début
du quatrième token. Le premier identifiant de 31 octets est lexicalement valide
puis produit E200; son 32e octet produit E101.

Les limites physiques déjà prouvées restent héritées : ASCII, EOL final, ligne
de 255 octets et source bornée. En revanche, B1.8 ne promet pas E101 pour un 17e
token situé dans une ligne de corps, car seuls son premier identifiant et sa
catégorie sont observés à ce tracer.

Cas adjacents figés :

- `section.text rx` reconnaît l'absence de `WS+` après `section` et produit E201
  sur le point;
- `section .textrx` forme un seul second token faux et produit E200 au début de
  `.textrx`; l'intention d'un séparateur est indécidable;
- `section .text, rx` reconnaît un troisième token adjacent et produit E201 sur
  la virgule faute de `WS+`.

## État interne minimal

Le descripteur `entry` de cinq qwords reste strictement immuable :

| Offset cadre | Champ conservé |
|---:|---|
| `+0x0E8` | `ENTRY_SEEN` |
| `+0x0F0` | `ENTRY_NAME_OFF` |
| `+0x0F8` | `ENTRY_NAME_LEN` |
| `+0x100` | `ENTRY_LINE` |
| `+0x108` | `ENTRY_LINE_START` |

Le slot mort après la fermeture des constantes devient :

| Offset cadre | Alias B1.8 | Valeur |
|---:|---|---:|
| `+0x110` (`F_CONST_META`) | `F_TEXT_OFFSET` | `0` |

`IN_TEXT=4` est un état de contrôle à sens unique; aucun autre stockage n'est
requis. `TEXT_OFFSET` n'avance jamais dans ce tracer. Dire qu'il « compte les
offsets de code » serait faux sans encodeur : le premier avancement réel est
reporté aux tracers qui mesurent `align` et les instructions.

Le snapshot positif B18-C01 porte sur six qwords little-endian dans l'ordre
`seen, entry_off, entry_len, entry_line, entry_line_start, text_offset` :

```text
01 00 00 00 00 00 00 00 34 00 00 00 00 00 00 00
08 00 00 00 00 00 00 00 06 00 00 00 00 00 00 00
2E 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
```

SHA-256 attendu des 48 octets :
`42555b52fd6769db515d3490b1aeb228733a2bc48cf34c7edb04de8517541172`.

## Diagnostics et EOF

Les positions restent ligne/colonne 1-based et offset byte 0-based.

- mauvais premier, deuxième ou troisième token : E200 au début de ce token;
- token obligatoire absent : E201 à la fin logique exclusive de la ligne;
- quatrième token : E201 au début du quatrième token;
- directive de données dans `.text` : E202 au début du premier token;
- statement texte non encore pris en charge : E400 au début du premier token;
- EOF dans `EXPECT_TEXT` : E200 à `L=lignes_physiques+1`, `C=1`,
  `O=taille_source`;
- EOF dans `IN_TEXT` : succès temporaire exact `NG_S0_T08_OK\r\n`, une fois.

Les diagnostics rendent `EFI_LOAD_ERROR`; T08 rend `EFI_SUCCESS`. Diagnostic et
succès ne créent ni ne sondent `NTASM1.EFI`. T08 n'apparaît qu'après validation
du descripteur `entry`, de `TEXT_OFFSET=0`, des canaris et du cleanup. Aucun
ancien T05, T06 ou T07 ne l'accompagne.

## Frontière B1.9 et non-objectifs

B1.9 introduira seulement la reconnaissance de la transition `.text -> .rdata`
et son droit `r`; B1.8 la refuse donc encore avec E200. L'exigence de payload
`.text` non vide ne peut pas être honnêtement prouvée avant un statement
émetteur. Elle doit rester explicitement reportée au premier tracer d'encodage,
sans transformer une ligne inconnue en octets fictifs.

Labels, symboles de label, résolution de `entry`, `align`, instructions,
planification x86_64, taille de code non nulle, `.rdata`, `.data`, deux passes,
layout PE et écriture de sortie sont hors périmètre.

Le corpus byte-exact et les oracles RED sont définis par
[`b1-8-fixtures.md`](../../ntasm-s0/b1-8-fixtures.md).

## Résultat vérifié

Source : 69 010 octets, SHA-256
`7ae2e397cf8b260535511e2c1d25da3549a54670b68bcd5c8fb4238230c4078d`.
PE externe : 11 264 octets, SHA-256
`dafb0aff3407f48e782599475b8ca7a20727767892561dee0ab419852d61ab3e`.
RED 35/35 divergences saines; GREEN cœur 30/30, cas limites 5/5,
régressions 111/111 et snapshot 2/2. Trois reconstructions sont bit-identiques.
Le binaire reste dans la quarantaine NASM; Gate B1 reste RED.
Le protocole est [`b1-8-test-protocol.md`](../../../docs/testing/b1-8-test-protocol.md);
la preuve canonique est `out/b1/step-8/promotion-r1/manifest.md`.
