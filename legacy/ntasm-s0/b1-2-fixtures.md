# Manifeste de recettes — fixtures physiques B1.2

## Statut et matérialisation

Ce manifeste a figé les octets avant tout code B1.2. Les 24 recettes ont ensuite
été matérialisées byte pour byte pour les campagnes RED et GREEN, sans ajouter
de générateur persistant. Elles restent des définitions de données, jamais du
code producteur. La campagne GREEN est sous
`out/b1/step-2/20260902-172215-65d1b7dcff08475a974763b49f036e46/green-matrix-24/`.

Lors d'un run, chaque recette est matérialisée byte pour byte dans un volume EFI
jetable sous `\NTASM1.NTASM`. Une copie de travail porte uniquement l'extension
`.ntasm` ou `.data`. Aucun script, source hôte ou exécutable générateur
n'appartient au corpus. `.ntasm` désigne de l'ASCII contrôlé ; `.data` désigne
une suite brute, vide, trop grande ou contenant un octet interdit.

## Notation byte-exacte

- `P` = les douze octets ASCII `format pe64` puis LF, soit
  `66 6F 72 6D 61 74 20 70 65 36 34 0A` ;
- `M` = le fichier existant `golden/minimal.ntasm` ;
- `A` = `41` ; `TAB` = `09` ; `LF` = `0A` ; `VT` = `0B` ; `CR` = `0D` ;
  `SP` = `20` ; `TILDE` = `7E` ; `DEL` = `7F` ; `NUL` = `00` ;
- `X^n` = exactement `n` répétitions de la suite X ;
- `A || B` = concaténation sans séparateur ;
- aucune recette n'ajoute BOM, conversion d'encodage, CRLF ou EOL implicite.

Autorités existantes :

| Symbole | Taille | SHA-256 |
|---|---:|---|
| `P` | 12 | `f6b71ed6b75803e8afc95684380526f8646d5e3afa42f0e27434f1b805526770` |
| `M` | 169 | `70bbe78ab101cfea36157ac0dbb228e6d8946a02216fceb65823a27cfb434e12` |

Toute modification de `P` ou `M` invalide les hashes dérivés. Les attentes ne
sont jamais remplacées automatiquement par le résultat d'un corpus divergent.

## Inventaire canonique

Les chemins `physical/...` sont des noms logiques de copies de travail. Aucun de
ces fichiers n'est créé par ce manifeste.

| ID | Chemin logique ou existant | Recette exacte | Taille | SHA-256 |
|---|---|---|---:|---|
| B12-00 | `physical/empty.data` | suite vide | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| B12-01 | `golden/minimal.ntasm` | `M` | 169 | `70bbe78ab101cfea36157ac0dbb228e6d8946a02216fceb65823a27cfb434e12` |
| B12-02 | `physical/source-65535.ntasm` | `P || ((A^255) || LF)^255 || (A^242) || LF` | 65 535 | `2770e746f57b88fefd3c53bbbb4ddb0ca772ec02c56cc917b4b8cc2dbc6b98fb` |
| B12-03 | `physical/source-65536.data` | B12-02 `|| LF` | 65 536 | `c791bded6e8b82457c7b9273f9d1710ba21517af792e5d607173914b3becb8e8` |
| B12-04 | `physical/nul.data` | `P || NUL || LF` | 14 | `71815b8e55b4d9f87d504593eb13e667424d56e637bf63584f471072b740ee21` |
| B12-05 | `physical/bom.data` | `EF BB BF || P` | 15 | `c643e9aa2c4e181c5b638ed8cd767bc9f3dcbb1db4c559df68eeb4e6b50957cd` |
| B12-06 | `physical/non-ascii.data` | `P || 80 || LF` | 14 | `eeba642a1a0e74840087205cf8b55615ffe9a9a5ebd1834420d931940b5c0c76` |
| B12-07 | `physical/isolated-cr.data` | `P || CR || 58 || LF` | 15 | `1654d846a5163d6a579f347d5f84fef751c29a72573f7cc6cf33215a7dff165d` |
| B12-08 | `physical/line-255.ntasm` | `P || A^255 || LF` | 268 | `a04710d7520388ffd0a25e26cbe7585c8066e905d2af7656fb028c759d0ed7f3` |
| B12-09 | `physical/line-256.ntasm` | `P || A^256 || LF` | 269 | `30e787286702e24c6e98b6ece43ddb100d9599e3283ef39a757fb71e15138584` |
| B12-10 | `physical/lines-4096.ntasm` | `P || LF^4095` | 4 107 | `eb23bcd7b17234917a21a229b8798df98dec448a7b8aec4c722e244a43676850` |
| B12-11 | `physical/lines-4097.ntasm` | `P || LF^4096` | 4 108 | `3a5ae20e152298a466d96ee4a1dbde5cc612ad5934cda43e8347838e1d03ab2c` |
| B12-12 | `invalid/no-eol.ntasm` | onze octets ASCII `format pe64`, sans EOL | 11 | `6ce8aebe99508d45ecc1f909e768ad6ce85172d3807d248cb6b0bcecde6aabf0` |
| B12-13 | `physical/terminal-cr.data` | `P || CR` | 13 | `dfcf54fdb75a0fba2ca63014a1fa77c3e57f5a33ce4f6466568dbc1ec0ef503b` |
| B12-14 | `physical/bom-ef.data` | `EF` | 1 | `4d4d75d742863ab9656f3d5f76dff8589c3922e95a24ea6812157ffe4aaa3b6b` |
| B12-15 | `physical/bom-ef-bb.data` | `EF BB` | 2 | `f257f0501a5e137710e26f1c35ddd32ce2b5752f20274a648cb6d0347849a5a9` |
| B12-16 | `physical/tab.ntasm` | `P || TAB || LF` | 14 | `c28f9cdc818395b2c21012b86580bb2827ee972567814c266a44621cb441b68f` |
| B12-17 | `physical/ascii-20.ntasm` | `P || SP || LF` | 14 | `8a274d410f8f8cbb8aecef15c709c606c3c1d34b43d66845f6db709fdbd780ce` |
| B12-18 | `physical/ascii-7e.ntasm` | `P || TILDE || LF` | 14 | `b8bb6d3291d4e5d5a2545b96e14b24b80740827e14fad406e68c38af40ed3ab5` |
| B12-19 | `physical/ascii-7f.data` | `P || DEL || LF` | 14 | `c9c2ad9ebc56d536bff423f9fcc8a9b2b6e0723269ee9ed828d5566a2c0fdff1` |
| B12-20 | `physical/vt-0b.data` | `P || VT || LF` | 14 | `709355d197ca2e68084984731e3496da029223fcc505eb1884fe59b4c8ef6fbb` |
| B12-21 | `physical/mixed-eol.ntasm` | `P || A || CR || LF || A || LF` | 17 | `73e21085d2ffb7378979c77c92fc2b6bde3a242a78c56a9b8e892c1dbb2d6901` |
| B12-22 | `physical/line-255-crlf.ntasm` | `P || A^255 || CR || LF` | 269 | `8d1dc530af9cd65dc581b66e2cb0cfa886d8727032f21abb116689eb1c4ddc32` |
| B12-23 | `physical/only-lf.ntasm` | `LF` | 1 | `01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b` |

## Calcul mécanique des grosses frontières

- B12-02 : `12 + 255 × (255 + 1) + 242 + 1 = 65 535` octets.
- B12-03 : `65 535 + 1 = 65 536` octets.
- B12-10 : `1 + 4 095 = 4 096` lignes et
  `12 + 4 095 = 4 107` octets.
- B12-11 : `1 + 4 096 = 4 097` lignes et
  `12 + 4 096 = 4 108` octets.
- B12-08/B12-09 : la seconde ligne contient respectivement 255 et 256 octets
  `41` hors EOL ; la première ligne `P` reste inchangée.
- B12-13 : `12 + 1 = 13` octets ; le CR terminal est à l'offset `0x0C`.
- B12-16 à B12-20 : `12 + 1 + 1 = 14` octets.
- B12-21 : `12 + 1 + 2 + 1 + 1 = 17` octets et trois lignes physiques,
  terminées successivement par LF, CRLF et LF.
- B12-22 : `12 + 255 + 2 = 269` octets ; le CRLF est exclu des 255 octets de
  la seconde ligne.

B12-02 contient 257 lignes : `P`, 255 lignes de 255 octets `41`, puis une ligne
de 242 octets `41`. Toutes finissent par LF et aucune ne dépasse 255 octets hors
EOL. Après le scan physique, la première ligne exacte permet d'atteindre le
marqueur B1.2 ; les lignes de remplissage ne constituent pas une preuve de
grammaire NTASM-S0 complète.

## Premier défaut attendu

| ID | Premier défaut | Ligne | Colonne | Offset | Code |
|---|---|---:|---:|---:|---|
| B12-00 | EOF sans aucun octet | 0 | 0 | `0x00000000` | E100 |
| B12-03 | cumul de lecture `0x10000` | 0 | 0 | `0x00000000` | E500 |
| B12-04 | NUL après `P` | 2 | 1 | `0x0000000C` | E100 |
| B12-05 | premier octet du BOM | 1 | 1 | `0x00000000` | E100 |
| B12-06 | `80` après `P` | 2 | 1 | `0x0000000C` | E100 |
| B12-07 | CR dont le successeur est `58` | 2 | 1 | `0x0000000C` | E100 |
| B12-09 | 256e `41` de la seconde ligne | 2 | 256 | `0x0000010B` | E101 |
| B12-11 | LF qui formerait la 4 097e ligne | 4 097 | 1 | `0x0000100B` | E500 |
| B12-12 | EOF après les onze octets présents | 1 | 12 | `0x0000000B` | E100 |
| B12-13 | CR terminal sans octet successeur | 2 | 1 | `0x0000000C` | E100 |
| B12-14 | premier octet `EF` du BOM tronqué | 1 | 1 | `0x00000000` | E100 |
| B12-15 | premier octet `EF` du BOM tronqué | 1 | 1 | `0x00000000` | E100 |
| B12-19 | `7F` après `P` | 2 | 1 | `0x0000000C` | E100 |
| B12-20 | `0B` après `P` | 2 | 1 | `0x0000000C` | E100 |
| B12-23 | première ligne sémantique vide après scan physique valide | 1 | 1 | `0x00000000` | E200 |

Le corpus canonique B1.2 compte désormais 24 cas, B12-00 à B12-23. B12-00 est
une régression B1.1 déjà GREEN et non un nouveau RED. B12-23 est également un
contrôle sémantique hérité : le scanner accepte son LF, puis la reconnaissance
de `format pe64` produit E200.

## Canaris de pools figés

Chaque payload WORK/SRC/OUT est encadré par sa paire de gardes distinctes. Ces
valeurs sont des données normatives du test ; elles ne sont pas des fixtures
source à copier sous `NTASM1.NTASM`.

| Garde | 16 octets exacts |
|---|---|
| `WORK_PRE` | `A5 5A C3 3C 96 69 F0 0F 55 AA 33 CC 78 87 E1 1E` |
| `WORK_POST` | `1E E1 87 78 CC 33 AA 55 0F F0 69 96 3C C3 5A A5` |
| `SRC_PRE` | `99 66 FF 00 AA 55 CC 33 69 96 0F F0 44 BB DD 22` |
| `SRC_POST` | `22 DD BB 44 F0 0F 96 69 33 CC 55 AA 00 FF 66 99` |
| `OUT_PRE` | `66 99 00 FF 55 AA 33 CC 96 69 F0 0F BB 44 22 DD` |
| `OUT_POST` | `DD 22 44 BB 0F F0 69 96 CC 33 AA 55 FF 00 99 66` |

Chaque POST est la suite byte pour byte inverse de son PRE. Les six valeurs sont
différentes entre elles. B1.2 exige leur présence et la preuve statique du chemin
E603 dans le source NASM quarantainé et son désassemblage, mais ne matérialise
aucune fixture de corruption. L'injection volontaire
d'une garde fautive est reportée à B1.25.

## Contrôle avant et après boot

La matérialisation est recevable seulement si :

1. sa taille égale la colonne Taille ;
2. son SHA-256 égale exactement la colonne SHA-256 ;
3. le fichier transporté porte le nom racine `NTASM1.NTASM`, quelle que soit
   l'extension logique ;
4. aucun outil n'a normalisé les EOL ou ajouté un BOM/EOL ;
5. `NTASM1.EFI` est absent du volume.

Après le boot, la source doit conserver le même hash et `NTASM1.EFI` doit rester
absent. Un calculateur SHA-256 peut observer ces données en lecture seule ; il ne
devient pas un producteur du seed ou d'une sortie NTASM.

Ces contrôles ont passé 24/24. Le détail par ID, les transcripts et la
vérification mécanique sont reliés par le manifeste GREEN canonique B1.2.
