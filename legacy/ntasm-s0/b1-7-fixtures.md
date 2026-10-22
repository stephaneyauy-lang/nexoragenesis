# Manifeste byte-exact — fixtures B1.7

Statut : corpus figé avant code. Les 19 fichiers sont ASCII sans BOM. Tous sont
LF (`0A`) sauf B17-C03, entièrement CRLF (`0D 0A`). `\t` désigne l'unique octet
`09`. Chaque source possède un EOL final.

Le préfixe LF commun `P = "format pe64\nabi efi_x64\n"` fait 24 octets :

```text
66 6F 72 6D 61 74 20 70 65 36 34 0A
61 62 69 20 65 66 69 5F 78 36 34 0A
```

Les contenus ci-dessous, avec `A{31}`/`A{32}` signifiant exactement 31/32
octets `41`, définissent intégralement les octets après `P`. B17-C03 donne son
contenu complet car il n'utilise pas `P`.

| ID | Fichier | Suffixe après `P` ou contenu complet | Taille | SHA-256 | Oracle B1.7 |
|---|---|---|---:|---|---|
| B17-C00 | `b1-7/B17-C00-minimal-entry.ntasm` | `entry start\n` | 36 | `177c0dbbfb869c4e65662b9c53b98ff479cfb1c5090204eb41eb4df54343e572` | `NG_S0_T07_OK` |
| B17-C01 | `b1-7/B17-C01-constants-before-entry.ntasm` | `const ZERO = 0\nconst NEG = -1\nentry start\n` | 66 | `47d0f73c9845679c9b17cb09f47a8eedba9d2f89abc11d7e46cea6cc3989aea5` | `NG_S0_T07_OK` |
| B17-C02 | `b1-7/B17-C02-ident-31.ntasm` | `entry A{31}\n` | 62 | `a57518f3f3c65f5bdac53df881e1f644491916149b26d22a16fb12105f1afd2a` | `NG_S0_T07_OK` |
| B17-C03 | `b1-7/B17-C03-crlf-comments-case.ntasm` | `format pe64\r\nabi efi_x64\r\nconst A = 0\r\nentry\tMiXeD_09 ; keep\r\n` | 62 | `8412551763fbbe22d4127a720a177676e39aed15c7279fcaf58ef9367f22714d` | `NG_S0_T07_OK` |
| B17-C04 | `b1-7/B17-C04-constant-target-no-resolution.ntasm` | `const start = 0\nentry start\n` | 52 | `b51c778b9af072021f81e9c11cf6bc5dad77f596e0ec976c29116b31c2da8c2d` | `NG_S0_T07_OK` ; aucune résolution |
| B17-C05 | `b1-7/B17-C05-section-boundary.ntasm` | `entry start\nsection .text rw\n` | 53 | `b8ad4ef1abcc490bad41e6b5991cb83a835f07ed5041f636ef73170cef71a51a` | `NG_S0_T07_OK` ; frontière B1.8 |
| B17-R00 | `b1-7/B17-R00-missing-entry.ntasm` | vide | 24 | `0028d9969d3e1551a3f7d0f336dfa11d3c2216d0a0326eeb47c582e235284a24` | `NGS0 E302 L0003 C0001 O00000018` |
| B17-R01 | `b1-7/B17-R01-missing-after-const.ntasm` | `const A = 0\n` | 36 | `9c85f94b0d3e5a0fc8a3a83943c738a012476a0e866a9887a1792e3da15fb325` | `NGS0 E302 L0004 C0001 O00000024` |
| B17-R02 | `b1-7/B17-R02-duplicate-entry.ntasm` | `entry start\nentry other\n` | 48 | `9162780dac2606a15b9e0e49e015e7cb66c878dde415338beb25377b6d14dfd1` | `NGS0 E200 L0004 C0001 O00000024` |
| B17-R03 | `b1-7/B17-R03-const-after-entry.ntasm` | `entry start\nconst A = 0\n` | 48 | `600600bdf43328bd7e2821de6039d658aae98abc60fe04f40cdb756148dc5ab5` | `NGS0 E200 L0004 C0001 O00000024` |
| B17-R04 | `b1-7/B17-R04-section-before-entry.ntasm` | `section .text rx\nentry start\n` | 53 | `4e09b9c5c92758dc40d0fc1cb5715bf26bcc6f7d79b81d507bc926dc9161b8ad` | `NGS0 E200 L0003 C0001 O00000018` |
| B17-R05 | `b1-7/B17-R05-missing-ident.ntasm` | `entry\n` | 30 | `3fad20637dbb608ecd07329d3b62cf327eb790f9587a31437d06f957f7ba0a2c` | `NGS0 E201 L0003 C0006 O0000001D` |
| B17-R06 | `b1-7/B17-R06-ident-start-digit.ntasm` | `entry 1start\n` | 37 | `652225b30550ae4e0511b3ceaf589ae80226b51812d2e6a2fc16ad0583f27258` | `NGS0 E201 L0003 C0007 O0000001E` |
| B17-R07 | `b1-7/B17-R07-bad-ident-char.ntasm` | `entry st@rt\n` | 36 | `fe0848c6c4043abd6ab43fed409cef672cb51c4ca642c98da9f615425d2cb9aa` | `NGS0 E201 L0003 C0009 O00000020` |
| B17-R08 | `b1-7/B17-R08-ident-32.ntasm` | `entry A{32}\n` | 63 | `2630bac66df1f14d14c4656f4e76a24bcbf4d8f05940ee6209acc93ca8203db1` | `NGS0 E101 L0003 C0026 O0000003D` |
| B17-R09 | `b1-7/B17-R09-wrong-keyword.ntasm` | `entrystart\n` | 35 | `25eef0c132dd4244206703884176833e3e7b1b900df2fbb726bd7c64175f7268` | `NGS0 E200 L0003 C0001 O00000018` |
| B17-R10 | `b1-7/B17-R10-extra-token.ntasm` | `entry start extra\n` | 42 | `bd34a7680e28140f91d3edffed289e7aca96cc5d5621f1a27345f9700e1d8aa4` | `NGS0 E201 L0003 C000D O00000024` |
| B17-R11 | `b1-7/B17-R11-keyword-as-ident.ntasm` | `entry const\n` | 36 | `530a8fc93d6244a7ecc6055e33551626d4369b202d33bbe38d8108aa20e45347` | `NGS0 E201 L0003 C0007 O0000001E` |
| B17-R12 | `b1-7/B17-R12-token-17.ntasm` | `entry start a b c d e f g h i j k l m n o\n` | 66 | `1d102faf3c0c0bc1d82936f79799093a5e546042a0e8568cda55a9eb66f028c8` | `NGS0 E101 L0003 C0029 O00000040` |

Les positions sont ligne/colonne 1-based et offset byte 0-based. Pour R00/R01,
E302 pointe l'EOF virtuel. Pour R08, E101 pointe exactement le 32e octet de
l'identifiant. Tous les succès rendent `EFI_SUCCESS`; toutes les erreurs
rendent `EFI_LOAD_ERROR`. Aucun cas ne crée ni ne sonde `NTASM1.EFI`.

## Frontière de tokens

R12 exerce directement `entry` avec 17 tokens : le 17e produit E101 avant que
la syntaxe du premier extra puisse produire E201. Les limites B15-17/B15-18
restent rejouées au futur GREEN pour la voie `const`.
