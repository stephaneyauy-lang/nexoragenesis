# Manifeste byte-exact — fixtures B1.8

Statut : corpus principal figé avant code. Ses 30 fichiers sont ASCII sans BOM,
utilisent uniquement LF (`0A`) et possèdent tous un EOL final. Cinq arêtes
complémentaires sont consignées séparément en fin de document; quatre sont LF et
la copie B18-X04 est entièrement CRLF.

Le préfixe commun `P = "format pe64\nabi efi_x64\nentry start\n"` fait 36
octets. Sauf B18-C01, chaque ligne décrite ci-dessous est ajoutée exactement à
`P`; les cas de corps ajoutent d'abord `section .text rx\n`, portant le début de
la ligne suivante à l'offset `0x35`.

| ID | Fichier | Suffixe après `P`, ou résumé | Taille | SHA-256 | Oracle B1.8 |
|---|---|---|---:|---|---|
| B18-C00 | `b1-8/B18-C00-minimal-text-header.ntasm` | `section .text rx\n` | 53 | `54e767e5d6a26fb11626d5130aa2e7ca6b91a3f4b18fb16d73f460a29b82c47f` | `NG_S0_T08_OK` |
| B18-C01 | `b1-8/B18-C01-tabs-comments-state.ntasm` | contenu commenté SP/TAB, voir fichier | 102 | `57665bf6c615d35066aea6799e5dff457e2462605f35c8ccc7c04e0aa23975e8` | `NG_S0_T08_OK`; snapshot 48 octets |
| B18-R00 | `b1-8/B18-R00-missing-text-header.ntasm` | aucun suffixe | 36 | `177c0dbbfb869c4e65662b9c53b98ff479cfb1c5090204eb41eb4df54343e572` | `NGS0 E200 L0004 C0001 O00000024` |
| B18-R01 | `b1-8/B18-R01-wrong-first-token.ntasm` | `sections .text rx\n` | 54 | `805fa1b1aeaf082bed1d553d6d482fc43b9c1cd9f4a952ebea84631513fad54c` | `NGS0 E200 L0004 C0001 O00000024` |
| B18-R02 | `b1-8/B18-R02-wrong-section-name.ntasm` | `section .rdata r\n` | 53 | `524b44c776f7ef7bba2ea5309e03132d4f1d7ee9d4a171c0f255155c9b9d6a8f` | `NGS0 E200 L0004 C0009 O0000002C` |
| B18-R03 | `b1-8/B18-R03-wrong-rights.ntasm` | `section .text rw\n` | 53 | `b8ad4ef1abcc490bad41e6b5991cb83a835f07ed5041f636ef73170cef71a51a` | `NGS0 E200 L0004 C000F O00000032` |
| B18-R04 | `b1-8/B18-R04-missing-section-name.ntasm` | `section\n` | 44 | `8c8b5d57e7f1f372d739c0490f67366cae06ed405815fdf31e380024ad4c159c` | `NGS0 E201 L0004 C0008 O0000002B` |
| B18-R05 | `b1-8/B18-R05-missing-rights.ntasm` | `section .text\n` | 50 | `f0adce6f4f06f2a160ff157581cc649683da5ff7569d54cf3dbe82538f985fab` | `NGS0 E201 L0004 C000E O00000031` |
| B18-R06 | `b1-8/B18-R06-extra-header-token.ntasm` | `section .text rx extra\n` | 59 | `55512867b2d80ef8d292d0f5e210f5a06e71e32af5e6c16d4bd1988e9605206e` | `NGS0 E201 L0004 C0012 O00000035` |
| B18-R07 | `b1-8/B18-R07-missing-ws-after-section.ntasm` | `section.text rx\n` | 52 | `5147e3a404933271bad9d514e2cc8547d56d46009ee3c004522093dcdc55ba8b` | `NGS0 E201 L0004 C0008 O0000002B` |
| B18-R08 | `b1-8/B18-R08-missing-ws-after-name.ntasm` | `section .textrx\n` | 52 | `4d84772785fb8a1091f41cf17f7388566cef9c0c2e167ce1ccd00fa91677df4f` | `NGS0 E200 L0004 C0009 O0000002C` |
| B18-R09 | `b1-8/B18-R09-header-punctuation.ntasm` | `section .text, rx\n` | 54 | `5531405ab1c6d10a7c65c8ef0bdf8c51ea4b19517200beedef8eba149fffac2c` | `NGS0 E201 L0004 C000E O00000031` |
| B18-R10 | `b1-8/B18-R10-duplicate-text.ntasm` | header puis `section .text rx\n` | 70 | `8ef86406990eee4c1f8c79b9175b7b46a6520c5d52c39a6816684c2d23b9724d` | `NGS0 E200 L0005 C0001 O00000035` |
| B18-R11 | `b1-8/B18-R11-rdata-too-early.ntasm` | header puis `section .rdata r\n` | 70 | `2b71ae1961040ef762803288f916e48232380184f45b1e01bdbfcafceaec53c2` | `NGS0 E200 L0005 C0001 O00000035` |
| B18-R12 | `b1-8/B18-R12-reloc-source.ntasm` | header puis `section .reloc r\n` | 70 | `6341a1ce5218e1d95a4661784ef747273fcc0e9e325f19dab2a9162ba4759d22` | `NGS0 E200 L0005 C0001 O00000035` |
| B18-R13 | `b1-8/B18-R13-preamble-in-text.ntasm` | header puis `const A = 0\n` | 65 | `c8ee3c31a7135c94ab64a93dd13cb6cbb887fb4a9fea97c4aa773169a6977569` | `NGS0 E200 L0005 C0001 O00000035` |
| B18-R14 | `b1-8/B18-R14-header-16-tokens.ntasm` | header suivi de 13 tokens `a..m` | 79 | `7679242c938edd5b76d70679cada2587f8c63341ce9217af82ccbf01d9d5384e` | `NGS0 E201 L0004 C0012 O00000035` |
| B18-R15 | `b1-8/B18-R15-header-17-tokens.ntasm` | header suivi de 14 tokens `a..n` | 81 | `06d94e7366f109854d67c2c5a5c3c870d628e232d0a6bf70db7502ab5a676b5a` | `NGS0 E101 L0004 C002C O0000004F` |
| B18-R16 | `b1-8/B18-R16-header-ident-31.ntasm` | `A{31} .text rx\n` | 77 | `8b21709d25bfab982477f41191bdb4783d326a369451c51e45270e996968afa2` | `NGS0 E200 L0004 C0001 O00000024` |
| B18-R17 | `b1-8/B18-R17-header-ident-32.ntasm` | `A{32} .text rx\n` | 78 | `70a83658f73da33fbe86565e327f1375ccd6918fe8fbd8f1d788a59a59531310` | `NGS0 E101 L0004 C0020 O00000043` |
| B18-R18 | `b1-8/B18-R18-byte-in-text.ntasm` | header puis `byte 0\n` | 60 | `cb1d9ac95a9a3722a12d8ebdab0254e69e7bf32ac22ec824ccc8c3aacf4725e1` | `NGS0 E202 L0005 C0001 O00000035` |
| B18-R19 | `b1-8/B18-R19-word-in-text.ntasm` | header puis `word 0\n` | 60 | `ae7b02d7b665068b8d6268af5045d3dfd2de22ca44d52f27220e2a92bfca95fa` | `NGS0 E202 L0005 C0001 O00000035` |
| B18-R20 | `b1-8/B18-R20-dword-in-text.ntasm` | header puis `dword 0\n` | 61 | `011a03206c69c2746dd97f6daccca06fc2138b29ea83dc9a1f0c2f2b6781fec5` | `NGS0 E202 L0005 C0001 O00000035` |
| B18-R21 | `b1-8/B18-R21-qword-in-text.ntasm` | header puis `qword 0\n` | 61 | `8ce1dc190460622980d269a8b64425d54531fb1b063840b4fa6703ab9464dae6` | `NGS0 E202 L0005 C0001 O00000035` |
| B18-R22 | `b1-8/B18-R22-ascii-in-text.ntasm` | header puis `ascii "x"\n` | 63 | `60c4a46b4dbc47bb0d8ddec2d26519e96ada4f37efc56b7d2d3bd3db37267cb3` | `NGS0 E202 L0005 C0001 O00000035` |
| B18-R23 | `b1-8/B18-R23-utf16z-in-text.ntasm` | header puis `utf16z "x"\n` | 64 | `6364ad4f788eae615b061947c640b05cf98f5249423c2ffeb5a42edbfa7a6416` | `NGS0 E202 L0005 C0001 O00000035` |
| B18-R24 | `b1-8/B18-R24-zero-in-text.ntasm` | header puis `zero 1\n` | 60 | `04b08f19975a8fbdbccafd02dc74454f23a77b9129899e4c63dd7abe4433ec30` | `NGS0 E202 L0005 C0001 O00000035` |
| B18-R25 | `b1-8/B18-R25-label-not-yet-supported.ntasm` | header puis `start:\n` | 60 | `7aba6c39374dd13e47c8aef5d90a7385a397ce3ad5fa3e4185b6c7ab55c20b7f` | `NGS0 E400 L0005 C0001 O00000035` |
| B18-R26 | `b1-8/B18-R26-align-not-yet-supported.ntasm` | header puis `align 16\n` | 62 | `aad22d734d71953baba024133b739413746629205f4c6f36f9f1758c03effb6b` | `NGS0 E400 L0005 C0001 O00000035` |
| B18-R27 | `b1-8/B18-R27-mnemonic-not-yet-supported.ntasm` | header puis `nop\n` | 57 | `d60323062eaf3f59d35c9fc44babe6e0bfe9da56f6da566d5e89bd4728130606` | `NGS0 E400 L0005 C0001 O00000035` |

`A{31}` et `A{32}` signifient exactement 31 et 32 octets `41`. Les valeurs de
taille et SHA-256 sont calculées sur les fichiers eux-mêmes, EOL inclus.

## Oracle d'état indépendant B18-C01

Dans B18-C01, la ligne `entry` commence à l'offset 46 (`0x2E`), `MiXeD_09`
commence à l'offset 52 (`0x34`), mesure 8 octets et se trouve ligne 6. La section
commence à l'offset 78; elle n'avance pas l'offset de code.

La concaténation qword LE
`seen=1, off=52, len=8, line=6, line_start=46, text_offset=0` fait 48 octets et
son SHA-256 indépendant attendu vaut
`42555b52fd6769db515d3490b1aeb228733a2bc48cf34c7edb04de8517541172`.

## Priorités vérifiées par construction

- B18-R14 atteint le parseur avec exactement 16 tokens : E201 vise le quatrième.
- B18-R15 possède 17 tokens : E101 vise le `n`, token 17, avant E201.
- B18-R16 atteint le parseur avec un identifiant de 31 octets; B18-R17 produit
  E101 sur son 32e octet avant E200.
- B18-R07, R08 et R09 distinguent séparateur absent reconnaissable, second token
  faux et ponctuation adjacente.
- B18-R18 à R24 couvrent les sept directives de données interdites dans `.text`.
- B18-R25 à R27 prouvent qu'aucun label, `align` ou mnémonique n'est accepté
  silencieusement avant son tracer.

Tous les succès rendent `EFI_SUCCESS`; toutes les erreurs rendent
`EFI_LOAD_ERROR`. Aucun cas ne crée ni ne sonde `NTASM1.EFI`.

## Arêtes complémentaires B18-X00..X04

Ces cinq cas ne modifient aucun fichier du corpus principal. Leur CSV séparé est
`b1-8-edge-cases.csv`.

| ID | Fichier | Objet | Taille | SHA-256 | Oracle B1.8 |
|---|---|---|---:|---|---|
| B18-X00 | `b1-8/B18-X00-section-name-case.ntasm` | `.TEXT` sensible à la casse | 53 | `a75527629389cd569863cd782b150310ea3289bc0cf1d44f332c435831d46340` | `NGS0 E200 L0004 C0009 O0000002C` |
| B18-X01 | `b1-8/B18-X01-rights-case.ntasm` | `RX` sensible à la casse | 53 | `044e0887d774dba50e783d078347dfac104d4515de41f7cad4f63801f27deb9b` | `NGS0 E200 L0004 C000F O00000032` |
| B18-X02 | `b1-8/B18-X02-data-keyword-boundary.ntasm` | `bytecode0` n'est pas `byte` | 63 | `17f8cadcf24e730f8fc3f4f1454c54b2eec596ceede90616f825373f080f4f72` | `NGS0 E400 L0005 C0001 O00000035` |
| B18-X03 | `b1-8/B18-X03-indented-data.ntasm` | `SP TAB byte 0` | 62 | `0b585aae328fdfe076912a02e17365eb06d670b3978707a409780910c13073f0` | `NGS0 E202 L0005 C0003 O00000037` |
| B18-X04 | `b1-8/B18-X04-minimal-text-header-crlf.ntasm` | copie logique de C00, 4 CRLF | 57 | `b2a8b89415fed05a3b7ff9a5a56a2e0aee33dc9a741118f6173822e25a65de20` | `NG_S0_T08_OK` |

X00/X01 couvrent la casse exacte des tokens de section; X02 couvre la frontière
d'identifiant sans confusion par préfixe; X03 prouve que la position vise le
premier octet sémantique après indentation; X04 prouve l'équivalence logique LF
et CRLF sans remplacer C00.
