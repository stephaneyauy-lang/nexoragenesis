# Manifeste byte-exact — fixtures B1.4

Statut : corpus final GREEN sur le candidat B1.4 hashé; preuve canonique sous
`out/b1/step-4/20260902-215921-b48ac1a7b2c04c4ea9b9d922948bd75d/manifest.md`.

Préfixe LF : `P="format pe64\n"`, `Q="abi efi_x64\n"`.

| ID | Fichier | Taille | SHA-256 | Oracle B1.4 |
|---|---|---:|---|---|
| B14-00 | `b1-4/B14-C00-b13-control.ntasm` | 24 | `0028d9969d3e1551a3f7d0f336dfa11d3c2216d0a0326eeb47c582e235284a24` | `NG_S0_T04_OK` |
| B14-01 | `b1-4/B14-R00-const-a-equals.ntasm` | 34 | `23638540b6732973ba903bcb0bc3e261225116e281e39f796c8c0591e954addd` | `NG_S0_T04_OK` |
| B14-02 | `b1-4/B14-R01-ident31.ntasm` | 64 | `e5abefc7ccc649addc3fa4e0493170d4ce4f98adf25226fd026d81a85421a17d` | `NG_S0_T04_OK` |
| B14-03 | `b1-4/B14-R02-ident32.ntasm` | 65 | `d626c4602ceecc465c4af1676da1740662c3bcefaa3453141fb35ab1495609ca` | `NGS0 E101 L0003 C0026 O0000003D` |
| B14-04 | `b1-4/B14-R03-numeric-start.ntasm` | 35 | `2faa82bd7d37a239ea36b55b9a7dd74da385cd4ca5c32b71ea0950a64c0ab175` | `NGS0 E201 L0003 C0007 O0000001E` |
| B14-05 | `b1-4/B14-R04-invalid-char.ntasm` | 36 | `2d2e6bc64ef385c167016587daf41af3a365d589e976ccdd8ff10b4decd642e1` | `NGS0 E201 L0003 C0008 O0000001F` |
| B14-06 | `b1-4/B14-R05-keyword.ntasm` | 38 | `ddea9e0121648e83078de89447b916ab2285e21d87497dc5a84f1aa3a10d97f5` | `NGS0 E201 L0003 C0007 O0000001E` |
| B14-07 | `b1-4/B14-R06-missing-equals.ntasm` | 32 | `7cf7bd3193d1bd8cb8291b631353ec49f9850c58d0b3ea01335e39417dee1db6` | `NGS0 E201 L0003 C0008 O0000001F` |
| B14-08 | `b1-4/B14-R07-ws-comment-crlf.ntasm` | 104 | `a9822ec7f93614e3cd43d0d462f68d8a80fbb6c02ff16ce6ed3b48cf62686393` | `NG_S0_T04_OK` |
| B14-09 | `b1-4/B14-R08-suffix-opaque.ntasm` | 50 | `994255e0116a26e561e69b02f49eb558b7086e203580b6dc7479ab5c87bd05bc` | `NG_S0_T04_OK` |

Contrôles de frontière ajoutés après audit :

| ID | Fichier | Taille | SHA-256 | Oracle |
|---|---|---:|---|---|
| B14-10 | `b1-4/B14-BUG-const-equal.ntasm` | 31 | `0d211992e8a2b9d2c473e6f7a1a8110a15b83aedf78fa6f9e1d58fdc1497daeb` | `NGS0 E201 L0003 C0006 O0000001D` |
| B14-11 | `b1-4/B14-C01-constA.ntasm` | 33 | `12a80b9c30f487932c4bce53cbe83a936d58e2e109b645964ef2b598e641b470` | `NG_S0_T04_OK` |

Dans la preuve d’exécution, ces deux contrôles gardent leurs IDs historiques de
découverte : B14-10 = `B14-BUG`, B14-11 = `B14-C01`.

Les positions sont ligne/colonne 1-based et offset byte 0-based. Le premier
octet fautif gagne. B14-09 fige explicitement que tout suffixe après le premier
`=` reste hors périmètre B1.4.
