# Manifeste byte-exact — fixtures B1.6

Tous les fichiers sont ASCII, LF, sans BOM. B16-00 réutilise exactement
`b1-4/B14-C00-b13-control.ntasm`, le préfixe seul de 24 octets.

| ID | Fichier | Taille | SHA-256 | Oracle B1.6 |
|---|---|---:|---|---|
| B16-00 | `b1-4/B14-C00-b13-control.ntasm` | 24 | `0028d9969d3e1551a3f7d0f336dfa11d3c2216d0a0326eeb47c582e235284a24` | `NG_S0_T06_OK` |
| B16-01 | `b1-6/B16-01-neg-one-dec.ntasm` | 37 | `89b159a939a49b9e63aa6724975c74c79f0010332487ef3b99dd0b6309df2637` | `NG_S0_T06_OK` |
| B16-02 | `b1-6/B16-02-i64-min-dec.ntasm` | 55 | `6eb0457bc6e3b3e5cc6f910d1fbcb7a127416a93414bd7fbf75ef7465edb29ab` | `NG_S0_T06_OK` |
| B16-03 | `b1-6/B16-03-i64-underflow-dec.ntasm` | 55 | `88b34f2bb53500082dd692bc51f28e1653901ff4e9a809996bacdbee02883231` | `NGS0 E102 L0003 C001E O00000035` |
| B16-04 | `b1-6/B16-04-unary-plus.ntasm` | 37 | `34d51b36ab7508a5948674e4a95f939b16977f33c94e523c4e2bf06c2dc3bfc4` | `NGS0 E201 L0003 C000B O00000022` |
| B16-05 | `b1-6/B16-05-space-after-minus.ntasm` | 38 | `ec24632bfc2923f1445e3e27034b436f0587202d4653258422820b93be827645` | `NGS0 E102 L0003 C000C O00000023` |
| B16-06 | `b1-6/B16-06-duplicate-same-case.ntasm` | 49 | `d4b36ed521918a8df455f74bab4fbcdda1dddeac83cb475833f9eab8cb391e34` | `NGS0 E300 L0004 C0007 O0000002A` |
| B16-07 | `b1-6/B16-07-distinct-case.ntasm` | 49 | `fdb0579ec473689e6e6c5a3ef601c26410e1f652275e8a05e40e4092275ce439` | `NG_S0_T06_OK` |
| B16-08 | `b1-6/B16-08-negative-zero.ntasm` | 37 | `89e23c45c6b4d464a7ecd71995f1b869cb897cbce502482d81c7164f4a7cf785` | `NG_S0_T06_OK` |
| B16-09 | `b1-6/B16-09-i64-min-hex.ntasm` | 54 | `e849f3bd9e714eb827a8df655cdd36e72aeff964a334af7c1be7bfcfe4c21016` | `NG_S0_T06_OK` |
| B16-10 | `b1-6/B16-10-i64-underflow-hex.ntasm` | 54 | `d8948acea54af5e56d140fe2e16f474785949f46f3cae1bb087855abd3b310d1` | `NGS0 E102 L0003 C001D O00000034` |
| B16-11 | `b1-6/B16-11-minus-without-magnitude.ntasm` | 36 | `e4aded8bad1d714c757675e3ed43ef1741f3aaf9cadfd768b64ef80d8b0642dc` | `NGS0 E102 L0003 C000C O00000023` |
| B16-12 | `b1-6/B16-12-tab-after-minus.ntasm` | 38 | `9f186e0ff8b44bf0dd4907199950a4b81ef9a4c0d92b70035f2bdd4f63be0935` | `NGS0 E102 L0003 C000C O00000023` |
| B16-13 | `b1-6/B16-13-u64max-positive.ntasm` | 55 | `56ac0a05974ac7904f7065765717967b7a785d81de8016698f29fcfcb0a957a4` | `NG_S0_T06_OK` |

Les positions sont ligne/colonne 1-based et offset byte 0-based. E102 désigne
le premier octet qui rend la magnitude ou la forme signée invalide. E300 pointe
le premier octet du second identifiant de même casse. Tous les succès rendent
`EFI_SUCCESS`; toutes les erreurs rendent `EFI_LOAD_ERROR`. Aucun cas ne crée ou
ne sonde `NTASM1.EFI`.

Goldens de records directs, calculés sur les 48 octets du record seulement :

- B16-01 : `f57ceab5ab39ec0fb9d693fc9dd2a6884d104cf6e1c4afd1be0a511b6f3c914c`;
- B16-02/B16-09 : `5e5b809dd9a88e3e22f960d1fa41ec8982194781395bdf34321193e12b90527a`;
- B16-08 : `414c96c76345fd0ae12cb43b8aa6eebea3e67c03b0c04bc2838562c8f2df8dc8`;
- B16-07, deux records contigus, 96 octets :
  `336db88410cfa14354ea86357dae91d8ca562839f13d70abcaefa95f6ab243b9`.
