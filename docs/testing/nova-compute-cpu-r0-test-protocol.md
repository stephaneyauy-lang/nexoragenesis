# Protocole de test — Nova Compute CPU R0 externe

Statut final : **NC-R0-PROBE GREEN**, preuve canonique :
`out/nova-cpu/r0/20260902-210855-22abc27896d449ad85a029c6ac28b720/manifest.md`.

## RED préalable

Avant toute source R0, le candidat B1.3 a été contrôlé contre
`NG_NOVA_CPU_REF_R0_OK`. Résultat : zéro occurrence du marqueur R0, une
occurrence de `NG_S0_T03_OK` et aucun binaire R0. Le comportement est absent.

## Matrice

| ID | Binaire | Oracle exact | Statut |
|---|---|---|---|
| NC-R0-GREEN-01 | canonique | `NG_NOVA_CPU_R0_OK N=8 SEM=MOD2P32` | EFI_SUCCESS |
| NC-R0-GREEN-02 | canonique, OVMF neuf | même oracle | EFI_SUCCESS |
| NC-R0-NEG-RESULT | `R0_FAULT_RESULT=1` | `NG_NOVA_CPU_R0_E201_RESULT` | EFI_ABORTED |
| NC-R0-NEG-GUARD | `R0_FAULT_GUARD=1` | `NG_NOVA_CPU_R0_E202_GUARD` | EFI_COMPROMISED_DATA |

Chaque cas exige oracle unique, aucun autre marqueur R0, retour firmware, QEMU
exit 0 via HMP, journaux vides, `-nic none`, ESP et variables propres.

## Inspection

- NASM 2.16.01, `-f bin`, aucun objet/linker;
- taille `0xC00`, PE32+ AMD64 EFI, quatre sections;
- `.text` RX, `.rdata` R, `.data` RW, `.reloc` R;
- imports/W+X/overlay nuls, une DIR64;
- tag externe exactement une fois;
- deux boucles bornées à 8, accès scale 4, aucun SIMD/privilège;
- stack alignée et shadow space avant `OutputString`;
- deux builds canoniques bit-identiques.

`NC-R0-PROBE GREEN` ne change ni Gate B1, ni NV1, ni l'absence du noyau.

Les quatre cas, l'inspection et la reproductibilité 2/2 sont satisfaits. Le RED
comportemental a précédé le source avec un nom de marqueur provisoire; l'assertion
exacte finale a été réparée après gel et cette chronologie reste explicite dans
le manifeste, sans prétendre un TDD parfait sur le nom.
