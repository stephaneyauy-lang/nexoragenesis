# Nova Compute CPU — oracle R0 fixe

Statut : spécification expérimentale vérifiée du probe externe
`NC-R0-PROBE GREEN`; elle ne promeut pas le vrai backend Nova.

Cette spécification ne définit ni la syntaxe Nova générale, ni Device IR, ni un
compilateur. Elle fige un unique calcul de référence à reproduire plus tard par
`cpu.ref`.

## Calcul

Tous les éléments sont des `u32` little-endian. L'addition est modulo `2^32`.

| Lane | A | B | Golden |
|---:|---:|---:|---:|
| 0 | `00000000` | `00000000` | `00000000` |
| 1 | `00000001` | `FFFFFFFF` | `00000000` |
| 2 | `FFFFFFFF` | `00000001` | `00000000` |
| 3 | `80000000` | `80000000` | `00000000` |
| 4 | `7FFFFFFF` | `00000001` | `80000000` |
| 5 | `12345678` | `11111111` | `23456789` |
| 6 | `AAAAAAAA` | `55555555` | `FFFFFFFF` |
| 7 | `DEADBEEF` | `21524111` | `00000000` |

La boucle visite exactement les lanes `0..7` dans cet ordre et utilise des
opérations 32 bits. La sortie est encadrée par `C0DEC0DE` et `DEC0ADDE`;
chaque élément vaut initialement `A5A5A5A5`.

Priorité : garde différente → E202; résultat différent → E201; sinon succès.

## Marqueurs exacts

```text
NG_NOVA_CPU_R0_OK N=8 SEM=MOD2P32
NG_NOVA_CPU_R0_E201_RESULT
NG_NOVA_CPU_R0_E202_GUARD
```

Statuts : `EFI_SUCCESS`, `EFI_ABORTED`, `EFI_COMPROMISED_DATA`, ou
`EFI_DEVICE_ERROR` si la console est indisponible.

Limites : UEFI/QEMU, GPR scalaires, aucune entrée/allocation, aucun
`ExitBootServices`, PE externe non souverain et non livrable.
