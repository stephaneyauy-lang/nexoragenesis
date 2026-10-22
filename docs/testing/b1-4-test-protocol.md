# Protocole de test — tracer B1.4

Statut final : **tracer B1.4 GREEN, Gate B1 RED**. Preuve canonique :
`out/b1/step-4/20260902-215921-b48ac1a7b2c04c4ea9b9d922948bd75d/manifest.md`.

## RED

Campagne principale :
`out/b1/step-4/agent-red-20260902-b14-b13-r1/manifest.md`, SHA-256
`4f5cf5a0e7f0986e4e7b544efd0413ad4ab75885398bb7ca2713311af8955766`.

- 8/8 nouveaux cas RED valides ;
- contrôle B1.3 1/1 vert ;
- erreurs de banc 0 ;
- `NTASM1.EFI` 0 ;
- logs non vides 0 ; QEMU restant 0.

Compléments avant code : `out/b1/step-4/red-supplemental/` prouve que zéro
constante et un suffixe opaque attendent T04 mais observent encore T03.

## Contrat observable

Succès : `NG_S0_T04_OK\r\n`, exactement une fois, `EFI_SUCCESS`. Erreurs
E101/E201 : diagnostic unique, `EFI_LOAD_ERROR`. Aucun cas ne crée ou sonde
`NTASM1.EFI`.

## Promotion

B1.4 est GREEN seulement si :

1. les douze cas B14-00..11 passent ;
2. les 10 cas cœur B1.3 et les 34 régressions/frontières passent avec oracles
   stage-aware ;
3. les non-régressions B1.1/B1.2 restent exactes ;
4. PE, ABI, canaris, cleanup et absence de sortie sont inchangés ;
5. NASM 2.16.01 produit deux hashes identiques ;
6. source-policy, manifeste et `MEM.md` concordent.

Ces conditions sont satisfaites, y compris les contrôles ajoutés `const=` et
`constA`. Annonce maximale : « tracer B1.4 GREEN, Gate B1 RED ». Prochaine
étape B1.5.
