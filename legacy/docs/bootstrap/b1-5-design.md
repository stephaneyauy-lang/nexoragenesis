# B1.5 — entiers non signés et table de constantes

Statut : implémenté et vérifié — **tracer B1.5 GREEN, Gate B1 RED**.

## Portée

B1.5 remplace le suffixe opaque B1.4 par :

```text
{ const WS+ IDENT WS? = WS? unsigned-integer }
```

Zéro, une ou plusieurs constantes sont acceptées. La première ligne non-`const`
termine le tracer. Les doublons restent autorisés jusqu'à B1.6.

Décimal : `0` ou `[1-9][0-9]*`. Hexadécimal : `0x[0-9A-Fa-f]+`. Chaque
accumulation est checked avant multiplication/addition. Overflow, leading zero,
préfixe vide, `_`, suffixe collé ou hex invalide → E102 au premier octet
responsable. Un second token séparé → E201. `+` et `-` restent E201 à B1.5.

Succès : `NG_S0_T05_OK\r\n`. Aucun output.

## Table

- `WORK+0x000` : `symbol_count u32` ;
- table `WORK+0x400`, 512 records × 48 octets ;
- record : `name[32]`, valeur u64 à `+0x20`, source offset u32 à `+0x28`,
  ligne u16 à `+0x2C`, meta `0x0001` à `+0x2E` ;
- validation complète puis record, incrément compteur en dernier ;
- 513e nouveau symbole → E500 au début de l'identifiant.

Le lexer de ligne compte au plus 16 tokens. La ponctuation `: , = [ ] + - * ( )`
forme toujours un token indépendant, même sans whitespace. Le 17e produit E101
avant écriture.
Avec 16 tokens mais un second opérande, la syntaxe produit E201 sur ce second
opérande.

## Layout PE B1.5

Le parser entier et la table ne tiennent pas honnêtement dans les `0x147` octets
restants du raw `.text` B1.4. B1.5 augmente uniquement le raw `.text` :

```text
headers  raw 0x0400
.text    raw 0x1800, RVA 0x1000, file 0x0400
.rdata   raw 0x0400, RVA 0x3000, file 0x1C00
.data    raw 0x0200, RVA 0x4000, file 0x2000
.reloc   raw 0x0200, RVA 0x5000, file 0x2200
file size 0x2400
```

Les RVA, permissions et DIR64 restent inchangées. `SizeOfCode=0x1800`,
`SizeOfImage=0x6000`.

## Non-objectifs

Signe, doublon, `entry`, sections, émission, output et NTASM v0 général.

## Résultat vérifié

- source NASM quarantainée : 37 995 octets, SHA-256
  `4bd49f49ef29aec677d160e2edb3cb0e7d288d6347430d7280eb3cb69ce943c9` ;
- PE B1.5 : 9 216 octets, SHA-256
  `657b3d41dd541cf8630b2b659a29a48c222fc28038516e9e93d176b8db9cadd1` ;
- reproductibilité NASM 2.16.01 : 3/3 productions bit-identiques ;
- corpus B1.5 : 22/22, snapshot des trois records exact, et régressions
  B1.4/B1.3/B1.2 : 56/56 ;
- aucun test ne crée `NTASM1.EFI`.

Preuve canonique :
`out/b1/step-5/20260902-231106-295817a46dbb430a92e6a27dfbd6ee27/manifest.md`.

Le candidat reste externe, quarantainé et non souverain. La Gate B1 reste
RED ; la prochaine étape est B1.6, signe, plage `i64` et doublons.
