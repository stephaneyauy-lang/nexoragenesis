# B1.4 — design du préfixe `const IDENT =`

Statut final : implémenté et vérifié — **tracer B1.4 GREEN, Gate B1 RED**.

## Portée

B1.4 conserve intégralement l'acquisition, le scanner physique et les deux
premières lignes sémantiques B1.3. Il ajoute seulement un probe optionnel de la
prochaine ligne sémantique :

```text
const WS+ IDENT WS? =
```

- zéro constante reste valide ;
- une ligne suivante qui ne commence pas par le token exact `const` reste hors
  périmètre et ne casse pas les succès B1.3 ;
- après `=`, aucun octet n'est analysé à B1.4 ;
- une seule ligne constante est probée ; les constantes multiples restent hors
  périmètre ;
- le succès temporaire devient `NG_S0_T04_OK\r\n`.

B1.4 ne parse aucun entier, signe, base, valeur, symbole, table de constante ou
émission. Le suffixe absurde `@not_an_integer` est volontairement accepté pour
prouver la frontière B1.5.

## Identifiant

Forme : `[A-Za-z_][A-Za-z0-9_]{0,30}`.

- longueur 31 acceptée ;
- le 32e caractère valide produit E101 sur cet octet ;
- début numérique ou caractère hors classe produit E201 ;
- le lexème exact `const` en position identifiant est refusé E201 comme mot-clé
  réservé canonique de ce tracer ;
- `=` peut être adjacent ou séparé par SP/TAB ;
- `=` absent produit E201 à la position logique attendue, y compris l'EOL.

La frontière 16/17 tokens de l'ancienne carte est différée au premier tracer qui
tokenisera réellement la valeur. La simuler avec des tokens opaques élargirait
B1.4 au-delà du plan actif et brouillerait la frontière B1.5.

## Machine sémantique

Stages :

```text
0 EXPECT_FORMAT
1 EXPECT_ABI
2 PROBE_OPTIONAL_CONST
```

Au stage 2 : EOF → succès ; ligne non-`const` → succès ; ligne `const` valide →
succès ; ligne `const` invalide → E101/E201 positionné. Le scanner physique
précède toujours cette machine, donc E100/E101 physique et E500 restent
prioritaires.

## Delta NASM attendu

- copier B1.3 vers un nouveau source `seed-b1.4-r1.asm` ;
- ne jamais modifier B1.2/B1.3 ;
- prolonger `semantic_next_record` pour le stage 2 ;
- ajouter un helper feuille `match_const_prefix` sans registre non volatil ;
- faire de `semantic_eof` stage 2 un succès ;
- remplacer uniquement le marqueur T03 par T04 ;
- conserver frame, pools, ownership, canaris, cleanup, PE et relocation.

Budget : `.text` B1.3 utile `0x0F00`, raw `0x1200`, marge `0x300`. Le delta
doit tenir sans déplacer les sections. `.rdata` reste dans `0x400`.

## Non-objectifs

- entier ou valeur ;
- 16/17 tokens ;
- constantes multiples ;
- insertion en table symbole ;
- pass 1/pass 2 ;
- output `NTASM1.EFI` ;
- NTASM v0 général.

Preuve canonique :
`out/b1/step-4/20260902-215921-b48ac1a7b2c04c4ea9b9d922948bd75d/manifest.md`.
