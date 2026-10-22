# Protocole de test — tracer B1.5

Statut : **tracer B1.5 GREEN, Gate B1 RED**.

Le test `const ZERO = 0` attend T05 et observe T04 sur le candidat B1.4, avec
banc sain et aucune sortie. Une campagne RED complète doit ensuite exécuter les
fixtures B15-00..20 sur le hash B1.4 inchangé.

## Promotion

B1.5 GREEN exige :

1. 22/22 fixtures B1.5, dont B15-21 ajouté après audit RED pour verrouiller la
   ponctuation accolée ;
2. snapshot `symbol_count=3` et trois records exacts pour B15-04 ;
3. corpus B1.4 stage-aware, cœur B1.3 et 34 régressions ;
4. canaris/cleanup/absence de sortie ;
5. NASM 2/2, PE audité, source-policy ;
6. NC-R0 inchangé et `MEM.md` concordant.

Annonce maximale : « tracer B1.5 GREEN, Gate B1 RED ». Suite : B1.6.

## Promotion exécutée

Les six conditions sont satisfaites sur le PE SHA-256
`657b3d41dd541cf8630b2b659a29a48c222fc28038516e9e93d176b8db9cadd1` :

- RED complet : 21/21 sur le candidat B1.4 canonique ;
- GREEN complet : 22/22, y compris B15-21 ;
- snapshot B15-04 : `symbol_count=3` et trois records exacts, PE observé
  SHA-256 `a531c80191563c16c8ef4655abe3c80aac66674e70ddc38506404c7668558226` ;
- régression stage-aware : 12/12 B1.4, 10/10 cœur B1.3 et 34/34
  frontières, soit 56/56 ;
- audit PE et source-policy approuvés ;
- NASM 2.16.01 reproductible 3/3.

Le manifeste canonique est
`out/b1/step-5/20260902-231106-295817a46dbb430a92e6a27dfbd6ee27/manifest.md`.
Cette promotion ne promeut pas la Gate B1 et n'autorise pas B1.7 avant B1.6.
