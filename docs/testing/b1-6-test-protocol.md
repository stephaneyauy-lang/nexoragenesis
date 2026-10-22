# Protocole de test — tracer B1.6

Statut : **tracer B1.6 GREEN, Gate B1 RED**. Le corpus a été figé avant code
et la campagne RED a été exécutée sur le candidat B1.5 canonique SHA-256
`657b3d41dd541cf8630b2b659a29a48c222fc28038516e9e93d176b8db9cadd1`.

## RED

Exécuter B16-00..13 sur quatorze ESP jetables et quatorze magasins de variables
OVMF frais. Le banc compare le diagnostic ou marqueur exact, exige le retour au
firmware, des journaux QEMU/stdout/stderr vides et l'absence de `NTASM1.EFI`.

La campagne est réellement RED si le banc est sain et qu'au moins un attendu
B1.6 diffère pour la raison de périmètre prévue. Les signatures principales sont :

- les valeurs négatives valides observent encore E201 au `-` sous B1.5 ;
- les dépassements négatifs n'atteignent pas encore leur chiffre responsable ;
- le doublon de même casse est encore accepté par B1.5 ;
- les succès B1.5 impriment encore T05, jamais T06.

B16-04 (`+1`) est une non-régression déjà attendue E201 sous B1.5; son succès
individuel n'invalide pas le RED global.

## GREEN

B1.6 est GREEN seulement si :

1. B16-00..13 passent sur le hash final B1.6 ;
2. B16-01, B16-02, B16-08 et B16-07 possèdent un oracle pré-cleanup des records
   conforme aux hashes du manifeste de fixtures ;
3. tout le corpus B1.5 passe, avec ses succès remappés de T05 vers T06 et ses
   diagnostics inchangés ;
4. les suites B1.1–B1.4, limites physiques, canaris, cleanup et ABI restent vertes ;
5. aucun cas ne crée ou ne sonde `NTASM1.EFI` ;
6. NASM 2.16.01 produit trois PE bit-identiques, leur structure est auditée et la
   politique de source reste conforme ;
7. NC-R0 et tous les anciens sources/PE canoniques restent inchangés ;
8. le manifeste canonique n'est créé qu'après cette preuve ; `MEM.md` reste
   réservé à la clôture d'intégration par l'agent principal.

Le marqueur T06 seul ne prouve pas les records, car `WORK` est libéré avant le
succès. Le snapshot doit donc être pris par un probe quarantainé pré-cleanup ou
par un debugger; un hash calculé seulement depuis le design n'est pas une preuve
runtime.

Annonce maximale : « tracer B1.6 GREEN, Gate B1 RED ». Suite : B1.7.

## Promotion exécutée

Les conditions dynamiques et statiques sont satisfaites sur le candidat B1.6
SHA-256
`f1246ec2a1922616f9a6031444cb7dde5a8d09083b18effb11cec5ac7bd4f30e` :

- RED B1.6 valide : 13 divergences prévues sur 14 cas, banc sain 14/14 ;
- cœur B16-00..13 : 14/14 ;
- snapshots pré-cleanup B16-01, B16-02, B16-07 et B16-08 : 4/4 ;
- corpus B1.5 remappé : 22/22 ;
- régressions héritées B1.4/B1.3/B1.2 : 56/56 ;
- reproductibilité NASM 2.16.01 : 3/3, 9 216 octets et hash identique ;
- audit source/PE approuvé : quatre sections, imports nuls, aucune section W+X,
  aucun overlay, relocation DIR64 et politique de quarantaine conforme.

Le manifeste canonique est
`out/b1/step-6/20260902-232720-a7d45bf179a546f4a03691f6f2cdde34/manifest.md`.
`MEM.md` n'est pas modifié par cette sous-tâche. La suite unique est B1.7.
