# Protocole de test — tracer B1.3 préambule sémantique

## Statut et portée

Statut final : **tracer B1.3 GREEN, Gate B1 RED**. Preuve canonique :
`out/b1/step-3/20260902-185633-f6ba2d902cf048a6a51633dfb7651f77/manifest.md`.

Le RED a été observé avant le premier changement B1.3. Huit cas autoritatifs sur
le candidat B1.2 ont produit un comportement différent de l'oracle B1.3 tout en
gardant le banc vert : retour firmware, QEMU zéro, journaux vides et aucune
sortie. Preuve :
`out/b1/step-3/agent-red-20260902-180451-eae138665ad5/manifest.md`.

B1.3 ajoute uniquement whitespace/commentaires et `abi efi_x64`. Il ne commence
ni constantes, ni identifiants généraux, ni `entry`, ni sections, ni passes, ni
writer PE. L'annonce maximale reste « tracer B1.3 GREEN, Gate B1 RED ».

## Ordre TDD observé

1. `valid-exact` a échoué car B1.2 affichait encore son ancien marqueur ;
2. le minimum exact LF/CRLF a reçu `NG_S0_T03_OK` ;
3. ABI absente a d'abord rendu L1/C1/O0, puis a été corrigée vers EOF L2/C1/O0C ;
4. `abi sysv` a d'abord rendu L1/C1/O0, puis le premier écart L2/C5/O10 ;
5. la fixture combinant lignes vides, whitespace, tabs et commentaires a
   d'abord rendu E200, puis a reçu le marqueur T03 ;
6. après chaque GREEN, les verticales précédentes ont été rejouées.

Les preuves intermédiaires portent les préfixes `tdd-slice1` à `tdd-slice4`
sous `out/b1/step-3/`. Elles documentent l'ordre; le manifeste final cité plus
haut promeut le tracer.

## Machine sémantique exigée

Le scanner physique B1.2 s'exécute intégralement en premier. Puis un itérateur
borné parcourt les records de lignes dans `WORK` :

- index strictement inférieur à `F_LINES_DONE` ;
- `start + length <= source_len` avant formation du pointeur ;
- trim SP/TAB et coupe du premier `;` ; à B1.3 aucune chaîne n'est admise dans
  le préambule, donc tout `"` antérieur reste un octet fautif E200 ;
- saut des lignes logiquement vides ;
- comparaison `format`/`pe64`, puis `abi`/`efi_x64`, séparés par WS+ ;
- aucun token supplémentaire avant commentaire/EOL ;
- arrêt sémantique après la seconde directive, sans analyser le suffixe.

E100/E101/E500 physiques dominent E200. E200 utilise le premier octet fautif de
l'ABI; l'absence de directive utilise l'EOF virtuel. Le mauvais format historique
reste positionné au premier octet sémantique.

## Promotion

B1.3 est GREEN seulement après :

1. corpus cœur B13-00..09 entièrement vert, dont B13-09 contrôle hérité ;
2. ponts B13-P00..P05 verts ;
3. rejeu stage-aware des 24 cas B1.2 et des quatre non-régressions B1.1 ;
4. inspection PE/désassemblage, bounds et ABI approuvés ;
5. build NASM reproductible 2/2, label externe et hashes consignés ;
6. aucune source étrangère hors quarantaine et aucune sortie `NTASM1.EFI` ;
7. manifeste canonique, documentation et `MEM.md` concordants.

Ces sept conditions sont satisfaites. La prochaine étape est B1.4, jamais B2.
