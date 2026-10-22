# NTASM — bootstrap temporaire C

Autorisé explicitement le 5 septembre 2026 pour accélérer NTASM. Le producteur
C ne délègue pas la traduction NTASM à GCC/Clang : ces outils compilent seulement
le code C de l'outil hôte. Provenance : BOOTSTRAP_EXTERNAL_C, non auto-hébergé.
La cible de livraison reste tout le contrat A1–A10; un test isolé ne la valide pas.

Construction et tests depuis WSL (racine du projet) :

```text
mkdir -p out/c-bootstrap
cc -std=c17 -Wall -Wextra -Werror -O0 -g compiler/c/ntasm/frontend/ntasm.c tests/c/ntasm/tests.c -o out/c-bootstrap/tests
out/c-bootstrap/tests
```

Premier outil Windows vérifié : `out/c-bootstrap/host-v1/ntasm.exe`.
Ses sources exactes sont conservées dans `host-v1/sources/`.
Le profil de ce snapshot accepte uniquement une fonction main retournant un
littéral u64; il refuse les constructions qui ne sont pas implémentées.

```text
out\c-bootstrap\host-v1\ntasm.exe check examples\ntasm-v0\c-bootstrap\return42.ntasm
out\c-bootstrap\host-v1\ntasm.exe assemble examples\ntasm-v0\c-bootstrap\return42.ntasm -o out\c-bootstrap\my-first.efi
out\c-bootstrap\host-v1\ntasm.exe inspect out\c-bootstrap\my-first.efi
```

L'assemblage refuse une sortie existante; choisir un chemin neuf. `inspect`
valide le PE indépendamment du writer et rend un résumé JSON. L'exécution de
la fonction est testée par le consommateur QEMU sous `uefi-test/`, pas par une
promesse fondée uniquement sur l'existence du fichier.

Le plan directeur de reprise C et l'état des exigences sont dans
`legacy/docs/bootstrap/c-bootstrap.md`. Les preuves anciennes restent immuables.
