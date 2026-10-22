# Protocole de test — tracer B1.1 `format pe64`

## But et portée

Ce protocole définit le premier tracer RED → GREEN de la Gate B1. Il teste
uniquement l'ouverture de `\NTASM1.NTASM` et la reconnaissance exacte de sa
première ligne sémantique `format pe64`.

Ce tracer ne prouve ni le parseur NTASM-S0 complet, ni les deux passes, ni le
writer PE32+, ni la Gate B1. La Gate B1 reste rouge après B1.1.

Statut courant : **B1.1-r1 GREEN** le 2 septembre 2026. Preuve canonique :
`out/b1/step-1/20260902-145037-be452b87dbe44384bb360d6cdc6b7ded/green-matrix-r1/manifest.md`.

## Autorités et fixtures

- seed RED historique : `bootstrap/seed/seed0.efi` ;
- candidat GREEN canonique : `bootstrap/seed/b1/seed-b1.1-r1.efi` ;
- source positive LF : `legacy/ntasm-s0/golden/minimal.ntasm` ;
- source positive CRLF : `legacy/ntasm-s0/golden/minimal-crlf.ntasm` ;
- source négative format : `legacy/ntasm-s0/invalid/bad-format.ntasm` ;
- source négative sans EOL : `legacy/ntasm-s0/invalid/no-eol.ntasm` ;
- chemin source vu par le seed sur le volume EFI : `\NTASM1.NTASM` ;
- chemin de sortie réservé : `\NTASM1.EFI` ;
- marqueur intermédiaire B1.1 : `NG_B1_1_FORMAT_OK` ;
- diagnostic source absente :
  `NGS0 E001 L0000 C0000 O00000000` ;
- diagnostic lecture/handle invalide :
  `NGS0 E002 L0000 C0000 O00000000` ;
- diagnostic format invalide :
  `NGS0 E200 L0001 C0001 O00000000` ;
- diagnostic fin de ligne absente : `E100`.

`minimal.ntasm` et `minimal-crlf.ntasm` portent la même source minimale normative
du golden décrit par `spec/ntasm/ntasm-s0.md` et `spec/formats/seed-pe32.md`. Le premier utilise
uniquement LF; le second utilise uniquement CRLF, y compris après sa dernière
ligne. `bad-format.ntasm` est la copie LF avec une seule mutation sémantique : la
première ligne vaut `format pe32` au lieu de `format pe64`. `no-eol.ntasm`
contient exactement les onze octets ASCII de `format pe64`, sans LF ni CRLF.

Le marqueur `NG_B1_1_FORMAT_OK` est volontairement distinct de
`NG_SEED0_OK` (succès B0) et de `NG_NTASM_S0_OK` (succès final de l'assembleur).
Il atteste seulement que la première ligne a été acceptée.

## Invariants du banc

Chaque cas utilise un volume EFI jetable et un magasin de variables OVMF neuf.
QEMU/OVMF est lancé sans Secure Boot, réseau, passthrough ni accès à du matériel
réel. Le volume contient le seed comme `EFI\BOOT\BOOTX64.EFI` et au plus une
copie de fixture renommée `NTASM1.NTASM` à sa racine.

Avant chaque lancement, confirmer que `NTASM1.EFI` est absent. Après le
lancement, conserver la sortie console et vérifier l'existence du fichier avec
le mécanisme de lecture du volume jetable. Une capture seule ne prouve pas
l'absence de sortie.

## RED obligatoire — seed B0 actuel

1. Placer `minimal.ntasm` à la racine du volume sous le nom exact
   `NTASM1.NTASM`.
2. Confirmer que `NTASM1.EFI` est absent.
3. Exécuter le seed B0 actuel sous le banc QEMU/OVMF validé par le protocole B0.
4. Vérifier la sortie console et le contenu du volume après le retour au
   firmware.

Le RED est valide seulement si le banc démarre correctement et si les trois
observations suivantes sont réunies :

- le seed B0 affiche son comportement historique `NG_SEED0_OK` ;
- `NG_B1_1_FORMAT_OK` est absent, car le seed B0 ne lit pas
  `\NTASM1.NTASM` ;
- `\NTASM1.EFI` reste absent, car le seed B0 ne crée aucune sortie.

Un crash de QEMU, un échec de chargement du seed ou un volume illisible ne
constitue pas un RED valide : cela prouverait seulement que le banc est cassé.

## GREEN positif LF — première ligne canonique

Après l'implémentation minimale B1.1 seulement :

1. Recréer un volume jetable neuf.
2. Copier `minimal.ntasm` sous le nom exact `NTASM1.NTASM` à sa racine.
3. Confirmer avant le boot que `NTASM1.EFI` est absent.
4. Exécuter le seed B1.1 sous QEMU/OVMF.
5. Exiger exactement une ligne `NG_B1_1_FORMAT_OK` puis un retour propre au
   firmware.
6. Confirmer après le boot que `NTASM1.EFI` est toujours absent.

## GREEN positif CRLF — première ligne canonique

Repartir d'un volume et d'un magasin OVMF neufs, puis répéter le cas positif en
copiant `minimal-crlf.ntasm` sous le nom `NTASM1.NTASM`. Exiger exactement une
ligne `NG_B1_1_FORMAT_OK`, l'absence de `NG_NTASM_S0_OK`, l'absence de
`NTASM1.EFI` avant et après le boot, puis un retour propre au firmware.

Les cas LF et CRLF doivent produire le même résultat observable. Vérifier avant
le boot que les octets du fichier exécuté correspondent au hash de la fixture et
que ses fins de ligne sont réellement celles annoncées.

Le seed B1.1 doit ouvrir et lire `\NTASM1.NTASM`, puis accepter exactement la
première ligne `format pe64` suivie d'un LF ou d'un CRLF. Il ne doit pas accepter
une casse différente, un autre mot, une autre cible, un suffixe ou des tokens
supplémentaires. Le tracer s'arrête après cette reconnaissance : il ne crée pas
encore de PE et ne doit pas afficher `NG_NTASM_S0_OK`.

## GREEN négatif — source absente

Repartir d'un volume et d'un magasin OVMF neufs sans copier de
`NTASM1.NTASM` :

1. Confirmer que `NTASM1.NTASM` et `NTASM1.EFI` sont tous deux absents.
2. Exécuter le seed B1.1 sous QEMU/OVMF.
3. Exiger exactement une ligne
   `NGS0 E001 L0000 C0000 O00000000`.
4. Exiger l'absence de `NG_B1_1_FORMAT_OK` et de `NG_NTASM_S0_OK`.
5. Confirmer après le retour propre au firmware que `NTASM1.EFI` reste absent.

Un Hello B0, un autre diagnostic, plusieurs diagnostics, un marqueur de succès
ou la création d'une sortie font échouer ce cas.

## GREEN négatif — injection E002

Repartir d'un volume et d'un magasin OVMF neufs. Créer à la racine un
**répertoire** nommé exactement `NTASM1.NTASM`, et non un fichier, puis y copier
`minimal.ntasm` sous le nom `ENTRY.NTASM`. Le répertoire non vide garantit sur
le banc OVMF/vvfat qu'un `Read` avec le tampon borné du tracer rencontre une
entrée `EFI_FILE_INFO` trop grande et produit une erreur ou un compte incohérent.

1. Confirmer que `NTASM1.NTASM` est un répertoire non vide et que `NTASM1.EFI` est absent.
2. Exécuter le candidat B1.1.
3. Exiger exactement une ligne
   `NGS0 E002 L0000 C0000 O00000000`.
4. Exiger l'absence des marqueurs de succès et de tout autre diagnostic.
5. Confirmer le retour propre au firmware et l'absence de `NTASM1.EFI`.

Ce cas est le test runtime minimal des chemins erreur de lecture/compte. Il ne
simule pas encore séparément chaque erreur possible de `Close`; ces branches
restent défensives et seront injectées avec le device de test de B1.25.

## GREEN négatif — format invalide

Après le cas positif, repartir d'un volume et d'un magasin OVMF neufs :

1. Copier `bad-format.ntasm` sous le nom exact `NTASM1.NTASM` à la racine du
   volume.
2. Confirmer avant le boot que `NTASM1.EFI` est absent.
3. Exécuter le même seed B1.1.
4. Exiger exactement une ligne
   `NGS0 E200 L0001 C0001 O00000000` pour la première ligne invalide.
5. Exiger l'absence de `NG_B1_1_FORMAT_OK` et de `NG_NTASM_S0_OK`.
6. Confirmer après le retour au firmware que `NTASM1.EFI` est toujours absent.

Tout fichier de sortie, même vide ou partiel, fait échouer ce cas. Un diagnostic
différent, plusieurs diagnostics ou un marqueur de succès font également échouer
le cas.

## GREEN négatif — fin de ligne absente

Repartir d'un volume et d'un magasin OVMF neufs :

1. Copier `no-eol.ntasm` sous le nom exact `NTASM1.NTASM` à la racine du
   volume.
2. Vérifier que ce fichier contient exactement `format pe64` sans octet suivant
   et confirmer que `NTASM1.EFI` est absent.
3. Exécuter le même seed B1.1.
4. Exiger un unique diagnostic NTASM-S0 de code `E100`.
5. Exiger l'absence de `NG_B1_1_FORMAT_OK` et de `NG_NTASM_S0_OK`.
6. Confirmer après le retour propre au firmware que `NTASM1.EFI` reste absent.

Tout EOL ajouté pendant le transport invalide le test. Toute sortie créée, tout
marqueur de succès ou tout diagnostic autre que `E100` fait échouer ce cas.

## Critères d'acceptation du tracer B1.1

B1.1 peut être déclaré vert uniquement si :

1. le RED du seed B0 actuel a été observé sur un banc fonctionnel ;
2. le futur seed B1.1 ouvre réellement `\NTASM1.NTASM` ;
3. `minimal.ntasm` et `minimal-crlf.ntasm` produisent chacun exactement une
   ligne `NG_B1_1_FORMAT_OK` ;
4. la source absente produit exactement
   `NGS0 E001 L0000 C0000 O00000000` ;
5. `bad-format.ntasm` produit exactement
   `NGS0 E200 L0001 C0001 O00000000` ;
6. le répertoire `NTASM1.NTASM` produit exactement
   `NGS0 E002 L0000 C0000 O00000000` ;
7. `no-eol.ntasm` produit uniquement le code `E100` ;
8. aucun cas ne crée `\NTASM1.EFI` ;
9. chaque cas revient proprement au firmware, sans reset, triple fault ni erreur
   fatale QEMU ;
10. les fixtures exécutées ont les mêmes tailles et SHA-256 que les fichiers
   inspectés avant le boot.

Sur un succès, OVMF poursuit vers `Boot0000 UiApp`. Sur un diagnostic retourné
avec `EFI_LOAD_ERROR`, OVMF consigne l'échec attendu puis poursuit vers
`Boot0002 EFI Internal Shell`. Ces deux continuations prouvent un retour propre;
le protocole ne doit pas attendre `UiApp` après un statut d'erreur.

Ces critères valident seulement le tracer B1.1. Ils ne doivent jamais être
présentés comme une Gate B1 complète.
