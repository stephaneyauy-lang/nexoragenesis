# Quarantaine NASM du bootstrap

Source actif unique depuis le 5 septembre :
[`ntasm-bootstrap.asm`](ntasm-bootstrap.asm), modifié en place pour le
chantier global. Les `seed-b1.*.asm` existants sont historiques; ne plus
en créer à chaque sous-étape. Sortie de développement :
`out/ntasm-bootstrap.efi`.

> **BOOTSTRAP_EXTERNAL_ASM** — tout contenu de ce dossier est externe,
> temporaire, non souverain et interdit aux builds finaux.

Cette quarantaine applique l'ADR
[`0009-temporary-nasm-bootstrap.md`](../../docs/architecture/decisions/0009-temporary-nasm-bootstrap.md).
Elle autorise uniquement NASM `2.16.01` pour matérialiser et tester des candidats
de bootstrap provisoires. Elle n'autorise ni C/C++, ni linker, ni objet
intermédiaire, ni script hôte persistant.

## Périmètre

- Toute source NASM et toute sortie productrice reste sous ce dossier. Les
  copies d'exécution et preuves QEMU peuvent résider uniquement sous `out/` dans
  un volume jetable identifié par leur manifeste.
- Chaque source commence par `; BOOTSTRAP_EXTERNAL_ASM`.
- Chaque manifeste contient `label=BOOTSTRAP_EXTERNAL_ASM`.
- Seul le format NASM `-f bin` est admis.
- Une sortie peut être transportée vers un volume EFI jetable pour un test, mais
  elle ne devient jamais un artefact canonique hors quarantaine.
- Aucun contenu de ce dossier n'est une source ou une dépendance d'un OS final.

Organisation réelle du premier candidat :

```text
legacy/nasm/
  seed-b1.2-r1.asm  source NASM explicitement labellisée
  out/       binaires provisoires produits avec -f bin
```

Les preuves lourdes restent dans `out/b1/...`; elles ne sont jamais des entrées
du chemin producteur.

## Run minimal

Depuis la racine du projet :

```text
wsl.exe -e bash -lc "nasm -v"
wsl.exe -e bash -lc "cd /mnt/c/NexoraGenesis && nasm -f bin legacy/nasm/<candidat>.asm -o legacy/nasm/out/<candidat>.efi"
Get-FileHash -Algorithm SHA256 bootstrap\quarantine\nasm\<candidat>.asm
Get-FileHash -Algorithm SHA256 bootstrap\quarantine\nasm\out\<candidat>.efi
```

Le run est recevable seulement si :

1. la version affichée est exactement `2.16.01` ;
2. la commande exacte et les hashes source/sortie sont consignés ;
3. aucun linker ou autre producteur n'est lancé ;
4. l'inspection PE/désassemblage et les tests QEMU/OVMF attendus passent ;
5. aucun artefact producteur hors quarantaine n'a été créé; seules des copies
   d'exécution et preuves jetables sous `out/` sont admises ;
6. la sortie reste marquée `BOOTSTRAP_EXTERNAL_ASM` dans sa preuve.

## Manifeste de preuve

Chaque run conserve au minimum :

```text
label=BOOTSTRAP_EXTERNAL_ASM
nasm_version=2.16.01
command=<commande exacte>
source_path=<chemin relatif sous cette quarantaine>
source_sha256=<64 hex>
output_path=<chemin relatif sous cette quarantaine>
output_size=<octets>
output_sha256=<64 hex>
inspection=<résultat>
tests=<identifiants et résultats>
```

## Premier run vérifié

`seed-b1.2-r1.asm` a été assemblé avec NASM 2.16.01, directement en `-f bin` :

- source : 22 591 octets, SHA-256
  `59affe1f1231e9b8ccfa304b58316c4cbdca9ea1fee6f809a199767d32364fc5` ;
- sortie : 7 680 octets, SHA-256
  `19b302389215f8377823e1577c1263dbba6e7a39b78b0cb628462c5e025bbddd` ;
- deux reconstructions fraîches : même SHA-256 ;
- matrice : 24/24 oracles et 4/4 non-régressions, aucune sortie
  `NTASM1.EFI` ;
- preuve :
  `out/b1/step-2/20260902-172215-65d1b7dcff08475a974763b49f036e46/manifest.md`.

Le candidat B1.3 est également vérifié : source 27 058 octets, SHA-256
`144da0a41ba8f272708e81dcc61f48fe55466c5f52661fe1e0fce7da7b435b0c`;
sortie 7 680 octets, SHA-256
`f6e4022ccd1938b680e6eb69f6ecb06518680b9455c940fde2d1bc0b9a082eb2`;
10/10 cas cœur et 34/34 régressions/frontières. Son manifeste producteur est
`out/build-b1.3-manifest.txt` et sa preuve canonique est
`out/b1/step-3/20260902-185633-f6ba2d902cf048a6a51633dfb7651f77/manifest.md`.

La quarantaine est toujours active : NTASM n'a encore reproduit ni B1.2 ni B1.3.

## Probe Nova Compute CPU R0

ADR 0010 autorise également le seul probe pré-kernel
`nova-compute-cpu-r0-r1.asm`. Il reste `BOOTSTRAP_EXTERNAL_ASM`, non souverain,
non release-éligible et sans dépendance finale.

- source : 4 808 octets, SHA-256
  `9546c58432e3469ae7a1819ba27f29a01bbb040f31a5142bfffb7452f587c8ce`;
- PE canonique : 3 072 octets, SHA-256
  `b9d6cafacfb5138cff3aa7d56fb7740bb1d4ad247e38c3f051a6c8c6131d37e8`;
- deux builds identiques;
- deux boots succès et deux fautes contrôlées : 4/4;
- preuve :
  `out/nova-cpu/r0/20260902-210855-22abc27896d449ad85a029c6ac28b720/manifest.md`.

Ce binaire n'analyse aucune source `.nova`, n'appelle pas `ExitBootServices` et
ne fait jamais partie du noyau ou du build final.

## Probe Nova Compute CPU R1

ADR 0010 autorise aussi explicitement
`nova-compute-cpu-r1-r1.asm` comme probe pré-kernel externe, toujours sans
source `.nova`, sans noyau et sans éligibilité release.

- source : 25 695 octets, SHA-256
  `60833edf2f3067fa2942657f10d4e777bd6c594865b1eed50e843d10c718e45a` ;
- PE canonique : 8 192 octets, SHA-256
  `cca37e90bd78cba9d62ada4377d62996ba5c843f377dc1517685a8f4f69c7156` ;
- reproductibilité NASM 2.16.01 : 3/3 ;
- tables A/B/G : 256 dwords chacune, 256/256 additions vérifiées ;
- corpus `N=0,1,15,16,17,255,256`, flux 2 254 octets et digest
  `7CF3026858C7AC7C` ;
- deux succès et six faults dirigés : 8/8 sous QEMU/OVMF, 24/24 logs vides ;
- preuve :
  `out/nova-cpu/r1/runtime-final-root-69d8a0eb18b448efb16a9788d6f43815/manifest.md`.

Les anciens artefacts de travail `fault-guard.efi` et
`fault-zero-n-write.efi` sont `SUPERSEDED_NONCANONICAL`; ils sont conservés
pour audit mais exclus des builds et tests retenus.

## Candidat B1.4

- source : 30 913 octets, SHA-256
  `9677a83f4ef97ad41d572226dbcfa1b6b231f92f8b79cfe0feadfaaeab460c07`;
- sortie : 7 680 octets, SHA-256
  `f994f31fa718a4ca2456c01ac4320fab1cd828945ad9dd7527c8f3aa08349b70`;
- reproductibilité 2/2 ; campagnes 12/12 + 10/10 + 34/34 ;
- preuve :
  `out/b1/step-4/20260902-215921-b48ac1a7b2c04c4ea9b9d922948bd75d/manifest.md`.

Le suffixe après `=` reste volontairement non analysé; l'entier commence en
B1.5. Ce candidat ne fait jamais partie d'une release.

## Candidat B1.5

- source : 37 995 octets, SHA-256
  `4bd49f49ef29aec677d160e2edb3cb0e7d288d6347430d7280eb3cb69ce943c9` ;
- sortie : 9 216 octets, SHA-256
  `657b3d41dd541cf8630b2b659a29a48c222fc28038516e9e93d176b8db9cadd1` ;
- reproductibilité NASM 2.16.01 : 3/3 ;
- corpus B1.5 22/22 et régressions stage-aware 56/56 ;
- PE32+ x86_64 EFI, quatre sections, import nul, aucune section W+X ni
  overlay, relocation DIR64 conservée ;
- preuve canonique :
  `out/b1/step-5/20260902-231106-295817a46dbb430a92e6a27dfbd6ee27/manifest.md`.

Le candidat parse les entiers non signés décimaux/hexadécimaux et stocke les
records constants bornés. Il reste `BOOTSTRAP_EXTERNAL_ASM`, non souverain et
interdit à toute release finale. La prochaine étape est B1.6.

## Candidat B1.6

- source : 42 315 octets, SHA-256
  `faa4725d1217d83491cad2c5c0cf8b0db2dc1c6fd8c42b7698bd1c97d696f293` ;
- sortie : 9 216 octets, SHA-256
  `f1246ec2a1922616f9a6031444cb7dde5a8d09083b18effb11cec5ac7bd4f30e` ;
- reproductibilité NASM 2.16.01 : 3/3 ;
- RED B1.6 valide, cœur B16 14/14, snapshots 4/4, corpus B1.5 22/22 et
  régressions héritées 56/56 ;
- PE32+ x86_64 EFI, quatre sections, imports nuls, aucune section W+X ni
  overlay, relocation DIR64 ;
- manifeste producteur : `out/build-b1.6-manifest.txt` ;
- preuve canonique :
  `out/b1/step-6/20260902-232720-a7d45bf179a546f4a03691f6f2cdde34/manifest.md`.

B1.6 ajoute le signe négatif, borne les magnitudes négatives à `2^63`,
conserve le flag lexical de `-0` et rejette les doublons exacts par E300. Le
candidat reste `BOOTSTRAP_EXTERNAL_ASM`, non souverain et interdit à toute
release finale. La prochaine étape est B1.7.

## Candidat B1.7

- source : 51 602 octets, SHA-256
  `17c296087c471dda1bbd6bf31a6e03fbac11215802b6bfd2a35990bd28d1c625` ;
- sortie : 9 728 octets, SHA-256
  `169a362b036edce895c1bf4d523f35ce3966d56e0ba6059c0ba3a2a4571f6702` ;
- reproductibilité NASM 2.16.01 : 3/3 bit-identique ;
- RED 19/19 divergent avec banc sain, cœur final 19/19, snapshots 7/7,
  B1.6 14/14, B1.5 22/22 et héritage 56/56 ;
- PE32+ x86_64 EFI, quatre sections, imports nuls, aucune section W+X ni
  overlay, relocation DIR64 ;
- manifeste producteur : `out/build-b1.7-manifest.txt` ;
- preuve canonique :
  `out/b1/step-7/20260904-204749-9790129aa52c4ec2995080290bf5a7d7/manifest.md`.

B1.7 exige une unique directive `entry IDENT`, ferme la phase des constantes
et conserve un descripteur source de cinq qwords. Le candidat reste
`BOOTSTRAP_EXTERNAL_ASM`, non souverain et interdit à toute release finale.
La prochaine étape est B1.8.

## Sortie de quarantaine

Le candidat historique **B1.8 GREEN**, source
`seed-b1.8-r1.asm` de 69 010 octets, SHA-256
`7ae2e397cf8b260535511e2c1d25da3549a54670b68bcd5c8fb4238230c4078d`.
Son PE `out/seed-b1.8-r1.efi` fait 11 264 octets, SHA-256
`dafb0aff3407f48e782599475b8ca7a20727767892561dee0ab419852d61ab3e`.
Il passe 35 nouveaux cas, 111 régressions, deux contrôles mémoire et trois
reconstructions identiques. Preuve : `out/b1/step-8/promotion-r1/manifest.md`
depuis la racine du projet; producteur : `out/build-b1.8-manifest.txt`.
Gate B1 reste RED.

Le dernier candidat est **B1.10 GREEN**, après B1.9. Son PE fait 11 776 octets,
SHA-256 `e673f8f07ee8f5f472f346c19587804f9f34c25677070e3cacd010b57da4b5f7`.
Les 201 cas retenus passent et trois builds sont identiques. Preuves depuis
la racine : `out/b1/step-9/promotion-r1/manifest.md` et
`out/b1/step-10/promotion-r1/manifest.md`. Prochaine étape B1.11.

La quarantaine cesse d'être active lorsque NTASM reproduit la sortie retenue
bit pour bit, avec le même SHA-256 sur deux builds frais, et que les tests passent
sans NASM. Le build final doit refuser explicitement :

- toute invocation de `nasm` ;
- toute source assembleur étrangère ;
- toute entrée ou sortie labellisée `BOOTSTRAP_EXTERNAL_ASM` ;
- toute dépendance à `legacy/nasm/`.

Après cette preuve, le dossier peut être conservé uniquement comme historique
d'audit. Il ne fait jamais partie de la chaîne productrice finale.
