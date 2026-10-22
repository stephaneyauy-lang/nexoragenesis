# ADR 0009 — Exception NASM temporaire pour le bootstrap

- **Statut :** Accepté
- **Date :** 2026-09-02
- **Autorisation :** décision explicite de l'utilisateur du 2026-09-02
- **Outil autorisé :** NASM `2.16.01` uniquement
- **Label obligatoire :** `BOOTSTRAP_EXTERNAL_ASM`
- **Amendement étroit :** ADR 0010 autorise les probes Nova Compute CPU R0 et R1 pré-kernel explicitement nommés, sans élargir NASM au noyau ou à l'OS final.

## Contexte

Les ADR 0002 et 0005 interdisent qu'un assembleur étranger produise les
binaires Genesis et imposent un seed initial saisi et audité en octets. Cette
discipline reste l'objectif final. Pendant la fermeture du bootstrap, la saisie
manuelle de chaque révision ralentit toutefois la validation des layouts PE, des
appels UEFI, des diagnostics et des tests de frontière.

L'utilisateur autorise donc une exception temporaire, explicite et révocable :
NASM peut matérialiser des candidats de bootstrap externes afin d'accélérer les
tests et la comparaison avec NTASM. Cette exception ne transforme pas NASM en
outil Genesis et ne donne aucune valeur souveraine à ses sorties.

## Décision

NASM `2.16.01` est autorisé uniquement sous
`legacy/nasm/`. Toute source, sortie, preuve et commande relevant
de cette exception porte visiblement le label `BOOTSTRAP_EXTERNAL_ASM`.

Les règles suivantes sont obligatoires :

1. Les sources NASM restent dans la quarantaine et utilisent une extension
   d'assembleur étranger explicite. Leur première ligne non vide contient
   `; BOOTSTRAP_EXTERNAL_ASM`.
2. NASM est appelé directement avec `-f bin`. Aucun objet intermédiaire, linker,
   compilateur C/C++, assembleur secondaire ou générateur PE n'est autorisé.
3. Les sorties NASM restent dans la quarantaine. Elles peuvent être placées sur
   un volume EFI jetable pour QEMU/OVMF, mais ne deviennent ni un seed canonique,
   ni une racine de confiance, ni une sortie finale Genesis.
4. Aucun fichier NASM, objet ou binaire portant le label
   `BOOTSTRAP_EXTERNAL_ASM` n'est une source d'un OS final. Il ne peut être
   importé, lié, embarqué ou copié dans un build produit.
5. La version est figée à `2.16.01`. Un changement de version exige une nouvelle
   décision explicite et invalide les hashes et preuves antérieurs.
6. Chaque exécution consigne la commande exacte, la sortie de `nasm -v`, le
   SHA-256 de la source, le SHA-256 de la sortie, la taille produite, les tests
   exécutés et leur résultat.
7. Une sortie NASM n'est jamais une preuve à elle seule. Les champs PE, les
   permissions, les relocations, les branches, les appels UEFI, l'absence
   d'import/W+X/overlay et le comportement QEMU/OVMF restent audités
   indépendamment.

Cette ADR amende temporairement les ADR 0002 et 0005 pour ce seul périmètre.
Elle ne les annule pas : la pureté de la chaîne productrice finale, le rôle de
NTASM et l'absence d'assembleur externe dans les builds Genesis restent les
gates de sortie.

## Commandes et preuves minimales

Les noms sont remplacés par ceux du candidat testé. La source et la sortie
productrice restent dans la quarantaine; une copie peut seulement entrer dans un
ESP jetable sous `out/` pour exécution :

```text
wsl.exe -e bash -lc "nasm -v"
wsl.exe -e bash -lc "cd /mnt/c/NexoraGenesis && nasm -f bin legacy/nasm/<candidat>.asm -o legacy/nasm/out/<candidat>.efi"
Get-FileHash -Algorithm SHA256 bootstrap\quarantine\nasm\<candidat>.asm
Get-FileHash -Algorithm SHA256 bootstrap\quarantine\nasm\out\<candidat>.efi
```

La sortie de la première commande doit identifier exactement NASM `2.16.01`.
Les commandes sont exécutées interactivement ou consignées comme preuve; aucun
script PowerShell, Batch, shell, C ou autre source hôte n'est ajouté au projet.

Chaque candidat doit ensuite passer au minimum :

- inspection PE32+ et désassemblage en lecture seule ;
- vérification des tailles, hashes, sections, droits et relocations attendus ;
- tests QEMU/OVMF sur volume et magasin de variables jetables ;
- matrice fonctionnelle et négative du tracer concerné ;
- confirmation qu'aucun artefact **producteur** hors quarantaine n'a été créé;
  les copies d'exécution et preuves sont confinées sous `out/` ;
- comparaison byte pour byte avec la future sortie NTASM correspondante.

Un manifeste de run indique au minimum :

```text
label=BOOTSTRAP_EXTERNAL_ASM
nasm_version=2.16.01
command=<commande exacte>
source_path=<chemin sous bootstrap/quarantine/nasm>
source_sha256=<64 hex>
output_path=<chemin sous bootstrap/quarantine/nasm>
output_size=<octets>
output_sha256=<64 hex>
tests=<identifiants et résultats>
```

## Premier exercice réel de l'exception

Le 2 septembre 2026, `legacy/nasm/seed-b1.2-r1.asm` a produit
directement `legacy/nasm/out/seed-b1.2-r1.efi` avec NASM 2.16.01
et `-f bin`, sans objet intermédiaire ni linker.

- source : 22 591 octets, SHA-256
  `59affe1f1231e9b8ccfa304b58316c4cbdca9ea1fee6f809a199767d32364fc5` ;
- sortie : 7 680 octets, SHA-256
  `19b302389215f8377823e1577c1263dbba6e7a39b78b0cb628462c5e025bbddd` ;
- reproductibilité : deux reconstructions fraîches identiques ;
- inspection : PE32+ AMD64 EFI Application, quatre sections, import nul,
  aucune W+X/overlay, relocation DIR64 à RVA `0x3300` ;
- tests : 24/24 oracles B1.2 et 4/4 non-régressions B1.1, aucun
  `NTASM1.EFI` ;
- preuve canonique :
  `out/b1/step-2/20260902-172215-65d1b7dcff08475a974763b49f036e46/manifest.md`.

Les copies `BOOTX64.EFI` contenues dans les ESP de preuve sont des transports
jetables. Elles ne deviennent ni producteur, ni racine de confiance, ni sortie
Genesis. L'ADR reste active jusqu'à reproduction bit-identique par NTASM.

Le même mécanisme a ensuite produit B1.3 : source SHA-256
`144da0a41ba8f272708e81dcc61f48fe55466c5f52661fe1e0fce7da7b435b0c`,
PE 7 680 octets SHA-256
`f6e4022ccd1938b680e6eb69f6ecb06518680b9455c940fde2d1bc0b9a082eb2`,
reproductible 2/2. Les 44 boots finaux passent sans output. Cette nouvelle
preuve n'étend pas l'autorisation : même outil, même version, mêmes chemins et
mêmes critères de sortie.

## Critères de sortie

L'exception prend fin seulement lorsque toutes les conditions suivantes sont
prouvées :

1. NTASM assemble la source maison correspondante sans appeler NASM, un linker
   ou un autre producteur externe.
2. La sortie NTASM reproduit byte pour byte chaque artefact quarantiné encore
   nécessaire; taille et SHA-256 sont identiques sur au moins deux builds frais.
3. Les tests structurels et QEMU/OVMF passent sur la sortie NTASM seule.
4. Le build final et sa trace de processus ne chargent ni NASM ni une sortie
   `BOOTSTRAP_EXTERNAL_ASM`.
5. La politique de build final échoue explicitement si `nasm`, une source
   assembleur étrangère ou un artefact de quarantaine entre dans le chemin
   producteur.

Après cette sortie, la quarantaine peut rester comme preuve historique, mais
elle est inactive et n'est jamais une dépendance du build. NASM redevient
entièrement interdit dans le chemin producteur normal.

## Conséquences

- Le bootstrap peut être testé plus vite sans dissimuler son producteur externe.
- Les sorties temporaires restent non souveraines et explicitement contaminées.
- Deux chaînes peuvent être comparées jusqu'à l'égalité bit à bit.
- La quarantaine et ses preuves augmentent le travail d'audit à court terme.
- Toute fuite d'un artefact quarantiné vers un build final est un échec de gate,
  même si son hash correspond à une sortie NTASM.

## Non-objectifs

- Autoriser NASM hors de `legacy/nasm/`.
- Autoriser C, C++, Rust, Zig, un script hôte, un objet ou un linker.
- Faire de NASM une dépendance permanente ou de secours.
- Remplacer NTASM, ses deux passes, son writer PE ou ses preuves.
- Qualifier une sortie externe de seed souverain ou de binaire OS final.
- Affaiblir les objectifs de pureté finale des ADR 0002 et 0005.

## Gates

- **Gate de quarantaine :** source et sortie productrices restent sous la
  quarantaine avec labels, commandes et hashes auditables; seules leurs copies
  d'exécution et preuves jetables peuvent résider sous `out/`.
- **Gate de version :** `nasm -v` prouve exactement `2.16.01` avant chaque run.
- **Gate de test :** inspection structurelle et matrice QEMU/OVMF concordent avec
  les oracles du tracer.
- **Gate bit-identique :** NTASM reproduit exactement les octets et le SHA-256 du
  candidat retenu.
- **Gate final sans NASM :** le build produit, sa configuration et sa trace de
  processus prouvent l'absence de NASM et refusent toute entrée quarantinée.
