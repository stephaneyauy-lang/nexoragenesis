# ADR 0002 — Pureté des sources et de la chaîne productrice

- **Statut :** Accepté
- **Date :** 2026-09-02
- **Amendement temporaire :** ADR 0009 pour NASM uniquement dans la quarantaine
  du bootstrap; l'objectif de pureté finale est inchangé.

## Contexte

Le projet refuse qu'un compilateur, assembleur, linker ou générateur étranger produise ses exécutables. Cette contrainte n'est vérifiable que si les sources autorisées, les données admises et les outils d'observation sont séparés sans ambiguïté.

Dans cet ADR, **notre langage** désigne un langage spécifié et maintenu par Nexora Genesis dont la source exécutable appartient à l'un des quatre profils autorisés : NX, Cnuva, Nova ou NTASM. Renommer un fichier étranger avec une extension autorisée ne le transforme pas en « notre langage ».

Un **binaire** est une suite d'octets directement interprétée par une machine, un firmware, un périphérique ou un chargeur. Les PE32+, NXO, NXK, NXB, NVO et NMU ainsi que les fixtures binaires sont des binaires; ils ne sont pas des sources et doivent conserver un producteur et une provenance auditable.

Le **chemin producteur** est l'ensemble des processus et entrées qui traduisent, assemblent, lient, empaquettent ou génèrent un binaire Genesis.

## Décision

Les seules sources exécutables autorisées sont :

| Extension | Profil | Domaine |
|---|---|---|
| `.nx` | NX | applications, services, Orbit, NexShell et logique portable |
| `.cnuva` | Cnuva | CPU, noyau, plateforme, runtime et pilotes génériques |
| `.nova` | Nova | pilote GPU côté hôte et kernels GPU côté device |
| `.ntasm` | NTASM | niveau machine typé, bootstrap et séquences non exprimables autrement |

Sont interdites comme sources exécutables, dans l'arbre et dans le build normal :

- C et C++ : `.c`, `.h`, `.cc`, `.cpp`, `.cxx`, `.hh`, `.hpp`, `.hxx`;
- Rust : `.rs`;
- Zig : `.zig`;
- Go : `.go`;
- Python : `.py`, `.pyw`;
- Java : `.java`;
- C# : `.cs`;
- JavaScript et TypeScript : `.js`, `.mjs`, `.cjs`, `.jsx`, `.ts`, `.tsx`;
- Lua : `.lua`;
- PowerShell : `.ps1`, `.psm1`, `.psd1`;
- Batch : `.bat`, `.cmd`;
- shells : `.sh`, `.bash`, `.zsh`, `.fish`;
- assembleurs étrangers : `.asm`, `.s`, `.S`, `.nasm`, `.masm`, `.fasm`.

Cette liste explicite est minimale : toute autre source exécutable qui n'est pas NX, Cnuva, Nova ou NTASM est également interdite. Sont aussi interdits dans le chemin producteur NASM, GAS, MASM, FASM, l'assembleur inline étranger, LLVM, GCC, Clang, MSVC, `link.exe`, `ld`, `lld`, LLVM MC et tout générateur externe de PE, d'objet, de SPIR-V ou de code machine.

Sont autorisés comme documentation ou données non exécutables : Markdown, polices, images, tables ISA déclaratives dans un format maison, hashes, fixtures binaires et artefacts Genesis. Aucun de ces formats ne doit dissimuler du code interprété, des commandes de build ou un payload exécutable non déclaré.

Les outils externes peuvent uniquement observer, transporter ou exécuter : éditeur hexadécimal, QEMU, OVMF, désassembleur et débogueur en lecture seule, calculateur de hash et comparateur binaire. Ils ne traduisent aucune source Genesis. Git n'est utilisable qu'après autorisation explicite et ne devient jamais un producteur.

## Conséquences

- Le bootstrap commence nécessairement par un seed binaire saisi et audité manuellement.
- Les outils de build, encodeurs, writers de formats et inspecteurs producteurs devront être écrits dans les langages maison.
- Une commodité hôte ne peut pas être ajoutée sous forme de script temporaire étranger.
- Les observations externes restent permises, car les interdire rendrait l'audit et l'exécution impossibles sans améliorer la souveraineté du producteur.

## Non-objectifs

- Prétendre que le matériel, l'UEFI, OVMF, QEMU ou le système hôte sont souverains.
- Interdire les documents, les données et les outils d'observation non producteurs.
- Autoriser un langage étranger parce que sa sortie est ensuite revalidée ou réencodée par un outil maison.
- Assimiler « zéro assembleur étranger » à « zéro NTASM » : NTASM est le niveau machine maison autorisé.

## Preuves et gates

- Revue manuelle immédiate : chaque fichier exécutable futur doit appartenir à l'une des quatre extensions autorisées.
- Chaque binaire doit déclarer ses entrées, son producteur, sa version et son hash; le seed suit en plus son ledger intégral.
- Gate B2 : NTASM atteint un point fixe bit-identique sans assembleur externe.
- Gate B4 : le compilateur commun et les outils producteurs sont auto-hébergés et déterministes.
- Gate B5 : `source-policy` refuse toutes les extensions ci-dessus, les sources étrangères déguisées et tout producteur externe; une trace de processus confirme la fermeture du build.
