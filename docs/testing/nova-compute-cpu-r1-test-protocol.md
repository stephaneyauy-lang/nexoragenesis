# Protocole de test — Nova Compute CPU R1 externe

Statut : **exécuté, NC-R1-PROBE GREEN**. La preuve canonique 8/8 est
`out/nova-cpu/r1/runtime-final-root-69d8a0eb18b448efb16a9788d6f43815/manifest.md`.

Contrat de référence :
`legacy/docs/bootstrap/nova-compute-cpu-r1-design.md`. Le GREEN B1.6 préalable ne
transforme pas ce probe en Nova compilé, en noyau ou en artefact de release.

## RED exécuté : R0 ne satisfait pas R1

Avant de promouvoir un candidat R1, booter le PE R0 canonique, SHA-256
`b9d6cafacfb5138cff3aa7d56fb7740bb1d4ad247e38c3f051a6c8c6131d37e8`,
avec un ESP et un magasin OVMF frais. L'oracle R1 exige :

```text
NG_NOVA_CPU_R1_OK CASES=7 N=0,1,15,16,17,255,256 SEM=MOD2P32 EXEC=SCALAR DIGEST=7CF3026858C7AC7C
```

Le RED est recevable si le boot R0 retourne au firmware, imprime exactement son
marqueur R0 historique et zéro occurrence de tout marqueur `NG_NOVA_CPU_R1_`.
Cela démontre l'absence du corpus à sept longueurs, du suffixe R1 et du digest de
run dans R0; cela ne prétend pas que R0 est cassé.

Ce RED a été exécuté avant le GREEN et est conservé sous
`out/nova-cpu/r1/tdd-red-da649a352e894e3baf6cb8f11cbe8249` : R0 affiche son
marqueur exact, zéro marqueur R1, puis retourne au firmware avec ses journaux
contrôlés vides.

## Préconditions de campagne

- NASM affiche exactement `NASM version 2.16.01` et produit directement avec
  `-f bin`, sans objet ni linker.
- Le source et toutes ses sorties productrices restent sous
  `legacy/nasm/` et portent `BOOTSTRAP_EXTERNAL_ASM`.
- Le manifeste porte au minimum
  `bootstrap_provenance=external-nasm`, `release_eligible=false` et
  `final_dependency=false`.
- QEMU/OVMF est le seul environnement d'exécution; `-nic none`, aucun
  passthrough et aucun matériel réel.
- Chaque boot reçoit un ESP jetable et un magasin de variables OVMF frais.
- Les six binaires de faute définissent exactement une macro test-only; le
  binaire canonique n'en définit aucune.
- L'ordre d'oracle est console, corpus (liste N puis FNV), garde, résultat,
  suffixe, digest.

## Matrice obligatoire 2 + 6

| ID | Construction | Oracle CHAR16 exact | Résultat attendu |
|---|---|---|---|
| NC-R1-GREEN-01 | canonique | `NG_NOVA_CPU_R1_OK CASES=7 N=0,1,15,16,17,255,256 SEM=MOD2P32 EXEC=SCALAR DIGEST=7CF3026858C7AC7C` | succès, retour firmware |
| NC-R1-GREEN-02 | canonique, OVMF neuf | même oracle | succès, retour firmware |
| NC-R1-NEG-CORPUS | `R1_FAULT_CORPUS=1` | `NG_NOVA_CPU_R1_E204_CORPUS` | `EFI_COMPROMISED_DATA`, retour firmware |
| NC-R1-NEG-RESULT | `R1_FAULT_RESULT=1` | `NG_NOVA_CPU_R1_E201_RESULT` | `EFI_ABORTED`, retour firmware |
| NC-R1-NEG-SUFFIX | `R1_FAULT_SUFFIX=1` | `NG_NOVA_CPU_R1_E203_SUFFIX` | `EFI_COMPROMISED_DATA`, retour firmware |
| NC-R1-NEG-GUARD-LO | `R1_FAULT_GUARD_LO=1` | `NG_NOVA_CPU_R1_E202_GUARD` | `EFI_COMPROMISED_DATA`, retour firmware |
| NC-R1-NEG-GUARD-HI | `R1_FAULT_GUARD_HI=1` | `NG_NOVA_CPU_R1_E202_GUARD` | `EFI_COMPROMISED_DATA`, retour firmware |
| NC-R1-NEG-DIGEST | `R1_FAULT_DIGEST=1` | `NG_NOVA_CPU_R1_E205_DIGEST` | `EFI_COMPROMISED_DATA`, retour firmware |

Pour chaque boot : exactement un oracle R1, aucun autre marqueur R1, aucun
marqueur de succès sur une faute, retour visible vers le firmware, HMP encore
réactif, puis arrêt contrôlé avec code QEMU 0.

Les fichiers `qemu.log`, `qemu-stdout.log` et `qemu-stderr.log` doivent tous
être vides : **0/24 logs non vides** sur huit boots. Les lignes attendues sont
capturées par le canal console prévu par le banc, pas par ces trois journaux.

## Oracles statiques des tables

Extraire depuis le PE ou rapprocher du listing NASM les trois blocs contigus de
256 dwords littéraux. Un calculateur de hash en lecture seule doit retrouver :

| Bloc little-endian | Taille | SHA-256 |
|---|---:|---|
| A | 1 024 | `00b009d804d56318c9407ce122ede9b50ee268f646b51336f79669bfd7f0759c` |
| B | 1 024 | `5b9cf5500a41298defca21b33b047a2e315ef09c2e800d357db3cab280a7800e` |
| G | 1 024 | `da6c5e284568b23c606efc6f4ac42c9550575aa46c5171973645efb0551367f4` |
| A puis B puis G | 3 072 | `0f15f037b9dc370681ba769b972375fed98b2d1ce85841581ac84b44592e71cd` |

L'audit recalcule en plus les 17 lanes dirigées, applique les formules sur
`17..255`, confirme `G=(A+B) mod 2^32` sur 256/256 lanes et vérifie les
frontières `i=17` et `i=255` données par le design. Une simple recherche des
hashes comme chaînes dans le source n'est pas une preuve.

Le probe ne calcule pas SHA-256, mais son préflight doit recalculer FNV-1a-64
sur les mêmes octets et vérifier avant tout kernel :

| Flux runtime | FNV-1a-64 |
|---|---|
| A | `C3F35DC2B53DEA64` |
| B | `2473B19E192A0FE7` |
| G | `558F555BEC217985` |
| A puis B puis G | `69EEB57856E393CE` |

Le cas `R1_FAULT_CORPUS` inverse le bit 0 du littéral `A[17]`; il doit donc
échouer E204 pendant ce préflight, avant l'initialisation d'un calcul. Le banc
confirme que la table des N reste pourtant exacte dans ce binaire de faute.

## Oracle indépendant du digest

Le banc reconstruit indépendamment le flux, sans réutiliser la routine du
probe :

```text
pour N dans [0,1,15,16,17,255,256] :
    émettre N comme u16 little-endian
    émettre G[0..N-1] comme u32 little-endian
```

Il exige `stream_size=2254` et recalcule FNV-1a-64 avec offset
`CBF29CE484222325` et prime `00000100000001B3`. Le résultat doit être
`7CF3026858C7AC7C`. À titre d'oracle d'audit supplémentaire, le SHA-256 du flux
de 2 254 octets ainsi défini est
`e66190d1f796dfebd250f685979d0ab5e9f7d57429af5715e33d7ef979ef4837`.

## Inspection du binaire

L'inspection PE et le désassemblage en lecture seule doivent confirmer :

- PE32+ AMD64 EFI Application, imports/IAT/TLS/debug/certificat/overlay nuls;
- sections non W+X, relocation(s) DIR64 valides et aucune ressource acquise;
- tables A/B/G littérales et distinctes, chacune de 256 dwords;
- corpus exact de sept `u16`, boucles bornées et accès dword scale 4;
- préflight FNV-1a-64 des trois tables et de leur concaténation avant calcul;
- addition 32 bits réellement modulo `2^32` et chemin `N=0` sans accès lane;
- réinitialisation des 256 sorties à `A5A5A5A5` pour chaque cas;
- vérification des deux canaris, des lanes actives et du suffixe inactif;
- FNV-1a alimenté par `LE16(N)` puis uniquement par les résultats actifs;
- taille de flux 2 254 et digest final comparé à `7CF3026858C7AC7C`;
- aucune instruction SIMD ou privilégiée, aucun `ExitBootServices`, aucun accès
  PCI/MMIO/DMA/MSR/ports I/O/microcode;
- stack x64 UEFI alignée, shadow space valide et registres non volatils
  préservés autour de `ConOut.OutputString`;
- label `BOOTSTRAP_EXTERNAL_ASM` exactement une fois et aucune chaîne laissant
  croire à du Nova compilé ou à une release.

Deux builds canoniques frais doivent être bit-identiques. Le PE booté dans les
deux cas GREEN doit avoir exactement le SHA-256 du candidat final consigné dans
le manifeste.

## Critère GREEN et preuve

R1 peut être annoncé GREEN seulement si, sur un même hash canonique final :

1. le RED R0→R1 a été exécuté et conservé avant le premier GREEN R1 ;
2. les quatre SHA-256 hôte, les quatre FNV runtime et le digest indépendant sont
   conformes ;
3. les deux boots canoniques et les six boots de faute passent, soit 8/8 ;
4. les 24 journaux sont vides, les huit retours firmware sont visibles et QEMU
   termine à zéro 8/8 ;
5. l'inspection PE/désassemblage et la reproductibilité 2/2 passent ;
6. le source R0, son PE canonique et ses preuves restent inchangés ;
7. le manifeste canonique enregistre commandes, tailles, hashes et preuves sans
   promouvoir Nova, le noyau, B1 ou la chaîne souveraine.

Le marqueur seul ne suffit pas : sans matrice de fautes, hashes de tables,
digest indépendant, inspection et artefacts de preuve, le statut reste RED.
