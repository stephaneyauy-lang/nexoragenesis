# Nova Compute CPU R1 — corpus scalaire et digest de run

Statut : **NC-R1-PROBE GREEN**, preuve canonique dans
`out/nova-cpu/r1/runtime-final-root-69d8a0eb18b448efb16a9788d6f43815/manifest.md`.
Ce statut ne constitue toujours ni une promotion de Nova/NV1, ni un noyau, ni
un gate OS.

## Frontière de vérité

R1 reste un probe UEFI x86_64 externe produit temporairement par NASM 2.16.01
sous `legacy/nasm/`, avec le label
`BOOTSTRAP_EXTERNAL_ASM`. Il est pré-kernel, QEMU/OVMF uniquement,
`release_eligible=false`, `final_dependency=false`, non Nova compilé et interdit
à tout build ou package final.

Le probe ne lit aucune source `.nova`, n'appelle pas `ExitBootServices`, ne
devient ni le frontend Nova, ni `cpu.ref`, ni Device IR, ni Cnuva, ni le noyau.
Il n'accède pas à PCI, MMIO, DMA, MSR, ports I/O, microcode ou matériel réel.
L'annonce maximale après preuve complète sera : « un probe CPU externe et
quarantainé exécute le corpus Nova Compute CPU R1 sous QEMU/OVMF ».

## Opération et corpus

L'unique opération est :

```text
G[i] = (A[i] + B[i]) modulo 2^32
```

`A`, `B`, `G` et le buffer de sortie contiennent des `u32`. Les dwords sont
sérialisés little-endian. L'exécution est exclusivement scalaire, avec des
opérations 32 bits; aucune instruction SIMD n'est admise.

Le corpus de longueurs est exactement, dans cet ordre :

```text
N = 0, 1, 15, 16, 17, 255, 256
```

Chaque cas réinitialise le buffer de sortie entier, puis visite exactement les
lanes `0..N-1` dans l'ordre croissant. `N=0` n'effectue aucune lecture de table
ni écriture de résultat. Les sept cas sont exécutés dans un seul boot.

## Tables littérales

Le source producteur doit porter trois tables indépendantes et entièrement
développées de **256 dwords littéraux** : `A`, `B` et `G`. Il est interdit de
calculer `G` depuis `A` et `B` au runtime avant la comparaison, car cela
supprimerait l'indépendance du golden. Les formules ci-dessous définissent le
corpus et permettent son audit; elles ne remplacent pas les 768 littéraux du
source.

Les lanes dirigées `0..16` sont :

| Lane | A | B | G |
|---:|---:|---:|---:|
| 0 | `00000000` | `00000000` | `00000000` |
| 1 | `00000001` | `FFFFFFFF` | `00000000` |
| 2 | `FFFFFFFF` | `00000001` | `00000000` |
| 3 | `80000000` | `80000000` | `00000000` |
| 4 | `7FFFFFFF` | `00000001` | `80000000` |
| 5 | `12345678` | `11111111` | `23456789` |
| 6 | `AAAAAAAA` | `55555555` | `FFFFFFFF` |
| 7 | `DEADBEEF` | `21524111` | `00000000` |
| 8 | `FFFFFFFF` | `FFFFFFFF` | `FFFFFFFE` |
| 9 | `80000000` | `7FFFFFFF` | `FFFFFFFF` |
| 10 | `0000FFFF` | `FFFF0001` | `00000000` |
| 11 | `00FFFFFF` | `FF000001` | `00000000` |
| 12 | `01020304` | `10203040` | `11223344` |
| 13 | `13579BDF` | `2468ACE0` | `37C048BF` |
| 14 | `40000000` | `40000000` | `80000000` |
| 15 | `CAFEBABE` | `35014542` | `00000000` |
| 16 | `00000001` | `00000001` | `00000002` |

Pour chaque indice entier `i` de 17 à 255 inclus :

```text
A[i] = (0x9E3779B9 * i + 0x243F6A88) modulo 2^32
B[i] = ((0x85EBCA6B * i + 0xB7E15162) modulo 2^32) xor 0xA5A5A5A5
G[i] = (A[i] + B[i]) modulo 2^32
```

Exemples de frontière recalculés :

```text
i=17  A=A5EE7FD1  B=392C67D8  G=DF1AE7A9
i=255 A=BD81A9CF  B=B81A5452  G=759BFE21
```

L'audit sérialise chaque table comme 256 `u32` little-endian, sans en-tête ni
padding. Les oracles SHA-256 sont :

| Flux | Octets | SHA-256 |
|---|---:|---|
| `A` | 1 024 | `00b009d804d56318c9407ce122ede9b50ee268f646b51336f79669bfd7f0759c` |
| `B` | 1 024 | `5b9cf5500a41298defca21b33b047a2e315ef09c2e800d357db3cab280a7800e` |
| `G` | 1 024 | `da6c5e284568b23c606efc6f4ac42c9550575aa46c5171973645efb0551367f4` |
| `A || B || G` | 3 072 | `0f15f037b9dc370681ba769b972375fed98b2d1ce85841581ac84b44592e71cd` |

Ces quatre valeurs ont été recalculées depuis les lanes et formules ci-dessus;
elles sont cohérentes entre elles.

Le probe exécute en plus un préflight FNV-1a-64 sur les mêmes octets. Avec
l'offset basis `0xCBF29CE484222325` et la prime `0x00000100000001B3`, les
oracles runtime sont :

| Flux | FNV-1a-64 |
|---|---|
| `A` | `C3F35DC2B53DEA64` |
| `B` | `2473B19E192A0FE7` |
| `G` | `558F555BEC217985` |
| `A || B || G` | `69EEB57856E393CE` |

Les SHA-256 restent des oracles d'audit hôte; les FNV ci-dessus sont les
contrôles exécutés par le probe avant tout calcul. Une différence produit E204.

## Garde, résultat et suffixe

Le buffer de sortie comporte exactement 256 dwords, précédés du canari bas
`0xC0DEC0DE` et suivis du canari haut `0xDEC0ADDE`. Avant chaque cas, les deux
canaris sont rétablis et les 256 lanes de sortie valent `0xA5A5A5A5`.

Après le kernel du cas :

1. les deux canaris doivent être inchangés, sinon E202 ;
2. chaque lane active `0..N-1` doit égaler la table littérale `G`, sinon E201 ;
3. chaque lane inactive `N..255` doit encore valoir `0xA5A5A5A5`, sinon E203.

L'ordre ci-dessus fixe la priorité à l'intérieur d'un cas. Pour `N=0`, toute la
sortie est suffixe; pour `N=256`, le suffixe est vide. Un échec interrompt le
run et aucun marqueur de succès n'est imprimé.

## Flux canonique et digest

Un unique flux de run est construit logiquement dans l'ordre des sept cas. Pour
chaque cas, il contient :

```text
LE16(N) || LE32(out[0]) || ... || LE32(out[N-1])
```

Il ne contient ni canari, ni suffixe inactif, ni padding, ni texte de console.
Sa taille exacte est :

```text
7 * 2 + 4 * (0 + 1 + 15 + 16 + 17 + 255 + 256) = 2254 octets
```

Le digest est FNV-1a 64 bits, mis à jour octet par octet sur ce flux : offset
basis `0xCBF29CE484222325`, xor de l'octet, puis multiplication par
`0x00000100000001B3` modulo `2^64`. L'oracle final est exactement
`0x7CF3026858C7AC7C`.

Le digest est alimenté seulement après validation des gardes, résultats et
suffixes du cas. Après les sept cas, une taille de flux différente de 2 254 ou
un digest différent produit E205.

## Préflight du corpus et diagnostics

Après validation de la console et avant tout calcul, le probe vérifie :

1. que la table des cas contient exactement sept `u16` et vaut littéralement
   `0,1,15,16,17,255,256` ;
2. que les FNV-1a-64 runtime de `A`, `B`, `G` et `A || B || G` valent les quatre
   oracles définis plus haut.

Toute différence de nombre, ordre, valeur ou table produit E204. La priorité
globale est : console, corpus (liste N puis FNV), garde, résultat, suffixe,
digest.

Les lignes CHAR16 exactes, terminées par `CRLF` puis NUL en mémoire, sont :

```text
NG_NOVA_CPU_R1_OK CASES=7 N=0,1,15,16,17,255,256 SEM=MOD2P32 EXEC=SCALAR DIGEST=7CF3026858C7AC7C
NG_NOVA_CPU_R1_E201_RESULT
NG_NOVA_CPU_R1_E202_GUARD
NG_NOVA_CPU_R1_E203_SUFFIX
NG_NOVA_CPU_R1_E204_CORPUS
NG_NOVA_CPU_R1_E205_DIGEST
```

Une exécution imprime exactement une de ces lignes. Les statuts sont figés :

| Issue | Statut EFI |
|---|---|
| succès | `EFI_SUCCESS` |
| E201 résultat | `EFI_ABORTED` |
| E202 garde | `EFI_COMPROMISED_DATA` |
| E203 suffixe | `EFI_COMPROMISED_DATA` |
| E204 corpus | `EFI_COMPROMISED_DATA` |
| E205 digest | `EFI_COMPROMISED_DATA` |
| console absente ou échec de `OutputString` | `EFI_DEVICE_ERROR` |

Un échec de console ne doit jamais transformer un diagnostic en succès.

## Injections test-only

Exactement six macros NASM test-only sont autorisées. Une construction de test
doit en définir une seule; le source refuse une combinaison de fautes.

| Macro | Mutation dirigée | Oracle |
|---|---|---|
| `R1_FAULT_CORPUS` | inverse le bit 0 du littéral `A[17]`; le préflight FNV échoue avant tout calcul | E204 |
| `R1_FAULT_RESULT` | inverse le bit 0 de `out[16]` après le kernel `N=17` | E201 |
| `R1_FAULT_SUFFIX` | écrit `out[16]` après le kernel `N=16`; cette première lane inactive n'est plus la sentinelle | E203 |
| `R1_FAULT_GUARD_LO` | inverse le bit 0 du canari bas après l'initialisation du cas `N=0`, avant son dispatch vide | E202 |
| `R1_FAULT_GUARD_HI` | inverse le bit 0 du canari haut après le kernel `N=256`, avant vérification | E202 |
| `R1_FAULT_DIGEST` | inverse le bit 0 du digest final après les sept cas validés | E205 |

Les deux fautes de garde ciblent donc des canaris et des moments distincts. Les
macros, leurs binaires et leurs preuves restent test-only et non livrables.

## Non-objectifs R1

Syntaxe `.nova`, frontend, IR, allocations, tenseurs multidimensionnels,
broadcast, SIMD, threads, float, GPU, noyau, scheduler, pilotes, matériel réel et
chaîne souveraine restent hors de R1.
