# Catalogue fermé NTASM v0

Les noms sont sensibles à la casse. Ce catalogue réunit les domaines du
critère A1.02 ; les règles de preuve et les formes d'opérandes restent celles
des documents cités. Une entrée n'autorise pas à ignorer la validation du
programme, des features, des effets ou du niveau de privilège.

| Domaine | Entrées | Autorité exécutable |
|---|---|---|
| Targets | `x86_64-nexora-none`, `x86_64-nexora-uefi` | targets.nova |
| Entiers | `u8`, `u16`, `u32`, `u64`, `i8`, `i16`, `i32`, `i64` | types.nova, register_widths.nova |
| Autres scalaires | `bool`, `never` | types.nova, return_types.nova |
| Types composés | `ptr<espace,T>`, `array<T,N>` avec N entier strictement positif | types.nova, pointer_spaces.nova |
| Types méta | `$T`, `expand Nom(...)`, `ast.expr`, `ast.type`, `ast.stmt`, `ast.decl`, `ast.block`, résultat `list<...>` | parser.nova, macro_expand.nova |
| Espaces | `user`, `kernel`, `physical`, `mmio`, `device`, `firmware` | pointer_spaces.nova, effects.nova |
| Features | `lm`, `msr`, `syscall`, `sse2`, `tsc` | features.nova |
| ABI fonction | `nx64-abi-v0`, `efi-x64-v0` | abi.nova ; ntasm.md §17.5 |
| Sections NXO | `.text`, `.rdata`, `.data` | nxo-v0.md |
| Relocations NXO | `REL32`, `DIR64` | nxo-v0.md ; x64-forms.csv |

`lm` est implicite ; le répéter est idempotent. Les autres features ne peuvent
être dupliquées et un nom qualifié n'est pas une feature. `bool` exprime une
valeur logique, pas un entier arbitraire. Un `never` n'a pas de retour normal.
Les types méta ne sont pas des valeurs runtime transportables par l'ABI.

## Registres

| Famille 64 bits | Alias 32 bits | Alias 16 bits | Alias 8 bits |
|---|---|---|---|
| rax | eax | ax | al, ah |
| rcx | ecx | cx | cl, ch |
| rdx | edx | dx | dl, dh |
| rbx | ebx | bx | bl, bh |
| rsp | esp | sp | spl |
| rbp | ebp | bp | bpl |
| rsi | esi | si | sil |
| rdi | edi | di | dil |
| r8–r15 | r8d–r15d | r8w–r15w | r8b–r15b |

L'intervalle r8–r15 désigne les huit entiers inclus, sans autre extension.
Les alias partagent une cellule physique ; une écriture 32 bits efface les
32 bits hauts, une écriture 8/16 bits préserve le reste. AH/CH/DH/BH occupent
les bits 8–15 et ne se combinent pas avec un préfixe REX. Une adresse base/index
exige le registre 64 bits. Le registre connu et sa largeur sont deux contrôles
distincts ; une graphie simplement de la bonne longueur n'est pas un registre.

`rip`, `rflags`, `gsbase`, `fsbase` sont des identités spéciales de contrat et
d'architecture, pas quatre GPR allouables. Les clobbers portent les bits 16,
17, 18 et 19 respectivement après les 16 familles GPR. Les registres de contrôle
`cr0`, `cr2`, `cr3`, `cr4`, `cr8` sont accessibles par leurs opérations dédiées,
avec les contrôles de privilège. Ni un clobber ni une feature ne crée un
accès matériel sur la machine hôte.

## Effets, prédicats et opérations machine

Les onze atomes d'effet sont `privileged`, `changes_flags`, `mmio`, `io_port`,
`msr`, `control`, `interrupt_state`, `no_return`, `memory_ordering`,
`reads_clock`, `suspends`. S'y ajoutent `reads(espace)` et `writes(espace)`
sur les six espaces ci-dessus. Les unions, doublons, fautes de forme et effets
implicites sont définis dans `ntasm.md` §17.4 et contrôlés par effects,
body_effects, body_intrinsics et call_effects.

Les dix prédicats sont `feature(x)`, `non_null(x)`, `canonical(x)`,
`stack_in(espace)`, `stack_aligned(n)`, `msr_initialized(x)`,
`interrupts_enabled()`, `interrupts_disabled()`, `mapping_present(x)` et
`valid_user_return(rip,rsp)`. Leurs arités, faits, invalidations et
substitutions sont fermés par `ntasm.md` §17.3 et le lot A4. Aucun solveur
général ni hypothèse implicite ne vient satisfaire un contrat non prouvé.

Le catalogue des opérations machine et de leurs formes est
[`x64-forms.csv`](x64-forms.csv), expliqué par [`x64-scope.md`](x64-scope.md).
Il inclut les instructions privilégiées, contrôle/ports et barrières. Les
préconditions et empreintes sont observées dans x64.c/conformance.c puis
confrontées aux exports Nova. `align_stack N` est une opération structurée
de vérification/abaissement, pas un mnémonique x86 supplémentaire ; son usage
doit satisfaire les règles de pile du §10. La graphie générique
`intrinsic nom(...)` dans la grammaire ne crée pas une bibliothèque ouverte
de noms : résolution et typage doivent justifier toute opération employée.

## Versions et frontières

Le bloc source `versions` publie les six domaines `ntir`, `machine_ir`,
`sections`, `symbols`, `relocations`, `nxo` à `0.1`. Ces versions de dialecte
ne sont pas l'en-tête binaire MIR : Machine IR est documenté dans
`machine-ir-v0.md` (MIR/1.3), NTIR dans `ntir-v0.md`, NXO dans `nxo-v0.md`,
PE dans la description NXO vers PE de `nxo-v0.md` et dans les preuves de
`../docs/ntasm-a7-chaine-commune.md`.
Une version incompatible est refusée, sans conversion silencieuse.

Les stubs structurés et leurs champs sont définis par `ntasm.md` §11/§17.8,
la grammaire et la preuve A6. Un wrapper à `ret` ne prouve pas une transition
matérielle SYSCALL/SYSRET. Les limites de comptime/macros demeurent celles de
la spécification et de l'acceptation A5 ; les macros n'ont pas d'I/O.

Ce catalogue n'étend pas le seed S0, ne retire pas le bootstrap C et ne
déclare pas B2.1 livré. Les formes invalides sont refusées dans leur passe
propriétaire, même si le parseur peut construire leur AST.
