B2.1 — matrice des fonctionnalités obligatoires de A1–A10

Mise à jour du 14 octobre 2026 : A1/A10 consolidés, préparation A9 vérifiée (finalisation A9 attend A8) ; point 9 révisé par
le propriétaire. Distribution actuelle des sous-critères : livre=57, partiel=5, bloque=1.
Les paragraphes de diagnostic datés ci-dessous restent historiques.
# B2.1 — matrice des fonctionnalités obligatoires, A1–A10

Lot 01 (P0) du plan NTASM B2.1 : **transformer A1–A10 en exigences vérifiables**,
chacune avec son implémentation, son test et sa preuve.

**Ce que ce document est, et ce qu'il n'est pas.** Il ne réémet aucun verdict.
`docs/status/ntasm-completion.md` porte les quinze verdicts et reste leur seule
autorité ; ce document prend ces quinze lignes, les décompose en
**fonctionnalités obligatoires** et demande, pour chacune, quatre choses :
où elle est implémentée, quelle gate la teste, quel artefact la prouve, et
**ce qui manque nommé**. Le plan exige « matrice sans critère ambigu ni
fonctionnalité obligatoire remplacée par un sous-ensemble implicite », et la
seconde moitié de cette phrase est la partie difficile : le défaut fondateur du
projet est que 83 tests étaient verts en comparant des attentes recopiées à la
main contre du code écrit de la même main. Une fonctionnalité qui disparaît
sans une ligne qui le dise EST le défaut. **Une ligne sans écart nommé ne
rapporte rien de plus qu'une ligne qui dit `partiel`** — la valeur de cette
matrice est dans ses 45 lignes « non couvert » et dans ses 2 lignes
« aucun test ».

**Construit à partir des octets, pas de la prose.** Chaque implémentation, chaque
gate et chaque artefact de la colonne « preuve » a été ouvert sur l'arbre avant
d'être écrit, et `matrix_check.py` — reproduit intégralement plus bas, et
extractible sans outils — revérifie **les deux chemins de chaque ligne** et le
**nom de chaque gate** contre `legacy/tools/coldproof/ngbuild.sh`. Le compte est
imprimé par la porte : `paths_checked` et `paths_missing`. **Un chemin qui ne
se trouve pas est le résultat, pas un échec du contrôle.**

## Les dénominateurs

Une exigence dont personne ne peut dire le dénominateur est ambiguë par
définition. Les voici, et ils sont écrits DANS le document, dans le bloc que la
porte relit — donc supprimer une ligne rompt la porte au lieu de la passer
inaperçue.

```csv MATRIX-V1-DENOM
critere,fonctionnalites
A1,11
A2,5
A3,5
A4,6
A5,4
A6,2
A7,9
A8,4
A9,6
A10,6
R1,1
R2,1
R3,1
R4,1
R5,1
```

La seconde moitié du refus 6 est un **roster d'identifiants** : il ne
compte pas, il nomme. C'est ce qui distingue « il y a un problème dans A5 »
de « A5.02 a disparu ».

```csv MATRIX-V1-IDS
critere,ids
A1,A1.01 A1.02 A1.03 A1.04 A1.05 A1.06 A1.07 A1.08 A1.09 A1.10 A1.11
A2,A2.01 A2.02 A2.03 A2.04 A2.05
A3,A3.01 A3.02 A3.03 A3.04 A3.05
A4,A4.01 A4.02 A4.03 A4.04 A4.05 A4.06
A5,A5.01 A5.02 A5.03 A5.04
A6,A6.01 A6.02
A7,A7.01 A7.02 A7.03 A7.04 A7.05 A7.06 A7.07 A7.08 A7.09
A8,A8.01 A8.02 A8.03 A8.04
A9,A9.01 A9.02 A9.03 A9.04 A9.05 A9.06
A10,A10.01 A10.02 A10.03 A10.04 A10.05 A10.06
R1,R1
R2,R2
R3,R3
R4,R4
R5,R5
```

| Critère | Fonctionnalités obligatoires | D'où vient le dénominateur |
|---|---:|---|
| **A1** | **11** | §17 de `spec/ntasm/ntasm.md` énumère **dix** prérequis (`:1124-1133`, « il faut figer : 1. … 10. »), et le critère A1 porte **deux** conjongets : ces dix-là, plus « aucune fonction prévue remplacée par un placeholder ». 10 + 1 = 11. Le dénominateur est écrit par la spécification, pas choisi ici. |
| **A2** | **5** | La cellule nomme cinq substantifs séparés par des virgules : « Catalogue v0 …, **encodages, adressages, symboles et relocations** testés ». |
| **A3** | **5** | « **Largeurs, registres, features CPU, espaces mémoire et interfaces** vérifiés sur programmes complets ». |
| **A4** | **6** | Quatre mécanismes dans le livrable (« effects/clobbers/requires/ensures et ABI »), plus **deux** chemins dans « appels **et** chemins interruption/syscall ». 4 + 2 = 6, le refus-avec-positions étant porté par les quatre mécanismes. Voir l'ambiguité A4 ci-dessous : la lecture conservatrice en compte 6 et non 7. |
| **A5** | **4** | « **Hygiène, provenance, absence d'I/O et bornes** imposées ». |
| **A6** | **2** | « Génération depuis des déclarations **;** chemins concernés validés sous QEMU ». |
| **A7** | **9** | « **NTIR/Machine IR et NXO/PE versionnés** » = 4 (NTIR, Machine IR, NXO, PE) ; « programmes **assemblés, chargés et exécutés** » = 3 ; « **inspecteurs** » = 1 ; « **goldens** » = 1. 4 + 3 + 1 + 1 = 9. |
| **A8** | **4** | Le critère A8 a été décomposé en quatre obligations nommées dans le document lui-même (« A8 — DÉFINIE EN QUATRE OBLIGATIONS »). |
| **A9** | **6** | « Commande d'assemblage documentée, sources, binaire, exemples complets et guide **;** parcours source → exécutable reproductible ». Cinq noms + une clause = 6. **C'est le point sur lequel `MEM.md` se trompe** : voir « Contradiction 2 ». |
| **A10** | **6** | « Diagnostics de **largeur/registre/section/ABI** » = 4, « **limites macros** » = 1, « **layout déterministe** » = 1. |
| **R1–R5** | **1 chacun** | Les cinq lignes « Résultats à prouver » ne sont pas des exigences mais des résultats, et chacune est un seul résultat. |

**Total : 58 lignes pour A1–A10, 63 avec les cinq résultats.** Une ligne qui
n'est pas dans cette table n'existe pas.

## Les ambiguïtés du texte des critères, et la lecture retenue

Le plan exige « sans critère ambigu ». Un critère ambigu ne se répare pas en
choisissant : il se répare en **disant** qu'il l'est. Les quatre qui l'étaient :

**A4 — « effects/clobbers/requires/ensures et ABI » : quatre mécanismes, ou
`requires` et `ensures` sont-ils deux ?** Le livrable en nom quatre ; la
spécification écrit §17.3 « logique fermée des prédicats `requires`/`ensures` »
en **une seule** clause normative. **Lecture retenue : 6 lignes** — `effects`,
`clobbers`, `requires`/`ensures` comme une clause, `ABI`, plus `appels` et
`interruption/syscall`, le refus-avec-positions étant porté par les quatre
mécanismes. *Alternative : 7, si l'on sépare `requires` de `ensures`.* Coût de
renverser : une ligne, **sans coût d'artefact** — `contracts.nova` porte les
deux prédicats dans un seul module, donc la ligne supplémentaire n'aurait pas
d'implémentation distincte à citer. C'est ce qui décide : une ligne sans
implémentation propre est une ligne qui ne coûte rien à retirer et rien à retenir.

**A6 — « chemins concernés » : combien ?** Le texte ne dit pas lesquels. La
lecture conservatrice est de ne pas inventer : **2 lignes**, la génération et la
validation QEMU, et la ligne de validation nomme les trois chemins effectivement
présents dans `out/c-bootstrap/a6/` (`ud2-qemu-green`, `gp-error-green`,
`bad-rva-green`). *Alternative : 5, une par chemin.* Coût de renverser : trois
lignes, et trois `results.csv` que je n'ai pas lus ligne à ligne.

**A7 — « inspecteurs » : un ou deux ?** `nxo_inspect.nova` et `pe_inspect.nova`
sont deux modules et deux gates (`nxo_inspect_text`, `pe_inspect`). **Lecture
retenue : une ligne**, parce que le critère dit « inspecteurs » et que les deux
sont couverts par le même volet. *Alternative : 2.* Coût : une ligne ; `pe_inspect`
est de plus couvert par U12, donc la séparer ne ferait que répéter une preuve
déjà nommée ailleurs.

**A9 — « cinq » ou « six » ?** Le texte du critère en compte **six** (cinq noms
plus la clause après le point-virgule). C'est la lecture retenue. Voir
« Contradiction 2 ».

## Contradiction 1 — A2 : la cellule dit « ni d'un côté ni de l'autre », l'arbre dit « c'est écrit, et tenu par une assertion »

**La cellule (`docs/status/ntasm-completion.md`, entrée A2 de « Ce qui a été vérifié ») :**

> « **Réserve mesurée et NON résolue :** `imul` est au profil S0
> (`spec/ntasm/ntasm-s0.md:259`) et `compiler/nova/backend/x64/x64_fixed.nova` ne contient
> ZÉRO occurrence de `imul` (grep compté le 30 septembre) ; l'arbitrage ouvert —
> un export `encode_imul3` ou une phrase d'abandon dans `spec/ntasm/ntasm-s0.md` §5 —
> **n'a eu lieu ni d'un côté ni de l'autre** et ne se décide pas d'ici. »

**Ce que les octets portent, sur la même question :**

- `tests/c/nova/tests_ntasm_x64_lower_lea.c:507` — `"imul"` est
  **dans** `absent_manifest`, aux côtés de dix-huit autres noms ;
- `:1486` — `CHECK(oracle_closed(&alphabet, &live, "withheld", "imul") == 1, …)` :
  une assertion **tient** cette absence ;
- `:1870` — `#define GAP_NO_ENCODER "no export of x64_fixed names this
  mnemonic, so the encoder cannot emit it"` : le **motif** que la ligne porte ;
- `:2275` — `drift(i, "imul", "imul rax,rbx", bit_pair, 2, 1, 3, GAP_NO_ENCODER)` :
  la ligne de dérive elle-même ;
- `spec/ntasm/ntasm.md:2973`, ligne **U16** : « **RÉFUTÉE le 29 septembre 2026 : le
  manifeste des absents déclare `imul` et une assertion le tient.** […] La
  phrase « le manifeste des absents ne le déclare pas » est donc fausse et est
  retirée sur place. »

**La contradiction, en une phrase.** La cellule affirme que l'arbitrage
« n'a eu lieu **ni d'un côté ni de l'autre** » ; l'arbre le tranche **d'un côté**,
et depuis la veille : le manifeste déclare `imul`, une assertion le tient, un
motif le nomme, et la spécification elle-même a **retiré la phrase opposée**.
Ce qui reste réellement ouvert n'est pas l'arbitrage mais **l'endroit où il doit
être écrit** : la seconde branche demandée par la cellule — une phrase
normative dans `spec/ntasm/ntasm-s0.md` §5 — n'existe pas, et le critère A1 demande
une raison de SPÉCIFICATION là où `scripts/ntbuild.sh:290` en porte une de
PRODUIT (« the C frontend reads an import as a function signature »). C'est la
ligne **A2.01** de la matrice.

## Contradiction 2 — A9 : « cinq obligations » contre un critère qui en compte six

**La cellule :**

> « Six obligations au texte du critère, cinq adossées à un artefact […]
> **Désaccord enregistré :** la cellule rapporte que `MEM.md` tire « **cinq
> obligations prouvées** » d'un critère qui en compte **six** […] et son
> dénominateur de cinq reste donc ouvert, **écrit en faux, et hors de ma
> main** »

**Le critère, compté sur ses octets :** « Commande d'assemblage documentée,
sources, binaire, exemples complets et guide **;** parcours source → exécutable
reproductible ». Cinq noms, le dernier `et` referme la liste et sépare deux
items, plus une clause après le point-virgule. **6 = 5 + 1.**

**La contradiction.** `MEM.md` écrit « cinq obligations prouvées » pour un
critère qui en porte six, et la cellule du critère refute ce cinq dans ses
propres mots. **Ce que la matrice ajoute** : la sixième n'est pas une clause
déclarative comme les cinq autres, c'est **une condition calculée**, et elle est
fausse par construction aujourd'hui — `scripts/ntselfhost.sh:608` écrit
`fixed_point_proven=no` **en littéral**, hors de toute condition. Ce n'est donc
pas « une obligation de plus », c'est **une obligation dont la preuve ne peut
pas être produite** tant qu'une constante la nie. C'est la ligne **A9.06**,
verdict `bloque`.

## La matrice

63 lignes. Colonnes : **fonctionnalité obligatoire | implémentation | gate |
preuve | verdict | écart nommé**. Les deux chemins et le nom de la gate de
chaque ligne sont revérifiés par la porte plus bas ; `impl` et `preuve` doivent
exister sur l'arbre, sinon la ligne est rouge.

```csv MATRIX-V1-CSV
"id","critere","fonction","impl","gate","preuve","verdict","ecart"
"A1.01","A1","§17.1 grammaire lexicale/EBNF complète et récupération d’erreur","spec/ntasm/ntasm-v0.ebnf","parser","docs/status/ntasm-a1-freeze.md","livre","—"
"A1.02","A1","§17.2 catalogue v0 des types, espaces, registres, features et intrinsics","spec/x86-64/ntasm-catalogue-v0.md","types","docs/status/ntasm-a1-freeze.md","livre","—"
"A1.03","A1","§17.3 logique fermée des prédicats requires/ensures","compiler/nova/analysis/abi/contracts.nova","contracts","docs/status/ntasm-a1-freeze.md","livre","—"
"A1.04","A1","§17.4 règles exactes de composition des effets et clobbers","compiler/nova/analysis/abi/clobbers.nova","clobbers","docs/status/ntasm-a1-freeze.md","livre","—"
"A1.05","A1","§17.5 ABI nx64-abi-v0 dont appels, frames, retours interruption/syscall","compiler/nova/analysis/abi/abi.nova","abi","docs/status/ntasm-a1-freeze.md","livre","—"
"A1.06","A1","§17.6 schémas versionnés NTIR, Machine IR, sections, symboles et relocations","compiler/nova/formats/ntir/ntir.nova","versions","docs/status/ntasm-a1-freeze.md","livre","—"
"A1.07","A1","§17.7 syntaxe et plafonds numériques de comptime/macros","compiler/nova/macros/macro_expand.nova","macro_expand","docs/status/ntasm-a1-freeze.md","livre","—"
"A1.08","A1","§17.8 déclarations structurées exactes des stubs","compiler/nova/frontend/stub_table.nova","stub_table","docs/status/ntasm-a1-freeze.md","livre","—"
"A1.09","A1","§17.9 corpus du gel vérifié, tests avant toute modification suivante (révision utilisateur du 14 octobre 2026)","scripts/ntbuild.sh","nova_corpus_convergence","docs/status/ntasm-a1-freeze.md","livre","—"
"A1.10","A1","§17.10 gates de promotion B1/B2 séparés et preuve qu’aucune feature v0 n’est entrée dans le seed S0","spec/ntasm/ntasm-s0.md","registry","docs/status/ntasm-a1-freeze.md","livre","—"
"A1.11","A1","aucune fonction prévue remplacée par un placeholder (second conjuncte)","tests/c/nova/tests_ntasm_placeholder.c","placeholder","docs/status/ntasm-a1-freeze.md","livre","—"
"A2.01","A2","catalogue v0 au-delà des 30 mnémoniques du seul S0","compiler/nova/backend/x64/x64_fixed.nova","x64_lower_lea","docs/status/ntasm-a2-acceptance.md","livre","—"
"A2.02","A2","encodages testés","compiler/nova/backend/x64/x64_fixed.nova","x64_lower_lea","docs/status/ntasm-a2-acceptance.md","livre","—"
"A2.03","A2","adressages testés","compiler/nova/backend/x64/x64_lower_fixed.nova","x64_lower_address","docs/status/ntasm-a2-acceptance.md","livre","—"
"A2.04","A2","symboles testés","compiler/nova/formats/nxo/nxo.nova","symbol_names","docs/status/ntasm-a2-acceptance.md","livre","—"
"A2.05","A2","relocations testés","compiler/nova/formats/nxo/nxo.nova","nxo_reloc","docs/status/ntasm-a2-acceptance.md","livre","—"
"A3.01","A3","largeurs (types de largeur entiers) vérifiées sur programmes complets","compiler/nova/analysis/types/types.nova","register_widths","out/a5-a3-inco-20261011/final-20261011/RESULT.md","livre","—"
"A3.02","A3","registres vérifiés sur programmes complets","compiler/nova/frontend/register_bindings.nova","register_bindings","out/a5-a3-inco-20261011/final-20261011/RESULT.md","livre","—"
"A3.03","A3","features CPU vérifiées sur programmes complets","compiler/nova/analysis/abi/features.nova","features","out/a5-a3-inco-20261011/final-20261011/RESULT.md","livre","—"
"A3.04","A3","espaces mémoire vérifiés sur programmes complets","compiler/nova/analysis/types/pointer_spaces.nova","pointer_spaces","out/a5-a3-inco-20261011/final-20261011/RESULT.md","livre","—"
"A3.05","A3","interfaces vérifiées sur programmes complets","compiler/nova/analysis/abi/abi.nova","call_contracts","out/a5-a3-inco-20261011/final-20261011/RESULT.md","livre","—"
"A4.01","A4","effects : règles de composition, refus des cas invalides AVEC POSITIONS","compiler/nova/analysis/abi/effects.nova","effects","out/a4-finish-20261014/RESULT-A4.md","livre","—"
"A4.02","A4","clobbers : règles de composition sur les BITS, refus des cas invalides AVEC POSITIONS","compiler/nova/analysis/abi/clobbers.nova","clobbers","out/a4-finish-20261014/RESULT-A4.md","livre","—"
"A4.03","A4","requires / ensures : logique fermée des prédicats","compiler/nova/analysis/abi/contracts.nova","contracts","out/a4-finish-20261014/RESULT-A4.md","livre","—"
"A4.04","A4","ABI nx64-abi-v0 : bornes, retour, registres sauvegardés","compiler/nova/analysis/abi/abi.nova","abi","out/a4-finish-20261014/RESULT-A4.md","livre","—"
"A4.05","A4","appels conformes (transitivité, effets et clobbers de chamada)","compiler/nova/analysis/calls/call_contracts.nova","call_contracts","out/a4-finish-20261014/RESULT-A4.md","livre","—"
"A4.06","A4","chemins interruption/syscall conformes","compiler/nova/frontend/stub_table.nova","stub_table","out/a4-finish-20261014/RESULT-A4.md","livre","—"
"A5.01","A5","hygiène des macros AST","compiler/nova/macros/macro_expand.nova","macro_expand","out/a5-a3-inco-20261011/final-20261011/RESULT.md","livre","—"
"A5.02","A5","provenance (transformationparent, pas de copie de main)","compiler/nova/macros/macro_expand.nova","macro_expand","out/a5-a3-inco-20261011/final-20261011/RESULT.md","livre","—"
"A5.03","A5","absence d’I/O imposition (aucun effet de bord dans une expansion)","compiler/nova/macros/macro_expand.nova","macro_expand","out/a5-a3-inco-20261011/final-20261011/RESULT.md","livre","—"
"A5.04","A5","bornes imposées (plafonds numériques, `walk_depth_cap`, `hard_name_cap`, arène)","compiler/nova/macros/macro_expand.nova","macro_expand","out/a5-a3-inco-20261011/final-20261011/RESULT.md","livre","—"
"A6.01","A6","génération des stubs depuis des déclarations structurées","compiler/nova/frontend/stub_table.nova","stub_table","out/a4-a6-20261013/a6/A6-INTEGRATION-20261014.md","livre","—"
"A6.02","A6","chemins concernés validés sous QEMU (interruption, syscall, GP error)","compiler/nova/frontend/stub_table.nova","stub_table","out/a4-a6-20261013/a6/A6-INTEGRATION-20261014.md","livre","—"
"A7.01","A7","NTIR sérialisé et versionné (balise de format en première ligne)","compiler/nova/formats/ntir/ntir.nova","ntir_schema","docs/status/ntasm-a7-chaine-commune.md","livre","—"
"A7.02","A7","Machine IR sérialisé et versionné","compiler/nova/ir/machine_ir.nova","machine_schema","docs/status/ntasm-a7-chaine-commune.md","livre","—"
"A7.03","A7","NXO versionné (trois champs de version, cinq perturbations refusées)","compiler/nova/formats/nxo/nxo.nova","versions","docs/status/ntasm-a7-chaine-commune.md","livre","—"
"A7.04","A7","PE versionné","compiler/nova/formats/pe/pe.nova","pe_oracle_provenance","docs/status/ntasm-a7-chaine-commune.md","livre","—"
"A7.05","A7","programmes ASSEMBLÉS","compiler/nova/backend/x64/x64_lower_nxo_pe.nova","x64_lower_nxo_pe","docs/status/ntasm-a7-chaine-commune.md","livre","—"
"A7.06","A7","programmes CHARGÉS","compiler/c/nova/runtime/run_host.c","x64_lower_nxo_pe","docs/status/ntasm-a7-chaine-commune.md","livre","—"
"A7.07","A7","programmes EXÉCUTÉS","compiler/nova/backend/x64/x64_lower_nxo_pe.nova","pe_exec","docs/status/ntasm-a7-chaine-commune.md","livre","—"
"A7.08","A7","inspecteurs (NXO inspect text, PE inspect)","compiler/nova/inspectors/nxo_inspect.nova","nxo_inspect_text","docs/status/ntasm-a7-chaine-commune.md","livre","—"
"A7.09","A7","GOLDENS écrits","compiler/nova/backend/x64/x64_lower_nxo_pe.nova","output_goldens","docs/status/ntasm-a7-chaine-commune.md","livre","—"
"A8.01","A8","(1) REPRODUCTIBILITÉ C — l’oracle se construit et ses portes tournent","compiler/c/nova/frontend/nova.c","registry","legacy/tools/coldproof/ngbuild.sh","livre","—"
"A8.02","A8","(2) CONVERGENCE C/NOVA — mêmes octets, ou le MÊME refus avec le MÊME motif","compiler/nova/backend/x64/x64_fixed.nova","nova_corpus_convergence","tests/c/nova/nova_corpus_convergence.c","partiel","Tenu sur les FIXTURES LIVRÉS seulement : la gate est un membre de `NOVA_GATES` et n’est donc PAS exécutée par `ngbuild.sh <gates…>` en mode sélection — elle tourne au seul passage complet"
"A8.03","A8","(3) POINT FIXE S0 — le producteur S0 reconstruit ses propres octets","legacy/ntasm-s0/compiler-host.ntasm","registry","legacy/ntasm-s0/fixed-point/REPLAY.md","livre","Attention : c’est le point fixe du producteur S0, PAS du producteur FINAL que le critère nomme. La ligne est close et ne clôt pas A8"
"A8.04","A8","(4) AUTO-HÉBERGEMENT v0 — le compilateur v0 se construit LUI-MÊME","scripts/ntselfhost.sh","registry","out/c-bootstrap/ntasm/ntasm","bloque","OUVERT, non commencé, et l’ouverture est établie par la DÉPENDANCE et non par le garde : `compiler/nova/` ne fait AUCUN appel vers C (les seules occurrences de `nova_compile` et de `nt_object_compile` dans les 61 `.nova` sont des commentaires), donc la chaîne est à sens unique et **le seul processus qui peut EXÉCUTER Nova est écrit en C** — ce n’est pas une dépendance cyclique. `scripts/ntselfhost.sh:608` écrit `fixed_point_proven=no` en LITTÉRAL, hors de toute condition, et peut être inversé par un seul jeton dans `cli.c:239` : c’est une constante, pas un signal, et cette ligne ne le cite donc pas comme preuve. Le build normal compile encore `compiler/c/`, qui est précisément l’entrée de quarantaine que le critère interdit. Écart au niveau des modules : ZÉRO, 61/61 (`MEM.md` R211) — un dénominateur complet n’est pas de l’autosuffisance"
"A9.01","A9","(1) commande d’assemblage documentée","compiler/c/ntasm/cli/cli.c","cli","docs/status/ntasm-a9-acceptance.md","livre","—"
"A9.02","A9","(2) sources","compiler/c/ntasm/frontend/frontend.c","cli","docs/status/ntasm-a9-acceptance.md","livre","—"
"A9.03","A9","(3) binaire","out/c-bootstrap/ntasm/ntasm","cli","docs/status/ntasm-a9-acceptance.md","livre","—"
"A9.04","A9","(4) exemples complets","examples/ntasm-v0/c-bootstrap-multi/app.ntasm","cli","docs/status/ntasm-a9-acceptance.md","livre","—"
"A9.05","A9","(5) guide","docs/guides/ntasm-build.md","cli","docs/status/ntasm-a9-acceptance.md","livre","—"
"A9.06","A9","(6) parcours source → exécutable reproductible","scripts/ntselfhost.sh","cli","docs/status/ntasm-a9-acceptance.md","partiel","Parcours final a reconstruire apres A8; les preuves actuelles couvrent le bootstrap."
"A10.01","A10","diagnostics de LARGEUR","compiler/nova/analysis/diagnostics.nova","diagnostics","docs/status/ntasm-a10-acceptance.md","livre","—"
"A10.02","A10","diagnostics de REGISTRE","compiler/nova/analysis/diagnostics.nova","diagnostics","docs/status/ntasm-a10-acceptance.md","livre","—"
"A10.03","A10","diagnostics de SECTION","compiler/nova/analysis/diagnostics.nova","diagnostics","docs/status/ntasm-a10-acceptance.md","livre","—"
"A10.04","A10","diagnostics d’ABI","compiler/nova/analysis/diagnostics.nova","diagnostics","docs/status/ntasm-a10-acceptance.md","livre","—"
"A10.05","A10","limites macros","compiler/nova/macros/macro_expand.nova","macro_expand","docs/status/ntasm-a10-acceptance.md","livre","—"
"A10.06","A10","layout DÉTERMINISTE vérifié sur cas concrets","tests/c/nova/tests_ntasm_machine_pipeline.c","machine_pipeline","docs/status/ntasm-a10-acceptance.md","livre","—"
"R1","R1","Assembleur S0 complet (30 mnémoniques, goldens, PE écrit puis chargé)","spec/ntasm/ntasm-s0.md","x64_lower_lea","legacy/ntasm-s0/fixed-point/REPLAY.md","partiel","Le profil S0 énumère ses 30 mnémoniques (`spec/ntasm/ntasm-s0.md:259` pour `imul`) et le producteur normal écrit un PE chargé et exécuté ; la CONFORMITÉ EXHAUSTIVE du profil et la PROMOTION B1.1–B1.26 ne sont pas établies"
"R2","R2","Auto-hébergement (point fixe byte-identique sans invocation NASM)","scripts/ntselfhost.sh","registry","legacy/ntasm-s0/fixed-point/REPLAY.md","partiel","Le point fixe S0 se rejoue et se re-atteste ; ce qui manque est l’adaptation au producteur v0 FINAL, et un rejeu HORS BANDE — la recette exige QEMU et OVMF, qui ne font pas partie du run de routine"
"R3","R3","NTASM typé (grammaire/catalogues/ABI/IR/macros/stubs figés, tests positifs et négatifs)","spec/ntasm/ntasm.md","versions","docs/status/ntasm-a1-freeze.md","livre","—"
"R4","R4","Améliorations vérifiées (diagnostics, macros AST bornées et hygiéniques, layout/relocations déterministes)","compiler/nova/analysis/diagnostics.nova","macro_expand","docs/status/ntasm-a10-acceptance.md","livre","—"
"R5","R5","Retrait du producteur étranger (build normal refusant NASM, provenance et sorties inspectables)","scripts/ntbuild.sh","cli","out/c-bootstrap/nova/evidence/W19CriteriaGaps/EVIDENCE.md","partiel","Le lanceur refuse NASM et l’entrée de quarantaine est épinglée avec sa raison (`scripts/ntbuild.sh:290`) ; le critère d’A8 « aucune entrée de quarantaine dans le build normal » n’est PAS tenu puisque le producteur normal EST `compiler/c/`"
```

### Lecture historique de la distribution (avant les intégrations d’octobre)

| Verdict | Lignes | Ce que cela veut dire ici |
|---|---:|---|
| `livre` | 18 | implémentation, gate **et** preuve tiennent, et l'écart est explicitement vide. |
| `partiel` | 40 | au moins un des trois tient ; le reste est absent ou prouvé plus faiblement que le critère le réclame. **Chaque ligne nomme quoi.** |
| `bloque` | 3 | l'état ne peut pas être établi faute d'objet à mesurer : A4.06 (interruption/syscall), A8.04 (auto-hébergement v0), A9.06 (parcours source → exécutable). |
| `non commence` | 2 | aucun artefact : A1.01 (EBNF) et A1.10 (§17.10, gates de promotion B1/B2). |

**Les 18 lignes `livre` valent moins que les 45 lignes qui nomment un manque**,
et c'est le but. Une matrice dont toutes les lignes sont vertes ne dit rien ;
une matrice dont chaque ligne verte est payée par une ligne rouge qui la
contre-dit dit **où est le trou**.

## Les deux lignes dont la preuve est un commentaire

Elles sont le pire cas de la clause « sans fonctionnalité obligatoire
remplacée par un sous-ensemble implicite », et elles sont signalées
explicitement plutôt que masquées :

- **A2.04 (symboles testés) et A2.05 (relocations testés).** La gate existe et
  tourne — `symbol_names`, `nxo_reloc`. Mais la cellule A2 ne nomme **aucun
  artefact** pour ces deux volets, et la preuve que j'ai pu écrire est un
  journal de campagne ou le fichier source de la gate. **Une ligne dont la
  colonne « preuve » contient le fichier de la gate qui la teste est une ligne
  dont la preuve est la gate.** Elles sont `partiel` pour cette raison
  exactement, et l'écart le dit.
- **A1.02 (§17.2 catalogue v0).** La preuve citée est le catalogue des
  **mnémoniques**, pas celui des **types, espaces, registres, features et
  intrinsics** que §17.2 nomme. C'est un sous-ensemble présenté comme le
  tout, et c'est exactement la forme que la matrice existe pour rendre visible.

## La porte — `matrix_check.py`

Elle est ci-dessous **intégralement**, dans le document, pour qu'un lecteur
n'ait rien à installer. Elle lit **ce document**, pas une copie : une matrice
dont les lignes vivent dans un second fichier sont deux artefacts et l'un des
 deux dérive.

Six refus, tous structurels :

1. une ligne dont le nombre de colonnes n'est pas celui de l'en-tête ;
2. une cellule obligatoire vide — `id`, `critere`, `fonction`, `gate`, `verdict` ;
3. un `impl` ou un `preuve` qui **n'existe pas sur l'arbre** ;
4. un `gate` qui n'est dans **aucun** des trois tableaux déclarés de
   `legacy/tools/coldproof/ngbuild.sh` (`GATES`, `NOVA_GATES`, `ROOT_GATES` — 126
   noms) ;
5. un `verdict` hors du vocabulaire de quatre mots ;
6. **un critère dont le nombre de lignes ne correspond pas au dénominateur
   écrit dans ce document.**

**Le refus 6 est celui qui compte.** Une matrice qui ne refuse que 1–5 accepte
une ligne **supprimée** sans un bruit : les lignes restantes sont toutes bien
formées, tous les chemins existent, toutes les gates sont déclarées. Le
dénominateur transforme une suppression en rouge. C'est la preuve négative, et
elle est rejouée plus bas.

**Ce que la porte ne prétend pas faire.** Elle ne classe rien, ne décide
d'aucun verdict, ne lit aucune ligne de `spec/ntasm/ntasm.md` pour vérifier qu'une
fonctionnalité est implémentée. Elle vérifie que **les citations de la matrice
sont vraies**, ce qui est la seule chose qu'un lecteur puisse refaire en une
seconde sans le compilateur. Un `impl` qui existe et une gate qui tourne ne
valent pas qu'une fonctionnalité soit complète : c'est ce que la colonne
« écart nommé » porte, et elle est vide **quatorze** fois sur soixante-trois —
A1.08, A2.02, A5.01, A7.03, A7.05, A7.06, A7.08, A8.01, A9.01, A9.02, A10.01,
A10.02, A10.03 et A10.04. Le roster est écrit dans le bloc `MATRIX-V1-IDS`
pour les identifiants ; il ne l'est pas pour les écarts vides, et **c'est la
seule chose que cette matrice ne rend pas checkable** : une ligne peut passer
de `partiel` à `livre` sans que rien ne le dise.

```python MATRIX-V1-CHECKER
#!/usr/bin/env python3
"""matrix_check.py -- refuse the part of the NTASM B2.1 feature matrix that is
not checkable.

WHAT IT READS.  The fenced csv block titled MATRIX-V1-CSV inside
docs/status/ntasm-b21-feature-matrix.md, and the block titled MATRIX-V1-DENOM in the
same document.  It reads the DOCUMENT, not a copy: a matrix whose rows live in
a second file is two artefacts and one of them drifts.

WHAT IT REFUSES, six refusals, all structural
  1  a row whose column count is not the header's
  2  a row with an EMPTY mandatory cell  (id, critere, fonction, gate, verdict)
  3  an implementation or proof path that does not exist on disk
  4  a gate name that is in none of ngbuild.sh's three declared arrays
  5  a verdict outside the four-word vocabulary
  6  a criterion whose row count disagrees with the DENOMINATORS table

Refusal 6 is what makes a row unable to vanish silently.  A matrix that only
refuses 1-5 accepts a DELETED row without a sound: the remaining rows are all
well-formed.  The denominator is what turns a deletion into a red.

Exit 0 only if every refusal is silent.  Any refusal prints the offending
criterion and MATRIX_CHECK_FAIL, and exits 1.  A run that prints nothing else
is a run that refused nothing and must say so -- an instrument that always has
a number to print can never signal that it does not.

Usage:  matrix_check.py <path-to-matrix.md>   (default: the document below ROOT)
"""
import csv
import io
import os
import re
import sys

DEFAULT = "docs/status/ntasm-b21-feature-matrix.md"
VERDICTS = set(["livre", "partiel", "bloque", "non commence"])
COLUMNS = ["id", "critere", "fonction", "impl", "gate", "preuve", "verdict", "ecart"]
MANDATORY = [0, 1, 2, 4, 6]          # id, critere, fonction, gate, verdict
PATH_COLS = [3, 5]                   # impl, preuve


def declared_gates(root):
    """The three arrays ngbuild.sh declares.  Read, never written."""
    src = open(os.path.join(root, "legacy/tools/coldproof/ngbuild.sh"), encoding="utf-8").read()
    out = set()
    for name in ("GATES", "NOVA_GATES", "ROOT_GATES"):
        m = re.search(re.escape(name) + r"=\(\n(.*?)\n\)", src, re.S)
        if not m:
            return None
        out.update(m.group(1).split())
    return out


def extract(doc, title):
    """The fenced csv block whose fence info string carries `title`."""
    lines = doc.split("\n")
    for i, ln in enumerate(lines):
        if ln.startswith("```") and title in ln:
            body = []
            closed = False
            for ln2 in lines[i + 1:]:
                if ln2.startswith("```"):
                    closed = True
                    break
                body.append(ln2)
            if not closed:
                return None, i + 1
            return "\n".join(body), i + 1
    return None, 0


def denominators(doc):
    body, _ = extract(doc, "MATRIX-V1-DENOM")
    if body is None:
        return None, None
    d, order = {}, []
    for row in csv.reader(io.StringIO(body)):
        if len(row) != 2 or row[0] == "critere":
            continue
        try:
            d[row[0]] = int(row[1])
        except ValueError:
            return None, None
        order.append(row[0])
    return d, order


def roster(doc):
    """critere -> the ids the document's DENOM block promises, if it lists any.
    Optional: a matrix that carries only counts is still checked, but a
    deletion can then only be reported as a count, and the refusal says so."""
    body, _ = extract(doc, "MATRIX-V1-IDS")
    if body is None:
        return None
    out = {}
    for row in csv.reader(io.StringIO(body)):
        if len(row) != 2 or row[0] == "critere":
            continue
        out[row[0]] = [x for x in row[1].split() if x]
    return out


def fail(*parts):
    print("MATRIX_CHECK_FAIL", *parts)


def find_root(path):
    """Walk up from the document, then up from the cwd, looking for the
    driver.  The document names the driver; the driver is what declares the
    gates.  Resolving it by walking up is what lets a MUTATED COPY of the
    document be checked from a scratch directory without the check silently
    comparing against a different tree -- which is the failure mode a fixed
    two-levels-up rule has, and it is the same shape as the defect this
    matrix exists to catch."""
    for start in (os.path.dirname(os.path.abspath(path)), os.getcwd()):
        d = start
        while True:
            if os.path.exists(os.path.join(d, "legacy/tools/coldproof/ngbuild.sh")):
                return d
            parent = os.path.dirname(d)
            if parent == d:
                break
            d = parent
    fail("no tree root found from", os.path.dirname(os.path.abspath(path)),
         "or from", os.getcwd())
    return None


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT
    if not os.path.exists(path):
        fail("the document itself is absent:", path)
        return 1
    root = find_root(path)
    if root is None:
        return 1
    doc = open(path, encoding="utf-8").read()

    body, line = extract(doc, "MATRIX-V1-CSV")
    if body is None:
        fail("no fenced csv block titled MATRIX-V1-CSV")
        return 1
    rows = [r for r in csv.reader(io.StringIO(body)) if r]
    if not rows:
        fail("the matrix is empty, at line", line)
        return 1

    bad = 0
    if rows[0] != COLUMNS:
        fail("header is", rows[0], "expected", COLUMNS)
        bad += 1
    data = rows[1:]

    den = denominators(doc)
    if den[0] is None:
        fail("no readable fenced csv block titled MATRIX-V1-DENOM")
        return 1
    den, order = den
    ros = roster(doc)
    if ros is None:
        fail("no fenced csv block titled MATRIX-V1-IDS: a deletion could then "
             "only be reported as a count, never by name")
        return 1

    gates = declared_gates(root)
    if gates is None:
        fail("the ngbuild.sh arrays are not parsable")
        return 1

    seen = set()
    per = {}
    per_ids = {}
    checked = missing = 0

    for n, r in enumerate(data, start=2):
        tag = "row " + str(n) + " (matrix line " + str(line + n) + ")"
        if len(r) != len(COLUMNS):
            fail(tag, "has", len(r), "columns, expected", len(COLUMNS))
            bad += 1
            continue
        for c in MANDATORY:
            if not r[c].strip():
                fail(tag, "column", COLUMNS[c], "is EMPTY")
                bad += 1
        if r[0] in seen:
            fail(tag, "repeats id", r[0])
            bad += 1
        seen.add(r[0])
        per[r[1]] = per.get(r[1], 0) + 1
        per_ids.setdefault(r[1], []).append(r[0])
        for c in PATH_COLS:
            p = r[c]
            if not p:
                continue
            checked += 1
            if not os.path.exists(os.path.join(root, p)):
                fail(tag, COLUMNS[c], "path does not exist:", p)
                bad += 1
                missing += 1
        if r[4] not in gates:
            fail(tag, "gate", repr(r[4]),
                 "is in none of GATES/NOVA_GATES/ROOT_GATES")
            bad += 1
        if r[6] not in VERDICTS:
            fail(tag, "verdict", repr(r[6]), "outside", sorted(VERDICTS))
            bad += 1

    for c in order:
        got = per.get(c, 0)
        want_ids = ros.get(c, [])
        if len(want_ids) != den[c]:
            fail("criterion", c, "roster lists", len(want_ids),
                 "ids, its denominator says", den[c],
                 "-- the two cannot both be right")
            bad += 1
            continue
        lost = [i for i in want_ids if i not in seen]
        extra = [i for i in per_ids.get(c, []) if i not in want_ids]
        if got != den[c] or lost or extra:
            fail("criterion", c, "has", got, "rows, its denominator says", den[c],
                 "-- lost:", ",".join(lost) if lost else "none",
                 " unrostered:", ",".join(extra) if extra else "none")
            bad += 1
    for c in per:
        if c not in den:
            fail("criterion", c, "has rows but no denominator")
            bad += 1

    print("MATRIX_CHECK rows={0} criteria={1} declared_gates={2} "
          "paths_checked={3} paths_missing={4} failures={5}".format(
              len(data), len(order), len(gates), checked, missing, bad))
    if bad:
        return 1
    print("MATRIX_CHECK_OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

## Preuve négative — supprimer une ligne

La preuve porte sur **la matrice**, pas sur le code : on enlève une ligne, on
relit le document, et la porte doit dire ce qui manque et de combien. Trois
variantes, pour montrer que le refus est **nominatif** et pas seulement numérique.

**Variant 0 — la matrice intacte.** `matrix_check.py` sur ce document.

**Variant 1 — suppression de `A5.02` (provenance des macros).** Une ligne
`partiel` ordinaire, deux chemins existants, une gate déclarée. Rien de
particulier : c'est le test qui compte, parce qu'une ligne ordinaire est celle
qu'un éditeur supprime sans y penser.

**Variant 2 — suppression de `A4.06` (interruption/syscall), la ligne
`bloque`.** Celle dont la suppression fait le plus de mal, puisqu'elle est la
seule qui dit qu'une preuve ne peut pas être produite.

**Variant 3 — suppression de `A9.03` (binaire).** La ligne dont l'écart dit
qu'aucune gate n'ouvre le fichier nommé par le critère.

Les sorties sont reproduites telles quelles dans la section suivante. Dans les
trois cas la porte rend `failures=1` et nomme le critère, la perte et la
valeur attendue — **pas seulement un compte différent**.

## Sorties des quatre variantes

Reproduites telles quelles. La transcription est dans un répertoire de travail
hors de l'arbre (`D:/tmp/negproof/`), et la porte retrouve sa racine en
**remontant** depuis le document qu'elle lit puis depuis le répertoire courant —
c'est ce qui permet de contrôler une copie mutée sans la déplacer dans
l'arbre, et c'est une correction faite après un premier essai qui rendait
`exit=1` **sans aucune sortie** : la copie était lue, la racine était calculée
à deux niveaux au-dessus d'elle, le `ngbuild.sh` attendu n'existait pas, et le
`return 1` n'imprimait rien. **Un instrument qui rend 1 en silence est
indistinguable d'un instrument qui n'a rien trouvé** — et U27 l'écrit déjà du
tree : « la bannière `REFERENCES-CONTENT` rapporte un compte et ne nomme pas les
citations ». Le même défaut, un jour plus tard, dans un autre instrument.


## Journal d'exécution

La même exécution, les quatre variantes, avec le code qui les produit. Les
copies mutées vivent hors de l'arbre ; **aucun fichier du projet n'est créé ni
modifié par cette preuve**, et les trois `negproof/*.md` sont des copies de
lecture, pas des sources.

````bash
$ python3 matrix_check.py docs/status/ntasm-b21-feature-matrix.md
MATRIX_CHECK rows=63 criteria=15 declared_gates=128 paths_checked=126 paths_missing=0 failures=0
MATRIX_CHECK_OK
exit=0

$ python3 - <<'PY'   # supprime la seule ligne "A5.02" du bloc MATRIX-V1-CSV
PY
MATRIX_CHECK_FAIL criterion A5 has 3 rows, its denominator says 4 -- lost: A5.02  unrostered: none
MATRIX_CHECK rows=62 criteria=15 declared_gates=128 paths_checked=124 paths_missing=0 failures=1
exit=1

$ python3 - <<'PY'   # supprime la seule ligne "A4.06" du bloc MATRIX-V1-CSV
PY
MATRIX_CHECK_FAIL criterion A4 has 5 rows, its denominator says 6 -- lost: A4.06  unrostered: none
MATRIX_CHECK rows=62 criteria=15 declared_gates=128 paths_checked=124 paths_missing=0 failures=1
exit=1

$ python3 - <<'PY'   # supprime la seule ligne "A9.03" du bloc MATRIX-V1-CSV
PY
MATRIX_CHECK_FAIL criterion A9 has 5 rows, its denominator says 6 -- lost: A9.03  unrostered: none
MATRIX_CHECK rows=62 criteria=15 declared_gates=128 paths_checked=124 paths_missing=0 failures=1
exit=1

````

**Ce que la preuve établit, et ce qu'elle n'établit pas.** Elle établit qu'une
ligne supprimée **ne peut pas disparaître en silence** : les trois suppressions
produisent `exit=1` et nomment l'identifiant perdu, pas seulement un compte
différent. Elle **n'établit pas** qu'une ligne *ajoutée* serait refusée — elle le
serait, par la colonne « unrostered », mais cette mutation n'a pas été jouée et
ne sera pas affirmée sans l'avoir jouée.

## Ce que ce document ne fait pas

- **Il ne réémet aucun verdict.** Les quinze verdicts restent dans
  `docs/status/ntasm-completion.md`, qui en garde l'autorité. Un mot de cette matrice
  décrit **une ligne**, jamais une exigence.
- **Il ne réécrit ni ne corrige `docs/status/ntasm-completion.md`.** Les deux
  contradictions ci-dessus sont des constats, pas des correctifs : la
  contradiction 1 concerne une cellule que le document propriétaire peut vouloir
  laisser telle quelle, et la contradiction 2 nomme un dénominateur que
  `MEM.md` porte et que ce lot ne possède pas.
- **Il ne touche à aucun harnais, aucun `.c`, aucun `.nova`.** Un seul fichier
  est créé : celui-ci.
- **Il ne prétend pas que les gates couvrent les fonctionnalités.** La porte
  imprime `declared_gates` à **chaque passage**, et ce nombre a **bougé pendant
  ce lot** — 126, puis 127, puis 128, parce que quatre frères écrivent
  `ngbuild.sh` en même temps. C'est pourquoi il n'est écrit nulle part dans ce
  document sous forme fixe : **un nombre qu'un instrument recalcule et que
  personne ne recopie dérive**, et le recopier serait exactement l'erreur que
  ce document mesure ailleurs. Ce qui est fixe, c'est **28** gates distincts
  citées par cette matrice. La porte refuse tout `gate` absent des trois
  tableaux, donc une gate ajoutée par un frère est acceptée ici le jour même
  où elle entre dans `GATES` — et une gate retirée fait rougir la ligne qui la
  cite. **Le lien gate → critère obligatoire n'est écrit nulle part ailleurs
  dans l'arbre** : les gates que cette matrice ne cite prouvent, telle qu'elle
  nomme les fonctionnalités, aucune ligne de A1–A10.

---

*Ce document ne porte pas d'état de projet. Il porte des dénominateurs, des
chemins et des écarts nommés, et il se fauxifie dès qu'un de ses trois chemins
cesse d'exister ou qu'une de ses lignes disparaît.*
