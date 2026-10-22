# A7 — la chaîne commune depuis le Machine IR : état et preuves

Date : 11 octobre 2026. **Verdict A7 : livré.** Périmètre : sorties versionnées et chaîne commune depuis un programme accepté par les passes de validation jusqu'au NXO/PE, chargement et exécution. Le modèle de registres MIR/1.0 est intégré au principal. A8 et B2.1 restent distincts ; le binaire annonce toujours BOOTSTRAP_EXTERNAL_C et B2.1=not-delivered.

Complément A3/A5 du 11 octobre : les paramètres macro utilisés, arguments imbriqués et blocs terminaux sont désormais validés et exécutés ; les anciennes réserves353/328 ci-dessous sont historiques. Preuves : `out/a5-a3-inco-20261011/final-20261011/RESULT.md` ; corpus1537/0, pipeline899/0, producteur62/0 et chargeur82/0.

## Preuves actuelles dans le principal

- Intégration de 20 fichiers avec préimages et vérification SHA256 avant/après : out/a7-integration-20261009/2026-10-11T16-55-11-314Z/receipt.json. Complément parser : out/a7-integration-20261009/parser-inline-20261011/receipt.json.
- Snapshot source figé : out/a7-closure-20261009/out/runs/2026-10-11T16-55-18-699Z-43584. Les 18 portes rendent chacune rc0 : machine_ir1111/0, machine_schema3733/0, machine_corpus1537/0, machine_pipeline896/0, machine_producer_exec62/0 (17 PE), machine_x64569/0, machine_missing27/0, object_pe_join166/0, output_goldens147/0, pe_exec61/0, nxo_inspect290/0, nxo_inspect_text186/0, versions45/0, ntir_schema6871/0, abi2073/0, c_conversion68/0, body_clobbers1067/0 et register_widths45/0.
- Après correction du parser, rejeu rc0 du corpus1537/0, pipeline896/0 et producteur62/0 : out/a7-closure-20261009/out/runs/2026-10-11T17-03-07-453Z-25368. Parité : 1259 cas, 877 accords, 382 refus communs, zéro C_ONLY/MIR_ONLY/WRONG/faults, 347 refus E401. Les 30 JOIN doivent s'exécuter correctement ; un refus ne les sauve plus. Canari : 6 résultats déplacés sur 17, 11 inchangés.
- Directions de paramètres générés par macro : pipeline899/0, 25 cas, rc0, out/runs/2026-10-11T17-05-29-104Z-32724 sous le candidat. L'image publiée porte exactement un IN, un OUT et un INOUT, zéro FLAG_DIR_UNREAD et zéro mode inattendu. Le relais effectif est abi.parameter_mode, interrogé sur le texte développé.
- Compléments rc0 : x64_high8 3842/0, pe_oracle_provenance et machine_macro_calls4/0, out/runs/2026-10-11T17-09-43-565Z-45384 sous le candidat.
- CLI réelle, rc0 : out/a7-integration-20261009/cli-20261011T170753-10921. Dix-neuf PE, dont boucle sans cmp (40) et sortie CH (22068), sont assemblés par --backend mir. Les chemins object/link MIR et le lien C donnent les mêmes octets PE sur la paire multi-module explicite. Le chargeur indépendant valide les u64 complets : 64 checks, zéro défaut, 19 positifs, un mutant du code et un en-tête endommagé. Trois PE contenant les paramètres macro inutilisés se chargent aussi et leur main rend42 : macro-params-20261011/host.log, 73/0, 22 positifs et les deux contrôles négatifs. Cette dernière preuve n'établit pas l'utilisation des paramètres de la fonction générée.
- QEMU/OVMF KVM, rc0 : cli-20261011T170753-10921/qemu-20261011T171027-14033. Dix-neuf résultats attendus, 19/19, A7DONE une fois. Le shell UEFI expose les 32 bits bas ; la valeur u64 entière est prouvée par le chargeur hôte. before.txt et after.txt sont vides : une seule instance lancée, aucun QEMU persistant.

## Changements et limites du périmètre

MIR/1.0 porte les cellules des familles GPR, les tranches 8/16/32/64, les drapeaux, les valeurs IN séparées des registres et les effets d'appel. Les jonctions, boucles, écritures partielles, lectures après appel, opérations étroites et immédiats hors plage sont maintenant confrontés à la référence. DIV/IDIV à un opérande restent des refus communs : la référence exige une preuve runtime indisponible (E503), MIR refuse981. Les expressions / et % gardent leur chemin typé.

L'essai CLI initial a trouvé un écart de parser sur les contrats en ligne : le C acceptait la source, Nova imposait un terminateur après le type de retour. function_decl suit maintenant la condition exacte de parse_function du C. La porte parser a été rouge127/4 avant la correction, verte127/0 ensuite, avec deux positifs en ligne et deux refus de contrats incomplets. Les fixtures loop/highbyte n'ont pas été normalisées pour faire passer le test.

La capture implicite app+math reste refusée374 selon l'hygiène de spec/ntasm/ntasm.md §13 ; l'appel explicite est accepté et exécuté. C accepte encore cette capture interdite. Les noms de paramètres de certaines fonctions générées par macro sont refusés353 par validate avant MIR, cas déjà épinglé par la porte validate ; d'autres sondes de bindings sont refusées328 avant MIR. Le C refuse lui-même le profil emit quote(decl) utilisé par les trois sondes en200. Ces écarts des passes de macros et de validation appartiennent à A5 ; le présent lot ne prétend pas les corriger. L'ancien doute sur FLAG_DIR_UNREAD est, lui, levé par la lecture des trois modes dans l'image publiée.

Le producteur par défaut reste C, MIR se choisit explicitement. run --backend mir reste605 ; les PE sont exécutés par le chargeur indépendant et QEMU. Aucun retrait du bootstrap, preuve d'auto-hébergement ou livraison B2.1 n'est déduit d'A7. La suite globale n'a pas été rejouée ; les rouges antérieurs hors A7 restent documentés dans l'historique.

## Historique du 7 octobre 2026 (état antérieur, remplacé ci-dessus)


Date : 7 octobre 2026. Périmètre : critère A7 de `ntasm-completion.md` — « NTIR/Machine IR et NXO/PE versionnés; programmes assemblés, chargés et exécutés, inspecteurs et goldens ». **Verdict : `partiel`.** La frontière écrite le 2 octobre est levée : des exécutables sortent du Machine IR, et le corpus v0 s'exécute avec les valeurs de la référence. La réserve est nommée en fin de document : la chaîne commune refuse, par des codes nommés, des programmes que le langage admet et que la référence C exécute. Les revues indépendantes ont trouvé, l'une après l'autre, des chemins où elle rendait une valeur fausse. Chacun est maintenant refusé et épinglé, mais l'absence de tout autre chemin n'est pas prouvée. A8 (auto-hébergement, retrait du producteur étranger) est un critère séparé.

## Ce qui est intégré dans le principal

La chaîne, écrite en Nova : source → une expansion de macros → validation de l'arbre développé → NTIR → Machine IR vérifié → émission x86-64 depuis le Machine IR → conteneur NXO → édition de liens et PE → chargement → exécution.

- `../toolchain/ntasm-nova/machine_emit.nova` : l'émetteur. Il ne lit que l'image Machine IR vérifiée et les octets des empans qu'elle cite, sans arbre ni NTIR. Il est « à cadre » : chaque valeur a un emplacement de pile de 8 octets, et aucune allocation de registres n'est lue, ce qui lève la frontière du 2 octobre (l'image ne portait pas de registre de destination). L'identité d'un registre de la source est la cellule que `machine_ir` associe à son orthographe ; un paramètre arrive dans le registre que sa liaison nomme. Branches, disposition des blocs, sauts, données, appels internes et importés, relocations REL32 et symboles NXO sont émis. Les refus portent les codes nommés 980 à 985 (`../spec/machine-ir-v0.md` §12), jamais une sortie vide.
- `../toolchain/ntasm-nova/machine_ir.nova` : format Machine IR **0.3** (`FORMAT_MAJOR` 0, `FORMAT_MINOR` 3). Faits de déclaration ajoutés : exportation, données en lecture seule ou modifiables, direction des paramètres, masque de clobbers, masque de features, cible d'import (`../spec/machine-ir-v0.md` §10–§11). La porte `machine_schema` confronte le schéma des §2 à §8 au module ; `machine_ir`, `machine_pipeline` et `machine_corpus` contrôlent les §10 à §12.
- `../toolchain/ntasm-nova/machine_pipeline.nova` : l'objet et le PE passent par `machine_emit`. La direction d'un paramètre est demandée au propriétaire de la règle, `abi.nova`, par le relais `abi.parameter_mode`. La mesure `PARAM_MODES` de `machine_pipeline` donne `in` 0, `out` 8192 (`FLAG_DIR_OUT`) et `inout` 16384 (`FLAG_DIR_INOUT`) ; sur le même fixture sans le pipeline, `machine_ir` mesure les trois à `FLAG_DIR_UNREAD`.
- Imports : un module qui importe une fonction donne un NXO relogeable portant l'import non résolu, et l'édition de liens le résout. Un PE demandé sur un import non résolu est refusé (`E804`), et la référence C le refuse aussi. Une faute de l'hôte n'est jamais un succès : `invoke`, dans `../bootstrap/quarantine/c/nova/machine_driver.c`, rend un refus dès que `runtime` est non nul ou qu'un retour 0 n'a écrit aucun octet.
- Commande : `ntasm assemble|object|link|check --backend mir` (`../bootstrap/quarantine/c/cli.c`). Il n'y a aucun repli ; `run --backend mir` est refusé (`E605`), et les verbes expérimentaux sont retirés. Guide : `ntasm-cli.md` §2.1.
- Les changements de Codex à `machine_x64.nova` et la porte `machine_x64_alloc` sont retirés, mais conservés sous `../out/a7-integration-20261007/withdrawn/`. Ils sont hors du chemin de production, et ils rendaient `object_pe_join` rouge.

## Résultats

Les harnais des portes sont compilés avec GCC `-std=c11 -Wall -Wextra -Werror -fsanitize=address,undefined` et exécutés avec `detect_leaks=1`. Les bibliothèques C que `ngbuild.sh` compile pour eux, `machine_driver.c` compris, ne prennent pas `-Werror`. Campagne complète sur les sources finales : `../out/c-bootstrap/builds/a7-final-20261007-6.driver.out` (empreinte dans `../out/a7-integration-20261007/final-manifest-6.json`), code de sortie 1, `GATES_DONE fail=1`. Ce rouge est entièrement antérieur (voir « Base ») ; le garde `MODULES_EDITED_BETWEEN_RUNS` y nomme exactement les deux fichiers du dernier passage, et aucun module n'a changé pendant la course.

| Mesure | Résultat |
|---|---|
| Corpus `examples/ntasm-v0` (22 fichiers, 25 lignes dont 3 paires liées), par les deux producteurs, PE chargés et appelés | `machine_corpus` 136/0 : 17 `AGREE` (même u64), 0 divergence, 0 faute, 7 refus des deux côtés, 1 `C_ONLY` épinglé |
| Objets par module : nom, drapeaux, section, texte du contrat, taille des données et entrée de chaque symbole | 19 accords sur les 19 modules acceptés par les deux ; 2 modules refusés des deux côtés ; `app.ntasm` refusé par la chaîne seule, épinglé |
| Contrôle : l'unique encodage `add` de `machine_emit.nova` remplacé par `sub`, à longueur égale, dans une copie | `CANARY_TALLY compared=17 moved=7 unchanged=10` ; la porte exige au moins un résultat déplacé (sinon `PROOF_INVALID`) et au moins un inchangé |
| Lignes `JOIN` : programmes que la référence exécute, où la chaîne doit refuser ou rendre la même valeur | 17 sur 17 refusées, étape et code épinglés pour chacune, 0 valeur fausse |
| Refus écrits dans la porte, refusés par les deux producteurs | 7 sur 7, chaque code épinglé des deux côtés, dont les quatre formes que la référence refuse (`E400`) et que la chaîne construisait : `load-wider-than-element`, `idiv-two-operands`, `div-two-operands`, `store-wider-than-element` (chaîne 981) |
| PE de la chaîne commune exécutés sur l'hôte | `machine_producer_exec` 53/0, 17 valeurs exactes |
| Images figées octet par octet, modes de paramètres | `machine_pipeline` 790/0, dont `PARAM_MODES in=0 out=8192 inout=16384` |
| Machine IR versionné | `machine_schema` 3113/0, `machine_ir` 1060/0 |
| NTIR, NXO, PE, inspecteurs, goldens de sortie, CLI | `ntir_schema` 6871/0, `nxo_inspect` 290/0, `nxo_inspect_text` 186/0, `output_goldens` 147/0, `pe_exec` 61/0, `x64_lower_nxo_pe` 2631/0, `corpus_e2e` 150/0 ; `call_contracts` 2040/0, `cli` 104/0, `object_pe_join` 166/0, `machine_x64` 488/0 |

Hors portes, 81 programmes de sonde, ceux de l'auteur et ceux des revues, ont été passés par `run --backend c` puis `assemble --backend mir` sur le principal final. Ils couvrent formes d'instructions, largeurs, littéraux, lectures et écritures de données, divisions, paramètres liés et registres après un appel. Leurs PE ont été chargés par le chargeur de `pe_exec`. La référence en exécute 63. La chaîne commune en construit 16 et n'en construit aucun que la référence refuse ; les 65 autres sont refusés par un code nommé. Les 16 rendent la valeur de la référence. Pour `paramexpr`, qui lit le paramètre de `main` (que `run` appelle avec `rcx`=0), la comparaison est faite entre les deux PE sous le même chargeur : 2 et 2 (`probes/paramexpr.same-loader.log`). Aucune valeur fausse. Sources : `../out/a7-integration-20261007/probes/` ; outil : `../out/a7-completion-20261004/out/team/claude/probe_values.sh` ; journal : `../out/a7-integration-20261007/probes-final.log`.

**La ligne `C_ONLY`.** La paire `app+math` est exécutée par la référence C et refusée par la chaîne à l'étape 2 (`E374`). Le gabarit de la macro de `examples/ntasm-v0/c-bootstrap-multi/app.ntasm` nomme `add`, un symbole du module appelant, et `../spec/ntasm.md` §13 interdit cette capture par défaut. La ligne est épinglée (`KNOWN`). La variante explicite `common-pipeline/multi-explicit-app.ntasm` donne `AGREE`.

**Base.** Campagne avant intégration : `../out/c-bootstrap/builds/a7-baseline-20261007.driver.out`. Les éléments rouges de la campagne finale sont ceux de la base, `LAST_RUN_SNAPSHOT_OLD` en moins : `initializer_types` (lignes « left associative », code 400), `registry` (8 `IDENT-MISSING` dans `spec/ntasm/ntasm.md`), `nova_language` (`UNREGISTERED_HARNESS`), le rail des fins de ligne (5 fichiers A2/A5) et `VERDICT_CHECK_FINDING` (titre de l'entrée A2). Aucune ligne `FAIL` n'est nouvelle ; six de la base ont disparu (les lignes d'opérandes `940` d'`initializer_types`). Les portes `abi` (2073/0) et `c_conversion` (68/0) ont tourné sur le travail d'une autre session, qui rend le recensement de la règle de direction sensible à `export fn` ; ce ne sont pas des résultats A7. `ntbuild.sh selftest` rendait `pass=41 fail=1` sur son attente littérale « pass=5 », un défaut antérieur qu'une autre session répare.

## Commande de l'utilisateur

```sh
bash scripts/ntbuild.sh
out/c-bootstrap/ntasm/ntasm assemble --backend mir examples/ntasm-v0/c-bootstrap-controlflow/branching-runtime.ntasm -o branching.efi
out/c-bootstrap/ntasm/ntasm object --backend mir examples/ntasm-v0/common-pipeline/multi-explicit-app.ntasm -o app.nxo
out/c-bootstrap/ntasm/ntasm object --backend mir examples/ntasm-v0/c-bootstrap-multi/math.ntasm -o math.nxo
out/c-bootstrap/ntasm/ntasm link --backend mir app.nxo math.nxo -o app.efi
out/c-bootstrap/ntasm/ntasm inspect app.efi
```

Parcours rejoué sur le binaire de la construction normale (`out/c-bootstrap/ntasm/ntasm`, 399 056 octets, sha256 `09ce92c31537561d…`, identique d'une construction à l'autre) : `../out/a7-integration-20261007/cli-e2e.log`, chaque code de sortie étant écrit par la commande elle-même.

- Quatre `assemble --backend mir` (`NTASM_MIR_PE`), deux `object` (`NTASM_MIR_OBJECT`) et un `link` (`NTASM_MIR_LINKED provenance=NEXORA_NOVA_LINKER`).
- Trois PE ont la même empreinte, `429d3b947a607ac2…` : celui que lie la chaîne, celui que l'éditeur de liens C écrit à partir des mêmes objets, et celui d'`assemble` sur les deux sources.
- Refus attendus : `E374` (`app.ntasm`), `E605` (`run --backend mir`), `E804` (import non résolu) et `E940` (boucle sans `cmp`).
- Les sept PE sont chargés et appelés par le chargeur de `tests_ntasm_pe_exec.c` : 28/0, valeurs exactes. Un octet de code muté change la valeur ; un fichier sans en-tête MZ est refusé.

**QEMU/OVMF**, une seule session : `../out/a7-integration-20261007/qemu-mir.log`. Les 17 PE que la commande écrit pour le corpus sont lancés depuis le shell UEFI (QEMU 8.2.2, KVM) : `QEMU_MIR_SUMMARY cases=17 pass=17 fail=0`, QEMU rend 0, et aucun QEMU ne tourne ni avant ni après. Le canal `%lasterror%` ne porte que 32 bits ; la valeur complète de `returnmax` est prouvée sur l'hôte.

## La réserve, nommée

**La chaîne commune refuse des programmes que le langage admet et que la référence C exécute.** Cinq familles, toutes épinglées par les lignes `JOIN` de `machine_corpus` avec leur étape et leur code :

1. **Une valeur de registre qui franchit une jonction ou une boucle.** Le Machine IR nomme un registre par sa dernière écriture dans l'ordre d'abaissement, et `mir_phi` ne porte pas de valeur. Les cas refusés :
   - une lecture après `if`/`else` ou après une étiquette (981) ;
   - une boucle avec `cmp` (Machine IR `E_SHAPE` 934) ;
   - une boucle sans `cmp`, faute de prédicat (`E_INPUT` 940) ;
   - un `cmp` séparé de son saut par un écrivain des drapeaux (981) ;
   - une destination mémoire (981).
2. **Un registre écrit sur moins de 64 bits, par une instruction ou par un `load`** (981). Le Machine IR garde une cellule par orthographe : `al` et `rax` y sont deux cellules.
3. **Une opération de moins de 64 bits qui n'est pas exacte entre deux constantes** (981). Le Machine IR type un littéral par sa grandeur et une opération par son opérande gauche.
4. **Un registre lu après un appel**, quand sa valeur vient d'une instruction ou d'un chargement d'avant l'appel (981). Le `mir_call` n'écrit aucune cellule : ni `rax`, ni les registres que l'appelé écrase.
5. **Un paramètre, dans une fonction qui appelle, lu ailleurs que dans le bloc d'entrée avant le premier appel** (981). La cellule du registre lié porte la valeur du paramètre, et l'image ne dit pas si l'opérande a été écrit par le nom du paramètre ou par celui du registre. `return x` après un appel est donc refusé lui aussi, alors que la référence le calcule correctement.

**Comment ces refus ont été trouvés.** Dix valeurs fausses et quatre acceptations à tort ont été exécutées par le chargeur de `pe_exec` :
- la seconde revue indépendante : `alias` (0x1234 au lieu de 0x1200) et `narrow` (0x80000000 au lieu de 0) ;
- l'auteur, en corrigeant ces deux-là et par des sondes : `literal-sum` (44 au lieu de 300) et `signed-division` (branche fausse) ;
- la troisième revue : `load` vers `eax`, `al` et `cl`, puis `rax` et `rcx` lus après un appel ;
- la quatrième revue : un paramètre lu par le nom de son registre après un appel (1 au lieu de 9), et un `load` 64 bits d'une donnée `u8` que la référence refuse (`E400`) ;
- la cinquième revue : `idiv` et `div` à deux opérandes (l'`idiv` s'exécutait non signé) et un `store` plus large que sa donnée, trois formes que la référence refuse (`E400`).

Les lignes `JOIN` et de refus correspondantes ont été vues rouges dans la porte (`WRONG` ou `MIR_ONLY`) avant chaque garde. Seules exceptions : `literal-sum` et `signed-division`, ajoutées après leur correction, dont la valeur fausse a été vue par sonde.

**Parité de validation, ouverte et mesurée.** La chaîne commune construit des programmes que la référence refuse. Mesuré le 7 octobre 2026 par la sixième revue (sources et sorties : `../out/a7-integration-20261007/review6/`) : `add`, `cmp`, `and` et `xor` avec un immédiat hors de la plage 32 bits signée — la référence refuse en `E401` (« value out of range ») ; la chaîne construit et exécute ce que la source écrit, en matérialisant l'immédiat sur 64 bits. `sub`, `or` et `test` n'ont pas été mesurés. Ce n'est pas une valeur fausse, mais un exécutable que la référence n'aurait pas produit ; il rejoint les quatre acceptations à tort fermées plus haut. Les sondes ne sont pas un balayage : la parité se mesurera en passant par `--backend mir` le catalogue des refus de la référence (les cas `E400` et `E401` de ses portes) et en publiant le compte des écarts.

Lever la réserve demande un modèle de registres et de largeurs dans le Machine IR lui-même : une cellule par famille de registres avec écriture partielle, des `mir_phi` porteurs de valeur, des effets d'appel sur les cellules, des paramètres distingués de leur registre, le type de la déclaration propagé aux expressions, et une largeur d'accès lue sur l'élément. C'est un changement de format, donc une révision 0.4. Le corpus v0 ne contient aucune de ces formes.

## Limites hors critère

- Le producteur par défaut de `ntasm` reste la référence C ; la chaîne commune se choisit par `--backend mir`. Annuler ce choix tient en une ligne de `cli.c` (la valeur initiale de `mir`) plus le rebasage des portes qui appellent la commande sans option ; le résultat d'`app.ntasm` changerait alors pour tous ses consommateurs.
- `run --backend mir` est refusé (`E605`), car `run` appelle en mémoire l'image de la référence C. Les PE de la chaîne sont chargés par le chargeur de `pe_exec` et sous QEMU/OVMF.
- Les objets sont comparés par leurs symboles et leurs contrats, pas par leurs octets : l'ordre des fonctions suit l'image, alors que la référence trie par nom. Le PE lié de la paire multi-module est, lui, identique octet pour octet entre les deux éditeurs de liens.
- La campagne QEMU est datée et hors routine ; la routine charge et exécute les mêmes PE sur l'hôte.
- La validation Nova accepte des formes que la référence refuse (`E400`) : une annotation `ptr<user,i32>` sur une donnée `u32`, un `load` ou un `store` plus large que sa donnée, et `div` ou `idiv` à deux opérandes. L'émetteur refuse ces formes ; l'écart de validation lui-même demeure, et la famille `E401` des immédiats hors plage reste acceptée (voir « Parité de validation » ci-dessus).
- Selon la seconde revue, un paramètre produit par une macro reste `FLAG_DIR_UNREAD`, et la chaîne le refuse. Je ne l'ai pas mesuré.
- Le pilote C de la chaîne (`machine_driver.c`) compile et appelle les modules Nova, et ce sont ces modules qui écrivent les octets. Un pilote en Nova relève d'A8.

## Empreintes et sauvegardes

Manifeste des sources finales, des journaux et du binaire : `../out/a7-integration-20261007/final-manifest-6.json`. Extraits (sha256, 16 premiers caractères) : `machine_emit.nova` `39423115f9b2a224`, `machine_ir.nova` `6ff1b0bc09c6cf08`, `machine_pipeline.nova` `dd7c7046c684eb91`, `abi.nova` `2044d8cc4282d82e` (commentaire réécrit par la session « abi »), `cli.c` `be37238a1b217635`, `machine_driver.c` `44d7faf8d32afdcb`, `tests_ntasm_machine_corpus.c` `44c6b431a29e4ce7`, `tests_ntasm_machine_pipeline.c` `d266b360cfe6f1c1`, `spec/formats/machine-ir-v0.md` `935fe59c49b09ba8`. Les six passages d'intégration ont vérifié l'empreinte de chaque fichier du principal avant de l'écrire. Sauvegardes : `../out/a7-integration-20261007/backup/`, `backup-round1/` à `backup-round5/`, `backup-docs/` à `backup-docs4/`.
