# NTASM v0 — langage machine typé de Nexora Genesis

Statut : spécification normative `NTASM-v0`, gel consolidé le 14 octobre 2026.

Jalon de livraison fixé le 4 septembre 2026 : **B2.1 = NTASM v0 complet**,
suivant [le contrat A1–A10](../../docs/status/ntasm-completion.md) et l'ADR 0011.
L'ancien ordre « dernier frontend après NX/Nova/OS » est remplacé.
Les prérequis de gel sont ceux de la section 17 et de son état de preuve courant.
Le simple auto-hébergement du profil S0 ne livre pas v0.

Ce document définit NTASM v0, langage source machine typé et structuré.
La grammaire complète est `ntasm-v0.ebnf`, avec ses contraintes lexicales et
contextuelles dans `ntasm-grammar-v0.md`. Le catalogue des domaines est
`ntasm-catalogue-v0.md` ; les formats sont `ntir-v0.md`, `machine-ir-v0.md`
et `nxo-v0.md`. Le catalogue d'encodage est `x64-forms.csv`.

Révision de gel du 14 octobre 2026 : les états datés des anciennes campagnes
restent des archives. L'état courant des dix prérequis, ses preuves et limites
sont dans `../docs/ntasm-a1-freeze.md`. Cette consolidation ne modifie ni le
profil S0, ni les règles de preuve de contrats, ni le besoin d'auto-hébergement
A8. Aucun comportement n'est autorisé par une ancienne phrase prospective
contre le catalogue et la grammaire maintenant fermés.

## 1. Deux langages de portée différente

`NTASM-S0` et `NTASM v0` ne sont pas deux noms pour le même profil.

| Propriété | NTASM-S0 | NTASM v0 |
|---|---|---|
| Rôle | bootstrap temporaire fermé | langage machine typé final |
| Autorité | [`ntasm-s0.md`](ntasm-s0.md) | ce document et ses futures révisions |
| Producteur initial | `seed0.efi` saisi en octets | frontend de la chaîne Genesis auto-hébergée |
| Syntaxe | lignes plates, trois sections fixes, 30 mnémoniques | modules, sections structurées, fonctions et contrats typés |
| Types | registres GPR et largeurs imposées par les formes | scalaires, registres, features CPU, pointeurs par espace et ABI |
| Métaprogrammation | aucune | comptime borné et macros AST hygiéniques sans I/O |
| Sortie | PE32+ `B1-PE-v1` | NTIR, Machine IR, NXO et PE selon profils versionnés |
| Durée de vie | jusqu’au bootstrap et au point fixe | maintenance durable du système |

**Règle de non-contamination :** S0 ne reçoit aucun module, fonction typée,
`effects`, `clobbers`, `requires`, `ensures`, pointeur par espace, macro,
comptime, génération de stub ou intrinsic supplémentaire défini ici. Toute
tentative de rétroporter une feature v0 dans S0 exige une révision explicite de
`ntasm-s0.md`, ses goldens, son budget d’octets et ses preuves; la décision par
défaut est le refus.

Les Gates B1 et B2 restent donc jugées exclusivement par NTASM-S0. NTASM v0 ne
peut ni détendre leurs bornes ni servir d’excuse pour agrandir le seed.

## 2. Objectifs de conception

NTASM v0 doit permettre d’écrire les portions du système qui exigent un contrôle
machine exact sans revenir à un assembleur textuel non typé.

Il doit :

- rendre visibles le target, l’ABI, les registres d’entrée, les clobbers, les
  effets, les préconditions et les postconditions;
- imposer une largeur explicite ou inférable sans ambiguïté;
- utiliser l’ordre d’opérandes `destination, source`;
- distinguer les espaces d’adresses dans les types de pointeurs;
- modéliser les registres, flags, features et intrinsics CPU par target;
- produire des symboles, sections et relocations versionnés et déterministes;
- générer les stubs répétitifs d’interruption/syscall depuis des déclarations
  structurées, pas depuis du texte concaténé;
- converger avec NX vers NTIR puis Machine IR sans imposer à NX de produire un
  fichier `.ntasm` intermédiaire;
- rester auditable : aucune capacité privilégiée implicite, aucune macro avec
  I/O, aucune évaluation comptime non bornée.

NTASM v0 n’est pas une syntaxe Intel générale, un préprocesseur de texte, un
linker universel ou une voie pour contourner les effets et capacités de Cnuva,
NX ou Nova.

## 3. Forme d’un module

Un fichier NTASM v0 contient exactement un module et exactement un target. Leur
ordre est figé : `module`, puis `target`, puis les déclarations et sections.

```text
module <nom.qualifié>
target <triple-cible>
```

- Le nom de module est stable, sensible à la casse et indépendant du chemin
  hôte. Deux modules ne peuvent partager le même nom dans une unité de build.
- Le target est une valeur enregistrée, telle que `x86_64-nexora-none`; il
  sélectionne le registre typé, les features, les intrinsics, l’ABI par défaut et
  les relocations disponibles.
- Un target inconnu ou une feature absente est une erreur avant Machine IR.
- Le profil initial accepte exactement `x86_64-nexora-none` et
  `x86_64-nexora-uefi`.
- Le catalogue x86_64 v0 est fermé à `lm`, `msr`, `syscall`, `sse2`, `tsc`.
  `lm` est implicite et idempotent; les autres doublons et les noms qualifiés ou
  inconnus sont refusés.
  Tout prédicat `feature(x)` dans `requires` ou `ensures` doit appartenir à ce
  catalogue et au masque effectivement déclaré par le module; le contrat ne
  peut pas fabriquer une capacité target.
- Le chemin absolu du fichier, l’heure, la locale et l’ordre du système de
  fichiers ne participent jamais à la sortie.

Les versions des contrats binaires sont des métadonnées du module compilé :

- ABI : `nx64-abi-v0` ou ABI target explicitement enregistrée;
- sections : `nxo-sections-v0`;
- symboles : `nxo-symbols-v0`;
- relocations x86_64 : `nxo-x64-reloc-v0`;
- NTIR et Machine IR : version majeure/mineure déclarée.

Le bloc `versions` v0, lorsqu'il est présent, contient exactement une entrée
pour `ntir`, `machine_ir`, `sections`, `symbols`, `relocations` et `nxo`, toutes
en version `0.1`. Un domaine inconnu, dupliqué, incomplet ou d'une autre version
est refusé.

Une incompatibilité de version est une erreur; elle ne déclenche jamais un
fallback silencieux.

## 4. Sections structurées et symboles

Une section est un bloc syntaxique, pas un changement d’état implicite qui se
propage jusqu’à la fin du fichier :

```text
section .syscall {
    ...
}
```

Chaque nom de section possède une classe, des permissions et une politique de
relocation définies par le profil de sortie. Une section source logique telle que
`.syscall` peut être regroupée dans une section exécutable du format final, mais
le mapping est déclaré et déterministe. Le compilateur refuse toute combinaison
W+X et toute permission plus large que celle du contenu.

Les symboles sont :

- locaux au module par défaut;
- visibles hors module uniquement avec `export`;
- importés uniquement par une déclaration typée et une version d’ABI compatible;
- triés dans un ordre canonique indépendant d’une table de hachage;
- référencés symboliquement jusqu’à la phase de relocation.

`export fn` exporte une fonction et son contrat, pas seulement une adresse brute.
Le nom, le type, l’ABI, les paramètres liés aux registres, les effets,
préconditions, postconditions et clobbers participent à l’identité d’interface.

## 5. Fonctions, paramètres et registres typés

La forme normative d’une fonction machine est :

```text
[export] fn nom(
    <direction> paramètre: type @registre,
    ...
) -> type_retour
effects { ... }
clobbers { ... }
requires { ... }
ensures { ... } {
    ...
}
```

Les directions initiales sont `in`, `out` et `inout`. Une liaison `@registre`
est une contrainte vérifiée, pas un commentaire : largeur, classe de registre et
type doivent être compatibles. Deux paramètres simultanément vivants ne peuvent
occuper le même registre sauf alias explicite prévu par l’ABI.

**Correction du 28 septembre 2026 : la phrase « reconnaît exactement
`nx64-abi-v0` » était fausse et est retirée sur place.** L'oracle C reconnaît
**deux** profils d'ABI, et non un. `validate_parameter_abi`
(`compiler/c/ntasm/frontend/frontend.c:2827`) ouvre deux blocs disjoints : le
bloc `nx64-abi-v0` à `frontend.c:2830` et le bloc `efi-x64-v0` à
`frontend.c:2894`, puis refuse tout autre nom en `400`/`403`
(`frontend.c:2944`). La borne de quatorze paramètres est **dans** le bloc
nx64 (`frontend.c:2832`), elle ne s'applique donc pas au second profil, qui
va jusqu'à soixante-quatre entrées (`compiler/c/ntasm/backend/codegen.h:36-38`
et `codegen.c:543`). Le profil `efi-x64-v0` n'est pas un alias : il est
l'**ABI Microsoft x64** (UEFI), et non un second nom de `nx64-abi-v0` — voir
le §17.5 pour la preuve et pour le coût de l'écart qui les sépare encore.
La phrase suivante est donc restreinte au seul profil nx64.

Le profil exécutable `nx64-abi-v0` se nomme explicitement sur la
fonction/import ou comme `default_abi`; son absence sélectionne ce défaut
pour les targets x86_64 Nexora actuels. **Un target `x86_64-nexora-uefi`
NE sélectionne PAS `efi-x64-v0`** : `frontend.c:5087` pose
`default_abi = "nx64-abi-v0"` sans condition, et `frontend.c:5088-5089` ne
valide le target que comme un nom. `efi-x64-v0` n'est atteignable que par une
clause `abi` explicite ou un `default_abi` explicite. Le profil nx64
accepte au plus quatorze paramètres
registre. Les quatre premiers paramètres `in` sans liaison explicite utilisent,
dans l’ordre, `rcx`, `rdx`, `r8`, `r9`; le cinquième et les suivants exigent un
`@GPR`. Tout paramètre `out` ou `inout` exige aussi un registre explicite et son
type doit être un entier machine ou un pointeur. Un pointeur est lié à une forme
64 bits. Les alias d’une même famille physique ne créent jamais deux emplacements
ABI distincts.
Une sortie ne peut utiliser rax, rsp ou rbp et sa famille ne peut pas figurer
simultanément dans `clobbers`.
Au call, les paramètres `in` et `inout` consomment un argument dans l’ordre de
la signature; un paramètre `out` n’en consomme aucun.
Chaque argument fourni est vérifié contre le type du paramètre : littéral borné,
paramètre/local du caller ou résultat de call déjà typé. Une expression dont le
type n’est pas encore prouvé échoue fermée.

Le catalogue scalaire v0 est fermé à `u8/u16/u32/u64`, `i8/i16/i32/i64`,
`bool` et `never`. Les formes composées sont `ptr`, `array`, les listes méta et
les variables de type macro prévues par la grammaire. Un tableau de longueur
zéro ou un nom scalaire inconnu est refusé.

**Un `bool` lié à un registre 8 bits est typé `bool`, et non `u8`.** Acté le
1er octobre 2026, à la charge de `compiler/c/ntasm/frontend/frontend.c`, et la
charge se lit en sept sites vérifiés un par un :

- l'exception qui l'accorde existe à **deux** sites et elle est **vraie** —
  (`frontend.c:2871-2872`, `reg.bits`) sur le chemin des paramètres, le refus
  `NTF_E_REGISTER` suivant à (`frontend.c:2860-2861`, `NTF_E_REGISTER`,
  fn parse_parameters) ; et
  (`frontend.c:5045-5046`, `reg.bits`) sur le chemin des macros, refus à
  (`frontend.c:5047-5048`, `NTF_E_REGISTER`, fn expand_macro_declaration).
  **2 187 lignes d'écart, dans le même
  fichier, et un `grep` les rapproche en une commande** ;
- le **troisième** site n'a pas la clause et **c'est lui qui refuse** — le refus
  `NTF_E_TYPE` « register width mismatch » est émis à
  (`frontend.c:1677`, `NTF_E_TYPE`, fn infer) ;
- `bool` vaut 1 bit comme **REPRÉSENTATION**, à (`frontend.c:1626`, `NTF_T_BOOL`,
  fn infer), (`frontend.c:1822`, `NTF_T_BOOL`, fn infer),
  (`frontend.c:1841`, `NTF_T_BOOL`, fn infer) et
  (`frontend.c:5531`, `NTF_T_BOOL`, fn verify_statement).

**Ces sept numéros ont été ré-ancrés le 1er octobre 2026, après que
`frontend.c` eut été réécrit et les eut décalés — et ils viennent de ce que le
lot a laissé DANS le fichier, à `frontend.c:1635-1645`, où le commentaire de la
correction nomme `:2843` et `:4992` pour les deux clauses. Un numéro que le code
lui-même corrige est plus sûr qu'un numéro que l'on cherche à l'extérieur du
fichier, parce que c'est le code qui l'a constaté et qu'il l'a réécrit quand il a
déplacé la chose qu'il désigne.**

**Et cela ne dit rien de la LIAISON : un entier d'un bit n'existe pas, donc une
liaison d'un bit n'est pas exprimable.** Refuser une liaison sur une propriété de
représentation qui n'a pas de portée sur elle est la confusion même qui fait que
(`frontend.c:1677`, `NTF_E_TYPE`, fn infer) refuse. L'expression-registre ne doit
donc plus
déduire son type de la seule largeur du registre lorsqu'un type est attendu :
**elle prend le type attendu, et c'est le prédicat de largeur qui vérifie
ensuite — non l'inférence qui le précède.**

**Et la clause à deux sites reste un ARGUMENT, pas une mesure.** Le chemin des
macros écrit ses paramètres sans mention de registre dans la syntaxe disponible
(`comptime-macro.ntasm` et `app.ntasm` écrivent `macro ret(v:ast.expr)->ast.stmt`),
donc la seconde copie n'est atteinte par aucune porte. **Deux sites qui portent la
même clause sont deux fois la même volonté ; un seul est mesuré, et l'écart est
>nommé.**

Le registre est une valeur target typée. Sur x86_64, `rax` n’est pas un simple
identifiant interchangeable avec un registre SIMD, un segment ou un control
register. Le catalogue target décrit :

- classe et largeur;
- alias de sous-registres;
- rôle spécial éventuel, notamment pile, instruction pointer et flags;
- feature CPU requise;
- privilège et effets de lecture/écriture;
- règles d’allocation et de préservation de l’ABI.

`never` signifie que le contrôle ne revient pas au caller. Un transfert par
`sysretq`, `iretq`, saut terminal ou arrêt vérifié peut satisfaire `-> never`;
une chute à la fin du bloc est une erreur.

Une fonction à valeur doit terminer par un `return` portant une expression, ou
par un `if` dont les deux branches sont terminales. Une fonction `never` refuse
tout `return` et doit terminer par un transfert reconnu. Le premier profil Nova
reconnaît directement `ud2`, `sysretq` et `iretq`; les calls vers une fonction
`never`. Un call statement final résolu vers une fonction locale ou un import
`-> never` est également terminal; les graphes plus généraux restent une
extension séparée.

La condition d’un `if` doit être prouvée `bool`. Le profil initial prouve les
littéraux booléens, les paramètres et locals de type `bool`, les comparaisons,
les calls locaux/importés dont le retour est `bool` et le prédicat target
`feature(x)`. Un entier, un nom d’un autre type ou une forme d’expression dont
le type n’est pas encore inféré est refusé. La résolution et l’arité des calls
sont contrôlées avant ce test de type afin de conserver leur diagnostic propre.

**Une comparaison constante qui se plie en `bool` est une forme prouvée, et le
refus `401` qu'elle reçoit de la référence C est un défaut de cette référence et
non une règle du langage.** Acté le 1er octobre 2026, à la charge de
`compiler/c/ntasm/frontend/frontend.c`.

- `integer_kind` est le test de famille qui borne le refus
  (`frontend.c:1332-1333`, `integer_kind`, `k >= NTF_T_U8 && k <= NTF_T_I64`) ;
- `literal_fits` est la fonction qui l'appelle
  (`frontend.c:1335`, `literal_fits`, fn literal_fits) et son ouverture est
  (`frontend.c:1359-1360`, `integer_kind`, fn literal_fits) :
  `if (!integer_kind(t->kind)) return 0;` ;
- l'énumération qui rend le refus inconditionnel est
  (`frontend.h:63-77`, `NTF_T_BOOL`, `NTF_T_I64`).

**Les trois noms sont dans trois parenthèses distinctes, et c'est la forme que la
porte sait lire.** La règle qu'elle applique est le GROUPE entre parenthèses, pas
la phrase : mesuré, un cadrage sur la phrase donne 134 candidats et 112 échecs
sur ce document, donc une porte rouge sur un document correct. **Ma première
version mettait les deux noms dans une seule parenthèse, et la porte a lu le
groupe comme une affirmation portant sur les deux — puis a refusé, parce que
`:1321` ne nomme pas `literal_fits`.** Chaque nom est désormais dans la seule
parenthèse qui cite sa propre ligne. **Tout `bool` plié est donc
refusé inconditionnellement, quelle que soit sa valeur et quel que soit
l'opérateur** — mesuré sur les six opérateurs et sur `0 == 0`, `1 == 1`,
`0 < 1`, `1 < 0`, tous refusés `401`. Ce n'est pas une restriction de profil :
`let b:bool = x < 1` sur un vrai paramètre est accepté, et `if x == 0`,
`if x < 1`, `if x < y` le sont aussi. **Le déclencheur est le PLIAGE, ni le `if`,
ni l'opérateur, ni la valeur.** La classe est gardée par
`tests/c/nova/tests_ntasm_bool_fold.c`, qui n'interroge JAMAIS la
référence comme oracle et affirme ce que le produit publie — 96 membres
générés depuis la règle, non depuis une liste.

**Et la direction de la divergence est celle qui compte.** Un produit qui refuse
du code valide blesse visiblement : le lecteur voit l'erreur et la corrige. Un
produit qui ACCEPTE du code invalide blesse sans signe — le code compile, il est
livré, il est faux. **Toutes les divergences mesurées jusqu'ici dans ce projet
sont de la première sorte ; celle-ci est la première de la seconde, et la seule
qui soit un défaut de CONFORMITÉ plutôt qu'une couverture manquante.** Elle est
ouverte : la porte est rouge en permanence sur l'arbre courant, et elle constate
au lieu de réparer.

### 5.1 Portée des noms, collisions et masquage — gelé

Un nom écrit à un endroit donné doit désigner exactement une liaison visible à
cet endroit. Le vérificateur refuse les deux collisions qui briseraient cette
propriété et accepte la troisième, qui ne la brise pas. Les trois cas sont
implémentés et gardés; aucun n'est une extension prévue.

| cas | verdict | position rapportée | code | passe |
| --- | --- | --- | --- | --- |
| le même nom déclaré deux fois dans un même bloc | refusé | le second nom | `315` | `locals.check` |
| un `let` prend le nom d'un paramètre de la même fonction, dans le bloc de corps comme dans tout bloc imbriqué | refusé | le mot-clé `let` | `316` | `bindings.check` |
| un `let` d'un bloc imbriqué reprend le nom d'un `let` d'un bloc externe de la même fonction | **accepté**, le bloc le plus interne gagne | — | — | les deux passes |

`315` ouvre une table de noms par bloc (kind 25) et n'y compare que les enfants
directs de kind 27, donc un `let` d'un bloc imbriqué ne peut pas le déclencher. Le
bloc de corps est un bloc comme un autre : le cas est signalé dans un `if` comme
au niveau principal. `316` collecte les paramètres (kind 19) de la fonction,
compare les `let` du bloc de corps, puis ceux de tout autre bloc dont le span est
contenu dans le span de la fonction. Les blocs imbriqués sont parcourus par id de
nœud croissant, qui est l'ordre de parse, donc le premier contrevenant rapporté
est le premier de la source. `315` et `316` publient tous deux ligne et colonne,
et aucune raison.

Le troisième cas est une divergence assumée par rapport à une lecture stricte de
« un nom = une liaison », et elle est justifiée par l'oracle C plutôt que par un
choix du frontend Nova. `compiler/c/ntasm/frontend/frontend.c:796` `find_variable`
parcourt les variables en sens inverse — la plus récemment déclarée d'abord — et,
pour une variable à portée, remonte `p->depth` vers le bloc le plus interne
(`frontend.c:806-808`, fn find_variable) ; c'est donc le bloc le plus interne qui
répond.
`tests/c/ntasm/tests_frontend.c:676` `nested_scope_shadow` attend `0`,
c'est-à-dire l'acceptation. Le résolveur Nova rend la même réponse en retenant le
`let` du bloc de plus petite étendue qui contient l'usage
(`compiler/nova/analysis/types/initializer_types.nova:52-67`).

**Ce masquage est un changement de type silencieux, et il doit être lu comme
tel.** Aucun code ne le signale : le même nom porte deux types déclarés différents
selon le bloc où il est écrit, et le seul diagnostic qui en découle est un refus
de type ultérieur, placé à l'usage et jamais à la déclaration. La gate
`initializer_types` le vérifie dans les deux sens : un `let x:u64` externe et un
`let x:u32` imbriqué font échouer en `359` un `let y:u64=x` écrit dans le bloc
imbriqué, tandis que le même `x` lu après le bloc se prouve `u64`
(`tests/c/nova/tests_ntasm_initializer_types.c:513`). Un
lecteur qui voit deux `let` de même nom dans une même fonction doit savoir que le
second est un masquage et non une redéfinition, et que ce qui change est le type
déclaré.

L'ordre des deux passes par rapport à `initializer_types.check` fait partie de
l'invariant et non de l'implémentation ; il est figé au §17.7.

## 6. Largeur et ordre des opérandes

L’ordre NTASM v0 est toujours `destination, source`. Une instruction à trois
opérandes place la destination en premier, puis les sources dans leur ordre
sémantique. Aucune instruction n’inverse cet ordre pour imiter une autre syntaxe.

Une largeur est valide seulement si elle est :

1. explicite dans le type ou l’intrinsic; ou
2. inférée de manière unique depuis la destination, la source mémoire typée et
   la signature target.

Pour `load`, la largeur du registre destination et celle du type pointé doivent
coïncider. Pour `store`, le type pointé de la destination et la source doivent
coïncider. Pour une opération arithmétique, toutes les valeurs ont la largeur du
type de destination. Un littéral non contraint, deux largeurs contradictoires ou
plusieurs encodages sémantiquement différents produisent un diagnostic; le
compilateur ne choisit jamais selon une préférence implicite de taille.

### 6.1 Formes d'opérande d'une instruction machine — gelé

Ajouté le 28 septembre 2026. **Le §6 fixait l'ordre et la largeur des opérandes
et ne disait rien de leurs FORMES.** Un lecteur du §6 pouvait conclure que la
règle « inférée de manière unique depuis la destination, la source mémoire typée
et la signature target » épuisait la question ; elle ne l'épuise pas, et la
forme d'opérande est une question distincte, mesurée et fermée.

**Un opérande de position est exactement l'un des quatre suivants, et rien
d'autre** : un registre GPR de n'importe quelle largeur ; un opérande mémoire
typé dont l'adresse est un symbole de données ; un littéral immédiat ; ou, **pour
`mov` seulement**, un nom de liaison. Le nom de liaison est un `let` local, un
paramètre `in` ou un paramètre `inout` de la fonction courante. Il est accepté
**uniquement en position source**, **uniquement avec une largeur égale à celle
du registre destination**, et **uniquement avec une seule source**.

**Un `data` n'est pas une liaison, et cette phrase est normative.** `mov rax,seed`
est refusé en `400` ; `mov rax,[seed]:ptr<user,u64>` est la seule forme qui le lit,
et c'est la seule qui **charge l'effet de lecture**. La raison est structurelle et
non arbitraire : l'abaissement mixte atteint un nom par le bras `NTF_X_NAME` de
`codegen.c`, dont la branche d'emplacement de frame est conditionnée à ce que la
variable possède une fonction propriétaire, et un symbole `data` n'en a pas ; son
offset n'est donc jamais assigné et la lecture atterrit sur `[rbp+0]` quelle que
soit la valeur stockée. Un `const` n'est pas une liaison non plus : c'est un
littéral, et il passe par le canal immédiat. Toutes ces refus tomient sur le même
diagnostic et le même code que tout autre opérande qui ne s'abaisse pas.

**Pourquoi `mov` a un cas et les autres mnémoniques non — c'est un abaissement,
et non une règle d'opérande.** L'abaissement mixte de `mov` (`codegen.c:1008-1015`)
évalue la source dans RAX, range RAX dans un emplacement de sauvegarde, le
restaure, puis charge la destination. **Cette séquence n'est saine que parce que
`mov` seul fait de sa destination une cible d'affectation pure.** Pour
`add rax,answer` la destination est aussi une source : évaluer le nom dans RAX
détruit alors l'accumulateur, et la forme demanderait un second registre de
scratch dont l'écriture est **invisible au footprint `nt_x64_effects`** que
l'oracle calcule depuis la liste d'opérandes déclarée. Étendre le cas au groupe
arithmétique serait donc un **changement de langage avec une conséquence d'ABI
et de contrat de clobbers** (§8.2, §17.4), et non un cas oublié. C'est dit ici
pour que la prochaine vague ne le re-dérive pas.

**La contrainte qui rend ce cas nécessaire : aucun emplacement de frame n'est
exprimable comme opérande mémoire en v0.** Une annotation `ptr<espace,T>` sur une
adresse en registre ne fabrique pas de provenance — `conformance.c:389-392` rend
`NTF_E_MEMORY` « memory annotation cannot manufacture register pointer
provenance » — donc **une variable locale n'a pas d'adresse écrivable en v0**.
C'est pourquoi `mov` possède une forme pour un nom, et non une forme mémoire :
le cas n'est pas un effet de bord, il compense une absence.

**`lea` est 64 bits, et seulement 64 — décision normative du 28 septembre 2026.**
Une destination `lea` dont la largeur n'est pas 64 est **refusée**, et cette phrase est
normative, pas descriptive. Elle a été rendue nécessaire par une divergence
mesurée, et non par une préférence : l'oracle `nt_x64_encode` refuse tout
destination `lea` qui n'est pas 64 bits, en `NT_X64_WIDTH`
(`compiler/c/ntasm/backend/x64.c:176-177`), donc **l'oracle n'a aucun flux d'octets
pour un `lea` étroit** et ne peut pas en fournir un. L'abaisseur Nova refuse de la
même façon avant même que l'export soit atteint
(`compiler/nova/backend/x64/x64_lower_fixed.nova:449`, `destination[1]!=64` donne
`403`), ce qui signifie que **la forme n'est pas exprimable en NTASM** : aucune
source v0 ne peut l'écrire. Il n'y a donc **aucune fonctionnalité de langage à
spécifier** dans ce que l'export `encode_lea` accepte en plus, et c'est ce qui
tranche la question. **L'export doit être ramené à 64 bits**, comme les onze
autres, et non pas le document élargi pour couvrir une extension située sous le
langage et hors de portée de toute source. Raison structurelle, visible dans le
fichier : `encode_lea` est le seul export qui **fabriche son propre préfixe au
lieu d'appeler `emit_prefix_frame`**, et le seul qui accepte une largeur que
`x64.c:176` interdit. **Décidé et appliqué le 28 septembre 2026.** L'export refuse
maintenant toute destination qui n'est pas 64 bits au même endroit de l'ordre de
validation que l'oracle — `x64_fixed.nova:522` — de sorte qu'une largeur 8
répond encore `411`/`410` avant `403` et que seule une adresse bien formée
atteint le contrôle de largeur. La réimplémentation architecturale qui servait
de second avis a disparu, et **les lignes étroites de la gate confrontent
maintenant l'oracle comme les autres** : `x64_lea` rend `474` checks, `0`
failure, `157` cas, et le nombre de cas n'a pas baissé — ces lignes ont changé
d'autorité, elles n'ont pas été supprimées. La propriété transactionnelle
s'y applique désormais aussi, ce qu'elle ne faisait pas avant.

Chaque `return` est comparé au type déclaré. Le premier vérificateur prouve les
littéraux bornés, les paramètres/locals et les résultats de calls de type exact;
une expression plus complexe reste refusée tant que son inférence n’est pas
portée. `bool` n’accepte que `true`/`false` et les littéraux entiers respectent
la plage signée ou non signée de leur type.

Les initialiseurs littéraux de `data` et `let` suivent les mêmes règles de
catégorie et de plage scalaire. Le vérificateur Nova v0 contrôle directement
les entiers et `true`/`false`; une expression non littérale est explicitement
différée vers l’inférence d’expressions et n’est jamais considérée comme prouvée
par ce contrôle.

Pour un `let`, le profil initial prouve ensuite les initialiseurs qui sont un
paramètre/local visible ou un call local/importé de type retour exact. Toute
autre expression reste refusée jusqu’à ce que son inférence soit portée; aucune
conversion numérique, pointeur ou booléenne implicite n’est appliquée.
« Visible » veut dire la liaison du bloc le plus interne qui contient l’usage; les
collisions de nom qui rendraient cette lecture ambiguë sont refusées et le
masquage accepté change le type au même endroit. Voir §5.1.

Il prouve aussi une expression entière binaire d’un seul niveau pour les
opérateurs arithmétiques et bit à bit v0 lorsque chaque opérande est un nom, un
call ou un littéral borné du type déclaré exact. Les expressions imbriquées et
les conversions restent refusées; ce contrôle de type n’effectue pas de repli
vers l’évaluation hôte.

Un `const` scalaire du profil initial exige un littéral compatible et borné.
Les expressions de constante plus générales restent refusées jusqu’au portage
de leur évaluation compile-time; elles ne sont pas rabattues silencieusement
vers une valeur hôte.

L’encodage le plus court peut être sélectionné seulement entre encodages
sémantiquement identiques explicitement autorisés par le profil target. Le choix
est alors canonique et testé byte pour byte.

## 7. Pointeurs par espace

La forme normative d’un pointeur est `ptr<espace, T>`. L’espace fait partie du
type et survit dans NTIR jusqu’à ce qu’un abaissement vérifié le transforme en
adresse machine.

Espaces conceptuels initiaux :

- `user` : mémoire d’un processus utilisateur;
- `kernel` : mémoire virtuelle noyau;
- `physical` : adresse physique non directement déréférençable;
- `mmio` : fenêtre de périphérique, accès volatile et ordonné;
- `device` : mémoire visible d’un device sous une capacité précise;
- `firmware` : pointeurs valides seulement pendant la phase firmware.

Le target peut en ajouter par version. Il n’existe aucune conversion implicite
entre espaces, ni entre entier et pointeur. Une conversion exige un intrinsic
typé, un effet déclaré et une précondition/capacité prouvée. `ptr<physical, T>`
ne devient pas déréférençable sans mapping; `ptr<mmio, T>` n’accepte pas un load
ordinaire si le target exige un intrinsic MMIO.

Sur x86_64, `fs:` et `gs:` sont des décorateurs d’adressage target, pas des
espaces de pointeur. Le symbole et l’annotation `ptr<...>` déterminent toujours
l’espace sémantique. Une annotation de type après un opérande mémoire décrit le
type de l’adresse et de la valeur pointée, jamais un cast silencieux.

## 8. Effets, clobbers et contrats

### 8.1 `effects`

`effects` déclare une borne supérieure vérifiable des effets de la fonction. Le
vocabulaire est fermé et versionné. Le noyau initial comprend au minimum :

- `privileged`;
- `reads_mem` et `writes_mem`, raffinés par les espaces touchés dans NTIR;
- `changes_flags`;
- accès `mmio`, `io_port`, `msr` ou control register;
- changement d’état interrupt/CPU;
- transfert de contrôle sans retour.

Le vocabulaire exact du profil v0, déjà porté par la grammaire et le frontend de
référence, est le suivant :

- effets atomiques sans argument : `privileged`, `changes_flags`, `mmio`,
  `io_port`, `msr`, `control`, `interrupt_state`, `no_return`,
  `memory_ordering`, `reads_clock`, `suspends`;
- effets mémoire : `reads_mem` et `writes_mem`, soit sans argument pour couvrir
  tous les espaces v0, soit avec exactement un espace parmi `user`, `kernel`,
  `physical`, `mmio`, `device`, `firmware`.

Les noms d'effet et d'espace ne sont pas qualifiés. Un argument sur un effet
atomique, un nom inconnu ou un espace hors catalogue est une erreur. Un set
refuse deux occurrences sémantiquement identiques; deux effets mémoire de même
nom mais portant sur deux espaces distincts restent valides. Ces règles ferment
la forme déclarative et son encodage; la preuve qu'un corps et ses appels sont
couverts par cette borne supérieure appartient à la composition décrite
ci-dessous.

Tout effet réel doit être couvert. Un call compose les effets déclarés du callee.
Une macro, un intrinsic ou un stub généré ne peut masquer un effet. Les profils
NX/Cnuva/Nova continuent d’appliquer leurs propres capacités; passer par NTASM
n’accorde aucune autorisation supplémentaire au caller.

Au call, les effets atomiques du callee doivent être un sous-ensemble de ceux du
caller. Il en va séparément des espaces lus et écrits : chaque bit d'espace du
callee doit être déclaré par le caller. Un `reads_mem` ou `writes_mem` sans
espace couvre les six espaces v0; une forme bornée ne couvre que son espace.
Cette composition s'applique de la même façon aux fonctions locales et aux
alias d'import, ainsi qu'aux calls statements et expressions.

Dans le corps, `load` ajoute un effet de lecture sur l’espace du `ptr<espace,T>`
de son opérande mémoire et `store` ajoute l’effet d’écriture correspondant. Le
contrat de la fonction doit couvrir ce bit d’espace, directement ou par la forme
mémoire non bornée. Un espace de pointeur hors catalogue est refusé avant NTIR.

Les effets intrinsèques fixes suivent le catalogue de conformance x86_64 :
`rdtsc` exige `reads_clock`; les fences exigent `memory_ordering`; `ud2` exige
`no_return`; `cli`/`sti` exigent `privileged` et `interrupt_state`; `hlt` exige
`privileged` et `suspends`; `swapgs`, les control registers et les opérations de
descripteurs exigent `privileged` et `control`; MSR exige `privileged` et `msr`;
I/O port exige `privileged` et `io_port`. `syscall` exige `control` et
`changes_flags`; `sysretq` et `iretq` ajoutent `privileged`, `control`,
`changes_flags` et `no_return`, car ils restoran l'image RFLAGS en plus de
terminer le flux. `popfq` exige `privileged` et `changes_flags`; `pushfq` ne lit
que les flags et n'en exige aucun.
Les opérations arithmétiques, `cmp`/`test`, shifts/rotations, multiplications,
divisions et bit operations exigent également `changes_flags`; `mov` et `xchg`
ne l'exigent pas par leur seule exécution. La liste exhaustive des mnémoniques
et des effets exigés est figée au §17.4.

### 8.2 `clobbers`

`clobbers` est l’ensemble des registres et états machine dont la valeur d’entrée
n’est pas préservée au point de retour ou de transfert. Les écritures directes,
les appels et les intrinsics générés sont composés puis comparés à la déclaration.

Les modifications temporaires sont suivies séparément dans un **write footprint**
inféré par la HIR/NTIR. Elles n'appartiennent à `clobbers` que si la valeur
d'entrée n'est pas restaurée à la frontière. Ainsi, modifier temporairement
`rsp` puis restaurer exactement sa valeur ne déclare pas `rsp` comme clobber;
omettre cette écriture du write footprint interne reste impossible.

Les paramètres `out` et les résultats liés à un registre sont distingués des
clobbers, mais restent vérifiés par l’ABI. Omettre un clobber est une erreur;
ajouter un clobber non utilisé peut être signalé comme contrat trop large.

Dans le profil x86_64 v0, chaque entrée de `clobbers` est un nom de registre non
qualifié appartenant au catalogue target. Les alias (`rax`/`eax`, `r10`/`r10d`,
etc.) désignent la même famille physique et un set ne peut la déclarer deux fois.
Au call, le bitset des familles clobber du callee doit être un sous-ensemble de
celui du caller, pour les fonctions locales comme pour les alias d'import et les
calls expressions.

Un `load` écrit sa destination GPR : la famille physique de ce registre doit
donc figurer dans les clobbers de la fonction. Les alias désignent le même bit.
`store` ne clobber pas son registre source par cette seule opération.
Les footprints fixes sont figés au §17.4 : `rdtsc` et `rdmsr` détruisent
`rax`/`rdx`, `cpuid` détruit `rax`/`rcx`/`rdx`/`rbx`, `syscall` détruit
`rcx`/`r11` et `iretq` écrit `rsp`. Ces familles doivent également être incluses,
alias compris.
Les formes qui écrivent explicitement leur premier opérande GPR ajoutent sa
famille au footprint ; `xchg` ajoute les deux familles ; `cmp` et `test`
n'écrivent aucun opérande. La liste fermée de ces formes, qui inclut `load`,
`movzx`/`movsx`/`movsxd`, `not` et `bswap`, est figée au §17.4.

**Une famille est un clobber si et seulement si la nommer pose un bit dans le
masque de clobbers du caller — et toute règle sur un set doit donc être écrite
sur des BITS, jamais sur des numéros de famille.** L'oracle le dit trois fois et
jamais en numéros : `frontend.c:1866` refuse un nom qu'il ne connaît pas,
`frontend.c:1874` refuse un nom dont le bit est déjà posé, `frontend.c:1880` le
pose. **L'espace de familles n'est pas dense** : 0 à 15 sont les GPR, 16 est
`rip`, 17 `rflags`, 18 `gsbase`, 19 `fsbase`
(`frontend.c:767-774`; `frontend.h:95` tient toute la famille sur une ligne).
Donc « famille n vaut bit n-1 » est faux à partir de 16. Énoncer les règles en
numéros les rend justes **exactement tant que la numérotation est dense depuis
zéro** — ce qui est pourquoi elles sont toutes correctes sur les seize GPR et
tombent ensemble au premier nom qui n'en est pas un. D'où la forme retenue :
`register_widths.clobber_bit` (`register_widths.nova:238-249`) rend **le bit
lui-même** — `1<<(famille-1)` pour les seize GPR, `1<<17` pour `rflags`, les bits16/18/19 pour `rip`/`gsbase`/`fsbase`, `0` pour
les autres noms — et les deux règles de `clobbers.nova` s'écrivent dessus. Rendre le bit
plutôt que la famille rend le décalage **non inscriptible**, puisqu'il n'existe
pas de dix-septième famille dont il faudrait soustraire un. `family()` reste fermée
sur les seize GPR, ce qui est correct : c'est la question du **registre**, et elle
exige une largeur d'opérande et un emplacement dans l'encodeur.
**Mise à jour du 14 octobre 2026 : les trois déclarations sont prises en charge.**
`rip`, `gsbase` et `fsbase` portent respectivement les bits16,18et19, distincts
de `rflags` au bit17. Les passes de clobbers, la représentation MIR, les
contrats NXO et la composition des appels conservent ces identités. Les trois
programmes de `examples/ntasm-v0/a4-clobbers/` sont exécutés et leurs contrats
comparés au frontal C dans la porte `machine_producer_exec`.
La famille des opérandes GPR reste distincte : ces déclarations ne créent
ni nouvel opérande `rip` ni écriture matérielle FS/GS implicite.
**L'asymétrie à ne pas confondre, parce qu'elle empêche le rapprochement par
analogie avec les treize.** Une famille GPR déclarée **omet une restauration**;
`rflags` **supprime une sauvegarde**. Un corps qui déclare `rflags` réclame donc
quelque chose de moins cher qu'un corps qui déclare `rcx`, et les deux règles ne
doivent pas être énoncées comme si elles décrivaient le même mécanisme.

**Ce que `clobbers` ne dit PAS de la préservation, et pourquoi la question est
ouverte.** `clobbers` déclare ce qui est détruit, jamais ce qui doit survivre à
un appel : le document ne fixe **aucun** ensemble de registres callee-saved
pour `nx64-abi-v0`, et il n'en faut pas inventer un. L'oracle C **accepte**
aujourd'hui les seize familles GPR dans un `clobbers` sous `nx64-abi-v0`,
rbx, rbp et rsp compris : `frontend.c` ne lit `f->clobbers` qu'à deux endroits
(`frontend.c:2886-2891`, l'intersection avec les familles de sortie, et
`frontend.c:2904`, le masque nonvolatile du seul profil efi). Déclarer un
ensemble callee-saved serait donc un **changement de langage**, pas une
description, et il est écrit comme proposition au §17.5 avec son coût.
Ce qui existe déjà et qui est contraignant : sous `efi-x64-v0` seulement,
l'oracle **refuse** tout clobber nonvolatile en `403`
(`frontend.c:2895-2907`), et le backend cesse alors de restaurer la famille
déclarée (`codegen.c:899-907`).

### 8.3 `requires` et `ensures`

Les contrats utilisent des prédicats typés enregistrés, pas du texte arbitraire.
`requires` décrit les faits nécessaires à l’entrée; `ensures` les faits établis
au retour ou au transfert terminal. Exemples de familles de prédicats : feature
CPU disponible, pointeur canonique/non nul, stack dans un espace donné et alignée,
MSR initialisé, interruptions dans un état précis, mapping présent ou contexte de
retour utilisateur valide.

Le catalogue déclaratif exact du profil v0 est : `feature(x)`, `non_null(x)`,
`canonical(x)`, `stack_in(espace)`, `stack_aligned(n)`, `msr_initialized(x)`,
`interrupts_enabled()`, `interrupts_disabled()`, `mapping_present(x)` et
`valid_user_return(rip, rsp)`. Les noms de prédicat ne sont pas qualifiés. Les
arités sont donc respectivement1,1,1,1,1,1,0,0,1,2; tout autre nom ou nombre
d’arguments est une erreur avant preuve. Cette fermeture du catalogue et de la
forme AST ne signifie pas que chaque famille possède déjà ses règles de preuve :
une famille reconnue mais non implémentée reste refusée par le vérificateur de
faits plutôt que supposée vraie.

Au call, l’état symbolique du caller doit satisfaire `requires`; il est ensuite
mis à jour par `ensures`, les effets et les clobbers. v0 n’exige pas un prouveur
général : les prédicats acceptés et leurs règles de transfert forment un ensemble
fermé, déterministe et versionné. Un contrat inconnu ou non prouvé est une erreur.

Le vérificateur de calls applique aujourd'hui une règle de preuve à chacune des
dix familles du catalogue. Trois mécanismes suffisent et aucun ne suppose un
fait :

- `feature(x)` est établi par le masque target du module, jamais par le caller ;
- un fait du caller sur le sujet remappé : le sujet du callee doit être un
  paramètre `in` nommé, l'argument du call à cette position doit être un nom
  qui est un paramètre du caller, et le `requires` du caller doit porter le même
  prédicat sur ce nom exact, arité comprise. Un littéral ou une expression
  calculée ne prouve rien ;
- un fait du caller apparié par octets, pour `stack_in(espace)` et pour
  `interrupts_enabled()`/`interrupts_disabled()`.

Chaque famille portée par un fait du caller porte en plus un garde
d'invalidation, et ce garde est la **conjonction de deux moitiés indépendantes** :
ce que la déclaration du caller autorise, et ce que le corps du caller fait
réellement. La moitié déclarative se lit dans les `effects` et les `clobbers` du
caller : un caller qui ne déclare pas l'atome ou le clobber gardé ne peut pas
avoir déplacé l'état que son fait nomme. Un set absent ou illisible se lit
toujours comme « a pu le faire », jamais comme une passe.

La moitié de corps est un **filtre syntaxique sur un ensemble fermé de
mnémoniques**, pas un modèle de la machine. Il se compose depuis les instructions
de la déclaration du caller et pose les mêmes trois questions. La règle normative
est celle de l'oracle, énoncée d'abord ; l'écart entre l'oracle et ce que le
filtre lit aujourd'hui est énoncé ensuite, daté, et ne change pas la règle.

- **le set d'atomiques masqué** est complet, et c'est le seul des trois qui le
  soit. Les quatre atomes que les gardes interrogent — `privileged`, `msr`,
  `control`, `interrupt_state` — sont portés par exactement les vingt
  instructions que la table d'intrinsics leur attribue
  (`compiler/nova/analysis/abi/body_intrinsics.nova:8-32`), et la table de la moitié de
  corps en nomme les vingt (`call_contracts.nova:760-791`, `body_atoms`). Aucun atome masqué
  n'échappe à cette moitié, et c'est vérifiable par énumération ;
- **une écriture de `rsp`.** Règle : l'ensemble implicite complet est celui de
  l'oracle, et il vaut **huit**. `nt_x64_effects` range `push`, `pushfq`, `pop`,
  `popfq`, `ret`, `return` et `call` dans un seul membre et leur donne à tous la
  même écriture de `rsp` — `registers_written |= UINT64_C(1) << 4`, la famille 5
  du numérotage `register_widths.family`
  (`compiler/c/ntasm/backend/x64.c:942-944`) — puis donne à `push`, `pushfq` et
  `call` une **écriture de pile** distincte (`stack_write = 1`, `x64.c:945-946`)
  et à `pop`, `popfq`, `ret` et `return` une lecture de pile. Sept pour l'écriture
  de `rsp`, plus `iretq` qui la publie par une branche séparée et le rend
  symétrique en lecture (`x64.c:1037-1042`,
  `registers_read = registers_written = 1<<4`, `stack_read = 1`). Une forme qui
  écrit `rsp` par un opérande qui le nomme s'y ajoute, comme dans le §17.4.
  `sysretq` est le seul qui reste en dehors : l'oracle ne lui publie aucun
  registre écrit (`x64.c:1032-1036`, il ne lit que `rcx` et `r11`) et le §17.4
  dit donc qu'il n'écrit aucun GPR. Il reste en dehors de l'ensemble implicite,
  et ce n'est pas une sur-approximation de confort : le laisser dehors n'est pas
  un fail ouvert, parce que `x64.c:1035` fait de `sysretq` une instruction
  terminale, donc aucun call qui la suit dans le même corps n'est atteignable et
  il n'y a pas de site de call où prouver le fait à tort
  (`compiler/nova/analysis/calls/call_contracts.nova:614-621`). `return` est kept dans
  l'ensemble pour parité avec le membre de l'oracle, alors que le lexer en fait
  l'instruction `return` et non un opcode : c'est une sur-approximation réelle,
  de coût nul, et elle est écrite comme telle
  (`call_contracts.nova:611-612`). État de l'arbre : la moitié de corps lit les
  huit, exactement le membre de l'oracle plus `iretq`, ni plus ni moins
  (`call_contracts.nova:623-626`) ;
- **une écriture mémoire.** Règle : toute écriture que l'oracle publie compte, y
  compris une écriture de pile qui n'a pas d'opérande mémoire et que donc aucune
  table par opérande ne peut voir. L'oracle donne cette écriture de pile à `push`,
  `pushfq` et `call` (`x64.c:945-946`) ; le frontend de référence écrit le bit de
  `rsp` dans le footprint inféré de toute instruction qui le publie, sans
  exception pour ces trois-là, et le seul masque qu'il applique est celui de
  `call_indirect` (`compiler/c/ntasm/frontend/frontend.c:5506-5508`,
  `effective_writes = facts.registers_written`). Sa règle d'instruction est plus
  large encore : il refuse, au niveau de la forme, tout fait portant une lecture
  ou une écriture de pile, ou le bit 4 ou le bit 5 dans `registers_written`,
  faute de la preuve d'équilibre de frame qui n'existe pas encore
  (`frontend.c:5493-5498`). Cette dernière règle **n'est pas** celle de v0, et
  la spécification ne l'impose pas : elle explique pourquoi l'oracle est plus
  strict que le modèle, et un lot qui la porterait rétrécirait l'ensemble accepté
  sans nécessité. État de l'arbre : la moitié de corps a les deux moitiés qu'il
  faut — l'écriture de pile implicite, `push|pushfq|call`
  (`call_contracts.nova:768-771`), et les opérandes mémoire que l'oracle ancre à
  une écriture (`call_contracts.nova:810-823`) — et les deux ensemble, parce que
  lire seulement la seconde laisse passer un corps `push rax` : son opérande est
  un registre, donc il n'a pas d'opérande mémoire à voir
  (`call_contracts.nova:908-945`).

**La charge d'un call imbriqué est désormais bornée, et c'est une exception
datée, pas un oubli.** Un call statement imbriqué dans le corps du caller n'est
plus chargé d'office : il ne l'est que s'il n'est pas une paire de frame
équilibrée. Une paire est équilibrée quand le callee est une déclaration locale
au sens de ce module, qu'il n'est pas `never`, et que le corps de ce callee
n'écrit aucune mémoire — la même question posée une fois de moins
(`call_contracts.nova:921-934`, `balanced_call_pair`). Le refus est donc
explicitement rendu dans ces trois cas, et la marche est bornée par le
paramètre `depth`, dont la borne est le nombre de déclarations de l'arbre. C'est
la forme sûre : le rétrécissement ne peut que **décharger**, jamais charger, donc il ne
peut pas inventer une preuve.

Ce que ce rétrécissement **ne touche pas** est écrit ici pour qu'un lecteur ne
l'extrapole pas. La moitié de pile est intacte : un call imbriqué déplace
toujours `rsp`, donc `stack_in` et `valid_user_return` le refusent toujours. La
moitié `push` est intacte : un corps `push rax` nu refuse toujours
`mapping_present`. Seul le rappel d'un call sur la question mémoire a bougé, et
la formule de fermeture du paragraphe suivant tient donc toujours.

La formulation correcte n'est donc pas « la moitié de corps ne sous-estime
rien », mais : **la règle est celle de l'oracle, et le filtre doit être un
sur-ensemble d'elle.** Un filtre qui sous-estimerait irait dans le sens qui
invente une preuve, donc dans le sens dangereux : c'est le filtre qui doit
s'élargir, et non la règle qui doit se rétrécir. Un filtre qui **sur-estime** ne
coûte qu'un refus de plus et reste dans le sens sûr. C'est la seule asymétrie que
ce §8.3 admet, et elle vaut pour les trois questions. La moitié déclarative, qui
lit les `effects` et les `clobbers` du caller, est dans le sens sûr par
construction. **Une preuve rendue par ce vérificateur seul ne doit donc pas être
lue comme ce que l'oracle concéderait au sens strict**, et le §17.6 enregistre
les codes que les deux modes rendent pour ces cas.

La sur-estimation a une conséquence concrète et assumée : un caller qui empile et
dépile autour de son call n'a pas déplacé `rsp` au moment du call et reste
refusé, parce que décider cela demanderait le graphe de contrôle que ce
vérificateur ne construit pas.

Dans le pipeline, les cinq passes qui précèdent (`body_effects`,
`body_intrinsics`, `body_clobbers`, `call_effects`, `call_clobbers`, §17.7)
refusent de toute façon un caller dont le corps ment sur sa déclaration, avec le
code de la passe qui possède le mensonge : c'est une défense en profondeur, et ce
n'est pas ce qui rend la passe locale saine. Au point d'entrée nu, cette défense
n'existe pas, et c'est pourquoi la moitié de corps doit être correcte par elle-même
plutôt que par ce que les autres passes feront avant elle.

La moitié déclarative seule n'est pas saine, et c'est pourquoi les deux moitiés
existent : lue seule, `effects {} clobbers {}` satisfait tous les gardes, et un
caller dont le corps stockait, déplaçait `rsp` ou exécutait `cli` obtenait une
preuve fausse pour `stack_in`, `interrupts_enabled`, `interrupts_disabled`,
`msr_initialized`, `mapping_present` et `valid_user_return`. Les cinq passes
`body_effects`, `body_intrinsics`, `body_clobbers`, `call_effects` et
`call_clobbers` (§17.7) composent ces corps en premier. Cela ne vaut que dans le
pipeline : ces cinq passes compensent les deux moitiés sous-approximantes
ci-dessus, et ce n'est pas ce qui rend la passe locale saine, c'est ce qui l'est
quand elle est appelée seule. `stack_aligned(n)` conserve sa branche non gardée :
le même fait du caller, ou la garantie ABI, dont le plafond est fixé une seule
fois au §17.3.

Un prédicat reconnu mais couvert par aucune règle v0 reste refusé au lieu d'être
supposé vrai. Après les `requires`, le vérificateur exige que le caller
redéclare chaque `ensures` du callee, faute de quoi 365 est rapporté : une
postcondition abandonnée est signalée, jamais transférée en silence. Un appel à
un callee `never` ne produit aucun état de retour et n'exige donc aucune
couverture, sauf si le caller est lui-même `never`. Le tableau exhaustif des
dix règles est figé au §17.3.

Pour une fonction `never`, `ensures` décrit l’état au point de transfert, pas un
retour inexistant.

## 9. Exemple syntaxique autoritatif x86_64

Le snippet suivant est conservé **mot pour mot** comme référence de forme fournie
par le porteur du projet. Il est normatif pour la surface syntaxique montrée,
mais pas encore pour la sûreté ou l'ABI complète d'un retour syscall.

```ntasm
module kernel.syscalls
target x86_64-nexora-none

section .syscall {
    export fn syscall_entry(
        in number: u64 @rax,
        in arg0: u64 @rdi,
        in arg1: u64 @rsi
    ) -> never
    effects { privileged, reads_mem, writes_mem, changes_flags }
    clobbers { rax, rcx, r11 } {
        swapgs
        load rsp, [gs:kernel_rsp]:ptr<kernel, u64>
        align_stack 16
        call nx_syscall_dispatch
        sysretq
    }
}
```

Cet exemple fixe :

- `load`/`store` ont une largeur 64 bits inférée sans ambiguïté depuis le registre
  et le type pointé;
- l’annotation mémoire n’autorise aucun cast d’espace;
- `swapgs` et `sysretq` sont des intrinsics privilégiés x86_64, pas des
  mnémoniques génériques disponibles sur tout target;
- `align_stack 16` agit sur la pile noyau active, produit un fait d’alignement
  dans NTIR et doit être compatible avec l’ABI de `nx_syscall_dispatch`.

Il ne prouve pas encore que `sysretq` est sûr : la sauvegarde/restauration du
RSP/RCX/R11 utilisateur, le second `swapgs`, la canonicalité du RIP/RSP, le
masquage des flags dangereux et le contrat du dispatcher restent à définir dans
l'ABI syscall. Ce bloc ne doit donc pas être exécuté tel quel. Une future variante
durcie sera un exemple séparé et ne remplacera ce snippet qu'après décision
explicite du porteur du projet.

## 10. `align_stack` et intrinsics privilégiés

`align_stack N` est un intrinsic de **vérification**, pas une macro
textuelle. Il n’abausse rien : un corps qui en porte un est refusé avec `800`
par `x64_lower_nxo.nova`, et l’oracle C n’a aucun `align_stack`. Les deux
règles que l’oracle applique sont **distinctes** et §10 les confondait en une :

- **à la déclaration** (`frontend.c:5725-5731`, `stack_aligned`, fn
  verify_function_predicates) — `N` est une puissance de deux positive et
  `N <= 4096` ;
- **à un site d’appel** (`frontend.c:1398-1403`) — `N` est une puissance de deux
  positive, `N <= 16`, et `16 % N == 0`.

**Ces deux règles sont un seul prédicat à deux phases, et le dire est plus exact
que de les présenter comme deux endroits.** Le code ne porte qu’une branche
`stack_aligned` : (`frontend.c:5725-5733`, `stack_aligned`, fn
verify_function_predicates) prouve la puissance de deux et `N <= 4096`, puis la
ligne suivante ajoute `N <= 16` et `16 % N == 0` sous un drapeau `phase`. La
distinction « déclaration / site d’appel » est donc celle du
**drapeau**, pas celle de deux implémentations. *(Citations réécrites le
28 septembre 2026 : elles pointaient `5543-5550`, `5491-5496` et `5478-5484`,
qui ne désignaient plus ces sites depuis un décalage de `frontend.c` — voir la
ligne U17 du §17.9 pour pourquoi `registry` ne l’a pas vu.)*

*(Citations re-écrites le **30 septembre 2026**, et **pour la DEUXIÈME fois** :
elles désignaient `5558-5565`, décalé de neuf lignes parce qu'une réparation de
`compiler/c/ntasm/frontend/frontend.c` — le fail-open de `effects` sur un espace
inconnu, `frontend.c:1846`, qui rendait 0 sans poser `p->failed` — a inséré des
lignes AU-DESSOUS de ce site. **Une réparation qui ajoute des lignes invalide
silencieusement toute citation située en aval, et la porte `registry` l'a
signalée par `IDENT-MISSING` : `spec/ntasm/ntasm.md:815 cite frontend.c:5558-5565 and
names stack_aligned beside it, which is nowhere in that range`.*
**Donc le mécanisme est établi, et il n'est pas rare : la première
réécriture datait du 28 septembre et corrigeait `5543-5550`, `5491-5496` et
`5478-5484`. **Deux réécritures en deux jours pour la même phrase, chacune
provoquée par une insertion de lignes plus haut dans le fichier.**
Et une TROISIÈME correction, la mienne, dans la minute : j'ai d'abord écrit
`5570-5575`, qui est le bon DÉCALAGE et le mauvais ENCADREMENT — **la porte
exige que le NOM soit À L'INTÉRIEUR de la plage, pas que le code qu'elle nomme
commence dedans.** `stack_aligned` est en `:5567` et la preuve en `:5570-5575` ;
une plage qui commence à la preuve exclut le nom. **Donc « corriger » n'est pas
« décaler » : une citation `file:ligne-ligne` est un intervalle, et un
intervalle doit contenir l'identifiant ET son site.*)*

L’ensemble utilisable est donc exactement `{1, 2, 4, 8, 16}`. C’est
exactement ce que `control_flow.nova:886-887` accepte et exactement ce que
`call_contracts.nova:1071` implémente, et l’écart entre les deux règles est la
raison pour laquelle `364` porte **deux** raisons et non une. `align_stack` :

- exige un `rsp` typé comme pile dans l’espace courant;
- produit le fait `stack_aligned(N)`;
- invalide les offsets de pile antérieurs non suivis par le système de frame;
- doit être compensé avant tout retour normal, sauf si la fonction est `never`
  et remplace explicitement la pile avant son transfert terminal.

`N` doit aussi rester sous le plafond d’alignement de pile, qui est fixé une
seule fois au §17.3 et qu’aucune de ces cinq obligations ne redéclare. Les cinq
obligations ci-dessus sont décidées par `control_flow` et refusées en `364` avec
les raisons `1` à `5` du §17.6 ; le §10.1 dit précisément ce qu’une répétition
de `align_stack` change et ce qu’elle ne change pas, et quelles de ces
obligations restent indécidables sans modèle de frame.

Les intrinsics privilégiés forment un catalogue fermé par target. Le catalogue
x86_64 pourra inclure notamment `swapgs`, `sysretq`, `iretq`, lecture/écriture
MSR, control registers, tables de descripteurs, invalidation TLB et I/O port.
Chaque entrée déclare :

- types d’opérandes et de résultats;
- features CPU requises;
- niveau de privilège;
- effets et clobbers;
- préconditions et postconditions;
- séquence Machine IR/encodage canonique.

Un nom d’intrinsic inconnu, une feature non prouvée ou un contexte non privilégié
est refusé avant émission. Un target ne peut accepter silencieusement
l’instruction d’un autre target.

### 10.1 Ce qu'un `align_stack` répété change, et ce qu'il ne change pas

Un `align_stack` répété produit deux effets distincts, et un seul des deux est
redondant. Le modèle avait raison et la revendication de redondance avait tort,
et la spécification tranche dans ce sens.

- **Le fait d'alignement est bien idempotent au maximum.** Sur des puissances de
  deux, `align_down(align_down(x, N1), N2) == align_down(x, max(N1, N2))`, donc
  répéter `align_stack` ne peut ni affaiblir ni renforcer la garantie au-delà de
  la plus forte des deux. Cette identité est vraie et **elle ne règle que le
  fait** ; elle ne dit rien du déplacement, et une identité vraie sur une
  composante ne rend pas l'autre composante triviale. C'est un refrain, pas une
  démonstration ;
- **le déplacement en attente est réarmé à chaque exécution, et n'est pas
  redondant.** L'état de la passe tient le fait d'alignement et, séparément, un
  déplacement en attente avec son `N` (`control_flow.nova:773-775`,
  `state[1]` pour le fait, `state[2]=1` et `state[3]` pour le déplacement). Deux
  `align_stack` déplacent la pile **deux fois**, et seul le retour du pointeur
  d'entrée paie les deux ; l'obligation est donc une, et le `N` qu'elle nomme
  est le plus fort des deux demandés. Le refus `364` raison 4 tombe alors sur le
  `return` ou le transfert qui suit, même si le second `align_stack` est
  identique au premier ;
- **la conséquence que l'identité ne donne pas : le fait se reconstruit à son
  propre `N`, pas au premier.** Après une forme qui déplace `rsp` le fait est
  mort, et le second `align_stack` le rebâtit de rien. `align_stack 16 ; push rbx
  ; align_stack 4` tient donc 4, ce qui ne décharge aucun callee qui exige 16,
  alors que `align_stack 16 ; push rbx ; align_stack 16` tient 16 et le décharge.
  Les deux cas sont gardés ;
- **le `N` publié n'est pas une taille de déplacement.** `364` publie en `out[3]`
  le `N` le plus fort jamais demandé, jamais une somme et jamais une borne. Deux
  `align_stack 4` puis `align_stack 16` publient `16`, alors que le déplacement
  réel est au plus `3 + 15`. Aucune passe ne calcule de frame — le §17.5 le dit
  et le maintient — donc **ce document ne prétend à aucun compte d'octets**. Le
  verdict, lui, est juste : un déplacement en attente existe ou n'existe pas, et
  la compensation est ou n'est pas visible syntaxiquement.

Le module porte le même raisonnement et le dit dans les termes qui viennent d'être
repris (`compiler/nova/analysis/control_flow.nova:742-763`) ; la gate le vérifie
sur le cas le plus court
(`tests/c/nova/tests_ntasm_control_flow.c:740`, `align_twice_bare` :
deux `align_stack` puis un `return` nu, `364` raison 4).

Une conséquence mérite d'être écrite parce qu'elle est une limite et non un
détail : le refus est synchrone et ignore l'ordre des branches. Une compensation
faite dans une branche d'un `if` ne vide pas le déplacement en attente de
l'autre : la fusion est `stack_branches` (`control_flow.nova:809-848`) et son
bloc de fusion lui-même `:831-843`, où le chemin le plus faible décide
(`:836-838`). La gate le vérifie
(`tests_ntasm_control_flow.c:701`, `align_half`, `364` raison 4). Une paire
`push`/`pop` autour du `return` ne compense pas non plus, faute de modèle de
frame (`tests_ntasm_control_flow.c:791`, `align_push_pop`, `364` raison 4). Ce
sont des refus par conservation, pas des preuves.

## 11. Stubs structurés d’interruption et syscall

Les familles répétitives de stubs sont générées depuis des déclarations AST
typées. Une déclaration de vecteur/interruption/syscall doit fournir au minimum :

- identifiant et numéro ou classe;
- ABI d’entrée et de sortie;
- paramètres matériels implicites liés aux registres ou à la frame;
- présence d’un error code matériel;
- registres sauvegardés, clobbers et stack alignment;
- politique de `swapgs`, masquage d’interruptions et transfert terminal;
- handler cible et son contrat;
- section, visibilité et symboles à générer.

**Révisé le 27 septembre 2026 — la phrase « Le générateur produit des nœuds NTIR,
des symboles et relocations typés » est barrée sur place, et non laissée en place
et renvoyée au §17.8 : elle était fausse, pas incomplète, et une affirmation
fausse dans un texte normatif ne se répare pas par un renvoi que le lecteur qui
s'arrête ici ne voit pas. Révisé une seconde fois le 27 septembre 2026 : la
barrure ci-dessus est elle-même caduque.** `stub_table` **émet désormais une
image** : `build_pe`, `build_pe_and_write` et leurs variantes de témoin
encodent le plan de corps abstrait en x86-64, construisent un objet NXO fermé et
écrivent un PE dont le `.text` est octet pour octet celui que `codegen.c`
produit pour la même source, dans un fichier octet pour octet identique à celui
de `nova_oracle_make_pe`. Ce qui reste vrai de la phrase barrée : il n'écrit
toujours **aucun nœud NTIR** — il n'a pas d'interface vers la représentation
intermédiaire, alors que `ntir.nova` existe désormais dans l'arbre — et il
n'est appelé par **aucune passe du pipeline**. Ce qu'il livre réellement est
écrit au §17.8, et c'est là que se trouve la liste de ce qui reste à faire.
Les deux affirmations qui restent
vraies sont inchangées : la forme déclarative est lue depuis l'AST, jamais
reconstruite par concaténation de texte et jamais re-lexée, et les stubs d'une
table sont ordonnés par clé numérique canonique, doublons et trous interdits
étant diagnostiqués avant émission (`stub_table` 1445/1445, 707 cas ; **compteur
volatile**, voir la note de volatility sous le registre 17.6).

Une déclaration structurée ne dispense pas de goldens byte pour byte et de cas
négatifs pour frame, privilège, clobbers, alignement et retour.

## 12. Comptime borné

Le comptime v0 est un évaluateur déterministe sur valeurs et AST typés. Chaque
unité de build possède des limites explicites et vérifiées avant incrément :

- fuel d’instructions;
- profondeur d’appel;
- mémoire d’arène;
- nombre de nœuds AST produits;
- profondeur d’expansion;
- taille totale des données constantes.

Atteindre la limite est permis si l’opération est complète; `+1` est une erreur
stable. Une récursion n’est autorisée que si elle termine dans le fuel. Une
évaluation ne peut observer ni fichiers, réseau, environnement, horloge,
aléatoire, locale, processus, adresse hôte ou état mutable externe.

Les entrées autorisées sont les littéraux, paramètres comptime, métadonnées
target/ABI versionnées, types, AST du module et tables déclaratives incluses dans
le graphe de build. Même entrée + mêmes versions + mêmes limites doit produire
les mêmes nœuds et les mêmes diagnostics.

Les valeurs comptime ne donnent aucune capacité runtime. Elles ne peuvent créer
un pointeur privilégié, affirmer une feature CPU ou satisfaire un `requires`
sans règle de preuve enregistrée.

## 13. Macros AST hygiéniques

Une macro reçoit et retourne des nœuds AST typés; elle ne reçoit pas une chaîne à
réinjecter dans le parseur. L’hygiène applique une marque fraîche déterministe à
chaque symbole introduit. La capture d’un symbole du caller est interdite par
défaut et, si elle est ajoutée plus tard, devra employer une forme explicite et
auditable.

**Résiduel fermé le 28 septembre 2026, et le paragraphe précédent est retiré sur place.**
Il disait : un littéral materialisé depuis un paramètre VALUE de comptime est estampé par
`macro_expand.emit_constant` avec le jeton de l'invocation, `ntir.type_literal` classe un
littéral par son jeton, le pipeline accepte l'arbre et `ntir.build` refuse l'image en
`817` — d'où le fait que l'IR n'ait pas été câblé comme trente-cinquième passe du §17.7.
**C'était exact, et c'est faux depuis.** Le propriétaire est `macro_expand`, et le correctif
est là : un littéral materialisé porte maintenant un jeton **INTEGER** pris dans le flux de
jetons du caller, dans la plage depuis laquelle la constante a été pliée. La preuve est la
gate elle-même : les cinq fixtures qui portaient `817` rendent maintenant `ir=1`, et la
table a grandi de 39 à 50 lignes en couvrant huit formes du paramètre VALUE — `data`,
`const`, `let`, `return`, plus `hex`, `u8` et `i32`. **L'IR n'a pas été affaibli pour accommoder cela : c'est le producteur qui a été
corrigé** — et c'est la moitié la plus utile, parce qu'elle dit ce que le correctif
**n'était pas**. Il n'a pas été weakené en bas, ni contourné, ni rendu permissif.
`macro_expand` corrige `stamp_literal_token`
(`compiler/nova/macros/macro_expand.nova:561`, appelé à `:1424` et `:1430`) :
**la forme du correctif est la raison pour laquelle le littéral porte aujourd'hui le
genre que le materialiseur a décidé.** Un correctif indexé sur l'argument de
l'invocation est **structurellement incapable** de couvrir un `let` de comptime
à l'intérieur d'un corps de macro, dont la valeur est pliée : il n'y a pas
d'invocation à regarder. C'est pourquoi le littéral porte le **genre** choisi par le
materialiseur et non un genre reconstruit depuis un site d'appel.
**Aucune gate n'aurait pu voir ce défaut** — et c'est le fait le plus important de
la ligne. Le golden `ntir` n'a pas bougé, et le bandeau `macro_expand` non plus.
Ce n'est donc pas une régression détectable, c'était un **défaut invisible** : un
arbre accepté par le pipeline et refusé par l'IR, dans une zone où les deux
instruments de mesure existants étaient muets. C'est l'argument exact pour une
gate qui confronte les deux côtés sur la même question — et c'est ce que U13
demande pour la forme d'opérande.
*(Décompte, daté et rectifié deux fois : un décompte transmis disait « 3 sur 39 » sans dire
5 ; le mien disait 33 lignes de table ; la table en comptait 39, puis 50 après le
correctif. Les trois chiffres portaient sur trois états différents du même fichier. Aucun
n'est publié comme un fait permanent, et c'est le motif pour lequel la phrase ci-dessus
cite la gate plutôt qu'un décompte.)*


Les macros :

- utilisent le même évaluateur et les mêmes limites que comptime;
- n’effectuent aucun I/O;
- ne peuvent ni supprimer un effet/clobber réel ni fabriquer une preuve;
- sont développées avant vérification finale des types et contrats;
- conservent des spans de provenance macro → invocation → source;
- participent au hash de build avec leur AST, version et limites;
- ne peuvent émettre que des constructions permises par le target et le profil.

Une macro qui dépasse fuel, mémoire, nœuds ou profondeur échoue sans AST partiel
utilisable. L’ordre d’expansion est lexical et stable.

## 14. NTIR, Machine IR et convergence avec NX

NTIR, « Nexora Typed Instruction IR », est la représentation intermédiaire typée
proche machine commune aux chemins qui ont besoin de registres, effets, espaces
mémoire, contrats et intrinsics exacts. Ce n’est ni du texte NTASM ni un nouveau
backend. Machine IR porte ensuite les instructions sélectionnées, contraintes
d’encodage, blocs, symboles et relocations du target. La relation entre NTIR et
la NIR générale déjà prévue par l’architecture doit être figée dans leur schéma
versionné avant implémentation; aucun renommage implicite ne suffit.

```text
NTASM v0 → AST typé → HIR commune → NTIR ───────────────┐
                                                        ├→ Machine IR → encodeur commun
NX → AST/HIR commune → System IR → abaissement NTIR ────┘
```

NX n’a pas à générer du texte `.ntasm`; le frontend NTASM n’est pas réutilisé
comme parseur obligatoire du backend NX. La convergence se fait par structures
IR versionnées en mémoire ou dans un format Genesis canonique.

La HIR commune porte un noyau partagé et des nœuds spécifiques au profil; elle
ne rend pas les effets NTASM disponibles à NX. Réciproquement, NTASM ne
contourne pas la chaîne commune : résolution de
symboles, validation d’ABI, Machine IR, encodeur, writer NXO/PE et diagnostics
sont partagés lorsque leurs contrats sont identiques. Un intrinsic NTASM peut
abaisser directement vers NTIR/Machine IR sans équivalent textuel NX.

Les tests différentiels doivent prouver que des opérations sémantiquement
identiques issues de NX et NTASM donnent la même Machine IR pertinente et les
mêmes octets, symboles et relocations. Une différence autorisée doit être
motivée par un contrat ou une ABI explicite.

## 15. ABI, sections, symboles et relocations versionnés

Chaque artefact porte les versions exactes de ses contrats. Le writer refuse :

- ABI absente ou incompatible;
- section inconnue, permission W+X ou mapping non canonique;
- symbole dupliqué, import non typé ou export dont le contrat diffère;
- relocation non supportée par le target ou incompatible avec le type du site;
- valeur/addend hors plage ou ordre non canonique;
- champ réservé non nul, timestamp, chemin hôte ou overlay.

Une relocation est un record typé, pas un entier magique dans le frontend. Elle
nomme au minimum target, kind, largeur, section/site, symbole, addend et règle de
plage. Le backend choisit uniquement une relocation enregistrée par la version
du format. Les records sont triés par section, offset, kind et symbole selon un
ordre canonique documenté.

Les sections, symboles et relocations créés par macros ou générateurs de stubs
suivent exactement le même chemin de validation que ceux écrits directement.

## 16. Déterminisme, diagnostics et sécurité

- Aucune table de hachage à ordre observable dans une sortie.
- Aucun timestamp, identifiant aléatoire, adresse hôte ou chemin absolu.
- Arithmétique de tailles, offsets, alignements et addends checked.
- Aucun pointeur d’un espace plus privilégié obtenu par inférence implicite.
- Aucun intrinsic privilégié sans target, feature, effet et précondition.
- Aucune page ou section W+X; émission en mémoire RW puis scellement RX pour le
  JIT, jamais RWX.
- Premier diagnostic par span source canonique; codes et paramètres stables.
- Toute expansion/génération conserve sa provenance et son budget.
- Tout appel vérifie ABI, paramètres registre, stack, requires, ensures, effets
  et clobbers.
- Toute sortie binaire possède un inspecteur Genesis et des goldens indépendants
  du writer.

## 17. Critères avant implémentation de NTASM v0

Prérequis du gel v0, consolidés avec leurs preuves dans
`../docs/ntasm-a1-freeze.md` le 14 octobre 2026 :

1. grammaire lexicale/EBNF complète et récupération d’erreur;
2. catalogue v0 des types, espaces, registres, features et intrinsics;
3. logique fermée des prédicats `requires`/`ensures`;
4. règles exactes de composition des effets et clobbers;
5. ABI `nx64-abi-v0`, dont appels, frames, retours interruption/syscall;
6. schémas versionnés NTIR, Machine IR, sections, symboles et relocations;
7. syntaxe et plafonds numériques de comptime/macros;
8. déclarations structurées exactes des stubs;
9. corpus positif/négatif et goldens du gel courant vérifiés ; pour toute
   modification suivante du comportement v0, nouveaux attendus écrits avant
   la modification de l'implémentation (révision explicitement approuvée par
   l'utilisateur le 14 octobre 2026, sans affirmation rétroactive sur toute
   la chronologie initiale);
10. gates de promotion séparés de B1/B2 et preuve qu’aucune feature v0 n’est
    entrée dans le seed S0.

Tant que ces points ne sont pas gelés, `spec/ntasm/ntasm-s0.md` reste la seule
spécification exécutable du bootstrap et ce document ne change aucun attendu de
Gate B1.

**Il n'y a pas de sous-section 17.2.** La numérotation des sous-sections saute de `17.1` à
`17.3`, et aucun renumérotage n'est fait ici : les références `§17.3` à `§17.8`
sont citées dans ce document, dans `docs/status/ntasm-completion.md` et dans les
commentaires de plusieurs modules, et les déplacer casserait des renvois qui
pointent vers du vrai contenu. Le trou est donc signalé au lieu d'être comblé,
et il ne correspond à aucun critère manquant : les dix critères sont ceux de la
liste ci-dessus, numérotés `1` à `10`.

### 17.1 Frontière AST vers NXOV0001 (lot de contrat du 25 septembre 2026)

Le format objet actuellement défini est **NXOV0001**, décrit par
`spec/formats/nxo-v0.md`. Son en-tête version 1, ses trois sections `.text`, `.rdata`
et `.data`, ses symboles et ses deux types de relocation REL32 et DIR64 sont
des règles de ce format. Le nombre `0.1` du bloc source `versions` concerne
les six domaines déclarés (`ntir`, `machine_ir`, `sections`, `symbols`,
`relocations`, `nxo`) ; il ne remplace ni les octets de magie NXOV0001 ni la
version entière 1 de l'objet. Un producteur ou lecteur ne doit pas inférer
la compatibilité d'un objet à partir du seul bloc source.

La frontière de conversion prend un AST syntaxiquement valide et sémantiquement
vérifié, une cible et des features explicites, puis construit un objet NXO
soumis à la validation du writer. Le frontend ne fabrique pas de relocation
numérique arbitraire : le kind, la largeur et la formule proviennent de
`spec/formats/nxo-v0.md`. L'index du symbole cible et celui de l'entrée sont en base
1 ; zéro signifie « aucune entrée » pour ce dernier. Les offsets de sites
sont relatifs à leur section. Les symboles sont ordonnés par nom, et les
relocations par section puis offset, sans chevauchement. Un échec de
validation interdit l'émission de l'objet. Ces règles gardent les octets du
format existant et s'appliquent aussi aux sorties issues de macros ou stubs.

Les adaptateurs Nova actuels restent des sous-ensembles fermés et nommés :

- `x64_lower_nxo.build` conserve le témoin historique `.text` avec un symbole
  `main` fixe et aucune donnée ou relocation ;
- `build_scalar_data` accepte exactement une fonction `main` et au plus 64
  déclarations littérales `u8`, `u16`, `u32` ou `u64` dans `.rdata`/`.data` ;
- `build_import_call` accepte un import fonction sans paramètre et un `main`
  réduit à `call alias()` puis `ret`, avec une relocation REL32 ;
- `build_import_call_with_scalar_data` compose ce même appel importé avec les
  données scalaires précédentes ;
- `build_local_helper_call` accepte les deux fonctions fermées `helper` et
  `main`, dans l'un ou l'autre ordre source, avec une REL32 locale ;
- `build_local_helper_call_with_scalar_data` ajoute de 1 à 64 données
  scalaires à ce cas local ;
- `build_local_helper_calls` accepte de 1 à 64 appels consécutifs de `helper`
  depuis `main`, chacun avec son record REL32 trié, avant le `ret` final ;
- `build_local_helper_calls_with_scalar_data` compose ces 1 à 64 appels avec
  1 à 64 données scalaires sans second chemin de sérialisation.

Pour ces APIs, la cible NXO est dérivée de la cible AST ; les producteurs
destinés directement au PE sont bornés à UEFI, les autres indiquent
explicitement s'ils acceptent aussi bare. Les octets de données sont
little-endian et conservent l'ordre source dans leur section. Les symboles et
chaînes sont sérialisés dans l'ordre canonique, puis les index base 1 de
l'entrée et des cibles de relocation sont recalculés. Les sites REL32 sont
croissants, non chevauchants et contenus dans `.text`. Les fonctions et données
portent le contrat `v0`. Toute forme hors du sous-ensemble échoue avant
émission ; les entrées et sorties empruntées restent inchangées en erreur. Ces
règles ont été comparées octet par octet au writer et au reader C, elles ne
créent aucun nouveau format NXO.

`x64_lower_nxo_pe.build` relie l'objet import+données à un NXO de définition
par le linker existant, matérialise les relocations puis produit le PE. Les
APIs PE locales convertissent de la même façon le cas mono-appel, sa composition
avec données, le cas de 1 à 64 appels et leur composition avec données. Le
buffer NXO reste vivant jusqu'à la fin de la conversion car le reader expose
des vues de ses sections. Lors de la
fusion, chaque objet reçoit une base alignée à 16 octets pour chacune des trois
sections, même si sa section est vide ; le padding résultant fait partie de
l'objet fusionné observable. Cette règle correspond à l'oracle C et ne modifie
pas les alignements stockés dans NXOV0001.

Ces adaptateurs ne constituent toujours pas un abaissement AST général : noms
de fonctions arbitraires, paramètres, appels vers plusieurs cibles, références
de données, expressions constantes transportées jusqu'aux octets, fonctions
nombreuses et autres relocations restent ouverts. Les appels multiples prouvés
visent tous le seul symbole local `helper`. La capacité plus large du linker ou
du bootstrap C ne doit pas être attribuée aux adaptateurs. La limite de 255
octets du résultat ancien de `x64_lower_control.lower` est une contrainte de
cette API historique ; `lower_wide`, avec longueur `u64` séparée, la lève sans
modifier NXOV0001.

Le bloc source `versions` est actuellement optionnel dans le vérificateur
Nova ; lorsqu'il est présent, ses six domaines doivent apparaître une fois
chacun à `0.1`. Cette vérification ne prouve pas l'existence d'un schéma
NTIR ou Machine IR sérialisé. Les schémas versionnés de ces IR, leur relation
avec NIR, l'ABI complète `nx64-abi-v0` et l'abaissement AST général restent
ouverts au sens du critère 17.6. Ainsi A1 reste **partiel** et ne promeut
ni NTASM v0 ni B2.1.

### 17.3 Catalogue fermé des prédicats `requires`/`ensures` — gelé

Ce qui suit est figé parce qu'il est implémenté et gardé. Il ne ferme pas le
critère 17.3 au sens de A1 : un prouveur général reste hors de portée, et le
§8.3 continue de ruler ce qui n'est pas encore porté.

Le catalogue est fermé à dix prédicats, sans nom qualifié, dans l'ordre exact
suivant. La colonne « arité » est normative : un autre nombre d'arguments est
refusé avant toute preuve (324, avec attendu et obtenu en sortie). La colonne
« famille » est normative elle aussi, pour une raison distincte : c'est
l'ordinal que `326` publie en `out[2]`, donc une valeur observable, et il ne suit
pas l'ordre du catalogue. Les deux ordres sont figés et distincts ; les confondre
reste un bug, pas une lecture.

| prédicat | arité | famille | règle de preuve au call |
| --- | --- | --- | --- |
| `feature` | 1 | 1 | le masque target du module porte le bit de la capability nommée |
| `non_null` | 1 | 2 | remap du sujet : paramètre `in` du callee, puis argument du call, puis paramètre du caller portant le même fait |
| `canonical` | 1 | 3 | remap du sujet, à l'identique de `non_null` |
| `stack_in` | 1 | 6 | le caller porte le même fait dans le même espace du catalogue §7, et son corps ne déplace pas `rsp` |
| `stack_aligned` | 1 | 4 | le caller porte le même fait, ou la garantie ABI, dont le plafond est fixé au paragraphe suivant ; cette branche n'est pas gardée |
| `msr_initialized` | 1 | 9 | le caller porte le même fait, par remap si le sélecteur est un nom sinon par appariement d'octets, et ni son corps ni sa déclaration ne portent `msr` ni `privileged` |
| `interrupts_enabled` | 0 | 7 | le caller porte le même fait, et ni son corps ni sa déclaration ne portent `interrupt_state`, ni `control`, ni `privileged` |
| `interrupts_disabled` | 0 | 8 | le caller porte le même fait, et ni son corps ni sa déclaration ne portent `interrupt_state`, ni `control`, ni `privileged` |
| `mapping_present` | 1 | 10 | le caller porte le fait remappé, et n'écrit aucune mémoire |
| `valid_user_return` | 2 | 11 | les deux sujets sont remappés dans l'ordre du callee, et son corps ne déplace pas `rsp` |

La famille `5` n'appartient pas au catalogue : c'est la valeur de refus par
défaut du résolveur de famille pour un nom qu'aucune règle v0 ne couvre, et elle
se lit comme un refus fermé. Elle est inatteignable par le pipeline, parce que
`contracts.check` (§17.7, passe 25) a déjà refusé tout nom hors catalogue en `323`
avant que `call_contracts.check` (passe 34) ne résolve une famille. Elle reste
néanmoins le comportement du point d'entrée nu, qui doit être honnête seul.

**Le plafond d'alignement de pile est énoncé ici une seule fois.** Il vaut
**16** : la garantie ABI porte sur une puissance de deux `n` telle que
`0 < n ≤ 16`, et sur rien d'autre. `32` est une puissance de deux et n'est pas
couvert. Ce nombre n'est pas une convention locale et il n'est pas réécrit dans
le §8.3 ni dans le §10 : il a aujourd'hui deux porteurs, et non trois, l'un
nommé et l'autre non.

- `control_flow.abi_ceiling` est **l'unique définition nommée** du plafond dans
  l'arbre (`compiler/nova/analysis/control_flow.nova:202`), et elle est lue à ses
  deux emplacements : le refus `364` raison 2 d'un `align_stack` au-delà
  (`control_flow.nova:771`) et l'état initial d'entrée d'un corps qui porte un
  `align_stack`, `state[1]=abi_ceiling()` (`control_flow.nova:938`), la seule
  garantie de pile que cette passe s'accorde à elle-même. Les deux lectures
  passent par la fonction, donc un changement du plafond ne peut pas les
  désynchroniser ;
- `call_contracts` porte **sa propre copie** du nombre dans la branche ABI de la
  famille 4, `parg.aux>0 && parg.aux<=16 && (16%parg.aux)==0`
  (`compiler/nova/analysis/calls/call_contracts.nova:1045`), et il doit la porter :
  `control_flow` ne peut pas être importé par ce module. Les deux nombres ne
  sont donc liés par aucun nom partagé, et seulement par la gate du paragraphe
  suivant.

**La gate `control_flow` compare le plafond lui-même, des deux côtés, et échoue
dès que les deux réponses diffèrent.** Elle ne fait pas que comparer les deux
tables de footprint passe contre passe (§17.4). `ceiling`
(`tests/c/nova/tests_ntasm_control_flow.c:148-163`) pose **la
même question `N` aux deux modules** — un `align_stack N` que `control_flow`
doit accepter ou refuser en `364` raison 2 (`control_flow.nova:771`), et un
`requires {stack_aligned(N)}` que la branche ABI de la famille 4 doit créditer
ou non (`call_contracts.nova:1042-1049`) — puis exige que les deux verdicts
coïncident (`:161`) et nomme `N` et les deux codes rendus dans son message
d'échec. Sept valeurs sont exercées dans les deux sens
(`tests_ntasm_control_flow.c:543-549`) : `1`, `2`, `4`, `8` et `16` sont
acceptées par les deux modules, `32` et `64` sont refusées par les deux. Les
deux questions ne sont posables que par le mode du point d'entrée de test
(`tests/nova/tests/control-flow-entry.nova:88-91`) : le mode `3` publie
`control_flow.abi_ceiling()` seul, le mode `4` appelle `call_contracts.check`
seul, et la gate lit les deux dans la même itération. La définition est de plus
épinglée par sa **valeur** (`ceiling_value`,
`tests_ntasm_control_flow.c:164-171`, appelé à `:542` avec `16`), de sorte que
modifier `abi_ceiling` échoue ici même si la copie de `call_contracts` suivait
le même changement. Un lot qui changerait l'un des deux nombres sans l'autre
fait donc échouer `control_flow` : il ne peut pas passer toutes les gates. C'est
le code du harnais, et non ce paragraphe, qui le dit ; `control_flow.nova:193-200`
le formule du côté du module.


Précisions normatives :

- le sujet d'un prédicat unaire ou binaire doit être un nom nu ; un littéral,
  une expression ou un qualified est refusé ;
- un prédicat binaire exige que les deux sujets soient des paramètres `in` : un
  `out` ne consomme pas d'argument de call et n'a donc rien à remapper ;
- l'appariement d'un fait du caller porte sur le nom **et** sur l'arité, sinon
  `valid_user_return(p,q)` dans le caller satisfaireait `non_null(p)` dans le
  callee ;
- un nom hors catalogue donne 323 raison 1, un nom qualifié donne 323 raison 2,
  une arité fausse donne 324 ;
- un `requires` de callee non prouve donne 326, qui publie en `out[0..1]` la ligne
  et la colonne du prédicat, en `out[2]` la famille du tableau ci-dessus et en
  `out[3]` son ordinal dans le set du callee ; un `ensures` de callee non
  redéclaré par le caller donne 365, qui publie la même position, la raison 1 en
  `out[2]` et l'ordinal du prédicat en `out[3]`.

### 17.4 Règle de composition des effets et des clobbers — gelé

La règle est un **sous-ensemble**, pas une égalité et pas une intersection. Un
ensemble absent, un effect set illisible ou un nom hors catalogue font échouer
la vérification ; ils ne sont jamais lus comme une permission.

Au call, pour chaque fonction locale et chaque alias d'import, et pour les calls
statements comme pour les calls expressions :

1. les atomes d'effets du callee doivent être un sous-ensemble bit à bit des
   atomes du caller ;
2. les espaces lus par le callee doivent être un sous-ensemble des espaces lus
   par le caller ;
3. les espaces écrits par le callee doivent être un sous-ensemble des espaces
   écrits par le caller.

Un `reads_mem` ou `writes_mem` sans argument couvre les six espaces v0 ; une
forme bornée ne couvre que le sien. Un manque en catégorie atomes, lecture ou
écriture donne 325 avec le bitset manquant. La même inclusion, sur le bitset des
familles physiques de registres, donne 331 au call et 335 dans le corps.

Le vocabulaire d'effets est fermé à onze atomes sans argument, dans cet ordre,
qui est aussi leur rang de bit : `privileged`, `changes_flags`, `mmio`,
`io_port`, `msr`, `control`, `interrupt_state`, `no_return`, `memory_ordering`,
`reads_clock`, `suspends`. S'y ajoutent `reads_mem` et `writes_mem`, sans
argument ou avec exactement un espace parmi `user`, `kernel`, `physical`,
`mmio`, `device`, `firmware`. Un atome nommé qualifié, un argument sur un
atome, un espace hors catalogue ou un groupement malformé donne 321 ; un second
doublon sémantiquement identique dans un même set donne 322, tandis que deux
effets mémoire de même nom sur deux espaces distincts restent valides.

Les effets et footprints fixes des intrinsics, tels que l'oracle de conformance
x86_64 les rapporte, sont :

| intrinsic | effets atomiques exigés |
| --- | --- |
| `rdtsc` | `reads_clock` |
| `lfence` | `memory_ordering` |
| `sfence` | `memory_ordering` |
| `mfence` | `memory_ordering` |
| `ud2` | `no_return` |
| `cli` | `privileged`, `interrupt_state` |
| `sti` | `privileged`, `interrupt_state` |
| `hlt` | `privileged`, `suspends` |
| `swapgs` | `privileged`, `control` |
| `rdmsr` | `privileged`, `msr` |
| `wrmsr` | `privileged`, `msr` |
| `syscall` | `control`, `changes_flags` |
| `sysretq` | `privileged`, `control`, `changes_flags`, `no_return` |
| `iretq` | `privileged`, `control`, `changes_flags`, `no_return` |
| `read_cr` | `privileged`, `control` |
| `write_cr` | `privileged`, `control` |
| `sgdt` | `privileged`, `control` |
| `sidt` | `privileged`, `control` |
| `lgdt` | `privileged`, `control` |
| `lidt` | `privileged`, `control` |
| `ltr` | `privileged`, `control` |
| `invlpg` | `privileged`, `control` |
| `in` | `privileged`, `io_port` |
| `out` | `privileged`, `io_port` |
| `popfq` | `privileged`, `changes_flags` |

Un effet atomique exigé absent du set du propriétaire donne 334 avec le bitset
manquant. Les formes qui portent `changes_flags` par leur seule exécution sont
exactement celles de la ligne `changes_flags` :

| effet | instructions |
|---|---|
| `changes_flags` | `add`, `adc`, `sub`, `sbb`, `and`, `or`, `xor`, `cmp`, `test`, `inc`, `dec`, `neg`, `shl`, `shr`, `sar`, `rol`, `ror`, `imul`, `mul`, `div`, `idiv`, `bt`, `bts`, `btr`, `btc`, `bsf`, `bsr` |

`mov`, `movzx`, `movsx`, `movsxd`, `xchg`, `not`, `bswap`, `pushfq` et `ret` n'en
portent pas. Cette liste est un sous-ensemble du catalogue d'instructions, pas
sa définition.

Une entrée de `clobbers` est un nom de registre non qualifié du catalogue
x86_64, seize familles physiques ; les alias d'une même famille la désignent
identiquement et un set ne peut la déclarer deux fois (320). Un nom inconnu ou
qualifié donne 330. Dans le corps, `load` ajoute une lecture de l'espace de son
`ptr<espace,T>` et `store` une écriture, par son premier opérande mémoire ; un
opérande mémoire ultérieur d'un `store` est une lecture. Un espace de pointeur
hors catalogue donne 333. Les écritures de destination, alias compris, sont
exactement celles de la ligne `writes_first` :

| effet | instructions |
|---|---|
| `writes_first` | `mov`, `load`, `movzx`, `movsx`, `movsxd`, `lea`, `add`, `adc`, `sub`, `sbb`, `and`, `or`, `xor`, `inc`, `dec`, `neg`, `not`, `shl`, `shr`, `sar`, `rol`, `ror`, `imul`, `bswap`, `bts`, `btr`, `btc`, `bsf`, `bsr`, `xchg`, `read_cr`, `in` |

`xchg` ajoute en plus la famille de son second opérande. `cmp` et `test` n'ajoutent
rien, et une destination qui n'est pas un registre donne 336.

Le tableau suivant n'est pas un tableau d'intrinsics. C'est le tableau des
**footprints fixes** au sens large : les cinq premières lignes sont des
intrinsics, les sept dernières sont des formes ordinaires dont l'écriture de la
famille `rsp` est implicite. Les nommer « footprints fixes des intrinsics » était
faux, et l'est devenait plus faux encore le jour où deux formes ordinaires
étaient venues s'y ranger.

**Chaque ligne porte le site de l'oracle qui la fonde, parce qu'une ligne qui
dit « l'oracle publie cette écriture » sans la ligne où elle est publiée est une
ligne qu'un lecteur ne peut pas vérifier.** La colonne `registres écrits` est
**mesurée**, jamais recopiée : ce sont les `registers_written` bruts, non masqués,
qu'un `nt_x64_effects` compilé à froid rend. Le bit 17 est `rflags`, hors des
seize familles que `register_widths.family` numérote, et il est laissé visible
plutôt que masqué — voir la correction de date sous le tableau.

**Les quatre règles d'écriture d'une citation, et elles sont des règles et non
une réparation.** Elles sont énoncées ici, devant ce tableau, parce que c'est
ici qu'un lecteur en ajoute une. **Le résolveur apparie chaque identifiant
écrit en chevrons sur une ligne à chaque site de la forme `fichier:ligne` de
cette même ligne** : une ligne qui porte trois fichiers et un symbole fait
trois assertions, et le résolveur en lit trois. Aucune des quatre n'est une
contrainte de l'instrument ; ce sont les quatre conditions sous lesquelles une
ligne porte une seule assertion.

1. **Un fichier par paragraphe.** Un paragraphe qui cite deux fichiers et qui
   abrège ensuite ne dit plus à quel fichier son abréviation appartient. Le
   résolveur ancre sur le dernier fichier nommé ; le lecteur ancre sur celui
   qu'il a en tête. Ce n'est pas le même, et le second n'est pas vérifiable.
2. **Aucun nom de fichier dans du matériel cité.** Un nom de fichier entre
   guillemets est une citation que l'instrument résout exactement comme une
   citation de l'auteur. Une phrase qui rapporte un commentaire source ne peut
   donc pas nommer le fichier que ce commentaire nomme.
3. **Aucun renvoi ordinal.** « le premier », « le second », « celui du
   dessus » désignent un ordre de lecture et non une adresse. Le résolveur
   pointe le dernier ; l'ordinal désigne le premier. Les deux sont légitimes et
   ils ne sont pas le même fichier.
4. **Aucune abréviation dans une cellule de tableau.** Une cellule est une
   assertion, et **une ligne de tableau ne se coupe pas sur plusieurs lignes
   physiques** : une cellule ne peut donc pas porter une ligne par assertion.
   C'est la contrainte de forme qui décide de la forme, et non l'inverse.

**Les deux règles qui paient, et il faut le dire parce qu'un lecteur choisira.**
Les règles 2 et 3 sont celles qui aujourd'hui produisent des **faux positifs**,
c'est-à-dire des rouges sur un document dont la citation est juste : la règle 2
quand le nom de fichier est dans une citation rapportée, la règle 3 quand un
ordinal vise le premier de deux fichiers nommés et que le résolveur vise le
second. **La règle 4 n'a rien empêché par elle-même** : elle ne se manifeste
que lorsqu'une cellule nomme un symbole à côté de plusieurs sites, et c'est
alors la règle 1 qui rendrait la même phrase inoffensive en prose. **Une
phrase qui viole la règle 4 est donc, presque toujours, une phrase qui en
viole aussi une autre** — et c'est la règle 1, la moins coûteuse des quatre,
qui la supprime.

**Et la réparation a un coût de détection, et c'est la moitié de la règle 4
qu'il ne faut pas perdre.** Réduire une cellule à une assertion **retire au
contrôle l'appariement même qu'il utilisait** : une citation écrite entre
parenthèses toutes seules — `(fichier:ligne)` — constitue un groupe qui ne
contient aucun identifiant, donc il n'y a plus rien à apparier et plus rien à
détecter. **Le même geste qui supprime un faux positif supprime, dans la même
cellule, la classe de citations fausses que le contrôle y vérifiait.** Ce n'est
pas une hypothèse : la réduction des cellules `U4` et `U38` a fait passer
l'appariement de dix vérifications à aucune — les dix `IDENT-MISSING` de ce
document, qui portaient sur **cinq** sites distincts — et **les deux citations
fausses que portait la cellule `U38` sont de cette classe** : elles sont
énoncées en prose sous le tableau du §17.9, avec leurs sites justes.

**La règle qui en découle, et elle vaut pour tout contrôle qu'on rétrécit :**
**quand on réduit la surface qu'un instrument examine, on écrit le trou dans le
document au moment où on fait la réduction.** Sinon le prochain lecteur lit le
vert comme une couverture alors que c'est une question plus étroite — **un
instrument qui devient moins bruyant en regardant moins n'a pas été réparé, il a
été rendu muet, et la différence se voit au compteur et pas au journal.** Le
vert et le trou sont tous deux des faits, et il faut les écrire tous les deux.

**La cinquième règle, celle qui est la huitième classe, et elle est la seule
dont l'absence coûte aux cent prochaines rétractions.** **Une retraction qui
quote le mauvais numéro, sous la forme que les instruments lisent, EST une
citation.** Corriger sept citations fausses en reproduisant les sept nombres
faux sous la forme `fichier:ligne` produit sept citations fausses que chaque
instrument relèvera à chaque passage, pour toujours. Le second costume est le
même défaut : **le nom de sortie d'un instrument, cité en prose pour que le
prochain lecteur le retrouve, est lu par l'instrument comme une citation
d'identifiant et échoue dessus.** Un nom de compteur est un mot comme un autre
pour l'appariement.

**La règle opérationnelle, et elle est courte : quand on nomme quelque chose
pour un lecteur, on ne le quote pas dans la forme que l'instrument lit. Une
phrase qui explique un échec ne doit pas être elle-même un échec.** Un numéro
cité comme faux s'écrit **en prose, sans la forme `:`** — il reste lisible et
vérifiable par un humain, et il cesse d'être une assertion que l'instrument
doit résoudre. C'est ce que fait le §17.5.2, et c'est ce que refuse de faire
une relecture qui « corrige » un rouge en remplaçant un nombre par un autre
nombre.


**Et la sixième, qui est la règle de provenance, et c'est celle qui décide si
les cinq ci-dessus valent quelque chose dans six semaines.** **Une affirmation
et l'artefact qui permettrait de la vérifier sont la même chose, et ils doivent
avoir la même durée de vie.** Un nombre écrit dans un rapport et dont la
reproduction dépend d'un journal qui n'existe plus est une affirmation, pas une
mesure — **et il doit le dire dans la phrase qui le porte**, parce qu'un lecteur
qui ne le voit pas le relit comme un fait. La forme est courte : *recompter à
partir d'un artefact qui existe* est une mesure ; *recompter à partir de ce que
j'ai lu* est un rapport, et le mot juste pour le second est « j'ai recompté à
partir des lignes capturées », jamais « j'ai mesuré ».

**Le corollaire qui coûte le plus cher, parce qu'il est invisible : un artefact
dans un répertoire que rien n'indexe vaut un artefact supprimé.** Ce document
est écrit dans une prose qui survit parce qu'elle vit sous
`out/c-bootstrap/nova/evidence/`, qui est indexé ; **les journaux qu'elle
résume, eux, atterrissent dans un répertoire temporaire que le système
reclaim**. C'est une inversion : **la conclusion est conservée et la chose qui
permettrait de la vérifier est jetée.** Un répertoire de course choisi à la main
plutôt que dérivé a le même défaut, en plus sourd : personne ne sait où le
chercher plus tard. **La règle est donc : mettre la chose là où on la cherche,
ou écrire où elle est dans l'endroit que l'on consulte** — et un chemin écrit
sans la forme `:` de la citation, comme le fait la ligne `U26` pour les
scripts hors de la portée du résolveur, parce qu'un chemin que l'instrument ne
peut pas résoudre ne doit pas être écrit comme s'il le pouvait.


| line | formes | familles physiques | `registers_written` mesuré | site de l'oracle |
| --- | --- | --- | --- | --- |
| `rdtsc` | `rdtsc` | `rax`, `rdx` | `0x05` | `x64.c:1004-1006` |
| `cpuid` | `cpuid` | `rax`, `rcx`, `rdx`, `rbx` | `0x0f` | `x64.c:1001-1003` |
| `rdmsr` | `rdmsr` | `rax`, `rdx` | `0x05` | `x64.c:1020-1024` |
| `syscall` | `syscall` | `rcx`, `r11` **et `rflags`** | `0x20802` | `x64.c:1027-1031` + `:1071-1072` |
| `iretq` | `iretq` | `rsp` **et `rflags`** | `0x20010` | `x64.c:1037-1042` + `:1071-1072` |
| `push` | `push` | `rsp` ; l'opérande est **lu**, jamais écrit | `0x0010` sur `push rbx` | `x64.c:942-944`, `:949-950` |
| `pop` | `pop` | `rsp` **plus** la famille de l'opérande lorsqu'il nomme un registre | `0x0010`, `0x0018` sur `pop rbx` | `x64.c:942-944`, `:951-952` |
| `pushfq` | `pushfq` | `rsp` — et rien d'autre | `0x0010` | `x64.c:942-944`, `:953-954` |
| `popfq` | `popfq` | `rsp` **et `rflags`** ; mesuré `0x20010`, **pas** `1<<4` | `0x20010` | `x64.c:942-944`, `:955-956` + `:1071-1072` |
| `ret` | `ret` | `rsp` — et rien d'autre | `0x0010` | `x64.c:942-944`, `:959-960` |
| `return` | `return` | `rsp` — **site de déclaration distinct**, voir ci-dessous | `0x0010` | `x64.c:942-944`, `:959-960` |
| `call` | `call` | `rsp` — **site de déclaration distinct**, voir ci-dessous | `0x0010` sur `FR1(rel)` et `FR1(reg)` | `x64.c:942-944`, `:957-958` |

**Deux corrections de date, et la seconde est une ligne que ce tableau
sacrifiait.** (a) Le bit 17 vient de la **queue** de `nt_x64_effects`
(`x64.c:1069-1074`), qui l'OR dans `registers_written` pour toute forme qui écrit
des drapeaux — et la version précédente de ce paragraphe citait `x64.c:1070-1071`,
la ligne du test sur `registers_read` et non celle de l'OR : la citation était
décalée d'un cran et ne nommait pas l'instruction. (b) **`iretq` publie
`0x20010` et non `1<<4`** : `x64.c:1041` lui pose `flags_written =
NT_X64_FLAGS_ARITH`, donc la queue lui rend le bit 17 aussi. La ligne
`iretq` portait `rsp` seul et **était fausse de la même façon que la
ligne `popfq`**, une octave plus bas et sans le dire. Les deux sont corrigées
ici, et `syscall` est dans le même cas (`0x20802`).

**Les cinq formes que ce tableau omettait, et ce qu'elles valent une fois
mesurées.** `pushfq` `0x0010`, `popfq` `0x20010`, `ret` `0x0010`, `return`
`0x0010`, `call` `0x0010` sur les deux formes `FR1` — et `iretq` `0x20010`,
`syscall` `0x20802`, ce qui n'apparaît nulle part ailleurs dans ce document.
`popfq` est le seul des sept du membre à écrire des drapeaux **par lui-même**
(`x64.c:955-956`) ; `pushfq` prend son bit 17 par l'autre chemin, une lecture de
`rflags` posée dans le membre même (`x64.c:953-954`), et ne l'écrit jamais.
**C'est pour cela que la réserve n'était pas seulement incomplète : une gate
écrite d'après sa figure aurait épinglé `1<<4` pour `popfq` et serait restée
verte.** L'instrument qui l'aurait laissée verte est nommé plus bas, avec la
mesure qui le rend visible.

**`return` et `call` ne peuvent pas rejoindre les trois autres, et ce n'est pas
une question de table.** `return` est le kind 29 et `call` le kind 28
(`compiler/nova/frontend/parser.nova:362-368` et `:370-374`) : **aucun corps ne les
détient jamais comme l'instruction kind-32 sur laquelle une table indexée par nom
peut se fonder.** C'est un fait de l'AST, pas du tableau, et la sonde de mode 5
exerce déjà ce site.

**Les négatifs, parce qu'un tableau de footprints sans négatifs n'est un tableau
que personne n'a confronté à ce qu'il exclut.** Dans le même voisinage,
`sysretq` publie `0x20000` et **n'écrit aucun GPR** (`x64.c:1032-1036`), et cinq
formes sont refusées par l'oracle : `call` `FR0` (`402`), `call` `FR1(imm)` (`409`),
`ret` `FR1(reg)` (`402`), `ret` `FR1(imm)` (`402`), `pushfq` `FR1(reg)` (`402`).

**Ce que la réserve affirmait, et ce qui en est resté — la réserve, la
contradiction, puis la mesure.** Elle disait qu'aucune des deux passes v0 ne lit
cette liste. C'était faux, et une vague l'a fait disparaître des modules avant
que ce paragraphe ne soit réécrit : `body_clobbers.fixed_mask` porte **une seule
rangée qui couvre le membre entier** —
`let d:buf<u8>="push|pushfq|pop|popfq|ret|return|call|iretq"` (`body_clobbers.nova:447`),
et `control_flow.footprint` rend la shape 5 pour `pushfq`, `popfq` et `ret`
(`control_flow.nova:309-311`), donc `writes_stack` répond **vrai** pour les trois
(`control_flow.nova:324-344`). Elle disait ensuite que le footprint ne pouvait pas
exprimer une écriture de pile parce qu'il se calcule depuis la liste d'opérandes :
**l'oracle publie `1<<4` pour `pushfq`, `popfq`, `ret` et `return` par-dessus une
liste d'opérandes vide** (mesuré, ci-dessus), donc la table est indexée sur le
*nom* du mnémonique et l'extension était légitime.

**Trois phrases de ce §17.4 sont donc retirées sur place, et elles sont
copiées ici pour qu'on ne les réintroduise pas.** (i) « Ce tableau est incomplet,
et l'oracle dit comment le compléter » — le tableau porte maintenant les douze
lignes ci-dessus et il est exhaustif. (ii) « `body_clobbers.fixed_mask` ne charge
que `push`, `pop` et `iretq` et garde le zéro pour les cinq autres », et sa
justification « la sonde de parité l'interdisait aujourd'hui » — la rangée
`fixed_mask` charge les sept, et la sonde de parité est verte. (iii) « aucune des
deux passes v0 ne lit l'écriture de `rsp` de `pushfq`, `popfq`, `ret`, `return` ou
`call` pour la question du footprint » — c'est l'affirmation que la mesure
ci-dessous réfute, et c'est la seule des trois qui avait un coût de programme.

**Dans quel sens l'omission errait : mesuré, et c'est le sens interdit.** Ce
n'est pas une opinion, c'est une perturbation : **une copie** de
`body_clobbers.nova` dont la rangée `fixed_mask` est ramenée aux trois formes que
le tableau gelé nommait —
`let d:buf<u8>="push|pop|iretq"` — et le **même** harnais
(`tests_ntasm_body_clobbers.c`, `memberC` balayant le membre entier) posé sur la
copie et sur le module réel. L'arbre n'est pas touché. Sur la copie :

```text
ORACLE-DIVERGENCE form=pushfq oracle_registers_written=0x0010 nova_charges=0x0000
ORACLE-DIVERGENCE form=popfq  oracle_registers_written=0x0010 nova_charges=0x0000
ORACLE-DIVERGENCE form=ret    oracle_registers_written=0x0010 nova_charges=0x0000
FAIL parity body_clobbers/pushfq: THIS CALL accepted, the pipeline refuses with 335,
  and 335 is the verdict of stage 22 (body_clobbers(22)), a stage THIS CALL runs
NTASM_NOVA_BODY_CLOBBERS checks=1043 failures=5 cases=260 oracle_divergences=3
```

et sur le module réel, le même binaire de harnais, le même jour :
`NTASM_NOVA_BODY_CLOBBERS checks=1055 failures=0 cases=263 oracle_divergences=0`.
**La lecture est donc une sous-approximation, et pas une sur-approximation de
confort : un corps dont le seul écrivain de la famille `rsp` est `pushfq`,
`popfq` ou `ret` est accepté avec `clobbers {}`, alors que la référence le
refuse en `335`.** C'est exactement la direction que le §8.3 interdit, parce
qu'elle invente une preuve ; et la sonde de parité est ici le **contrôle
positif** de cette négatif, parce qu'elle ne compare pas la copie à une table
mais à la chaîne complète : elle dit que le pipeline refuse et que ce refus
viendrait du stage que la copie fait tourner. Une sur-approximation n'aurait
produit que des refus en trop, jamais un corps que la référence refuse et que le
produit accepte.

**Ce qui reste sous-approximé aujourd'hui, et c'est un reliquat nommé, pas
l'omission.** `return` et `call` sont **publiés et non chargés** : le bras
d'instruction de `body_clobbers` les lit sur les kinds 29 et 28
(`body_clobbers.nova:766-796`) et décide de ne rien charger, parce que le §8.2
ne fait d'une écriture une obligation de `clobbers` que si la valeur d'entrée
n'est pas restaurée à la frontière, et que ces deux instructions sont
précisément la paire qui la restaure. La gate l'asserte dans les deux sens et
imprime l'écart en nombre plutôt que de l'énoncer :

```text
MEMBER-STATEMENT form=return oracle_registers_written=0x0010 nova_charges=0x0000
  agree=1 reason=abi-restores-rsp-at-the-boundary
MEMBER-STATEMENT form=call   oracle_registers_written=0x0010 nova_charges=0x0000
  agree=1 reason=abi-restores-rsp-at-the-boundary
```

`0x0000` contre `0x0010` est une sous-approximation **assumée, motivée et
gardée**, et elle ne disparaît pas en chargeant `1<<4`. **La phrase que je
portais ici — « la charger donnerait `335` sur **tout** corps du langage, un
`return` étant le dernier statement de chacun d'eux » — est FAUSSE et est
retirée le 29 septembre 2026.** Elle a été mesurée depuis, sur une matrice de
cinq niveaux construite en **copies** du module et jamais sur l'arbre : le
refus `335` tombe sur `109` corps sur `182` au niveau « chaque `return` et
chaque `call` charge `1<<4` », sur `85` au niveau « la charge est sortie de la
liste des statements », sur `42` si seul un `return` non terminal charge, sur
`47` si seul le `return` d'une fonction appelée charge, et sur `27` au niveau
« seul `call` charge ». **La charge est payable** : un corpus dont les `129`
corps portant un `clobbers` ont été réécrits pour déclarer `rsp` donne le même
résultat aux six niveaux, `116` acceptés et `5` refusés `335` — donc le niveau
de la charge ne change rien à ce qui est payable, et `push rbx` avec
`clobbers {}` reste refusé `335` à tous les niveaux, ce qui est le contrôle
positif. **Le vrai coût n'est donc pas un compte de refus, et ce n'est pas non plus l'entrée obligatoire dans le set du corps : c'est un point fixe sur le graphe d'appels.** `call_clobbers` compare le callee au caller et jamais l'inverse (`call_clobbers.nova:96`), donc un callee qui déclare `rsp` refuse son propre caller en `331` tant que celui-ci ne le déclare pas, et l'obligation remonte à tout ancêtre, à toute profondeur — mesuré sur trois rangs, le refus est au sommet et non au premier saut (`leaf{rsp}, main{}` → 331 ; `leaf{rsp}, mid{rsp}, main{}` → 331 **au sommet** ; les trois déclarent → accepté). Les 96 corps sur 182 comptent ce que la déclaration coûte au **corps** ; ils n'expriment pas ce qu'elle coûte au **programme**, et un compte de corps ne peut pas l'exprimer. **La déclaration est aujourd'hui ACCEPTÉE et jamais vérifiée** : `clobbers {rsp}` passe sur un corps dont le seul écrivain de pile est son propre `return`. Le statut est donc *non vérifié*, pas *interdit* — personne n'a construit le canal
deviendrait une entrée obligatoire de tout ensemble `clobbers`**, et le §8.2
dit que cette déclaration serait fausse, puisque l'ABI restaure la valeur de
`rsp` à la frontière. C'est une contrainte meilleure que celle que la phrase
retirée énonçait, et c'est celle que le §8.3 doit retenir.

**Le conflit est nommé ici, parce que deux règles de ce document ne peuvent pas
tenir ensemble et qu'aucune des deux n'est fausse.** Le §8.2 est la règle
définitionnelle : une écriture n'appartient à `clobbers` que si la valeur d'entrée
n'est pas restaurée à la frontière, et il donne `rsp` expressément comme exemple de
ce qui ne se déclare pas. Le §8.3 autorise la sur-approximation et n'interdit que la
sous-approximation. Payer la charge `1<<4` impose donc de déclarer `rsp` sur un
corps dont l'ABI restaure la valeur : **une règle exige la déclaration, l'autre la
déclare fausse.**

**Ce document préfère aujourd'hui le §8.2, et il vaut mieux écrire pourquoi que
le laisser implicite.** Le §8.2 est la règle définitionnelle, et le coût du §8.3
était jusqu'ici une phrase que personne n'avait mesurée ; il est désormais un
chiffre, et ce chiffre ne dit pas ce que la phrase disait. **Tant que ce conflit
n'est pas tranché délibérément, la ligne `return`/`call` du §17.4 est un arbitrage
et non une conclusion**, et la charge reste à `0x0000` parce que c'est la seule des
deux branches qui ne demande pas au programmeur de déclarer un faux. **La formulation précédente laissait croire que déclarer `rsp` était *interdit* ; la mesure montre qu'il est *accepté et jamais vérifié*.** Ces deux mots ne désignent pas le même travail : l'un est une décision de langage, l'autre est un canal non construit, et la différence est celle entre « le langage le refuse » et « personne ne l'a écrit ».

**Le bit `rflags` n'est plus un trou, et la phrase qui le disait est fausse
depuis le 29 septembre 2026.** `popfq` publie `0x20010` et `body_clobbers` ne
charge que `1<<4` ; les deux passes qui balayent le membre ne peuvent pas voir
le bit 17, parce que leur comparaison **masque avec `0xffff`** — `orx`
(`tests_ntasm_body_clobbers.c:114`) rend `e.registers_written & 0xffff` avant
toute comparaison, et `A4_GPR` (`tests_ntasm_control_flow.c:206`) fait le même
tranchement en séparant `gpr=` de `non_family_bits=`. **Mais le bit 17 n'est pas
un dix-septième registre : c'est le canal des drapeaux publié deux fois**,
puisque `x64.c:1071-1073` pose le bit et `NT_X64_EFFECT_CHANGES_FLAGS` dans la
même instruction. Le produit le porte donc comme l'atome `changes_flags`, et
une gate le garde : le balayage `A4-FLAGS` de
`tests/c/nova/tests_ntasm_body_intrinsics.c` — enregistré dans
`GATES` — demande à `nt_x64_effects` et à `body_intrinsics` la même question
pour chaque branche de la chaîne d'effets, et refuse toute forme que l'oracle
marque aux drapeaux et que le produit n'exige pas. **La phrase « le bit
`rflags` n'est établi par aucune gate de ce dépôt » est donc retirée sur place ;
elle était vraie le jour où elle a été écrite et fausse aujourd'hui.**
**Le trou qui reste n'est pas le bit 17 : ce sont les bits 18 `GSBASE` et 19
`FSBASE`.** Aucun atome d'effet ne les nomme, et `swapgs` publie
`registers_written` `0x40000` sans qu'aucune gate puisse voir le bit lui-même :
le balayage confirme que `body_intrinsics` exige `control` et `privileged` pour
`swapgs`, ce qui est vrai, et ne dit rien du `GSBASE` que l'oracle publie dans
le même mot. Corriger 17 sans enregistrer 18 et 19 aurait laissé un faux voisin
debout avec des citations neuves autour de lui.

**Et ce trou-ci n'est pas un coût que le §8.3 accepte : c'est une absence sans
expression.** Les bits 18 et 19 ne sont pas seulement non gardés, ils n'ont
**aucun canal**. `x64.c:859-863` pose le bit 19 sur tout opérande de segment
`FS` et le bit 18 sur tout opérande de segment `GS`, et `swapgs` publie
`registers_written` `0x40000` ; or le vocabulaire d'atomes ne contient ni
`gsbase` ni `fsbase`, si bien que `effects {gsbase}` et `effects {fsbase}` sont
refusés en **`321` raison 1, « nom d'effet inconnu »** (`effects.nova:188`) —
**exactement comme une faute de frappe**, et de façon indiscernable d'elle.
Contrôle dans la même exécution : `effects {control}` sur un corps `swapgs` est
accepté, et `effects {changse_flags}` — une faute de frappe volontaire — est
refusé `321` comme `gsbase` et `fsbase`. **Il n'existe donc aucun moyen,
pour une fonction, de déclarer qu'elle déplace un registre de base, ni aucun
instrument qui puisse le demander.** C'est une classe de défaut différente de
celle de `return` et `call` : ceux-là sont un arbitrage énoncé et payé, celui-ci
n'est simplement pas dans le langage. **C'est la phrase la plus utile que ce §17.4
*puisse rendre à A4, et elle se lit avec le paragraphe du bit 17 : le masque
`0xffff` est correct pour 17, et le résidu est 18 et 19.**

**La première colonne du tableau des footprints est un libellé du document, et elle
est écrite sans le préfixe `clobbers_` précisément parce qu'aucun
`clobbers_<mnémonique>` n'existe dans l'arbre.** La version précédente portait ce
préfixe : les étiquettes ressemblaient alors à du code, la gate `registry` les a
donc cherchées dans la plage citée — qui est celle de `x64.c`, l'oracle — et a
reporté `IDENT-MISSING` sur quinze lignes d'un coup. **C'est la septième classe, et
elle n'apparaît qu'avec un instrument qui lit le document comme du code :** un
document qui nomme les choses dans un vocabulaire que le code n'emploie pas crée
des identifiants indistinguables de ceux du produit pour tout ce qui le lit. Les
formes réelles sont celles du membre de `x64.c:942`,
`"push|pushfq|pop|popfq|ret|return|call"`, et c'est là que la citation pointe.

**Et la règle que cet exemple établit, parce qu'elle va contre l'intuition du
projet.** Un masque n'est pas un trou par lui-même : c'est un trou quand le bit
qu'il efface porte une obligation que rien d'autre ne porte, et c'est une
redondance quand il y en a une ailleurs. Les deux instruments qui balayent le
membre masquent avec `0xffff`, et **le masque a raison** — le bit 17 porte une
obligation que `body_intrinsics` vérifie déjà par un autre canal. *« Un canal que
personne ne voit est un canal que personne ne vérifie »* reste vrai, et il a une
symétrique qu'il fallait dire : **un canal que personne ne voit peut être un
canal vérifié ailleurs**, et c'est le seul cas où un masque correct ressemble à un
défaut à qui n'a pas lu `x64.c:1069-1074`. C'est la sixième classe, et c'est la
seule jusqu'ici qui plaide pour un instrument qui fait **moins**.

**Ce que la preuve exécutée couvre, et jusqu'où.** `memberC` demande à
`nt_x64_effects` la valeur attendue **au moment de l'exécution** et la compare à
la charge de la passe, sans littéral écrit dans le fichier, puis republie le
même corps derrière un `clobbers` construit depuis `FAM` pour exiger que la
charge soit **payable** et pas seulement calculée
(`tests_ntasm_body_clobbers.c:239`, la définition ; la fin de la fonction n'est
pas citée parce qu'elle n'a pas été lue). Le même principe est côté
`control_flow`, qui balaie le membre entier et publie `A4-EXACT` par forme
(`A4-EXACT form=popfq shape=FR0 registers_written=0x20010 gpr=0x0010
non_family_bits=0x20000`). Le négatif reste à sa place : `sysretq` publie
`0x20000` et n'écrit aucun GPR, et `leave` et `enter` sont refusés par l'oracle
lui-même (`admitted=no`).

**Ajout du 27 septembre 2026 — `push`, `pop` et `leave`.** `push` et
`pop` sont ajoutés par `compiler/nova/analysis/abi/body_clobbers.nova`, vérifié
par le gate `body_clobbers`. Ils comblent un refus faux : avant cette ligne,
`align_stack 16` suivi de `pop rsp` était refusé comme un alignement non
compensé, alors que §17.4 ne nommait ni `push` ni `pop` et qu'aucun `clobbers`
ne pouvait donc décrire ce que ces deux formes déplacent. Les deux lignes sont
lues, pas déduites : l'oracle de conformance x86_64
(`compiler/c/ntasm/backend/x64.c`, `nt_x64_effects`, membre
`push|pushfq|pop|popfq|ret|return|call`) publie `registers_written` valant
`1<<4` pour `push` et pour `pop`, et `tests_conformance.c` gate
`push r64` sur `registers_written == (1u<<4)`. `1<<4` est la famille 5, `rsp`,
dans le numérotage de `register_widths.family`. Ce paragraphe est le récit daté
du lot ; la règle complète du membre et ses sept formes sont énoncées plus haut
et lui sont prioritaires. **La phrase qui y disait « et les cinq qui manquent au
tableau » est retirée le 29 septembre 2026 : le tableau ne les manque plus, et la
mesure de la direction de l'omission est plus haut dans cette section.**
Trois précisions restent :

- `push` **lit** son premier opérande et n'écrit que `rsp` : la ligne
  `writes_first` ne change pas et `push rbx` ne coûte que `rsp` ;
- `pop` **écrit** aussi son premier opérande : son footprint est
  `pop` **plus** la famille de cet opérande lorsqu'il nomme un
  registre. Un opérande mémoire ne coûte que `rsp`, son écriture mémoire
  appartenant à `body_effects` et non au tableau des clobbers ; un opérande
  qui n'est ni registre ni mémoire donne 336, comme pour `writes_first` ;
- `leave` et `enter` sont des pseudo-opérations que la grammaire admet, car
  toute instruction `NAME` devient un nœud de kind 32, mais dont **l'encodeur
  n'a pas d'entrée** : aucun oracle ne peut donc ancrer un footprint. La règle
  du projet est un refus explicite et jamais un no-op, et `body_clobbers` refuse
  `leave` par **336** — la destination qui n'est pas un registre — quelle que
  soit la déclaration de `clobbers`. `call_contracts` note la même absence
  d'encodeur et exclut `leave` de son ensemble d'ajustements implicites. Ce
  refus ne dit rien de l'x86_64 : il dit que l'outil ne sait pas l'émettre.

Effets : ni `push` ni `pop` ne portent d'atome, `flags_written` restant nul
dans l'oracle pour les deux ; `body_intrinsics` ne leur demande donc rien. Le
même lot donne à `align_stack` (kind 45) l'atome `changes_flags` seul, gate
`body_intrinsics` : l'oracle n'a pas d'entrée pour un intrinsic de
vérification et d'abaissement, l'ensemble fermé exact reste donc ouvert et n'est
pas inventé. Voir §10 et §10.1 pour ce que cette vérification décide et ce qu'elle
ne décide pas.

Limite connue et assumée : `call_effects` distingue une clause ABI explicite
d'un call statement par la nature de son premier enfant
(`call_effects.nova:61-70`), alors que `call_clobbers` et `call_contracts`
classent encore tout nœud de cette forme comme un call
(`call_clobbers.nova:47-49`, `call_contracts.nova:364-366`). Une déclaration qui
porte une clause `abi nx64-abi-v0` **et** effectue un call n'est donc pas
couverte par ces deux passes.

**Trois tables de footprint coexistent, et elles ne se recouvrent pas.** Il y a
trois réponses à « cette forme écrit-elle la famille `rsp` ? », et il faut les
lire ensemble parce qu'elles ne répondent pas à la même question :

| forme | `body_clobbers` — footprint, `fixed_mask`/`form` | `control_flow` — footprint, `writes_stack` | `control_flow` — déplacement, `displaces_stack` | `call_contracts` — ensemble implicite du §8.3 |
| --- | --- | --- | --- | --- |
| `push` | `rsp` par `fixed_mask` (`:447`) | forme 5 | oui | oui |
| `pop` | `rsp` par `fixed_mask`, plus l'opérande par la forme 3 | forme 3 | oui | oui |
| `iretq` | `rsp` par `fixed_mask` | forme 6 | oui | oui |
| `pushfq` | `rsp` par `fixed_mask` | forme 5 | oui | oui |
| `popfq` | `rsp` par `fixed_mask`, **bit 17 non chargé** | forme 5 | oui | oui |
| `ret` | `rsp` par `fixed_mask` | forme 5 | oui | oui |
| `call` | **lu et non chargé**, bras kind 28 (`body_clobbers.nova:766-796`) | **oui**, par `statement_writes_stack` (`control_flow.nova:516-531`) | oui, et rend le fait | oui |
| `sysretq` | absent | forme 0 | oui | oui, **au-dessus** de l'oracle |
| `leave` | forme 4, refus `336` | forme 4, refus `336` | non, le refus vient d'abord | absent |
| `return` | **lu et non chargé**, bras kind 29 (`body_clobbers.nova:766-796`) | **oui**, par `statement_writes_stack` (`control_flow.nova:516-531`) | oui | oui |

**Cette table a été réécrite le 29 septembre 2026 parce que quatre de ses
cellules étaient fausses.** Elle disait « absent, garde zéro » pour `pushfq`,
`popfq` et `ret` dans la colonne `body_clobbers`, et « forme 0, donc non » pour
les mêmes trois dans la colonne `control_flow` ; les deux sont fausses depuis la
vague qui a chargé le membre entier dans `fixed_mask` et ajouté les trois lignes
de `footprint`. Elle disait ensuite que la raison du zéro était « une contrainte
de gate, pas une lecture de l'oracle » : cette phrase est **retirée**, parce que
la contrainte de gate a été levée et que la rangée lit aujourd'hui l'oracle
directement.

Trois choses à ne pas confondre, et la quatrième est la seule qui reste une
question ouverte. **La colonne footprint de `control_flow` est bornée par la
sonde de parité** : elle doit répondre ce que répond `body_clobbers` sur la
même forme, et la gate échoue sur un désaccord — c'est ce couplage, et non une
erreur de table, qui a motivé le zéro d'autrefois. **La colonne déplacement est
une autre question** — le §10, le déplacement et la compensation — et elle
répond oui pour `pushfq`, `popfq`, `ret` et `sysretq`
(`displaces_stack`, `control_flow.nova:444-484` ; le tableau des formes que le
commentaire en donne est à `:397-426`). **La colonne `call_contracts` est une
troisième question encore**, celle du §8.3, alignée sur le membre de l'oracle
(`call_contracts.nova:650`). Une forme peut donc être refusée par `335` dans un
corps, déplacée pour les besoins du §10, et déplacée pour les besoins du §8.3 :
ce n'est pas une incohérence, ce sont trois questions. **La quatrième est le
bit 17 de `popfq`**, qui n'appartient à aucune des trois colonnes et que rien ne
garde — le masque `0xffff` de la comparaison est nommé et mesuré plus haut.

**`call` et `return` ont une ligne où les deux modules se rejoignent, et c'est la
seule de cette table où ils sont d'accord pour une raison qu'ils énoncent
différemment.** `control_flow` ne les perd pas de vue : il leur a trois
verdicts à part, lus sur le nœud de statement et non sur un mnémonique —
`statement_footprint` rend 7 pour `return` et 8 pour `call`
(`control_flow.nova:516-521`), `statement_writes_stack` répond **vrai** pour les
deux, `statement_displaces_stack` répond **vrai** pour les deux, et
`statement_restores_stack` répond **vrai pour `call` seulement** (`:541-556`).
`body_clobbers` lit le même `1<<4` et choisit de ne pas le charger. **Les deux
réponses sont correctes et ne se contredisent pas** : l'une répond « cette
écriture existe-t-elle », l'autre « doit-elle être déclarée », et le §8.2 est
exactement l'endroit où la seconde se décide. C'est la phrase la plus courte
qu'on puisse écrire sur ce couple, et elle remplace la cellule « sans objet »
que cette table portait pour les deux formes — **une cellule qui était fausse :
elles ne sont pas sans objet, elles sont répondues par une autre porte.**

`control_flow` n'a pas le droit de lire la table de `body_clobbers` — la gate
`return_types` compile `control_flow.nova` sans `body_clobbers.nova` dans l'image
— donc il exporte ses trois verdicts, chacun dans son propre groupe :
(`writes_stack`, `control_flow.nova:426`), (`replaces_stack`,
`control_flow.nova:454`) et (`displaces_stack`, `control_flow.nova:539`) ; et la
gate `control_flow` met les
trois sur un corps à une instruction et échoue quand elles divergent d'un
tableau qu'elle porte (`tests_ntasm_control_flow.c:848-865`, le tableau
d'invalidation ligne par ligne).
**Ce couplage est un risque énoncé avec une gate, et il ne s'étend pas à
`call_contracts`,** qui ne lit aucune des trois et qui tient sa propre règle. **Il
faut dire ce que le
couplement de ce couplage ne prouve pas :** il compare deux tables Nova l'une à
l'autre, et la gate `body_clobbers` compare chacune à l'oracle par un chemin
distinct ; c'est le croisement des deux qui tient le §17.4, et non l'une des
deux comparaisons prise seule.


### 17.5 Frontières de déclaration `nx64-abi-v0` — gelé, et ce qui ne l'est pas

Sont validé et gardés aujourd'hui, et seulement cela :

- `nx64-abi-v0` est le seul nom d'ABI accepté, soit par `default_abi`, soit par
  une clause `abi` sur la fonction ou l'import ; un nom inconnu donne 327, un
  second `default_abi` donne 327 raison 3 ;
- au plus quatorze paramètres par déclaration ; le quinzième donne 328
  raison 1 ;
- les quatre premiers paramètres `in` sans liaison explicite reçoivent, dans
  l'ordre, `rcx`, `rdx`, `r8`, `r9` ; le cinquième et les suivants exigent un
  `@GPR` explicite (328 raison 2) ;
- un paramètre `out` ou `inout` exige toujours un registre explicite (328
  raison 3) et son type doit être un entier machine ou un pointeur, le
  « entier machine » étant actuellement lu comme `u8`, `u16`, `u32` ou `u64`
  seulement (329 raison 1) ;
- un pointeur doit être lié à une largeur 64 bits (329 raison 2) ;
- une sortie ne peut utiliser les familles de sortie réservées `rax`, `rsp`,
  `rbp` (328 raison 5) et sa famille ne peut pas figurer dans `clobbers`
  (328 raison 6) ;
- une liaison `@GPR` explicite dont le catalogue ne connaît ni la famille ni la
  largeur donne 328 raison 4 (`compiler/nova/analysis/abi/abi.nova:222-224`) ; cette raison était absente de
  cette liste et est rendue ici ;
- une liaison explicite qui entre en collision avec l'affectation par défaut
  d'un paramètre antérieur donne 328 raison 7 ; se lier explicitement au
  registre que le défaut aurait donné n'est pas une collision.

Les huit raisons de `328` sont donc, dans l'ordre où la passe les teste :
`1` plus de quatorze paramètres, `2` cinquième paramètre `in` sans `@GPR`,
`3` `out`/`inout` sans registre explicite, `4` `@GPR` inconnu du catalogue,
`5` famille de sortie réservée, `6` cette famille aussi dans `clobbers`,
`7` collision avec l'affectation par défaut, et `8` `rbp` déclaré comme clobber.
**La raison 8 a été retirée et ce paragraphe, qui la déclarait, est faux — correction du 28 septembre 2026.** Une recherche de `reason=8` sur l'arbre Nova ne rend **rien**, le commentaire du propriétaire dit que ce refus « **était FAUX et a été retiré** », et la gate `abi` asserte qu'une déclaration `clobbers {rbp}` est **acceptée**. **§17.5 et §17.6 se contredisaient donc à l'intérieur du même document, et §17.6 est la section que la gate applique.** Le motif du retrait vaut mieux qu'une suppression : la passe ne pouvait pas tenir la promesse que la déclaration faisait, et elle ne la tient plus. *(
« aucune huitième » : la phrase était vraie le 27 et est fausse depuis.** Elle
est évaluée après la raison 6 et avant la raison 7, chacune sous `if code==0`
(`compiler/nova/analysis/abi/abi.nova:252-268`), donc aucune raison déjà rapportée ne
peut changer de code, de raison ou de position. **Elle est nx64-seulement et
c'est un changement de langage, non une règle de l'oracle** : voir §17.5.2.
Les raisons `1` et `2` sont, elles, **aveugles au profil** — le compteur de
quatorze et la table des quatre premiers registres par défaut sont appliqués
quelle que soit l'ABI nommée — et la gate `abi` le note explicitement dans
`pin_abi_profile_scope`. C'est un défaut connu, énoncé ici pour que le prochain
lecteur sache quelles règles suivent le profil et lesquelles ne le suivent pas.

N'est **pas** implémenté sur le chemin qui produit l'image, et ne doit donc pas
être présenté comme fermé : la frame d'appel du chemin de fichier, sa taille,
l'ensemble des registres préservés et la convention callee-saved de ce chemin, le
passage d'arguments sur la pile, les arguments variadiques et la zone rouge. La
phrase « aucun de ces éléments n'a de code ni de gate » était fausse et a été
corrigée le 26 septembre 2026 : il existe désormais un producteur de corps
trame, il a une gate, et il n'est pas sur le chemin de l'image. Ce qui suit
nomme lequel des deux est réel, parce que la spec ne doit pas laisser croire que
l'écart est une question ouverte alors qu'il est un fait.

**B2, le producteur réel de l'image exécutable est connu et il est sans trame.**

- Le producteur est le module `x64_lower_nxo`
  (`x64_lower_nxo.nova`, export `build_function_bodies`) et il **n'émet ni prologue ni
  epilogue**. Il abaisse chaque corps par `x64_lower_control.lower_wide_range` et
  écrit les octets du corps à l'offset calculé pour lui ; il n'écrit ensuite que
  `mov rax,imm64` avec `ret` (classe 4) ou un `ret` nu (classe 5). Aucun `pushfq`,
  aucun `push` de registre sauvegardé, aucun `push rbp`, aucun `sub rsp`. Les
  numéros de ligne de ce module sont **volatils** : il est en cours d'édition et sa
  longueur a changé pendant l'audit de la spec, qui les donne ici par symbole
  plutôt que par ligne pour cette raison.
- Le point d'entrée qui écrit un fichier est
  `x64_lower_nxo_pe.build_function_bodies_and_write`
  (`x64_lower_nxo_pe.nova:130`), et c'est lui qui appelle ce producteur. Les trois
  seuls exports du projet qui ouvrent un fichier sont
  `build_function_bodies_and_write`, `build_function_bodies_and_write_linked`
  et `build_function_bodies_and_write_sized` ; ils passent tous
  par `build_function_bodies` ou par `build_function_bodies_linked`,
  qui appelle le même producteur. **Les numéros de ligne sont volontairement
  absents d'ici, et c'est la règle que les trois lignes ci-dessus énoncent déjà
  — « les numéros de ligne de ce module sont volatils […] je les donne par
  symbole » — que ce paragraphe ne suivait pas.** Ils y étaient présents et
  **tous faux** : les numéros 118, 161, 185, 96, 97, 147 et 149
  nommaient `build_function_bodies_and_write`, `…_and_write_linked`,
  `…_and_write_sized`, `build_function_bodies` (appel), et
  `build_function_bodies_linked` (appel), qui sont en réalité à `:130`,
  `:194`, `:218`, `:107` (appel `:108`) et `:180` (appel `:182`) dans un
  fichier de 234 lignes. **Ils sont écrits ici sans la forme `:` de la citation,
  et c'est délibéré : un numéro cité comme faux reste une citation pour tout
  instrument qui résout les abréviations, et l'instrument le relèverait à chaque
  passage. Une retraction qui quote la mauvaise chose sous une forme lisible par
  la machine est un défaut que la machine recommencera de signaler
  indéfiniment.** **Le cas le plus instructif est la contradiction à
  trois lignes d'intervalle : la ligne précédente cite `x64_lower_nxo_pe.nova:130`
  pour `build_function_bodies_and_write` et c'est exact, et deux lignes plus bas
  le même symbole est cité au numéro 118.** Un lecteur qui vérifie l'un et pas l'autre
  tire deux conclusions opposées du même document, sans moyen de savoir
  laquelle est la bonne.
  `rt_open_new`, `rt_write` et `rt_close` n'apparaissent que dans ces trois
  exports : aucun producteur de `x64_lower_nxo` n'ouvre de fichier, donc aucun
  producteur ne peut contourner cet
  adaptateur.
- La preuve exécutée est donc frameless, et son point d'entrée est écrit dans la
  preuve : `examples/ntasm-v0/frameless-uefi/`, dont le programme sous test
  `program.ntasm` (352 octets, `91cd6d80…`) est **désormais dans l'arbre**, et
  l'image produite `nova-produced.efi` (3072 octets, `905e84ce…`) avec elle.
  **Le harnais, lui, reste sous `out/c-bootstrap/nova/ntasm-nova-uefi-20260926/`
  et n'est pas recopié** : `AGENTS.md` interdit tout runner persistant hors de
  `out/` (`:39-43`), et `out/` est un état consommé que l'auto-hôte détruit à
  l'entrée. **La ligne 287 de `driver.c` est un littéral de chaîne dans un
  `printf`** — le programme se décrit lui-même — et non un appel ; elle nomme
  donc le point d'entrée sans l'établir, et le mot qui la présentait comme
  l'appelant n'était pas fondé. Ce qui l'établit est dans l'arbre, par symbole :
  `x64_lower_nxo_pe.build_function_bodies_and_write`. Marqueur
  `NG_NTASM_C_RESULT_OK`, résultat 42, entry RVA `0x1000`, PE 3072 octets,
  sha256 `905e84…`, sur un programme de trois fonctions à **zéro** paramètre et
  sans un seul `push`.
- L'écart avec l'oracle C est réel et non nul. `codegen.c:1252-1266` ne se
  passe de la frame que dans **une** forme, et cette forme est étroite : un
  corps sans `requires stack_aligned`, **sans aucun paramètre**, dont l'unique
  instruction est un `return` de constante. Sur toute autre forme
  l'oracle encadre la fonction — `pushfq` (`codegen.c:1289`), treize `push` de
  registres sauvegardés (`codegen.c:1291-1294`, sur la table de
  `codegen.c:93-94`), `push rbp` puis `mov rbp,rsp` (`codegen.c:1295-1296`),
  le sondage de page puis `sub rsp` (`codegen.c:1298-1310`), un store de spill
  par paramètre (`codegen.c:1331-1348`), puis l'épilogue — et le producteur
  sans trame n'en émet aucune. Dans le programme réellement exécuté, `seed()`
  prend ce raccourci et `main()` et `twice()` ne le prennent pas : l'image qui
  a donné 42 n'a pas la forme que l'oracle C lui donnerait.
  *(Les numéros de ligne de ce paragraphe ont été réécrits le 28 septembre
  2026 : ceux qui précédaient — `1159`, `1196`, `1198-1201`, `1202-1204`,
  `1206-1217`, `1224-1255` — ne désignaient plus ces sites depuis plusieurs
  révisions de `codegen.c`, et la gate `registry` ne les bloquait pas parce
  qu'ils résolvaient encore vers un fichier existant, seulement vers la
  mauvaise ligne.)*
- **La limite, nommément, et réduite le 27 septembre 2026.** L’affirmation
  précédente — « le seul appelant du projet est le module d’entrée de sa propre
  gate ; aucun module de production ne l’appelle » — **est devenue fausse**.
  `x64_lower_nxo.nova` aiguille désormais vers `build_framed_functions`
  depuis `build_function_bodies`, qui est le producteur qu’atteignent les trois
  routes fichier et PE, et la gate le tient déjà. Ce qui reste vrai : l’export
  n’a toujours **ni sortie PE ni point d’entrée d’écriture** propres, et il
  n’existe toujours ni `build_framed_functions_to_pe` ni
  `build_framed_functions_and_write`. **Le résidu exact, énoncé, et
  CORRIGÉ le 28 septembre 2026 :** la version précédente de cette phrase
  disait qu'« une fonction **sans paramètre dont le corps est plus qu'un
  `return` constant` n'atteint jamais la route trame ». **C'est l'inverse de
  ce que fait l'oracle, et c'était une affirmation fausse.** Le raccourci
  n'est pris que si le corps se réduit à un `return` de constante
  (`codegen.c:1252-1266`) ; une fonction sans paramètre dont le corps est plus
  volumineux **tombe donc bel et bien sur la route trame**, où elle est
  encadrée et s'exécute. Mesuré le 28 septembre 2026 en executant l'oracle
  sur quatre sources distinctes, en lisant l'octet zéro de chaque image
  (`9c` = `pushfq` = encadrée, `48` = `mov rax,imm64` = sans trame) **et** en
  appelant chaque point d'entrée : constante seule → sans trame, valeur 7 ;
  `let` puis `return x` → **encadrée**, valeur 5 ; `let` puis `return x+1` →
  **encadrée**, valeur 6 ; `let` puis `return v` → **encadrée**, valeur 9.
  **Ce résidu n'existe plus sous la forme qu'il avait, et la phrase qui le
  décrivait est retirée le 29 septembre 2026 : elle était fausse contre
  l'arbre.** Elle affirmait, en ces termes, qu'« une fonction **sans paramètre et
  au corps non trivial n'a donc aucun producteur Nova** », et le producteur trame
  en a un.
  `collect_frame_signature` a une branche `pcount==0`
  explicite (`x64_lower_nxo.nova:3676-3677`) qui ne refuse que la forme que
  l'oracle ne cadre pas — `parameterless_takes_shortcut(g,body.first_child)==1`,
  le `return` de constante — et qui cadre tout le reste. La borne
  `x64_lower_nxo.nova:3583` (`if param_direction(g.source,node)!=1{return 0;}`)
  filtre la **direction** de chaque paramètre présent ; elle n'exige pas qu'il y
  en ait un. **Les deux citations de la phrase retirée étaient fausses** :
  `x64_lower_nxo.nova:1801-1802` et `:3256-3257` ne contiennent ni l'un ni l'autre
  un compte de paramètres, et le fichier compte 4270 lignes.
  **Preuve, et non lecture :** la gate `x64_lower_nxo_function_bodies` porte un
  bloc « 33. The parameterless function that had no producer »
  (`tests/c/nova/tests_ntasm_x64_lower_nxo_function_bodies.c:3155`),
  et ses neuf fixtures confrontent le modèle, les octets de `.text`, les symboles,
  les relocations, le NXO et le PE à l'image de référence `nt_codegen_x64_object`
  — donc à l'oracle C, pas à une transcription de Nova. Exécution à froid :
  `NTASM_NOVA_X64_LOWER_NXO_FUNCTION_BODIES checks=3721 failures=0 cases=391`.
  **Preuve négative, sur une copie et non sur l'arbre** : remplacer le corps de
  la branche `pcount==0` par un refus inconditionnel rend **9 lignes rouges**,
  nommées une par une (« zero parameter, one local returned », « two locals, the
  second returned », « a branch on a local bool », « a call to a framed callee »,
  « a call inside an if arm », etc.), toutes en `NOVA_REFUSED code=800`. La
  capacité est donc **présente et mesurée**, et non un chemin mort que rien ne
  traverse. **Ce qui reste vrai de la phrase retirée** : le producteur **sans
  trame** ne sait toujours produire qu'une feuille à `return` constant, et c'est
  cette limite-là qui reste ouverte. C'est un résidu **réduit**, pas nul.

**Le gate qui tient cette déclaration, et qui échoue des deux côtés.**
`case_framed_route`, dans la gate `x64_lower_nxo_function_bodies`
(`tests/c/nova/tests_ntasm_x64_lower_nxo_function_bodies.c`),
n'est alimenté par aucune transcription du producteur Nova : le prologue de
référence est sorti de `nt_x64_encode`, et l'image de référence de
`nt_codegen_x64_object`. Il vérifie quatre choses. Un : sur `SRC_TWO`, l'image de
référence **encadre** la fonction exportée, dont la première instruction est un
appel, et **n'encadre pas** l'autre fonction de la même source, dont le corps est
un unique `return` de constante — les deux faits tiennent dans une seule image de
référence, ce qui rend le contrôle discriminant. Deux : l'image produite par le
producteur sans trame sur cette même source **ne commence pas** par ce prologue,
et diffère de l'image de référence. Trois : le producteur trame produit exactement
l'image de référence, prologue compris, et le producteur sans trame refuse cette
source avec 800 en laissant le tampon intact — donc aucune source qui reçoit une
trame n'atteint un point d'entrée de fichier. Quatre : les sites d'appel sont
comptés dans les sources Nova, trois écrivains de fichier, deux appels au
producteur sans trame, **zéro** appel au producteur trame, et aucune primitive de
fichier dans `x64_lower_nxo.nova`. Une trame qui apparaît dans l'image du chemin
de fichier, ou une route PE ou fichier pour le producteur trame, font rougir ce
gate. Le critère 17.5 reste donc ouvert sur la **frame de l'image du chemin de
fichier**, et il n'est plus ouvert sur la question de savoir quel producteur
produit cette image : cette question a une réponse, et elle est ci-dessus.

**L'alignement de pile produit par `align_stack` n'est plus dans cette liste, et
la correction est datée.** Cette phrase disait qu'il n'avait « aucun code ni de
gate » ; c'était faux. `control_flow` décide les six obligations du §10 sur le
nœud kind 45 et l'état de corps qu'il produit, dans l'ordre où le §10 les énonce,
et les refuse en `364` raisons 1 à 5
(`compiler/nova/analysis/control_flow.nova:137-180` et `:764-777` puis `:869` et `:893`), le tout gardé
par la gate `control_flow`. Le §10.1 pose ce qui reste ouvert dans cette
matière : le `N` publié n'est pas une taille de déplacement, aucune passe ne
calcule de frame, et les refus de compensation sont syntaxiques. Le critère 10
reste donc ouvert sur la **valeur** de l'alignement, et ne l'est plus sur son
**détection**. Ce que la passe ne peut pas décider est écrit dans son propre
commentaire, qui est ici repris parce qu'il vaut mieux une limite citée qu'une
limite absente : `mov rsp, rbx` est accepté comme compensation sans que rien
puisse dire si `rbx` tient le pointeur d'entrée
(`control_flow.nova:170-180`).

Les retours d'interruption et de syscall, eux, ne sont plus dans cette liste, et
la correction est datée. `stub_table` (§17.8) valide leurs **déclarations** contre
vingt-trois règles et les abaisse en **records ordonnés et en plan de corps
abstrait**, le tout gardé par la gate `stub_table`. Ce paragraphe disait
« Cela ne change rien pour l'image » ; c'est faux depuis le 27 septembre 2026,
et `stub_table` **émet une image**. `build_pe` encode le plan de corps
abstrait, construit un objet NXO fermé et écrit un PE dont le `.text` est
octet pour octet celui de `codegen.c` pour la même source. Deux affirmations
de ce paragraphe survivent à cette correction : `stub_table` n'écrit **aucun
nœud NTIR**, et il n'est appelé par **aucune passe du pipeline** du §17.7. La
phrase « Le
générateur produit des nœuds NTIR, des symboles et relocations typés » reste
fausse, mais pour une raison plus étroite qu'avant : les symboles et les
relocations sont produits, les nœuds NTIR ne le sont pas. Les critères 17.5,
11 et 10 restent ouverts sur l'image — et l'image, désormais écrite, **n'a
jamais été exécutée** : le boot sous OVMF entre dans le point d'entrée et n'en
ressort pas. Voir le rapport de vague 7.

#### 17.5.1 Les deux profils d'ABI de v0, et l'écart de capacité qui les sépare

Ajouté le 28 septembre 2026. Ce paragraphe remplace la prémisse de la vague 8,
qui affirmait que le passage d'arguments sur la pile était « non défini dans le
langage » et que « sous `nx64-abi-v0` le chemin est inatteignable ». **Les deux
affirmations sont fausses et sont retirées sur place.** Le chemin n'est pas
indéfini : il est orthographié, implémenté, et **exécuté par un test**.

**Ce que l'oracle implémente.** `codegen.c:435-437` `is_efi` est un `strcmp`
simple sur `efi-x64-v0` qui retourne trois comportements distincts : le compte
des arguments de pile côté appelant (`codegen.c:447-449`), la copie des
arguments au-delà des quatre premiers vers l'espace d'ombre après `[rsp+32]`
(`codegen.c:562-571`), et la relecture des emplacements entrants côté callee
(`codegen.c:1312-1327`). `frontend.c:2894` ouvre un second bloc de règles avec
ses propres refus, dont celui des `out`/`inout` non implémentés
(`frontend.c:2912-2915`).

**Ce n'est PAS un alias, et la preuve est la borne de paramètres.** La borne
de quatorze est **à l'intérieur** du bloc nx64 : `frontend.c:2832`
`param_count > 14` est gardé par `frontend.c:2830`
`!strcmp(function->abi, "nx64-abi-v0")`. Elle ne s'applique donc pas au second
profil, dont la limite est soixante-quatre entrées
(`compiler/c/ntasm/backend/codegen.h:36-41`, `codegen.c:543`), et pour lequel le
cinquième paramètre est un **paramètre de pile légal** et non un refus. Un
alias n'aurait pas deux bornes. Deux profils.

**De quel profil s'agit-il ?** Du **Microsoft x64** (UEFI), pas d'un second nom
de nx64. Le masque de registres non volatils de `frontend.c:2895-2897` vaut
`rbx`, `rbp`, `rsi`, `rdi`, `r12`, `r13`, `r14`, `r15` en indices de famille
`3,5,6,7,12,13,14,15` — c'est l'ensemble non volatile x64 de Microsoft, `rsp`
exclu parce qu'il n'est pas une famille liable. C'est aussi l'ABI sous
laquelle l'appel de test fournit ses arguments. Le §5 a été corrigé en
conséquence : **un target `x86_64-nexora-uefi` ne sélectionne PAS
`efi-x64-v0`**, car `frontend.c:5087` pose `default_abi = "nx64-abi-v0"` sans
condition et `frontend.c:5088-5089` ne valide le target que comme un nom.

**Mise à jour du 14 octobre 2026 — les deux profils sont exécutables.**
La sélection consulte le défaut du module puis la clause de la fonction.
EFI transporte les quatre premières entrées dans RCX/RDX/R8/R9 et les suivantes
sur la pile, avec32octets de home area et un alignement16. La borne est64;
65est refusé avec une position. Les profils mélangés sont vérifiés dans les
deux sens. Nx64 conserve bindings et règles OUT/INOUT, y compris les tranches
haut-octet. Les métadonnées call_arg transportent les arguments supplémentaires;
leurs valeurs doivent dominer le call. type_decl conserve les types déclarés.
Les contrats NXO lisent le profil et les clauses effectivement vérifiés.

Les portes `abi`, `validate`, `machine_ir` et `machine_producer_exec` confrontent
ces règles au C et aux exécutables. Les preuves QEMU actuelles comprennent
les sentinelles des huit GPR non volatils et un mutant qui détruit RBX, sous
`out/a4-finish-20261014/qemu/`. Les ABI de stubs restent des profils distincts.

#### 17.5.2 `callee-saved` — la règle écrite, et le fait qu'elle ne l'est plus

**Réécrit le 28 septembre 2026, puis le 29 septembre 2026 après une seconde
lecture de l'arbre.** La version du 28 disait qu'aucun ensemble n'était déclaré
et proposait d'en créer un ; celle du 28 au soir disait que la règle « existe
maintenant dans le produit » et qu'elle est « une divergence d'oracle ». **Les
deux sont fausses contre l'arbre d'aujourd'hui, et la seconde l'est devenue
parce que la première l'a été :** le refus qu'elle décrivait — `rbp` en `328`
raison 8 — a été retiré parce qu'il était faux, et **le retrait a emporté la
seule écriture de la notion qu'il avait**. Ce sous-chapitre décrit donc une règle
qui a existé dans ce document et **n'existe plus dans le produit** ; il est écrit
pour que le prochain lecteur sache ce qu'elle était, où elle a disparu, et que
rien ne l'applique.

**La règle, en une phrase — et le fait qu'elle n'est écrite nulle part.**
*Une famille de `clobbers` doit être une famille que la frame nx64 pousse à
l'entrée et peut donc ne pas restaurer à la sortie, c'est-à-dire l'une des
seize familles GPR sauf `rax`, `rsp` et `rbp`.*
**Cette règle n'est écrite dans aucun code du produit, et le dire est la
première chose à écrire ici.** Les paragraphes suivants de cette sous-section
affirmaient le contraire : ils nommaient `clobber_frame_family`
(`compiler/nova/analysis/abi/abi.nova:333-335`) et `clobber_frame_mask` (lignes 338 à 340)
comme « les seules écritures de la notion ». **Aucun des deux identifiants
n'existe dans l'arbre** — une recherche sur `compiler/c` et
`toolchain/` n'en rend aucun, et les lignes 333-335 et 338-340 d'`abi.nova` sont
l'affectation de `out[0..3]` et le commentaire de codes qui la suit. **Cette
phrase est retirée et n'est PAS remplacée par une ligne voisine qui existe :** ce
que la règle désigne n'a pas de site, et un pointeur vers autre chose aurait
exactement le défaut que la phrase commettait — il aurait fait croire à un
mécanisme.
**Ce qui existe à la place, et c'est mesuré.** (a) La seule lecture d'un ensemble
de `clobbers` **en code** dans `abi.nova` est `abi.nova:425-436`, et elle produit
`328` raison 6 — un clobber déclaré qui touche une famille de sortie. Ce n'est
pas la règle callee-saved. (b) **L'ensemble lui-même est de la prose** :
`abi.nova:460-530` le déclare par son complément, l'explique, et dit pourquoi le
complément et non une liste. (c) **Il n'existe pas « aucun tableau de treize
éléments dans le produit » : il y en a trois**, et c'est la table de **frame**,
pas l'ensemble de clobbers — `saved_registers[]` à `codegen.c:93-94`,
`fn saved_register` à `x64_lower_nxo.nova:2270`, `saved[13]` à
`tests_ntasm_x64_lower_nxo_function_bodies.c:1654`. Les trois portent les mêmes
treize, et c'est une gate qui les tient égaux, non une absence de table. (d)
**La conséquence qui compte :** rien dans le produit n'applique l'ensemble,
donc rien ne peut s'y tromper, et **le retirer ne coûte aucun programme** — ce
qui est aussi pourquoi l'affirmation « plus stricte que l'oracle » n'avait plus
de sujet.

**Ce qui est réellement refusé : rien. La correction d'abord, la phrase périmée
ensuite, et marquée.** **Aucune famille n'est refusée pour cette raison.** La
version précédente de ce paragraphe disait « seul `rbp` l'est », en `328` raison
8. **La raison 8 n'existe pas comme code dans l'arbre** : une recherche de
`reason=8` sur `compiler/c` et `toolchain/` rend **trois lignes, et
les trois sont des commentaires** — `abi.nova:517` porte le refus lui-même et ne contient pas memberC, qui est défini à `tests_ntasm_body_clobbers.c:239` ; les deux autres recherches qui le rendent sont en prose, une cellule ne portant qu'une seule assertion. Nommer un symbole une fois devant plusieurs fichiers oblige le controle a l'apparier a chacun d'eux, et l'une de ces trois ne le contient pas : c'est la regle qu'un fichier par paragraphe, et un paragraphe qui tient trois fichiers et un symbole oblige le controle a inventer deux rattachements.
`stub_table.nova:1928`, qui parle d'un autre sujet (le `reason 8` de
`stub_table`) — **et aucune n'en émet**. Le propriétaire du site dit que le refus
« était FAUX et a été retiré » (`abi.nova:516-520`), et la gate `abi` asserte
qu'une déclaration `rbp` est acceptée. *(La phrase précédente disait « une
recherche de `reason=8` sur l'arbre ne rend rien » : elle rend trois occurrences
et il fallait dire trois, toutes en commentaire, parce qu'un zéro demandé à une
recherche qui rend trois est un négatif fabriqué.)*
`rax` et `rsp` sont hors de l'ensemble et **restent acceptés**, chacun pour un
motif qui doit être dit : `rax` est le canal de retour et la destination
d'opérandes mixtes, la frame ne le restaure jamais, et une déclaration de `rax`
est donc redondante **et vraie** — plusieurs programmes d'exemple vivants et le
secteur de boot la déclarent ; `rsp` est inerte. **Un lecteur qui prendrait
« hors de l'ensemble est refusé » au pied de la lettre refuserait `rax` et
casserait le programme d'exemple `examples/ntasm-v0/c-bootstrap/return42.ntasm`,
dont la clause `clobbers {rax}` est précisément ce cas légitime.**

> **PHRASE PÉRIMÉE — conservée, marquée, et retirée de sa fonction de constat
> (28 septembre 2026).** *« Seul `rbp` est le cas genuinely faux : c'est le
> pointeur de frame, et l'épilogue ne peut pas le sauter parce qu'il ne lui
> réserve jamais d'emplacement. »*
> Elle est fausse **comme refus de déclaration** — aucune famille n'est refusée,
> et `rbp` moins que les quinze autres. Elle reste vraie **comme fait machine** :
> le pointeur de frame est bien un registre que l'épilogue ne saute pas. **Ce
> qui était faux, c'est d'en avoir fait un motif de refus d'une déclaration de
> `clobbers`.** La phrase reste ici parce qu'une correction qui ne laisse pas de
> trace n'apprend rien : elle est exactement ce qu'un lecteur qui arrive d'une
> édition antérieure vient chercher, et elle doit le trouver étiquetée.

**L'oracle n'a pas cette règle non plus, donc il n'y a plus de divergence à
décrire — et c'est un changement d'état du document.** Mesuré : sous
`nx64-abi-v0`, `nt_frontend_compile` accepte les seize familles sans aucun
diagnostic, `rbp` et `rsp` compris, et `frontend.c` ne touche un masque de
clobbers qu'à deux endroits — `frontend.c:2886-2891`, l'intersection avec les
familles de sortie, et `frontend.c:2904`, le profil efi seul. **La formulation
précédente de ce paragraphe, « l'oracle n'a pas cette règle : c'est un changement
de langage », décrivait un produit qui appliquait la règle ; il ne l'applique pas,
et il n'y a donc plus rien à décider ici.** Elle est remplacée, non corrigée en
passant : le sujet de la phrase a disparu.

**Le gate qui tient l'ensemble, et qui échoue des deux côtés.**
`scan_saved_register_copies`, dans
`tests/c/nova/tests_ntasm_abi.c:992`, lit l'initialiseur de
`codegen.c` lui-même (`saved_registers[]`, `codegen.c:93-94`) et confronte **les
deux autres écritures** de la table —
`x64_lower_nxo.nova:2270` `fn saved_register` et
élément et dans l'ordre, puis confronte l'ensemble à la **règle** (seize moins
`{rax, rsp, rbp}`) et non à un littéral, de sorte qu'une transposition de deux
entrées échoue aussi. Preuve négative enregistrée : viser une seule entrée et
la gate rapporte `FAIL SAVED-DRIFT x64_lower_nxo.nova saved_register[2] is
family 4, codegen.c says 3`. C'est la fermeture de la ligne U3 du §17.9.

**Un ensemble qui n'est ni l'un ni l'autre des deux conventions x86, et qu'il ne
faut donc pas nommer « callee-saved ».** La table de la frame fait **treize**
entrées; l'ensemble non volatile d'`efi-x64-v0` en fait **huit** — `rbx`,
`rbp`, `rsi`, `rdi`, `r12`–`r15` (`frontend.c:2895-2897`) — et c'est la
convention Microsoft x64, refusée par l'oracle en `403`. Le premier ensemble
est **strictement plus large** : `rcx`, `rdx` et `r8`–`r11` sont
caller-saved en SysV x86-64 et figurent pourtant dans la table de la frame,
parce que ce qui décide de l'appartenance est la question « la frame
possède-t-elle ce registre », et non une convention de volatilité. La
différence entre les deux vaut `rbp`, `rcx`, `rdx`, `r8`, `r9`, `r10`, `r11`.
Confondre les deux ensembles serait une erreur d'ABI, pas une approximation.
**La phrase « `rbp` est la seule famille que les deux règles refusent » est
retirée** : il n'y a plus de règle du produit à opposer à l'ensemble efi, `rbp`
n'est refusée par aucun des deux côtés sous nx64, et l'ensemble non volatile de
huit familles est un fait de convention de `efi-x64-v0`, non une règle appliquée.

#### 17.5.3 Alignement de section — PROPOSITION, la fonctionnalité n'existe pas

Ajouté le 28 septembre 2026. **La grammaire de NTASM v0 n'a pas d'alignement
de section, et ce document ne prétend pas le contraire.** Ce qui existe est
autre chose, et les deux ne doivent pas être confondues :

- `align_stack` est un **fait d'ABI sur `rsp`**, pas un alignement de section.
  Il est traité au §10 et §10.1 et gardé par la gate `control_flow` ; il ne
  produit aucun octet de padding de section.
- L'alignement réel des sections est **codé en dur** : `nxo.nova:78`
  `fn aligned(value) = ntasm_pe.align(value,16)`, appelé à `:176`, `:184`,
  `:234-236` et `:252`, et les champs d'en-tête de section sont écrits en dur à
  `nxo.nova:181-183` et `:254-256` — 16 pour `.text`, 8 pour `.rdata` et
  `.data`. Le commentaire de fusion (`nxo_merge.nova:77-79`) dit que la base est
  l'align16 du total courant appliqué **inconditionnellement** aux trois
  sections, et qu'une section droite vide consomme quand même une base. Ce
  comportement est épinglé par gate `nxo_merge` et ne doit pas être « optimisé ».
- La grammaire n'a pas le mot-clé : `parser.nova:74` `keyword_words()` compte
  **77** entrées et se termine par `...fs\0gs\0align_stack\0`, `align_stack`
  étant le mot-clé d'indice 77 en base 1 (`parser.nova:72`), et
  `parser.nova:140-144` `section_name()` produit `node(p,93,…)` puis
  `expect(p,46,4)` puis `name(p)` — un nom nu, sans emplacement d'alignement.

**Ce que ce manque coûte aujourd'hui : rien, et c'est la phrase qui décide de
toute la section.** Un trou d'émission serait une source produisant une
section que le chargeur refuse et que Nova émettrait quand même ; il n'y en a
pas, et pour une raison structurelle plutôt que par chance. **La disposition
PE de `pe.nova` est de forme fermée, non déclarée** : `pe.nova:96-98` dérive
chaque adresse virtuelle de `align(previous_end, 4096)`, et `pe.nova:119-120`
dérive chaque pointeur et chaque taille bruts d'une chaîne de 512 démarrant à
1024. Il n'existe **ni paramètre, ni champ de structure, ni construction de
source** capable de perturber un alignement ; même le cas limite
`pe.nova:95` `if data_size==0{data_size=8;}` retombe sur une frontière de 4096.
La réponse est donc toujours le couple 4096 et 512, et c'est exactement ce que le
chargeur exige. **La proposition n'est donc pas « réparer un trou » : c'est donner au
langage une orthographe pour un fait qu'il ne sait pas aujourd'hui énoncer.**
C'est une phrase différente, et c'est celle-ci qu'il faut écrire.

**La proposition, si elle est un jour adoptée.** Mot-clé `align`, **ajouté à la
fin** de `parser.nova:74` et jamais inséré — `parser.nova:71-72` est explicite
sur ce point, parce que chaque passe nomme ces identifiants par index numérique
— donc l'indice 78 en base 1, immédiatement après `align_stack`. **La sécurité
de préfixe est vérifiée et valait la peine d'être vérifiée** : `keyword()`
(`parser.nova:42-63`) compare d'abord la longueur exacte
(`) puis les octets, donc un mot de longueur 5 et un mot de longueur 11 ne peuvent
se confondre dans un sens ni dans l'autre : `align` et `align_stack` sont
distinguables, et **aucun changement de lexer n'est nécessaire**. L'attribut
porterait sur la déclaration de section, donc sur le nœud que construit
`section_name()` à `parser.nova:140-144` ; comme ce nœud est aujourd'hui un nom
nu, l'attribut n'a **aucun emplacement existant** et il s'agit d'un changement
de forme d'AST, pas d'une édition de table. Il typerait vers une expression
constante `u64` contrainte à une puissance de deux, dans `[512, 65536]` pour le
`FileAlignment` et `>= 4096` pour le `SectionAlignment`, avec `4096`/`512` par
défaut en l'absence de l'attribut. **Le coût** est de trois choses, énoncé ici
pour qu'on ne le découvre pas en l'implémentant : `parser.nova` gagne le mot-clé,
un emplacement d'attribut sur le nœud 93 et un parseur de constante entière ;
`align` devient un paramètre de `ntasm_pe.Image` et `pe.nova:126` cesse d'être
  deux littéraux ; et `pe_inspect.nova:153` devient le même paramètre nommé, ce
  qui transforme le contrôle `833` de « cette image porte 4096 et 512 » en
« cette image porte l'alignement que ses en-têtes de section annoncent ».
**Une affirmation à porter comme une affirmation et non comme une mesure :**
les octets émis pour tout programme existant seraient **inchangés**, puisque
le défaut reproduit exactement ce couple. Cela reste **à vérifier** tant que
l'attribut n'a pas atterri et que `nxo_pe` n'a pas rejoué ses 2486
comparaisons octet à octet ; personne ne doit le lire comme un résultat.

**Le code `833` (`ERR_BAD_ALIGNMENT`) n'est pas le point d'entrée de cette
proposition, et il n'est pas mort — deux faits distincts, mesurés le
  28 septembre 2026.** Son seul site est `pe_inspect.nova:153`, qui teste
  `SectionAlignment` et `FileAlignment` de l'en-tête d'image PE contre le
  couple fixe `4096`/`512` (`if r32(image,opt+32)!=4096 || r32(image,opt+36)!=512
  { return 833; }`). **La ligne 100 citée précédemment était fausse** : elle
  porte aujourd'hui `while i<4 {`, et `833` n'y figure pas. Le code est bien au
  site unique que la phrase décrit ; c'est le numéro qui avait dérivé, et la
  seconde occurrence de cette citation dans ce paragraphe a été corrigée avec
  la première.
  couple fixe `4096`/`512`. Il porte donc sur l'**image**, pas sur une source,
et c'est ce qui le rend étranger à la question d'un attribut de section.
Quant à sa vivacité : il est **inatteignable depuis l'écrivain** — `pe.nova:126`
écrit `4096` et `512` en littéraux inconditionnels, sans paramètre, et aucune
construction de source Nova n'atteint ces deux champs — et il est
**atteignable quand même**, parce que `pe_inspect.inspect` valide un
`image:buf<u8>` quelconque et non la sortie de l'écrivain. La gate le prouve en
mutant les octets d'une image de référence : `tests_ntasm_pe_inspect.c:339-340`
pose `{184, 4, 512}` et `{188, 4, 4096}` et attend `ERR_BAD_ALIGNMENT` dans les
deux cas. **La formulation juste est donc : joignable depuis toute image que
l'écrivain n'a pas produite, injoignable depuis toute image qu'il a produite.**
Il ne doit donc figurer ni comme un code mort ni comme une ligne de réserve
dans le §17.6.

**Une précision d'attribution, pour ne pas confondre trois alignements.** Le
champ d'alignement que `nxo.nova:181-183` et `:254-256` écrivent dans l'en-tête
de section NXO appartient à l'**alignement de conteneur**, et son autorité est
`object.c:23` `aligned(n) = (n + 15) & ~15`, reflété par `nxo.nova:78` ; ce
n'est ni le `FileAlignment` d'une image PE, ni un attribut de section
demandable par la source. La phrase exacte est donc : *l'alignement du
conteneur NXO est figé à 16/8/8 par `object.c`, et le langage n'a aucun moyen
d'en demander un autre.*

### 17.6 Registre gelé des codes de diagnostic

Quatre schémas cohabitent dans l'arbre et ne sont pas synchronisés, et un
cinquième s'y est ajouté sans que ce registre le suive. Ce registre fixe lequel
fait foi et quelle est la relation de sous-ensemble. Il ne crée aucun code et ne
corrige aucun code.

**Note de volatility des compteurs de gate, 27 septembre 2026.** Les compteurs
`N/M, K cas` cités dans ce document — `stub_table`, `call_contracts`,
`control_flow`, `body_clobbers`, `body_effects`, `abi`, `locals`, `bindings`,
`diagnostics` — sont des **mesures de banners de gate à une date donnée**, pas
des propriétés normatives. La règle du `305` et de sa liste de vingt-trois
raisons, la liste des dix prédicats et l'ordre des trente-quatre passes sont
normatifs et stables ; leurs compteurs ne le sont pas. Un lot qui touche une
gate déplace ses deux nombres sans qu'aucune phrase de ce document ne doive
 changer. Les compteurs de `locals` (`42/42, 13 cas`) et de `bindings`
(`45/45, 14 cas`) sont inchangés depuis le 27 septembre 2026. Ceux de
`diagnostics` ont été **remesurés deux fois le 27 septembre 2026**, après la
vague 7 puis après la vague 8 : `167/167, 80 cas` puis **`161/161, 77 cas`**,
contre `73/73, 33 cas` avant la vague 7. La gate a reçu les quatre familles de
diagnostics (largeur, registre, section, ABI) énoncées par le critère A10, puis
la vague 8 a corrigé deux de ses propres cas : la visibilité de section, qui
avait été ajoutée sur une prémisse fausse, et les deux `319` épinglés dans la
pipeline qui fixaient un refus que l'oracle ne porte pas. **Un compteur faux ne
rend pas la règle fausse ; c'est la seule raison pour laquelle il est écrit ici
plutôt que dans chaque cellule de ce registre.

| schéma | plage | portée | relation |
| --- | --- | --- | --- |
| S0 | `E001`–`E702` | bootstrap `seed0.efi` | source de vérité unique pour S0 ; autorité `spec/ntasm/ntasm-s0.md` |
| oracle C | `401`–`412` | `NtX64Error` de l'encodeur x86_64 | source de vérité unique pour l'encodeur ; le module Nova `x64_fixed` rend ces codes à l'identique |
| oracle frontend C | `100`, `200`, `201`, `300`–`303`, `400`–`403`, `500`–`504`, `600`, `900` | `NtFError` du frontend de référence | autorité du nommage seulement ; Nova réutilise les **nombres** `100`, `200`, `300` et `900`, mais ce document n'audite pas l'identité des vocabulaires de raisons, et pour `201` elle est fausse — voir la règle de lecture sur `201` |
| Nova sémantique | `300`–`386` | passes frontend Nova | espace disjoint du S0 **et** de la bande `4xx` de l'encodeur, mais **non** versionné par un document de format ; voir la règle de recouvrement ci-dessous |
| Nova structurel | `800`–`899` | refus transactionnels, lecteurs d'objets NXO et d'images PE, abaissement des labels Machine IR, **et** réceptions d'un conteneur d'octets IR | `800` est le refus transactionnel commun ; `820` et `821` sont publiés par `x64_lower_control` autant que par `nxo_merge`, donc la portée de cette ligne n'est pas seulement binaire. **La borne était `844` jusqu'au 29 septembre 2026, et elle était fausse** : le code déclarait `STRUCT_HI 899` depuis le début, et rien ne comparait les deux nombres. `ir_image.nova` s'est logé dans l'écart `850`–`860` pour une raison écrite et correcte — *« 8xx est parlé jusqu'à 844 et 9xx à partir de 930 »* — et les deux vérifications rouges sont tombées en bernamaant ce module plutôt que la déclaration. Une borne qui n'est pas comparée à son plafond dans le code est une borne nominale, pas un contrat |

**`800` porte UN nom, et la règle qui l'impose est écrite ci-dessous parce
qu'elle décide une question qui revient : ce projet nomme-t-il un CODE ou un
SITE ? Il nomme un CODE, et le CONTENU d'un code est une SIGNIFICATION — la
nature d'un refus — jamais un site, jamais un propriétaire.** Trois faits de
l'arbre tranchent, et aucun ne vient d'un résumé.

*Un code a plusieurs propriétaires, donc il ne peut pas nommer un site.* La
ligne `336` de la table des familles ci-dessus porte **trois** propriétaires
dans **une** seule ligne, et la colonne « raisons » écrit le motif : *« Les
trois publient le même nombre pour trois refus de même nature, et c'est
délibéré. »* Une cellule qui ne peut appartenir qu'à un site ne peut en avoir
trois. La ligne `340` est le cas miroir, et elle est nommée comme tel : *« Les
deux publient le même nombre pour deux refus de nature différente »*.
*La table est indexée par le NOMBRE et non par le propriétaire*, et sa colonne
« raisons » porte les distinctions **sous** un code : `305` y porte `1`–`23`,
`328` y porte `1`–`7`. **La granularité du nom est donc la signification, et
l'instrument du nom en dessous du code est le MOT DE RAISON, jamais un nombre
supplémentaire.**
*Le critère de division est écrit par le projet, sur lui-même*, dans
`nova_language_parse.nova` : *« 803 UNDECLARED is a fourth and is deliberately
NOT one of the three … keeping it separate is what lets the gate tell 801 from
803 with a perturbation that differs from both of the briefed ones. »* **Un
split s'obtient quand — et seulement quand — deux refus doivent rester
distinguables POUR UN CONSOMMATEUR.** Un nom qui tient à un site sur six cents
est un nom de site ; `E_UNCLOSED_BRACE`, qui vaut `800` dans
`nova_language_parse.nova` et qui est vrai à **un** des sites d'émission de
`800` dans l'arbre, en est aujourd'hui l'exemple.

**Le nom est `UNANSWERABLE`, et il est le même aux six cent soixante-huit
sites.** Ce n'est pas un nom par nombre : c'est le nom que la règle par
signification produit ici, parce que les six cent soixante-huit sites ont UNE
seule signification, et elle est une POSTURE et non une condition — *ce
produit ne répond pas à la demande telle qu'elle a été posée, et il n'y
publi aucune réponse*. `abi.nova` l'écrit en une phrase, à l'endroit où la
distinction avec un verdict compte : *« 800 means the query was malformed, 0
means the answer is no. »* Le nom ne peut pas être « entrée malformée », parce
qu'un identifiant suspendu n'est pas une entrée malformée ; il ne peut pas
être « hors domaine », parce qu'un tampon trop court n'est pas hors domaine.
*La preuve que ces formes n'en font qu'une est dans le code et non dans une
dérivation* : quatorze modules portent, caractère pour caractère, le même
prologue — `if tree.ok==false||tree.node_count==0||len(out)<4{return 800;}` —
et `clobbers.nova` en fait de même en quatre clauses sur une ligne. Quatre
refus de structures différentes, un seul `return 800;`, écrit quatorze fois à
l'identique par les auteurs du projet lui-même.
*Le split n'est donc pas mérité*, et le critère le disqualifie de lui-même :
`800` ne publie aucun verdict, donc il n'y a rien en aval sur quoi brancher.
**Aucune valeur émise ne change** : le nom est un nom, il ne renumérote rien.

**Ce qui reste imprécis, énoncé et non réparé.** Pour les lecteurs — `nxo`,
`pe_inspect`, `ntir_inspect` — `800` couvre aussi « les OCTETS que vous m'avez
demandé de lire sont malformés », où le pointeur de l'appelant était bon et le
contenu ne l'était pas ; `UNANSWERABLE` couvre ce cas-là également, et un
appelant qui doit séparer « votre pointeur est faux » de « vos octets sont
faux » ne le peut toujours pas. Là où l'arbre veut une distinction sous un
code, il l'écrit dans le MOT DE RAISON : `800` l'emploie déjà, aux
vingt-quatre sites `fail(env,800,reason,…)` de `macro_expand`, avec les seules
raisons `1` et `2`. **Le résiduel honnête est donc un vocabulaire de raisons à
écrire sur la bande, et non un code à frapper** — et les raisons ne changent
aucune valeur émise.

La borne `386` remplace la borne `365` que ce registre portait jusqu'ici. La
plage était fausse dès avant l'entrée de `305` et `306` : la bande d'hygiène des
macros occupe `370`–`386` et était déjà publiée, gardée par la gate
`macro_expand`, hors de la plage déclarée. Le commentaire de bande de
`stub_table.nova` s'appuyait alors explicitement sur « the frozen Nova semantic
band 300-365 » pour placer `305` et `306`. **Ce commentaire a été corrigé le
27 septembre 2026 et ne porte plus `365`** : il nomme aujourd'hui « the Nova
semantic band: 300 to 386 » (`stub_table.nova:34`), y marque le `365` comme
CADUQUE et écrit la raison à `:35-38`. La borne basse reste `300`
parce que l'énumération de l'oracle C
(`compiler/c/ntasm/frontend/frontend.h:39-42`) possède déjà `300`, `301`, `302` et
`303`. Aucun code Nova de `301`, `302` ou `303` n'est publié ; `300`, lui, l'est,
par `semantics.index` — voir la table qui suit. La valeur `386` ci-dessus n'est
pas reprise d'un rapport : elle est vérifiée par la gate `registry`, qui lit les
bornes `300`-`386` et `800`-`844` dans la table des schémas de cette section, les
compare aux bornes réellement publiées et émises dans l'arbre, et échoue si l'une
des deux directions ne tient pas.

**Portée de la recherche qui produit la table.** La liste ci-dessous vient d'une
recherche de tout littéral `3xx` sur les modules `*.nova` du répertoire
`compiler/nova/`, puis d'un tri qui sépare les **émissions** — une
affectation `code=3xx`, un `fail(env,3xx,…)`, un `return 3xx` — des simples
mentions. Trois lectures ne sont pas des publications et sont nommées ici pour
qu'un lecteur futur ne les redécouvre pas comme des codes : `304`, `308` et `392`
sont des **offsets d'octets dans un buffer**, dans `pe.nova:129` et `:131` ;
`303` n'apparaît que dans un commentaire de `stub_table.nova:33` ; et les
modules de `tests/nova/tests/` répètent les nombres de la passe qu'ils
entrent, comme `tests/control-flow-entry.nova:20-21` répète `335` et `336` dans
son commentaire de sonde. Aucun de ces quatre cas ne publie un code.

Répartition **complète** des familles sémantiques publiées dans l'arbre, avec la
gate qui les prouve. Cette table ne couvre pas seulement les familles dont la
publication a été contestée : elle couvre **tous** les codes `3xx` que
l'arbre publie, et cette phrase est la réponse à la question que l'ancienne
version de ce registre posait sans y répondre.

| famille | propriétaire | raisons | gate qui la prouve |
| --- | --- | --- | --- |
| `300` | `semantics.index` | aucune ; ligne et colonne du second nom **de fonction** (kind 18) dans le module — `duplicate_function` (`frontend.c:2950`) ne consulte que `p->functions`, jamais les variables, et la section n'entre pas dans la comparaison. Le refus équivalent sur les **données** relève de `319`, pas de `300` | `semantics` |
| `305` | `stub_table.check`, `measure`, `plan_for`, `lower` | `1`–`23`, les vingt-trois raisons et ses quatre propriétaires — `check`, `measure`, `plan_for`, `lower` — sont tous dans `stub_table.nova:796-1063` | `stub_table` 1445/1445, 707 cas, un cas par raison |
| `306` | `stub_table.lower` et `stub_table.plan_for` | `1`–`3` sur `lower`, `4`–`5` sur `plan_for` ; `lower` et `plan_for` ne publient jamais la même raison | `stub_table` 1445/1445, 707 cas |
| `310` | `calls.check`, `ntasm_refs.resolve` | aucune ; ligne et colonne du premier nom de callee absent. `refs` blâme le qualificatif lui-même quand le nom a plusieurs segments, plutôt que d'accepter le dernier seul | `calls`, `refs` |
| `311` | `calls.check` | `out[2..3]` = arité attendue puis arité reçue ; `out[4]` porte la raison et `out[5]` l'index, dans le vocabulaire de `call_types` | `calls` |
| `313` | `callable_names.check` | aucune ; ligne et colonne du second nom appelable global | `callable_names` |
| `314` | `parameters.check` | aucune ; ligne et colonne du second nom de paramètre dans une même déclaration | `parameters` |
| `315` | `locals.check` | aucune ; ligne et colonne du second nom dans un même bloc | `locals` 42/42, 13 cas |
| `316` | `bindings.check` | aucune ; ligne et colonne du mot-clé `let` | `bindings` 45/45, 14 cas |
| `317` | `register_bindings.check` | aucune ; ligne et colonne du second `@registre` explicite d'une même famille physique dans une déclaration | `register_bindings` |
| `318` | `register_widths.check` | aucune ; ligne, colonne, largeur attendue du type puis largeur obtenue du registre | `register_widths` |
| `319` | `symbol_names.check` | aucune ; ligne et colonne du second nom **dans le même des deux espaces de noms disjoints** — espace appelable : nom de fonction (kind 18) ou alias d'import (kind 9) ; espace lien : nom de donnée (kind 24) ou de constante (kind 10). Un nom de fonction et un nom de donnée **peuvent** coïncider, et l'oracle les compile | `symbol_names` |
| `320` | `clobbers.check` | aucune ; ligne et colonne du second nom d'une même famille physique dans un même set | `clobbers` |
| `321` | `effects.check` | `1` nom d'effet inconnu, `2` argument sur un atome, `3` espace mémoire hors catalogue, `4` groupement malformé | `effects` |
| `322` | `effects.check` | aucune ; second doublon sémantiquement identique dans un même set | `effects` |
| `323` | `contracts.check` | `1` nom de prédicat hors catalogue, `2` nom qualifié | `contracts` |
| `324` | `contracts.check` | aucune ; arité fausse du prédicat, attendu et obtenu en sortie | `contracts` |
| `325` | `call_effects.check` | `out[2]` = catégorie `1` atomes, `2` lectures, `3` écritures ; `out[3]` = le bitset manquant | `call_effects` |
| `326` | `call_contracts.check`, et `control_flow.check` pour la seule famille 4 | `out[2]` = famille résolue, `out[3]` = ordinal du prédicat dans le set du callee. `control_flow` réémet cette forme, avec la famille 4 en dur, pour le seul cas qu'il prend en charge | `call_contracts` (2052/2052, 511 cas) (**compteur remesuré par le jumeau à chaque exécution et confronté à la valeur écrite ici : il est vérifié, pas figé**) ; `control_flow`. **Ce que la gate établit, et qui ne bouge pas :** `call_contracts` refuse une déclaration `clobbers` qui omet un registre ou un effet que le callee écrit, refuse un `call_indirect` dont le rôle ne correspond pas, et refuse l'écriture de `rsp` par un corps — la restauration se fait par `mov rsp,rbp` en tête d'épilogue, jamais par un équilibrage de `push` (voir le paragraphe sur `346`) |
| `327` | `abi.check` | `1` nom inconnu sur `default_abi`, `2` nom inconnu sur une clause `abi`, `3` second `default_abi` | `abi` |
| `328` | `abi.check` | `1` plus de quatorze paramètres, `2` cinquième paramètre `in` sans `@GPR`, `3` `out`/`inout` sans registre explicite, `4` `@GPR` inconnu du catalogue, `5` famille de sortie réservée, `6` cette famille aussi dans `clobbers`, `7` collision avec l'affectation par défaut | `abi` |
| `329` | `abi.check` | `1` type d'un `out`/`inout` qui n'est pas un entier machine, `2` pointeur lié à une largeur autre que 64 bits | `abi` |
| `330` | `clobbers.check` | aucune ; nom de registre inconnu ou qualifié, à la ligne et colonne de ce nom | `clobbers` |
| `331` | `call_clobbers.check` | `out[2]=1` ; `out[3]` = le bitset des familles manquantes | `call_clobbers` |
| `332` | `body_effects.check` | `out[2]` = catégorie `2` lectures ou `3` écritures ; `out[3]` = le bit d'espace manquant | `body_effects` |
| `333` | `body_effects.check` | aucune ; ligne et colonne du nœud responsable, qui est l'opérande mémoire, le nom d'espace ou le nom d'élément selon ce qui est illisible | `body_effects` |
| `334` | `body_intrinsics.check` | `out[2]=1` ; `out[3]` = le bitset des atomes exigés et non déclarés | `body_intrinsics` |
| `335` | `body_clobbers.check` | `out[2]=1` ; `out[3]` = le bitset des familles requises et non déclarées | `body_clobbers` |
| `336` | `body_clobbers.check`, `body_effects.check`, `control_flow.check` | aucune dans les trois ; ligne et colonne de la destination qui n'est pas un registre, du pseudo-op sans encodeur, ou de l'opérande mémoire que l'oracle n'ancre pas. Les trois publient le même nombre pour trois refus de même nature, et c'est délibéré | `body_clobbers`, `body_effects`, `control_flow` |
| `337` | `control_flow.check` | aucune ; un `return` dans une fonction `never`, à la ligne et colonne du `return` | `control_flow` |
| `338` | `control_flow.check` | `1` corps d'une fonction à valeur qui tombe de sa fin, `2` corps d'une fonction `never` qui tombe de sa fin ; ligne et colonne de la fonction | `control_flow` |
| `339` | `control_flow.check` | aucune ; `return` nu dans une fonction à valeur | `control_flow` |
| `340` | `control_flow.check`, `pointer_spaces.check` | `control_flow` : `1` première instruction qu'un fallen-through n'atteint pas, après une instruction terminale ou un `jmp` inconditionnel, `2` après un call à une fonction `never`. `pointer_spaces` : aucune raison, un espace de `ptr<espace,T>` hors du catalogue du §7. Les deux publient le même nombre pour deux refus de nature différente | `control_flow`, `pointer_spaces` |
| `341` | `features.check`, `feature_requirements.check` | aucune ; nom de feature inconnu ou qualifié | `features` |
| `342` | `features.check` | `1` doublon d'une feature autre que `lm` dans un même set, `2` second set `features` | `features` |
| `343` | `feature_requirements.check` | aucune ; `feature(x)` malformé ou hors catalogue | `feature_requirements` |
| `344` | `feature_requirements.check` | aucune ; feature connue du catalogue mais absente du masque du module | `feature_requirements` |
| `345` | `targets.check` | aucune ; triple de cible inconnu | `targets` |
| `346` | `targets.check` | aucune ; le compte de nœuds de target n'est pas 1, publié à ligne 1 colonne 1. **Voir le paragraphe sur `346`** | **aucun cas** |
| `347` | `versions.check` | `1` domaine inconnu, `2` domaine dupliqué ou second bloc `versions` | `versions` |
| `348` | `versions.check` | `out[2..3]` = le majeur et le mineur lus | `versions` |
| `349` | `versions.check` | `out[2]` = le masque des domaines effectivement vus, sur un bloc incomplet | `versions` |
| `350` | `types.check` | aucune ; nom de type scalaire hors du catalogue fermé | `types` |
| `351` | `types.check` | aucune ; longueur de tableau nulle | `types` |
| `352` | `return_types.check` | aucune ; le type rendu ne correspond pas au type déclaré | `return_types` |
| `353` | `return_types.check` | `1` littéral hors plage, `2` forme d'expression non prouvée | `return_types` |
| `354` | `call_types.check` | `1` type d'argument incompatible, `2` argument hors plage, `3` argument non prouvé, `4` argument en trop, `5` argument en moins | `call_types` |
| `355` | `literal_initializers.check` | aucune ; initialiseur littéral de catégorie ou de type incompatible | `literal_initializers` |
| `356` | `literal_initializers.check` | aucune ; littéral hors plage du type déclaré | `literal_initializers` |
| `357` | `condition_types.check` | `1` littéral entier nu ; sinon le statut de `initializer_types.bool_status` moins 100 | `condition_types` |
| `358` | `condition_types.check` | le statut de `initializer_types.bool_status` moins 200 | `condition_types` |
| `359` | `initializer_types.check` | `1` type prouvé différent du type déclaré, `2` statut d'entier nul ou hors plage | `initializer_types` |
| `360` | `initializer_types.check` | `1` nom non résolu, `2` type de retour d'un call non résolu, `3` forme non prouvée | `initializer_types` |
| `361` | `constant_types.check` | aucune ; catégorie ou type d'initialiseur de `const` incompatible | `constant_types` |
| `362` | `constant_types.check` | aucune ; valeur constante évaluée hors plage du type déclaré | `constant_types` |
| `363` | `constant_types.check` | aucune ; expression non constante ou forme hors du vocabulaire de l'évaluateur | `constant_types` |
| `364` | `control_flow.check` | `1` `N` qui n'est pas une puissance de deux positive, `2` puissance de deux que l'ABI n'autorise pas, `3` `rsp` qu'aucun `load` ne type comme une pile dans l'espace courant, `4` retour normal avec le déplacement encore en attente, `5` transfert terminal avec lui. `out[3]` est le `N` du plus grand `align_stack` vu, et le §10.1 dit pourquoi ce n'est pas une taille | `control_flow` |
| `365` | `call_contracts.check` | `1` ; l'ordinal du prédicat est publié séparément en `out[3]` | `call_contracts` (**volatil par construction** : le compte appartient à la sortie de la gate, et la citer ici la rendrait fausse à chaque amélioration) |
| `366` | `abi.obligations` — **une REQUÊTE, pas une étape du pipeline : aucun appel depuis `validate.nova` à ce jour** | `1` sujet de prédicat `requires`/`ensures` qui est un nom nu ne nommant aucun paramètre de la déclaration ; `2` mot de direction illisible, c'est-à-dire ni `in` ni `out` ni `inout` ; `3` paramètre `out`/`inout` sans `@GPR` explicite, donc sans lieu où restituer. `out[0..1]` est la ligne et la colonne, `out[2]` la raison, et la COMPTABILITÉ des lignes est dans un MOT RÉSERVÉ distinct de toute valeur de direction — les deux partageaient `out[0]` et `in` est aussi le nombre 1, donc tout cas à un seul paramètre lisait `dir=1` | `directions` — **compteur NON MESURÉ par le registre : cette porte n'a ni jumeau in-process ni entrée dans `COVER[]`, donc son nombre ici n'est vérifié par rien.** La porte existe et l'affirmation porte sur le refus, pas sur le compte |
| `367` | `abi.fact_validity` — **une REQUÊTE, pas une étape du pipeline : aucun appel depuis `validate.nova` à ce jour** | aucune raison : le refus est la RÉPONSE ENTIÈRE et il **n'écrit RIEN**. Le parcours des faits n'a pas pu aboutir — cycle, ou limite d'analyse — donc il ne peut pas dire quels faits il avait déjà purgés ; un lecteur qui recevrait la moitié créditerait la moitié d'un résumé faux pour le cas récursif et juste pour le cas acyclique. `out[0..2]` ne sont écrits que sur une réponse DÉCIDÉE | `read_write` |
| *(aucun code — contrôle de forme)* | `validate.prune` et `validate.spliced_shape` | aucune ; cette gate ne publie **aucun** code de diagnostic et n'ajoute donc aucune famille à ce tableau. Elle mesure que la table d'identifiants publiée ne contient aucun identifiant de kind 0, que tout identifiant publié est un nœud que la racine atteint, et que l'IR accepte tout arbre que le pipeline accepte. **C'est un substrat de mesure et non une famille de codes** : la ligne est ici pour que sa présence ne se lise pas comme un code omis. **Elle porte aussi le résiduel `817` du §13** — cinq fixtures sur trente-neuf, dont trois où le pipeline répond `0` | `splice` 609/609, 50 cas (**compteur volatile**) |
| `370`–`381`, `386`, plus `201` et `203` | `ntasm_macro_expand.expand` | `201` raison `1`–`6` pour les six budgets de comptime, `203` sans raison ; puis `370` `1`–`2`, `371` `1`, `372` `1`–`6`, `373` `1`, `374` `1`, `375` `1`–`3` et `9`, `376` `1`–`2`, `377` `1`–`7`, `378` `1`, `379` sans raison propre, `380` `1`–`2`, `381` `1`, `386` `1`. La liste des codes est celle de `macro_expand.nova:114-131`, celle des raisons celle de ses appels `fail` | `macro_expand` |
| *(aucun code — contrôle de forme)* | `frontend.c` `parse_parameter` et le prédicat `NTF_X_REGISTER` de `infer` | aucune ; cette gate ne publie **aucun** code de diagnostic et **n'ajoute donc aucune famille** à ce tableau. Elle mesure que la RÈGLE du binding est une compatibilité et non une liste : lier `W` à `R` est accepté **si et seulement si** `width(R) == W` **et** `R` n'est pas un pointeur de cadre. Les 256 membres sont le produit croisé 8 largeurs × 16 familles, donc un registre nouveau demande une LIGNE et non un cas. **Le contrôle est imprimé à chaque course et il est en trois formes** — `nocall=0` (le binding, que la porte affirme), `call_true=0` (le binding plus le chemin d'argument, sain) et `call_int_literal=400` (un littéral ENTIER dans un paramètre `bool`) — **et les deux premiers DOIVENT concorder, sinon la porte dit qu'elle ne mesure pas le binding.** Elle **contourne** le chemin d'argument et le rend visible au lieu de le cacher. **Elle ne teste pas la clause du chemin des macros**, qu'aucun programme atteint : copie non couverte, et rien n'est affiré dessus. | `reg_width_binding` 258/258, 257 cas |

**`201` a trois propriétaires, et deux de ses trois lectures ne se recouvrent
pas.** Le tableau ci-dessus ne donne que le premier. `201` est `NTF_E_LIMIT` dans
l'oracle
(`frontend.h:38`), et trois modules Nova le publient avec trois vocabulaires de
raisons distincts et non interchangeables :

- `lexer.limited` publie `201` avec les raisons `11`, `12` et `13` de la limite
  de lexing (`lexer.nova:32-35`, appelé à `:67`, `:99` et `:217`) ;
- `ntasm_macro_expand.expand` publie `201` avec les raisons `1` à `6`, les six
  budgets de comptime ;
- `x64_lower_control` publie `201` **sans raison** pour une table de labels pleine,
  au-delà de 64 labels par appel (`x64_lower_control.nova:30` et `:89`, et la
  limite est écrite dans son en-tête à `:13-14`).

Un même nombre, trois significations, aucune passerelle entre elles. C'est
exactement la situation que la double possession de `300`–`303` crée déjà avec
l'oracle, et elle doit se lire comme telle : le registre donne le propriétaire
d'un code, il ne garantit pas qu'un lecteur qui reçoit `201` sache qui l'a
émis. La distinction par le message, plus bas, est la seule qui reste sûre.

**`346` est publié mais ni observable ni gardé.** `targets.check` l'émet quand le
compte de cibles n'est pas 1 (`targets.nova:5`). Deux faits le rendent
inobservable aujourd'hui, et ils sont énoncés pour qu'on ne le prenne pas pour une
gate manquante par oubli : le parseur exige une cible et en consomme exactement
une avant toute analyse sémantique (`compiler/nova/frontend/parser.nova:631-633`, et un module sans
cible y échoue en `200`), et la gate `targets` ne comporte **aucun** cas pour ce
nombre — elle n'asserte que `345` et `800` sur les diagnostics, plus les deux
entrées nominales
(`tests/c/nova/tests_ntasm_targets.c:12-14`). La colonne « gate »
de sa ligne dit donc `aucun cas`, et c'est la réponse exacte.

Sont non attribués, et ne doivent donc pas être émis : `301`, `302`, `303`,
`304`, `307`, `308`, `309`, `312`, `368`, `369`, `382`–`385`, et
tout `387` ou au-delà. Cette énumération résulte de la recherche de portée
détaillée plus haut ; elle est une affirmation sur l'état de l'arbre à la date
de ce registre, pas une garantie structurelle. **Un code publié qui n'a pas de
ligne dans la table ci-dessus ne peut pas l'être** : la table est exhaustive sur
la bande `3xx`, et c'est elle qui rend la règle vérifiable au lieu de
la rendre tautologique.

**`366` et `367` sont SORTIS de cette énumération le 30 septembre 2026, et la
raison est le registre lui-même :** les deux sont désormais émis, par deux
requêtes d'`abi.nova` — `abi.obligations` et `abi.fact_validity` — et chacune a
sa ligne dans la table de famille. **Les deux restent des REQUÊTES et non des
étapes du pipeline : `validate.nova` n'appelle ni l'une ni l'autre à ce jour,
et une ligne qui le disait a été retirée quand la preuve l'a contredite.** Un
code listé comme non attribué ET émis était un code dont personne n'était
propriétaire ; laisser une ligne qui le disait était une contradiction de la spécification, et c'est le registre qui l'a nommée, pas moi.

Règles de lecture :

- un code S0 ne doit jamais être réutilisé par Nova, et un code Nova ne doit
  jamais être réutilisé par S0 : les deux espaces sont disjoints par
  construction, pas par convention ;
- la bande `4xx` de l'encodeur et la bande `3xx` de Nova sont **disjointes**, et
  c'est intentionnel : `x64_fixed` rend les diagnostics de son propre oracle,
  qui possède `401`–`412`, et rien n'oblige ses codes à tomber dans la bande
  sémantique. Le texte de ce registre les disait « partiellement
  recouvrants » ; ils ne se recouvrent pas, et la formulation était fausse ;
- le recouvrement réel est avec l'énumération du frontend C, et il existait avant
  ce registre : `NtFError`
  (`compiler/c/ntasm/frontend/frontend.h:36-53`) possède `100`, `200`, `201`,
  `300`–`303`, `400`–`403`, `500`–`504`, `600` et `900`, et quatre de ces nombres
  sont réémis par Nova : `100` et `900` par le lexer
  (`compiler/nova/frontend/lexer.nova:30` et `:232`), `200` par le parseur
  (`parser.nova:32`) et `300` par `semantics.index` (`semantics.nova:87`).
  **Ce document n'affirme pas** que les vocabulaires de raisons coïncident avec
  ceux du frontend C : il constate la coïncidence des nombres, qui est vérifiable,
  et laisse la comparaison des raisons hors de portée. `300` est donc réellement
  publié par Nova, et l'ancienne ligne de schéma qui disait que Nova « ne possède
  pas `300`–`303` » se contredisait dans la même phrase en rendant `300` « à
  l'identique » ; la formulation est remplacée ci-dessus. `301`, `302` et `303` ne
  sont en revanche publiés par aucun module Nova, et `stub_table.nova:33-34` les
  laisse intacts pour cette raison. Un nouveau code Nova dans `304`–`399`
  n'appartient pas à l'oracle : il occupe un intervalle que l'oracle ne possède
  pas, ce qui est la situation de `305`, `306` et de toute la bande d'hygiène des
  macros ;
- `201` est le seul code que Nova publie à la fois dans le vocabulaire de l'oracle
  et dans un vocabulaire qui n'est pas le sien, et il a trois propriétaires
  comme il est dit plus haut. C'est le recouvrement le plus dangereux du
  registre, parce qu'il est invisible dans la plage alors qu'il est réel ;
- la bande `8xx` décrit un **refus de lecture** ou un **refus de capacité**, jamais
  un diagnostic de source : la position et l'objet sont dans le log, pas dans un
  span source. Cette ligne était trop étroite, qui disait « lectures d'objets NXO
  et d'images PE » alors que `820` et `821` sont aussi publiés par
  `x64_lower_control`, l'un pour un label dupliqué et l'autre pour un label non
  résolu, qui sont deux diagnostics de source ;
- les schémas ne sont pas de même génération. Un lecteur ne doit jamais
  traduire un code d'un schéma vers un autre : la traduction se fait par
  le message, jamais par le nombre. C'est la seule règle qui survit à `201` et à
  `300` ;
- le schéma `G-*` cité dans les audits de septembre 2026 est hors du périmètre
  gelé : aucun fichier de `spec/`, `toolchain/` ou `bootstrap/` ne porte de code
  de cette forme, et il n'est donc pas vérifié ici. Il ne doit être ni publié
  ni consommé tant qu'un document d'arbitrage n'aura pas désigné un porteur.

Ce registre décrit l'état observé. Il ne prouve pas que les cinq schémas
soient compatibles entre eux, et il n'autorise pas à publier un code sans
l'entrée correspondante dans la table des familles.

### 17.7 Ordre des passes du pipeline Nova — gelé

Le pipeline est une chaîne à arrêt au premier refus : `validate.stages` est une
suite de blocs `if code==0` et chaque passe n'est appelée que si toutes les
précédentes ont rendu zéro (le corps de la fonction est
`compiler/nova/analysis/validate.nova:109-209`, précédé de son commentaire d'ordre
à `:99-108`). Il
y a donc trente-quatre passes, et l'ordre n'est pas décoratif : il fixe le
diagnostic qu'un module portant plusieurs défauts reçoit, et une seule de ces
trente-quatre a en plus une vraie dépendance de données.

Le compte est contrôlé par machine, et il en va de même de l'**ordre** depuis
l'export `validate.stage_table`. `validate.validate` écrit `out[0]=34` en succès
(`compiler/nova/analysis/validate.nova:298`) et la gate `validate` l'exige
(`tests/c/nova/tests_ntasm_validate.c:14`, et `:37` pour le
variante à six mots — la ligne 36 est la fin du commentaire qui le précède). Cette
borne a remplacé `33` quand l'expansion est devenue
la première passe ; le harnais l'atteste en clair
(`tests_ntasm_call_contracts.c:33-37`).

**L'ordre est contrôlé par machine, et cette phrase est plus forte que ce qu'elle
était.** `validate.stage_table` exporte les trente-quatre noms de passes dans
l'ordre du pipeline, séparés par NUL
(`compiler/nova/analysis/validate.nova:220-227`), et la gate `validate` les compare
**octet pour octet** à une liste de trente-quatre noms qu'elle porte
elle-même (`tests_ntasm_validate.c:49-49`, `expect_stage_order`, appelé à
`:459`). Un nom ajouté, retiré ou déplacé échoue donc à la gate et plus
seulement à la revue. Le chemin qui y mène est le mode 1 du point d'entrée de
test : le septième mot de `out` vaut `1`, la table est copiée dans le tampon
source que le caller prête en écriture et son nombre d'octets revient en `out[0]`
(`tests/nova/tests/validate-entry.nova:19-27`). Le mot septième est un
sélecteur sûr parce qu'aucune passe du pipeline ne l'écrit et qu'aucun caller de
quatre, cinq ou six mots ne peut l'atteindre. Le tableau de ce paragraphe est
donc une revue, mais il n'est plus le seul gardien de l'ordre : il l'est encore
de la **forme** de chaque ligne, que la table ne porte pas.

| n | passe | point d'entrée | classe de la dépendance |
| --- | --- | --- | --- |
| 1 | expansion des macros | `ntasm_macro_expand.expand`, via `validate.expand_stage` | **donnée** |
| 2 | index sémantique | `semantics.index` | précédence |
| 3 | target | `targets.check` | précédence |
| 4 | versions | `versions.check` | précédence |
| 5 | features | `features.check` | précédence |
| 6 | noms appelables | `callable_names.check` | précédence |
| 7 | noms de symboles | `symbol_names.check` | précédence |
| 8 | types | `types.check` | précédence |
| 9 | types de constantes | `constant_types.check` | précédence |
| 10 | initialiseurs littéraux | `literal_initializers.check` | précédence |
| 11 | paramètres | `parameters.check` | précédence |
| 12 | locals | `locals.check` | précédence |
| 13 | bindings | `bindings.check` | **donnée** (vers la passe 30) |
| 14 | liaisons de registres | `register_bindings.check` | précédence |
| 15 | largeurs de registres | `register_widths.check` | précédence |
| 16 | clobbers | `clobbers.check` | précédence |
| 17 | ABI | `abi.check` | précédence |
| 18 | espaces de pointeur | `pointer_spaces.check` | précédence |
| 19 | effects | `effects.check` | précédence |
| 20 | effects de corps | `body_effects.check` | précédence |
| 21 | intrinsics de corps | `body_intrinsics.check` | précédence |
| 22 | clobbers de corps | `body_clobbers.check` | précédence |
| 23 | flux de contrôle | `control_flow.check` | précédence |
| 24 | types de retour | `return_types.check` | précédence |
| 25 | contrats | `contracts.check` | précédence |
| 26 | prérequis de features | `feature_requirements.check` | précédence |
| 27 | résolution des références | `ntasm_refs.resolve` | précédence |
| 28 | calls | `calls.check` | précédence |
| 29 | types de call | `call_types.check` | précédence |
| 30 | types d'initialiseurs | `initializer_types.check` | précédence |
| 31 | types de condition | `condition_types.check` | précédence |
| 32 | effects au call | `call_effects.check` | précédence |
| 33 | clobbers au call | `call_clobbers.check` | précédence |
| 34 | contrats au call | `call_contracts.check` | précédence |

**Donnée, passe 1.** C'est la seule passe dont l'exécution change ce que les
suivantes lisent. Elle peut remplacer l'arbre et la source : `expand_stage`
construit `Splice`, `build_text` ajoute la table de noms du produit à une copie
privée de la source, et les 33 passes reçoivent alors `unit_of(s)` et `s.text`
plutôt que l'arbre du caller (`macro_splice.nova:139-139`, `unit_of`).
Sans elle, toutes les passes de types et de contrats verraient un template. La
raison normative est le §13 : une macro est développée avant la vérification
finale des types et des contrats. La passe propage son diagnostic tel quel —
`201` garde la raison de budget, `203` garde la taille requise, `800` garde le
refus structurel, et chaque code d'hygiène `3xx` atteint le caller inchangé
(`macro_splice.nova:478-481`).

**Donnée, passe 13 avant passe 30.** `bindings.check` ne lit rien et n'écrit
rien que `initializer_types` ne sache refaire; la dépendance est sémantique, pas
de flux. `initializer_types.visible_type_id` ne renvoie le type d'un paramètre
que lorsque **aucun** bloc contenant l'usage ne déclare le nom
(`compiler/nova/analysis/types/initializer_types.nova:75-76`). Cette branche de repli ne
nomme donc un paramètre que parce que `316` a déjà refusé tout `let` qui pourrait
rendre la lecture ambiguë, dans le corps et dans tout bloc imbriqué (§5.1).
Inverser les deux passes rendrait le repli faux dans les deux sens : un `let`
masquant un paramètre serait typé depuis le paramètre, et un `let` d'un bloc
externe serait lu comme un paramètre lorsque l'usage le précède. `316` est donc
une condition de correction de `visible_type_id`, pas un diagnostic de confort.

**Précédence, tout le reste.** Aucune autre passe n'écrit `tree.node_words` : la
seule écriture de nœuds de l'arbre dans l'arbre est celle de `macro_expand`, et
elle vise le tampon qu'il produit, pas l'arbre du caller. Chaque passe lit
`source`, `tree` et son propre scratch, et le scratch est remis à zéro entre deux
passes (`validate.nova:90` et suivantes). Un grand nombre de passes sont en
outre **auto-suffisantes** : elles relisent elles-mêmes ce dont elles ont besoin
et propagent le code qu'elles obtiennent. `feature_requirements.check` appelle
`features.check` et rend `341`/`342` lui-même
(`compiler/nova/analysis/abi/feature_requirements.nova:15`) ; `call_contracts.check`
compose lui-même les deux moitiés de chaque garde (§8.3)
(`compiler/nova/analysis/calls/call_contracts.nova:43-51`). Pour ces passes,
l'ordre ne change rien à ce qui est prouvé : il change seulement le code
renvoyé.

Les précédences qui sont tout de même requises, avec leur raison :

| précédence | raison |
| --- | --- |
| 5 `features` avant 26 `feature_requirements` | `341`/`342` sur un nom de feature doivent être rapportés par la passe qui possède le catalogue, pas par celle qui en consomme le masque |
| 11 `locals` avant 13 `bindings` | un bloc qui porte à la fois un doublon et une collision avec un paramètre rend `315` |
| 12 `locals` et 13 `bindings` avant 30 `initializer_types` | voir ci-dessus ; c'est la seule vraie dépendance |
| 16 `clobbers` avant 17 `abi` | `328` raison 6 teste l'absence d'une famille dans `clobbers`, et une famille non conforme (`320`/`330`) doit parler avant |
| 19 `effects` avant 20/21/22 | une déclaration d'effets mal formée (`321`/`322`) doit parler avant l'écart entre le corps et la déclaration |
| 25 `contracts` avant 34 `call_contracts` | un nom de prédicat hors catalogue rend `323` et une arité fausse `324`, jamais `326` ; c'est ce qui rend la famille `5` inatteignable par le pipeline (§17.3) |
| 27 `ntasm_refs` avant 34 `call_contracts` | une référence absente rend `310` avant qu'une preuve de contrat ne soit tentée sur elle |
| 20/21/22 et 32/33 avant 34 `call_contracts` | **raison de diagnostic, pas de correction.** Un caller dont le corps ment sur sa déclaration est refusé par la passe qui possède le mensonge — `332` pour un `store` non déclaré, `334` pour un `cli` non déclaré, `335` pour un `rsp` déplacé — et `call_contracts` ne le voit jamais. C'est vérifié dans les deux modes par la gate `call_contracts` : en mode pipeline les quatre mensonges et leur version honnête sont à `tests_ntasm_call_contracts.c:185-195` (les `stage(&image,…)` et `stage(&vimage,…)`) puis `:198-209` (les `ok` et `okv`) ; en mode point d'entrée nu, le mode `1` seul, le bloc est à `:218-277` (les `aerrp` et `aok`), précédé de son commentaire à `:210-217` |

La dernière ligne est la seule où la documentation du code et le code
dispersent, et la dispersion était réelle au moment où ce paragraphe a été écrit.
Elle est en train d'être refermée, et le §8.3 a été réécrit pour ne dépendre
d'aucun de ces commentaires. Ce qui reste, en date :

- `call_contracts.nova:10-53` est exact sur le principe — le point d'entrée est
  honnête seul, les cinq passes sont « a defence in depth over a local check
  rather than the thing that makes it sound » ;
- le même module affirmait encore « The body halves under-approximate nothing »
  et « one of the three instructions that move rsp without naming it », alors que
  la fonction qui suit en nommait cinq et non trois. Ces deux phrases sont
  remplacées par la règle complète et datée du §8.3, qui est celle de l'oracle ;
- le commentaire de
  `tests/c/nova/tests_ntasm_call_contracts.c:174-183` disait que le
  garde « is sound only once » les cinq passes avaient composé le corps et
  qu'« a standalone call_contracts.check … reads the declaration, never the
  body ». La gate elle-même exerce cette entrée seule, avec les deux corps que le
  §8.3 nomme (`tests_ntasm_call_contracts.c:289-293` et `:302-308`, cas adverses
  « HOLE 1 » et « HOLE 2 »). Ce commentaire est un fichier `.c` hors du
  périmètre de ce document : il est **signalé et non corrigé**.

La seule chose qui reste vraie du commentaire de gate est sa première phrase :
dans le mode pipeline, ces sources sont rendues avec le code de la passe qui
possède le mensonge, et `call_contracts` ne les voit pas.

**Contrôle machine de l'ordre : appliqué, et différent de celui qui était
proposé.** Le paragraphe qui occupait cette place proposait trois choses :
`validate.nova` exporterait une table de noms de passes dans l'ordre, `validate`
publierait sa longueur en `out[3]`, et une assertion unique du harnais
comparerait cette table à la liste de ce paragraphe. Les trois sont datées, et
elles n'ont pas été faites de la façon proposée :

- l'export existe, sous le nom `stage_table`, et il ne touche pas au harnais
  (`validate.nova:220-227`) ;
- la longueur n'est **pas** publiée en `out[3]`, qui reste le zéro de réserve
  (`validate.nova:301`), et la gate l'asserte ainsi
  (`tests_ntasm_validate.c:37`, `... || r.out[3] || ...` — l'assertion `out[3]`
  est dans `okw`, la ligne 36 étant la fin de son commentaire). La longueur voyage
  par le mode 1 du point d'entrée de test, dans le tampon source et en `out[0]`
  de ce mode, où le nombre d'octets est aussi le contrôle du compte
  (`tests/validate-entry.nova:19-27`, `tests_ntasm_validate.c:44-45`) ;
- l'assertion existe, et elle compare les octets : `expect_stage_order` reconstruit
  la table à partir d'une liste de trente-quatre noms qu'elle porte et la compare
  à ce que le module publie (`tests_ntasm_validate.c:38-45`, appelé à `:284`).

Ce qui reste vrai de la réserve d'origine, et qui est donc la seule chose à
retenir de ce paragraphe : la table compare des **noms**, pas des signatures. Elle
ne dit pas que la passe nommée est celle qui est appelée, ni que la classe de
dépendance déclarée plus haut est vérifiée. La chaîne `if code==0` de
`validate.stages` reste écrite à la main, et le « stage table » que le module
`diagnostics` réclame pour la remplacer n'existe pas
(§17.8, dernier paragraphe).

### 17.8 Tables de stubs structurés et substrat de diagnostics — ce qui est fermé

`stub_table` est implémenté et gardé par la gate `stub_table` (1445/1445, 707 cas),
mais il **n'est appelé par aucune passe du pipeline du §17.7** : il n'est importé
que par son propre point d'entrée de test. La gate `validate` ne contient aucun
cas `stub_table`. Ce qui suit décrit donc un générateur livré et non branché, et
non une passe du produit.

Ce que `stub_table` ferme, au sens du §11 :

- la forme déclarative est lue depuis l'AST, jamais reconstruite par
  concaténation de texte et jamais re-lexée ; le module le déclare lui-même
  (`compiler/nova/frontend/stub_table.nova:6-10`) ;
- les vingt-trois règles de déclaration sont vérifiées et localisées, en `305`
  avec la raison qui va avec (`stub_table.nova:796-804`), un cas de gate par
  raison ;
- l'ordre canonique numérique des entrées est établi, et les doublons comme les
  trous interdits sont refusés en `305` raisons 3 et 16 avant toute émission
  (`stub_table.nova:878-896`) ;
- l'abaissement produit des **records entiers** de seize mots par stub et un
  **plan de corps abstrait** de trois mots par étape, huit opcodes au total
  (`stub_table.nova:41-52`), et `measure` permet de dimensionner avant d'émettre
  (`stub_table.nova:963-978`).

Ce que `stub_table` ne ferme pas :

- **aucune image exécutée.** Ce point est la moitié la plus petite de ce qui
  manque, et la vague 7 l'a rétréci. `lower` n'émet toujours aucun octet, mais
  `build_pe` et `build_pe_and_write` encodent désormais le plan en x86-64,
  construisent un objet NXO fermé et écrivent un PE ; la gate le confronte à
  `nt_x64_encode` et à `nova_oracle_make_pe` sur chaque exécution. Ce qui reste
  vrai de la phrase barrée : `stub_table` ne produit **aucun nœud NTIR**, alors
  que `ntir.nova` existe désormais dans l'arbre. Ce qui est nouveau et décide
  que le point reste ouvert : l'image, écrite et épinglée, **n'a jamais été
  exécutée**. Sous OVMF le firmware charge le PE, entre dans le point d'entrée
  et n'en ressort pas ; le marqueur `NG_NTASM_C_RESULT_OK` n'a donc jamais été
  observé pour un stub structuré, ni son négatif. C'est le critère A6 seconde
  clause, et il est ouvert ;
- **aucune taille de frame.** La raison 8 de `305` vérifie que le nom de frame
  appartient au profil ; elle ne calcule aucune taille, ne place aucun registre
  et ne produit aucun offset ;
- **aucune convention callee-saved.** Les raisons 17, 21 et 22 vérifient que le
  set de sauvegarde est non vide, couvre les clobbers du handler et ne nomme que
  des registres du catalogue. Elles ne décident pas quels registres sont
  préservés par le matériel ;
- **aucune exécution.** Aucun path d'interruption ni de syscall n'a été validé
  sous QEMU, ni par ce module ni par un autre. La ligne A6 « chemins concernés
  validés sous QEMU » de `docs/status/ntasm-completion.md` reste ouverte, et elle ne
  s'est pas refermée du fait que la déclaration soit vérifiée ;
- **aucune branche du pipeline.** Un module dont la table de stubs est mal
  déclarée passe `validate`.

`diagnostics` est un **substrat**, pas une passe, et il est dans le même cas :
`diagnostics.nova:15-22` le déclare, et rien ne l'appelle.
`parser.nova` s'arrête toujours à sa première erreur et n'enregistre encore
qu'un seul diagnostic, donc la règle « Premier diagnostic par span source
canonicale » du §16 reste la règle du produit. Ce qui est livré et gardé par la
gate `diagnostics` (162/162, 77 cas) est la couche dont le parsing en flux aura
besoin : une liste bornée append-only avec refus de capacité compté et refus de
doublon d'identité comptés (`diagnostics.nova:44-104`), un ordre total par source,
span, code et raison avec une seule passe de réordonnancement
(`diagnostics.nova:115-147`), la conversion position/offset dans les deux sens
(`diagnostics.nova:184-218`), trois familles de frontières de resynchronisation
déclarées sur le vrai flux de tokens (`diagnostics.nova:308-349`), un collecteur
multi-constructions (`diagnostics.nova:456-528`) et une tranche verticale de huit
passes du pipeline qui prouve que le contrat « premier code, quatre mots de
scratch » est préservé (`diagnostics.nova:547-615`). Les points d'entrée que
`parser.nova` et `validate.nova` devront ajouter sont écrits en clair en bas du
module (`diagnostics.nova:621-651`) ; ils ne sont pas faits, et le « stage table »
que ce point réclame n'existe pas encore — la chaîne de `if code==0` du §17.7
est toujours écrite à la main. **Précision pour ne pas se tromper de mot** :
`validate.stage_table` existe et publie les noms des passes (§17.7), mais c'est
une table de noms produite pour le harnais, pas une table de passes qui pilote la
boucle. Ce que ce point réclame — un loop sur une table déclarée, qui enregistre
chaque échec dans une liste et renvoie le premier code non nul — n'est pas fait,
et c'est lui qui reste la condition pour que l'ordre du §17.7 cesse d'être une
chaîne écrite à la main.


### 17.9 Documenté mais non mesuré — registre des trous de couverture

Ajouté le 28 septembre 2026. Ce registre existe parce qu'une affirmation
normative sans contrôle mécanique est la même forme de trou que le
`registers=0` de la vague 8, une couche plus haut : une propriété dont
l'arbre dépend, que ce document énonce, et que **aucune gate ne mesurerait**.
Il est délibérément une liste courte et non une déclaration de couverture. Chaque
ligne dit ce qui est écrit ici, ce qui le mesurerait, et ce qui se passe s'il
cesse d'être vrai.

| # | affirmation écrite dans ce document | ce qui la tient aujourd'hui | propriétaire proposé |
|---|---|---|---|
| U1 | v0 définit **deux** profils d'ABI, `nx64-abi-v0` et `efi-x64-v0` (§17.5.1, §5) | **partiellement, et la seconde moitié est close.** La gate `abi` déclare désormais un profil par ligne — la table `prof_rows` à `tests/c/nova/tests_ntasm_abi.c:717-734` — et confronte deux fonctions du produit sur **les deux** noms : six lignes nx64 où elles doivent s'accorder mot pour mot, et six lignes efi, de la ligne 728 à la ligne 732, où la seconde doit refuser le nom. *Les deux numéros de cette cellule ont été rejoués le 30 septembre 2026 : ils disaient 616-634 et 627-631, exacts jusqu'à cette édition, puis périmés par l'insertion du correctif de troncature du générateur de fixture dans le même fichier.* **Ce que cela ne fait pas, et c'est ce qui reste :** l'oracle n'est pas appelé. Les colonnes de verdict de cette table sont des **littéraux** comparés au produit seul, donc supprimer le bras efi de l'oracle ne rougit toujours rien. **La moitié du §17.5.1 qui porte sur le nom est close ; la moitié qui porte sur l'accord des deux côtés ne l'est pas.** | **résidu : l'oracle.** Une ligne de plus dans cette gate, qui confronte le produit à l'oracle sur les douze lignes de la table et exige le même verdict des deux côtés. **Ce qui la changerait :** cette ligne, et rien d'autre — il n'y a pas de gate à inventer, il y a un appel qui manque. |
| U2 | le profil `efi-x64-v0` passe des arguments sur la pile, après l'espace d'ombre, à partir du cinquième | **CLOS le 30 septembre 2026 — gate `conformance_efi`.** La cause n'était pas une ligne de tableau manquante : le harnais est dans le répertoire que les deux rails ne cherchent pas, donc **invisible** et non « non enregistré ». Le détail est en prose sous le tableau. | clos — gate `conformance_efi`, déclarée dans `ROOT_GATES` |
| U3 | la frame nx64 pousse **treize** registres et son complément exact sur les seize est `{rax, rsp, rbp}` (§17.5.2) | **CLOS le 28 septembre 2026.** `scan_saved_register_copies` (`tests_ntasm_abi.c:992` — et non le numéro 685, que la citation portant ce nom portait le 29 septembre 2026 ; la fonction s'est déplacée et personne n'a rejoué le numéro) lit l'initialiseur de `codegen.c` lui-même (`codegen.c:93-94`) et confronte les deux autres écritures élément par élément, puis confronte l'ensemble à la règle et non à un littéral | clos — gate `abi` |
| U4 | une fonction sans paramètre au corps non trivial **n'a aucun producteur Nova** (§17.5) | **CLOS le 29 septembre 2026 — gate `x64_lower_nxo_function_bodies`, bloc « 33. The parameterless function that had no producer » (`tests/c/nova/tests_ntasm_x64_lower_nxo_function_bodies.c:3155`).** Cette cellule affirme une seule chose, et c'est que la gate la tient ; **les neuf fixtures, les cinq sites, la preuve négative et la correction de date sont en prose sous le tableau**, parce qu'une cellule ne peut pas porter une ligne par assertion — une ligne de tableau ne se coupe pas sur plusieurs lignes physiques | clos — gate `x64_lower_nxo_function_bodies`, bloc 33 |
| U5 | `abi.nova` suit le profil pour le nom mais **pas** pour `default_family` ni pour la borne de quatorze (§17.5.1) | **RÉFUTÉE le 29 septembre 2026 : une gate déclare un profil courant, ligne par ligne, et la borne de quatorze est confrontée sous le profil qu'elle se donne.** La table est à (`tests/c/nova/tests_ntasm_abi.c:600-634`) — la plage commence sur la ligne qui dit ce que vaut la colonne `target` et couvre la table entière — et porte un champ de profil par ligne, plus une cible qui vaut 1 pour le `default_abi` du module. **Un point que cette citation ne peut pas porter, et qu'il faut donc dire ici :** le `default_family` du critère est une fonction d'`abi.nova`, à la ligne 577 de ce module, et cette gate ne l'écrit nulle part ; ce qu'elle écrit est `default_abi`, la directive que la colonne `target` vaut 1. Aucune plage de ce fichier ne contiendra ce nom, et c'est un fait sur le fichier, pas une dérive de citation. Les deux lignes nx64 sur quinze et seize paramètres non liés, aux lignes 620 et 621, épinglent la borne à quatorze ; les mêmes signatures sous efi rendent zéro, de la ligne 627 à la ligne 631. **La règle est donc confrontée des deux côtés du seuil, ce qui est exactement ce qu'un profil aveugle ne pourrait pas faire. La phrase « aucune gate ne déclare de profil courant » est fausse et est retirée sur place.** Ce qui n'est pas couvert reste écrit par U1 : l'accord avec l'oracle. | **clos — gate `abi`** (`tests/c/nova/tests_ntasm_abi.c:616-634`). **Ce qui la rouvrirait :** une ligne ajoutée à cette table sans champ de profil, ce que la construction de la table rend impossible sans que la ligne soit réécrite à la main. |
| U6 | la grammaire n'a pas d'alignement de section et l'alignement est codé en dur à 16/8 (§17.5.3) | `nxo_merge` et `pe_inspect` épinglent le **résultat** ; rien n'épingle l'**absence** de l'attribut dans `parser.nova:74` et `parser.nova:140-144` | `parser` |
| U7 | `lea` + segment, et `displacement_offset`, ne sont couverts par aucun cas enregistré — donc le détecteur de dérive ne sait pas qu'une forme **manque** (A2, réserve du 28 septembre 2026) | **CLOS le 29 septembre 2026 : l'inégalité que cette ligne demandait existe, et elle refuse.** Les deux compteurs sont déclarés à (`tests/c/nova/tests_ntasm_x64_lower_lea.c:1035-1035`), et la boucle qui les remplit signale par un appel HOLE, à la ligne 1196, tout export à opérande mémoire qui ne porte pas de paramètre `segment`. La mutation qui fait perdre ce paramètre à l'encodeur est nommée à la ligne 1704. **La phrase « un détecteur qui ne peut pas échouer sur une absence » est donc retirée sur place : il en échoue, et le mutant le prouve.** | **clos — gate `x64_lower_lea`** (`tests/c/nova/tests_ntasm_x64_lower_lea.c:1036-1036`). **Ce qui la rouvrirait :** retirer l'appel qui signale l'absence, et la mutation qui fait perdre le paramètre doit alors survivre — c'est-à-dire exactement la propriété que U31 demandait et qu'elle n'avait pas. |
| U8 | le budget de 177 lignes de dérive est complet sur la bande qu'il couvre | **partiellement.** `138+31+8=177` est pinné par une assertion, donc il n'existe pas de cinquième catégorie **parmi les lignes existantes** ; mais rien ne vérifie que le manifeste couvre toute forme publiable, ce qui est U7 | `x64_lower_lea` |
| U9 | le point fixe **S0** est un fait sur des octets, et les empreintes de son checkpoint ne sont **re-dérivées par rien** (A8, 28 septembre 2026) | **RÉSOLU par DÉCISION le 30 septembre 2026, et la décision a été vérifiée contre l'arbre avant d'être écrite — pas recopiée d'un message.** *Ce qui reste vrai, et qui est la moitié non résolue de cette ligne :* les empreintes du point fixe S0 ne sont **toujours pas recalculées** par quoi que ce soit. (les empreintes S0 : `scripts/ntselfhost.sh:65-74`) et (le refus : `QUARANTINE_TREES`, `classify`, `check_producer`, `NTBUILD_SELFTEST_DONE` — `scripts/ntbuild.sh:179-1506`) nomme `P_0 = P_1(S) = P_2(S) = 82826f45… / a02425be…` et la chaîne croisée `stage2 → stage3` qui la rend genuinely auto-référentielle, **et c'est du texte dans un commentaire** ; la seule occurrence de `native-selfhost-checkpoint` dans les trois scripts est cette ligne de commentaire. **Ce qui décide de la ligne n'est donc pas un contrôle mais un refus, et il est vérifié par exécution :** le producteur S0 est un NASM en quarantaine, et le build normal le refuse — `QUARANTINE_TREES` déclare `legacy/nasm` avec une **grant vide** (`:146-149`, ce qui est « tout le refus », comme le dit le commentaire à la ligne 145), `classify` rend `CLASS=quarantine-nasm-input` (`:261`), `check_producer` rend `class=forbidden-producer` (`:454`), et la suite de refus exerce les deux **avec leur contrôle positif dans le même tableau** : 37 cas rendus, dont `producer is NASM` en `exit=78`, les deux sources de quarantaine en `exit=78`, et en face `clean C and a string are allowed` en `no inline assembly` plus `granted translation unit` en `exit=0`. **Un refus qui tiendrait pendant que l'outil est cassé n'est pas une preuve, donc les huit produits sont vérifiés dans la même exécution et tous rendent leur empreinte.** Ce refus **tient** la ligne parce qu'il rend le rejeu impossible depuis cet arbre, pas parce qu'il rend les empreintes vraies | **une décision, et c'est la première ligne de ce registre dont le détenteur est une décision et non une gate.** Elle tient par deux choses nommées. *Ce qui la tient :* le refus du producteur S0 par le build normal, ci-dessus, qui est une **décision enregistrée dans un fichier de code** et non dans un message — `scripts/ntbuild.sh` est relu, compilé et exercé par sa propre suite de refus à chaque exécution, donc la décision ne peut pas disparaître sans que `NTBUILD_SELFTEST_DONE` change. *Ce qui la détiendrait, et c'est la moitié qu'une clôture décorative n'écrit jamais :* **soit** un script de self-hôte qui recalcule les deux empreintes et compare aux épingles — auquel cas la ligne redevient un trou de couverture réel et doit être rouverte comme telle ; **soit** la levée de la quarantaine NASM, c'est-à-dire un `NG_PRODUCER` que le refus n'intercepte plus, auquel cas le rejet s'éteint en même temps que la décision. **Un troisième geste la détiendrait aussi et c'est le plus probable : un `sha256sum` des octets S0 ajouté aux scripts — car c'est exactement la forme que la seconde moitié de la phrase précédente reconnaît comme absente, et elle ferait de cette ligne une gate sans qu'aucune écriture ici n'ait à l'expliquer** |
| U10 | ~~le producteur n'implémente pas l'abandon de drapeaux pour `rflags`~~ | **CLOS le 28 septembre 2026, et la prétendue lacune n'existait pas.** Le mécanisme est **une suppression de sauvegarde, pas un emplacement de restauration omis** : `codegen.c:1277` met `preserve_flags` à faux, `codegen.c:1289` omet alors le `pushfq` et `codegen.c:909` le `popfq`. Le produit l'implémente des deux côtés (`x64_lower_nxo.nova:2016`, `:2027-2029`, `:2057`, `:2092`) et la gate `x64_lower_nxo_function_bodies` le confronte à l'oracle sur quatre cas `rflags` | clos — gate `x64_lower_nxo_function_bodies` |
| U11 | l'observation « le binaire producteur a changé sous le contrôle et les sept sorties n'ont pas bougé » est citée comme argument de robustesse (28 septembre 2026) | **RÉFUTÉE le 29 septembre 2026 : l'observation a été conservée, et dans deux documents.** Les deux empreintes rendent **18 occurrences** sur `docs/guides/ntasm-build.md` et `legacy/docs/bootstrap/producer-usage.md`, dont `:153`, `:164` et le tableau `:187` pour le premier, `:60`, `:62`, `:63`, `:68`, `:76` et `:83` pour le second ; les deux fichiers étaient stables sur 50 s quand j'ai compté. **La phrase « `96e000e9…` n'est nulle part » est donc fausse et est retirée sur place.** Ce qui reste vrai est plus interesting : `docs/guides/ntasm-build.md:187` porte `fae0ae67…` avec la mention « does not reproduce », c'est-à-dire **l'empreinte consignée et son impuissance à se reproduire écrites à côté** — ce que cette ligne demandait et que l'artefact a fait. | **clos — `docs/guides/ntasm-build.md` et `legacy/docs/bootstrap/producer-usage.md`**, qui portent les deux empreintes. **Ce qui la rouvrirait :** un `sha256sum` du producteur `-O2` qui ne rende ni l'une ni l'autre — auquel cas l'artefact ment sur son propre arbre, et la ligne redevient juste. |
| U12 | ~~Le module d'inspection d'image NXO est importé par aucun module du produit~~ | **CLOS le 29 septembre 2026 : la sonde de mutation que cette ligne nommait comme étape suivante existe, et elle refuse.** Le compteur des mutants **invisibles sur l'entrée** est incrémenté à `tests/c/nova/tests_ntasm_pe_inspect.c:913-913`, et il refuse de les compter comme couverture — ce qui est la moitié sage de la sonde. L'autre moitié est un constructeur d'écrivain muté, à la ligne 828, alimenté par une mutation de source à la ligne 801, et le contrôle est là où il doit être : l'assertion que le chargeur refuse l'image mutée est à la ligne 926, et la confrontation à l'inspecteur à la ligne 929. **La mesure de 7124 sorties et 0 rejet reste vraie et ne prouve plus rien** : c'était la preuve du trou, et le trou est fermé. | **clos — gate `pe_inspect`** (le constructeur à la ligne 828 et l'assertion à la ligne 926). **Ce qui la rouvrirait :** une mutation dont le chargeur accepte l'image, ce que l'assertion rend rouge. La cellule ne portait aucun propriétaire — elle portait une étape, ce qui n'est pas la même chose. |
| U13 | le §6.1 fixe l'ensemble fermé des formes d'opérande, et **l'oracle ne l'applique que d'un côté** (28 septembre 2026) | **RÉFUTÉE le 29 septembre 2026 : la passe et la gate que cette ligne demandait existent, et la divergence mesurée vaut zéro.** Le corpus de cette gate compte soixante-cinq formes d'opérande ; son bloc B va de `tests/c/nova/tests_ntasm_initializer_types.c:326-331` et s'intitule *« a name as the SOURCE of a mnemonic other than mov »*, et sa première ligne est `add rax,answer` — avec `sub` et `cmp` dans les deux qui suivent, les trois formes que cette ligne nommait, et seize autres, **une ligne par mnémonique**. Le bandeau est à la ligne 495 et exige `diverged == 0` à la ligne 494 ; les garde-fous d'anti-vacuité, aux lignes 487 et 488, exigent que le corpus accepte et refuse **des deux côtés**, pour qu'un corpus réduit à tout-refuser ne passe pas. **La phrase « la divergence est actuellement INVISIBLE » est retirée sur place : elle est mesurée, ligne par ligne, et elle vaut zéro.** | **clos — gate `initializer_types`** (le bloc B, et l'assertion d'anti-vacuité à la ligne 487). **Ce qui la rouvrirait :** un `diverged` non nul, ou un mnémonique ajouté au corpus sans sa ligne — que l'assertion de la ligne 482 rend rouge. |
| U14 | l'abaissement mixte `mov`-avec-un-nom est **sain** et ne peut pas être étendu au groupe arithmétique (§6.1) | **RÉFUTÉE le 29 septembre 2026, et par la même ligne que U13.** Le bloc B du corpus **est** le test négatif que cette ligne demandait : une source nommée, un mnémonique autre que `mov`, un refus attendu des **deux** côtés. Le commentaire de `tests/c/nova/tests_ntasm_initializer_types.c:326-329` dit pourquoi une ligne par mnémonique : *« a single mnemonic regaining the name form is a red on its own row and not a change in a total »*. **Donc la garantie n'est plus une garantie par lecture du code**, et c'est la seule chose que cette ligne demandait. | **clos — gate `initializer_types`**, le bloc B du corpus. **Ce qui la rouvrirait :** un mnémonique du bloc qui regagne la forme nommée, rouge sur sa propre ligne et non dans un total. |
| U15 | `displacement_offset` est un champ dont `codegen.c` dépend, et il n'est épinglé que par un harnais **hors du registre des 93 gates** (28 septembre 2026) — **et ce nombre est un fait mesuré qu'un instrument calcule déjà et que personne ne recoupe ; il avait dérive dans la même vague où le registre lui-même est passé de 30 à 32 lignes. Un nombre écrit dans un document qu'un instrument calcule déjà, et que personne ne vérifie, est un nombre qui derives** | **partiellement, et c'est un défaut d'inventaire plutôt qu'un défaut de couverture.** Le champ est écrit (`x64.c`) et lu par `codegen.c`, donc le code le produit et le consomme ; mais aucune gate du registre ne le confronte, si bien qu'une dérive y passerait inaperçue. C'est la réserve restante du volet adressages de A2 | rattacher le harnais existant au registre, ou porter la confrontation dans une gate enregistrée |
| U16 | `imul` est l'unique mnémonique du S0 30 sans aucun canal v0, et **le manifeste des absents ne le déclare pas** (28 septembre 2026) | **RÉFUTÉE le 29 septembre 2026 : le manifeste des absents déclare `imul` et une assertion le tient.** `tests/c/nova/tests_ntasm_x64_lower_lea.c:507-507`. L'assertion qui exige que l'oracle le classe absent est à la ligne 1486, la définition du motif de dérive qu'il porte est à la ligne 1870, et la ligne de dérive elle-même est à la ligne 2275. **La phrase « le manifeste des absents ne le déclare pas » est donc fausse et est retirée sur place.** | **clos — gate `x64_lower_lea`** (`tests/c/nova/tests_ntasm_x64_lower_lea.c:507-507`, et l'assertion à la ligne 1486). **Ce qui la rouvrirait :** retirer `imul` de la table des absents, ce que l'assertion rend rouge. |
| U17 | ~~le résolveur de références n'a aucun contrôle de contenu~~ | **CLOS le 28 septembre 2026, et il a trouvé de vraies erreurs dans ce document.** Les deux contrôles existent désormais et sont mesurés : `REFERENCES-CONTENT span_covered=218 span_blank=0 span_comment=4 ident_covered=18 ident_tokens=19 ident_missing=0`. **À sa première exécution, `ident_missing` valait 12 et chacun des douze était une citation fausse de ce lot** — un numéro de ligne qui ne contenait pas le symbole nommé, ou un symbole nommé à côté d'une plage qui ne le contenait pas. Les douze sont corrigées ; `span_blank=0` tient aussi, les deux plages à extremité vide que j'avais trouvées plus tôt étant les siennes. `span_comment=4` est **rapporté et non échoué**, parce que ce document cite de la prose en commentaire à dessein et qu'aucune règle ne peut distinguer cela d'une dérive dans un commentaire — la limite est écrite dans le harnais, ce qui est la forme juste. **La limite que j'avais annoncée est confirmée par la bannière elle-même** : `span:well_formedness_only_not_which_line` — une plage bien formée qui nomme la mauvaise ligne non vide **n'est pas vérifiable** par ce contrôle | clos — `registry`, section `REFERENCES-CONTENT` |
| U18 | la gate `splice` est-elle mesurable **dans le harnais** et pas seulement hors de lui ? (28 septembre 2026) | **MESURÉE, mais avec une observation qui n'a pas survécu à une reconstruction propre et qui doit être lue comme telle.** La gate rend `607` checks, `0` failure, `50` cas, le jumeau existe dans `tests_ntasm_registry.c` et le bandeau est `COVERAGE claims=10 sites=10 gates=6 measured=6 verified_gates=6`. **Réserve à ne pas lire comme une propriété de la gate :** sur un premier run, le jumeau a rendu cinq échecs avec `build=9257` là où le même binaire, lancé seul, rendait `356/0/39` (compteur depuis remplacé). `9257` n'est un littéral ni dans `ntir.nova` ni dans `validate.nova`, donc il ne vient pas du jeu de refus de l'IR, et il est revenu sur les cinq lignes y compris les deux que le pipeline refuse déjà à `363` et `800` — ce qui ne s'explique pas par les fixtures. **Cela ne s'est pas reproduit**, ni sur un run incrémental, ni après reconstruction complète dans un répertoire neuf. **La formulation juste est donc « observé une fois, non reproduit », et non « cette gate est verte quand on la lance et rouge quand la suite la lance ».** La seconde phrase serait une propriété de la gate, et elle ne tient pas ; ce qui la tient est une propriété du **répertoire de build** — voir U19 | un contrôle qui exige qu'une gate soit exécutée dans un répertoire de build neuf au moins une fois avant d'être déclarée mesurée |
| U19 | **le répertoire de build masque l'état réel de l'arbre, et une porte « verte » produite dans un répertoire incrémental n'est pas une preuve** (28 septembre 2026) | **RÉSOLU par DÉCISION le 30 septembre 2026 : la preuve froide EST la construction, et c'est vérifié par exécution.** *Le défaut que cette ligne énonçait est réel et il a été remesuré :* `stale_obj` est une soustraction de `stat -c %Y` — deux secondes de mur, **aucun contenu lu** — et le motif `sha256sum`, `md5sum` ou `checksum` rend **zéro** occurrence dans le script de construction en vérification froide, avec pour contrôle positif le même motif dans `scripts/ntbuild.sh`, qui épingle des entrées. Donc une source restaurée par une copie qui lui rend sa date est réutilisée sans reconstruction. U20 a fermé le cas de la même seconde ; **le cas de la copie reste ouvert et reste le seul.** *Ce qui décide de la ligne n'est pas un correctif de `stale_obj` mais le fait que la construction soit elle-même l'instrument :* `rails_selftest` est appelé **avant** la boucle de compilation qui consomme `stale_obj` — `:201` pour l'appel, `:206-211` pour la boucle — donc sur **chaque** invocation, `libsonly` compris où il précède la sortie, et il appelle **les deux vraies fonctions par nom** sans écrire de copie. Le bandeau a deux formes, dont la forme rouge nomme ce qui n'est pas fiable. Mesuré dans un répertoire neuf jamais utilisé : `RAIL_SELFTEST 9 cases, 0 failed`, puis `LIBS_OK 14`, puis la gate verte. **La table de vérité porte le cas que `[ -nt ]` ne voit pas et son contrôle négatif dans la même paire d'assertions**, et le cas inverse — l'objet réellement plus récent, le seul où la compilation est sautée — est dans la table parce qu'un rail qui recompilerait toujours passerait tous les autres et serait faux | **une décision, et non une inscription manquante : la vérification froide est la construction, telle qu'elle est déjà écrite dans le fichier.** *Ce qui la tient :* `rails_selftest` est sur le chemin de **toute** invocation, devant la boucle de compilation, et son verdict entre dans le code de sortie par `rail_fail` — une invocation dont les rails sont faux sort non-zéro **avant** d'avoir produit un objet. *Ce qui la détiendrait, et c'est la partie qu'une clôture décorative n'écrit pas :* **soit** la sortie de `rails_selftest` du chemin de l'invocation — derrière un drapeau, ou replacée après la boucle, ce que la version précédente faisait et que le commentaire à `:192-197` nomme *« un post-mortem »* ; **soit** la substitution d'une copie locale des deux prédicats dans l'auto-test, après quoi la mutation que ce test existe pour attraper — quelqu'un éditant `stale_obj` — passerait verte ; **soit** `stale_obj` passant à une empreinte de contenu, ce qui fermerait le résidu et rendrait la décision caduque, et il faut alors le dire ici plutôt que laisser une ligne close porter deux apologies du même défaut. **La limite est nommée et non comblée : le résidu de la copie qui restitue une date survit à cette décision, et c'est un choix, pas un trou oublié** |
| U20 | ~~un répertoire de build chaud masque l'état réel de l'arbre~~ | **CLOS le 28 septembre 2026, et la preuve est précisément le cas que `[ src -nt obj ]` ne voit pas.** `ngbuild.sh` implémente désormais `stale_obj` : **reconstruire sauf si l'objet est strictement dans une seconde de mur postérieure à celle de sa source**, donc le cas « source et objet écrits dans la même seconde » est traité comme périmé. Le commentaire qui accompagne la fonction nomme exactement le défaut : *« `[ a -nt b ]` compare des secondes entières, donc une source enregistrée dans la même seconde que l'objet paraît plus ancienne ou égale et n'est silencieusement PAS recompilée »*. Le coût est une compilation supplémentaire dans ce cas et aucun trou. Vérifié : `stale_obj` est appelé par la boucle de compilation, donc la règle est dans le chemin et pas seulement dans un commentaire | clos — `ngbuild.sh` |
| U21 | **39 lignes sur 65** de forme d'opérande divergent entre le produit et l'oracle (28 septembre 2026) | **mesuré, et le bloqueur est mesuré aussi.** `NTASM_NOVA_OPERAND_FORM rows=65 agreed=26 accepted_by_both=17 refused_by_both=9 diverged=39`. **Le correctif n'est pas local** : `initializer_types` ne peut pas importer `register_widths` sans rendre `return_types`, `call_types` et `condition_types` rouges en `E302 3:8`. Rétrécir côté Nova est la bonne direction ; **c'est un changement inter-lots**, pas un lot, et il est nommé comme tel | les trois passes concernées, ensemble |
| U22 | **le footprint déclaré est aveugle à RAX** (28 septembre 2026) | **mesuré, et aucun gate ne peut le voir.** L'abaissement mixte écrit RAX deux fois et le restaure une fois, alors que `nt_x64_effects` calcule `registers_written` à partir de la **seule liste d'opérandes** (`x64.c:815`). **Supprimer la restauration rend la déclaration fausse, et aucune gate ne s'en aperçoit** : le canal par lequel le défaut se propagerait n'est pas observé. C'est le §6.1 écrit en une phrase, et c'est la limite que la forme `mov`-avec-un-nom porte déjà | une gate qui confronte le footprint inféré à l'image émise, octet à octet |
| U23 | la règle du corps sans paramètre (l'ancienne U4) est **plus étroite** que « zéro paramètre » (28 septembre 2026) | **mesurée, par exécution.** `codegen.c:1252-1256` ne prend le raccourci d'entrée brute que si `!requires_aligned_body && !f->param_count && first_statement && kind==NTF_S_RETURN && !ST.next && evaluate_constant(expr)`. **Sept formes sont le trou**, et elles ont été redérivées en lisant l'octet 0 de l'image de référence — `9c` encadrée, `48` sans trame — sur vingt formes, pas en relisant la condition | la forme du corps, pas le compte de paramètres : c'est la nuance que l'ancien texte perdait |
| U24 | le manifeste de dérive était **court de douze** (28 septembre 2026) | **CLOS.** Sept noms gardés à la main alors que `nt_x64_encode` répondait pour **126** mnémoniques distincts, et `126 = 104 + 3 + 19` exactement. `DRIFT-ORACLE offered=136 names=126 literals=147 pseudo=3 absent=19 holes=0`, et `MUTANT` rejette **14/14** mutations, dont « un nouveau mnémonique dans un export existant » et « un mnémonique retiré d'un export » — c'est-à-dire les deux mutations qu'un manifeste court ne pouvait pas voir | clos — `x64_lower_lea` |
| U25 | un mnémonique **assemblé à l'exécution** plutôt que lu d'un littéral passe entre la vue textuelle et la sonde (28 septembre 2026) | **RÉFUTÉE le 29 septembre 2026 : la méthode a un troisième regard, et il refuse.** `oracle_builder` est à `tests/c/nova/tests_ntasm_x64_lower_lea.c:616-620` et liste les seize appels de bibliothèque qui écrivent dans un tampon de l'appelant ; le balayage du texte de l'encodeur, à la ligne 739, refuse sur **n'importe lequel** d'eux, en disant que le nom peut être assemblé à l'exécution et que l'alphabet de littéraux n'est plus celui de l'encodeur. C'est **plus fort** que le correctif que cette ligne demandait : il ne fait pas figurer le nom produit dans le manifeste, il refuse l'encodeur dont l'alphabet n'est plus le sien. | **clos — gate `x64_lower_lea`** (`tests/c/nova/tests_ntasm_x64_lower_lea.c:616-620`, et le refus à la ligne 739). **Ce qui la rouvrirait :** un nom produit par une voie qui n'est ni un littéral ni l'un des seize appels. Cette réserve est nommée et n'est pas comblée. |
| U26 | **le format du corpus ne peut pas enregistrer un refus**, et il ne peut pas porter un membre multi-fichiers (28 septembre 2026) | **mesuré, et c'est une limite de la preuve et non du produit.** Le corpus est **un fichier par membre** : la table de corpus de `ntbuild.sh` synthétise `examples/ntasm-v0/c-bootstrap/$name.ntasm` — un seul chemin — et le script de self-hôte lit un enregistrement `name\|rel\|pin` puis passe **un seul** `$rel` à **un seul** appel `assemble`. *Ces deux scripts sont hors de la portée déclarée du résolveur — `scripts/` n'est pas une racine et le script de build est hors de l'arbre — ils sont donc nommés sans la forme `fichier:ligne`, que le résolveur tenterait et échouerait*. **Le piège à nommer : un corpus qui ne sait enregistrer que des succès n'a aucun moyen de dire « ceci ne doit jamais s'assembler ».** Les deux fichiers de données de l'exemple multi-modules ne peuvent donc pas être épinglés du tout : l'un refuse **par conception**, et le format ne sait pas exprimer un refus comme une empreinte. **Épingler la paire deux modules exige un changement de format** — une liste de sources par membre, à faire passer par les quatre sites — et **ce changement modifie ce que le script de self-hôte prouve** : le premier membre de corpus dont le chemin est une liste. **Le coût réel est le changement de format, pas l'empreinte.** Il faut épingler `c9d9786d…`, la forme one-shot, et **pas** la forme objet+liaison : elle produit des octets différents (`.text` 0x31e contre 0x326, 352 octets divergents) et le script de self-hôte n'exécute jamais ce chemin | un format de corpus qui exprime une liste de sources **et** un refus attendu |
| U27 | **la bannière `REFERENCES-CONTENT` rapporte un compte et ne nomme pas les citations** (28 septembre 2026) | **mesuré, et c'est la limite de l'instrument le plus proche que nous ayons.** Une édition unique a déplacé **trois** citations d'un coup, parce qu'un script a grandi de 866 à 911 lignes ; la bannière a rendu `ident_missing=3` et **n'a jamais écrit lesquelles**. Le compte a suffi à nommer la cause, mais **la correspondance n'était pas prouvable** parce que l'instrument n'émet pas la liste. **La lecture honnête de `ident_missing=N` est donc : un signal d'aller voir, et non une liste actionnable** — un lecteur qui y voit un `0` peut raisonnablement croire qu'on lui a dit ce qu'il fallait faire, et ce n'est pas ce qu'il a reçu. C'est la même forme que `stale_lines=0` : **un instrument étiqueté qui ne dit pas ce qu'il n'a pas résolu.** Le correctif est l'extension de `limits=` qui nomme cette limite, afin qu'un lecteur de la bannière la voie | `limits=` de `REFERENCES-CONTENT` : la limite doit y figurer, parce qu'une limite non écrite dans la bannière est une limite que personne ne voit |
| U28 | **une citation vers un fichier en cours d'édition dérive entre deux contrôles ; le contrôle certifie l'état contre lequel il a tourné, pas celui du tour suivant** (28 septembre 2026) | **mesuré, et c'est la limite qui explique pourquoi ce document produira encore ce défaut.** Huit lots écrivaient simultanément pendant la vague ; un seul script a grandi de 866 à 911 lignes et **trois citations d'un coup** ont suivi, et un harnais a changé d'ancres **quatre fois** en une soirée. **Une lecture honnête de `ident_missing=0` n'est donc pas « le document est sain », c'est « le document était sain au moment de ce contrôle »** — la bannière se lit aujourd'hui comme un bulletin de santé et n'en est pas un. C'est la règle du répertoire froid et la découverte du répertoire chaud, **un cran plus haut** : un instrument qui n'a été exercé qu'à un instant ne décrit pas l'instant suivant | **un contrôle de dérive sur les citations elles-mêmes** : comparer deux exécutions et nommer celles qui ont bougé, ce que U27 dit déjà ne pas être fait. **La cellule absorbait autre chose** — un paragraphe de constat de géométrie sans lien avec le propriétaire de cette ligne ; il est relogé dans sa propre ligne, `U36`, et non jeté. |
| U29 | **une constante de budget a été épinglée indépendamment par deux gates, et aucune n'a dit à l'autre qu'elle l'avait** (28 septembre 2026) | **mesuré, et c'est un couplage sans instrument derrière lui.** Deux gates épinglaient un littéral de carburant de 30 et de 29 pour le même corps, parce que l'expanseur imputait au module du caller une marche de carburant. La marche supprimée, **le même corps coûte 8**, et les deux épingles durent être refaites en même temps. **Un changement de budget n'est donc pas une édition locale** : il a déplacé un nombre que deux gates portaient chacune de son côté, et **aucune des deux n'a parlé à l'autre**. La réponse durable la moins chère est **une source dérivée unique pour ce chiffre, que les deux gates lisent** — la même leçon que le manifeste du détecteur de dérive, arrivée par l'autre côté | **un point de dérivation unique pour le chiffre de carburant**, lu par `tests_ntasm_validate.c` et `tests_ntasm_splice.c` — les deux qui l'épinglent aujourd'hui chacune de son côté. **La cellule absorbait une copie mot pour mot de la règle de clôture du registre** ; elle est retirée, et la règle reste une seule fois, sous la table. |
| U30 | **une citation est une dépendance à un numéro de ligne, et un contrôle qui signale une citation périmée ne peut pas dire quelle édition l'a périmée — donc la partie nommée dans l'échec n'est pas la partie qui l'a causé** (28 septembre 2026) | **mesuré, et c'est une règle et non une anecdote.** Un lot éditait un module Nova ; ce module a changé d'ancres quatre fois en une soirée, et **chaque fois `registry` a nommé le document, pas le fichier du lot** — le rouge est arrivé dans le journal du propriétaire du document pour une édition qu'il n'avait pas faite. **La clause opérationnelle est celle-ci, et elle coupe dans les deux sens : un compte de rouges d'un propriétaire de document n'est pas une mesure du document.** Cela **excuse** le propriétaire des rouges qu'il n'a pas causés, **et cela interdit** au propriétaire du code de rejeter un rouge parce que le fichier nommé n'était pas le sien. **Une ligne qui ne porterait que la première moitié serait une défense et non une constatation.** Le mécanisme coupe aussi **dans l'autre sens** : une édition de document peut rendre faux les numéros de ligne d'un fichier de code, et le rouge apparaît alors dans le document — même couplage vu par l'autre bout. **C'est ce qui relie U27 et U28 à cette ligne** : U27 dit *un compte n'est pas une liste*, et ceci dit *une liste sans partie n'est pas une attribution*. **La forme du correctif est la même dans les deux — émettre la citation, pas le nombre** — et celle-ci a un consommateur qui n'existait pas quand U27 a été écrit : **sans elle un propriétaire de document ne peut pas dire lesquels de ses rouges sont les siens**. Un contrôle de dérive qui compare deux exécutions et nomme les citations déplacées n'est donc pas une aide à la lecture, c'est **la seule chose qui puisse attribuer** | un contrôle de dérive qui émet la citation déplacée et la partie responsable, ou au minimum la citation |
| U31 | **un garde correct qu'aucune fixture ne peut faire rougir était indiscernable d'un garde absent** (28 septembre 2026) | **mesuré, et c'est une troisième chose — ni « le garde est faux », ni « le garde est inatteignable ».** Deux sites de garde de premier niveau dans `x64_lower_nxo.nova` : l'un, `collect_frame_sections`, n'était couvert par **rien du tout** — **supprimer le garde entièrement laissait la gate VERTE à 3641 checks et zéro échec** ; l'autre, `build_function_bodies`, n'était couvert que pour une seule sorte, et par un seul mode, et supprimer le garde ne faisait rougir qu'un check. La moitié `&&item.kind!=11&&item.kind!=13` des deux gardes n'était couverte par rien non plus : **élargir les deux pour refuser 11 et 13 laissait la suite VERTE.** **Les deux lignes qui lisent VERTE sont donc celles qui portent la constatation** : c'est à cela que ressemble « rien n'exerce ceci » dans une gate. **Cause, et c'est une classe :** la gate appelait un mode unique, et le second site n'est atteint que par d'autres modes — **on ne l'a donc jamais rien demandé.** **Ce n'est pas « le garde est faux » et ce n'est pas « le garde est mort » : le garde est juste et rien ne l'exerce, et la suite ne pouvait pas distinguer cela du cas où le garde n'existe pas.** C'est la pire des trois à découvrir par accident, parce que le site a l'air correct à la revue et passe en intégration indéfiniment. **Le producteur est resté identique octet pour octet et le comportement du produit n'a pas changé** : les gardes sont justes, on a seulement rendu la suite capable de le remarquer | **une fixture par site et par mode, et une preuve négative par site.** **La cellule absorbait elle aussi une copie mot pour mot de la règle de clôture** ; retirée. Ce que la ligne demande est un travail de fixture et non une gate, et c'est dit ici pour qu'un lecteur ne l'attende pas d'un counter. |
| U32 | **un contrôle qui lit du texte ne distingue pas un commentaire d'un code, donc la prose d'un commentaire peut changer un build** (28 septembre 2026) | **mesuré, et c'est dix-neuf gates.** `ng_parity_imports_present` trouve les imports avec `strstr(text, "import ")` et **ne sait pas ce qu'est un commentaire**. Un brouillon de note disait « cannot import this module » ; **c'est le mot qui a changé, pas l'analyseur**, et le build a cassé. **La phrase à retenir : une phrase écrite pour expliquer quelque chose ÉTAIT quelque chose, et la différence entre les deux tenait à un mot.** Ce n'est pas U30 — U30 est une citation qui ne peut pas dire quelle édition l'a périmée. C'est la famille à laquelle appartient le contrôle de géométrie : **un instrument qui lit une surface qu'il ne modélise pas.** Mais c'est pire sur un point : le sujet du contrôle de géométrie est un document qu'un humain a écrit, et celui-ci est **un commentaire dans un fichier `.nova`, qui est du code**. Donc un relecteur qui lit le module voit un commentaire, un relecteur qui lit l'en-tête voit une liste de modules, et **aucune des deux surfaces n'est fausse.** Trois conséquences nommées. **Un : `ng_parity_imports_present` est l'arête la plus vive de cet en-tête**, et le correctif est un analyseur qui saute les commentaires ; l'en-tête porte seize gates, donc c'est un élément de vague 19 et non une chose à glisser. **Deux : toute note future dans un fichier `.nova` est une entrée de build**, et la règle de formulation est celle que j'ai déjà appliquée aux documents — **une note qui dit « cette formulation a été envisagée et écartée » est elle-même une source de la formulation écartée** ; ici l'écart pouvait casser le build, ce qui est une raison plus forte de ne rien dire. **Trois : la même forme existe partout où un contrôle fait `strstr` sur une source, et je n'affirme pas que ce soit le seul endroit** — un registre qui prétendrait l'exhaustivité ferait exactement ce que ce registre condamne | un analyseur qui saute les commentaires dans l'en-tête de parité, en vague 19 |
| U33 | **un contrôle qui rapporte un nombre que sa propre entrée garantit RAPPORTE UNE GARANTIE COMME UNE MESURE** (28 septembre 2026) | **La moitié de cette ligne qui était fausse a été retirée le 28 septembre 2026, et c'est la moitié importante à lire.** Elle affirmait qu'« un jeu d'épingles que deux builds sans rapport satisfont tous les deux est un témoin plus faible qu'il n'y paraît ». **C'est faux, et c'était faux sur les goldens** : les épingles sont des **littérales de chaîne codées en dur**, (les littérales `RECORDED_EXAMPLES` : `scripts/ntbuild.sh:262-271`) et (`cmd_corpus` : `scripts/ntbuild.sh:779-785`), et `cmd_corpus` à `:516` se contente de les imprimer sans consulter un binaire. **Un jeu d'épingles est censé être une cible fixe — c'est ce qu'est un golden**, et deux builds sans rapport qui satisfont les mêmes huit littérales, c'est le golden qui fonctionne ; un golden qu'un seul build pourrait satisfaire serait un golden **cassé**, et non plus strict. **Ce qui est vrai et qui est gardé est l'autre clause, qui est la vraie :** rien ici ne séparait la garantie de la mesure, et c'est cela qu'un lecteur ne voit pas. **La forme exacte du dépôt, et non du document :** `RECORDED_EXAMPLES` **tient** les épingles ; `out/c-bootstrap/selfhost/corpus.csv` est un **rendu régénéré à chaque exécution**, et il est byte-identique au rendu aujourd'hui, donc **non distinguable par contenu**. **Vérifié par DEUX EMPREINTES calculées indépendamment, et non par un `diff`** — le rendu et l'artefact rendent tous deux `0d85cc2b…deaa92`. **La distinction est la moitié de la ligne :** une lecture périmée peut rendre un résultat plus faible — une rouge qui nomme la mauvaise casse, une restauration silencieusement non faite — et elle **s'annonce**, parce que le compte et le cas se contredisent. Elle peut aussi le rendre **plus fort**, et **c'est le cas dangereux** : un `diff` peut se tromper dans la direction qui flatte, une comparaison concordante peut avoir été fabriquée par deux lectures périmées, et **l'absence de tell est le tell** — tout semble propre, et l'accord n'a jamais eu lieu entre les deux choses que l'on croyait comparer. **La règle, dans les deux sens : un accord se noue à une empreinte, jamais à un `diff`.** « Ces deux fichiers concordent » se dit par deux empreintes calculées indépendamment ; « mon restauration a fonctionné », par une empreinte prise **avant** la perturbation ; « ma rouge nommait la bonne casse », par l'identifiant de la casse confronté à la mutation réellement faite. **Conséquence qu'aucune phrase ne peut réparer :** la garde dont on dispose — « il faut d'abord établir que le script qui a produit le rendu est non modifié » — **est inapplicable telle qu'écrite**, parce que les deux artefacts **ne peuvent pas être distingués par leur contenu** ; le seul discriminant est `mtime`, qui est exactement le signal par lequel ce projet s'est déjà fait prendre. **La limite d'anti-vacuité est la phrase la plus utile de cette ligne, et trois lots l'ont dite indépendamment : les épingles sont respectées, et l'on ne sait pas si elles mordent.** **Et l'histoire, qui est le contenu de la ligne : l'affirmation du faux vert a été ÉCRITE PAR DEUX LOTS ET RÉTRACTÉE PAR LES DEUX.** Un registre qui n'enregistre que la version corrigée n'apprend à personne à quoi le piège ressemblait. **La norme, qui est le vrai contenu de cette ligne :** tout chiffre cité depuis l'arbre nomme sa **SOURCE KIND** — **chemin vivant** (répertoire, binaire, tout ce que `ntbuild.sh clean` possède) : c'est un **échantillon d'un répertoire en mouvement, pas une propriété de l'arbre**, et il n'est pas citable comme telle ; **artefact durable** (épingles versionnées, répertoire de preuves, journal conservé) : c'est une propriété, et c'est citable. **Un chiffre sans son genre de source ne dit pas lequel des deux il est — et la différence est exactement celle qui fait qu'un vert se lit comme une propriété alors qu'il était un instantané** | **la règle que cette ligne énonce, appliquée au dépôt et non au document :** un contrôle ne doit pas rapporter un nombre que son entrée garantit, et un rendu régénéré ne doit pas servir de référence à sa propre définition. **Ce n'est pas un propriétaire, c'est une règle** — la cellule en portait deux à la fois, ce qui la rendait impossible à classer. |
| U34 | **sur un montage DrvFs, chaque restauration par copie se relit périmée — donc une preuve négative dont la restauration n'est pas vérifiée par une empreinte calculée APRÈS la restauration n'est pas une preuve négative, c'est une exécution dont on ne peut pas énoncer la provenance** (28 septembre 2026) | **mesuré, et cela touche tous les lots de la vague, puisque tous perturbent un arbre et le restaurent.** Chaque build voyait donc la mutation **précédente** en plus de la mutation courante. **Le tell est gratuit et décisif : une rouge qui nomme une autre casse que celle qu'on a mutée n'est pas une rouge, c'est une lecture périmée.** Le second essai de ce lot est mort de la même manière : **une mutation qui n'a jamais été appliquée, rapportée comme « le mutant a survécu » — et un vert issu d'une mutation jamais appliquée est un drapeau sur LA PREUVE, pas sur l'arbre.** **La règle, une commande :** restaurer, puis `sha256sum` et comparer à l'empreinte prise **avant** toute perturbation — non à ce qu'on s'attend à obtenir, mais **à ce qu'il était**. Si sur DrvFs l'empreinte ne correspond pas, **ne pas non plus faire confiance au build suivant.** **Et la règle d'écriture qui accompagne :** si une tranche écrit une ligne dans un tableau, **éditer la ligne existante ; ne pas ajouter un bloc et refermer.** Un ajout en fin de fichier suivi d'une règle de fin réintroduit l'orphelin, et c'est arrivé trois fois en une semaine à ce document. Si l'ajout est indispensable, **l'arbitre est le contrôle de géométrie du registre, et il nomme la ligne** | chaque restauration de perturbation est vérifiée par une empreinte calculée après elle, et comparée à celle d'avant  **La seconde moitié, et elle est le trou de la première : sur un montage en édition concurrente, un instantané n'est recevable que si le fichier a été observé QUIESCENT — même empreinte sur deux lectures séparées dans le temps — AVANT d'être pris. Sans cela, un instantané est une affirmation sur un instant, et un instant ne peut pas soutenir une preuve négative sur un fichier qui bouge.** Le cas qui l'a fait apparaître : un instantané à `mtime` 20:49:06 et le document vivant à 20:50:30 puis 20:53:55, **le registre passant de 33 à 34 lignes entre deux vérifications du même document** — donc l'écart d'empreinte n'était pas une lecture périmée, c'était le propriétaire du document qui écrivait sous le lot, deux fois, et l'instantané était réellement une autre édition. L'instance avait d'abord été offerte comme **preuve mesurée de la dérive du registre**, puis retirée : *je ne peux pas dire quelle des deux éditions a déplacé le compte, parce que je n'ai jamais vérifié que le fichier était quiescent avant de l'instantaner.* **La forme composée, et c'est celle qu'il faut garder :** **1. RESTAURATION — le fichier est maintenant comme je l'ai trouvé** (empreinte après) ; **2. QUIESCENCE — c'était le même fichier pendant que je travaillais** (empreinte deux fois, séparée, avant). **La première seule donne une bonne restauration d'un fichier qui n'a jamais été le mien ; la seconde seule donne une base correcte d'un fichier qui a bougé sous moi ; les deux ensemble donnent une preuve négative.** Et si une base s'avère prise pendant une édition, **on dit que la conclusion est inadmissible plutôt que de la réinterpréter** : c'est tout le prix de la règle, elle produit un **retrait**, et un retrait est recevable. **Enfin la consigne d'écriture, qui vaut pour le reste de la vague : si une tranche écrit une ligne dans un registre, elle ÉDITE la ligne existante ; elle n'ajoute pas un bloc et ne referme pas.** C'est exactement le geste qui a produit l'orphelin trois fois dans ce document.  **Le troisième sens, et c'est celui qui ÉCRIT du code : une lecture périmée peut faire paraitre un fichier PLUS PETIT qu'il n'est.** Trois sens, donc. Une lecture périmée rend un résultat **plus faible** — une rouge qui nomme une casse qu'on n'a pas mutée ; elle le rend **plus fort** — un `diff` qui annonce un accord qui n'existe pas ; et elle rend **un fichier plus petit** — un `grep` qui ne rend rien pour du code qui EST là. **Un résultat négatif est la seule espèce de résultat qu'une lecture périmée peut fabriquer outright.** Tout les autres sens donnent un nombre faux, qu'on détecte en vérifiant l'arithmétique ; **une absence donne une chose MANQUANTE, et la réponse d'un programmeur à une chose manquante est de l'écrire.** Le sens qui produit le fichier le plus petit en apparence est donc celui qui produit le plus sûrement du code dupliqué — il est arrivé cette semaine : un commentaire promettait une routine de fermeture, la `grep` est revenue vide, et le lot allait **écrire la routine**, en croyant à une absence alors qu'il avait lui-même la routine sous les yeux. **La règle, et elle est courte : ne jamais écrire du code pour corriger une absence observée une fois. Relire d'abord — deux lectures séparées dans le temps, empreintes comparées. Une absence confirmée deux fois est un fait ; une absence vue une fois est une rumeur.** Et quand une `grep` revient vide, **vérifier le motif et pas seulement le fichier** : un accent, un `static`, une macro, un nom différent de celui qu'on suppose — chacune de ces choses produit une `grep` vide sur un fichier qui contient le code. **Et la forme générale qui couvre tous les lots : un résultat négatif n'est recevable que si la lecture qui l'a produit était quiescente.** C'est la règle de quiescence pointed the other way : un résultat **positif** sur une lecture périmée est une valeur qu'on peut revérifier ; un résultat **négatif** sur une lecture périmée est une absence **sur laquelle on va agir**. L'impulsion d'écrire est le symptôme.  **La réponse qui rend les deux règles inutiles : perturber une COPIE, pas l'arbre.** Copier le fichier, perturber la copie, construire contre la copie. **Il n'y a alors aucune restauration qui puisse mentir, aucune fenêtre de quiescence à perdre, et aucun frère qui tienne une base qui vient de bouger sous lui.** C'est la raison pour laquelle les résultats ainsi obtenus sont recevables là où ceux d'un lot qui perturbe puis restaure ne le sont pas forcément. Et la formulation générale de l'échec, tirée d'un lot qui avait les trois problèmes à la fois — restauration correcte à 20:41, une exécution déjà déclarée VOIDE terminée à 20:47 **et laissée mutée**, et un build compilé sur le mutant : **une restauration qui a déjà menti une fois n'est la preuve de rien pour la suite, y compris pour sa propre étape suivante ; l'échec n'est pas que la restauration était fausse, c'est que toute croyance ultérieure a hérité de sa certitude.** Personne n'avait besoin d'apprendre cette règle : il pouvait copier le fichier. **Et l'invariant qu'un correctif de nommage doit tenir, vérifié sur deux exécutions :** un correctif de nommage **ne doit pas déplacer un compte.** Avant et après, le bandeau doit être identique octet pour octet — ici `checks=751 failures=1 cases=266` des deux côtés, alors que la seule chose qui change est qu'un échec **devient trouvable** et **dit ce qu'il a réellement jugé**. Si un changement qui n'ajoute qu'un message déplace un nombre, ce n'est pas un correctif de nommage. **Vérifier que le compte est inchangé, c'est la preuve qu'on n'a pas modifié ce qui est mesuré.** **Le corollaire, qui vaut pour chaque chiffre de ce chantier : un classifieur statique qui rapporte un compte sur cet arbre a un taux de faux positifs connu et élevé, et les causes sont structurelles** — des accolades **dans des littérales de chaîne** (les sources Nova sont embarquées en C et contiennent `effects {}`), une « ligne d'impression la plus proche » qui est la mauvaise question, une « accolade la plus interne » que `if (X) {...} else Y;` contredit, et un helper qui n'est pas une impression. **Lire les lignes avant de croire un chiffre — y compris ceux de nos propres répertoires de preuve.** |
| U35 | **le rail d'inventaire du harnais — un harnais présent dans l'arbre et absent de `GATES` est un trou de couverture silencieux — est le bon défaut, et ce registre ne le suit pas** (28 septembre 2026) | **c'est une constatation sur ce document, énoncé par son propriétaire.** Ce registre a gagné des lignes, et **rien n'échoue quand sa propre forme se dégrade** : il est passé de 32 à 34 lignes en une soirée, un `U33` en double a existé quelques minutes, une règle de fin a été dupliquée **à l'intérieur d'un corps de tableau**, et un bloc a été ajouté puis refermé — **aucun de ces défauts n'a rien déclenché**, parce que rien ne vérifie la forme de ce registre. Ils ont été trouvés par relecture, ou par le contrôle de géométrie quand il est arrivé, **et c'est trop tard** : un contrôle de forme doit faire échouer, pas rassurer après coup. **Un lot a mesuré qu'un contrôle de *compte* serait passé sur tous ces défauts ; c'est pourquoi l'on construit une assertion de *forme* et non de *nombre*** — parce que le nombre est précisément ce qui dérive. **La règle d'écriture qui suit, et que je me discipline d'appliquer à ce fichier : ÉDITER une ligne existante, ne pas ajouter un bloc et refermer** ; et si un ajout est indispensable, **le contrôle de géométrie est l'arbitre, et il nomme la ligne** | une assertion de forme sur le registre : nombre de lignes d'en-tête, de séparateur et de données, unicité des identifiants, et une closing rule unique en fin de tableau |
| U36 | **L'ÉTIQUETTE PRÉCÈDE LA LECTURE.** Un motif est un classifieur qui ne peut pas dire que sa portée est trop étroite ; un titre est un classifieur qu'on écrit avant de lire ce qu'il nomme — **les deux échouent de la même manière, le nom est choisi d'abord et la lecture est ensuite forcée de s'y ajuster** (28 septembre 2026) | (28 septembre 2026) ; **c'est la forme qui explique les cinq pièges sans en ajouter un sixième.** **Portée → ce que la lecture a trouvé :**  *un bloc* ; *quatre sites fantômes* ; *« ligne d'impression la plus proche »* ; *la ligne FAIL* ; *un diagnostic entre les deux* ; *« accolade la plus interne »* ; *le bloc enclosing* ; *une paire déjà fermée* ; *« un helper n'est pas une impression »* ; *le site du compteur* ; *`show()` à deux cadres plus haut* ; *`grep -oE` pour « n'existe pas »* ; *une affirmation d'absence* ; *un biconditionnel, un fragment, un contrefactuel* ; *`startswith` pour la règle de fin* ; *une règle en double* ; *un titre de section* ; *`failures`* ; *un compteur de défaillance* ; *un compteur nommé `failed`* ; *« quatre corrections »* ; *quatre corrections* ; *deux corrections, deux constatations* ; **Une portée de motif est une affirmation sur le monde, exactement comme le nombre qu'elle produit — et c'est l'affirmation qu'on a le moins de chances de vérifier, parce que le motif est ce qu'on a écrit et donc ce qu'on comprend déjà.** Deux conséquences, et elles sont peu coûteuses. **Un : énoncer la portée dans l'affirmation, pas seulement le compte** — « incréments d'un compteur nommé `failures` », et non « sites de comptage de défaillance » ; **un nombre sans portée énoncée est un nombre sur un ensemble non borné.** **Deux : rejouer un balayage avec un motif délibérément plus large, pour voir ce que le premier ne pouvait pas voir** ; c'est ainsi que `failed` est apparu, et cela coûte une commande. **Et un point de méthode que ce registre s'applique : la portée de chaque compte qu'il contient est nommée dans la ligne qui porte le compte** une portée nommée par motif, et un second balayage plus large par tout balayage qui prétend porter sur l'arbre  **La défense la moins chère de la soirée, et c'est une ligne de sortie : AFFICHER UNE CORRESPONDANCE AVANT DE citer UN RAPPORT.** Un instrument de densité a mesuré une section comme citée 24,4/kloc contre une médiane de 135,6 ; il a imprimé ses deux correspondances et elles étaient **deux mentions du MÊME document**, avec **zéro** citation `fichier:ligne` dans la section. Le motif demandait « ce jeton entre backticks est-il un nom de fichier avec extension connue », et la réponse a été lue comme « quelle part de cette section est citée » — **une question à laquelle le motif ne peut pas répondre : il notait de la prose qui NOMME comme si elle CITAIT.** Une correspondance qui se révèle être un nom de domaine est visible en une seconde et totalement invisible à l'intérieur d'un `24,4/kloc`. **Tout classifieur de la soirée aurait été moins cher et plus honnête si sa première ligne de sortie avait été un exemple et non un compte** — y compris le relevé qui a annoncé 24 défaillances silencieuses et en a trouvé 3, le compte d'absences qui en a annoncé 10 et en a trouvé 8, et le `startswith` qui a annoncé une règle de fin en double et trouvé un titre de section. **C'est désormais le défaut pour tout ce qui produit un nombre : un exemple, puis le compte.** Cela coûte une ligne et c'est la seule défense qui fonctionne avant d'avoir eu tort. **Et ce qui décide des dégâts quand un instrument se révèle faux, et c'est ce qui vaut plus que tous les chiffres de la soirée :** quand il a été faux, la question décisive était **de savoir si l'affirmation porteuse avait un second appui indépendant.** Elle en avait un, vérifié par lecture, et la constatation tient même si le rapport est effacé. *Connaître un piège et savoir le voir dans l'instrument qu'on a construit une heure plus tôt sont deux compétences différentes* — et **personne n'est exempté de son propre travail antérieur ; l'instrument dont on est le plus sûr est celui qu'on a construit le plus récemment.** | une portée nommée par motif ; un second balayage plus large par tout balayage qui prétend porter sur l'arbre |
| U37 | **les défauts structurels de ce registre et de `docs/status/ntasm-completion.md` ont été réels et ont été introduits derrière une suite verte** (28 septembre 2026) | **clos pour ce registre, mesuré sur l'édition du 29 septembre 2026** : une ligne de critère A2 fendue sur plusieurs lignes physiques, de sorte que son rendu perd une cellule ; une ligne de ce registre à trois cellules sous un en-tête à quatre ; une ligne en forme de ligne sans en-tête au-dessus ; et une orpheline. **Aucun ne concernait le sujet d'un critère** : ils portaient sur la forme du document, et quatre instruments n'en disaient rien. **Ce paragraphe vivait dans la cellule propriétaire de `U28`, qui n'était donc plus une cellule** ; il est ici, avec son propriétaire, et non jeté | **le contrôle de géométrie de table de la gate `registry`**, section `DOC-TABLE`, et l'assertion de forme de la vague 20 qui lit les relations entre les lignes plutôt qu'un compte. **Ce qui la rouvrirait :** une ligne du tableau dont le nombre de cellules diffère de l'en-tête |
| U38 | **un négatif demandé d'une recherche qui rend plus de zéro est un négatif fabriqué, et il se transmet mieux qu'un positif** (29 septembre 2026) | **mesuré sur un cas, et le cas est dans ce document.** La règle opérationnelle tient en une clause : **un négatif n'est admissible que si la lecture qui l'a produit était calme ET portait un contrôle positif.** Les trois occurrences rendues, leur caractère de commentaire, les deux contrôles positifs et les deux citations fausses que cette cellule portait sont en prose sous le tableau — **une cellule ne peut pas porter une ligne par assertion**, et c'est la forme qui l'a forcée | **l'instrument du négatif lui-même : aucune recherche ne devrait pouvoir être citée sans le motif qu'elle a rendu, ni le nombre de lignes rendues ; c'est la même clause que `U27` pour un compte, et elle s'applique à un compte de zéro comme à un compte de dix** |
**La règle que ce registre s'impose.** Une ligne ne sort pas de cette table parce qu'elle est devenue vraie : elle en sort quand une gate la couvre, et le nom de cette gate doit alors être écrit à la place de « rien » dans la troisième colonne. Une affirmation qui n'a pas de gate ne devient pas une affirmation, elle devient une note — et c'est pour cela qu'elle est ici, à plat, plutôt que fondue dans la prose des sections qu'elle concerne. **La seconde clause, et elle ne fait que ramener `U36` dans ce registre :** la portee de chaque compte que cette table porte est nommee dans la ligne qui porte le compte, et **un nombre ecrit ici est une affirmation tant que les lignes qu'il compte n'ont pas ete lues**. Un motif est un classifieur qui ne peut pas dire que sa portee est trop etroite, et une etiquette est un classifieur ecrit avant la lecture -- **l'etiquette precede la lecture**, et c'est la regle qui a produit vingt-quatre echecs silencieux la ou il y en avait trois. Le test qui reste : *une portee plus large trouve-t-elle ce que la premiere ne pouvait pas voir ?*

**Le détail des cellules `U4` et `U38`, sorti des cellules et mis ici, et c'est
la première application des quatre règles du §17.4.** Ces deux cellules
étaient les seules lignes physiques du document que la gate `registry` faisait
rouge, et **les deux étaient de cette forme** : une cellule qui nomme un
symbole à côté de plusieurs sites. **Les dix `IDENT-MISSING` que cet
instrument a rendus étaient donc tous de la même classe, et aucun n'était une
citation fausse** — c'était dix fois la même phrase lue dix fois de travers.
**Le onzième rouge de la même exécution n'est pas de cette classe** : c'est un
`DOC-TABLE-TAIL` dans `docs/status/ntasm-completion.md`, c'est-à-dire une ligne de
tableau fendue — **onze rouges, dix d'une classe, et le onzième d'une autre** ;
confondre les deux serait compter une classe par son total.

**Le détail suit, et chaque paragraphe ne cite qu'un seul fichier, ce qui est la
première des quatre règles.**

**`U4`, et le bloc qui la tient.** La gate `x64_lower_nxo_function_bodies`
porte un bloc intitulé *33. The parameterless function that had no producer*,
dont le commentaire d'en-tête est à
`tests/c/nova/tests_ntasm_x64_lower_nxo_function_bodies.c:3155`.
Les neuf fixtures du bloc vont de la ligne 3169 à la ligne 3204 et confrontent
modèle, octets de `.text`, symboles, relocations, NXO et PE à l'oracle C et non
à une transcription de Nova. **L'argument de la ligne `U4` — qu'aucune fixture
ne prenne la route encadrée à zéro paramètre — est donc devenu faux**, et la
ligne a été close.

**Les cinq sites de ce bloc, un par assertion, et c'est la forme que la
règle 4 impose.** Le modèle de référence est défini à la ligne 674 du fichier
de gate ; la forme du commentaire de la route encadrée est à la ligne 1503 ;
la parité NXO elle-même est l'assertion de `expect_ok`, dont le corps commence
à la ligne 334 et dont l'assertion de parité est à la ligne 429. **La version
précédente de cette cellule citait le numéro 1503 pour cinq symboles d'un seul
tenant, alors que la ligne 1503 est `case_framed_route` et rien d'autre** — un
identifiant collé à un numéro qui en désigne un autre, ce que `U30` énonce.
**Le site était juste et la plage était décalée d'un facteur deux** : le
commentaire que la cellule citait — *One in parameter, so codegen.c never takes
its raw entry shortcut and always frames this shape* — est bien aux lignes
1780 et 1781, et non à 1767-1780. **Ce bloc enchaîne sur une parité de route
par la section `.data`, de la ligne 3206 à la ligne 3232, et sur les formes que
l'élargissement ne doit pas admettre, à la ligne 3234.**

**La preuve négative de `U4`, et sa provenance.** Rendre la branche
`pcount==0` de `x64_lower_nxo.nova` inconditionnellement refusante rend **neuf
lignes rouges** de cette gate, nommées une par une, toutes en `NOVA_REFUSED
code=800`. L'exécution à froid rend `checks=3721 failures=0 cases=391`. **Les
phrases « aucune autre ligne de la gate ne prend la route encadrée à zéro
paramètre » et « RIEN, et c'est exact » sont retirées sur place**, et le même
retrait est fait au §17.5 : **une ligne de ce registre et une section qui
portent le même trou ne doivent pas être closes l'une sans l'autre**, ou le
document continue de l'affirmer à l'autre endroit.

**`U38`, et les trois occurrences que la phrase retirée disait absentes.** Le
§17.5.2 affirmait qu'« une recherche de `reason=8` sur l'arbre ne rend rien ».
**La recherche rend trois occurrences dans `compiler/nova/analysis/abi/abi.nova`, à la
ligne 517** — c'est le refus lui-même — **et trois autres dans
`tests/c/nova/tests_ntasm_abi.c`, à la ligne 1132, et dans
`compiler/nova/frontend/stub_table.nova`, à la ligne 1928.** Les trois sont des
commentaires et **aucune n'émet le code**. La phrase était donc fausse en
surface et vraie en substance, ce qui est la pire forme : un lecteur qui la
corrige en « trois » peut conclure à tort que la règle existe, et un lecteur
qui la garde peut conclure à tort qu'elle est introuvable.

**Les deux contrôles positifs de `U38`, et ils sont ce qui rend le négatif
admissible.** Le premier est la fonction `memberC` de
`tests/c/nova/tests_ntasm_body_clobbers.c`, dont la définition
est à la ligne 239 et qui rend une ligne par forme du membre. Le second est
l'impression `A4-EXACT` de
`tests/c/nova/tests_ntasm_control_flow.c`, dont le `printf` est à
la ligne 1129 et qui en rend une par forme aussi. **Un sweep qui répondrait
zéro partout se verrait à la première ligne qu'il imprime** — c'est ce qui les
distingue d'une recherche, et c'est pourquoi leur présence rend le négatif
admissible.

**Les deux citations fausses que la cellule `U38` portait, et elles sont
exactement le trou que la réduction vient d'ouvrir.** La cellule affirmait que
le contrôle positif était `memberC` **à la ligne 208** du fichier de clobbers,
et que l'impression `A4-EXACT` était **à la ligne 1096** du fichier de flux de
contrôle. **Les deux numéros sont faux : la définition de `memberC` est à la
ligne 239 et non à la 208, et le `printf` de `A4-EXACT` est à la ligne 1129 et
non à la 1096.** Les lignes 208 et 1096 sont des commentaires de voisinage.
**L'instrument ne les voyait pas et ne les voit pas encore**, et la raison est
structurelle : une citation entre parenthèses toutes seules — `(fichier:ligne)`
— constitue un groupe qui ne contient **aucun** identifiant, donc l'appariement
n'a rien à vérifier. **Un rouge que l'on ne voit pas est un trou de couverture
et non une propreté, et la réduction à une assertion par cellule vient d'en
créer un nouveau.** Les deux numéros sont donc écrits ici **sans la forme de la
citation** — 208 et 1096 en prose, les sites justes en citation — pour la
raison énoncée au §17.4 : un numéro cité comme faux reste une citation pour
tout instrument qui résout les abréviations.

**Ce que ces deux cellules illustrate, et c'est la classe entière.** Une
cellule de tableau ne se coupe pas sur plusieurs lignes physiques, donc **une
cellule ne peut pas porter une ligne par assertion** ; la tentative de couper la
ligne a cassé la géométrie du tableau et a été revertie, et la forme qui reste
est de réduire la cellule à une assertion et de porter le détail en prose. **Le
détail n'est pas perdu : il est déplacé vers un support qui peut le porter**, et
la règle 1 s'applique à cette prose comme au reste du document — un seul
fichier par paragraphe, aucun nom de fichier dans une citation rapportée, aucun
renvoi ordinal, aucune abréviation dans une cellule.

**`U2`, et le second répertoire sans rail.** La gate qui tient cette ligne est
`conformance_efi`, déclarée dans le tableau `ROOT_GATES` du script de construction
en vérification froide — à la ligne 489, **écrite ici en prose et non dans la
forme de la citation** : les racines du résolveur de références sont
`. toolchain/ bootstrap/ spec/ docs/ examples/ os/ out/c-bootstrap/`, et
`tools/` n'en fait pas partie, donc un numéro cité pour ce fichier serait un
`REF-DRIFT` — c'est mesuré, pas prévu, et c'est la troisième fois que ce
document porte la règle sous forme de retracted number. Elle est construite par
la fonction `run_harness`
déjà présente. Elle rend `EFI_ABI_TESTS checks=18 failures=0`. **Ce qui rend cette
ligne instructive n'est pas la gate : c'est la raison pour laquelle elle ne
tournait pas.** Le harnais est `tests/c/ntasm/tests_conformance_efi.c`,
241 lignes, `int main(void)` à la ligne 235. Il est dans `compiler/c`
et **non** dans son sous-répertoire `nova`.

**Les deux rails de ce script sont enracinés sur ce sous-répertoire.** Le filtre
de nom est le `find "$root/nova" -maxdepth 1 -name 'tests_ntasm_*.c'` de la ligne
351 ; le rail de déclaration est le `find "$root/nova" -maxdepth 1 -name '*.c'`
de la ligne 381. Le répertoire parent n'est cherché par aucun des deux. **Le
fichier n'était donc pas « non enregistré », un état qu'un rail sait signaler et
qui se répare en une ligne : il était invisible, un état qu'aucun rail de ce
script ne sait signaler.** Et une entrée `GATES` ne pouvait pas y remédier, car la
boucle construit `$root/nova/tests_ntasm_<nom>.c` par nom : **un fichier du
répertoire parent ne peut pas y être exprimé.** La ligne de tableau que cette
cellule demandait n'existait pas et ne pouvait pas être écrite.

**La mesure avant et après, sur le même journal.** Une exécution complète,
garde-fous activés, du script **inchangé** ne produit pas la chaîne
`EFI_ABI_TESTS` : **zéro** occurrence, dans un journal de 411 lignes. La même
exécution, sur le script étendu, la produit une fois, avec dix-huit checks et
zéro échec. **Les deux journaux sont conservés hors de l'arbre**, et c'est la
seule chose qui rend ce « zéro » vérifiable plutôt qu'affirmatif.

**Ce que la correction a coûté, et c'est la partie qui vaut la lecture.** 52
fichiers `.c` sont assis directement sous `compiler/c` ; 39
définissent un `main` ; **aucun des 39 n'était nommé par une ligne invoquant un
compilateur dans l'arbre.** Il y a quatre telles lignes hors `out/` et
`evidence/`, et aucune ne nomme un fichier de ce niveau. Les trois occurrences de
`tests.c` dans `scripts/ntbuild.sh` sont des **fixtures de refus** — la commande
`check` qui attend le refus `ungranted-quarantine-source` — **ce qui est
l'inverse d'une construction**, et c'est pour cela qu'un nom dans un script ne
suffit pas à dire qu'un fichier est construit.

**Les 28 gates autonomes de ce niveau sont aujourd'hui déclarées et
exécutées**, par la même fonction de construction que les autres, et les 28
rendent leur bandeau avec `failures=0` dans le journal de la même exécution :
**aucune n'a apporté de rouge.** Les 6 autres `main` sont des pilotes, qui
prennent un fichier en argument et rendent 2 sans ; les 4 derniers compilent puis
échouent à l'édition de liens, faute d'une bibliothèque que la liste `LIBS` ne
compile pas — **une gate qui ne lie pas est une gate qui ne peut pas tourner, et
cela est un résidu et non une classification.**

**Et la ligne `U15` de ce registre l'avait déjà remarqué, à la main.** Elle
affirmait qu'un champ n'était épinglé que par un harnais « hors du registre des
93 gates », et son propriétaire proposait en Held de « rattacher le harnais
existant au registre ». Le harnais en question est
`tests/c/ntasm/tests_conformance.c`, et il rend
`CONFORMANCE_TESTS checks=26 failures=0`. **Un défaut que l'on ne peut découvrir
qu'en lisant les fichiers un par un laisse exactement la signature qu'il a
laissée** : ici, une ligne de registre quibutait sur un trou que personne
d'autre n'avait vu parce que personne n'avait mesuré le répertoire.
