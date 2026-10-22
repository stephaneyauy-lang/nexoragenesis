# Machine IR 1.3 — appel indirect typé (candidat)

Stride 24 conservée, catalogue 40 genres. `call_indirect` 2087 conserve les slots d'arguments du call : `arg_a` est la valeur cible 64 bits non signée, `arg_b/c` les deux premiers arguments, `arg_count=min(3,argc+1)`, `aux=argc` (0..64). `aux2` référence une vraie déclaration `function` servant de signature ; ce n'est pas OP_CALL ni un pointeur natif. Les `call_arg` suivants restent contigus, ordonnés et liés au record d'appel. Largeur/signe/espace du résultat correspondent à la déclaration ; une valeur produite non nulle est de classe VALUE. Flags exactement SIDE_EFFECT|MAY_FAULT, masque23 exactement celui de la signature, retour déclaré compris.

Cible et arguments doivent avoir une définition concrète antérieure disponible sous dominance au site d'appel, jamais seulement une déclaration vreg. Les types des arguments, la signature type_decl, l'arité, les directions IN et le masque sont vérifiés. Les images 1.1 et 1.2 restent lisibles sans 2087 ; 2087 sous une ancienne version est refusé. local_cell reste valide dès 1.2. La sérialisation conserve le tag de l'image.

L'émetteur indirect prend actuellement le transport EFI/ms_abi existant : quatre premiers slots RCX/RDX/R8/R9, suivants sur pile, home32 et alignement16. Cible et arguments sont calculés avant la préparation physique ; la cible est chargée en r11 en dernier, puis l'encodeur maison encode call GPR64. Il n'y a ni relocation vers la déclaration-signature ni recherche de son adresse par nom. Les appels directs conservent leur contrat et leur chemin REL32. Une adresse de code réellement valide et une implémentation respectant la signature sont un contrat du fournisseur du pointeur ; cette vérification structurelle n'est pas une preuve de l'identité du code dynamique. L'entrée Nova ABI2 et ses contrôles de contexte/runtime sont un lot séparé.

Régression de ressources encore ouverte, distincte de 2087 : `tests/fixtures/indirect-callback-handle-exhaustion.ntasm` conserve la sonde longue qui a produit NV2_EXHAUSTED13 dans mnemonic_op sous le runtime actuel. Aucune borne runtime n'est relevée et cette source n'est pas déclarée verte.
# Machine IR 1.2 — cellules scalaires locales, candidat A8

Stride 24 et offsets existants conservés. Le genre `local_cell` 2086 étend le catalogue à 39 genres. Le producteur écrit 1.2 ; le vérificateur accepte aussi 1.1 sans ce genre. Les autres versions sont refusées, et un `local_cell` dans une image 1.1 est refusé. La sérialisation conserve la version de l'image.

`local_cell` est une opération de bloc (depth 3), initialisée au site où elle s'exécute. `value_out` est une adresse opaque non nulle, `arg_a` l'initialiseur déjà disponible, `arg_count=1`, `width=64`, `signed=0`, `space=0`, `class=ADDRESS`, `flags=SIDE_EFFECT`. `aux` porte la largeur stockée 8/16/32/64, `aux2` son signe 0/1. Les champs 20 à 23 sont nuls. La valeur adresse possède une seule définition ; les tranches de registres physiques gardent leur contrat existant.

L'adresse est réservée à `arg_a` direct de `load`/`store` de même fonction, après la déclaration et sous sa dominance. Toute copie, arithmétique, conversion, retour, passage en argument ou stockage de l'adresse est refusé. Initialiseur et valeur écrite ont exactement la largeur et le signe déclarés, sans espace pointeur, classe VALUE ou CONSTANT. Une coercition explicite précède donc l'initialisation/écriture si nécessaire.

Un load local définit une nouvelle valeur snapshot, `arg_count=1`, classe VALUE, flags 0, aux OP_LOAD, aux2 0. Un store local ne définit aucune valeur, `arg_count=2`, classe ADDRESS, flags SIDE_EFFECT, aux OP_STORE, aux2 0. Les accès ont le type stocké et `space=0`. Les initialisations/lectures ne sont jamais anticipées par la résolution récursive des dépendances de l'émetteur : une consommation avant émission effective est refusée. Chaque lecture source doit produire son propre load ; une ancienne valeur chargée reste un snapshot.

L'émetteur réserve deux slots de huit octets par déclaration : adresse immuable et stockage privé. Ils sont alloués avant les cellules GPR/drapeaux et les arguments. Seul `frame()` calcule les déplacements après connaissance de la taille du cadre. Aucun offset rbp/rsp ne vient de la source. Chaque appel, récursif compris, possède son stockage ; une nouvelle exécution de la déclaration réinitialise sa cellule. Cette extension ne définit pas encore les tableaux locaux ni les pointeurs locaux transmissibles au runtime.

Les tables normatives ci-dessous décrivent 1.2 ; les sections historiques sont conservées avec leurs dates.
# Machine IR1.1 — A4, 14 octobre 2026

La stride24 et les offsets1.0 sont conservés ; le nouveau genrecall_arg2083 porte les arguments après les deux premiers inline. Au call, aux reste le nombre total0..64 et arg_count=min(3,aux+1). Chaque extra a arg_a=value_id, arg_b=call_record, arg_count2, aux=ordinal2..63, value_out0, classNONE et owner=bloc. Les extras sont contigus juste après le call, dans l’ordre des ordinals. Les expressionsargument et leurs effets précèdent le call ; leurs valeurs doivent dominer ce site, pas seulement la metadata. Doublons/trous/ordre/owner/lien/valeur future/non-dominante sont refusés. Les images d’une autre version sont actuellement refuséesE_TAG ; aucun reformatage implicite1.0.

ABI : les mir_abi existants désignent les profils des fonctions par digest ; défautmodule puis clausefonction propriétaire. EFI entrées0..3 dansRCX/RDX/R8/R9, suivantes surpile ; home32, alignement16 et capacité64. Nx64 conserve bindings etOUT/INOUT. Les catalogues entry_abi/exit_abi des stubs restent séparés. Les clauses de stubs ne sont pas changées par l’ouverture EFI.

Historique du format antérieur conservé ci-dessous. Les tables normatives portent MIR/1.2 ; preuves courantes dans out/a4-finish-20261014/.

# Machine IR v0 — schéma de l'image et de sa sérialisation

**Statut : lot MIR/1.0 stable, 9 octobre 2026. Derniers contrôles IR 1111/0 et schéma 3733/0, rc0. Les 1259 cas de parité et 30 JOIN ont imprimé zéro échec, mais le gate corpus final a été arrêté par la garde mémoire (rc75) : ce gate n’est pas certifié vert. Voir out/team/RESULT-REGISTER-MODEL.md.**

**D'où viennent les nombres.** Les positions, les noms de champs, les genres, les constantes et les codes de refus
ne sont PAS recopiés du long commentaire du module. Ce sont les réponses du module lui-même : `schema_field`,
`kind_at`, `kind_text`, `FORMAT_*`, `E_*` et `header_text`, lues par `machine-schema-entry.nova`. La porte
`tests_ntasm_machine_schema.c` relit ce document **et** réinterroge le module à chaque exécution. Elle juge aussi des
images réellement produites (`parse` -> `ntir.build` -> `machine_ir.lower` -> `verify` -> `serialize`). Tout
désaccord la rougit : un changement de version ou de disposition n'est jamais absorbé en silence. Les phrases de
description sont de la prose ; seuls les tableaux portent le contrat.

## 1. Forme générale

Une image Machine IR est un tampon plat de mots `u64`. Il commence par un en-tête de `HEADER_WORDS` mots, puis
contient un enregistrement de `NODE_WORDS` mots par nœud. Les identifiants d'enregistrement commencent à 1, et
l'enregistrement `id` est au mot `HEADER_WORDS + (id-1) * NODE_WORDS`. Le premier mot est la balise de format
`magic`. Un lecteur qui ne trouve pas cette balise, ou pas la version attendue, refuse en `E_TAG`.

## 2. Constantes

| nom | valeur | rôle |
|---|---|---|
| `header_text` | MIR/1.3 | premier mot de toute sérialisation |
| `magic` | 0x4D495231 | mot 0 de toute image (« MIR1 ») ; non exporté, lu sur l'image |
| `FORMAT_MAJOR` | 1 | version majeure du format |
| `FORMAT_MINOR` | 3 | version mineure du format |
| `version_pin` | 103 | `FORMAT_MAJOR*100 + FORMAT_MINOR` |
| `HEADER_WORDS` | 10 | mots de l'en-tête |
| `NODE_WORDS` | 24 | mots d'un enregistrement |
| `SCHEMA_FIELDS` | 34 | `HEADER_WORDS + NODE_WORDS` champs nommés par `schema_field` |
| `KIND_BASE` | 2048 | valeur du premier genre |
| `KIND_COUNT` | 40 | nombre de genres |
| `DOMAIN_BIT` | 2 | domaine `machine_ir` du bloc `versions` (`versions.nova`) |

## 3. En-tête (mots 0 à 9, `schema_field(0..9)`)

| mot | champ | description |
|---|---|---|
| 0 | `magic` | balise de format, `magic` du §2 |
| 1 | `major` | `FORMAT_MAJOR` |
| 2 | `minor` | `FORMAT_MINOR` |
| 3 | `record_count` | nombre d'enregistrements |
| 4 | `root` | l'enregistrement de l'unité |
| 5 | `stride` | `NODE_WORDS` |
| 6 | `values` | plus haut numéro de valeur virtuelle |
| 7 | `blocks` | nombre de blocs de base |
| 8 | `domain_bit` | domaine du bloc `versions` sous lequel l'image est produite |
| 9 | `typed_count` | enregistrements portant au moins un mot typé |

## 4. Enregistrement (mots 0 à 23, `schema_field(10..33)`)

| mot | champ | description |
|---|---|---|
| 0 | `kind` | un genre du §5 |
| 1 | `ntir_node` | le nœud NTIR que cet enregistrement EST, 0 s'il est synthétisé |
| 2 | `line` | ligne source, copiée du nœud NTIR |
| 3 | `column` | colonne source, copiée du nœud NTIR |
| 4 | `value_out` | la valeur machine que l'enregistrement définit, 0 sinon |
| 5 | `arg_a` | premier opérande ou lien |
| 6 | `arg_b` | deuxième opérande ou lien |
| 7 | `arg_c` | troisième opérande ou lien |
| 8 | `arg_count` | nombre d'opérandes vivants parmi a, b et c |
| 9 | `width` | largeur en bits, 0 si non typé |
| 10 | `signed` | 0 non signé, 1 signé, 2 sans signe |
| 11 | `space` | bit d'espace pointeur, 0 sinon |
| 12 | `class` | classe Machine IR, 0 à 4 (pas une famille de registres NTIR) |
| 13 | `flags` | bits `FLAG_*` du module |
| 14 | `aux` | propre au genre |
| 15 | `aux2` | propre au genre |
| 16 | `parent` | l'enregistrement propriétaire, 0 pour l'unité |
| 17 | `ordinal` | rang dans le parent, à partir de 0 |
| 18 | `origin` | le nœud NTIR dont l'enregistrement est SYNTHÉTISÉ |
| 19 | `depth` | 0 unité, 1 fonction, 2 bloc, 3 opération |
| 20 | `cell_family` | famille physique GPR 1..16, 0 sans accès |
| 21 | `cell_offset` | décalage de la tranche ou liaison param, 0 ou 8 (ah..bh) |
| 22 | `cell_mode` | bits : 1 lecture GPR, 2 écriture GPR, 4 définition drapeaux, 8 lecture drapeaux |
| 23 | `call_clobbers` | masque explicite des effets de l'appelé ; 16 GPR et bit 17 rflags |

## 5. Genres (`kind_at(i)`, `kind_text(i)`, i = 1..40)

| valeur | nom |
|---|---|
| 2048 | `unit` |
| 2049 | `target` |
| 2050 | `versions` |
| 2051 | `function` |
| 2052 | `extern` |
| 2053 | `block` |
| 2054 | `param` |
| 2055 | `bind` |
| 2056 | `vreg` |
| 2057 | `symbol` |
| 2058 | `const` |
| 2059 | `string` |
| 2060 | `data` |
| 2061 | `align` |
| 2062 | `abi` |
| 2063 | `effect` |
| 2064 | `clobber` |
| 2065 | `asm` |
| 2066 | `address` |
| 2067 | `load` |
| 2068 | `store` |
| 2069 | `copy` |
| 2070 | `binary` |
| 2071 | `unary` |
| 2072 | `select` |
| 2073 | `convert` |
| 2074 | `extend` |
| 2075 | `truncate` |
| 2076 | `call` |
| 2077 | `return` |
| 2078 | `jump` |
| 2079 | `branch` |
| 2080 | `phi` |
| 2081 | `unreachable` |
| 2082 | `space` |
| 2083 | `call_arg` |
| 2084 | `type_decl` |
| 2085 | `contract_expr` |
| 2086 | `local_cell` |
| 2087 | `call_indirect` |

## 6. Sérialisation, ligne d'en-tête

La sérialisation (`machine_ir.serialize`) est un texte ASCII de lignes terminées par LF. La première ligne est
`header_text`, suivie des étiquettes ci-dessous, chacune précédée d'un espace et suivie d'un entier décimal.

| étiquette | mot d'en-tête |
|---|---|
| `records=` | 3 |
| `values=` | 6 |
| `blocks=` | 7 |
| `domain=` | 8 |
| `typed=` | 9 |

## 7. Sérialisation, lignes d'enregistrement

Une ligne par enregistrement, dans l'ordre des identifiants. Elle commence par l'identifiant décimal, puis donne les
étiquettes ci-dessous dans cet ordre. Le mot `aux2`… n'est pas omis : les vingt-quatre mots apparaissent tous, et l'ordre
des étiquettes n'est **pas** l'ordre des mots (`org=` vient en troisième).

| étiquette | mot d'enregistrement |
|---|---|
| `kind=` | 0 |
| `ntir=` | 1 |
| `org=` | 18 |
| `line=` | 2 |
| `col=` | 3 |
| `val=` | 4 |
| `a=` | 5 |
| `b=` | 6 |
| `c=` | 7 |
| `n=` | 8 |
| `w=` | 9 |
| `s=` | 10 |
| `sp=` | 11 |
| `cl=` | 12 |
| `f=` | 13 |
| `x=` | 14 |
| `y=` | 15 |
| `p=` | 16 |
| `o=` | 17 |
| `d=` | 19 |
| `cf=` | 20 |
| `co=` | 21 |
| `cm=` | 22 |
| `cc=` | 23 |

## 8. Refus du vérificateur (`machine_ir.verify`)

| code | nom |
|---|---|
| 930 | `E_TAG` |
| 931 | `E_HEADER` |
| 932 | `E_KIND` |
| 933 | `E_LINK` |
| 934 | `E_SHAPE` |
| 935 | `E_CYCLE` |
| 936 | `E_SHARED` |
| 937 | `E_UNREACHED` |
| 938 | `E_TYPED` |
| 939 | `E_ORIGIN` |
| 940 | `E_INPUT` |
| 941 | `E_VALUE` |
| 942 | `E_TARGET` |
| 943 | `E_VERSION` |
| 944 | `E_ARITY` |
| 945 | `E_SCALE` |
| 946 | `E_NTIR` |
| 947 | `E_FRAME` |
| 948 | `E_FORM` |

## 9. Règles de version

- Changer le sens d'un mot existant, `NODE_WORDS` ou `HEADER_WORDS` est un changement **majeur**.
- Ajouter un bit `FLAG_*` disjoint, ou un sens à un mot jusque-là nul, est un changement **mineur**. `header_text`
  suit `FORMAT_MINOR`.
- Toute modification de §2 à §8 doit être faite dans ce document ET dans le module dans le même lot. La porte
  `tests_ntasm_machine_schema.c` rougit sur le moindre écart, des deux côtés.
- Ce que la porte ne fait PAS : elle ne dit pas quels genres un corpus atteint. `MIR_KINDS_SEEN` est imprimé,
  pas exigé, parce que la couverture des genres est une propriété du pipeline, pas du format.

## 10. Paramètres physiques — révision mineure 0.3

Pour un enregistrement de genre param, aux2 (mot 15) conserve la famille physique calculée par NTIR : zéro signifie sans liaison explicite, 1 à 16 désignent les familles GPR de register_widths. Le vérificateur refuse une valeur supérieure à 16 avec E_TARGET. L'ordinal reste dans aux (mot 14). Les autres genres gardent leur interprétation existante d'aux2. La taille des enregistrements ne change pas. La version est relevée afin qu'un lecteur ancien ne puisse ignorer silencieusement cette information ABI.

Pour le genre space, arg_count (mot 8) est le compteur d'usages calculé par space_counts, pas un nombre d'opérandes. Il est borné par le nombre d'enregistrements ; les trois slots d'opérandes restent nuls.

## 11. Faits de déclaration — révision mineure 0.3, complétée le 6 octobre 2026

Un objet NXO nomme ses symboles, les marque (export, import, fonction, donnée), les place dans une section et les
décrit par un contrat. L'image 0.2 ne portait aucun des faits qui ne viennent pas du code lui-même : l'arbre garde
`export` dans son mot `aux`, que `ntir.nova` ne recopie pas, et l'abaissement réduisait un `clobbers` à une largeur.
Un émetteur qui lisait 0.2 devait donc deviner ou relire le source. Ces faits sont ajoutés sans changer la taille
d'un enregistrement ni le sens d'un mot déjà écrit : des bits `FLAG_*` disjoints de 1..512, et des mots jusque-là
nuls. C'était une révision mineure (§9) ; `header_text` était `MIR/0.3`, la révision n'ayant jamais été publiée sans
eux dans le principal.

| fait | genre | où | source de l'abaissement |
|---|---|---|---|
| `FLAG_EXPORT` (1024) | function, data | mot 13 | le mot `export` dans l'écart avant le nœud, sur la même ligne |
| `FLAG_RDATA` (2048) | data | mot 13 | la section englobante est `.rdata` |
| `FLAG_WDATA` (4096) | data | mot 13 | la section englobante est `.data` ; une donnée sans aucun des deux est un `const` |
| `FLAG_DIR_OUT` (8192) | param | mot 13 | `abi.direction` répond `out`, écrit par `machine_pipeline.lower_tree` |
| `FLAG_DIR_INOUT` (16384) | param | mot 13 | `abi.direction` répond `inout`, écrit par `machine_pipeline.lower_tree` ; aucun bit de direction signifie `in` |
| `FLAG_DIR_UNREAD` (65536) | param | mot 13 | la direction n'a pas été lue : `machine_ir.lower` le pose sur chaque paramètre, la façade le remplace, il reste quand `abi.parameter_mode` répond 0 ; les paramètres produits par macro sont mesurés IN/OUT/INOUT sans UNREAD par machine_pipeline |
| `FLAG_PREDICATED` (32768) | function | mot 13 | un `requires` ou un `ensures` non vide ; le texte des prédicats n'est pas porté |
| nom d'une donnée | data | mots 6-7, `arg_count` 3 | l'empan du nom ; `arg_a` est la valeur initiale ou 0 |
| cible d'un import | function sans corps | premier enfant `mir_symbol` | l'empan du nom qualifié (`math.add`) ; `arg_b`/`arg_c` gardent le nom local |
| masque de clobbers | clobber | mot 5, `arg_count` 1 | `register_widths.clobber_bit` : rax bit 0 … r15 bit 15, rflags bit 17 |
| masque de features | unit | mot 15 | `lm`=1 toujours, puis un bit par entrée (`lm` 1, `msr` 2, `syscall` 4, `sse2` 8, `tsc` 16) |

Le vérificateur tient chaque bit à ses genres et refuse en `E_SHAPE` : `FLAG_EXPORT` hors function/data,
`FLAG_RDATA`/`FLAG_WDATA` hors data ou ensemble, `FLAG_DIR_*` hors param ou deux à la fois, `FLAG_PREDICATED`
hors function.

**La direction a un seul propriétaire.** La règle de lecture du mot `in`/`out`/`inout` appartient à
`abi.nova` (`direction`, sur un nœud de paramètre de l'arbre) ; `tests_ntasm_abi.c` recense ses copies et en
refuse une nouvelle. `machine_ir` n'a pas d'arbre : il ne lit pas la direction et marque chaque paramètre
`FLAG_DIR_UNREAD`. `machine_pipeline.lower_tree`, qui tient l'arbre développé, demande `abi.parameter_mode` pour
chaque enregistrement de paramètre par son nœud NTIR (les identifiants NTIR sont ceux de l'arbre) et écrit la
réponse avant `verify`. Mesuré le 7 octobre 2026 : une première version lisait l'écart dans `machine_ir`, et
refusait en 940 les paramètres produits par une macro (portes `validate` et `splice`). `mir_symbol` est exclu de cette règle parce que son mot 13 est un compte (la profondeur de
qualification), pas un masque. `arg_is` répond 5 (valeur, zéro permis) pour le mot 5 d'une donnée, 3 (pas un
opérande) pour ses mots 6-7 et pour le mot 5 d'un clobber.

Correction de la même révision : un littéral booléen porte maintenant `true`=1 et `false`=0 dans `arg_a`. Il
portait l'inverse (`which-1` sur le code de `boolean_word`, 1 pour `true`) ; mesuré en exécutant
`branching-entry.ntasm`, qui rendait 43 au lieu de 42 par l'émetteur.

## 12. L'émetteur de la chaîne commune (machine_emit.nova)

La façade appelle machine_emit.build avec l'image MIR et les empans des noms et déclarations. L'émetteur vérifie l'image, consomme ses faits et écrit le NXO avec les encodeurs x64_fixed existants. Aucun AST, NTIR, reparse ni producteur de secours ne fournit les octets.

Chaque valeur immuable dispose d'un slot de huit octets, les cellules runtime sont distinctes. À l'entrée, les registres et drapeaux sont capturés avant les calculs synthétiques du cadre. Chaque instruction de la source publie ses drapeaux avant normalisation. Une branche booléenne consomme un prédicat calculé ; un saut conditionnel lit la cellule runtime des drapeaux.

La largeur de destination d'une instruction et la largeur de l'élément mémoire sont distinctes. Un accès plus large que son élément reste refusé, ainsi que div/idiv à deux opérandes. La légalité d'un immédiat est contrôlée par les encodeurs existants sur sa forme et sa signedness MIR : un registre contenant un grand entier n'est pas un immédiat, et un littéral u64 maximal n'est pas un littéral signé -1.

Les lignes JOIN de machine_corpus exigent désormais une exécution correcte, sans échappatoire par refus. Les mutations de vrais records sont dans machine_ir : famille, tranche, largeur, mode, définition/lecture des drapeaux et effets sur un genre inapproprié. Le masque d'appel doit également correspondre à la déclaration du callee à l'émission. Une analyse des drapeaux certainement définis suit les blocs accessibles et intersecte les faits aux jonctions ; un appel qui clobbere rflags tue le fait, et un jcc sans tous les drapeaux requis est refusé en E_INPUT.

## 13. Cellules runtime MIR/1.0

La stride passe de 20 à 24 mots : conformément au §9, la version majeure passe à 1. Les mots 0 à 19 gardent leurs positions. Chaque lecture physique est un vreg distinct, mode 1, dont la valeur est échantillonnée au site d'exécution. Chaque instruction écrit sa famille avec le mode 2 ; 8/16 bits remplacent seulement leur tranche, 32 bits remplace la famille avec extension par zéro, 64 bits remplace tout. Les paramètres IN portent un snapshot immuable indépendant de la cellule du registre lié ; les noms OUT/INOUT lisent la cellule actuelle selon les flags de direction résolus par ABI.

Les cellules vivent dans le cadre de la fonction et sont communes aux blocs : la branche ou boucle exécutée détermine les écritures vues au point de jonction. Aucun phi sans valeur ne prétend représenter ces mutations. Les opérations arithmétiques portent largeur et signe explicites ; les déclarations propagent leur type aux expressions. Les drapeaux sont une cellule dédiée, capturée immédiatement après leur écrivain et restaurée par la branche.

Un appel porte le masque de clobbers déclaré, augmenté des familles OUT/INOUT et de rax si un résultat est déclaré. L'émetteur vérifie ce masque contre la déclaration MIR de l'appelé, fournit les registres depuis les cellules, conserve les paramètres, puis capture les sorties physiques. Les familles hors clobbers restent préservées par le cadre ; les familles clobberées sont publiées à la sortie. Une liaison OUT/INOUT 8/16 bits sans clobber de la famille ne publie que sa tranche et préserve les autres bits sauvegardés.

## 14. Multiplication native et immédiats calculés

OP_UMUL (44) est réservé à asm : un opérande multiplicateur, width8/16/32/64, famille1, offset0, mode6 et value_out0. Il écrit AX pour8bits, DX:AX pour16bits, EDX:EAX avec zero-extension pour32bits ou RDX:RAX pour64bits ; seuls CF/OF sont définis. OP_MUL (4) garde la multiplication d'expression et les formes asm IMUL2/IMUL3, à destination explicite. Les formes MUL2/IMUL1/IMUL2-immédiat restent invalides.

Un immédiat calculé se résout depuis les records MIR constants, copies et opérations pures, avec bits, signe et validité distincts. Les restrictions de magnitude et d'overflow de la référence sont appliquées avant les encodeurs. Un store immédiat utilise la largeur de l'élément annoté, tandis qu'un store registre exige cette même largeur.

DIV1/IDIV1 sont refusés en981 dans le profil actuel, comme DIV2/IDIV2 : la référence exige une preuve runtime safety indisponible (E503 pour les formes1). Aucune implémentation45/46 n'est publiée ; expressions / et % conservent leur chemin typé.

## 15. Signatures et contrats MIR/1.1

Les signatures type_decl2084 portent un propriétaire déclaration (mot5), un type enfant (6), un symbole de paramètre (7), la largeur/signe/espace (9..11), une racine NAMED (13), la forme scalaire/pointeur/tableau (14) et la longueur du tableau (15). Les liens enfants sont en avant, de même propriétaire, sans partage, profondeur64maximum. Les types des paramètres et du retour ne sont pas reconstruits depuis le source dans l'émetteur.

contract_expr2085 est une métadonnée, sans valeur runtime. Son parent16 est la fonction, avec les ordinaux/provenances usuels. Le propriétaire est5 ; les mots6et7 dépendent de la forme15 :1feature(symbole de capability en6),2prédicat(symbole du nom en6,premier argument en7),3paramètre(ordinal en6),4littéral(magnitude6,négatif7),5nom(symbole6),6opération(gauche6,droite7). Le mot14 distingue requires1 et ensures2. NAMED marque les seules racines1/2 ; PURE est présent partout. La largeur9 vaut64ou1 pour un littéral et0 sinon, signé10 vaut0 pour un littéral et2 sinon. Classe12 et espace11 sont nuls.

Pour ce genre uniquement,20 est le lien vers l'argument frère et21 l'opérateur du vocabulaire C des contrats ;22et23 restent nuls. Les règles GPR/runtime ne s'appliquent pas à ces deux mots, mais sont remplacées par les règles strictes du graphe de contrat : liens en avant, propriétaire et clause identiques, racines sans entrant et nœuds internes avec exactement un entrant, arité du catalogue, formes/opérateurs connus, profondeur64maximum. Les autres genres conservent intégralement leurs règles de cellules runtime. Le bit PREDICATED de la fonction doit correspondre à la présence de racines.

L'émetteur formate ces faits, plie les constantes, trie et déduplique les prédicats comme le contrat NXO de référence. Aucun AST, re-lexing ni contrat vide de substitution. Le prédicat feature garde la forme canonique publiée pred(feature) ; le masque de capacités du module est porté séparément par features dans le contrat.