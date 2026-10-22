# NTIR v0 — schéma de l'image et de sa sérialisation

**Statut : CANDIDAT** (A7.01), 4 octobre 2026. Il repart du brouillon de la session A7 de l'équipe Claude
(`workspaces/A7/spec/ntir-v0.md`, 13 h 44), dont il reprend les règles de refus. La forme des tableaux a changé
pour qu'une porte puisse les lire, et la ligne sérialisée a été corrigée sur le code : le brouillon écrivait
`,<line>:<column>`, alors que `serialize` émet un ESPACE avant la ligne.

**D'où viennent les nombres.** Les constantes, les genres et la balise sont les réponses de `ntir.nova`
(`FORMAT_*`, `KIND_*`, `CLASS_*`, `WIDTH_*`, `SIGNED_*`, `E_TYPE_REFUSED`, `kind_at`, `kind_text`, `header_text`),
lues par `ntir-schema-entry.nova`. `ntir.nova` ne publie PAS les noms de ses champs comme données (il n'a pas de
`schema_field`, contrairement à `machine_ir.nova`). Les NOMS des §3 et §4 sont donc de la prose, reprise du
commentaire du module, mais chaque mot est jugé par son EFFET :
- la ligne sérialisée est relue champ par champ, mot par mot, sur des images réelles ;
- les mots que les règles nomment (`magic`, `major`, `minor`, `node_count`, `stride`, `ast_node_count`) sont
  contrôlés sur ces images ;
- chaque ligne du §8 est rejouée en ABÎMANT une image réelle et en exigeant le code écrit.

Tout désaccord rougit la porte `tests_ntasm_ntir_schema.c`.

## 1. Forme générale

Une image NTIR est un tampon plat de mots `u64` : un en-tête de `HEADER_WORDS` mots, puis un nœud de
`NODE_WORDS` mots par nœud de l'AST. Les identifiants de nœud sont ceux de l'AST, à partir de 1, et le nœud
`id` commence au mot `HEADER_WORDS + (id-1) * NODE_WORDS`. Cinq mots par nœud sont des faits que l'AST n'a pas :
`child_count`, `type_width`, `type_signed`, `memory_space` et `reg_class`. Ils sont calculés à l'abaissement.

## 2. Constantes

| nom | valeur | rôle |
|---|---|---|
| `header_text` | NTIR/0.1 | début de toute sérialisation |
| `magic` | 0x4E544952 | mot 0 de toute image (« NTIR ») ; non exporté, lu sur l'image |
| `FORMAT_MAJOR` | 0 | version majeure |
| `FORMAT_MINOR` | 1 | version mineure |
| `KIND_BASE` | 1024 | premier genre ; bande hors de portée des genres AST (au plus 96) et des codes Nova |
| `KIND_COUNT` | 53 | nombre de genres |
| `HEADER_WORDS` | 8 | mots d'en-tête |
| `NODE_WORDS` | 16 | mots d'un nœud |
| `CLASS_NONE` | 0 | nœud non typé |
| `CLASS_MEMORY` | 17 | opérande mémoire |
| `CLASS_IMMEDIATE` | 18 | littéral entier |
| `CLASS_RELOCATABLE` | 19 | symbole relogeable |
| `CLASS_CONTROL` | 20 | instruction |
| `CLASS_LABEL` | 21 | étiquette |
| `CLASS_LIMIT` | 21 | classe maximale admise |
| `FAMILY_LIMIT` | 16 | plafond des familles physiques de `register_widths` (1 à 16) |
| `WIDTH_MEMORY` | 80 | largeur d'un descripteur mémoire |
| `WIDTH_POINTER` | 64 | largeur d'un pointeur |
| `SIGNED_UNSIGNED` | 0 | non signé |
| `SIGNED_SIGNED` | 1 | signé |
| `SIGNED_NONE` | 2 | sans signe |
| `E_TYPE_REFUSED` | 817 | typage refusé pendant l'abaissement |

## 3. En-tête (8 mots)

| mot | champ | règle |
|---|---|---|
| 0 | `magic` | vaut `magic`, sinon 808 |
| 1 | `major` | vaut `FORMAT_MAJOR`, sinon 808 |
| 2 | `minor` | vaut `FORMAT_MINOR`, sinon 808 |
| 3 | `node_count` | nombre de nœuds |
| 4 | `root` | id de l'unité, dans [1, node_count], sinon 814 |
| 5 | `stride` | vaut `NODE_WORDS`, sinon 814 |
| 6 | `ast_node_count` | vaut `node_count` (l'AST dont l'image est abaissée), sinon 814 |
| 7 | `typed_count` | nœuds portant au moins un mot typé, sinon 814 |

## 4. Nœud (16 mots)

| mot | champ | règle |
|---|---|---|
| 0 | `kind` | un genre du §5, sinon 813 |
| 1 | `source` | copié de l'AST |
| 2 | `line` | copié de l'AST |
| 3 | `column` | copié de l'AST |
| 4 | `start` | copié de l'AST |
| 5 | `end` | copié de l'AST |
| 6 | `ast_kind` | genre AST dont ce nœud est abaissé |
| 7 | `ast_id` | vaut l'id du nœud, sinon 814 |
| 8 | `first_child` | id du premier fils, 0 sans fils |
| 9 | `last_child` | nul exactement quand `first_child` l'est, sinon 818 |
| 10 | `next_sibling` | id du frère suivant, 0 sinon |
| 11 | `child_count` | longueur de la chaîne de fils possédés, sinon 815 |
| 12 | `type_width` | largeur typée, 0 si non typé |
| 13 | `type_signed` | `SIGNED_*` |
| 14 | `memory_space` | bit d'espace pointeur, 0 sinon |
| 15 | `reg_class` | 0, une famille 1 à 16, ou 17 à 21 |

## 5. Genres (`kind_at(i)`, `kind_text(i)`, i = 1..53)

| valeur | nom |
|---|---|
| 1024 | `unit` |
| 1025 | `module` |
| 1026 | `target` |
| 1027 | `versions` |
| 1028 | `version_entry` |
| 1029 | `default_abi` |
| 1030 | `output` |
| 1031 | `features` |
| 1032 | `import` |
| 1033 | `const` |
| 1034 | `comptime` |
| 1035 | `comptime_item` |
| 1036 | `macro` |
| 1037 | `macro_param` |
| 1038 | `stub_table` |
| 1039 | `stub_entry` |
| 1040 | `section` |
| 1041 | `function` |
| 1042 | `parameter` |
| 1043 | `effects` |
| 1044 | `clobbers` |
| 1045 | `requires` |
| 1046 | `ensures` |
| 1047 | `data` |
| 1048 | `block` |
| 1049 | `let` |
| 1050 | `abi_clause` |
| 1051 | `call` |
| 1052 | `return` |
| 1053 | `if` |
| 1054 | `expand` |
| 1055 | `instruction` |
| 1056 | `label` |
| 1057 | `predicate` |
| 1058 | `memory_operand` |
| 1059 | `expr` |
| 1060 | `type` |
| 1061 | `meta_block` |
| 1062 | `meta_let` |
| 1063 | `meta_if` |
| 1064 | `meta_for` |
| 1065 | `meta_return` |
| 1066 | `meta_emit` |
| 1067 | `quote` |
| 1068 | `binding_set` |
| 1069 | `align_stack` |
| 1070 | `name` |
| 1071 | `qualified` |
| 1072 | `dashed` |
| 1073 | `section_name` |
| 1074 | `literal` |
| 1075 | `stub_field` |
| 1076 | `binding` |

## 6. Sérialisation, ligne d'en-tête

Texte ASCII, lignes terminées par LF, décimaux uniquement, sans chemin, adresse, horodatage ni locale. La
première ligne est `header_text`, suivie de ces étiquettes, chacune précédée d'un espace :

| étiquette | mot d'en-tête |
|---|---|
| `nodes=` | 3 |
| `root=` | 4 |
| `typed=` | 7 |

## 7. Sérialisation, lignes de nœud

Une ligne par nœud, par id croissant. Elle commence par l'id décimal, puis donne les champs ci-dessous, dans
cet ordre et rien après. Jetons de séparateur : `SP` = un espace ; `@`, `-` et `:` littéraux ; un jeton qui
finit par `=` est précédé d'un espace. Forme : `<id> <kind> <ast_kind> <ast_id>@<start>-<end> <line>:<column>
c=… w=… s=… sp=… rc=… f=… l=… n=…`.

| ordre | séparateur | mot du nœud |
|---|---|---|
| 1 | `SP` | 0 |
| 2 | `SP` | 6 |
| 3 | `SP` | 7 |
| 4 | `@` | 4 |
| 5 | `-` | 5 |
| 6 | `SP` | 2 |
| 7 | `:` | 3 |
| 8 | `c=` | 11 |
| 9 | `w=` | 12 |
| 10 | `s=` | 13 |
| 11 | `sp=` | 14 |
| 12 | `rc=` | 15 |
| 13 | `f=` | 8 |
| 14 | `l=` | 9 |
| 15 | `n=` | 10 |

Le mot 1 (`source`) n'est pas sérialisé.

## 8. Refus du vérificateur, rejoués par la porte

Chaque ligne nomme un mot, un mot d'en-tête `k` ou un mot de nœud `N<id>.<k>`, la valeur qu'on y écrit sur une
image réelle et valide, et le code que `ntir.verify` doit alors rendre.

| code | mot | valeur |
|---|---|---|
| 808 | 0 | 0 |
| 808 | 1 | 9 |
| 808 | 2 | 9 |
| 814 | 4 | 0 |
| 814 | 5 | 15 |
| 814 | 6 | 0 |
| 814 | 7 | 999999 |
| 813 | N1.0 | 9999 |
| 814 | N1.7 | 99 |
| 815 | N1.11 | 999 |
| 818 | N1.9 | 0 |

Autres codes du module, non rejoués ici : 800 (image absente ou tampon trop court), 816 (cycle, ou nœud
revendiqué par deux parents), 817 (`E_TYPE_REFUSED`, à l'abaissement) et 819 (mots typés qu'aucun genre n'admet).

## 9. Règles de version

1. Un lecteur qui ne reconnaît pas la balise, la majeure ou la mineure refuse en 808, sans autre test.
2. Un producteur écrit les mots 0, 1 et 2 ; aucune valeur par défaut.
3. `KIND_BASE` est une bande : un genre hors de [`KIND_BASE`, `KIND_BASE + KIND_COUNT`) est un refus 813, jamais
   un genre réinterprété.
4. Ce document ne décrit que 0.1. Toute autre paire se publie en modifiant ce document ET le module dans le même
   lot ; la porte rougit sur tout écart, des deux côtés.
5. Ce que la porte ne fait PAS : elle ne dit pas quels genres un corpus atteint. `NTIR_KINDS_SEEN` est imprimé,
   pas exigé.
