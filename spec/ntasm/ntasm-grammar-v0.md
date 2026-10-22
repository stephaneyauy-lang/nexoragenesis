# Grammaire NTASM v0

Contrat syntaxique du parseur Nova, daté du 14 octobre 2026. Le fichier
`ntasm-v0.ebnf` décrit toutes ses productions. Il ne définit ni une seconde
implémentation ni un sous-ensemble S0. L'acceptation syntaxique n'implique pas
l'acceptation sémantique ou l'émission d'un exécutable.

## Lexique

L'entrée est une suite d'octets. Les noms suivent `[A-Za-z_][A-Za-z0-9_]*`,
sensibles à la casse. Les mots-clés sont des tokens NAME reconnus dans leur
contexte ; ils ne constituent pas une nouvelle classe lexicale.

Les entiers non signés ont une valeur comprise entre 0 et 18446744073709551615.
Écriture décimale ou hexadécimale après `0x`/`0X` ; `_` n'est permis qu'entre
deux chiffres de la base. Suffixes, débordements et préfixes sans chiffre sont
refusés. Un signe est un opérateur syntaxique séparé.

STRING est entouré de guillemets doubles. Les échappements sont `\\`, `\"`,
`\n`, `\r`, `\t`, `\0` et `\xHH` (exactement deux chiffres hexadécimaux).
LF, CR et NUL bruts sont refusés dans une chaîne ; les autres octets sont
conservés. Particularité actuelle : le scanner accepte aussi un NUL après un
antislash. Cette compatibilité lexicale ne constitue pas une notation source
recommandée. Aucune interprétation Unicode n'est appliquée aux identifiants.

Espace et tabulation sont ignorés, chacun avance la colonne d'un octet.
`//` introduit un commentaire jusqu'au LF ou à la fin du fichier ; son contenu
est ignoré. Hors commentaire et chaîne, CR n'est admis qu'immédiatement avant
LF. LF produit NEWLINE. Il n'existe pas de commentaire de bloc.

Les tokens composés sont `-> == != <= >= << >> && ||`. Tout autre octet ASCII
imprimable est un token de ponctuation ; cela ne le rend pas valide dans une
production. Hors des exceptions ci-dessus, les octets non imprimables et
non ASCII sont refusés. EOF est toujours ajouté.

La source est limitée à 4194304 octets. Au plus 262142 tokens non EOF sont
admis, puis EOF ; une opération supplémentaire est refusée. Les positions
contiennent source, ligne et colonne (base 1), offsets début inclus/fin exclue
(base 0). La source vide se termine par EOF à la position 1:1.

## Lecture de l'EBNF et contraintes contextuelles

`::=`, alternatives `|`, répétitions `{}`, options `[]`, groupes `()` et
terminaux entre apostrophes composent la notation. Les terminaux lexicaux
externes sont NAME, INTEGER, STRING, NEWLINE et EOF. Les espaces de la notation
ne suppriment pas les NEWLINE du programme. Seule la production Lines le fait.

Les alternatives introduites par un mot-clé ont priorité sur Name ou Qualified.
Une faute après `ptr`, `array`, `expand` ou `intrinsic` ne revient pas à
l'alternative Name. Les instructions génériques n'absorbent pas les énoncés
`let`, `call`, `return`, `if`, `expand` et `align_stack`.

DeclName refuse `true` et `false` hors template (E200, raison 13). Dans un
template macro/comptime/quote, l'analyse syntaxique les conserve pour que
l'expansion signale elle-même l'introduction interdite (E376, raison 3).
Name accepte ces graphies ; leur usage comme booléens est résolu ensuite.

Chaque Term exige `;` ou au moins un LF. La fin du fichier ne remplace pas ce
terminateur. OptionalTerm accepte l'absence de séparateur entre les éléments
explicitement concernés (signature/contrats, contrats successifs, features).
Un LF n'est pas admis arbitrairement entre deux tokens d'une expression.

Dans `quote(stmt)`, Term peut être omis seulement lorsque le prochain token
est `}`. Cela vaut aussi pour les statements imbriqués tant que ce contexte
est actif. Le retour sans valeur conserve toutefois son test explicite :
`return }` est refusé ; écrire `return;` ou `return` suivi de LF.
`quote(block)` n'active pas cette omission. Les formes expr/type/decl ne la
créent pas non plus ; une quote(stmt) imbriquée suit la même règle locale.

Dans Type, `>>` peut être scindé en deux fermetures de types ; dans Expression,
il demeure un décalage. Le paramètre d'array est un token INTEGER, pas une
expression ; l'expansion en position de type utilise TypeArguments et non
MetaArguments. `ast.kind` n'est accepté syntaxiquement que dans MacroType.

Les opérateurs binaires sont associatifs à gauche, avec les priorités de
l'EBNF, du OU logique au produit. Une comparaison ne se chaîne pas sans
parenthèses. Les unaires sont associatifs à droite et plus prioritaires.
Les listes Args/Set/Parameters admettent une virgule finale ; une instruction
générique n'en admet pas. TypeArguments n'admet pas de LF avant son premier
argument ni entre le dernier argument et `)`, sauf après une virgule.

La syntaxe mémoire accepte historiquement la liste vide et un `+`/`-` final.
Le contrôle d'adressage doit les refuser : cette grammaire ne les transforme
pas en adresses exécutables. Le préfixe fs/gs exige `:`. Les champs d'une
entrée stub sont tous présents, exactement dans l'ordre écrit dans l'EBNF.
Une section contient uniquement fonctions, données et expansions. Le parseur
consomme aussi `export expand`, mais l'expansion/validation décide sa validité.

## Erreurs et reprise

La stratégie v0 est l'arrêt à la première erreur de l'unité. Le premier
diagnostic reste stable ; aucune synchronisation interne destinée à produire
plusieurs diagnostics n'est promise. L'arbre retourné est marqué invalide et
son nombre de nœuds publiés vaut zéro. Le caller libère ses buffers et peut
analyser une autre unité avec un nouvel état. Il ne consomme jamais cet arbre
partiel pour émettre du code. Les échecs lexicaux précèdent le parseur.

## Correspondance avec le code

`compiler/nova/frontend/lexer.nova` : scan, lex. Dans `parser.nova` :

| Productions | Fonctions |
|---|---|
| Source, Top | source_tree |
| Name, DeclName, Qualified, Dashed, SectionName | name, decl_name, qualified, dashed, section_name |
| Lines, Term, OptionalTerm | lines, term, tests locaux de terminaison |
| Versions, DefaultAbi, Output, Features | versions_decl, simple_top, source_tree |
| Set, Predicates, Contracts | set_node, predicate_set, contracts |
| Parameters, Function, Import | parameters, function_decl, import_decl |
| Constant, Data, Section | constant_decl, data_decl, section_decl |
| Type, MacroType | parse_type, type_close, macro_type |
| Block, Statement et variantes | block, statement |
| Memory, AddressTerm, Operand | memory, operand |
| Expression et précédences | parse_expression, precedence, primary |
| Arguments, MetaArguments, MetaValue | boucles d'arguments, meta_value |
| Quote | quote_value |
| Comptime, Macro, MetaBlock | comptime_decl, macro_decl, meta_block |
| StubTable, StubEntry, Bindings | stub_table_decl, stub_field, binding_set |

La complétude de cette table est une aide à la revue. Elle ne remplace pas les
cas exécutés ni ne prétend prouver automatiquement l'équivalence de deux
parseurs. Les règles de types, effets, ABI, registres, métadonnées et budgets
restent définies par leurs catalogues et contrôles dédiés.
