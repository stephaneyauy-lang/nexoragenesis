# NTASM v0 — paquet de travail exécutable après B2

Statut : **contrats candidats et ordre d'exécution**, non norme adoptée.

Ce document transforme les exigences A1–A10 et les dix prérequis de
`spec/ntasm/ntasm.md` §17 en lots testables. Il ne modifie ni `spec/ntasm/ntasm.md`, ni le
profil fermé S0. Une proposition ci-dessous ne devient normative qu'après une
décision explicite et une révision de la spécification autoritative.

## 1. Vérité de départ

### Existant vérifié au moment du premier paquet (historique)

- `spec/ntasm/ntasm-s0.md` définit le seul langage de bootstrap exécutable : profil
  borné, 30 mnémoniques, PE `B1-PE-v1`, diagnostics et limites S0.
- La paire `compiler-host.ntasm` / `compiler-core.ntasm` traite des sources S0
  externes et ses trois exports sont exercés pendant `StartImage` sur 237 cas;
  l'état et les hashes sont consignés dans `MEM.md` et
  `out/ntasm/native-modular-source-checkpoint.md`.
- `NTLB0001` et `NTLC0001` décrivent une liaison UEFI synchrone, interne au
  bootstrap. `legacy/docs/bootstrap/module-abi.md` dit expressément qu'elle n'est ni
  la grammaire ni l'ABI des modules typés v0.
- Le producteur S0 dépend encore de NASM quarantainé. Le writer natif, la
  conformité S0 exhaustive et le point fixe B2 sont des travaux séparés en
  cours. Ils ne constituent aucune preuve A1–A10.

### Conceptuel mais non figé

`spec/ntasm/ntasm.md` fixe la direction `destination, source`, la forme générale des
modules/fonctions, `ptr<espace,T>`, les familles de contrats, macros AST,
comptime, stubs et le flux NTIR → Machine IR → encodeur. Il reconnaît lui-même
que la grammaire complète, les catalogues, l'ABI, les schémas IR/NXO, les
plafonds numériques et le corpus restent ouverts.

### Interdictions de promotion

- Aucun résultat S0, NTLB/NTLC ou parseur partiel ne peut être étiqueté module
  typé v0.
- Aucun comportement v0 ne doit entrer dans le seed S0.
- Macros, types et contrats ne démarrent pas en parallèle tant que leurs
  interfaces AST/HIR, target, diagnostics et provenance ne sont pas gelées.
- Les fichiers de `out/ntasm/agent-v0/` sont des oracles documentaires, pas des
  sources, outils, binaires, manifests de livraison ou preuves GREEN.

## 2. Décisions bloquantes à prendre

| ID | Décision nécessaire | Pourquoi elle bloque |
|---|---|---|
| D1 | Séparation proposée : backend x86_64 commun; targets, ABI et sorties explicites et distincts pour application EFI et code système bare | L'hôte actuel de l'outil est UEFI, mais il n'impose pas que les futurs programmes OS soient des applications EFI. La proposition doit être figée dans les catalogues; elle n'est pas une preuve d'implémentation. |
| D2 | EBNF, syntaxe d'import/export versionné et syntaxe des métadonnées ABI/formats | La forme de module existe, mais l'interface intermodule et les versions n'ont pas de surface normative. |
| D3 | Catalogue x86_64 v0 borné et règle d'évolution | A2 exige plus que les 30 mnémoniques S0; aucune liste exhaustive n'existe. |
| D4 | Catalogue fermé des types, espaces, registres, features et intrinsics | Les espaces et intrinsics actuels sont explicitement conceptuels/non exhaustifs. |
| D5 | Algèbre exacte des effets, clobbers et prédicats | Les familles sont décrites, pas les règles de chemins, d'alias et de preuve. |
| D6 | `nx64-abi-v0`, dont frame, appels, interruption et syscall durci | Le snippet syscall normatif de forme est déclaré impropre à l'exécution. |
| D7 | Schémas et encodages canoniques NTIR, Machine IR et NXO | Le lien NTIR/NIR et le format NXO sont ouverts; A7 ne peut pas être testé sans eux. |
| D8 | Syntaxe et valeurs numériques des six budgets comptime/macro | La spec nomme les ressources mais aucun plafond v0. |
| D9 | Syntaxe exacte et politique des tables de stubs | Seuls les champs sémantiques minimaux sont connus. |
| D10 | Taxonomie des diagnostics v0 et interface de l'outil | Les codes S0 ne doivent pas être étendus implicitement au profil final. |

Résolution technique proposée pour D1 : `x86_64-nexora-uefi` + ABI
`efi-x64-v0` + sortie `pe32plus-efi-v0` pour les applications firmware, et
`x86_64-nexora-none` + ABI `nx64-abi-v0` + sortie `nxo-v0` ou
`pe32plus-system-v0` pour le système bare. Les deux abaissent vers le même
backend x86_64 et les mêmes schémas Machine IR/relocations compatibles. Cette
séparation est un contrat candidat à intégrer lors du gel, pas une extension de
S0, une preuve, ni une affirmation que le bootstrap UEFI dicte la cible finale.

Les D2–D10 sont des décisions techniques de conception à instruire par les
vagues suivantes; seules celles qui changeraient la portée ou contrediraient une
décision du porteur exigent nécessairement son arbitrage. Recommandation : geler
ces éléments dans cet ordre, avec un identifiant de version pour chaque
catalogue. Ne pas inventer une ISA « complète » : commencer
par un catalogue v0 explicitement borné aux programmes d'acceptation, puis le
faire évoluer uniquement par nouvelle version et nouveaux goldens.

## 3. Carte A1–A10

| ID | Définitions utilisables | Trou exact | Dépendances | Acceptation minimale concrète |
|---|---|---|---|---|
| A1 | `ntasm.md` §§3–16; ordre module/target et formes structurées | EBNF, recovery, imports, métadonnées et diagnostics non figés | D1, D2, D10 | Parse de tout le corpus; chaque négatif rend code+span stables; recovery rapporte l'erreur suivante sans produire d'IR utilisable. |
| A2 | Ordre des opérandes, largeur unique, encodeur S0 comme antécédent | Catalogue v0, adressages, features et relocations exhaustifs absents | D3, D4, D7 | Un golden par forme et frontière; erreurs largeur/feature/adressage; octets comparés à un inspecteur indépendant; programme chargé sous QEMU. |
| A3 | Forme `fn`, directions, `@registre`, `never`, `ptr<espace,T>` | Tables complètes, alias/liveness, imports typés et layout de types | D2, D4, D6 | Modules complets positifs; collision de registres, sous-registre incompatible, espace/cast implicite et feature absente refusés. |
| A4 | Sémantique générale §§8–10 | Algèbre fermée et ABI interruption/syscall ouvertes | D5, D6 | Composition transitive des calls; omission de clobber/effet refusée par span; requires non prouvé refusé; chemins normaux et terminaux vérifiés. |
| A5 | AST hygiénique, provenance, six ressources, zéro I/O | Syntaxe, phases, plafonds et diagnostic de dépassement absents | D2, D8, D10 | Cas exact-limit/+1 pour chaque budget; capture, récursion, I/O et preuve fabriquée refusées; expansion déterministe et sans AST partiel. |
| A6 | Champs minimaux d'un stub §11 | Déclaration exacte, table de vecteurs et politiques retour absentes | D6, D9 | AST → NTIR sans re-lexing; ordre numérique; doublon/trou/frame/clobber invalides; au moins un chemin interruption et un syscall durcis sous QEMU. |
| A7 | Pipeline conceptuel §14 et invariants §15 | Schémas sérialisés, NXO, mapping PE, inspecteurs absents | D7 | Round-trip inspecteur, rejets de versions/champs réservés/W+X; goldens NTIR/MIR/NXO/PE; mêmes entrées → mêmes hashes. |
| A8 | ADR 0002/0005/0011 et règle de non-contamination | Point fixe et build normal souverain non réalisés | B1/S0 conforme puis B2 | `ntasm2 == ntasm3`; seed reconstruit; trace du build normal sans NASM/quarantaine; mutation de provenance refusée. |
| A9 | Exemples S0 et intention d'outil | Aucun **manifest** de livraison, et aucune installation : l'outil est une sortie de build | D1, D2, D7, D10, A8 | **La surface décidée n'est pas `--target/--emit`**, et la ligne est remise à la surface livrée (28 septembre 2026). Un verbe par sortie, `-o` pour le chemin, les sources positionnelles en nombre quelconque : `assemble SRC... -o OUT.efi`, `object SRC... -o UNIT.nxo`, `link UNIT.nxo... -o OUT.efi`, `check SRC...`, `inspect PROGRAM.efi\|UNIT.nxo`, `-h/--help`, `--version`; codes de sortie 0/1/2/3. `target` est une **déclaration de ligne source** (`target x86_64-nexora-uefi`), jamais un drapeau. « Installation maison » est **répondue, pas contournée** : il n'y a rien à installer, `out/c-bootstrap/ntasm` sur `PATH` ou le chemin complet. `source → NXO/PE → inspect → QEMU` est fait, et le rejeu depuis un répertoire propre aussi (`ntbuild.sh clean && build`, incrémental sur manifeste de contenu). Reste ouvert : le critère reste OUVERT tant que A8 l'est. |
| A10 | Invariants largeur, sections, ABI, macros, déterminisme | Aucun corpus v0 ni baseline de diagnostics | A1–A9 | Mutants dédiés largeur/registre/section/ABI/budget/layout; triple build identique; diagnostic attendu exact. |

La matrice machine-lisible correspondante est
`out/ntasm/agent-v0/a1-a10-matrix.csv`.

**Pourquoi `--target/--emit` a été écrit, et pourquoi il n'est plus demandé.**
Ce paquet est un cahier des charges, pas un relevé : la ligne A9 énumérait D1
et D10 comme des décisions **à prendre**, et `--target/--emit` était la forme
pressentie tant qu'aucune n'était prise. La décision a été prise dans l'autre
sens — un verbe par sortie, `-o` pour le chemin — et elle est décrite, avec les
codes de sortie et le refus de réinterpréter `-o` ailleurs qu'à sa place, dans
`docs/guides/ntasm-cli.md` §2 « The surface » et ses rubriques « Verbs », « Flags »,
« Exit codes ». Le critère n'est pas affaibli : il est écrit contre la
surface qui existe, et la surface qui existe est vérifiée (`ntbuild.sh
selftest` reprint les huit programmes épinglés, `NTSELFHOST_COMPARE
compared=8 converged=8 pinned=8`). Ce qui reste réellement absent est écrit
dans la colonne « Trou exact » et nulle part ailleurs.

## 4. Carte des prérequis §17

| §17 | État honnête | Sous-contrat livrable | Gate documentaire |
|---:|---|---|---|
| 1 | Partiel conceptuel | `grammar-v0` : EBNF entière, tokens, commentaires, recovery et spans | Tous les exemples ont un arbre ou un diagnostic attendu; ambiguïtés LR/LL résolues explicitement. |
| 2 | Partiel conceptuel | `x64-target-v0` : types, espaces, registres/alias, features, intrinsics et ISA | Chaque entrée porte signature, feature, privilège, effets, encodage et cas frontières. |
| 3 | Partiel conceptuel | `predicate-v0` : ensemble fermé et règles de transfert | Tout prédicat a constructeur typé, invalidation, règle de preuve et diagnostic. |
| 4 | Partiel conceptuel | `effect-v0` : lattice fermé, footprint et composition par CFG | Cas de `contract-cases.csv` décidés, y compris chemins divergents et calls. |
| 5 | Ouvert | `nx64-abi-v0` et profils UEFI/syscall/interrupt séparés | Prologues/frames/volatils/retours définis; goldens QEMU sûrs. |
| 6 | Ouvert | Schémas `ntir-v0`, `mir-x64-v0`, `nxo-v0` et mapping `pe32plus-v0` | Sérialisation canonique, version/rejet, inspecteur et goldens indépendants. |
| 7 | Partiel conceptuel | `meta-v0` : syntaxe, phases, six plafonds numériques et provenance | Limite et limite+1 pour chaque ressource; aucun I/O; replay byte-identique. |
| 8 | Partiel conceptuel | `stub-v0` : AST des déclarations et politiques par ABI | Tables positives/négatives; génération NTIR sans texte ni second lexer. |
| 9 | Absent | Corpus versionné avant comportement | IDs stables; positif/négatif/golden pour chaque règle, sans oracle auto-référentiel unique. |
| 10 | Règle présente, preuve v0 absente | Gates `V0-SPEC`, `V0-FRONT`, `V0-META`, `V0-OUT`, `B2.1` | Scan du seed prouvant zéro feature v0; chaque gate référence artefact, hash, test et marqueur. |

## 5. Contrats candidats assez précis pour écrire les goldens

### 5.1 Types machine et fonctions

Proposition à faire accepter : v0 initial expose `u8/u16/u32/u64`,
`i8/i16/i32/i64`, `bool`, `never` et `ptr<space,T>`; aucune promotion implicite,
aucun entier ↔ pointeur implicite. Les registres sont des emplacements target,
pas des types scalaires. Un `@registre` exige largeur et classe compatibles;
les alias x86 se chevauchent pour la liveness (`rax/eax/ax/al/ah`). Les règles
de zéro-extension d'une écriture 32 bits appartiennent à la signature target.

Une interface exportée est identifiée au minimum par : module, symbole, target,
version ABI, directions/types, bindings de registres, retour, effets, clobbers,
requires et ensures. Le corps ne participe pas à l'identité, mais son hash
participe au build. Un import doit donner ou référencer cette identité complète.

### 5.2 Effects, clobbers, requires et ensures

Proposition autonome `effect-v0` :

1. `effects` est un ensemble fermé, sans négation, et une borne supérieure.
2. `reads_mem(space)` et `writes_mem(space)` sont distincts pour chaque espace;
   `mmio`, `io_port`, `msr`, `control`, `interrupt_state`, `privileged`,
   `changes_flags` et `no_return` sont des atomes séparés.
3. L'effet inféré d'un bloc est l'union de toutes ses instructions et de tous
   les callees atteignables. Tous les chemins sont vérifiés; l'inaccessibilité
   doit être prouvée par le CFG, pas supposée.
4. La déclaration doit être un sur-ensemble. Un atome manquant est une erreur;
   un surplus est un warning stable en v0 et ne change pas le binaire.
5. Le write footprint enregistre toute écriture/alias. `clobbers` contient les
   emplacements dont la valeur d'entrée n'est pas prouvée égale à la sortie.
   Une sauvegarde/restauration exacte peut retirer un clobber, jamais une entrée
   du footprint. Un chemin qui ne restaure pas suffit à imposer le clobber.
6. Les sorties/résultats liés sont validés séparément et ne sont pas ajoutés à
   `clobbers`; tout autre alias détruit doit l'être.
7. Les prédicats sont des termes d'un registre fermé. Un call exige chaque
   `requires` prouvé, tue les faits invalidés par effets/clobbers, puis ajoute
   les `ensures`. `unknown` vaut échec, jamais succès.
8. Pour `-> never`, chaque feuille CFG doit être un transfert terminal reconnu;
   les ensures sont vérifiés au transfert.

Hypothèse à décider : le warning de contrat trop large peut devenir erreur sous
un mode `--strict-contracts`, mais le choix par défaut doit être figé avant A4.

### 5.3 Macros AST et comptime

Proposition autonome `meta-v0` : les six limites sont des entiers `u32`
obligatoires dans le profil de build, inscrits dans le hash et comparés **avant**
l'incrément. Les valeurs par défaut ne sont pas proposées ici : D8 doit les
fixer à partir d'un corpus représentatif. L'ordre d'expansion est source puis
profondeur; la marque d'hygiène est dérivée de `(module-id, span-invocation,
ordinal-expansion)` et non d'un aléa hôte.

Une expansion fautive est transactionnelle : aucun nœud, symbole, effet ou fait
produit n'est publié. Les APIs fichiers, réseau, environnement, temps, aléa,
processus et adresses hôte n'existent pas dans l'évaluateur. Une tentative est
donc un nom/API inconnue, non une opération filtrée après coup. La chaîne de
provenance complète accompagne chaque diagnostic.

### 5.4 NTIR, Machine IR, NXO et PE

Le minimum à figer pour chaque schéma est : magic, version majeure/mineure,
endianness, target, ABI, tables ordonnées, tailles checked, champs réservés à
zéro et règle de compatibilité. NTIR conserve types, espaces, contrats,
intrinsics, provenance et CFG. Machine IR conserve instruction sélectionnée,
opérandes physiques, contraintes, symboles et relocations. NXO transporte des
sections, symboles/imports/exports typés, relocations et un hash d'interface.
PE est une sortie liée; il ne remplace pas NXO ni NTIR.

Ordre canonique proposé : sections par rang du profil puis nom; symboles par
visibilité/module/nom; relocations par `(section-rank, offset, kind, symbol,
addend)`. Toute égalité restante doit conserver l'ordre source canonique. Les
versions majeures inconnues et tout champ réservé non nul sont refusés.

## 6. Ordre de mise en œuvre après S0 et auto-hébergement

1. **Vague 0 — fermer S0/B2** : writer, conformité, point fixe et exclusion
   NASM. Ne pas entamer une feature v0 dans le seed.
2. **Vague 1 — V0-SPEC** : D1–D7/D10, EBNF, target/ISA bornée, ABI et schémas;
   écrire/mutant-tester les fixtures avant le frontend.
3. **Vague 2 — frontend typé minimal** : modules, fonctions, types, symboles,
   CFG et diagnostics; sortie NTIR inspectable, sans macros ni stubs.
4. **Vague 3 — contrats** : effect-v0, prédicats et ABI calls; cas négatifs par
   chemin et appels intermodules.
5. **Vague 4 — sorties** : Machine IR, encodeur commun, NXO puis PE;
   inspecteurs maison et QEMU. C'est ici seulement que le parcours A9 existe.
6. **Vague 5 — meta** : budgets figés, comptime transactionnel et macros AST
   hygiéniques sur l'AST stable.
7. **Vague 6 — stubs** : déclarations structurées abaissées en NTIR, puis tests
   interruption/syscall durcis sous QEMU.
8. **Vague 7 — promotion B2.1** : triple déterminisme, mutants A10, manifest
   A1–A10, build normal sans NASM/quarantaine et guide utilisateur complet.

Chaque vague est RED → GREEN → REFACTOR. Une vague produit : corpus gelé,
diagnostics exacts, sortie inspectable, hashes, marqueur et rapport de reprise.
La réussite d'une vague ne réduit aucune ligne d'A1–A10.

## 7. Artefacts documentaires associés

- `out/ntasm/agent-v0/a1-a10-matrix.csv` : couverture et dépendances.
- `out/ntasm/agent-v0/section17-matrix.csv` : état de gel des dix prérequis.
- `out/ntasm/agent-v0/contract-cases.csv` : cas positifs/négatifs proposés pour
  types, contrats, macros et formats. Les codes `V0-*` sont des identifiants de
  cas, pas des diagnostics normatifs.
- `out/ntasm/agent-v0/grammar-v0-candidate.ebnf` : grammaire de surface candidate
  complète, sans catalogue ISA implicite.
- `out/ntasm/agent-v0/grammar-v0-examples.md` : six programmes positifs, six
  négatifs et registre des choix syntaxiques encore non normatifs.
- `out/ntasm/agent-v0/README.md` : mode d'emploi et limites de ces artefacts.

Ces fichiers permettent à la vague de spécification d'accepter, modifier ou
rejeter chaque contrat sans confondre proposition et implémentation.

## 8. Consolidation Astra du 5 septembre — grammaire et instructions

Le complément courant est `out/ntasm/agent-v0-astra/`. Les états S0 et nombres
d'exports de la section 1 sont un instantané historique; consulter `MEM.md`
et les checkpoints natifs pour leur état courant. Ce lot ne modifie aucun
producteur et ne promeut aucun gate B1/B2/B2.1.

- `grammar-v0.ebnf` : 92 productions tokenisées proposées, distinctes de
  l'ancienne candidate 128 productions conservée. Paramètres multilignes,
  contrats omis et appels liés préservent la surface autoritative de §9.
- `decisions.md` : règles lexicales/spans, priorité des constantes, types
  imbriqués, SIB, quotes AST et récupération transactionnelle. Le snippet
  syscall demeure non sûr, malgré son statut syntaxique autoritatif.
- `x64-forms.csv` et `x64-scope.md` : catalogue fermé proposé de 126 orthographes
  sur 49 familles, formes/largeurs/features/privilèges/diagnostics et exclusions.
  Les masques flags, ABI et goldens d'encodage restent à produire avant gel.
- `corpus.md` : 15 positifs et 19 négatifs, avec production d'entrée et phase
  sémantique indiquée lorsque le négatif n'est pas une erreur de syntaxe.
- `native-integration.md` : lots F0–F8 du parser NTASM natif, interfaces à
  geler, recovery, validation AST puis NTIR, sans contaminer le lecteur S0.
- `check-consistency.ps1 -SelfTest` : contrôle de références EBNF, index du
  corpus, équilibre des positifs, champs/IDs du catalogue et huit mutants
  adverses du checker. Ce n'est **pas un reconnaisseur syntaxique**.

Marqueur documentaire : `V0_DOCUMENT_CONSISTENCY_OK`. Il ne signifie ni que
`compiler-core.ntasm` accepte la grammaire, ni que 126 instructions sont encodées,
ni qu'A1/A2 sont livrés. La prochaine intégration v0 reste F0 puis F1/F2 après
clôture S0/B2 et gel des contrats requis par §17.
