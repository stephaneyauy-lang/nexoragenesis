# Produire et utiliser le producteur NTASM actuel

Réécrit le 28 septembre 2026. **La version précédente décrivait un produit qui
n'est plus celui du dépôt** : elle nommait
`legacy/nasm/ntasm-bootstrap.asm` comme source active et
`legacy/nasm/out/ntasm-bootstrap.efi` comme binaire, et elle
affirmait que le build normal produisait ce producteur. C'était faux dans les
deux sens. Ce qui est réellement produit est décrit ci-dessous.

> **Aucune commande de cette page n'est transcrite.** Chacune a été exécutée
> sur le 28 septembre 2026, dans WSL Ubuntu 24.04 (`gcc (Ubuntu 13.3.0-6ubuntu2~24.04.1`),
> depuis la racine du dépôt. Les blocs `console` reproduisent la sortie réelle.
> Si une ligne ci-dessous ne correspond plus à la sortie de votre poste, c'est
> cette page qui a tort, pas la sortie.

## 1. Ce que le dépôt produit aujourd'hui

Un seul binaire, `out/c-bootstrap/ntasm/ntasm` : l'assembleur NTASM, qui lit
des sources `.ntasm` et écrit soit un objet NXO, soit une application
PE32+ EFI. C'est une **application UEFI produite par un outil hôte** — l'inverse
de ce que décrivait l'ancienne version, qui présentait un exécutable UEFI
(`ntasm-bootstrap.efi`) comme le produit.

Ce binaire est le **producteur de bootstrap externe**, pas l'outil auto-hébergé
que A8 demande. Il le dit lui-même, et il faut le lire avant de citer une de ses
sorties :

```console
$ ./out/c-bootstrap/ntasm/ntasm --version
ntasm 0.0.1-c-bootstrap provenance=BOOTSTRAP_EXTERNAL_C B2.1=not-delivered
```

`B2.1=not-delivered` n'est pas une précaution de style : c'est l'état réel.

## 2. Le build normal

`scripts/ntbuild.sh` est « le build normal » au sens d'`AGENTS.md`. Il compile
et lie **seize unités de traduction C** sous `compiler/c/`, puis
écrit le binaire dans `out/c-bootstrap/ntasm/`. Il n'assemble rien : `ntbuild.sh:85`
refuse `.asm .ASM .nasm .NASM .s .S .sx` comme entrée, et `ntbuild.sh:764-765`
vérifie que le NASM ne peut pas être réintroduit (le refus lui-même est
`ntbuild.sh:308`, `class=forbidden-producer`). *Ces numéros ont été corrigés le
28 septembre 2026 : la table du corpus de `ntbuild.sh` est passée de 14 à 28
lignes, et tout ce qui suit a descendu de 40 lignes.*

La chaîne complète, à froid, depuis la racine du dépôt :

```console
$ bash scripts/ntbuild.sh clean
NTBUILD_CLEAN removed out/c-bootstrap/ntasm
$ bash scripts/ntbuild.sh build
NTBUILD_PRODUCER path=/usr/bin/x86_64-linux-gnu-gcc-13 sha256=1b998261… is_assembler=no is_script=no
NTBUILD_INLINE_ASM_SCAN sources=34 hits=0
NTBUILD_INPUTS_CHANGED units=16 headers=18
  CC compiler/c/nova/frontend/nova.c
  … (15 autres)
  LD /mnt/d/Projets/Racine-C/NexoraGenesis/out/c-bootstrap/ntasm/ntasm
NTSELFHOST_BEGIN policy=NTBUILD-POLICY/1
NTSELFHOST_CORPUS members=8 from=ntbuild.sh-corpus
NTSELFHOST_PRODUCERS a=-O2 sha256=96e000e9… b=-O0 sha256=26abbc66… distinct=yes
NTSELFHOST_COMPARE compared=8 converged=8 pinned=8
NTSELFHOST_RESTORE sha256=96e000e9… reproduced=yes
NTBUILD_SELFHOST_RESTORE sha256=96e000e9… verified=yes
NTBUILD_OK policy=NTBUILD-POLICY/1
producer=gcc flags=-std=c11 -O2
binary=out/c-bootstrap/ntasm/ntasm
bytes=377352
sha256=96e000e98687c4aa32cec02a0c762e49a2864ee4593ec11c6a56bcb92e3b5531
provenance=BOOTSTRAP_EXTERNAL_C
version=ntasm 0.0.1-c-bootstrap provenance=BOOTSTRAP_EXTERNAL_C B2.1=not-delivered
selfhost=compared=8 converged=8 pinned=8 depth=0
input_units=16 input_headers=18
```

~23 s sur ce poste, `clean` compris. Le binaire complet fait
`96e000e98687c4aa32cec02a0c762e49a2864ee4593ec11c6a56bcb92e3b5531`,
377 352 octets.

**Ce digest est une valeur de l'arbre, pas une constante.** Il change dès
qu'une des seize unités ou dix-huit en-têtes change, et le dépôt est
activement édité. Ne citez jamais ce digest sans nommer la révision des
sources avec lui. À titre de comparaison, `docs/guides/ntasm-build.md:157` enregistre
`-O2 → fae0ae67…`, qui ne correspond plus à l'arbre du 28 septembre : c'est
une divergence à trancher par le porteur de ce document, pas un chiffre à
répéter.

### Ce que le point fixe prouve, et ce qu'il ne prouve pas

`build` appelle `scripts/ntselfhost.sh` tout seul, pour que la vérification ne
dépende pas de la mémoire de personne. Elle reconstruit le producteur, compare,
et **restaure** ensuite le binaire que le build avait lié ; si la restauration
ne rend pas exactement les mêmes octets, le build échoue. La ligne
`NTBUILD_SELFHOST_RESTORE … verified=yes` est cette preuve.

Ce que la comparaison mesure est dit par le script lui-même, et il le dit
négativement :

```console
$ bash scripts/ntselfhost.sh
NTSELFHOST_COMPARE compared=8 converged=8 pinned=8
NTSELFHOST_BOUNDARY fixed_point_proven=no
  reason:the producer's source is C; the producer consumes .ntasm v0.
NTSELFHOST_DONE compared=8 failures=0 evidence=out/c-bootstrap/selfhost
```

`fixed_point_proven=no` est exact et doit être cité tel quel : un point fixe de
A8 exige un producteur écrit dans le langage qu'il consomme, et celui-ci est
écrit en C. Les huit entrées comparées sont les sept exemples de la section 4
de `docs/guides/ntasm-cli.md` plus le couple deux modules de `c-bootstrap-multi/`, pas
un corpus de compilateur.

## 3. Les autres commandes, et quand les employer

Toutes exécutées le 28 septembre 2026 depuis la racine du dépôt.

| commande | ce qu'elle fait | sortie utile |
|---|---|---|
| `bash scripts/ntbuild.sh build` | compile, lie, vérifie, restaure | `NTBUILD_OK`, digest, version |
| `bash scripts/ntbuild.sh clean` | supprime `out/c-bootstrap/ntasm` | `NTBUILD_CLEAN removed …` |
| `bash scripts/ntbuild.sh check CHEMIN…` | classe des entrées candidates ; n'exit 78 que sur un refus | `NTBUILD_CHECK inputs=N refused=N policy=NTBUILD-POLICY/1` |
| `bash scripts/ntbuild.sh policy` | imprime la politique sans rien construire | les 16 TU, les 12 classes de refus |
| `bash scripts/ntbuild.sh corpus` | imprime le corpus produit épinglé | `nom|sources(+)|sha256`, 8 lignes |
| `bash scripts/ntbuild.sh selftest` | exécute la suite de refus dans les deux sens | `NTBUILD_SELFTEST_DONE pass=32 fail=0` |
| `bash scripts/ntbuild.sh selfhost` | le contrôle de point fixe seul | `NTSELFHOST_DONE compared=8 failures=0` |
| `bash scripts/ntbuild.sh --help` | le résumé en anglais du script | idem |

### Vérifier qu'un chemin est constructible

C'est la seule de ces commandes qui **échoue**, et c'est celle qui répond à
« ce fichier peut-il entrer dans le build ? » :

```console
$ bash scripts/ntbuild.sh check legacy/nasm/ntasm-bootstrap.asm
NTBUILD_REFUSED class=quarantine-nasm-input
  input:   legacy/nasm/ntasm-bootstrap.asm
  reason:  … This build carries no grant for legacy/nasm/ at all, so
           no flag and no environment variable can make this input legal.
           remedy: translate the .ntasm with NTASM itself, or keep working under
           legacy/nasm/ outside the normal build.
NTBUILD_CHECK inputs=1 refused=1 policy=NTBUILD-POLICY/1
$ echo $?
78
```

C'est exactement le refus que l'ancienne version de cette page contournait en
recommandant `nasm -f bin legacy/nasm/ntasm-bootstrap.asm`. Cette
ligne-là est abolie : elle produisait un exécutable UEFI que le build normal ne
peut ni reproduire ni consommer. Si vous avez besoin du producteur S0, il se
construit hors du build normal, sous `legacy/nasm/`, et son
résultat n'est ni un produit ni une preuve A1–A10.

### Le corpus épinglé

`corpus` est la seule liste de programmes que le produit garantit, et elle est
épinglée dans `ntbuild.sh` lui-même :

```console
$ bash scripts/ntbuild.sh corpus
return42|examples/ntasm-v0/c-bootstrap/return42.ntasm|1ecdb7eec14d2db1a2ff47923b9bf213ffa149618c42c54b7ec1b6922da99457
return43|examples/ntasm-v0/c-bootstrap/return43.ntasm|5811fda51dd2e115eabb39cc2d5c688fcc494da29660e4ac817794bc2b127ac3
returnmax|examples/ntasm-v0/c-bootstrap/returnmax.ntasm|f91e4ba4a0aa3901baebf42f227b05fc97439368584b00737e88ae944cd2bbb5
helper-first|examples/ntasm-v0/c-bootstrap/helper-first.ntasm|c74c7db2e1cf0e6f21e96eac129fee50ef77f705d2bbe9e8ee477c6ea4e5e9c3
static-data|examples/ntasm-v0/c-bootstrap/static-data.ntasm|43fddd77fe59b29b11e6e1d0d05ec05e02d159a357484da8090bfe5fe1dc207a
mutable-data|examples/ntasm-v0/c-bootstrap/mutable-data.ntasm|42f6e3459bdf7bf32280dbea534165d453c361a5fe9228135ae7562f48420690
comptime-macro|examples/ntasm-v0/c-bootstrap/comptime-macro.ntasm|1ecdb7eec14d2db1a2ff47923b9bf213ffa149618c42c54b7ec1b6922da99457
multi-app-math|examples/ntasm-v0/c-bootstrap-multi/app.ntasm+examples/ntasm-v0/c-bootstrap-multi/math.ntasm|c9d9786d9edd2210b3b9d90c96f3da7997d3b260d286dd219e7ef174f526c08d
```

Le deuxième champ est une **liste** de sources, jointes par `+`, parce qu'un
programme est un ensemble d'unités de compilation : `multi-app-math` est un
module qui en importe un autre. Toutes les sources d'un membre vont à **un seul**
appel `assemble`, dans l'ordre écrit. Ce membre est épinglé sur la forme
one-shot, `assemble a b -o x`, parce que c'est la forme que le build et
`ntselfhost.sh` exécutent ; la forme `object` puis `link` donne **d'autres
octets** — 3 584 octets dans les deux cas, 352 différents — et n'est jamais
exécutée par ces deux scripts.

`comptime-macro` porte **le digest de `return42`** : ce n'est pas une faute de
copie, c'est un témoin anti-vacuitée. La macro produit le même programme, donc
les mêmes octets ; dire le contraire serait mentir. `selftest` rejoue les huit à
chaque exécution, ce qui est pourquoi le corpus est une preuve et pas une
table décorative.

Ce que le corpus **ne dit pas**, et qui reste vrai après ce changement : il
n'enregistre que des succès. Il n'a nulle part où écrire « ceci ne doit jamais
s'assembler », donc les deux sources de `c-bootstrap-multi/` qui refusent par
conception — le couple de l'import de donnée, sur `E200 expected 'fn'`, parce
que la grammaire qui lit `import x as y: u64` comme autre chose qu'une signature
de fonction n'existe pas — restent non épinglables. C'est une limite **nommée
et mesurée**, pas un oubli : aucun des deux refus n'est épinglé parce qu'aucun
des deux ne doit le rester.

## 4. Utiliser le binaire

Une fois construit, l'outil s'utilise comme n'importe quel assembleur hôte.
**La surface complète, les codes de sortie, les exemples et le parcours source →
exécutable sous QEMU sont dans `docs/guides/ntasm-cli.md`.** Cette page ne les répète
pas, pour qu'il n'y ait qu'un seul endroit à corriger quand la surface change.

Le minimum, exécuté le 28 septembre 2026 :

```console
$ ./out/c-bootstrap/ntasm/ntasm check examples/ntasm-v0/c-bootstrap/return42.ntasm
NTASM_C_CHECK_OK phase=frontend
$ ./out/c-bootstrap/ntasm/ntasm assemble examples/ntasm-v0/c-bootstrap/return42.ntasm -o /tmp/ret42.efi
NTASM_C_ASSEMBLED bytes=3072 provenance=BOOTSTRAP_EXTERNAL_C
$ sha256sum /tmp/ret42.efi
1ecdb7eec14d2db1a2ff47923b9bf213ffa149618c42c54b7ec1b6922da99457  /tmp/ret42.efi
```

Le digest est celui du corpus ci-dessus : la sortie du build normal est
reproductible sur les huit exemples — dont le couple deux modules, dont la
forme `object`+`link` reste elle-même hors de ce contrôle.

## 5. Ce que cette page ne prétend pas

- Le binaire n'est pas l'outil auto-hébergé. `fixed_point_proven=no` (§2) et
  `B2.1=not-delivered` (§1) disent la même chose de deux côtés.
- Le point fixe de `ntselfhost.sh` porte sur huit programmes d'acceptation, dont
  un à deux modules, pas sur un corpus de compilateur, et pas sur le
  producteur S0. Le passage à une liste de sources est écrit dans
  `scripts/ntselfhost.sh`, section « What the source list changed ».
- Le refus de `check` porte sur les **entrées** de build. Il ne dit rien de ce
  que l'assembleur accepte ensuite comme source `.ntasm` ; c'est le rôle de
  `docs/guides/ntasm-cli.md` §7.
- `ntbuild.sh selfhost` ne compare pas le producteur C au producteur Nova. Le
  script le dit et nomme la piste ouverte : c'est le chemin restant vers A8,
  pas ce que cette commande mesure.
- Les programmes de `examples/ntasm-v0/c-bootstrap/` sont des programmes
  **UEFI** : des images chargées par le firmware. Rien ici ne dit quoi que ce
  soit d'un noyau ou d'un autre ABI.

## Références

- `docs/guides/ntasm-cli.md` — la surface de l'outil, les codes de sortie, les sept
  exemples épinglés et la paire multi-modules de la version 4.1, le parcours
  source → PE qui démarre sous QEMU. Gaté par
  `tests/c/nova/tests_ntasm_cli.c`, **qui ne couvre pas la
  version 4.1**.
- `docs/guides/ntasm-build.md` — la politique de build, les classes de refus, la
  matrice des digests par niveau d'optimisation. **Attention : ses digests
  `-O0`..`-O3` ne sont plus ceux de l'arbre du 28 septembre 2026** (voir §2).
- `docs/status/ntasm-completion.md` — les critères A1–A10 et leur état. C'est la ligne
  A9 que `docs/guides/ntasm-cli.md` prétend répondre ; **elle n'est pas close**, et le
  28 septembre 2026 elle ne portait encore aucun texte d'état.
- `out/c-bootstrap/ntasm/build.log` — la provenance du dernier build.
- `out/c-bootstrap/selfhost/` — la preuve du contrôle de point fixe.
