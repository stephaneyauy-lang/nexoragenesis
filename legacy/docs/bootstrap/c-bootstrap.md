# Reprise C — NTASM v0 complet

Décision active du 5 septembre 2026 : utiliser temporairement C pour terminer
NTASM; Nova Bootstrap progresse maintenant en parallèle sur demande explicite.
Dès qu'il est prêt, porter tout NTASM en Nova, conserver C comme référence
pendant les comparaisons et retirer cette dépendance après reconstructions prouvées.
Cette décision autorise les composants C hôte en quarantaine, pas un OS en C.

## Contrat conservé

Le résultat attendu demeure `docs/status/ntasm-completion.md`, A1–A10. Le frontend,
les vérifications, macros/comptime, stubs, formats, outil utilisable, diagnostics
et point fixe du producteur final doivent être prouvés, pas seulement projetés.
Les preuves S0 et les sources NTASM natives existantes sont des références.

Le bootstrap C applique progressivement la surface de `spec/ntasm/ntasm.md` et la
grammaire candidate `out/ntasm/agent-v0-astra/grammar-v0.ebnf`. Chaque contrat
implémenté est figé et testé avant extension; tant que §17 n'est pas entièrement
clos et A1–A10 satisfaits, l'outil est un bootstrap expérimental explicitement
incomplet. Une construction inconnue doit être refusée avant toute sortie.

## Première révision de contrat d'exécution hôte

- Entrée mémoire `(source,length)`; résultat possédé par l'appelant, libérable
  même en erreur. Aucun accès à un traducteur externe dans la bibliothèque.
- Diagnostics E100 lexical, E200 syntaxe, E500 sémantique, E600 émission,
  E900 comportement non implémenté; span offset0, ligne1, colonne1.
- Grammaire de départ : module puis target puis section .text; fonctions
  typées à contrats explicites. Première cible exécutable : x86_64 UEFI.
- Sortie machine et futurs PE/NXO déterministes; pas de chemin hôte/timestamp.
- Tests hôte : RW pendant copie puis RX pendant exécution, jamais RWX.
- Les littéraux u64 sont préservés bit pour bit. Aucune feature non supportée
  ne devient silencieusement no-op. Tests négatifs avant leurs implémentations.

## Travail jusqu'au résultat complet

1. Producteur C hôte de vrais modules NTASM vers instructions et PE; exemples
   exécutés nativement et sous QEMU, erreurs et protection de l'existant.
2. Fonctions/modules/types, expressions/scopes/CFG et contrats ABI/effets.
3. Catalogue x86_64, mémoire, symboles/relocations et formats NTIR/MIR/NXO/PE.
4. Macros AST/comptime bornés et génération structurée de stubs système.
5. CLI, diagnostics, tests adverses, manifest A1–A10 et reproductibilité.
6. Nova utilisable, portage des producteurs, point fixe et retrait C/NASM du
   build normal final. A8 ne devient pas vert avec un simple rebuild C.

## État

Dernier lot root : host-v7 branche la compilation source séparée. `object app`
conserve les imports externes typés; `object math` produit une bibliothèque
sans main. Les NXO sont relus, liés, puis leur PE retourne42 sous QEMU/OVMF.
Tests source séparée15 Windows+ASan, CLI33 ASan, codegen385/object13 ASan.
Le vrai ntasm.exe Windows exécute les quatre commandes et produit les mêmes
NXO/PE que GCC. Le tests-cli.exe Windows est bloqué par contrôle d'application,
ce qui empêche de revendiquer toute la suite CLI33 sous Windows. Sources et
preuve détaillée dans `out/c-bootstrap/host-v7/checkpoint.md`.

Dernier lot root vérifié : `out/c-bootstrap/host-v6/ntasm.exe` ajoute `object`,
`link UNIT.nxo [MORE.nxo ...] -o PROGRAM.efi` et `inspect UNIT.nxo`. Les imports
NXO sont résolus strictement par nom qualifié, rôle et contrat identique avec
définition exportée; les relocations REL32/DIR64 sont appliquées réellement.
CLI28/28 Windows+ASan/UBSan, linker19/19 Windows+ASan/UBSan dont appel natif
entre objets retournant42. Backend figé machine-v4; pas les évolutions Nova
ou frontend ultérieures. Sources et hashes dans le package; format dans
`spec/formats/nxo-v0.md`. La compilation source séparée avec imports non résolus reste
à brancher dans ce lot v6 (ajoutée dans v7). Exemple comptime-macro : PE objet/link identique au PE direct.

La construction hôte de cette révision lie ntasm.c, frontend.c, codegen.c,
x64.c, conformance.c, cli.c, pe.c, object.c, object_build.c,
object_materialize.c, object_link.c et main.c, avec leurs headers figés.
Les paragraphes suivants conservent l'historique des lots précédents.

Première verticale vérifiée : module NTASM avec fonction main retournant un
littéral u64 → code machine → PE32+ de 3072 octets. Le writer PE est C maison,
sans appel à un outil externe. Compilation GCC/WSL et Clang/Windows du producteur
donne le même PE SHA256 `1ecdb7eec14d2db1a2ff47923b9bf213ffa149618c42c54b7ec1b6922da99457`.
21 contrôles de génération/PE/déterminisme, sanitizer propre. CLI `assemble`
et `check`, sortie préexistante refusée et conservée :6 contrôles verts.

Preuves QEMU natives : out/c-bootstrap/uefi/{return42,return43,returnmax}-green.
Le consommateur UEFI est un test C externe explicitement étiqueté; il charge le
PE produit, valide ses plages et appelle la fonction à sa base réelle. Les
valeurs42,43 et u64max sont comparées à EXPECT.BIN; wrong-value-green refuse
effectivement43 quand42 est attendu. Tous reviennent au firmware avec transport
HMP fermé et exit0. Le PE n'est pas seulement reconnu par son marqueur.

Le profil C actuel reste partiel. Aucun contrat A1–A10 n'est promu par ce seul
parcours. Frontend/encodeur complets, intégration, métaprogrammation, stubs et
portage/auto-hébergement final demeurent requis. Un seul agent Sol High assure
le travail délégué après demande de maîtrise des coûts; aucune dépense illimitée
ou plafond automatique n'est promis.

## Intégration vérifiée host-v2

Snapshot utilisable pour les constructions couvertes :
`out/c-bootstrap/host-v2/ntasm.exe`, sources complètes sous `sources/`, hashes
dans `hashes.csv`. Il incorpore le snapshot compiler-green-20260905-2 et la CLI
multi-fichiers. Les sources de travail peuvent être plus récentes.

- Appels forward, paramètres liés aux registres, variables locales, opérations
  entières, branches et imports typés sont réellement abaissés en x86-64.
- Un nom de paramètre désigne son snapshot immuable d'entrée; une expression
  registre explicite lit le registre courant. Les registres/flags temporaires
  du compilateur sont préservés selon les contrats des chemins pris en charge.
- La CLI lit jusqu'à64sources (16Mio par source,64Mio au total); elle appelle
  `nt_compile_many`. Les diagnostics portent un index source one-based.
- Le build Windows et le build GCC de app/math donnent le même PE
  `e02e5d69fd7d0fb001ecb93c1847d6e2b671162c7ae24ab3afdb2916d7bca99a`.
- Tests CLI :14contrôles, puis ASan/UBSan sans erreur ni fuite signalée.
- QEMU : `linked-import-green` appelle math.add(20,22) et rend42;
  `static-data-green` lit42 depuis .rdata réellement chargée;
  `helper-first-green` appelle main à RVA4107, après une autre fonction, et
  rend42. Le mauvais résultat, fichier absent et PE tronqué sont aussi refusés.

Le premier snapshot compiler-green-20260905-1 ne transportait pas encore les
buffers data jusqu'au writer : conserver seulement ses preuves fonctions.
Le snapshot2 corrige ce trou; ne pas distribuer le snapshot1 pour les données.

Ces preuves ne couvrent pas encore toute la grammaire, le catalogue, les contrats,
macros, stubs ou les formats NTIR/MIR/NXO. Aucun A1–A10 complet n'est revendiqué.
