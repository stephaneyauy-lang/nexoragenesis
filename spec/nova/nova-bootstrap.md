# Nova Bootstrap — profil hôte minimal

Priorité différée : la dernière correction utilisateur demande de terminer
NTASM en C d'abord (« on fait le ntasm mais a vitess grand V »).

Décision utilisateur : employer NTASM existant pour construire un Nova simple,
puis écrire les composants manquants de NTASM en Nova. Les travaux NTASM v0
existants restent des sources et preuves réutilisables, pas des livraisons finales.

## Chaîne de construction

Révision explicite du 5 septembre : « nova first comme sa on fini le ntasm avec
nova et c ». Le premier compilateur Nova utile est développé en C quarantainé,
sur le backend x86-64 et writer PE maison déjà implémentés. Les sources .nova
sont analysées et traduites par notre code; elles ne sont pas converties en C
puis confiées à un compilateur extérieur. Le runtime C de bootstrap expose une
ABI explicite pour fichiers, buffers, allocations et diagnostics.

Les compilateurs GCC/Clang construisent uniquement ces outils C de bootstrap,
conformément à ADR0012. Le lexer/compiler.ntasm Nova historique et leurs preuves
restent conservés. Le parcours S0 texte antérieur est historique pour cet ordre.
Les schémas privés du backend C ne sont pas présentés comme NTIR/NXO final
tant que ces formats versionnés et leurs inspecteurs ne sont pas livrés.

## Minimum nécessaire avant de porter NTASM

- Types u8/u64/bool, pointeurs/buffers bornés et représentations explicites.
- Fonctions nommées, paramètres, retours, appels et portée lexicale.
- Variables locales, expressions entières, comparaisons, if/else et while.
- Lecture/écriture de buffers, chaînes et tableaux; allocations/libérations.
- Runtime fichiers/diagnostics testé sous UEFI/QEMU; aucune E/S comptime.
- Diagnostics avec positions, refus sans sortie partielle publiée, limites.
- Compilation de plusieurs fichiers/exemples nécessaires à un compilateur.
- Preuve finale de ce bootstrap : porter en Nova un vrai composant NTASM,
  compiler et exécuter ses cas de référence avec résultats identiques.

Le langage n'est PAS déclaré suffisant sur un lexer ou un return42. Le premier
test vertical sera petit, mais ne remplace pas les critères ci-dessus.
L'auto-hébergement Nova est une étape ultérieure, pas affirmé à la création.

## Première convention lexicale

Source ASCII pour ce premier profil, mots identifiants sensibles à la casse
(lettres/underscore puis lettres/chiffres/underscore), espaces/tab/CR/LF trivia.
Tokens initiaux : identifiant, entier décimal u64, ponctuation ASCII isolée,
EOF. Les mots-clés seront résolus par le parser. Les opérateurs composés,
commentaires, chaînes et positions ligne/colonne seront ajoutés avec tests
avant les constructions correspondantes. Un octet invalide ou un entier
dépassant u64 est une erreur positionnée, jamais tronquée.

Ce profil scalaire est un outil de bootstrap, pas un pilote GPU, pas le langage
Nova optimisé complet, ni une nouvelle spécification des probes CPU R0/R1.
