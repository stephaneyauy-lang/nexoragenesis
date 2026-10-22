# Lexer natif NTASM

Source : legacy/ntasm-s0/native-lexer.ntasm.
native_lex_line et son helper nl_hex_digit sont entièrement écrits en NTASM.
Le reste du fichier est le driver UEFI et ses oracles, pas un compilateur complet.

## ABI et frontières

- RCX : adresse de la ligne sans EOL; RDX : longueur.
- R8 : tampon distinct de 256 octets, soit 16 records {offset:u64, length:u64}.
- L'appelant fournit une région source lisible pour min(RDX,255) octets et
  un tampon de sortie non chevauchant. Aucun pointeur n'est dérivé du texte.
- RAX : nombre de records complets; R10 : 0, 100, 101 ou 102.
- R11 : index fautif, zéro en succès; R9 : début du token fautif, zéro en succès.
- Les registres non volatils et la pile sont préservés. Aucun I/O/allocation.

Le gate physique examine les octets déclarés, commentaires compris. Il accepte
TAB et ASCII imprimable, refuse CR/LF/NUL/non-ASCII et s'arrête avant le 256e
octet. La tokenisation traite whitespace, commentaires hors chaîne, ponctuation,
identifiants de 31 octets, candidats numériques et noms de section.
Les nombres restent des candidats : native_parse_u64 valide leurs chiffres.
Les chaînes valident les échappements et gardent leurs guillemets dans la tranche;
ce lexer ne les décode pas.

Un token invalide n'est jamais partiellement publié. En erreur, les records
précédents restent disponibles; le reste du tampon est inchangé. Le code appelant
devra intégrer ces résultats au collecteur de diagnostics du compilateur :
ce composant seul ne décide pas la priorité globale des erreurs du fichier.

## Preuve

native-lexer-red a échoué avec un corps provisoire avant l'implémentation.
native-lexer-green a passé 32 vecteurs structurés. Le driver étendu a ensuite
exécuté 544 vecteurs dans native-lexer-exhaustive-green :

- 32 cas : adressages, chaînes/échappements, commentaires, limites 31/32,
  16/17 tokens et 255/256 octets, fautes physiques et positions.
- Chacune des 256 valeurs d'un octet comme ligne à un octet.
- Chacune des 256 valeurs comme premier chiffre d'un échappement hexadécimal.

Chaque appel compare les résultats, tous les records et la partie inutilisée
du tampon remplie de A5, les deux canaris et les sentinelles ABI.
Ces vecteurs s'exécutent dans un seul programme UEFI, pas 544 instances QEMU.

Le PE est créé par notre producteur, puis lancé dans une seconde VM.
Marqueur : NG_NTASM_NATIVE_LEX_OK. Cette preuve n'est pas un point fixe
d'auto-hébergement et ne valide pas B2.1.
