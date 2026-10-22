# B1.12 — alignement mesuré

Contrat avant code : `align WS+ n` accepte seulement les littéraux décimaux
2, 4, 8 et 16 dans les trois sections. Aucune donnée n'est encore écrite.
Le nouveau compteur est `(offset + n - 1) & ~(n - 1)`, avec overflow vérifié
avant addition et contrôle de la capacité de section après alignement.
Un label suivant mémorise ce nouveau compteur.

Valeur ou syntaxe invalide → E201 à l'opérande ou séparateur responsable;
17e token → E101. Dépassement de section/arithmetic u64 → E500 avant mutation
du compteur. TEXT ≤ 32768, RDATA ≤ 16384, DATA ≤ 8192.
Le cas général non pris en charge reste E400; `align8` n'est pas `align 8`.
T12 reste un marqueur de mesure, jamais une preuve d'émission du padding.

Les probes test-only pourront simuler un offset texte déjà mesuré :
1 → align 8 = 8; 32767 → align 8 = 32768;
32769 → align 8 = E500; UINT64_MAX → align 8 = E500.
Les offsets artificiels sont exclus du build canonique et ne constituent
pas une preuve d'émission d'octets.
Corpus : `legacy/ntasm-s0/b1-12-cases.csv`.
