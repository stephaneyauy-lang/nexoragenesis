# Chaînes et zéro — chantier regroupé

Contrat avant code : ascii/utf16z prennent une chaîne entre guillemets;
zero prend un entier strictement positif. WS obligatoire après le mot-clé.
Les données sont interdites dans .text. Les chaînes sont un seul token,
avec seulement ASCII imprimable brut et échappements \\, \", \r, \n, \t,
\0 et \xHH. E102 vise l'échappement fautif ou EOF si non fermé.
Les commentaires commencent uniquement hors chaîne; un guillemet échappé ne
ferme pas la chaîne. Le lexage borné conserve les 16 tokens.

ascii conserve tous les octets décodés, sans terminaison. utf16z exige des
octets ≤ 0x7F, les élargit en UTF-16LE et ajoute deux zéros terminaux;
un octet supérieur donne E201 au début de son contenu/échappement.
La dernière ligne validée occupe le scratch WORK+0x1C500; taille publiée à
WORK+0x20. WORK+0x28 indique BYTES=1 ou ZERO=2. Pour zero, la taille peut
dépasser le scratch : c'est une description de remplissage implicite, pas
un buffer artificiellement tronqué. La pass 2 exécutera ce remplissage.

zero 0/signe/constante → E201; entier invalide → E102; dépassement de section
ou addition débordante → E500 au mot-clé, avant publication du compteur.
Les offsets s'avancent de la taille mesurée. Aucun fichier de sortie avant le
writer final. Corpus : legacy/ntasm-s0/text-data-cases.csv.
