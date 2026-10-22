# B1.11 — labels et table commune

Contrat figé avant code. Dans les trois sections, `IDENT WS? :` définit un
label seul sur sa ligne; aucun autre token ne peut suivre. Les limites
lexicales de 31 octets par identifiant et 16 tokens restent actives.
Le caractère initial doit être lettre ASCII ou tiret bas.
La forme avec deux-points est reconnue avant les mots-clés de statements.

Les constantes et labels partagent le quota de 512 records et l'espace de
noms sensible à la casse. Un doublon, y compris entre sections ou catégories,
produit E300 au nom de la nouvelle définition. La recherche de doublon
précède le contrôle de capacité; un 513e nom nouveau donne E500.

Record de 48 octets : nom[32] terminé par zéro, offset de section u64,
position source u32, ligne u16, métadonnées u16. Bits 0..3 : kind
(constante=1, label=2); bit4 : signe d'une constante; bits5..6 : section
(texte=1, rdata=2, data=3); bit7 : début d'instruction, toujours nul avant
les encodeurs. Les labels portent donc 0x22, 0x42 ou 0x62 à ce tracer.
Ils n'avancent pas l'offset du payload.

Les cinq qwords entry restent immuables; la résolution de la cible entry
attend le bit début d'instruction et le tracer de résolution. EOF après les
trois en-têtes et labels valides produit T11. Aucun fichier de sortie.
Corpus : `legacy/ntasm-s0/b1-11-cases.csv`.
