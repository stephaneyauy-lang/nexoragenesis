# Adressages et instructions mémoire S0

Contrat gelé avant implémentation, dérivé de spec/ntasm/ntasm-s0.md §4–5.
Le groupe couvre lea, load8/16/32/64 et store8/16/32/64 avec base GPR,
SIB optionnel, échelle 1/2/4/8 et déplacement i32 canonique.
RIP et ses fixups restent réservés au groupe suivant, sans acceptation fictive.

Registre destination/source invalide : E400. Base, index et échelle
invalides : E402. Un index rsp/r12 est interdit par le profil. Déplacement
hors plage ou constante négative : E401; symbole absent : E301.
Ponctuation/opérande manquant : E201. Une constante déplacement doit tenir
dans i32 non négatif avant application du signe; le littéral 2147483648
n'est accepté que derrière le signe moins. Aucun octet n'est tronqué.

Les goldens figés dans instructions-memory-cases.csv couvrent les 16 bases,
les tailles de données, REX, SIB et les frontières disp8/disp32.
