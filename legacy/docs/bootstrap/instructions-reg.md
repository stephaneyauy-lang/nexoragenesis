# Premier groupe d'instructions — registres et immédiats

Contrat avant code, conforme aux octets canoniques de spec/ntasm/ntasm-s0.md §5 :
nop, ret, push/pop GPR, call GPR, mov registre/imm64 numérique, ALU
add/sub/and/or/xor/cmp registre ou imm32 signé, test registre, shl/shr imm8
dans 0..63, imul registre/registre/imm32 signé.

Les 16 GPR sont rax..r15 selon le catalogue S0. Les mémoires et cibles de
branches ne sont pas implicitement acceptées avant leurs encodeurs.
Un registre de destination invalide ou une forme valide mais non supportée
produit E400; syntaxe/virgule/nombre d'opérandes E201; entier E102;
constante absente E301; immédiat hors plage E401.
Les constantes sont permises dans les immédiats sauf mov imm64, numérique
seulement selon le profil S0.

Les instructions mesurent et préparent leurs octets dans le scratch commun,
publient BYTES=1 et incrémentent TEXT_OFFSET et WORK+0x30 (compteur
d'instructions borné). Les labels texte sur le même offset reçoivent le bit
0x80 de début d'instruction. Aucun PE de sortie n'est encore écrit.
Les goldens sont figés dans instructions-reg-cases.csv avant code.
