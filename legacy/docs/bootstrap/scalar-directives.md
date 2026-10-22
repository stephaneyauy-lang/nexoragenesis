# Directives scalaires — chantier NTASM regroupé

Contrat avant code : byte/word/dword/qword portent respectivement des scalaires
de 1/2/4/8 octets little-endian, en .rdata ou .data seulement.
La liste exige WS après le mot-clé, une valeur puis des valeurs séparées par
virgules. Valeurs : entier décimal/hexadécimal, signe moins contigu facultatif,
ou identifiant de constante. Label et symbole absent : E301.
Les entiers négatifs doivent tenir dans i64 avant conversion; pas de plus unaire.

Les valeurs positives tiennent dans u8/u16/u32/u64; les négatives dans
i8/i16/i32/i64. Dépassement de la largeur : E401 au début du scalaire;
entier lexical invalide ou débordement u64/i64 : E102 sur le premier octet
responsable. L'adresse courante de word/dword/qword doit être naturellement
alignée avant mesure : E402 au mot-clé sinon. Une capacité de section
dépassée produit E500 au mot-clé avant mise à jour du compteur.

La table de tokens reste bornée à 16, soit au plus huit scalaires sans signe.
Un 17e token produit E101. Après validation d'une ligne, les octets sont
matérialisés dans WORK+0x1C500 (scratch 1024 octets) et la taille de la dernière
ligne est publiée dans WORK+0x20. Le compteur de section avance de cette taille.
Cela prépare la pass 2 : aucun PE ni fichier de sortie n'est encore émis.
Une ligne invalide ne publie pas de taille de scratch utilisable.

Corpus figé : `legacy/ntasm-s0/scalars-cases.csv`.
Source modifiée en place : `legacy/nasm/ntasm-bootstrap.asm`.
