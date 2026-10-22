# Références addr et préparation des relocations

Contrat préalable : qword addr(label), seulement dans les données et à
alignement naturel 8. Le label peut être défini plus tard, dans toute section.
Mauvaise catégorie/nom absent : E301 au nom. Mauvaise largeur : E400 à addr.
Nom non identifiant : E400. Ponctuation : E201. Limite de références : E500.

WORK+0x60 compte au plus 512 records à WORK+0x12400, 16 octets chacun :
source_offset:u32, section_site:u32, line:u16, column:u16,
name_length:u16, section:u16 (2=rdata, 3=data).
Le site est mesuré en pass 1; la pass 2 émet ImageBase + RVA et un DIR64.
Cette étape ne crée pas encore la table .reloc ni un fichier de sortie.
