# Mesure et résolution des fixups S0

Contrat avant code : call/jmp/je/jne/jb/jae label .text et mémoire RIP vers
un label des trois sections. Rel32 toujours calculé depuis la fin de
l'instruction, dans i32. Les références peuvent précéder leur définition.
E301 vise le nom source si absent ou de mauvaise catégorie. Les cas golden
sont figés avant l'implémentation dans legacy/ntasm-s0/fixups-cases.csv.

WORK+0x40 compte les fixups, au plus 2048. Records à WORK+0x6400, 24 octets :
source_offset:u32, text_site:u32, next_text_offset:u32, line:u16, column:u16,
name_length:u16, kind:u16 (1=branche, 2=RIP), resolved_rel32:i32.
WORK+0x50/+0x58 reçoivent les RVA calculés rdata/data; aucune sortie disque
ne découle de cette étape seule. La pass 2 et le writer restent nécessaires.

Scratch adresse WORK+0x1C900 réutilise le futur buffer de diagnostic seulement
pendant la sémantique; sa durée de vie se termine avant cleanup/formatage.
