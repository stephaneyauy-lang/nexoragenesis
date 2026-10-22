# Table des symboles native

Source : legacy/ntasm-s0/native-symbols.ntasm. Les trois fonctions natives
sont native_name_check, native_symbol_find et native_symbol_insert.
Le driver UEFI n'est pas un compilateur complet.

## Contrat et mémoire

Le contexte est une région distincte et lisible/inscriptible de 0x6400 octets.
Le compteur u64 est à +0; les 512 records de 48 octets commencent à +0x400.
Les autres octets du préfixe ne sont pas modifiés. Le contexte est initialisé
par l'appelant et n'est pas modifié concurremment.

- native_symbol_find : RCX=contexte, RDX=nom, R8=longueur.
- native_symbol_insert : RCX=contexte, RDX=candidat lisible de 48 octets,
  non chevauchant avec la table. Le nom du candidat doit se terminer dans ses
  32 premiers octets.
- Retour : RAX=record ou zéro, R10=code, R11=index d'une faute de nom.
- Codes : 0, 101 (nom trop long), 201 (nom invalide), 300 (doublon),
  301 (absent), 500 (plein), 600 (compteur interne au-delà de 512).

La recherche est sensible à la casse et exige le nom entier, pas un préfixe.
L'insertion recherche le doublon avant le contrôle de table pleine. Une erreur
ne publie aucun record. La fin du champ name[32] est mise à zéro sans modifier
le candidat. Les 16 octets de metadata sont copiés exactement; leur sens
type/section/source doit être validé par le frontend appelant.
Les registres non volatils et la pile sont préservés; ces fonctions ne font
aucun I/O et aucune allocation.

## Preuve exécutée

Le driver alloue 0x6420 octets auprès d'UEFI, avec quatre canaris et un payload
initialisé à A5. Il vérifie :

- 512 insertions et 512 recherches, adresses des records et metadata exactes;
- nom de 31 octets, valeur u64 maximale, padding canonique et candidat inchangé;
- doublon à table pleine, 513e nom, absent, casse, préfixe, nom vide/invalide,
  nom non terminé et compteur corrompu;
- les 256 octets en première position, puis en seconde position d'un nom;
- les 24 Kio de records après les refus, le préfixe réservé, les canaris,
  les sentinelles ABI et le succès de FreePool.

Le test exhaustif a trouvé un vrai défaut : appliquer OR 0x20 avant le test
des chiffres acceptait certains contrôles comme chiffres en seconde position.
Le test des chiffres précède maintenant le pliage de casse. Le diagnostic
E900 du driver (L=index, C=phase) est uniquement un outil de test, pas un
nouveau diagnostic de NTASM-S0.

Preuves : out/ntasm/native-symbols-checkpoint.md.
Ce composant reste à intégrer au frontend natif et ne prouve pas l'auto-hébergement.
