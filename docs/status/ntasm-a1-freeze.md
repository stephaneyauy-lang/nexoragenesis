# A1 — état du gel v0, 14 octobre 2026

La consolidation technique ci-dessous est vérifiée dans le candidat
`out/a1-a10-a9-20261014/candidate`. Le reçu d'intégration dira quels octets
ont rejoint le principal. Le propriétaire a explicitement approuvé la révision
du point 9 le 14 octobre 2026 : gel vérifié maintenant, tests avant toute
modification ultérieure. Aucun fait historique non démontré n'est affirmé.

| Obligation de §17 | Contrat et preuve | État |
|---|---|---|
| 1. Grammaire et erreurs | `spec/ntasm/ntasm-v0.ebnf`, `spec/ntasm/ntasm-grammar-v0.md` : 68 productions reliées ; 20 fixtures, 9 positives et 11 négatives ; parser 231/0 ; stratégie première erreur, unité suivante indépendante | Technique vérifiée |
| 2. Catalogue | `spec/x86-64/ntasm-catalogue-v0.md`, catalogue x64 existant ; types 102/0, features 30/0 ; registres, effets et ABI conservés depuis A4 | Technique vérifiée |
| 3. Prédicats | §17.3, catalogue de dix prédicats, transfert/invalidation et métadonnées typées ; lot A4 intégré avec corpus complet et contrôle QEMU | Vérifié par A4 |
| 4. Effets/clobbers | §17.4 et A4 ; bits RIP/RFLAGS/GSBASE/FSBASE préservés, refus de contrat falsifié avant émission | Vérifié par A4 |
| 5. ABI | §17.5, nx64/EFI, 0 à 64 arguments ; A4 et A6 distinguent retour ordinaire, interruption et wrapper | Vérifié par A4/A6 |
| 6. Formats | NTIR, MIR/1.1, NXOV0001/PE ; schémas A7 et versions 51/0 après correction du lecteur de déclaration du harnais | Technique vérifiée |
| 7. Macros/comptime | Contrat A5 conservé ; macro_expand 1223/0 et bounds_ceiling 114/0, codes de sortie 0 | Vérifié |
| 8. Stubs | §11 et §17.8, grammaire exacte des quinze champs, preuve A6 intégrée ; aucun ajout de chemin SYSCALL/SYSRET prétendument mesuré | Vérifié par A6 |
| 9. Corpus/goldens du gel, tests avant changements suivants | Corpus négatif externe désormais représentable, 20 verdicts explicitement enregistrés avant exécution ; goldens A7 présents ; la chronologie de tous les anciens goldens avant leurs implémentations n'est pas démontrée | Vérifié au sens de la révision utilisateur |
| 10. Séparation S0/v0 | Trois empreintes historiques préservées ; S0 reconstruit son host à l'identique sous QEMU ; une source v0 est refusée E200 avant tout fichier de sortie | Vérifié sur frontière et artefacts gelés |
| Sans placeholder | Porte placeholder 14/0 ; aucun code produit modifié dans ce lot, aucune opération remplacée par un retour constant | Vérifié sur le périmètre de la porte |

Les preuves de la séance sont dans `out/a1-a10-a9-20261014/GRAMMAR-CHECK.json`,
`VERIFIED.json`, les deux campagnes `s0-boundary/`, et les journaux figés
`out/a7-closure-20261009/out/runs/2026-10-14T21-27-41-293Z-19476` (versions/parser)
et `2026-10-14T21-24-53-694Z-21948` (types/features/macros/bornes/CLI).
La première campagne de bornes interrompue par la RAM ne sert pas de preuve.

## Révision approuvée pour le point 9

Conserver les références existantes avec leurs dates et vérifier le gel actuel.
Pour toute modification ultérieure du comportement v0, écrire les nouveaux
attendus positifs, négatifs et octets de référence avant la correction du code.
Cette règle ne prétend pas reconstruire rétroactivement la chronologie initiale.
Cette décision est appliquée dans le point 9 de `spec/ntasm/ntasm.md` et la ligne
A1.09 de la matrice, sans changer le nombre d'obligations.

## Frontières

La validation structurelle de l'EBNF n'est pas une preuve formelle d'équivalence
avec le parseur ; les fixtures s'exécutent sur le vrai parseur. L'absence de
modification des octets S0 ne prouve pas l'absence de tout défaut historique de
S0. Le contrôle négatif porte sur la frontière des dialectes, pas sur chacun
des mots v0 séparément. A8, le point fixe du producteur final, reste ouvert.
