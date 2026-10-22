# Frontière producteur final : proposition NTBH0001

Statut : **contrat d'intégration proposé, non implémenté dans l'hôte partagé**.
NTBUILD2 livre aujourd'hui uniquement `profile=ntasm-s0`. Une requête
`profile=ntasm-v0` est réellement refusée E911. Les drivers parser NV0P0001
et encodeur NX64ENC1 ne sont pas des producteurs complets et restent exclus.

Une frontière privée **NTBH-T01** est maintenant exécutée avec une fixture
explicitement TEST : voir `ntbh-test-abi.md` et
`out/ntasm/agent-release-v0-adapter/checkpoint.md`. Elle vérifie réellement
ENTRY/COMPLETE, les versions, l'ownership et l'intégrité avant publication
du seul format NTBHTEST. Sa signature/profil distincts n'activent pas la
présente proposition publique ni un compilateur v0.

## Dépendance constatée

Le parser expose des fonctions internes de reconnaissance en mémoire sans
AST public, exporttable ou traitement de fichiers. L'encodeur expose des
familles d'instructions et un driver de tests en mémoire; il ne relie pas
encore la syntaxe à une sortie PE/NXO complète. Leurs noms de profils et
leurs marqueurs de tests ne satisfont pas A8/A9. Le refus du profil v0 et
le rejet des deux drivers employés comme NTASM.EFI sont des tests exécutés
dans `out/ntasm/agent-release-integration/`.

La nouvelle génération native S0 utilise les producteurs recovery gelés et
vérifiés; aucune adaptation finale v0 ne peut honnêtement être déclarée avant
un producteur réel, des formats versionnés et les preuves A1–A10.

## Problèmes que la future interface doit résoudre

1. StartImage peut rendre EFI_ABORTED avant l'entrée ou après une erreur du
   programme. Le retour seul ne constitue pas un accusé d'entrée.
2. L'hôte actuel relit le cœur et la source sur disque après vérification.
   Le volume doit rester figé; le lanceur ne supprime pas ce TOCTOU.
3. Une reconnaissance réussie n'est pas un artefact produit. Le consommateur
   doit connaître l'état exact et contrôler le résultat avant publication.

## Proposition de LoadOptions, 128 octets alignés sur 16

Le lanceur possède et conserve le descripteur, les buffers et le callback
pendant StartImage. Tous les nombres sont little-endian u64. Le producteur
valide signature, taille, version, réservés et capacités avant de les utiliser.

| Offset | Champ |
|---:|---|
| 0 | Signature ASCII `NTBH0001` : u64 `0x313030304842544e` |
| 8 | Taille exacte : 128 |
| 16 | Version : 1 |
| 24 | Profil demandé : 1=S0, 2=v0 |
| 32 | Capacités requises : bit0=PE64, bit1=NXO, bit2=source préchargée, bit3=cœur préchargé |
| 40 | Sortie demandée : 1=PE64, 2=NXO; ce champ ne définit pas leur format |
| 48 | Adresse source immuable, non nulle |
| 56 | Longueur source, bornée par le profil validé |
| 64 | Adresse du cœur préchargé immuable |
| 72 | Longueur exacte du cœur approuvé |
| 80 | Callback de progression, efi_x64 |
| 88 | Contexte opaque du callback appartenant au lanceur |
| 96 | Buffer de sortie inscriptible appartenant au lanceur |
| 104 | Capacité de sortie, bornée et entourée de gardes |
| 112 | Réservé zéro |
| 120 | Réservé zéro |

La table n'autorise pas une capacité parce qu'un binaire la déclare : les pins
et le manifeste approuvé restent l'autorité. Le producteur ne peut modifier
le descripteur, le source ou le cœur. Le lanceur en conserve des copies et
contrôle leur intégrité après retour. Aucun pointeur ne survit à StartImage.

Callback : `report(RCX=context, RDX=phase, R8=EFI_STATUS, R9=output_len)`.
ABI efi_x64 : shadow32, pile alignée avant CALL, non-volatils préservés.

- Phase1 ENTRY : après validation de LoadOptions, avant traitement du source;
  status=SUCCESS et output_len=0. Une seule occurrence autorisée.
- Phase2 COMPLETE : exactement une occurrence après ENTRY; status réel final.
  SUCCESS exige output_len dans1..capacité; échec exige output_len=0.
- Une transition invalide est refusée par le callback. Aucun succès ne peut
  remplacer une erreur mémorisée. Le retour StartImage doit concorder avec
  le résultat COMPLETE; l'absence d'ENTRY ou COMPLETE interdit publication.

Le lanceur écrit l'artefact seulement après COMPLETE, vérification des gardes,
intégrité des entrées et contrôle du format/longueur/hash de sortie. La
construction de PE/NXO reste exclusivement dans nos producteurs. Les détails
des diagnostics v0 et de leur canal de restitution restent à négocier avec
l'implémentation finale; les codes NV0P internes ne deviennent pas NGS0.

## Preuves requises avant activation

Producteur réel avec export/version de profil, deux générations reproductibles,
sorties exécutées, ENTRY/COMPLETE manquants ou dupliqués refusés, capacités
insuffisantes refusées, modification de buffers détectée et aucun fallback
vers l'ancien profil ou NASM. Les critères v0 A1–A10 restent indépendants.

Cette proposition ne change ni l'ABI actuelle de compiler-host/core, ni leurs
LoadOptions, ni les formats communs. Son implémentation demande une édition
partagée coordonnée et un producteur adapté. NTBUILD2 n'envoie pas aujourd'hui
ce descripteur à une image qui ne sait pas le consommer.
