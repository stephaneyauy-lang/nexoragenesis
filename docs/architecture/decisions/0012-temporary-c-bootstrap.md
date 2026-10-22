# ADR 0012 — Compilateurs de bootstrap en C

- Statut : accepté par instruction explicite de l'utilisateur.
- Date : 5 septembre 2026.
- Instruction : « go en c finis tout et ne t'arrête pas ne fait pas trop de pause ».

## Décision

Le C est autorisé temporairement pour accélérer la livraison de NTASM. Ses
sources, headers et tests restent sous `compiler/c/`. GCC/Clang et
leur linker construisent ces outils hôte et les consommateurs UEFI de test.
Les artefacts, snapshots et preuves restent sous `out/c-bootstrap/`.

Le producteur NTASM C analyse et vérifie lui-même nos sources, encode lui-même
les instructions et écrit les formats. Il n'appelle pas un compilateur,
assembleur ou linker externe pour traduire les programmes NTASM. La provenance
du producteur est `BOOTSTRAP_EXTERNAL_C`; un test UEFI en C est marqué
`BOOTSTRAP_C_TEST`, jamais présenté comme un noyau Genesis.

Cette exception amende temporairement les interdictions C des ADR 0002/0005,
AGENTS et TRUST. Elle ne change pas le profil S0 et ne réinitialise ni ne supprime
ses sources, binaires ou preuves. Elle ne s'étend pas à l'OS final et ses pilotes.

Nova Bootstrap n'est plus un préalable à l'implémentation de NTASM v0. Le travail
progresse avec C, puis Nova permet le portage des producteurs. A1–A10 restent les
critères de livraison complets, y compris le retrait du producteur extérieur.

## Sortie de la dépendance C

1. Le producteur maison reconstruit le compilateur porté à partir de ses sources.
2. Deux générations successives comparables donnent le même compilateur final.
3. Les mêmes sources NTASM et contrats versionnés donnent les sorties attendues
   avec le producteur de référence et le nouveau producteur.
4. La trace du build normal final ne contient plus de dépendance C/NASM.

Une reconstruction du binaire C par GCC ne satisfait pas ce point fixe. L'égalité
du binaire hôte GCC/Clang avec un compilateur porté n'est pas exigée : ce sont
des implémentations différentes; leurs traductions et la chaîne finale sont les
objets de comparaison pertinents.

## Précision d'ordre ultérieure du même jour

L'utilisateur précise : « nova first comme sa on fini le ntasm avec nova et c ».
Nova Bootstrap devient prioritaire, implémenté en C et utilisant le backend
machine existant; il doit ensuite permettre d'écrire réellement des composants
NTASM en Nova. Le C conserve son rôle d'hôte/runtime de bootstrap. Cette
précision ne supprime aucun acquis ni aucun critère de livraison NTASM.

Correction immédiatement suivante : « mais nan on fait le ntasm mais a vitess
grand V ». La priorité active revient à NTASM en C; Nova est différé. Conserver
les acquis et reprendre les blocs NTASM sans refaire le travail déjà validé.

Décision de portage confirmée ensuite : quand Nova est suffisamment complet et
vérifié, tout NTASM sera porté en Nova. Cela comprend frontend, encodeur, formats
et outil. La version C reste référence pendant la migration; les reconstructions
et la suppression de la dépendance du build normal sont vérifiées avant retrait.

## Validation et coût

Les tests hôte rapides servent aux règles de langage et aux octets. QEMU sert
aux preuves UEFI et machine nécessaires. Les résultats doivent rester complets,
positionnés et inspectables. Un seul sous-agent Sol High est actuellement retenu
pour limiter la consommation; le budget compte est Pro5x avec un reset réservé.
