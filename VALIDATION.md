# Validation de la réorganisation — 22 octobre 2026

**Copie de revue locale. Aucun commit, push ni livraison B2.1 annoncée.**

| Contrôle réellement exécuté | Résultat et portée |
|---|---|
| Compilation du compilateur principal | 17 unités C compilées et liées avec GCC O0 ; contrôle de déplacement distinct du build officiel |
| Corpus NTASM épinglé | 8 PE produits, 8 empreintes identiques aux références antérieures |
| Objet NXO via le backend C | Réussi, 496 octets, exemple return42 |
| Objet NXO via le backend MIR | Non validé : allocation Nova refusée sous la limite de 1 Gio du test |
| Includes C locaux | 730 références, aucune cible manquante |
| Modules Nova chargés explicitement par C | 57 chemins, tous présents |
| En-tête supprimé dans une copie de contrôle | Refus effectif, code 78 |
| Corpus déclaré du build | 9 fichiers épinglés, 3 exclusions, aucun désaccord |
| Syntaxe des scripts actifs et exemples OS | 9 Python et 6 Bash, aucune erreur |
| Liens des nouveaux documents d'entrée | Aucune cible manquante |
| Bannière SVG | XML valide, ressource locale sans script ni service externe |

## Trois écarts préexistants restent visibles

`bash scripts/ntbuild.sh pins --verify` vérifie 35 entrées : **32 conformes, 3 écarts**.

- `compiler/c/nova/frontend/nova.c` : empreinte déclarée antérieure au contenu du principal.
- `compiler/c/nova/frontend/nova.h` : même situation.
- `compiler/c/nova/analysis/seed_reachability.h` : en-tête requis sans empreinte déclarée.

Les références des autres sources ont été adaptées uniquement lorsque l'ancienne source correspondait déjà à son empreinte et que la transformation concernait les chemins/includes. Les trois écarts antérieurs n'ont pas été effacés. Les préimages et empreintes des transformations sont conservées dans le reçu local.

La compilation de contrôle démontre que le déplacement permet de reconstruire le programme et de reproduire son corpus. Elle ne remplace pas l'acceptation du build officiel, toujours bloqué par ces trois écarts de confiance.

## Travail restant

- Valider explicitement les trois entrées avant de mettre à jour leurs empreintes.
- Rejouer le backend MIR avec une enveloppe mémoire adaptée, dans les gardes de la machine.
- Rejouer la suite étendue après déplacement : les chemins construits dynamiquement par les anciens harnesses ne sont pas tous couverts par le contrôle statique.
- Rejouer les OS/QEMU : les chemins des scripts ont été adaptés, pas leurs boots revalidés.
- Terminer A8, dont l'essai 05 s'est arrêté en `paused (shutdown)`, puis finaliser A9.

Les cases A1–A7/A10 du README reflètent les validations enregistrées du principal, pas une certification exhaustive de cette copie. Les archives citées sous `out/` ne sont pas toutes distribuées.

Les traces détaillées de préparation sont dans `.publication-local/`, exclu de Git. Le laboratoire principal, le checkout public avec ses changements OS et la clé USB sont préservés.
