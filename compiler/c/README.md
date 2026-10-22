# Compilateur principal en C — encore actif

`../../scripts/ntbuild.sh` décrit explicitement les 17 unités C du binaire NTASM. Les fichiers ne sont pas sélectionnés par un glob qui compilerait tous les tests.

| Dossier | Responsabilité |
|---|---|
| `ntasm/cli/` | Point d'entrée, options et verbes de commande |
| `ntasm/frontend/` | Lecture des sources et structures du frontend |
| `ntasm/analysis/` | Contrôles de conformité |
| `ntasm/backend/` | Génération et encodage x86-64 |
| `ntasm/formats/` | Objets, liaison, matérialisation et conteneur PE |
| `nova/frontend/` | Compilation des sources Nova par le bootstrap C |
| `nova/backend/` | Chargement des modules Nova du backend MIR |
| `nova/runtime/` | Runtime et chargement hôte des programmes Nova |
| `nova/pe/` | Lecture et vérification du format PE |
| `nova/analysis/` | Analyse des fonctions atteignables |
| `nova/cli/` | Commande Nova distincte de la CLI NTASM |

Après validation et intégration d'A8, le bootstrap C pourra être déplacé dans `legacy/`. Le faire maintenant supprimerait encore une dépendance active. Les trois écarts d'empreintes préexistants sont décrits dans `../../VALIDATION.md`.
