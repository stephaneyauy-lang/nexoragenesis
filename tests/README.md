# Tests

| Dossier | Périmètre |
|---|---|
| `c/ntasm/` | Harnesses C du compilateur NTASM |
| `c/nova/` | Harnesses C qui vérifient Nova et les modules communs |
| `nova/tests/` | Entrées et fixtures écrites en Nova |
| `nova/native-driver-inputs/` | Entrées du protocole des pilotes natifs |
| `runtime/programs/` | Programmes d'exercice du runtime |

Une partie des corpus contient volontairement des sources invalides. Ne pas les corriger comme s'il s'agissait du compilateur. Les anciennes campagnes sous `legacy/tools/` sont des archives ; la réorganisation complète de leurs scénarios n'est pas une preuve qu'ils ont tous été rejoués. Les résultats mesurés sur cette édition figurent dans `../VALIDATION.md`.
