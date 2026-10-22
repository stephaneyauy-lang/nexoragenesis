# Les compilateurs

Trois ensembles, trois rôles explicites :

| Ensemble | Utilisation actuelle | Guide |
|---|---|---|
| `c/` | Construit le binaire principal NTASM avec GCC. Encore nécessaire tant qu'A8 n'est pas intégré. | [Structure C](c/README.md) |
| `nova/` | Implémentations en Nova ; plusieurs sont chargées par le backend MIR C, et d'autres portent la reconstruction native A8. | [Index des modules](nova/README.md) |
| `runtime/` | Fournit les services d'exécution Nova sur l'hôte UEFI maison. | [Runtime](runtime/README.md) |

Ce dossier contient le code utilisé ou développé pour la chaîne actuelle. Les tests sont dans `../tests/`. Les anciennes voies entièrement séparées sont dans `../legacy/` ; leur présence ne les active pas dans le build normal.

Les noms de modules Nova et les interfaces publiques n'ont pas été renommés : le changement porte sur l'organisation des fichiers et les chemins qui les chargent.
