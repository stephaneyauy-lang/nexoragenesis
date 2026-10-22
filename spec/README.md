# Spécifications des langages et formats

Les documents ci-dessous définissent le contrat attendu. Les déplacer dans une catégorie ne modifie ni la grammaire ni les formats binaires.

| Domaine | Documents de référence |
|---|---|
| NTASM v0 | [Spécification](ntasm/ntasm.md), [grammaire expliquée](ntasm/ntasm-grammar-v0.md), [EBNF](ntasm/ntasm-v0.ebnf) |
| Nova | [Bootstrap](nova/nova-bootstrap.md), [profil CPU](nova/nova-compute-cpu-r0.md) |
| Représentations intermédiaires | [NTIR](formats/ntir-v0.md), [Machine IR](formats/machine-ir-v0.md) |
| Conteneurs et objets | [NXO](formats/nxo-v0.md), [seed PE32](formats/seed-pe32.md) |
| Cible x86-64 | [Périmètre](x86-64/x64-scope.md), [formes](x86-64/x64-forms.csv), [catalogue](x86-64/ntasm-catalogue-v0.md) |

## Comment lire le contrat

1. La grammaire dit quelles formes syntaxiques existent.
2. Les règles sémantiques décrivent types, appels, registres, effets et contraintes.
3. NTIR/Machine IR portent les étapes de transformation ; NXO/PE décrivent les données émises.
4. Les tests doivent exercer les cas acceptés et refusés. Un parseur qui accepte une source ne prouve pas qu'elle est émise ou exécutable.

Les niveaux NTASM « moins » et « plus », C-Nova, NX, MEM et le langage de scheduler sont des directions de roadmap : ce dossier ne leur invente pas une spécification déjà validée. Voir la [roadmap générale](../README.md#roadmaps).
