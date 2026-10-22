# B1.10 — section finale de données en lecture/écriture

Tracer B1.10 GREEN — 5 septembre 2026. Contrat figé avant code.
Après .rdata r, exiger exactement
`section WS+ .data WS+ rw`, puis entrer dans IN_DATA=6.
EOF après ce préfixe complet produit T10; EOF sans .data produit E200.
Les erreurs de tokens, noms et droits suivent le parseur de section B1.9.

Dans .data, les en-têtes répétés sont E200, les mnémoniques connus E202 et
les directives non encore implémentées, labels et align restent E400.
Le payload est provisoirement vide; les trois sections non vides seront
exigées avant la Gate B1. Aucun octet de sortie n'est produit.
L'offset de .data est initialisé dans WORK+16 et doit rester nul.
Corpus de 12 cas : `legacy/ntasm-s0/b1-10-cases.csv`.

Preuve : `out/b1/step-10/promotion-r1/manifest.md`, cœur 12/12 et
régressions 189/189; 603 journaux nuls. PE 11 776 octets, SHA-256
`e673f8f07ee8f5f472f346c19587804f9f34c25677070e3cacd010b57da4b5f7`.
Les tailles et adresses fichier PE sont centralisées dans le source;
cette réorganisation préserve exactement les octets du binaire.
