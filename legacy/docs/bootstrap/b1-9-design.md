# B1.9 — transition vers les données en lecture seule

Tracer B1.9 GREEN — 5 septembre 2026. Contrat figé avant implémentation.
Après .text rx, reconnaître exactement
`section WS+ .rdata WS+ r` et entrer dans IN_RDATA=5.
EOF avant .rdata devient E200 à EOF; EOF après .rdata produit T09.
Les préfixes sans payload sont toujours provisoires.

Le parseur de section réutilise les limites lexicales B1.8. Mauvais nom/droits
→ E200 au début du token; token absent/extra ou séparateur manquant → E201.
La répétition de .text reste E200 au début de section.
Dans IN_RDATA, tout en-tête répété/futur est E200. Chacun des 30 mnémoniques
S0 est interdit et produit E202 au début de la ligne sémantique. Un mot
inconnu, une directive de données non implémentée, un label ou align donnent
encore E400. Les opérandes ne sont pas encore analysés.

Le descripteur entry reste immuable, TEXT_OFFSET reste nul et l'offset
rdata dans WORK+8 est initialisé à zéro. Aucun octet de sortie n'est produit.
Corpus : `legacy/ntasm-s0/b1-9-cases.csv`, 43 cas figés avant code.

Preuve : `out/b1/step-9/promotion-r1/manifest.md`, cœur 43/43 et
régressions 146/146 après reprise des cas dont le banc avait échoué.
PE 11 776 octets, SHA-256
`df2199d29ecb4f4587cdd5feba04557fd4ce9f7b6d3cd2473bf4b6e66dfc4f64`.
