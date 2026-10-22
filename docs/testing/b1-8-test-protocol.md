# Protocole B1.8 — section texte

Statut : tracer B1.8 GREEN; Gate B1 RED.

Les oracles sont figés avant code dans les manifests et CSV
`legacy/ntasm-s0/b1-8-cases.csv` (30 cas) et
`legacy/ntasm-s0/b1-8-edge-cases.csv` (5 cas).
Leur provenance est `b1-8-fixtures.md`, avec tailles et SHA-256.

## Exécution

Le runner hôte archivé `out/b1/step-8/run-qemu-oracles.ps1` reçoit les
paramètres `CandidatePath`, `ExpectedCandidateSize`,
`ExpectedCandidateSha256`, `OracleCsv`, `EvidenceRoot` et
`CampaignMode=RED|GREEN`. Il ne produit aucun octet du compilateur.
`EvidenceRoot` doit être absent; les dossiers ESP et variables OVMF sont
créés séparément pour chaque cas.

Le mode RED utilise le PE B1.7 de 9 728 octets, SHA-256
`169a362b036edce895c1bf4d523f35ce3966d56e0ba6059c0ba3a2a4571f6702`.
Les 35 cas observent T07 et divergent tous du contrat B1.8.
Le mode GREEN utilise le PE B1.8 de 11 264 octets, SHA-256
`dafb0aff3407f48e782599475b8ca7a20727767892561dee0ab419852d61ab3e`.

Le banc attend un marqueur réel quelconque Txx/Eddd puis un retour firmware.
`harness_pass` exige un seul marqueur, les hashes conformes, le retour
firmware, HMP exit 0, les trois journaux vides et aucune sortie
`NTASM1.EFI`. `contract_match` compare ensuite exactement ce marqueur à
l'oracle; un mauvais résultat ne doit jamais être présenté comme un timeout.
En GREEN, le premier désaccord arrête la campagne.

## Preuves retenues

Tous les chemins suivants sont sous `out/b1/step-8/`.

| Campagne | Résultat | Dossier |
|---|---:|---|
| RED cœur | banc 30/30, concordance 0/30 | `red30-b17-against-b18` |
| RED cas limites | banc 5/5, concordance 0/5 | `red-edge5-b17-against-b18` |
| GREEN cœur | 30/30 | `green-core-r1` |
| GREEN cas limites | 5/5 | `green-edge-r1` |
| Régressions B1.1–B1.7 | 111/111 | `green-regressions-r1` |
| Snapshot mémoire et désaccord volontaire | 2/2 | `green-snapshot` |

La matrice historique provient de `regression-plan/regression-runtime.csv`.
Neuf anciens oracles changent pour les raisons documentées dans
`regression-plan/mapping.md`; 102 restent identiques.

Le snapshot `B18_SNAPSHOT=1` compare les 48 octets
`(seen=1, off=52, len=8, line=6, line_start=46, text_offset=0)`.
C01 donne T08; C00, dont le descripteur diffère volontairement, donne E603.
Cette détection avait d'abord échoué sur le canonique non instrumenté dans
`red-snapshot`. Le SHA-256 des 48 octets attendus est
`42555b52fd6769db515d3490b1aeb228733a2bc48cf34c7edb04de8517541172`.

Les 148 tests finaux sont verts, les 444 journaux sont vides et le binaire est
reproductible 3/3. La synthèse avec hashes est
`out/b1/step-8/promotion-r1/manifest.md`.
