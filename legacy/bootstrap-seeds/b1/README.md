# Candidats B1

- `seed-b1.1.efi` / hash `dd6970…87fbe` : candidat historique. Cinq comportements ont été prouvés, mais son chemin E002 existait avant son RED dédié; il n'est pas canonique.
- `seed-b1.1-r1.efi` / hash `86d430…16b7` : candidat B1.1 canonique. Il utilise un unique `Read(13)` et les six comportements LF, CRLF, E001, E002, E100 et E200 ont chacun un RED antérieur puis un GREEN.
- Le candidat B1.2 n'est pas stocké ici : il est externe, non souverain et
  quarantainé sous `legacy/nasm/out/seed-b1.2-r1.efi`. Son tracer
  est GREEN, mais il n'est ni un seed canonique ni une sortie de NTASM.
- Le candidat B1.3 suit la même quarantaine sous
  `legacy/nasm/out/seed-b1.3-r1.efi`. Son tracer est GREEN avec
  préambule `format`/`abi`, mais il reste externe et non souverain.
- Le candidat B1.4 est sous
  `legacy/nasm/out/seed-b1.4-r1.efi`. Son tracer GREEN sonde
  `const IDENT =`, mais ne parse encore aucune valeur.
- Le candidat B1.5 est sous
  `legacy/nasm/out/seed-b1.5-r1.efi`, SHA-256
  `657b3d41dd541cf8630b2b659a29a48c222fc28038516e9e93d176b8db9cadd1`.
  Son tracer GREEN parse les entiers non signés décimaux/hexadécimaux et
  stocke jusqu'à 512 records constants. Il reste externe, quarantainé et non
  souverain.
- Le candidat B1.6 est sous
  `legacy/nasm/out/seed-b1.6-r1.efi`, SHA-256
  `f1246ec2a1922616f9a6031444cb7dde5a8d09083b18effb11cec5ac7bd4f30e`.
  Son tracer GREEN ajoute le signe négatif, la plage négative bornée, le flag
  lexical de `-0` et le rejet E300 des doublons exacts. Il passe le cœur 14/14,
  les snapshots 4/4, B1.5 22/22 et les régressions héritées 56/56, mais reste
  externe, quarantainé et non souverain.
- Le candidat B1.7 est sous
  `legacy/nasm/out/seed-b1.7-r1.efi`, SHA-256
  `169a362b036edce895c1bf4d523f35ce3966d56e0ba6059c0ba3a2a4571f6702`.
  Son tracer GREEN exige `entry IDENT` et passe le cœur 19/19, les snapshots
  7/7, B1.6 14/14, B1.5 22/22 et l'héritage 56/56. Il reste externe,
  quarantainé et non souverain.

- Le candidat B1.8 est sous
  `legacy/nasm/out/seed-b1.8-r1.efi`, SHA-256
  `dafb0aff3407f48e782599475b8ca7a20727767892561dee0ab419852d61ab3e`.
  Son tracer GREEN valide l'en-tête `section .text rx` et classe les
  statements interdits. Les 148 tests finaux passent; NASM reste quarantainé.

- B1.9 puis B1.10 sont promus sous la même quarantaine. Le dernier PE
  `legacy/nasm/out/seed-b1.10-r1.efi` fait 11 776 octets,
  SHA-256 `e673f8f07ee8f5f472f346c19587804f9f34c25677070e3cacd010b57da4b5f7`.
  Il vérifie les trois en-têtes de sections; preuves :
  `out/b1/step-10/promotion-r1/manifest.md`.

Aucun de ces fichiers ne termine la Gate B1. La prochaine étape est B1.11.
