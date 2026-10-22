# ADR 0005 — `seed0.efi` comme racine binaire initiale

- **Statut :** Accepté
- **Date :** 2026-09-02
- **Amendement temporaire :** ADR 0009 autorise des candidats NASM externes et
  non souverains; `seed0.efi` reste l'unique racine binaire initiale.

## Contexte

Un processeur x86_64 n'exécute pas directement NX, Cnuva, Nova ou NTASM. Puisque tout compilateur et assembleur étranger est exclu du chemin producteur, le premier programme doit être saisi en octets machine. Cette nécessité doit rester visible et auditable : le seed n'est pas « magique » et l'auto-hébergement seul n'écarte pas une attaque de type trusting trust.

## Décision

`bootstrap/seed/seed0.efi` est l'unique racine binaire initiale du bootstrap Genesis.

- C'est un PE32+ x86_64 saisi directement en octets, destiné d'abord à OVMF sous QEMU.
- Sa taille maximale est de 64 Kio.
- Chaque octet est couvert par un ledger `offset -> octets -> rôle` sans trou ni overlay inexpliqué.
- Son hash cryptographique, son layout PE, ses permissions de sections et son comportement observé sont figés comme artefacts.
- Il ne contient aucune section W+X, aucun réseau, plugin, macro générale, code auto-modifiant, entrée non bornée ou allocation non bornée.
- Sa première forme imprime uniquement `NG_SEED0_OK` puis retourne proprement à l'UEFI.
- Son extension vers NTASM-S0 reste strictement bornée : source, symboles, sections, labels, constantes, relocations et sortie ont des limites explicites.
- Dès que NTASM est disponible, `seed0.ntasm` doit reconstruire exactement le seed binaire.
- Un second seed indépendant est différé mais requis à terme pour renforcer la défense contre trusting trust.

Les racines externes x86_64, UEFI/OVMF, QEMU, système hôte et opérateur restent déclarées dans `TRUST.md`; elles transportent, observent ou exécutent le seed sans le produire par traduction.

## Conséquences

- La saisie initiale est lente, sujette à l'erreur et exige une revue offset par offset.
- Si le seed devient trop grand ou inexplicable, NTASM-S0 doit être réduit; un compilateur étranger n'est pas une solution de repli.
- L'égalité bit à bit fournit une preuve de déterminisme, mais pas une preuve absolue d'absence de porte dérobée.
- Le bootstrap reste reproductible et ses hypothèses de confiance sont explicites.

## Non-objectifs

- Prétendre démarrer sans aucune racine de confiance externe.
- Faire du seed un compilateur général, un linker complet ou un environnement extensible.
- Utiliser le seed comme voie permanente de développement après l'auto-hébergement.
- Considérer un hash stable, à lui seul, comme une preuve de sûreté ou d'innocuité.

## Preuves et gates

- Gate B0 : deux exécutions OVMF produisent exactement `NG_SEED0_OK`, retournent proprement et conservent le même hash; le PE est inspectable et sans W+X.
- Gate B1 : ledger couvrant 100 % des octets, limites de NTASM-S0 vérifiées, entrées malformées refusées sans sortie partielle.
- Gate B2 : `ntasm2` et `ntasm3` sont identiques bit pour bit; NTASM reconstruit `seed0.efi` exactement depuis `seed0.ntasm`.
- Toute modification du seed invalide ses preuves et exige un nouveau ledger complet, un nouveau hash et la répétition des gates concernés.
