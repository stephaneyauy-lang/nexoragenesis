# Protocole de test — tracer B1.7

Statut : **contrat figé avant code ; RED et GREEN validés**. La campagne RED
historique cible exclusivement le PE B1.6 canonique de 9 216 octets, SHA-256
`f1246ec2a1922616f9a6031444cb7dde5a8d09083b18effb11cec5ac7bd4f30e`.
Pendant cette phase RED, aucun source ASM B1.6 ou futur B1.7 ne devait être
modifié ou créé.

## Préconditions byte-exactes

1. Recalculer taille et SHA-256 du candidat avant le premier boot et de sa copie
   `EFI/BOOT/BOOTX64.EFI` dans chaque cas.
2. Recalculer taille et SHA-256 des 19 fixtures depuis le disque et les comparer
   au manifeste [`b1-7-fixtures.md`](../../legacy/ntasm-s0/b1-7-fixtures.md).
3. Utiliser pour chaque cas un nouveau dossier, un ESP neuf et une copie neuve
   du template de variables OVMF.
4. Lancer QEMU x86_64/TCG, sans réseau ni passthrough, avec OVMF code en lecture
   seule et le seul ESP jetable du cas.

## Readiness neutre vis-à-vis du contrat

Le banc ne doit jamais attendre uniquement l'oracle B1.7, puisqu'une vraie
campagne RED doit pouvoir observer le comportement B1.6. Il devient prêt après
exactement une ligne réelle correspondant à l'une des formes suivantes, puis
après une preuve de retour au firmware située après cette ligne :

```text
NG_S0_T[0-9]{2}_OK
NGS0 E[0-9]{3} L[0-9A-F]{4} C[0-9A-F]{4} O[0-9A-F]{8}
```

Le résultat sépare obligatoirement :

- `observed_oracle`, dérivé de la ligne réelle ;
- `contract_match`, comparaison exacte avec l'oracle B1.7 ;
- `harness_pass`, santé du transport et du boot, indépendante de
  `contract_match`.

`harness_pass` exige : fixture et PE copiés sans divergence, une seule ligne
réelle, retour au firmware, pas de timeout, arrêt QEMU propre par HMP, code de
sortie 0, logs QEMU/stdout/stderr vides et absence de `NTASM1.EFI`.

## Verdict RED

La phase RED est valide si et seulement si :

- les 19 cas terminent avec `harness_pass=true` ;
- au moins un `contract_match=false` pour la raison de périmètre attendue ;
- aucune divergence de hash, erreur de banc, seconde ligne, sortie EFI ou log
  parasite ne masque le comportement.

Avec B1.6, la signature attendue est T06 sur chaque fixture : ce tracer s'arrête
au premier statement non-`const`, ou à EOF, sans imposer ni analyser `entry`.
Les 19 oracles B1.7 doivent donc diverger proprement.

Les preuves sont conservées sous
`out/b1/step-7/red-<uuid>/` : `environment.json`, `results.csv`, `summary.json`,
un sous-dossier par cas avec ESP, variables OVMF, commande, logs, transcript HMP
et `result.json`, puis un `manifest.md` de synthèse.

## Frontières héritées obligatoires au GREEN

B1.7 ajoute R12 pour la limite de tokens de `entry` et doit aussi rejouer les
fixtures B1.5 déjà byte-figées :

| Cas hérité | Tokens | Oracle inchangé |
|---|---:|---|
| `B15-17-16-tokens.ntasm` | 16 | `NGS0 E201 L0003 C000D O00000024` |
| `B15-18-17-tokens.ntasm` | 17 | `NGS0 E101 L0003 C0028 O0000003F` |

Le GREEN exige les 19 cas B1.7, un snapshot runtime des descripteurs positifs,
tous les corpus B1.1–B1.6, les frontières physiques, canaris/cleanup, absence
de sortie, reproductibilité et audit PE. La phase RED historique n'autorisait
aucune implémentation; les preuves GREEN sont consignées plus bas.

## Exécution RED vérifiée — 2026-09-03

La campagne `red-40e651a0309e4982a3d60959ea48f982` a exécuté les 19 cas sur
le hash B1.6 canonique. Résultat : banc sain 19/19, observation réelle unique
`NG_S0_T06_OK` 19/19, retour firmware 19/19, oracles B1.7 concordants 0/19,
donc divergences attendues 19/19 et `red_valid=true`.

Chaque cas possède un ESP et un magasin OVMF frais, termine sans timeout par
HMP avec code QEMU 0, conserve QEMU/stdout/stderr vides et ne crée pas
`NTASM1.EFI`. La preuve canonique de cette phase est
`out/b1/step-7/red-40e651a0309e4982a3d60959ea48f982/manifest.md`.

## Exécution GREEN vérifiée — 2026-09-04

Le source final B1.7 fait 51 602 octets, SHA-256
`17c296087c471dda1bbd6bf31a6e03fbac11215802b6bfd2a35990bd28d1c625`.
Le PE testé et promu dans la quarantaine fait 9 728 octets, SHA-256
`169a362b036edce895c1bf4d523f35ce3966d56e0ba6059c0ba3a2a4571f6702`.

- cœur B1.7 final : 19/19, preuve
  `out/b1/step-7/core-final-633c325e0c1745bb8661593eb3727e7f/manifest.md`;
- snapshots : contrôle canonique et C00..C05, 7/7, preuve
  `out/b1/step-7/snapshot-green-c1974e4a83044d3a90221ba294018c0f/manifest.md`;
- B1.6 : 14/14; B1.5 : 22/22; héritage : 56/56;
- reproductibilité : 3/3 bit-identique;
- audit source et PE : approuvé.

Chaque campagne exige oracle unique, retour firmware, HMP exit 0, journaux
vides, ESP et variables OVMF frais et absence de `NTASM1.EFI`. La synthèse
canonique est
`out/b1/step-7/20260904-204749-9790129aa52c4ec2995080290bf5a7d7/manifest.md`.
