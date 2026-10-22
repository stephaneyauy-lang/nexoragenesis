# Preuve de clôture A2 — NTASM v0 x86-64

Date : 4 octobre 2026. Périmètre : critère A2 de `ntasm-completion.md`. Cette clôture ne vaut pas livraison de B2.1.

## Code intégré

- Catalogue explicite : `../spec/x64-scope.md`, `../spec/x64-forms.csv` — 126 orthographes, alias inclus, regroupées en 44 familles; adressages et relocations séparés.
- `../toolchain/ntasm-nova/x64_fixed.nova` : familles manquantes intégrées; interface binaire commune; opérations mémoire et immédiats; high8/REX; IMUL; tests de bits; CR et ports; descripteurs système.
- `../toolchain/ntasm-nova/x64_lower_fixed.nova` : raccordement depuis l'AST; opérandes signés; contrôle des largeurs; adresses 64 bits, index seul et déplacement seul; descripteur `array<u8,10>`.
- Les anciens cas déclarés non pris en charge sont conservés et exigent désormais les octets de la référence. Les cas interdits gardent leurs contrôles de refus et de sortie intacte.
- Deux nouvelles portes enregistrées dans `legacy/tools/coldproof/ngbuild.sh` : `x64_binary`, `x64_a2_parity`. Le classificateur dérive leurs cellules C3 depuis leurs comparaisons; aucune cellule de classification n'a été saisie à la main.

## Résultats effectivement exécutés

Les harnais ont été reconstruits avec GCC, ASan et UBSan. Les harnais emploient aussi `-Wall -Wextra -Werror`. Les bibliothèques C ont été recompilées lorsque `frontend.c` a changé dans le principal pendant le travail.

**51 suites ciblées sans échec** dans la campagne isolée. Le manifeste complet, les résumés et les empreintes sont dans `../out/a2-finish-20261004/out/final-validation.json`; les journaux individuels dans `../out/a2-finish-20261004/out/a2-build/`.

| Preuve | Résultat |
|---|---|
| Octets attendus et contrôles du C de référence | `X64_TESTS cases=477 failures=0` |
| Parité encodeur binaire | 69 545 contrôles, 23 181 cas, zéro échec |
| Raccordement source des paires de registres, IMUL compris | 65 716 contrôles, 21 902 cas, zéro échec |
| Décalages et high8 | `x64_shift_mem` : 6 937 contrôles, 2 309 cas, zéro échec |
| Inventaire des formes raccordées | 189 rangs : 181 acceptations, 8 refus attendus, zéro trou déclaré; résultat publié pour chaque rang |
| Adressage index seul | Comparaison obligatoire aux octets C; ne peut pas se substituer silencieusement à base+déplacement |
| Corpus complémentaire Space Bunny, relu et renforcé | 531 contrôles, 176 cas, zéro échec |
| Formes structurelles | `FORM_MATRIX checks=154 failures=0 cases=154`; ce nombre n'est pas une mesure de complétude du langage |
| Objets et liaison | Suites C `object`, `object_build`, `object_link`, `object_errors`, `object_separate` sans échec |
| Symboles et relocations Nova | `nxo_symbol` 72/0; `nxo_reloc` 75/0 |
| Source vers PE | `x64_lower_nxo_pe` : 2 631 contrôles, 204 cas, zéro échec |
| Corpus de bout en bout | `corpus_e2e` : 150 contrôles, 25 cas, zéro échec |

Après intégration, cinq suites ont été recompilées et rejouées depuis le principal : `x64_a2_parity`, `x64_binary`, `x64_lower_lea`, `x64_lower_nxo_pe`, `corpus_e2e`. Chacune a un code de sortie 0 enregistré sous `../out/c-bootstrap/builds/a2-close-20261004/`.

Le contrôle d'enregistrement `python3 legacy/tools/coldproof/lot145_derivable_cells.py --pending` termine avec code 0 et dérive `x64_binary` et `x64_a2_parity` en C3. Les commentaires dans la liste Bash GATES qui étaient pris pour des noms de tests ont été déplacés hors de cette liste, sans suppression de leur contenu.

## Reproduction

Depuis la racine sous Linux/WSL, le pilote reconstruit ses bibliothèques et les harnais :

```sh
NG_BUILD="$PWD/out/c-bootstrap/builds/a2-replay" bash legacy/tools/coldproof/ngbuild.sh \
  x64_fixed x64_binary x64_a2_parity x64_rr x64_ri x64_high8 x64_memory \
  x64_lea x64_shift_cl x64_shift_mem x64_two_reg x64_lower_two_reg \
  x64_lower_lea x64_lower_shift_cl x64_lower_address x64_lower_sib \
  x64_lower_nxo_pe nxo_symbol nxo_reloc corpus_e2e
```

Le pilote exécute aussi des contrôles transversaux de B2.1. Un échec de ces contrôles doit être nommé séparément; il ne faut ni le cacher ni le confondre avec le résultat d'une porte d'encodage.

## Limites et conservation

- A3, A4, A7, A8 et les autres critères conservent leurs propres exigences. L'auto-hébergement n'est pas obtenu par cette clôture.
- Les instructions privilégiées sont vérifiées par leurs encodages et leurs refus; aucun accès au matériel réel n'a été exécuté.
- Les formes matérielles encodables et les adresses autorisées par les contrats du langage sont deux niveaux distincts.
- La preuve est attachée aux empreintes enregistrées. Un changement ultérieur exige les contrôles correspondant à son impact.
- Les changements contemporains du principal ont été conservés. Sauvegardes préintégration : `../out/a2-finish-20261004/out/main-before-integration/`.
- Aucun push ni réinitialisation de quota. Space Bunny a travaillé via OMP; les essais OpenCode bloqués par authentification ne constituent pas une contribution.
