# Guide utilisateur `ntasm` (Bootstrap C temporaire ADR0012)

Guide provisoire du bootstrap. A9 reste partiel; livraison finale apres A8.

Ce guide décrit l'usage du binaire temporaire C `ntasm`. B2.1 reste non livré : A8 doit encore prouver l’auto-hébergement du producteur final.

## 1. Construction du bootstrap
Depuis la racine du dépôt :
```bash
bash scripts/ntbuild.sh build
```
- **Binaire produit** : `out/c-bootstrap/ntasm/ntasm`
- **Construction vérifiée du 14 octobre 2026, candidat A1/A10/A9** : 17 unités C, 19 headers, 399056 octets.
- **SHA256** : `0e5ef71c276a13a2ded09560b1df5e1a6df63d1a4216065066c4b7688f33df02`
- **Reproductibilité R1/R2** : 2 binaires GCC O2/O0 distincts, 8/8 PE conformes aux pins, et la 3e passe reproduit fidèlement le binaire initial (ne constitue pas un auto-hébergement).

## 2. Règles d'usage de la CLI
- **6 verbes** : `assemble`, `check`, `inspect`, `object`, `link`, `run`.
- **Backend** : C sélectionné par défaut. L'option `--backend mir` est réservée à `assemble`, `check`, `object` et `link`, sans aucun repli (fallback). Les MIR sont émis par Nova au-dessus du bootstrap C.
- **Chemin racine** : L'option `--root <chemin>` choisit exactement le dépôt. Sans elle, l'outil cherche depuis son exécutable puis le répertoire courant ; la préciser rend l'appel hors dépôt non ambigu.
- **Cibles de sortie** : Tout fichier spécifié via `-o` doit impérativement pointer vers un fichier inexistant (rejet avec code `E700` si la cible existe). Placer toutes les sorties dans `out/`. Aucun commit/push ni installation externe.
- **Exécution** : Le verbe `run` s'exécute exclusivement via le backend C (`--backend mir` sur `run` est strictement rejeté). Le chargement hôte via `run` et les validations UEFI sous QEMU constituent des preuves distinctes.

## 3. Commandes d'exemple

### Chaîne MIR : Source -> NXO -> PE et inspection
```bash
# Production de l'objet NXO
out/c-bootstrap/ntasm/ntasm object examples/ntasm-v0/c-bootstrap/return42.ntasm -o out/return42.nxo --backend mir

# Édition de liens vers PE
out/c-bootstrap/ntasm/ntasm link out/return42.nxo -o out/return42.efi --backend mir

# Inspection de l'artefact
out/c-bootstrap/ntasm/ntasm inspect out/return42.efi
```

### Exécution directe sous backend C
```bash
out/c-bootstrap/ntasm/ntasm run examples/ntasm-v0/c-bootstrap/return42.ntasm --expect 42
```

## 4. Gardes et environnement
- **Environnement d'exécution** : WSL (2 CPU, 6 Go RAM, 2 Go swap). Les tests doivent impérativement être sérialisés.
- **Garde mémoire système** : Démarrage conditionné à un minimum de 9 GiB de RAM libre ; arrêt immédiat des tâches si la mémoire disponible descend sous 8 GiB.

## Preuves et limites

Les mesures ci-dessus sont rattachées à `out/a1-a10-a9-20261014/build-candidate.log` et au reçu d’intégration du lot. Une autre construction peut avoir une autre empreinte : consulter son `build.log`, ne pas recopier cette valeur comme une preuve nouvelle. Le guide détaillé reste `ntasm-cli.md` ; la politique du build reste `ntasm-build.md`.
