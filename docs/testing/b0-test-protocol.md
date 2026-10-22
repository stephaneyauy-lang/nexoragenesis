# Protocole de test — Gate B0 Seed Hello

## But et état

Ce protocole prouve qu'un `seed0.efi` conforme au ledger est chargé par OVMF, appelle la console UEFI, affiche une ligne exactement égale à `NG_SEED0_OK`, puis retourne proprement au firmware.

Le protocole a été défini avant le binaire. Il a ensuite produit un RED valide et deux GREEN indépendants le 2 septembre 2026. Résultat courant : **B0 GREEN**; preuve canonique dans `out/b0/20260902-135815-ddaea37914764ec9828b8f6fa4b87a9d/manifest.md`.

## Banc local vérifié en lecture seule

| Élément | Chemin / valeur vérifiée |
|---|---|
| QEMU | `C:\Program Files\qemu\qemu-system-x86_64.exe` |
| Version | `10.2.0 (v10.2.0-12105-g0f12d445bd)` |
| Accélérateur retenu | `tcg` |
| Firmware x86_64 non Secure Boot | `C:\Program Files\qemu\share\edk2-x86_64-code.fd` — 3 653 632 octets |
| Modèle de variables compatible | `C:\Program Files\qemu\share\edk2-i386-vars.fd` — 540 672 octets |
| Affichage | backend headless avec framebuffer VGA capturable; `gtk` reste disponible pour inspection humaine |
| Capture HMP | `screendump <fichier> -f png` supporté par cette installation |

Le nom `edk2-i386-vars.fd` est celui livré par QEMU pour le magasin de variables x86 commun; le code exécuté reste bien `edk2-x86_64-code.fd`. Le firmware `secure-code` n'est pas utilisé à B0, car le seed n'est pas signé.

## Autorité et marqueur

- Ledger binaire : `bootstrap/seed/seed0-bytes.md`.
- Binaire à tester : `bootstrap/seed/seed0.efi`.
- Emplacement de boot amovible dans le disque FAT de test : `EFI\BOOT\BOOTX64.EFI`.
- Marqueur attendu, sans préfixe ni suffixe sur sa ligne : `NG_SEED0_OK`.
- Octets CHAR16 appelés par le seed : `NG_SEED0_OK\r\n\0`.

L'autorité runtime est la sortie réelle de `ConOut`, observée soit dans une capture, soit dans `serial.log` lorsque les variables OVMF routent cette même console vers la série. Un log série sans marqueur ne suffit pas seul à déclarer le seed rouge. Quand le log contient, dans cet ordre, le démarrage de `Boot0001`, une ligne exacte `NG_SEED0_OK`, puis le chargement de `Boot0000 UiApp`, il prouve à la fois l'appel `OutputString` et le retour au firmware. À B0, il est interdit d'ajouter un accès série direct au seed uniquement pour faciliter le test.

## Préparation immuable du banc

Ces commandes PowerShell hôte transportent les fichiers et collectent des preuves; elles ne produisent pas le PE. Elles créent un répertoire de preuve unique et ne suppriment ni n'écrasent aucun fichier existant.

```powershell
$repo = 'C:\NexoraGenesis'
$qemu = 'C:\Program Files\qemu\qemu-system-x86_64.exe'
$ovmfCode = 'C:\Program Files\qemu\share\edk2-x86_64-code.fd'
$ovmfVarsTemplate = 'C:\Program Files\qemu\share\edk2-i386-vars.fd'
$runId = '{0}-{1}' -f (Get-Date -Format 'yyyyMMdd-HHmmss'), ([guid]::NewGuid().ToString('N'))
$evidenceRoot = Join-Path $repo (Join-Path 'out\b0' $runId)
$redEsp = Join-Path $evidenceRoot 'red\esp'
$green1Esp = Join-Path $evidenceRoot 'green-1\esp'
$green2Esp = Join-Path $evidenceRoot 'green-2\esp'

foreach ($esp in @($redEsp, $green1Esp, $green2Esp)) {
    New-Item -ItemType Directory -Path (Join-Path $esp 'EFI\BOOT') | Out-Null
}

foreach ($caseName in @('red', 'green-1', 'green-2')) {
    Copy-Item -LiteralPath $ovmfVarsTemplate -Destination (Join-Path $evidenceRoot "$caseName\edk2-vars.fd")
}

Copy-Item -LiteralPath (Join-Path $repo 'bootstrap\seed\seed0.efi') -Destination (Join-Path $green1Esp 'EFI\BOOT\BOOTX64.EFI')
Copy-Item -LiteralPath (Join-Path $repo 'bootstrap\seed\seed0.efi') -Destination (Join-Path $green2Esp 'EFI\BOOT\BOOTX64.EFI')

& $qemu --version | Tee-Object -FilePath (Join-Path $evidenceRoot 'qemu-version.txt')
Get-FileHash -Algorithm SHA256 -LiteralPath $ovmfCode, $ovmfVarsTemplate | Format-Table -AutoSize
```

Préconditions obligatoires après préparation :

```powershell
Test-Path -LiteralPath (Join-Path $redEsp 'EFI\BOOT\BOOTX64.EFI')
Get-Item -LiteralPath (Join-Path $repo 'bootstrap\seed\seed0.efi') | Select-Object FullName, Length
Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $repo 'bootstrap\seed\seed0.efi')
Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $green1Esp 'EFI\BOOT\BOOTX64.EFI'), (Join-Path $green2Esp 'EFI\BOOT\BOOTX64.EFI')
```

Résultats exigés :

- le premier `Test-Path` retourne `False`;
- la taille du seed est `1536`;
- les trois copies du seed ont le SHA-256 `69fa9aedbe1d009457c6cd065a78d90d1d997111d49719ce79fe3045603901d0`.

Si une de ces préconditions échoue, ne pas lancer QEMU et conserver B0 rouge.

## Commande QEMU canonique

Avant chaque invocation, fixer `$caseName` à `red`, `green-1` ou `green-2`, puis exécuter tout le bloc. Chaque cas utilise un magasin de variables neuf issu du même modèle.

```powershell
$caseName = 'red'
$caseRoot = Join-Path $evidenceRoot $caseName
$esp = Join-Path $caseRoot 'esp'
$vars = Join-Path $caseRoot 'edk2-vars.fd'
$serialLog = Join-Path $caseRoot 'serial.log'
$qemuLog = Join-Path $caseRoot 'qemu.log'
$screen = Join-Path $caseRoot 'screen.png'

$ovmfCodeQemu = $ovmfCode.Replace('\', '/')
$varsQemu = $vars.Replace('\', '/')
$espQemu = $esp.Replace('\', '/')
$serialLogQemu = $serialLog.Replace('\', '/')
$screenQemu = $screen.Replace('\', '/')

Write-Host "Dans le moniteur QEMU, capturer avec : screendump $screenQemu -f png"
Write-Host 'Puis vérifier avec : info status'
Write-Host 'Enfin arrêter avec : quit'

& $qemu `
    -machine 'q35,accel=tcg' `
    -cpu max `
    -m 256M `
    -drive "if=pflash,format=raw,unit=0,readonly=on,file=$ovmfCodeQemu" `
    -drive "if=pflash,format=raw,unit=1,file=$varsQemu" `
    -drive "if=virtio,format=raw,readonly=on,file=fat:ro:$espQemu" `
    -boot 'order=c,menu=off' `
    -nic none `
    -display none `
    -monitor stdio `
    -serial "file:$serialLogQemu" `
    -d guest_errors `
    -D $qemuLog `
    -no-reboot `
    -no-shutdown
```

Le backtick ci-dessus est seulement la continuation de ligne PowerShell. La commande complète doit être conservée dans le manifeste de preuve. Ne pas activer WHPX, Secure Boot, réseau, passthrough ou périphérique physique pour B0.

## Phase RED

### RED-0 — seed absent

1. Garder `$caseName = 'red'`.
2. Confirmer une seconde fois que `red\esp\EFI\BOOT\BOOTX64.EFI` est absent.
3. Lancer la commande QEMU canonique.
4. Après l'échec de recherche du chargeur amovible ou l'arrivée dans le firmware, saisir dans le moniteur HMP la commande `screendump ... -f png` affichée avant le lancement.
5. Saisir `info status`, enregistrer sa sortie dans les notes de test, puis `quit`.
6. Inspecter `red\screen.png`, `red\serial.log` et `red\qemu.log`.

Résultat RED attendu : OVMF démarre, mais aucun support de preuve ne contient la ligne `NG_SEED0_OK`. Le test ne doit pas être considéré valide si QEMU ou OVMF ne démarre pas : cela prouverait seulement un banc cassé.

La recherche textuelle complémentaire est :

```powershell
Select-String -SimpleMatch 'NG_SEED0_OK' -LiteralPath (Join-Path $evidenceRoot 'red\serial.log'), (Join-Path $evidenceRoot 'red\qemu.log')
```

Elle doit être vide. La capture graphique reste à inspecter séparément.

## Phase GREEN

### GREEN-1

1. Fixer `$caseName = 'green-1'` dans le bloc canonique.
2. Lancer QEMU.
3. Attendre la ligne `NG_SEED0_OK` dans `serial.log` lorsque `ConOut` y est routé; sinon utiliser le backend GTK et capturer la ligne à l'écran.
4. Exécuter `info status`. QEMU doit encore être actif : le retour du seed ne doit provoquer ni arrêt, ni reset, ni triple fault.
5. Exécuter `quit`.

### GREEN-2

Répéter exactement GREEN-1 avec `$caseName = 'green-2'`. Ne pas réutiliser le magasin de variables ni la capture du premier passage.

Après les deux passages :

```powershell
Get-FileHash -Algorithm SHA256 -LiteralPath `
    (Join-Path $evidenceRoot 'green-1\esp\EFI\BOOT\BOOTX64.EFI'), `
    (Join-Path $evidenceRoot 'green-2\esp\EFI\BOOT\BOOTX64.EFI'), `
    (Join-Path $evidenceRoot 'green-1\screen.png'), `
    (Join-Path $evidenceRoot 'green-2\screen.png') | Format-Table -AutoSize

Select-String -SimpleMatch 'NG_SEED0_OK' -LiteralPath `
    (Join-Path $evidenceRoot 'green-1\serial.log'), `
    (Join-Path $evidenceRoot 'green-2\serial.log')
```

La seconde commande peut être vide pour la raison de routage `ConOut` documentée plus haut. Si elle trouve le marqueur, chaque log doit contenir exactement une ligne correspondante et montrer ensuite le retour vers `UiApp`.

## Inspection statique obligatoire

Avant de déclarer GREEN, une revue en lecture seule doit confirmer :

- `MZ` à `0x0000` et `PE\0\0` à `0x0040`;
- machine `0x8664`, PE32+ `0x020b`, sous-système 10;
- point d'entrée RVA `0x1000`;
- taille image `0x3000`, taille en-têtes `0x200`, taille fichier `0x600`;
- exactement deux sections : `.text` RX et `.rdata` R;
- aucune section avec les bits `WRITE` et `EXECUTE` simultanément;
- répertoire import nul, répertoire relocation nul, aucun overlay;
- code utile exactement aux offsets `0x0200..0x021b`;
- chaîne CHAR16 exactement aux offsets `0x0400..0x041b`;
- désassemblage correspondant aux huit instructions du ledger.

Un désassembleur externe peut être utilisé en lecture seule. Il ne doit jamais réécrire, relier, normaliser ou produire le seed.

## Critères d'acceptation B0

B0 devient GREEN uniquement si les preuves suivantes sont toutes présentes :

1. RED-0 valide : OVMF fonctionnel, seed absent, marqueur absent.
2. Le seed fait exactement 1 536 octets et son hash correspond au ledger.
3. L'inspection PE et le désassemblage sont conformes, sans import, overlay ou section W+X.
4. GREEN-1 montre une ligne exactement égale à `NG_SEED0_OK` dans la sortie `ConOut` capturée et le chargement ultérieur de `UiApp`.
5. GREEN-2 montre la même séquence depuis un magasin de variables neuf.
6. Dans les deux passages, `info status` répond après l'affichage et aucun log ne montre reset inattendu, exception fatale ou triple fault.
7. Les deux copies exécutées gardent le hash attendu.
8. Un manifeste associe version QEMU, hashes OVMF, commande, seed, captures, logs, observations et résultat final.
9. `MEM.md` n'est mis à jour vers B0 GREEN qu'après revue de toutes ces preuves.

Une capture isolée, une seule exécution, un hash sans exécution, un affichage sans retour propre ou une sortie série supposée ne suffisent pas.

## Incertitudes à fermer pendant la première exécution

- **Routage console fermé sur ce banc :** OVMF a recopié `ConOut` dans `serial.log`; les deux runs canoniques contiennent exactement une ligne marqueur.
- **PE sans bloc `.reloc` fermé sur ce banc :** le loader EDK2 local a chargé deux fois le profil RIP-relatif exact. Cette preuve ne vaut pas compatibilité universelle; B1 garde une `.reloc` canonique.
- **Persistance visuelle :** l'application retourne immédiatement. Capturer dès l'apparition de la ligne; ne pas transformer le seed en boucle ou en attente pour rendre la capture plus facile.
