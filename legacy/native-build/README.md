# NTBUILD2 — lanceur natif contrôlé S0

Source `ntbuild.ntasm`, exclusivement assemblé par NTASM. Le package testé se
trouve dans `out/ntasm/agent-release-integration/package/`. Il utilise la paire
S0 stable `token-limit-stage3`, pas les fichiers de travail modifiables.

```text
EFI/BOOT/BOOTX64.EFI   NTBUILD2
NTASM.EFI             hôte S0, 17408 octets, SHA82826f45…b4882d
NTCORE.EFI            cœur S0, 20992 octets, SHAa02425be…1d428f
NTASM1.NTASM          source S0 choisie
NTBUILD.JOB           recette exacte ci-dessous
```

Recette ASCII de 153 octets, six lignes LF, sans CR/BOM ni suffixe :

```text
NTBUILD2
profile=ntasm-s0
source=NTASM1.NTASM
producer=NTASM.EFI
core=NTCORE.EFI
sha256=<64 chiffres hexadécimaux minuscules du source>
```

Remplacer le placeholder par le véritable hash. Un calculateur de SHA-256
peut inspecter les sources : il n'est pas producteur. Préparer un ESP neuf,
matérialiser un raw et exécuter seulement sous QEMU/OVMF. La sortie
`NTASM1.EFI` est écrite par l'hôte natif et doit être absente au départ.
La recette NTBUILD1 historique reste réservée aux anciens packages; elle est
refusée ici. Migrer demande NTBUILD2, sa ligne de profil et les nouveaux pins.

| Diagnostic | Refus |
|---|---|
| E910 | Accès initial ou recette : syntaxe, chemins, taille, doublon, suffixe |
| E911 | Profil non disponible, notamment ntasm-v0 |
| E912 | Source absente, vide, trop grande, lecture ou digest incorrect |
| E913 | Cœur absent ou taille/digest non approuvé |
| E914 | Hôte absent ou taille/digest non approuvé |
| E915 | Chargement/lancement ou contexte image incorrect |
| E916 | Cleanup en erreur après succès du producteur |
| E917 | Énumération des images impossible ou hors borne |

La forme complète est `NG_NTASM_MODULE_Eddd`. Après lancement, les diagnostics
du producteur restent prioritaires. E700 signifie sortie préexistante conservée.
E916 peut suivre un marqueur writer de succès : ne jamais promouvoir cette
sortie. Exiger tout le journal, retour firmware, fichier extrait, comparaison
et exécution; `NG_NTASM_NATIVE_SCAN_OK` seul ne suffit pas.

SHA-256 est implémenté dans ce source. Les pins hôte/cœur sont embarqués, pas
fournis par la recette. LoadImage reçoit le buffer hôte effectivement vérifié.
Après StartImage, NTBUILD énumère jusqu'à 256 handles LoadedImage sans
déréférencer un handle détruit; seul un handle encore vivant est déchargé.
SECURITY_VIOLATION avec image allouée est nettoyé sans démarrage. Les appels
Close/Free/Unload ne sont pas répétés après une erreur de résultat ambigu.

Le lanceur conserve le premier EFI_STATUS de cleanup dans son état interne.
Une erreur primaire garde la priorité; une erreur de cleanup après succès
transforme l'issue en E916. Une énumération impossible rend l'ownership
incertain : E917, aucun Unload aveugle, reprise dans une VM neuve.

Confiance : lanceur et pins authentifiés hors bande. Le digest source vérifie
l'intégrité de l'entrée choisie, pas son auteur. L'hôte relit cœur/source :
volume VM figé et de confiance requis. Aucun contrôle global de Windows,
aucune sandbox hostile, aucun Secure Boot prétendu. L'énumération protège
l'ownership; seul un futur handshake peut attester précisément l'entrée.

`producer-handoff.md` propose NTBH0001, non implémenté dans l'hôte partagé.
Les drivers parser/encodeur v0 sont réellement refusés comme producteurs.
Le compilateur v0 final et ses gates A1–A10 restent nécessaires pour B2.1.
Guide et preuves : `legacy/docs/bootstrap/native-build.md` et checkpoint du package.
