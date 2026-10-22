# Construction native NTASM — intégration S0 contrôlée

NTBUILD2 est un programme NTASM exécutable qui vérifie le profil, la recette,
les sources et les producteurs avant d'appeler l'hôte natif. La génération
intégrée utilise les snapshots `token-limit-stage2/stage3`, vérifiés sur les
fichiers des ESP, sans lecture des sources hôte/cœur de travail.

Source : `legacy/native-build/ntbuild.ntasm`. Package et preuves :
`out/ntasm/agent-release-integration/`. Les packages précédents restent
immuables. Aucun défaut partagé du projet ou fichier de quarantaine modifié.
Cette intégration S0 ne livre pas le compilateur v0 ni B2.1.

## Parcours utilisable

`package/` est un ESP prêt pour QEMU/OVMF :

```text
EFI/BOOT/BOOTX64.EFI   lanceur NTBUILD2, génération finale 2
NTASM.EFI             hôte S0 approuvé
NTCORE.EFI            cœur S0 approuvé
NTASM1.NTASM          exemple hello à assembler
NTBUILD.JOB           recette et digest de la source
```

La recette est ASCII, exactement 153 octets, six lignes LF, sans BOM/CR,
doublon ou suffixe. La dernière LF est obligatoire :

```text
NTBUILD2
profile=ntasm-s0
source=NTASM1.NTASM
producer=NTASM.EFI
core=NTCORE.EFI
sha256=<64 chiffres hexadécimaux minuscules du source>
```

Remplacer le placeholder par le hash réel. Un calculateur de hash peut
inspecter le fichier; aucun compilateur extérieur n'est requis. Matérialiser
une copie de l'ESP en raw et démarrer QEMU/OVMF. La sortie `NTASM1.EFI` est
écrite par le producteur natif sur le même volume; elle doit être absente.
Pour un autre programme, créer un nouvel ESP et changer source/digest.
Les trois sources de la chaîne permettent trois jobs distincts, puis la
génération suivante utilise les trois PE reconstruits.

NTBUILD1 appartient aux packages historiques. Le nouveau lanceur la refuse;
la migration exige NTBUILD2 et sa ligne de profil. `profile=ntasm-v0` est
explicitement refusé E911. Il n'existe pas encore de CLI générale ni de
compilateur final v0 derrière cette interface.

## Identités de la génération finale

| Composant | Taille PE | SHA-256 |
|---|---:|---|
| NTBUILD2 | 10240 | `ee3b0f2568c9d01cc88f5c86e78b44786ec1f40cad408eac486aef91c2226b0b` |
| Hôte | 17408 | `82826f458aff21d4f5167b296b56813899ea422caedb9d8fda2d8120a9b4882d` |
| Cœur | 20992 | `a02425be642b839586593b6b5468bc13f4f85d29a503987aa972e4750d1d428f` |

Source du lanceur : 13503 octets, SHA-256
`95900d4982c62735d5965651672ef8881bbd80ba7c94cef92d5590f32f58e891`.
Les pins producteurs sont compilés dans NTBUILD. La recette ne peut pas les
changer; même un autre PE natif de taille identique est refusé.

## Validation, erreurs et reprise

SHA-256 maison contrôle source, cœur et hôte. LoadImage reçoit les octets
hôte effectivement hachés, sans relecture. Le DeviceHandle du fils est lié
au même volume. NTBUILD énumère ensuite les handles LoadedImage vivants,
sans déréférencer celui qui peut avoir été détruit. Il préserve tout statut
réel du producteur, notamment les erreurs d'I/O; il ne suppose plus seulement
SUCCESS/ABORTED. Une image encore résidente est déchargée une seule fois.

Une application UEFI est retirée lorsqu'elle se termine; LoadImage peut aussi
créer une image tout en rendant SECURITY_VIOLATION. Le lanceur traite ce
dernier cas sans démarrage et libère l'image. Références :
[cycle de vie UEFI](https://uefi.org/specs/UEFI/2.10/04_EFI_System_Table.html),
[services image UEFI](https://uefi.org/sites/default/files/resources/UEFI_Spec_2_10_Aug29.pdf).

| Code | Cause |
|---|---|
| E910 | Accès initial ou recette invalide |
| E911 | Profil non disponible |
| E912 | Source ou son digest |
| E913/E914 | Cœur/hôte non approuvé |
| E915 | Chargement/lancement/contexte image |
| E916 | Cleanup en erreur après succès |
| E917 | Énumération impossible ou supérieure à 256 handles |

Les marqueurs sont `NG_NTASM_MODULE_Eddd`; l'hôte conserve ses `NGS0 E…`.
La première erreur reste prioritaire. Close/Free/Unload ne sont jamais répétés
aveuglément. E700 doit conserver la sortie existante. E916 peut suivre un
marqueur writer de succès : le PE ne doit alors pas être promu. E917 interdit
un Unload sur un handle dont la validité n'est pas connue; reprendre en VM neuve.

Ne jamais déduire le succès de `NG_NTASM_NATIVE_SCAN_OK` seul. Exiger le journal
complet, retour firmware, arrêt HMP confirmé/code0, fichier extrait du raw,
comparaison attendue puis exécution. Une erreur d'I/O peut laisser un fichier
partiel invalide : le conserver et repartir d'un ESP neuf, sans écrasement.
Chaque rejeu utilise un nom de campagne neuf; les traces rouges restent gardées.

## Preuves et portée de la revue

Il s'agit d'une **auto-revue**, pas d'une revue indépendante de l'agent principal.
`audit/self-review.md` décrit les défauts trouvés, corrections et limites.

- RED/GREEN réels pour cleanup, lancement, résidence/retour d'erreur, profil,
  pins de la nouvelle paire et SECURITY_VIOLATION/handle nul.
- Treize injections firmware natives : échecs, ownership, première erreur,
  faux succès de lancement et énumération. Aucun hook dans le produit livré.
- Sources 0/65535/65536 et dossier; SHA aux frontières 55/56/63/64/65 octets.
  Le source de 65535 octets produit réellement le golden hello.
- Deux générations corrigées recovery, puis repin explicite et deux générations
  finales token-limit des trois composants. Six PE finaux byte-identiques,
  hello produit/exécuté et E700 conservant le fichier.
- Recettes étrangères, chemins alternatifs, suffixes/doublons, downgrade et
  imposteurs natifs refusés. Les drivers v0 parser et encodeur ne sont pas
  admis comme producteurs; l'encodeur de 17408 octets teste aussi le hash.

Les noms de campagnes `release-*` désignent cette preuve S0, pas une release
NTASM v0. Les chemins exacts, tailles et hashes sont dans les CSV et le manifeste.

## Transport et dépendance finale v0

QEMU/OVMF exécutent; qemu-img prépare le raw; mcopy extrait; PowerShell copie,
orchestre et inspecte. Aucun ne traduit nos sources ou patche les PE.
VVFAT sert seulement à préparer le raw avant boot. Le runner privé effectue
compact /U puis /C avant QEMU avec SHA identique; l'attribut Compressed seul
ne garantit pas une faible occupation physique après une écriture WSL.
Aucun runner sous out/ n'est un composant du produit de release.

Racine de confiance : le lanceur retenu et ses pins vérifiés hors bande.
Le digest source n'authentifie pas son auteur. Le cœur/source sont relus par
l'hôte : volume VM figé et de confiance requis. Aucun Secure Boot, contrôle
global de Windows ou sandbox hostile n'est prétendu. L'énumération protège
l'ownership, mais ne prouve pas absolument l'entrée de l'image.

`legacy/native-build/producer-handoff.md` propose NTBH0001 : buffers gelés,
LoadOptions128 et callback ENTRY/COMPLETE. Cette interface n'est pas appliquée
à l'hôte partagé. Le parser/encodeur v0 n'offre toujours pas de producteur
fichier→PE/NXO complet; leur intégration finale exige ce producteur, une ABI
publique versionnée, les preuves de sortie et les gates A1–A10. A8/B2.1 n'est
donc pas déclaré terminé par cette seule intégration native S0.

## Frontière privée NTBH-T01 testée

`legacy/native-build/ntbh-test-adapter.ntasm` implémente désormais une
invocation LoadOptions/StartImage distincte, avec une fixture explicitement
TEST épinglée. ENTRY/COMPLETE, versions/capacités, fermeture du callback,
ownership, snapshots et gardes sont vérifiés avant publication de NTBH.TEST.
La seule sortie est le texte de 8 octets NTBHTEST, jamais un programme v0.
Le contrat est `legacy/native-build/ntbh-test-abi.md`; les preuves et
le paquet privé sont dans `out/ntasm/agent-release-v0-adapter/`.

Cette implémentation privée prépare un raccord réel, mais ne remplace pas
NTBH0001 public proposé. Les packages S0 restent figés et cette fixture ne
devient ni le producteur normal, ni un fallback pour le parser/encodeur.
