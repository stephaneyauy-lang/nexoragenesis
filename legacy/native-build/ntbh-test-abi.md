# NTBH-T01 — frontière native privée TEST

Cette interface est **implémentée et testée**, séparément de NTBUILD2/S0.
Source : `ntbh-test-adapter.ntasm`. Fixture :
`out/ntasm/agent-release-v0-adapter/fixtures/test-producer.ntasm`.
Elle ne constitue ni un compilateur v0, ni une activation de NTBH0001 public.

La fixture produit seulement les 8 octets ASCII `NTBHTEST`. Elle ne parse pas
un langage et ne construit aucun PE/NXO. Les modes adverses sont des données
de test, pas du code source assemblé par cette fixture.

## Entrée exécutable et propriété

L'ESP privé contient BOOTX64.EFI=adaptateur, `NTBH.PROD`=fixture EFI épinglée,
`NTBH.REQ`=ASCII1 puis LF, `NTBH.CORE`=ASCII `TESTCORE` puis LF et
`NTASM1.NTASM`=données de cas TEST (1..64 octets). Le nom d'entrée réutilise le
transport S0; le profil TEST ne prétend pas interpréter ces octets en NTASM.
La sortie est `NTBH.TEST`, jamais `NTASM1.EFI`.

L'adaptateur vérifie le SHA-256 embarqué de la fixture avant LoadImage et
transmet le buffer réellement vérifié. Il renseigne LoadOptions128, puis
appelle StartImage. La fixture ne rouvre aucun fichier : source/cœur sont
préchargés et restent vivants pendant tout l'appel. L'image EFI, les handles
et le buffer brut sont détenus par le lanceur; la fixture ne les libère pas.
Les buffers partagés appartiennent à l'image de l'adaptateur, pas au descripteur
mutable fourni au callee. Aucun Free ne suit un pointeur modifié par le callee.

## Descripteur, 128 octets, alignement16

| Offset | Champ privé T01 |
|---:|---|
| 0 | ASCII `NTBH-T01`, u64 `0x3130542D4842544E` |
| 8 | Taille exacte128 |
| 16 | Version1 |
| 24 | Profil TEST, `0x54534554` |
| 32 | Capacités exactes12 : source et cœur préchargés; aucune capacité PE/NXO |
| 40 | Format TEST, `0x54534554` |
| 48/56 | Source empruntée immuable / longueur1..64 |
| 64/72 | Cœur de test emprunté immuable / longueur9 |
| 80/88 | Callback / contexte opaque appartenant au lanceur |
| 96/104 | Sortie empruntée writable / capacité64 |
| 112/120 | Réservés zéro |

La fixture valide l'en-tête, la version, les réservés et les capacités avant
ENTRY. Des probes UEFI transmettent réellement des descripteurs invalides et
exigent EFI_UNSUPPORTED sans aucun callback. NTBH-T01 ne devient pas une ABI
publique simplement parce que ces tests passent.

## Callback et fin du job

`report(RCX=context, RDX=event, R8=status, R9=output_len)`, ABI efi_x64.
Shadow32, pile alignée et registres non-volatils préservés.

```text
INITIAL -- ENTRY(1, SUCCESS, 0) --> ENTERED
ENTERED -- COMPLETE(2, status, length) --> COMPLETED
StartImage retourne --> CLOSED --> validation --> publication TEST
```

ENTRY est obligatoire une seule fois. COMPLETE est obligatoire une seule fois
après ENTRY. Seul status0 est un succès : il exige une longueur dans1..64;
tout autre statut exige longueur0. Contexte faux, événement inconnu, répétition
ou mauvais ordre rendent l'erreur persistante. Un succès tardif ne remplace
jamais une erreur. Aucun pointeur de contexte fourni n'est déréférencé avant
comparaison au contexte attendu.

Après StartImage, le callback est fermé et les statuts de retour/COMPLETE
doivent concorder. La fermeture est exercée par un probe appelant ENTRY après
retour, pendant que l'adaptateur est encore vivant; elle ne promet pas qu'un
pointeur puisse être appelé après déchargement de son propriétaire.

L'adaptateur compare le descripteur128, les deux régions d'entrée et leurs
gardes aux snapshots qu'il possède. Les gardes de sortie sont aussi contrôlées.
Les mutations de source/cœur/version/pointeur et les écritures avant/après la
sortie sont refusées avant publication. Seul le format TEST de longueur8 et
contenu exact NTBHTEST est publiable dans cette version.

## Résultats et erreurs

| Code | Refus |
|---|---|
| E920 | Requête/version, fichier d'entrée ou cœur TEST invalide |
| E921 | ENTRY ou COMPLETE absent |
| E922 | Callback invalide, dupliqué, hors ordre ou fermé |
| E923 | Retour StartImage différent du statut COMPLETE |
| E924 | Échec honnêtement signalé par la fixture |
| E925 | Entrée/descripteur/garde altéré ou format TEST incorrect |
| E926 | Chargement, ownership, I/O ou cleanup en échec |
| E927 | Fichier de sortie déjà présent, conservé |
| E928 | Fixture absente, taille ou SHA non épinglé |

Marqueurs `NG_NTASM_MODULE_Eddd`; MODULE_OK signifie seulement succès de cette
preuve privée. Les probes utilisent MODULE_OK pour leurs assertions, même
lorsqu'ils prouvent un refus; leurs noms et le manifeste distinguent ces cas.
Une erreur d'écriture peut laisser un fichier partiel invalide; aucune preuve
ne réutilise un tel résultat comme producteur.

## Garanties et frontière A8

Prouvé : invocation native d'une image épinglée, protocole d'entrée/fin,
ownership borné, versions/capacités refusées, intégrité aux frontières, sortie
contrôlée, absence de publication sur les cas adverses et reproductibilité
des deux EFI TEST par NTASM-S0. Aucun script hôte ne produit de code.

Les comparaisons détectent les mutations présentes au contrôle; elles ne sont
pas une protection mémoire contre un code natif hostile qui pourrait restaurer
les octets ou écrire hors des régions contrôlées. La fixture est connue/épinglée.
L'exécution est synchrone et les pointeurs ne peuvent être conservés après appel.

Restent pour A8 final : vrai producteur v0 relié syntaxe/sémantique/contrats/IR/
backend, sortie PE/NXO réelle, ABI publique négociée, pins et point fixe du
producteur final et gates A1–A10. La proposition NTBH0001 dans
`producer-handoff.md` n'est pas modifiée ni activée par ces tests privés.
