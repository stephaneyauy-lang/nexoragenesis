# Liaison synchrone de composants NTASM — preuve initiale

Cette ABI de preuve n'est pas le système de modules typés NTASM v0. Elle
permet de préparer la séparation du cœur compilateur et de l'hôte UEFI,
sans dépasser les limites d'un source S0 ni ajouter de producteur étranger.

## Cycle de vie

L'hôte lit le PE du module, appelle LoadImage, contrôle son profil PE S0 et
sa table d'exports, puis passe un bloc de LoadOptions et appelle StartImage.
L'entrée du module appelle le callback de l'hôte avec la table d'exports.
L'hôte utilise les fonctions pendant ce callback, puis retourne au module.
Le module quitte; l'hôte ne conserve aucun export utilisable après StartImage.

UEFI fournit le chargement mémoire et les LoadOptions; une application est
déchargée à sa sortie. Sources : [Boot Services](https://uefi.org/specs/UEFI/2.10_A/07_Services_Boot_Services.html),
[Loaded Image](https://uefi.org/specs/UEFI/2.10/09_Protocols_EFI_Loaded_Image.html),
[cycle de vie des applications](https://uefi.org/specs/UEFI/2.10_A/02_Overview.html).
Les pages directes ont répondu 403 pendant ce travail; les extraits officiels
indexés et l'exécution QEMU ont servi à vérifier cette piste.

## Tables de la preuve arithmétique initiale (entiers little-endian)

La table d'exports est au début de .rdata. En-tête de 32 octets :

| Offset | Champ |
|---|---|
| 0 | Magic ASCII NTLB0001 |
| 8 | Version u64 = 1 |
| 16 | Taille u64 = 48 pour cette preuve |
| 24 | Nombre d'exports u64 = 1 |
| 32 | ID u32 = 1, signature u32 = 1 |
| 40 | Adresse relocalisée u64 de module_sum |

Le bloc LoadOptions fait 48 octets : magic NTLC0001, version 1,
adresse du callback, contexte hôte, cookie 0x6E747363616C6C31 et zéro réservé.
Ce cookie constant est une vérification de cohérence, PAS un secret ou un MAC.
Le callback reçoit RCX=exports, RDX=contexte, R8=cookie, R9=handle du module.

Le module de preuve normalise son retour en EFI_SUCCESS ou EFI_ABORTED.
L'hôte traite ces deux retours comme une sortie d'application; il annule les
pointeurs de module. Avant StartImage, les chemins d'échec appellent UnloadImage
si LoadImage a fourni un handle. Fichier, racine et buffer sont ensuite libérés.

## Preuve arithmétique et limites

module-host.ntasm charge probe-library.ntasm compilé; module_sum lit le biais
3 dans .data et renvoie a+b+3. L'hôte exige 45 pour (7,35), puis 29 pour (17,9),
un seul callback et une adresse relocalisée dans la section .text du module.
Cette preuve exige volontairement une base différente de 0x140000000.

Les modules sont des binaires natifs DE CONFIANCE produits pour ces tests.
Ce n'est ni une sandbox ni un chargeur général de PE arbitraires. Les fautes
de nettoyage et toutes les erreurs firmware ne sont pas encore injectées;
un échec de nettoyage peut être masqué par le diagnostic initial conservé.
Durcir et tester ce point avant d'en faire l'hôte final.

Dans le banc arithmétique initial, le harnais place le PE sous NTASM1.NTASM :
c'est une convention de test, pas un format source. Ce banc ne lit pas de source
utilisateur. L'état modulaire courant est décrit ci-dessous.

## Cœur compilateur et hôte externe

Le cœur est maintenant dans `legacy/ntasm-s0/modules/compiler-core.ntasm`.
L'en-tête conserve le magic et la version 1, avec taille=80 et nombre=3.
Les trois records de 16 octets sont ordonnés et validés par l'hôte :

| ID | Signature | Fonction et contrat |
|---|---|---|
| 100 | 2 | native_front_line : RCX=WORK, RDX=ligne, R8=longueur, R9=paire offset/ligne; RAX=tag, R10=code, R11=index |
| 101 | 3 | nb_resolve : RCX=WORK, RDX=source, R8=taille; RAX=code; positions R8/R9/R11 sur erreur |
| 102 | 3 | nr_resolve : mêmes arguments/retours, pour les références addr |

nb_resolve calcule le layout et doit précéder nr_resolve, après les lignes.
Cette ABI est interne au bootstrap, pas la grammaire des modules typés v0.

`module-host.ntasm` reste le banc de 14 cas avec programme intégré et gardes.
L'hôte actif `compiler-host.ntasm` charge NTCORE.EFI, puis lit NTASM1.NTASM
durant le callback. Il diffère le rapport après StartImage et le nettoyage,
sans appeler Exit(parent) depuis l'enfant. Il produit encore un résultat
d'analyse, pas un PE. 237 cas sémantiques et trois erreurs de chargement/garde
passent; voir `out/ntasm/native-modular-source-checkpoint.md`.
