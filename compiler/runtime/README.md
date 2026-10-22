# Runtime Nova ABI2 natif — candidat

Runtime et lanceur écrits en NTASM-S0, dépendants du producteur **S0 natif** et
des services **UEFI x64**. Ces composants ne prouvent pas le point fixe du
compilateur Nova ni la livraison d'A8.

## Interface

Contexte ABI2 de 48 octets : version/+0, taille/+8, erreur/+16, source/+24,
offset/+32, table runtime*/+40. Table de 128 octets : version 2/+0, taille/+8,
12 callbacks/+16..104, état*/+112, extension copy/+120.
Les 13 callbacks sont alloc, free, open_read, open_new, read, write, close, diag,
resolve, slice, length, literal et copy. Convention Microsoft x64 :
callback(ctx,a,b,c). Buffers et records utilisent des handles avec génération ;
les tailles du runtime sont en octets. La première erreur reste prioritaire.

L'entrée privée du runtime reçoit BootServices*, racine EFI_FILE* et Serial* ;
elle retourne le descripteur NVRH0001 donnant contexte, destroy, borrow et clear.
Une seule instance active par image. Le host charge NVRUNTIME.EFI et
NOVACORE.EFI par LoadImage puis appelle directement leurs entrées.
Le host normal invoque Nova avec **(ctx,NULL,0), zéro argument aplati**.
Il capture retour/erreur avant destroy, puis décharge les images et ferme la
racine. Aucun StartImage n'est appliqué à une entrée Nova ABI2.

## Bornes portées

65 536 handles de buffers, 128 fichiers, 64 Mio par buffer, 256 Mio de buffers possédés,
générations de 32 bits, chemins ASCII de 1 à 4096 octets sans NUL.
Tables allouées par pools ; allocation zéro initialisée, slices liées au parent,
readonly et copies recouvrantes contrôlés, création de fichiers exclusive.
Le host borne l'image runtime à 1 Mio et l'image Nova à 64 Mio.
La construction S0 conserve ses plafonds : source de 65 535 octets et PE de 65 536 octets.

## Preuves conservées

Chemins relatifs à la racine NexoraGenesis, sous
out/a8-selfhost-20261015/runtime-native/ :

- callbacks-03 : 77 assertions natives, fichier exact et cleanup réussi.
- callbacks-exclusive-red-02 : statut 2 / assertion 45 / erreur 8 capturée avant destroy ;
  fichier UNCHANGED, retour firmware associé au Boot/nom démarrés.
- seed-01 : seed C quarantainé, 76 contrôles, 3 compilations et 3 oracles réussis.
  Ces PE portent explicitement **C_SEED_ORACLE**, preuve d'interchangeabilité.
- nova-roundtrip-01 : retour 0 / erreur 0, record/alloc/index/slice/copy, lecture-écriture
  de NOVA.BIN exactement 0123456789abcdef et diagnostic exact.
- nova-readonly-01 et nova-stale-01 : retour 0 / erreurs 9 et 7, identiques aux oracles C.
- asm-runtime-01/02 et asm-host-test-03/04 : deux assemblages séparés de la même
  paire S0, sorties identiques (runtime 8704 octets ; host-test 11776 octets).
  La variante host-test change uniquement la directive entry du source normal.

Les exécutions exigent retour firmware après marqueur, arrêt HMP, QEMU rc 0,
absence d'arrêt forcé et vérification des octets. Les 33 tests purs du runner
vérifient sa reconnaissance des retours et causes ; ils ne prouvent pas A8.
Recettes détaillées : runtime-native/README.md et NOVA-SEED-ORACLE.md.

## Limites de la preuve

La table pleine à 65 536 et la génération forcée à sa borne sont testées ; le plafond
de 256 Mio et les 128 fichiers simultanés ne sont pas exercés exhaustivement.
Pas de campagne d'injection des échecs firmware, de concurrence ou de firmware
physique. Le nettoyage des scénarios négatifs n'est pas mesuré indépendamment
par les trois mots du refus : le host conserve sa première erreur.
La fermeture complète du compilateur, sa reconstruction autonome et les
générations finales identiques restent à démontrer. Les trois PE Nova sont
encore produits par le seed C temporaire, jamais présentés comme producteur final.

