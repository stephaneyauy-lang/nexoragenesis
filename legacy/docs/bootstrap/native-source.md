# Cœur natif et lecture du fichier

native-source.ntasm est le nouveau point de portage du producteur natif.
Il reprend le cœur de native-frontend.ntasm sans ses grands drivers/oracles,
puis ajoute les appels UEFI de lecture et le parcours du source.
L'ancien fichier reste un banc de régression, pas une dépendance de build.

Le programme est lui-même assemblé par notre producteur UEFI actuel.
Pour le tester, placer son PE comme EFI/BOOT/BOOTX64.EFI et un fichier source
comme NTASM1.NTASM sur un disque QEMU jetable.

## Ce qui fonctionne

- LoadedImage → DeviceHandle → SimpleFS → OpenVolume; source ouverte READ.
- GetInfo avant Read; répertoires et informations incohérentes refusés.
- WORK et SRC alloués avec leurs bandes canari normatives, contrôle après
  chaque Read et avant FreePool, fermeture des handles avant libération.
- Lecture réelle jusqu'à EOF, maximum 65535 octets; à cette taille la
  dernière requête Read vaut un octet, indépendamment de FileSize.
- Parcours LF/CRLF, limites 255 octets/4096 lignes, provenance et appel
  de native_front_line pour chaque ligne du sous-ensemble porté.
- Diagnostic positionné, état de sortie, cleanup et BootServices.Exit.

Une ligne NSCAN donne symboles, tailles text/rdata/data, octets lus (B) et
dernière capacité demandée à Read (Q). Les statistiques sont capturées avant
la libération; aucune lecture de WORK n'est effectuée après FreePool.

## Frontière importante

NG_NTASM_NATIVE_SCAN_OK signifie seulement que ce parcours du sous-ensemble
pris en charge a atteint la dernière section. Il ne prouve pas un programme
exécutable valide : instructions/chaînes/addr, validation finale d'entry,
sections non vides, récupération globale, deux passes et writer natifs restent
à compléter. Aucun NTASM1.EFI n'est créé par ce programme pour l'instant.

io_test_fault vaut zéro dans le source courant. Le mode de test 1 simule un
AllocatePool « succès + pointeur nul » sans allocation réelle; il a permis
de corriger un faux succès. Ce n'est pas une option contrôlée par le source lu.

Preuves : out/ntasm/native-source-checkpoint.md.
B2.1 et l'auto-hébergement ne sont pas encore livrés.

## Chaînes natives

ascii et utf16z sont désormais décodés par ce cœur, tag 10, kind BYTES=1.
Les échappements sont décodés explicitement; utf16z exige des valeurs 0..127
et ajoute le code unit nul. ascii n'ajoute aucun terminateur.
Les données sont préparées dans WORK+1C900..1CCFF, puis copiées à +1C500
seulement après validation de la chaîne, de l'arité et de la capacité.
Cette zone temporaire réutilise le buffer GetInfo après fermeture de la source.

io_test_fault=4 est un mode de preuve : il trace les octets BYTES sous NSDATA
et compare exactement les compteurs/descripteur/scratch avant et après une
ligne refusée. Une mutation indue est signalée comme erreur interne.
Le source normal conserve io_test_fault=0; les traces ne sont pas activées.
Les remplissages ZERO/NOP ne sont pas développés par cette trace BYTES.

## Références différées et premiers opcodes

qword addr(label) est maintenant enregistré et résolu après les définitions.
Les références conservent source/position/site/section dans les records
WORK+12400 (16 octets, compteur +60, maximum 512). Les records d'une ligne
sont préparés à +1CE80 et publiés seulement après validation de toute la ligne.
Les constantes ne sont pas des labels; absence ou catégorie incorrecte donne E301.

Les RVA rdata/data sont calculés à +50/+58 à partir des tailles mesurées.
Le mode de trace affiche NSADDR avec le site et la VA canonique résolue.
Attention : les qwords du scratch restent des placeholders zéro à ce stade;
le futur writer devra appliquer les adresses et produire DIR64 dans l'image.

nop et ret émettent réellement 90/C3, tag 11, et marquent les labels placés
au début de l'instruction. Les autres instructions restent à porter.
Le champ de dispatch des instructions non nulles désigne pour l'instant
uniquement ces opcodes sans opérandes : ne pas y inscrire les autres opcodes
avant d'implémenter leurs formes.

## Groupe registres et immédiats (porté)

Sont maintenant encodés nativement : mov registre/registre ou imm64 numérique,
push/pop, call registre, add/sub/and/or/xor/cmp registre ou imm32 signé,
test registre, shl/shr compte 0..63, imul registre/registre/imm32, nop et ret.
Les 16 GPR sont reconnus exactement. Les plages et arités sont contrôlées avant
publication; un staging de 15 octets à WORK+1CF00 précède le scratch publié.

Le descripteur interne d'instruction contient opcode bas, famille bits 8..15
et extension ModRM bits 16..23. Les mots sont désormais stockés inline dans
les records de dispatch, et non via 41 labels auxiliaires.
Les appels relatifs, branches et opérandes mémoire restent à porter.
Les traces vérifient les octets encodés; ces programmes d'entrée ne sont pas
eux-mêmes exécutés par l'analyseur.

## Adressages mémoire (portés hors RIP)

lea, load8/16/32/64 et store8/16/32/64 utilisent désormais le parseur mémoire
commun : base, index/échelle, déplacement canonique nul/disp8/disp32.
RSP/R12 restent interdits comme index dans le profil S0. RBP/R13 sans déplacement
émettent disp8=0; RSP/R12 en base utilisent SIB. Les constantes de déplacement
doivent être non négatives et tenir dans i32 avant application du signe externe.

Le descripteur temporaire à WORK+1CF20 contient mod/rm, SIB ou -1,
déplacement, largeur du déplacement et bits REX.BX. Le commit commun conserve
l'absence d'émission partielle. Les adressages RIP restent refusés explicitement.

## Point de reprise : en-têtes factorisés

État vérifié courant : voir `../../out/ntasm/native-header-checkpoint.md` et
`../../MEM.md`. Le source actif utilise une table de sept en-têtes de 56 octets
et une boucle de validation commune; entry/const restent séparés. 38 cas ciblés
et 163 régressions passent sur le nouveau PE. Aucun writer natif ni point fixe
n'est prouvé par ces tests. Prochain cycle : branches et fixups, dont le premier
cas `jmp start` est encore rouge. Les sections historiques ci-dessus décrivent
les étapes précédentes; leurs hashes ne sont pas ceux du binaire courant.

## Point de reprise : branches relatives natives

État actuel : `../../out/ntasm/native-branches-checkpoint.md` et `../../MEM.md`.
call(label), jmp, je, jne, jb et jae enregistrent maintenant des fixups puis
résolvent les labels texte à EOF, y compris les références vers l'avant.
WORK+40 compte les records de 24 octets, à partir de WORK+6400 (2048 max).
Le record conserve sourceOff/site/next/line/column/nameLength/kind/disp32.
Les appels par registre restent disponibles. Une cible absente ou non texte
est refusée E301 au nom; le dépassement de capacité est E500 au 2049e nom.

Exemple : `start:`, puis `jmp start` à l'offset 0, donne un site à 1 et
un déplacement -5. La trace montre NSDATA E900000000 puis NSFIX S00000001
VFFFFFFFB. Le vérificateur compare la reconstruction E9FBFFFFFF au golden;
le compilateur natif n'écrit pas encore une image PE avec ces octets patchés.

222 tests normaux passent; 13 goldens et 2048 records sont vérifiés en trace.
RIP, writer natif, validation EOF complète/récupération, point fixe et v0
restent à livrer. io_test_fault est revenu à zéro. Les en-têtes et leurs
preuves ci-dessus sont une étape historique, pas le hash courant.

## Point de reprise : RIP natif

Le checkpoint courant est `../../out/ntasm/native-rip-checkpoint.md`.
RIP couvre désormais les neuf opérations mémoire et les trois sections.
Les records relatifs ont kind=1 pour les branches texte et kind=2 pour RIP.
Le résolveur commun nr_rva calcule les adresses des labels; +1CF48/+1CF50
sont réservés au nom/provenance de l'instruction en cours.

237 tests normaux passent. Les traces correspondent à 18 goldens et à une
matrice de 432 instructions, contre-vérifiée avec le PE du bootstrap. Les
2048 records mêlant branches et RIP sont exacts, le 2049e est refusé.
Ces contrôles ne prouvent toujours pas un PE écrit par le producteur natif.
Le fichier est à 20 octets de la limite : séparer cœur et hôte UEFI est la
prochaine étape, avant writer natif, validation complète et auto-hébergement.

## État modulaire courant

`native-source.ntasm` est désormais conservé comme référence monolithique.
Le cœur est extrait dans `modules/compiler-core.ntasm`; `compiler-host.ntasm`
reprend l'I/O et appelle ses exports. Le programme n'est plus limité au test
intégré : NTASM1.NTASM est un vrai fichier source, NTCORE.EFI son compagnon.
237 cas sémantiques passent sur cette paire. Le diagnostic est émis après la
sortie du module et le nettoyage. Aucun writer PE natif n'est encore présent.
Preuve courante : `../../out/ntasm/native-modular-source-checkpoint.md`.
