# NG3D — deux moteurs 3D, un seul pipeline, une seule preuve

Ce répertoire contient deux moteurs 3D logiciels écrits dans les deux langages
du projet, sans NASM et sans `.INC` :

| fichier | langage | rôle |
| --- | --- | --- |
| [`ng3d.nova`](ng3d.nova) | Nova | moteur complet : damier 12×12 + cube, z-buffer, brouillard, écriture d'un PNG sur le volume UEFI |
| [`ng3d.ntasm`](ng3d.ntasm) | NTASM | moteur niveau machine : cube seul, rendu ligne par ligne, division signée écrite à la main |

Les deux implémentent **le même pipeline entierement entier**, et les deux
produisent **le même digest FNV‑1a** : `18167402047558109440`
(`0xFC1F93E84067C900`). Ce digest est aussi celui d'une troisième
implémentation indépendante écrite en Python (`out/ng3d/ref/ng3d_ref.py`,
outil hôte jetable, jamais une source livrée).

## Le pipeline, exactement

Tout est en fixe Q16.16, `ONE = 65536`. Aucun flottant n'existe dans l'un des
deux langages, donc aucune approximation ne peut se glisser entre eux.

- **Scène** — damier 12×12 de cases de 1 unité, `x,z ∈ [-6,6]`, `y = -1.5` ;
  cube de demi‑côté 1, de `y = -0.8` à `y = 1.2`.
- **Rotation** — Y de 30° puis X de 20°, `cos30 = 56756`, `sin30 = 32768`,
  `cos20 = 61566`, `sin20 = 22416`, décalages arithmétiques (floor).
- **Projection** — caméra à `z = +8`, `FOCAL = 350<<16`,
  `x16 = (160<<16) + x*FOCAL/w`, `y16 = (100<<16) - y*FOCAL/w`, `w = 8 - z`.
  La division est **tronquée vers zéro**, comme `idiv`, comme `/` en C et
  comme Nova — mesuré, pas supposé.
- **Culling** — aire signée `(x1-x0)(y2-y0) - (x2-x0)(y1-y0)`, discarded si
  `<= 0`.
- **Rasterisation** — fonctions de bord entières en Q32.32, pas constant par
  pixel, test `e01 >= 0 && e12 >= 0 && e20 >= 0`.
- **Profondeur** (profil complet) — interpolation de `1/z` par coordonnées
  barycentriques, z‑buffer qui garde le plus grand `1/z`.
- **Éclairage** — Lambert sur la normale **exactement unitaire** (les faces
  d'un cube sont alignées sur les axes, donc aucune racine carrée et aucune
  normalisation ne tournent) : `d = (nx*37837 + ny*45000 + nz*37837) >> 16`,
  `shade = 16384 + ((d*49152) >> 16)`.
- **Brouillard** (profil complet) — `fog = ((2^40/recip) - 655360) * 65536 / 786432`,
  borné à `[0,65536]`, mélange vers `(18,22,34)`.
- **Digest** — FNV‑1a 64 sur les `320*200*3` octets de l'image.

### Pourquoi deux profils

Le profil **complet** (sol + cube, z‑buffer, brouillard) est rendu par Nova et
produit l'image. Le profil **cube** est rendu par les DEUX moteurs : le cube est
convexe, ses faces visibles ne se recouvrent pas, et il est à `w ∈ [6.5, 9.5]`
où le brouillard sature à zéro — donc ni le z‑buffer ni la profondeur ne
changent un pixel. C'est ce qui rend l'égalité entre les deux langages
vérifiable sans écrire deux fois une image complète en mémoire.

## Exécuter

```bash
# Nova, sur l'hôte : rend l'image, écrit NG3D.PNG dans le répertoire courant,
# et renvoie le digest du profil cube.
cd out/ng3d/hostrun
../../../out/c-bootstrap/nova/readiness-v6/nova.exe run ../../../examples/ng3d/ng3d.nova
# -> {"ok":true,"result":"18167402047558109440",...}

# NTASM : même profil, même digest, sans appel système ni allocation.
./out/c-bootstrap/ntasm/ntasm run examples/ng3d/ng3d.ntasm --expect 18167402047558109440
# -> NTASM_C_RUN result=18167402047558109440 expected=18167402047558109440

# La référence indépendante, qui écrit aussi le PNG de référence.
python3 out/ng3d/ref/ng3d_ref.py full out/ng3d/ref/ng3d_ref.png
python3 out/ng3d/ref/ng3d_ref.py cube out/ng3d/ref/ng3d_cube.png
```

**Une seule écriture par volume.** Le runtime Nova n'expose que `rt_open_new`,
qui refuse d'écraser un fichier présent, et `rt_open_read`, dont l'échec pose
une erreur collante : il n'existe donc aucun test d'existence non destructif.
Le moteur écrit `NG3D.PNG` une fois ; une seconde exécution sur le même volume
signale `error 8` alors que le digest rendu est inchangé. Le digest est calculé
**avant** l'écriture, précisément pour que l'image ne puisse pas le fausser.

L'image produite par Nova est **identique octet pour octet** à celle de la
référence : `sha256 2e4cdbbd645e6966f99d7f635825e1d511ec4ed6afa99e4194dc60895f599e4a`,
192 278 octets. Le PNG est écrit par le moteur lui‑même : signature, IHDR,
IDAT en blocs deflate *stored*, Adler32 et CRC32 calculés en NTASM/Nova, pas de
compresseur disponible.

## Le PNG, pourquoi il est « stored »

Le moteur n'a pas de compresseur. Un flux deflate *stored* est un PNG valide que
n'importe quel lecteur décode ; c'est donc le flux le plus simple à écrire
depuis les deux langages, et il rend la comparaison d'octets possible entre les
trois implémentations. Les blocs font 65 535 octets, le dernier est final, et
l'Adler32 porte sur les 192 200 octets bruts (200 lignes × (1 octet de filtre +
960 octets RVB)).

## Les mines de NTASM v0 rencontrées ici

Ces cinq points ont été **mesurés**, pas lus dans une documentation. Ils sont
écrits ici parce que chacun a coûté une heure et qu'aucun n'est visible dans
les exemples existants.

1. **`div` et `idiv` sont refusés** : `E503: idiv requires an unavailable
   runtime safety proof`. Aucune branche ne satisfait la preuve, le refus est
   inconditionnel (`facts.may_trap`). La division signée est donc écrite à la
   main, en restoring shift‑subtract, dans `sdiv`.
2. **Un immédiat négatif casse l'exécutable** : `mov rax, -65536` passe le
   frontend puis produit une **segfault** à l'exécution. La même valeur écrite
   en décimal non signé (`18446744073709486080`) fonctionne, et
   `mov rax, 0 / sub rax, 65536` aussi. Toutes les constantes négatives du
   moteur sont donc écrites en complément à deux non signé.
3. **`store [sym]:ptr<user,i64>,-N` ne se parse pas** : le même motif avec `-N`
   donne `E200: expected '>' after type`, sans rapport avec la position réelle.
   La forme `mov rax, -N` puis `store [sym]:ptr<user,i64>,rax` est acceptée.
4. **`imul` à trois opérandes n'accepte qu'un immédiat** : `imul r, r, r2` est
   refusé (`invalid operand form`) ; la forme à deux opérandes `imul r, r2`
   est celle du moteur.
5. **Un registre déclaré corrompu par un appelé est réellement détruit** :
   `draw` déclare r15 dans ses `clobbers`, donc le compteur de lignes que
   `main` gardait dans r15 disparaissait au premier appel et la boucle
   s'arrêtait à la ligne 39 sur 200. L'état qui doit survivre à un appel vit
   dans un symbole `.data`, pas dans un registre.

Deux contraintes de forme, moins graves : un littéral `array<u8,N>` doit faire
exactement N octets, et l'accès à un tableau se fait par un pointeur typé
`ptr<user,array<u8,N> >` — le `ptr<user,u8>` direct ne correspond pas au type
déclaré du symbole.

## Ce que NTASM v0 ne sait pas faire, et qui compte ici

- Pas de variables locales : tout l'état vit dans des symboles `.data` à un
  seul élément ou dans des registres. C'est ce qui donne au moteur sa forme.
- Pas de tampon d'image possible sans littéral géant : d'où le **rendu ligne
  par ligne** — une seule ligne de 320 pixels tient dans les 960 octets du
  tampon `rowbuf`, et le digest est replié ligne après ligne.
- Pas d'indirection par variable : les triangles sont écrits explicitement dans
  `main`, six blocs de dix-huit instructions, générés depuis la même table
  d'index que la référence.

## État du banc UEFI

`out/ng3d/run-uefi.sh` est un runner hôte (il vit sous `out/`, ce n'est jamais
une source) : il construit un ESP **partitionné** — MBR, une partition FAT16
amorçable au secteur 63 — parce que c'est la forme des exécutions vertes
enregistrées dans l'arbre, et qu'OVMF ne prend son chemin de boot normal que
sur une image partitionnée. Il lance OVMF sous QEMU, collecte le journal
série, prend un `screendump` par le canal HMP et rapatrie un fichier du volume.

### Pourquoi le framebuffer est hors de portée aujourd'hui, mesuré

Le rendu vers le framebuffer n'est pas écrit, et ce n'est pas un marcher de
protocoles qui manque. La règle `memory_pointer` de la conformance ferme la
porte en deux temps :

- un accès mémoire par **symbole** est forcé à l'espace `user` avant la
  comparaison — `space = NTF_SPACE_USER;` — donc une annotation
  `ptr<firmware,…>` sur un symbole `.data` est refusée ;
- un accès par **registre** exige que le registre porte un type de pointeur
  *prouvé*, et le seul endroit où un pointeur `firmware` entre dans un
  registre est un `load` à travers un pointeur `firmware` déjà typé, donc à
  travers la chaîne `SystemTable → BootServices → …`.

L'adresse du framebuffer, elle, **ressort d'un appel firmware** : elle arrive
dans `rax` comme `u64` nu, et aucune forme ne la recharge avec un type
`firmware`. Le `store` est refusé avant l'encodage. Ce n'est pas une lacune de
l'encodeur x86 : c'est le modèle de contrats qui ne sait pas nommer un
pointeur obtenu d'un appel. Peindre dans l'écran demande aujourd'hui une
porte que le type n'a pas — et c'est la prochaine étape du projet, pas une
ligne manquante dans ce moteur.

### La porte de secours existe : ConOut

Le framebuffer est fermé par le type, mais **la console, non**. NTASM appelle
`SystemTable+64` puis `ConOut->SetAttribute` et `ConOut->OutputString`, et une
cellule de console est un demi-bloc `U+2580` dont le premier plan peint le
haut et le fond le bas. Une console 80×25 affiche donc une image couleur de
**80×50 pixels**. C'est mesuré : `out/ng3d/run-console2/serial.log` contient 80
demi-blocs écrits par NTASM sous OVMF.

Deux détails ne s'inventent pas :

- **le type de pointeur ne survit pas à une branche.** Après un `cmp`/`je`, le
  registre n'est plus reconnu comme une adresse : les trois `load` doivent être
  collés, et les adresses de protocole sont rangées dans des symboles `.data`
  avant la première branche ;
- **les adresses de fonction doivent vivre dans des registres callee-saved.**
  En r8/r9 elles sont écrasées par le firmware au premier appel et le
  `call_indirect` suivant saute vers 3 — c'est un `#UD` en cascade que le
  journal série nomme proprement.

Le rendu 3D complet n'est pas encore branché dessus : le pilote de console
reste à écrire, et le rendu sur écran s'efface dès que le programme rend la
main, parce que le firmware relance son shell interne qui efface l'écran.