# Frontend natif — constantes et structure du fichier

native-frontend.ntasm compose les corps déjà testés du lexer, du parser u64
et du registre de symboles avec native_add_const et native_front_line. Ce fichier est statique :
aucun générateur ou concaténateur externe n'est nécessaire au build.
Les drivers des composants séparés ne sont pas inclus.

## API native_add_const

RCX=WORK de 0x1D000 octets, RDX=ligne lisible, R8=longueur,
R9=deux qwords de provenance {offset absolu, numéro de ligne}.
Les régions sont distinctes; la ligne et la provenance restent en lecture seule.
RAX retourne le record inséré ou zéro; R10 le code; R11 l'index local de faute.
Les non-volatils et la pile sont préservés.

Le caller initialise le compteur/table. Le helper emploie les tokens à
WORK+1C400 et un candidat séparé à +1CD00; il publie seulement après validation.
Le contexte de phase globale du fichier n'est pas encore traité par ce helper.

Syntaxe : const, whitespace, identifiant, '=', entier signé ou non signé.
Les commentaires/whitespace sont gérés par le lexer. const et entry ne peuvent
pas être des noms de constantes. Le moins doit être adjacent à la magnitude.
Les positifs vont jusqu'à u64::MAX, les négatifs jusqu'à i64::MIN; -0 garde
son flag signé. Les metadata du record conservent valeur, nom, offset et ligne.

Codes propagés : lexer 100/101/102, syntaxe 201, doublon 300, capacité 500,
provenance/contexte interne 600. L'index est relatif à la ligne, pas une colonne
1-based; le formateur global devra le convertir. La provenance exige une ligne
1..4096 et une fin de tranche ne dépassant pas l'offset 65535.

## Preuve de composition

543 appels contrôlés dans un programme UEFI :

- 24 déclarations variées, dont 7 publiées et 17 refusées, puis comparaison
  de la table finale et de ses octets non publiés;
- 512 déclarations générées dans le driver, toutes réellement passées par
  lexer → parser u64 → table, avec records et provenance exacts;
- 513e nom refusé, puis doublon refusé avant capacité sans changer sa valeur;
- 5 contrôles de provenance, dont la borne haute valide.

Le driver vérifie compteurs, records, absence d'écriture après la table, canaris,
sentinelles ABI et FreePool. Les erreurs sont localisables via son diagnostic
de test E900. Ce code ne constitue pas encore un frontend complet de fichier :
format/abi/entry/sections/instructions, récupération globale et émission native
restent à composer, puis le point fixe doit être prouvé.

## API native_front_line (structure maintenant portée)

Même signature d'entrée que native_add_const. RAX retourne un tag :
0 ligne vide/commentaire, 1 format, 2 abi, 3 const, 4 entry, 5 section, 6 label.
R10/R11 gardent le code et l'index local. Les erreurs ne publient pas de nouvel état.

WORK+80 contient la phase : 0 format, 1 abi, 2 const/entry, 3 attente text,
4 text, 5 rdata, 6 data. Le descripteur entry occupe +88..B0 :
seen, pointeur de nom, longueur, offset absolu du nom, ligne, début absolu de ligne.
Le caller conserve les octets source immuables pendant toute l'analyse.

Les labels utilisent le curseur text à +18, rdata à +8 et data à +10
(offsets hexadécimaux), les catégories 22/42/62 et la provenance courante.
Leur insertion partage la table des constantes et refuse les collisions.
Le driver emploie des curseurs préremplis 12/32/48 pour tester ces liaisons.

42 scénarios enchaînés vérifient ordre, droits, arité, collisions, casse,
entry et invariance du descripteur après erreur. Table et entry sont recomparés
entièrement à la fin. Ils s'ajoutent aux 543 contrôles précédents.

Frontière : entry est ici collectée, pas validée comme cible d'instruction à EOF.
Le contrôle des sections non vides, les données/instructions, la récupération
globale et l'émission native restent nécessaires. Les corps non portés sont
refusés E400, jamais ignorés; les opérations connues dans la mauvaise section
sont refusées E202. Cette couche ne doit pas être présentée comme un assembleur
natif complet ni comme B2.1.

## Alignements et remplissages natifs

native_front_line traite aussi align (tag 7) et zero (tag 8).
align accepte exactement 2/4/8/16; zero exige un entier positif, décimal ou hex.
Les compteurs sont bornés à 32768/16384/8192 pour text/rdata/data.
Les calculs vérifient la place restante avant addition; un offset hors borne
ne peut pas être ramené à zéro par un overflow.

WORK+20 publie la longueur complète et +28 le kind : 2 ZERO, 3 NOP.
Le scratch +1C500 contient au plus min(longueur,1024) octets. Un consommateur
doit émettre le remplissage décrit par le kind, pas lire longueur octets dans
ce scratch. Il ne consomme ce descripteur que si R10=0 et le tag désigne
une opération émettrice. Les autres lignes peuvent conserver le dernier descripteur.

30 cas supplémentaires vérifient curseur, longueur, kind, préfixe exact,
partie inutilisée A5, gardes et absence de publication en erreur.
Les données scalaires, chaînes et instructions natives restent à porter.

## Scalaires natifs (port effectué)

byte/word/dword/qword sont désormais pris en charge, tag 9, kind BYTES=1.
Les entiers signés/non signés et les constantes sont vérifiés à leur largeur,
y compris -0. Les labels ne sont pas des constantes implicites. addr(...) reste
explicitement refusé E400 jusqu'au port des relocations natives.

Le helper privé nd_parse_value retourne les bits, le signe et le nombre de
tokens consommés; il réutilise native_parse_u64 et native_symbol_find.
Les valeurs sont d'abord validées dans WORK+1CE00 (8 qwords maximum).
Après validation de la liste et de la capacité, les octets little-endian sont
copiés vers +1C500, puis le curseur et le descripteur sont publiés.
Une erreur tardive ne modifie donc ni le scratch publié ni le descripteur.

31 nouveaux vecteurs couvrent limites, listes, références, alignement naturel,
ponctuation, capacité, constante négative et absence de publication partielle.
La garde du test a été déplacée après le tableau temporaire : le dernier record
du buffer de tokens appartient bien au lexer lors des listes à 16 tokens.
Les chaînes, addr et les instructions restent à porter.
