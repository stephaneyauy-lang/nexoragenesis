# Périmètre x86-64 de NTASM v0 — A2

Ce catalogue décrit le périmètre déjà porté par le producteur C de référence et son encodage Nova. Il ne définit pas toute l'ISA x86-64 et n'ajoute aucune instruction au langage par simple inscription dans une table.

Le critère A2 de `docs/status/ntasm-completion.md` exige un catalogue v0 au-delà du seul S0, des encodages, adressages, symboles et relocations testés. Les règles d'utilisation dans un programme restent celles de `spec/ntasm/ntasm.md` : largeur, provenance des adresses, contexte CPU, privilège et contrats.

## Catalogue

`x64-forms.csv` décrit 44 familles d'instructions comprenant 126 orthographes, alias inclus. Il indique formes, largeurs, restrictions, points d'entrée C/Nova et suites de tests. Dix lignes supplémentaires décrivent l'adressage; les lignes SYM distinguent symboles, relocations et effets.

L'inventaire est contrôlé dans `tests_ntasm_x64_lower_lea.c` depuis les deux implémentations. Le scan du C offre les noms; un appel au véritable encodeur décide si chacun appartient au catalogue. Le scan Nova et le manifeste vérifient les exports, noms, alias et canaux. Les contrôles négatifs du scan doivent détecter une suppression ou une incohérence volontaire. Leurs lignes HOLE/AH sont des résultats de mutations attendues, pas des défauts supplémentaires du produit.

Les deux orthographes `ret` et `return` ne suppriment pas la distinction entre instruction machine et énoncé de retour du langage. `load` et `store` sont des formes contrôlées de mouvement; les appels et branchements symboliques ont leur raccordement propre.

## Formes et limites

- Registres 8, 16, 32 et 64 bits, registres étendus, AH/CH/DH/BH et incompatibilités REX.
- Paires registre/registre, registre/mémoire, mémoire/registre et immédiats selon la famille; aucune généralisation mémoire/mémoire.
- Immédiats et déplacements contrôlés aux bornes, valeurs négatives et extensions de signe.
- ModRM/SIB, base, index, échelles 1/2/4/8, base absente, index seul, déplacement seul, RIP et préfixes FS/GS.
- Les noms utilisés comme base/index désignent des registres 64 bits; un numéro de famille ne transforme pas EAX en RAX.
- Les descripteurs GDTR/IDTR utilisent le type existant `ptr<espace,array<u8,10>>`. Une source `ptr<espace,u64>` reste refusée pour cette instruction.
- CR0/2/3/4/8, transferts de port via immédiat ou DX, features CPU et CPL selon la référence.
- Symboles locaux/importés, liaison des sections, REL32 et DIR64. L'adressage symbolique passe par la construction/liaison d'objet; il ne doit pas être remplacé par une adresse immédiate devinée.

Les formes d'adressage encodables sont distinctes des formes autorisées par la vérification de provenance d'un programme v0. Un test d'encodeur sur `[rbx+8]` ne prouve pas qu'une fonction sans contrat de mémoire peut utiliser cette adresse.

## Vérifications complémentaires

- `x64_fixed`, `x64_rr`, `x64_ri`, `x64_two_reg`, `x64_binary`, `x64_high8`, `x64_memory`, `x64_lea`, `x64_shift_mem`, et les autres suites de famille : comparaison à l'encodeur C, cas positifs, limites et refus.
- `x64_lower_two_reg` couvre aussi IMUL à deux/trois opérandes, y compris mémoire et immédiat. Une preuve qui traverse un export depuis la source constitue bien une preuve de cet export; l'absence de wrapper direct dédié ne signifie pas absence de test.
- `x64_lower_lea` exige zéro trou déclaré parmi ses 189 rangs, dont 181 acceptations et 8 refus attendus. Chaque rang publie son issue et sa source échappée. L'index seul est également comparé séparément et doit rester distinct de base+déplacement.
- `x64_a2_parity` ajoute 176 cas complémentaires de source/opérandes et garde la sortie intacte au refus. Le cas absolu est une assertion de parité, pas une divergence seulement imprimée.
- Les suites `x64_lower_nxo_*`, `nxo_symbol`, `nxo_reloc` et les tests C d'objet vérifient les artefacts et la liaison.
- `tests_x64.c` confronte l'encodeur de référence à des octets attendus et à des vérifications d'exécution. La référence n'est donc pas seulement comparée à elle-même.
- `form_matrix` recense les formes structurelles réellement acceptées. Son total n'est ni un pourcentage d'avancement ni un remplacement du catalogue par instruction.

## Frontières de la clôture

Une suite verte ne clôt pas à elle seule A2. La livraison doit associer catalogue, code intégré, constructions fraîches et résultats de toutes les suites concernées. Les preuves et empreintes de la livraison sont référencées dans `docs/status/ntasm-a2-acceptance.md`.

A2 ne clôt pas A3 (typages), A4 (contrats), A7 (consommation du backend commun), A8 (auto-hébergement), ni B2.1. Les essais d'encodeur ne constituent pas une preuve de démarrage UEFI ou d'exécution matérielle des instructions privilégiées.
