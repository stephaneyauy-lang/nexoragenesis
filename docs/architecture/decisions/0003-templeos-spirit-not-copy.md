# ADR 0003 — L'esprit d'immédiateté, jamais la copie de TempleOS

- **Statut :** Accepté
- **Date :** 2026-09-02

## Contexte

TempleOS démontre une expérience forte : le langage est aussi l'interface, le shell dialogue directement avec le compilateur, et l'utilisateur peut éditer, exécuter et inspecter dans un atelier cohérent. Son code, son identité et son modèle de sécurité ne répondent toutefois ni à l'objectif d'originalité ni aux exigences modernes de confinement de Genesis.

## Décision

Genesis reprend uniquement des principes d'expérience généraux :

- boucle immédiate `éditer -> compiler -> exécuter -> inspecter`;
- frontend et backend communs pour AOT et JIT;
- shell programmable en NX, sans cinquième langage;
- sources, documentation, exemples, dessin et inspection réunis dans Orbit;
- cible initiale étroite, personnalité propre et comportement observable de bout en bout.

Genesis refuse explicitement :

- toute copie de code, nom, texte, graphisme, asset, symbole, religion ou identité TempleOS;
- le ring 0 généralisé et l'espace d'adressage unique sans isolation;
- les pages simultanément inscriptibles et exécutables;
- l'accès matériel libre depuis une commande interactive;
- l'idée qu'une interface simple dispense de tests, de bornes ou de récupération.

L'identité fonctionnelle visée est originale : Orbit ouvre une source NX, la modifie, l'exécute dans un environnement borné, montre les représentations intermédiaires et revient intact après fermeture ou faute.

## Conséquences

- Les choix de sécurité peuvent demander plus d'étapes qu'une exécution directe en noyau.
- L'interpréteur NIR borné précède le JIT natif.
- Le JIT natif s'exécute en ring 3, dans un processus enfant doté de capacités minimales, avec transition RW vers RX et jamais RWX.
- Le vocabulaire, le design visuel, les démonstrations et le code doivent être propres à Genesis.

## Non-objectifs

- Réimplémenter TempleOS, HolyC, DolDoc ou son environnement visuel.
- Obtenir une compatibilité avec ses sources ou ses binaires.
- Reproduire ses compromis matériels ou de sécurité sous prétexte d'authenticité.
- Revendiquer une filiation de code : la référence porte exclusivement sur l'immédiateté créative.

## Preuves et gates

- Revue de provenance et d'identité avant chaque livrable visible.
- Gate D2 : Orbit réunit éditeur, shell, aide, fichiers, canvas et inspection dans une interface originale.
- Gate D3 : une source NX modifiée s'exécute sans reboot; faute, dépassement ou boucle infinie sont récupérés sans perdre Orbit.
- Gate I0 : les applications et essais sont confinés en ring 3 par capacités.
- Gate J0 : JIT et AOT donnent des résultats équivalents, aucune page RWX n'existe et le crash d'un enfant est récupéré.

