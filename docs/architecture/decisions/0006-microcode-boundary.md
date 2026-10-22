# ADR 0006 — Frontière entre microcode constructeur et Cnuva-µ

- **Statut :** Accepté
- **Date :** 2026-09-02

## Contexte

Le mot « microcode » peut désigner abusivement du firmware CPU constructeur, des séquences machine ordinaires ou le programme de contrôle interne d'un CPU maison. Sur les processeurs AMD et Intel réels, les mises à jour de microcode sont authentifiées par le constructeur. Cnuva ne peut pas fabriquer un microcode arbitraire accepté par le Ryzen 5 7500F ou un CPU Intel.

Dans Genesis, le **microcode** est un programme de contrôle interne pour le datapath explicitement spécifié de `nxmu64` ou d'un futur softcore FPGA. Il est distinct du code machine x86_64, d'un kernel GPU, d'un pilote et d'un firmware constructeur.

Le label **constructeur** désigne un blob, firmware, pilote ou composant signé et contrôlé par le fabricant du matériel. Son utilisation doit être annoncée et ne devient jamais une preuve de souveraineté Genesis.

## Décision

- Sur AMD/Intel réel, Cnuva peut identifier famille, modèle et stepping, sélectionner un blob officiel authentifié, demander son chargement par le mécanisme documenté et vérifier la révision obtenue.
- Aucun blob AMD/Intel ne peut être présenté comme une production Cnuva ou comme du microcode maison.
- Aucun microcode expérimental ou non constructeur n'est chargé sur un CPU réel.
- Le compilateur autorise uniquement `@microcode(target="nxmu64")` pour produire le format maison NMU0 via Micro IR.
- Les cibles `@microcode(target="amd64")` et `@microcode(target="intel64")` sont refusées avec un diagnostic stable et explicite.
- Le rail souverain est `Cnuva-µ -> Micro IR -> NMU0 -> simulateur nxmu64 -> CPU virtuel -> softcore FPGA ultérieur`.
- Ce rail commence après l'expérience Orbit vivante et ne bloque jamais le boot x86_64.

## Conséquences

- Le support d'un Ryzen réel dépend honnêtement du microcode constructeur.
- Le microcode maison exige la définition d'un datapath propre et ne promet aucune compatibilité interne avec AMD ou Intel.
- Les démonstrations Cnuva doivent distinguer CPUID, code machine, chargement de blob officiel et microcode `nxmu64`.
- Le FPGA reste différé jusqu'à validation exhaustive du simulateur.

## Non-objectifs

- Contourner l'authentification de microcode AMD/Intel.
- Rétroconcevoir ou remplacer le microcode interne du Ryzen 5 7500F.
- Qualifier des instructions x86_64, un pilote CPU ou un kernel GPU de microcode.
- Charger automatiquement du microcode ou toucher au matériel réel avant autorisation explicite et gate dédié.

## Preuves et gates

- Tests négatifs du compilateur : les cibles `amd64` et `intel64` sont toujours refusées.
- Gate M0 : seuls un blob constructeur authentifié, une correspondance famille/modèle/stepping et une révision relue permettent d'annoncer le support microcode d'un CPU x86 réel.
- Gate M1 : 100 000 séquences déterministes concordent entre ISA visible, modèle de référence et microsteps du simulateur `nxmu64`; aucun chargement n'a lieu sur CPU réel.
- Toute future cible FPGA nécessite un plan et une autorisation séparés après le simulateur vert.

