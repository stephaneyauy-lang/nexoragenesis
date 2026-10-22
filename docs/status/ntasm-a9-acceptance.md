# A9 — outil utilisable, preuves du 14 octobre 2026

Statut A9 : PARTIEL. Les preuves ci-dessous concernent la preparation bootstrap; A9 sera finalise apres A8 sur le producteur auto-heberge.

Le livrable est le bootstrap explicite ADR0012, pas le producteur final
auto-hébergé d'A8. Sa provenance reste `BOOTSTRAP_EXTERNAL_C` et son bandeau
annonce toujours B2.1 non livré. Aucune publication distante n'est effectuée.

## Sources, construction et binaire

`scripts/ntbuild.sh build` construit réellement 17 unités C et leur fermeture
de 19 headers, avec 34 empreintes épinglées. Deux pins périmés ont été mis à
jour après vérification des reçus d'intégration A4/A6 : frontend.c et
nova/machine_driver.c. Aucun pin n'est dérivé automatiquement à chaque build.

La construction normale du candidat a terminé 0 : binaire de 399056 octets,
SHA256 `0e5ef71c276a13a2ded09560b1df5e1a6df63d1a4216065066c4b7688f33df02`.
Deux producteurs distincts (-O2/-O0) donnent les huit exécutables épinglés ;
une troisième reconstruction reproduit le binaire de départ. Les neuf NXO
des deux générations sont également identiques. Logs et sorties originales :
`out/a1-a10-a9-20261014/build-candidate.log` et
`candidate/out/c-bootstrap/selfhost/` sous ce même dossier de campagne.

Le binaire testé reste dans `out/a1-a10-a9-20261014/candidate/out/c-bootstrap/ntasm/` : aucun remplacement du binaire principal pour A9 dans ce lot ; A9 sera finalisé après A8. La taille et le hash écrits dans ce document servent de preuves bootstrap et ne constituent pas une livraison finale A9.

## Surface et preuves utilisateur

Le guide court est `docs/guides/ntasm-quickstart.md`, relu à partir d'une proposition
Gemini 3.8 Flash ; `ntasm-cli.md` et `ntasm-build.md` restent les guides détaillés.
La porte CLI exécute 120 contrôles, sans échec, et détecte les fichiers
d'exemple supplémentaires, les fichiers manquants et les refus attendus.

Le binaire réellement construit, et non seulement cli.c inclus par un test,
a effectué onze invocations enregistrées : version, aide, objet MIR, lien MIR,
assemblage MIR direct, inspection, exécution C, résultat attendu incorrect,
refus de fallback MIR sur `run`, refus d'écrasement et source déplacée.
Le PE direct est identique au PE lié et le NXO ne change pas lorsque le chemin
source et le répertoire courant changent. `run --backend mir` reste refusé
explicitement ; le backend C demeure le défaut documenté.

Le PE lié par la vraie CLI a été chargé et exécuté sous QEMU/OVMF : retour 42,
huit GPR non volatiles préservés, retour au firmware, sortie QEMU 0 par HMP,
aucun log d'erreur et aucun émulateur restant. Le consumer UEFI vient du lot A4
déjà vérifié ; il ne produit pas le PE testé. La distinction exécution hôte
`run` / chargement UEFI est conservée.

Preuves : dossier nommé par `out/a1-a10-a9-20261014/cli-real-latest.txt`,
ses fichiers `.command`, `.log`, `.status`, `DONE`, `artifacts.sha256`, et
`out/a1-a10-a9-20261014/a9-qemu-run1/mir-cli/result.json`.

## Limites

Le succès d'A9 ne retire pas le compilateur C, ne transforme pas le point fixe
S0 en auto-hébergement v0 et ne certifie pas toute la suite globale B2.1.
Les mesures sont rattachées aux sources et artefacts du reçu d'intégration.
Les tâches lourdes sont sérialisées, avec départ à 9 Gio libres et arrêt sous
8 Gio ; aucun achat, installation ou endpoint de secours n'a été nécessaire.
