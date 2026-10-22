# A10 — diagnostics, limites et déterminisme

Validation du 14 octobre 2026 dans le candidat A1/A10/A9 ; intégration tracée
par le reçu du même lot. Les diagnostics largeur/registre/section/ABI passent
162 contrôles ; les limites macros passent 1223 contrôles d'expansion et
114 contrôles de plafonds. Tous ces tests retenus ont terminé avec code 0.

Le gate existant `tests_ntasm_machine_pipeline.c` compare désormais les
conteneurs entiers entre deux images Nova compilées et mappées séparément :
31 sorties NXO/PE, sur 12 programmes, concordent octet pour octet. Les mêmes
assertions refusent une mutation d'un octet et une troncature d'un octet.
Les lecteurs/matérialiseurs C indépendants et les comparaisons d'exécution
déjà présents continuent à vérifier l'exactitude, séparément du déterminisme.

Résultat du gate complet : **1240 contrôles, 0 échec, 25 cas**. Il a été exécuté
avec les objets du build normal `-O2`. La tentative avec sanitizers a été
interrompue par la garde RAM, code 75 ; elle n'est pas certifiée verte.

Le build normal a également produit deux exécutables C différents, compilés
en `-O2` et `-O0` : huit PE correspondent aux références et les neuf objets NXO
sont identiques entre les constructions. La troisième reconstruction à `-O2`
retrouve les octets du premier producteur. Ce sont des propriétés de
reproductibilité ; aucune ne prouve l'auto-hébergement A8.

Le test réel de CLI ajoute un changement de chemin source et de répertoire
courant sans changement du NXO, ainsi que la comparaison PE direct/PE lié.

Preuves : `out/a1-a10-a9-20261014/VERIFIED.json`, `layout-release.run.log`,
`build-candidate.log`, `candidate/out/c-bootstrap/selfhost/` et le répertoire
nommé par `cli-real-latest.txt`. Le script historique `ntlayout.py` garde sa
signification : audit de forme d'un objet ; il n'est pas renommé en preuve de
déterminisme. Le corpus exécuté ne constitue pas une preuve mathématique pour
toute entrée possible et aucun résultat de performance n'est déduit.
