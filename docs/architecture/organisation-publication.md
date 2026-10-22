# Organisation orientée compilateur

Le dossier générique `toolchain/` est remplacé par `compiler/`. Les sources sont classées selon leur responsabilité ; les tests sont séparés. `compiler/c/` contient la dépendance actuelle, pas une archive prématurée. `compiler/nova/` contient les implémentations Nova encore utilisées ou en cours de validation.

La correspondance exhaustive des anciens et nouveaux chemins est dans [source-map.csv](source-map.csv). Les imports par nom de module Nova et les interfaces publiques restent identiques. Les chemins explicites des chargeurs, les includes C et les commandes sont adaptés.

La fermeture des en-têtes du build doit rechercher d'abord le dossier du fichier incluant, comme le compilateur C, et normaliser les chemins. Cette règle a été adaptée pour éviter qu'un classement en sous-dossiers fasse disparaître des headers du contrôle d'empreintes. Les trois écarts de confiance préexistants restent visibles.

Les anciennes implémentations et campagnes sont dans `legacy/`. Les OS restent des exemples sous `examples/os/`. Les archives privées et les images de travail ne sont pas présentes.
