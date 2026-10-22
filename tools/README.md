# Outils actuels

- `inspection/ntlayout.py` : inspecte la structure des artefacts et sert au contrôle de layout du script d'auto-reconstruction.
- `validation/check_layout.py` : vérifie les en-têtes C et les listes de modules chargés après réorganisation.
- `validation/a8_run_evidence.py` : lit, en lecture seule, un répertoire d'exécution A8 archivé et en tire les faits mesurés (lots terminés, phase d'arrêt, état de la machine, durée d'attente, empreintes des images). Voir `../docs/status/a8-trial05-shutdown.md`.
- `validation/a8_pin_discrepancies.py` : explique les trois écarts d'empreinte de la réorganisation (pin déclaré, révision réelle désignée, delta des chemins) et signale les en-têtes requis sans empreinte. Voir `../docs/status/a8-pin-discrepancies.md`.

Les anciens scripts de campagne, de réécriture ponctuelle et d'analyse de journaux sont archivés dans `../legacy/tools/`. Ils ne doivent pas être pris pour la commande de build actuelle.
