# Exemples de systèmes

- [Nexora OS](nexoros/README.md) : démonstration UEFI avec commandes et exécution d'une application Nova.
- [Nexora Kart](kart/README.md) : démonstration bare-metal.

Ces exemples proviennent du dernier commit du dépôt public. Les modifications OS non publiées de l'autre checkout n'ont pas été fusionnées automatiquement. Les chemins des scripts de construction sont adaptés à `examples/os/`, mais aucun boot QEMU n'a été rejoué pendant cette préparation.

La compilation NTASM utilise le build officiel : ses trois écarts d'empreintes doivent donc être résolus avant la reconstruction des exemples. Ne pas lancer plusieurs QEMU sans contrôle.
