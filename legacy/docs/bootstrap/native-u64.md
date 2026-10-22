# Premier composant natif du compilateur

Source : legacy/ntasm-s0/native-u64.ntasm.
La fonction native_parse_u64 est écrite entièrement en NTASM-S0. Son driver
UEFI est un test, pas un assembleur auto-hébergé.

## Contrat

- RCX : adresse des octets; RDX : longueur; R8 : borne u64 inclusive.
- L'appelant garantit une région lisible de longueur RDX.
- RAX : valeur, ou zéro en erreur; R10 : 0 ou 102; R11 : index de faute.
- Décimal et préfixe 0x minuscule; chiffres hexadécimaux des deux casses.
- Pas de signe ni de zéros initiaux décimaux, sauf la valeur zéro seule.
- Aucun I/O, allocation, modification du source ou assemblage externe dans
  cette fonction. Les non-volatils utilisés et la pile sont restaurés.

Le contrôle de borne précède multiplication/addition. La division de la borne
par dix est une division binaire de 64 étapes, exprimée avec les instructions
S0 disponibles; le reste intermédiaire ne dépasse pas 19. Aucun DIV externe,
élargissement implicite ou troncature de débordement n'est utilisé.

## Preuve

Le driver a d'abord échoué avec un corps provisoire (native-u64-red).
Le vrai parser a passé 16 vecteurs, puis 199 vecteurs et les sentinelles ABI
RSI/RDI/R14/R15; RBX/R12/R13 servent réellement au driver.
Le PE est produit par notre assembleur puis exécuté dans une seconde VM :
native-u64-abi-build puis native-u64-abi-green sous out/ntasm/.

Les données couvrent les petites bornes 0..31, les frontières 8/16/32/64 bits,
u64::MAX, i64::MAX et 2^63, les dépassements, formats malformés et 16 bornes
pseudo-aléatoires déterministes. Seed 0x4e5441534d5f5330, récurrence modulo 2^64 :
x = x * 6364136223846793005 + 1442695040888963407.
Les oracles ont été calculés en précision entière non bornée, puis figés dans
les qword du test; aucun générateur externe n'est requis pour les rejouer.

Cette preuve concerne un composant et son ABI. Elle ne prouve ni un compilateur
complet écrit en NTASM, ni stage2 == stage3, ni la livraison B2.1.
