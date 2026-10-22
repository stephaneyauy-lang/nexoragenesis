# ADR 0010 — Nova Compute CPU d'abord et probes UEFI externes R0/R1

- **Statut :** Accepté
- **Date :** 2026-09-02
- **Autorisation :** décision explicite de l'utilisateur du 2026-09-02
- **Producteur temporaire :** NASM 2.16.01 sous ADR 0009
- **Label obligatoire :** `BOOTSTRAP_EXTERNAL_ASM`

## Contexte

L'utilisateur choisit de commencer par Nova Compute CPU et autorise ASM ou
NTASM pour tester et amorcer le travail OS. Le compilateur commun, le frontend
Nova, Cnuva et le noyau n'existent pas encore. Présenter immédiatement un
binaire NASM comme Nova compilé ou comme noyau serait donc faux.

Le premier résultat doit être un oracle exécutable petit et vérifiable : une
application UEFI x86_64 externe calcule un kernel fixe `u32 vector_add`, vérifie
ses résultats et retourne au firmware. Elle fige une sémantique que le futur
backend `Nova Compute CPU cpu.ref` devra reproduire.

## Décision

Nova Compute CPU devient le premier rail expérimental visible. Il reste une
cible de calcul non privilégiée de Nova Device, jamais un remplaçant de Cnuva.
Cnuva demeure propriétaire du boot réel, du noyau, de la mémoire, du scheduler,
des IRQ, de CPUID/MSR et du matériel privilégié.

ADR 0009 est amendée uniquement pour autoriser :

```text
legacy/nasm/nova-compute-cpu-r0-r1.asm
  -> NASM 2.16.01 -f bin
  -> legacy/nasm/out/nova-compute-cpu-r0-r1.efi
  -> ESP jetable QEMU/OVMF

legacy/nasm/nova-compute-cpu-r1-r1.asm
  -> NASM 2.16.01 -f bin
  -> legacy/nasm/out/nova-compute-cpu-r1-r1.efi
  -> ESP jetable QEMU/OVMF
```

Chaque manifeste porte respectivement
`artifact_kind=NOVA_COMPUTE_R0_EXTERNAL_PROBE` ou
`artifact_kind=NOVA_COMPUTE_R1_EXTERNAL_PROBE`, un `claim_scope` pré-kernel
scalaire borné,
`bootstrap_provenance=external-nasm`, `release_eligible=false` et
`final_dependency=false`.

## Frontière du probe

Le probe peut uniquement exécuter un calcul scalaire entier borné en mémoire
statique, vérifier deux canaris et un golden indépendant, afficher exactement
un marqueur CHAR16 via `ConOut.OutputString`, puis retourner au firmware.

Il ne lit aucune source `.nova`, n'appelle pas `ExitBootServices`, n'acquiert
aucune ressource et n'accède ni à PCI, MMIO, DMA, MSR, ports I/O ou microcode.
Il ne peut entrer dans aucun bundle, package ou build final.

## Gates séparées

- `NC-R0-PROBE` : probe externe NASM sous QEMU, jamais release-éligible.
- `NC-R1-PROBE` : extension scalaire externe aux frontières
  `N=0,1,15,16,17,255,256`, toujours non release-éligible et distincte de NV1.
- `NV1 cpu.ref` : futur vrai frontend Nova et chaîne maison; impossible à
  promouvoir avec ce probe seul.

Après `NC-R0-PROBE` ou `NC-R1-PROBE`, le bootstrap minimal et Cnuva restent
nécessaires avant le vrai frontend Nova. Aucun probe externe ne termine NV1.

## Claim autorisé

> Un probe CPU x86_64 pré-kernel, produit par NASM externe et quarantainé,
> exécute sous QEMU/OVMF le corpus scalaire borné explicitement documenté pour
> son niveau R0 ou R1.

Claims interdits : « Nova compile », « l'OS boote », « noyau Genesis »,
« backend Nova terminé », « chaîne souveraine », « support CPU matériel » ou
« Gate B1 GREEN ».
