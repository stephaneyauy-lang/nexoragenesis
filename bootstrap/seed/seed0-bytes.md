# Ledger B0 — `seed0.efi` PE32+ x86_64

- **Révision du layout :** `B0-PE-v0`
- **État :** matérialisé et validé B0 sous QEMU/OVMF le 2 septembre 2026
- **Taille exacte attendue :** `0x600` = 1 536 octets
- **SHA-256 pré-calculé depuis les octets de ce ledger :** `69fa9aedbe1d009457c6cd065a78d90d1d997111d49719ce79fe3045603901d0`
- **Gate :** B0 GREEN; preuve canonique dans `out/b0/20260902-135815-ddaea37914764ec9828b8f6fa4b87a9d/manifest.md`.

Ce document est l'autorité octet par octet de la première forme de `seed0.efi`. Il ne contient pas le binaire. Toute différence de taille, d'octet ou de hash est un échec, pas une variante équivalente.

## Contrat observable

L'image est une application UEFI x86_64 dont le point d'entrée reçoit `RCX = ImageHandle` et `RDX = EFI_SYSTEM_TABLE *`. Son seul effet externe intentionnel est :

1. charger `SystemTable->ConOut`;
2. appeler `ConOut->OutputString(ConOut, L"NG_SEED0_OK\r\n")`;
3. ignorer le statut de cet affichage;
4. retourner `EFI_SUCCESS` (`RAX = 0`) au firmware.

Il n'y a aucun import PE, appel réseau, accès fichier, allocation, écriture MMIO, accès port I/O, boucle, entrée utilisateur ou code auto-modifiant.

## Layout complet

Tous les intervalles sont inclusifs et couvrent sans trou `0x0000..0x05ff`.

| Offset fichier | Taille | Contenu | Permission chargée |
|---:|---:|---|---|
| `0x0000..0x003f` | `0x40` | en-tête DOS minimal | en-têtes |
| `0x0040..0x0043` | `0x04` | signature PE | en-têtes |
| `0x0044..0x0057` | `0x14` | en-tête COFF | en-têtes |
| `0x0058..0x0147` | `0xf0` | en-tête optionnel PE32+ | en-têtes |
| `0x0148..0x016f` | `0x28` | en-tête de section `.text` | en-têtes |
| `0x0170..0x0197` | `0x28` | en-tête de section `.rdata` | en-têtes |
| `0x0198..0x01ff` | `0x68` | bourrage d'en-têtes, tous les octets à zéro | en-têtes |
| `0x0200..0x021b` | `0x1c` | point d'entrée x86_64 | RX |
| `0x021c..0x03ff` | `0x1e4` | bourrage `.text`, tous les octets à zéro | RX |
| `0x0400..0x041b` | `0x1c` | chaîne UCS-2/CHAR16 terminée par zéro | R |
| `0x041c..0x05ff` | `0x1e4` | bourrage `.rdata`, tous les octets à zéro | R |

Il n'existe ni overlay après `0x05ff`, ni espace non déclaré, ni section inscriptible. `SectionAlignment = 0x1000` place `.text` et `.rdata` sur deux pages virtuelles distinctes; aucun mélange W+X n'est donc caché par un partage de page.

## Champs PE/COFF

Les entiers multioctets sont encodés little-endian.

### En-tête DOS

| Offset | Octets | Champ | Valeur / rôle |
|---:|---|---|---|
| `0x0000` | `4D 5A` | `e_magic` | `MZ` |
| `0x0002..0x003b` | 58 octets `00` | autres champs DOS | nuls; aucun stub DOS exécutable |
| `0x003c` | `40 00 00 00` | `e_lfanew` | en-tête PE à `0x40` |

### Signature et en-tête COFF

| Offset | Octets | Champ | Valeur / rôle |
|---:|---|---|---|
| `0x0040` | `50 45 00 00` | signature | `PE\0\0` |
| `0x0044` | `64 86` | `Machine` | `0x8664`, x86_64 |
| `0x0046` | `02 00` | `NumberOfSections` | `.text`, `.rdata` |
| `0x0048` | `00 00 00 00` | `TimeDateStamp` | nul et déterministe |
| `0x004c` | `00 00 00 00` | `PointerToSymbolTable` | aucune table COFF |
| `0x0050` | `00 00 00 00` | `NumberOfSymbols` | aucun symbole COFF |
| `0x0054` | `F0 00` | `SizeOfOptionalHeader` | 240 octets, PE32+ avec 16 répertoires |
| `0x0056` | `22 00` | `Characteristics` | `EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE`; `RELOCS_STRIPPED` reste à 0 |

### En-tête optionnel PE32+

| Offset | Octets | Champ | Valeur / rôle |
|---:|---|---|---|
| `0x0058` | `0B 02` | `Magic` | `0x020b`, PE32+ |
| `0x005a` | `00 00` | versions linker | nulles, aucun linker |
| `0x005c` | `00 02 00 00` | `SizeOfCode` | taille brute `.text`, `0x200` |
| `0x0060` | `00 02 00 00` | `SizeOfInitializedData` | taille brute `.rdata`, `0x200` |
| `0x0064` | `00 00 00 00` | `SizeOfUninitializedData` | aucune BSS |
| `0x0068` | `00 10 00 00` | `AddressOfEntryPoint` | RVA `0x1000` |
| `0x006c` | `00 10 00 00` | `BaseOfCode` | RVA `0x1000` |
| `0x0070` | 8 octets `00` | `ImageBase` | base préférée nulle, image position-indépendante |
| `0x0078` | `00 10 00 00` | `SectionAlignment` | `0x1000` |
| `0x007c` | `00 02 00 00` | `FileAlignment` | `0x200` |
| `0x0080..0x008b` | 12 octets `00` | versions OS/image/subsystem | non revendiquées |
| `0x008c` | `00 00 00 00` | `Win32VersionValue` | réservé, zéro |
| `0x0090` | `00 30 00 00` | `SizeOfImage` | `0x3000` après alignement virtuel |
| `0x0094` | `00 02 00 00` | `SizeOfHeaders` | `0x200` |
| `0x0098` | `00 00 00 00` | `CheckSum` | non utilisé ici |
| `0x009c` | `0A 00` | `Subsystem` | `EFI_APPLICATION` = 10 |
| `0x009e` | `00 01` | `DllCharacteristics` | `NX_COMPAT`, aucune page de données exécutable |
| `0x00a0..0x00bf` | 32 octets `00` | réserves/commits pile et tas | gérés par l'environnement UEFI, non revendiqués par cette image |
| `0x00c0` | `00 00 00 00` | `LoaderFlags` | réservé, zéro |
| `0x00c4` | `10 00 00 00` | `NumberOfRvaAndSizes` | 16 |

### Répertoires de données

Chaque entrée fait huit octets `{VirtualAddress, Size}`. Elles sont toutes nulles : aucun import, export, certificat, unwind, IAT, TLS ou relocation de base.

| Offset | Répertoire | Octets |
|---:|---|---|
| `0x00c8..0x00cf` | export | huit `00` |
| `0x00d0..0x00d7` | import | huit `00` |
| `0x00d8..0x00df` | resource | huit `00` |
| `0x00e0..0x00e7` | exception | huit `00` |
| `0x00e8..0x00ef` | certificate | huit `00` |
| `0x00f0..0x00f7` | base relocation | huit `00` |
| `0x00f8..0x00ff` | debug | huit `00` |
| `0x0100..0x0107` | architecture | huit `00` |
| `0x0108..0x010f` | global pointer | huit `00` |
| `0x0110..0x0117` | TLS | huit `00` |
| `0x0118..0x011f` | load config | huit `00` |
| `0x0120..0x0127` | bound import | huit `00` |
| `0x0128..0x012f` | IAT | huit `00` |
| `0x0130..0x0137` | delay import | huit `00` |
| `0x0138..0x013f` | CLR | huit `00` |
| `0x0140..0x0147` | réservé | huit `00` |

L'absence de table de relocation est intentionnelle : le code n'incorpore aucune adresse absolue. Le bit COFF `RELOCS_STRIPPED` est néanmoins nul. La bibliothèque PE/COFF d'EDK2 documente explicitement ce cas comme « image relocatable but has no base relocs to apply ». Cette propriété a été confirmée par les deux boots du test B0 sur le banc OVMF consigné; elle ne vaut pas promesse de compatibilité avec tout firmware propriétaire.

### En-têtes de sections

| Offset | Section / champ | Octets | Valeur |
|---:|---|---|---|
| `0x0148` | `.text.Name` | `2E 74 65 78 74 00 00 00` | `.text` |
| `0x0150` | `.text.VirtualSize` | `1C 00 00 00` | 28 octets utiles |
| `0x0154` | `.text.VirtualAddress` | `00 10 00 00` | RVA `0x1000` |
| `0x0158` | `.text.SizeOfRawData` | `00 02 00 00` | `0x200` |
| `0x015c` | `.text.PointerToRawData` | `00 02 00 00` | offset `0x200` |
| `0x0160..0x016b` | relocations/lignes `.text` | 12 octets `00` | absentes |
| `0x016c` | `.text.Characteristics` | `20 00 00 60` | code, lecture, exécution; jamais écriture |
| `0x0170` | `.rdata.Name` | `2E 72 64 61 74 61 00 00` | `.rdata` |
| `0x0178` | `.rdata.VirtualSize` | `1C 00 00 00` | 28 octets utiles |
| `0x017c` | `.rdata.VirtualAddress` | `00 20 00 00` | RVA `0x2000` |
| `0x0180` | `.rdata.SizeOfRawData` | `00 02 00 00` | `0x200` |
| `0x0184` | `.rdata.PointerToRawData` | `00 04 00 00` | offset `0x400` |
| `0x0188..0x0193` | relocations/lignes `.rdata` | 12 octets `00` | absentes |
| `0x0194` | `.rdata.Characteristics` | `40 00 00 40` | données initialisées, lecture; jamais écriture/exécution |
| `0x0198..0x01ff` | alignement | 104 octets `00` | complète `SizeOfHeaders = 0x200` |

## Routine x86_64

Le code ne touche aucun registre non volatil. À l'entrée UEFI, `RSP` pointe sur l'adresse de retour. La soustraction de `0x28` réserve les 32 octets de shadow space et rétablit l'alignement de 16 octets exigé avant `call`; l'addition symétrique restaure exactement le `RSP` d'entrée.

| Offset fichier | RVA | Octets | Instruction / preuve |
|---:|---:|---|---|
| `0x0200` | `0x1000` | `48 83 EC 28` | `sub rsp, 0x28` |
| `0x0204` | `0x1004` | `48 8B 4A 40` | `mov rcx, [rdx+0x40]`; `EFI_SYSTEM_TABLE.ConOut` est à l'offset `0x40` sur x64 |
| `0x0208` | `0x1008` | `48 8D 15 F1 0F 00 00` | `lea rdx, [rip+0x0ff1]`; RIP suivant = RVA `0x100f`, cible = RVA `0x2000` |
| `0x020f` | `0x100f` | `48 8B 41 08` | `mov rax, [rcx+0x08]`; second pointeur du protocole = `OutputString` |
| `0x0213` | `0x1013` | `FF D0` | `call rax`; arguments `RCX = ConOut`, `RDX = chaîne` |
| `0x0215` | `0x1015` | `31 C0` | `xor eax, eax`; `EFI_SUCCESS`, zéro étendu dans `RAX` |
| `0x0217` | `0x1017` | `48 83 C4 28` | `add rsp, 0x28`; restaure pile et shadow space |
| `0x021b` | `0x101b` | `C3` | `ret`; retour propre au chargeur UEFI |
| `0x021c..0x03ff` | — | 484 octets `00` | alignement brut de `.text` |

La disposition x64 de `EFI_SYSTEM_TABLE` utilisée est : en-tête 24 octets; `FirmwareVendor` à `0x18`; `FirmwareRevision` à `0x20`; padding à `0x24`; `ConsoleInHandle` à `0x28`; `ConIn` à `0x30`; `ConsoleOutHandle` à `0x38`; `ConOut` à `0x40`. Dans `EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL`, `Reset` est à `0x00` et `OutputString` à `0x08`.

## Chaîne CHAR16

| Offset fichier | RVA | Octets | Contenu |
|---:|---:|---|---|
| `0x0400` | `0x2000` | `4E 00 47 00 5F 00 53 00 45 00 45 00 44 00 30 00` | `NG_SEED0` |
| `0x0410` | `0x2010` | `5F 00 4F 00 4B 00 0D 00 0A 00 00 00` | `_OK\r\n\0` |
| `0x041c..0x05ff` | — | 484 octets `00` | alignement brut de `.rdata` |

La chaîne compte 13 caractères visibles/contrôle puis un terminateur CHAR16 nul : 28 octets au total.

## Hex dump canonique

Chaque ligne commence par l'offset du premier octet et contient exactement 16 octets. Ce dump couvre les 1 536 octets du fichier; il n'y a rien avant `0x0000` ni après la ligne `0x05f0`.

```text
0000  4D 5A 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0010  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0030  00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 00
0040  50 45 00 00 64 86 02 00 00 00 00 00 00 00 00 00
0050  00 00 00 00 F0 00 22 00 0B 02 00 00 00 02 00 00
0060  00 02 00 00 00 00 00 00 00 10 00 00 00 10 00 00
0070  00 00 00 00 00 00 00 00 00 10 00 00 00 02 00 00
0080  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0090  00 30 00 00 00 02 00 00 00 00 00 00 0A 00 00 01
00a0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00b0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00c0  00 00 00 00 10 00 00 00 00 00 00 00 00 00 00 00
00d0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00e0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00f0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0100  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0110  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0120  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0130  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0140  00 00 00 00 00 00 00 00 2E 74 65 78 74 00 00 00
0150  1C 00 00 00 00 10 00 00 00 02 00 00 00 02 00 00
0160  00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 60
0170  2E 72 64 61 74 61 00 00 1C 00 00 00 00 20 00 00
0180  00 02 00 00 00 04 00 00 00 00 00 00 00 00 00 00
0190  00 00 00 00 40 00 00 40 00 00 00 00 00 00 00 00
01a0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
01b0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
01c0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
01d0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
01e0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
01f0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0200  48 83 EC 28 48 8B 4A 40 48 8D 15 F1 0F 00 00 48
0210  8B 41 08 FF D0 31 C0 48 83 C4 28 C3 00 00 00 00
0220  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0230  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0240  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0250  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0260  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0270  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0280  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0290  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
02a0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
02b0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
02c0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
02d0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
02e0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
02f0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0300  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0310  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0320  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0330  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0340  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0350  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0360  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0370  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0380  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0390  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
03a0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
03b0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
03c0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
03d0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
03e0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
03f0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0400  4E 00 47 00 5F 00 53 00 45 00 45 00 44 00 30 00
0410  5F 00 4F 00 4B 00 0D 00 0A 00 00 00 00 00 00 00
0420  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0430  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0440  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0450  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0460  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0470  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0480  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0490  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
04a0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
04b0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
04c0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
04d0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
04e0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
04f0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0500  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0510  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0520  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0530  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0540  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0550  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0560  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0570  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0580  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0590  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
05a0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
05b0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
05c0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
05d0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
05e0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
05f0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
```

## Vérifications obligatoires après saisie

- taille brute exactement 1 536 octets;
- hash exactement égal à la valeur annoncée en tête de document;
- désassemblage de `0x0200..0x021b` exactement égal aux huit instructions du tableau;
- deux sections seulement, sans bit `WRITE` et sans section W+X;
- répertoire d'import nul et aucune donnée après `0x05ff`;
- test RED puis deux exécutions GREEN selon `docs/testing/b0-test-protocol.md`.

## Résultat vérifié B0

- `seed0.efi` matérialisé directement depuis les 96 lignes de 16 octets du dump, sans compilateur, assembleur ni linker;
- taille : 1 536 octets;
- SHA-256 : `69fa9aedbe1d009457c6cd065a78d90d1d997111d49719ce79fe3045603901d0`;
- inspection GNU objdump 2.42 : `pei-x86-64`, entry `0x1000`, `.text` RX, `.rdata` R, aucune importation;
- RED : OVMF fonctionnel, seed absent, aucune occurrence du marqueur;
- GREEN-1 et GREEN-2 canonique : une occurrence exacte de `NG_SEED0_OK` chacune;
- dans les deux runs, la console montre dans l'ordre le démarrage du périphérique UEFI, le marqueur, puis le chargement de `UiApp`, ce qui prouve le retour au firmware;
- QEMU est resté `running` après chaque retour et les logs QEMU ne contiennent aucune faute fatale.

## Références normatives consultées

- UEFI 2.10, images, sous-système 10, point d'entrée et convention x64 : <https://uefi.org/specs/UEFI/2.10/02_Overview.html>
- UEFI 2.10, `EFI_SYSTEM_TABLE` et exemple `ConOut->OutputString` : <https://uefi.org/specs/UEFI/2.10/04_EFI_System_Table.html>
- EDK2, ordre des membres de `EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL` : <https://github.com/tianocore/edk2/blob/master/MdePkg/Include/Protocol/SimpleTextOut.h>
- Microsoft, format PE/COFF et caractéristiques de sections : <https://learn.microsoft.com/en-us/windows/win32/debug/pe-format>
- EDK2, cas relogeable sans entrées de relocation : <https://github.com/tianocore/edk2/blob/master/MdePkg/Library/BasePeCoffLib/BasePeCoff.c>
