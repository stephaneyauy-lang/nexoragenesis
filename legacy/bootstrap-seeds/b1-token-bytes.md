# B1.1 — ledger du premier token NTASM-S0

Statut : **historique, non canonique**. Ce document contient à la fois
le mapping explicatif de tous les champs/instructions/données et le hex dump
canonique complet destiné au décodage direct, sans assembleur ni linker externe.
Le binaire correspondant est conservé sous `bootstrap/seed/b1/seed-b1.1.efi`. Il a précédé le RED E002 dédié et a été remplacé par la révision r1; il ne constitue plus la preuve canonique.

## 1. Portée exacte du jalon

B1.1 est un exécutable de bootstrap intermédiaire, pas encore l'assembleur
NTASM-S0 de la Gate B1 complète. Il effectue uniquement ce flux :

1. reçoit `ImageHandle` dans `RCX` et `SystemTable` dans `RDX`;
2. obtient `LoadedImageProtocol` par `BootServices.HandleProtocol`;
3. obtient le `DeviceHandle`, puis `SimpleFileSystemProtocol` par un second
   `HandleProtocol`;
4. ouvre le volume, puis `\NTASM1.NTASM` en lecture seule;
5. lit **un octet par appel**, au plus treize octets au total;
6. accepte si et seulement si la première ligne physique vaut les onze octets
   ASCII `format pe64`, immédiatement suivis de `LF` ou de `CR LF`;
7. ferme le fichier puis la racine du volume avant tout affichage;
8. affiche `NG_B1_1_FORMAT_OK\r\n` et quitte avec `EFI_SUCCESS`, ou affiche un
   diagnostic stable parmi `E001`, `E002`, `E100` et `E200`, puis quitte avec
   `EFI_LOAD_ERROR = 0x8000000000000001`;
9. appelle `BootServices.Exit(ImageHandle, status, 0, NULL)`; si `Exit` rend la
   main, son statut devient celui retourné après restauration complète de l'ABI.

Le premier `LF` termine la ligne : les octets d'une éventuelle deuxième ligne
ne sont ni lus ni validés par B1.1. Le chemin de sortie `\NTASM1.EFI` n'est
jamais ouvert; aucun fichier de sortie ne peut donc être créé, tronqué ou
modifié. Le registre non volatil `EDI` porte l'état interne : `0=succès`,
`1=E001`, `2=E002`, `3=E100`, `4=E200`. Les erreurs de protocole, volume ou
ouverture gardent `E001`; une erreur de `Read`, un compte lu incohérent ou une
erreur de fermeture donnent `E002`; EOF avant EOL donne `E100`; le premier
octet incompatible avec `format pe64`/LF/CRLF donne `E200`. Une erreur déjà
détectée n'est jamais masquée par une erreur de fermeture ultérieure.

### Décisions transitoires et limite de preuve

- Les diagnostics exacts sont `NGS0 E001 L0000 C0000 O00000000`,
  `NGS0 E002 L0000 C0000 O00000000`,
  `NGS0 E100 L0000 C0000 O00000000` et
  `NGS0 E200 L0001 C0001 O00000000`, chacun suivi de `CR LF NUL`. B1.1 donne
  une position nulle à EOF, car aucun octet fautif n'existe à pointer; le futur
  parseur complet devra calculer la position de fin de source.
- Le succès final normatif est `NG_NTASM_S0_OK`; le marqueur
  `NG_B1_1_FORMAT_OK` ne prouve que le premier token et ne doit jamais faire
  passer la Gate B1 complète au vert.
- `seed-pe32.md` décrit B1 comme le producteur complet. Une future révision doit
  nommer explicitement les intermédiaires B1.x qui utilisent l'enveloppe
  `B1-PE-v1` sans encore produire de PE.
- Si `SystemTable`, `ConOut` ou `ConOut.OutputString` est nul, il est impossible
  d'émettre sûrement un diagnostic. Ce chemin restaure l'ABI et retourne tout de
  même `EFI_LOAD_ERROR`; l'exigence d'affichage suppose donc l'environnement UEFI
  valide promis au point d'entrée.

## 2. Layout PE32+ canonique

Tous les entiers multioctets sont little-endian. Tout champ ou intervalle non
explicitement utile ci-dessous vaut zéro.

| Zone | Offset fichier | RVA | Taille utile | Taille brute |
|---|---:|---:|---:|---:|
| En-têtes | `0x0000` | — | `0x0228` | `0x0400` |
| `.text` RX | `0x0400` | `0x1000` | `0x0395` | `0x0400` |
| `.rdata` R | `0x0800` | `0x2000` | `0x01A8` | `0x0200` |
| `.data` RW | `0x0A00` | `0x3000` | `0x0008` | `0x0200` |
| `.reloc` R, discardable | `0x0C00` | `0x4000` | `0x000C` | `0x0200` |

Taille fichier exacte : `0x0E00` (3 584 octets). `SizeOfImage = 0x5000`.
Il n'existe aucun overlay.

SHA-256 attendu de la suite d'octets entièrement spécifiée par ce mapping :
`dd69708d4ebb8a93659058e1c06d916e5c4d40a1e97b70e4b075bf3103d87fbe`.
Cette valeur a été calculée sur une image de 3 584 octets construite uniquement
en mémoire pour vérification; aucun fichier binaire n'a été écrit.

### 2.1 DOS, COFF et Optional Header

| Offset | Taille | Champ | Valeur |
|---:|---:|---|---:|
| `0x0000` | 2 | `e_magic` | `4D 5A` |
| `0x0002` | 58 | autres champs DOS | `0` |
| `0x003C` | 4 | `e_lfanew` | `0x00000080` |
| `0x0040` | 64 | réserve/stub DOS | `0` |
| `0x0080` | 4 | signature | `50 45 00 00` |
| `0x0084` | 2 | `Machine` | `0x8664` |
| `0x0086` | 2 | `NumberOfSections` | `4` |
| `0x0088` | 4 | `TimeDateStamp` | `0` |
| `0x008C` | 4 | `PointerToSymbolTable` | `0` |
| `0x0090` | 4 | `NumberOfSymbols` | `0` |
| `0x0094` | 2 | `SizeOfOptionalHeader` | `0x00F0` |
| `0x0096` | 2 | `Characteristics` | `0x0022` |
| `0x0098` | 2 | `Magic` | `0x020B` |
| `0x009A` | 1 | `MajorLinkerVersion` | `0` |
| `0x009B` | 1 | `MinorLinkerVersion` | `0` |
| `0x009C` | 4 | `SizeOfCode` | `0x00000400` |
| `0x00A0` | 4 | `SizeOfInitializedData` | `0x00000600` |
| `0x00A4` | 4 | `SizeOfUninitializedData` | `0` |
| `0x00A8` | 4 | `AddressOfEntryPoint` | `0x00001000` |
| `0x00AC` | 4 | `BaseOfCode` | `0x00001000` |
| `0x00B0` | 8 | `ImageBase` | `0x0000000140000000` |
| `0x00B8` | 4 | `SectionAlignment` | `0x00001000` |
| `0x00BC` | 4 | `FileAlignment` | `0x00000200` |
| `0x00C0` | 12 | six champs de version | `0` |
| `0x00CC` | 4 | `Win32VersionValue` | `0` |
| `0x00D0` | 4 | `SizeOfImage` | `0x00005000` |
| `0x00D4` | 4 | `SizeOfHeaders` | `0x00000400` |
| `0x00D8` | 4 | `CheckSum` | `0` |
| `0x00DC` | 2 | `Subsystem` | `0x000A` |
| `0x00DE` | 2 | `DllCharacteristics` | `0x0140` |
| `0x00E0` | 8 | `SizeOfStackReserve` | `0x0000000000100000` |
| `0x00E8` | 8 | `SizeOfStackCommit` | `0x0000000000001000` |
| `0x00F0` | 8 | `SizeOfHeapReserve` | `0x0000000000100000` |
| `0x00F8` | 8 | `SizeOfHeapCommit` | `0x0000000000001000` |
| `0x0100` | 4 | `LoaderFlags` | `0` |
| `0x0104` | 4 | `NumberOfRvaAndSizes` | `16` |

Les répertoires `0..4` à `0x0108..0x012F` sont nuls. Le répertoire 5,
Base Relocation, à `0x0130` contient `RVA=0x4000, Size=0x000C`, soit les octets
`00 40 00 00 0C 00 00 00`. Les répertoires `6..15` à
`0x0138..0x0187` sont nuls. Il n'y a donc ni import, export, ressource,
exception, certificat, debug, TLS ni IAT.

### 2.2 Table des sections

Chaque entrée fait 40 octets; ses champs de relocation et de lignes sont nuls.

| Offset | Nom brut | VirtualSize | RVA | RawSize | RawPtr | Characteristics |
|---:|---|---:|---:|---:|---:|---:|
| `0x0188` | `2E 74 65 78 74 00 00 00` | `0x0395` | `0x1000` | `0x0400` | `0x0400` | `0x60000020` |
| `0x01B0` | `2E 72 64 61 74 61 00 00` | `0x01A8` | `0x2000` | `0x0200` | `0x0800` | `0x40000040` |
| `0x01D8` | `2E 64 61 74 61 00 00 00` | `0x0008` | `0x3000` | `0x0200` | `0x0A00` | `0xC0000040` |
| `0x0200` | `2E 72 65 6C 6F 63 00 00` | `0x000C` | `0x4000` | `0x0200` | `0x0C00` | `0x42000040` |

`0x0228..0x03FF` est nul.

## 3. `.text` — mapping exact des instructions

Pour chaque ligne, l'offset fichier est `0x0400 + (RVA - 0x1000)`. Les lignes
sont contiguës; la première commence au RVA `0x1000`, la dernière finit au RVA
`0x1394`. `0x1395..0x13FF` (fichier `0x0795..0x07FF`) est du padding nul.

| RVA | Octets | Instruction / rôle |
|---:|---|---|
| `0x1000` | `53` | `push rbx` |
| `0x1001` | `56` | `push rsi` |
| `0x1002` | `57` | `push rdi` |
| `0x1003` | `41 54` | `push r12` |
| `0x1005` | `41 55` | `push r13` |
| `0x1007` | `41 56` | `push r14` |
| `0x1009` | `41 57` | `push r15` |
| `0x100B` | `48 83 EC 70` | `sub rsp, 0x70` |
| `0x100F` | `49 89 CC` | `mov r12, rcx` |
| `0x1012` | `49 89 D5` | `mov r13, rdx` |
| `0x1015` | `31 DB` | `xor ebx, ebx` |
| `0x1017` | `31 F6` | `xor esi, esi` |
| `0x1019` | `45 31 F6` | `xor r14d, r14d` |
| `0x101C` | `45 31 FF` | `xor r15d, r15d` |
| `0x101F` | `BF 01 00 00 00` | `mov edi, 1` |
| `0x1024` | `48 85 D2` | `test rdx, rdx` |
| `0x1027` | `0F 84 15 02 00 00` | `je cleanup` |
| `0x102D` | `4C 8B 7A 40` | `mov r15, [rdx+0x40]` |
| `0x1031` | `4C 8B 72 60` | `mov r14, [rdx+0x60]` |
| `0x1035` | `4D 85 FF` | `test r15, r15` |
| `0x1038` | `0F 84 04 02 00 00` | `je cleanup` |
| `0x103E` | `4D 85 F6` | `test r14, r14` |
| `0x1041` | `0F 84 FB 01 00 00` | `je cleanup` |
| `0x1047` | `49 8B 86 98 00 00 00` | `mov rax, [r14+0x98]` |
| `0x104E` | `48 85 C0` | `test rax, rax` |
| `0x1051` | `0F 84 EB 01 00 00` | `je cleanup` |
| `0x1057` | `48 C7 44 24 30 00 00 00 00` | `mov qword [rsp+0x30], 0` |
| `0x1060` | `4C 89 E1` | `mov rcx, r12` |
| `0x1063` | `48 8D 15 96 0F 00 00` | `lea rdx, [rip+loaded_image_guid]` |
| `0x106A` | `4C 8D 44 24 30` | `lea r8, [rsp+0x30]` |
| `0x106F` | `FF D0` | `call rax` |
| `0x1071` | `48 85 C0` | `test rax, rax` |
| `0x1074` | `0F 85 C8 01 00 00` | `jne cleanup` |
| `0x107A` | `48 8B 44 24 30` | `mov rax, [rsp+0x30]` |
| `0x107F` | `48 85 C0` | `test rax, rax` |
| `0x1082` | `0F 84 BA 01 00 00` | `je cleanup` |
| `0x1088` | `48 8B 48 18` | `mov rcx, [rax+0x18]` |
| `0x108C` | `48 85 C9` | `test rcx, rcx` |
| `0x108F` | `0F 84 AD 01 00 00` | `je cleanup` |
| `0x1095` | `48 C7 44 24 38 00 00 00 00` | `mov qword [rsp+0x38], 0` |
| `0x109E` | `49 8B 86 98 00 00 00` | `mov rax, [r14+0x98]` |
| `0x10A5` | `48 85 C0` | `test rax, rax` |
| `0x10A8` | `0F 84 94 01 00 00` | `je cleanup` |
| `0x10AE` | `48 8D 15 5B 0F 00 00` | `lea rdx, [rip+simple_fs_guid]` |
| `0x10B5` | `4C 8D 44 24 38` | `lea r8, [rsp+0x38]` |
| `0x10BA` | `FF D0` | `call rax` |
| `0x10BC` | `48 85 C0` | `test rax, rax` |
| `0x10BF` | `0F 85 7D 01 00 00` | `jne cleanup` |
| `0x10C5` | `48 8B 4C 24 38` | `mov rcx, [rsp+0x38]` |
| `0x10CA` | `48 85 C9` | `test rcx, rcx` |
| `0x10CD` | `0F 84 6F 01 00 00` | `je cleanup` |
| `0x10D3` | `48 8B 41 08` | `mov rax, [rcx+0x08]` |
| `0x10D7` | `48 85 C0` | `test rax, rax` |
| `0x10DA` | `0F 84 62 01 00 00` | `je cleanup` |
| `0x10E0` | `48 C7 44 24 60 00 00 00 00` | `mov qword [rsp+0x60], 0` |
| `0x10E9` | `48 8D 54 24 60` | `lea rdx, [rsp+0x60]` |
| `0x10EE` | `FF D0` | `call rax` |
| `0x10F0` | `48 85 C0` | `test rax, rax` |
| `0x10F3` | `0F 85 49 01 00 00` | `jne cleanup` |
| `0x10F9` | `48 8B 5C 24 60` | `mov rbx, [rsp+0x60]` |
| `0x10FE` | `48 85 DB` | `test rbx, rbx` |
| `0x1101` | `0F 84 3B 01 00 00` | `je cleanup` |
| `0x1107` | `48 8B 43 08` | `mov rax, [rbx+0x08]` |
| `0x110B` | `48 85 C0` | `test rax, rax` |
| `0x110E` | `0F 84 2E 01 00 00` | `je cleanup` |
| `0x1114` | `48 C7 44 24 60 00 00 00 00` | `mov qword [rsp+0x60], 0` |
| `0x111D` | `48 89 D9` | `mov rcx, rbx` |
| `0x1120` | `48 8D 54 24 60` | `lea rdx, [rsp+0x60]` |
| `0x1125` | `4C 8D 05 F4 0E 00 00` | `lea r8, [rip+source_name]` |
| `0x112C` | `41 B9 01 00 00 00` | `mov r9d, 1` |
| `0x1132` | `48 C7 44 24 20 00 00 00 00` | `mov qword [rsp+0x20], 0` |
| `0x113B` | `FF D0` | `call rax` |
| `0x113D` | `48 85 C0` | `test rax, rax` |
| `0x1140` | `0F 85 FC 00 00 00` | `jne cleanup` |
| `0x1146` | `48 8B 74 24 60` | `mov rsi, [rsp+0x60]` |
| `0x114B` | `48 85 F6` | `test rsi, rsi` |
| `0x114E` | `0F 84 EE 00 00 00` | `je cleanup` |
| `0x1154` | `48 C7 44 24 58 00 00 00 00` | `mov qword [rsp+0x58], 0` |
| `0x115D` | `4C 8B 54 24 58` | `mov r10, [rsp+0x58]` |
| `0x1162` | `49 83 FA 0D` | `cmp r10, 13` |
| `0x1166` | `0F 83 CC 00 00 00` | `jae set_e200` |
| `0x116C` | `48 C7 44 24 40 01 00 00 00` | `mov qword [rsp+0x40], 1` |
| `0x1175` | `48 89 F1` | `mov rcx, rsi` |
| `0x1178` | `48 8D 54 24 40` | `lea rdx, [rsp+0x40]` |
| `0x117D` | `4E 8D 44 14 48` | `lea r8, [rsp+r10+0x48]` |
| `0x1182` | `48 8B 46 20` | `mov rax, [rsi+0x20]` |
| `0x1186` | `48 85 C0` | `test rax, rax` |
| `0x1189` | `0F 84 95 00 00 00` | `je set_e002` |
| `0x118F` | `FF D0` | `call rax` |
| `0x1191` | `48 85 C0` | `test rax, rax` |
| `0x1194` | `0F 85 8A 00 00 00` | `jne set_e002` |
| `0x119A` | `48 83 7C 24 40 00` | `cmp qword [rsp+0x40], 0` |
| `0x11A0` | `0F 84 88 00 00 00` | `je set_e100` |
| `0x11A6` | `48 83 7C 24 40 01` | `cmp qword [rsp+0x40], 1` |
| `0x11AC` | `0F 85 72 00 00 00` | `jne set_e002` |
| `0x11B2` | `4C 8B 54 24 58` | `mov r10, [rsp+0x58]` |
| `0x11B7` | `49 83 FA 0B` | `cmp r10, 11` |
| `0x11BB` | `0F 82 34 00 00 00` | `jb check_prefix` |
| `0x11C1` | `0F 84 13 00 00 00` | `je check_first_eol` |
| `0x11C7` | `42 0F B6 44 14 48` | `movzx eax, byte [rsp+r10+0x48]` |
| `0x11CD` | `3C 0A` | `cmp al, 0x0a` |
| `0x11CF` | `0F 85 63 00 00 00` | `jne set_e200` |
| `0x11D5` | `E9 43 00 00 00` | `jmp valid` |
| `0x11DA` | `42 0F B6 44 14 48` | `movzx eax, byte [rsp+r10+0x48]` |
| `0x11E0` | `3C 0A` | `cmp al, 0x0a` |
| `0x11E2` | `0F 84 35 00 00 00` | `je valid` |
| `0x11E8` | `3C 0D` | `cmp al, 0x0d` |
| `0x11EA` | `0F 85 48 00 00 00` | `jne set_e200` |
| `0x11F0` | `E9 1A 00 00 00` | `jmp advance` |
| `0x11F5` | `4C 8D 1D 44 0E 00 00` | `lea r11, [rip+format_ascii]` |
| `0x11FC` | `43 0F B6 04 13` | `movzx eax, byte [r11+r10]` |
| `0x1201` | `42 0F B6 54 14 48` | `movzx edx, byte [rsp+r10+0x48]` |
| `0x1207` | `39 C2` | `cmp edx, eax` |
| `0x1209` | `0F 85 29 00 00 00` | `jne set_e200` |
| `0x120F` | `49 83 C2 01` | `add r10, 1` |
| `0x1213` | `4C 89 54 24 58` | `mov [rsp+0x58], r10` |
| `0x1218` | `E9 40 FF FF FF` | `jmp read_loop` |
| `0x121D` | `31 FF` | `xor edi, edi` |
| `0x121F` | `E9 1E 00 00 00` | `jmp cleanup` |
| `0x1224` | `BF 02 00 00 00` | `mov edi, 2` |
| `0x1229` | `E9 14 00 00 00` | `jmp cleanup` |
| `0x122E` | `BF 03 00 00 00` | `mov edi, 3` |
| `0x1233` | `E9 0A 00 00 00` | `jmp cleanup` |
| `0x1238` | `BF 04 00 00 00` | `mov edi, 4` |
| `0x123D` | `E9 00 00 00 00` | `jmp cleanup` |
| `0x1242` | `48 85 F6` | `test rsi, rsi` |
| `0x1245` | `0F 84 3E 00 00 00` | `je close_root` |
| `0x124B` | `48 8B 46 10` | `mov rax, [rsi+0x10]` |
| `0x124F` | `48 85 C0` | `test rax, rax` |
| `0x1252` | `0F 84 22 00 00 00` | `je file_close_bad` |
| `0x1258` | `48 89 F1` | `mov rcx, rsi` |
| `0x125B` | `FF D0` | `call rax` |
| `0x125D` | `31 F6` | `xor esi, esi` |
| `0x125F` | `48 85 C0` | `test rax, rax` |
| `0x1262` | `0F 84 21 00 00 00` | `je close_root` |
| `0x1268` | `85 FF` | `test edi, edi` |
| `0x126A` | `0F 85 19 00 00 00` | `jne close_root` |
| `0x1270` | `BF 02 00 00 00` | `mov edi, 2` |
| `0x1275` | `E9 0F 00 00 00` | `jmp close_root` |
| `0x127A` | `31 F6` | `xor esi, esi` |
| `0x127C` | `85 FF` | `test edi, edi` |
| `0x127E` | `0F 85 05 00 00 00` | `jne close_root` |
| `0x1284` | `BF 02 00 00 00` | `mov edi, 2` |
| `0x1289` | `48 85 DB` | `test rbx, rbx` |
| `0x128C` | `0F 84 3E 00 00 00` | `je report` |
| `0x1292` | `48 8B 43 10` | `mov rax, [rbx+0x10]` |
| `0x1296` | `48 85 C0` | `test rax, rax` |
| `0x1299` | `0F 84 22 00 00 00` | `je root_close_bad` |
| `0x129F` | `48 89 D9` | `mov rcx, rbx` |
| `0x12A2` | `FF D0` | `call rax` |
| `0x12A4` | `31 DB` | `xor ebx, ebx` |
| `0x12A6` | `48 85 C0` | `test rax, rax` |
| `0x12A9` | `0F 84 21 00 00 00` | `je report` |
| `0x12AF` | `85 FF` | `test edi, edi` |
| `0x12B1` | `0F 85 19 00 00 00` | `jne report` |
| `0x12B7` | `BF 02 00 00 00` | `mov edi, 2` |
| `0x12BC` | `E9 0F 00 00 00` | `jmp report` |
| `0x12C1` | `31 DB` | `xor ebx, ebx` |
| `0x12C3` | `85 FF` | `test edi, edi` |
| `0x12C5` | `0F 85 05 00 00 00` | `jne report` |
| `0x12CB` | `BF 02 00 00 00` | `mov edi, 2` |
| `0x12D0` | `85 FF` | `test edi, edi` |
| `0x12D2` | `0F 85 0C 00 00 00` | `jne select_error` |
| `0x12D8` | `48 8D 15 71 0D 00 00` | `lea rdx, [rip+success_message]` |
| `0x12DF` | `E9 46 00 00 00` | `jmp do_print` |
| `0x12E4` | `83 FF 01` | `cmp edi, 1` |
| `0x12E7` | `0F 84 1E 00 00 00` | `je use_e001` |
| `0x12ED` | `83 FF 02` | `cmp edi, 2` |
| `0x12F0` | `0F 84 21 00 00 00` | `je use_e002` |
| `0x12F6` | `83 FF 03` | `cmp edi, 3` |
| `0x12F9` | `0F 84 24 00 00 00` | `je use_e100` |
| `0x12FF` | `48 8D 15 52 0E 00 00` | `lea rdx, [rip+diagnostic_e200]` |
| `0x1306` | `E9 1F 00 00 00` | `jmp do_print` |
| `0x130B` | `48 8D 15 6E 0D 00 00` | `lea rdx, [rip+diagnostic_e001]` |
| `0x1312` | `E9 13 00 00 00` | `jmp do_print` |
| `0x1317` | `48 8D 15 AA 0D 00 00` | `lea rdx, [rip+diagnostic_e002]` |
| `0x131E` | `E9 07 00 00 00` | `jmp do_print` |
| `0x1323` | `48 8D 15 E6 0D 00 00` | `lea rdx, [rip+diagnostic_e100]` |
| `0x132A` | `4D 85 FF` | `test r15, r15` |
| `0x132D` | `0F 84 12 00 00 00` | `je prepare_status` |
| `0x1333` | `49 8B 47 08` | `mov rax, [r15+0x08]` |
| `0x1337` | `48 85 C0` | `test rax, rax` |
| `0x133A` | `0F 84 05 00 00 00` | `je prepare_status` |
| `0x1340` | `4C 89 F9` | `mov rcx, r15` |
| `0x1343` | `FF D0` | `call rax` |
| `0x1345` | `48 BA 01 00 00 00 00 00 00 80` | `mov rdx, 0x8000000000000001` |
| `0x134F` | `85 FF` | `test edi, edi` |
| `0x1351` | `0F 85 02 00 00 00` | `jne status_ready` |
| `0x1357` | `31 D2` | `xor edx, edx` |
| `0x1359` | `4D 85 F6` | `test r14, r14` |
| `0x135C` | `0F 84 20 00 00 00` | `je no_exit` |
| `0x1362` | `49 8B 86 D8 00 00 00` | `mov rax, [r14+0xd8]` |
| `0x1369` | `48 85 C0` | `test rax, rax` |
| `0x136C` | `0F 84 10 00 00 00` | `je no_exit` |
| `0x1372` | `4C 89 E1` | `mov rcx, r12` |
| `0x1375` | `45 31 C0` | `xor r8d, r8d` |
| `0x1378` | `45 31 C9` | `xor r9d, r9d` |
| `0x137B` | `FF D0` | `call rax` |
| `0x137D` | `E9 03 00 00 00` | `jmp epilogue` |
| `0x1382` | `48 89 D0` | `mov rax, rdx` |
| `0x1385` | `48 83 C4 70` | `add rsp, 0x70` |
| `0x1389` | `41 5F` | `pop r15` |
| `0x138B` | `41 5E` | `pop r14` |
| `0x138D` | `41 5D` | `pop r13` |
| `0x138F` | `41 5C` | `pop r12` |
| `0x1391` | `5F` | `pop rdi` |
| `0x1392` | `5E` | `pop rsi` |
| `0x1393` | `5B` | `pop rbx` |
| `0x1394` | `C3` | `ret` |

## 4. Données exactes

### 4.1 `.rdata`

| Offset fichier | RVA | Octets | Rôle |
|---:|---:|---|---|
| `0x0800` | `0x2000` | `A1 31 1B 5B 62 95 D2 11 8E 3F 00 A0 C9 69 72 3B` | GUID LoadedImageProtocol |
| `0x0810` | `0x2010` | `22 5B 4E 96 59 64 D2 11 8E 39 00 A0 C9 69 72 3B` | GUID SimpleFileSystemProtocol |
| `0x0820` | `0x2020` | `5C 00 4E 00 54 00 41 00 53 00 4D 00 31 00 2E 00 4E 00 54 00 41 00 53 00 4D 00 00 00` | `L"\\NTASM1.NTASM"` |
| `0x083C` | `0x203C` | quatre octets `00` | alignement explicite |
| `0x0840` | `0x2040` | `66 6F 72 6D 61 74 20 70 65 36 34` | référence ASCII `format pe64` |
| `0x084B` | `0x204B` | cinq octets `00` | alignement explicite |
| `0x0850` | `0x2050` | `4E 00 47 00 5F 00 42 00 31 00 5F 00 31 00 5F 00 46 00 4F 00 52 00 4D 00 41 00 54 00 5F 00 4F 00 4B 00 0D 00 0A 00 00 00` | succès CHAR16Z |
| `0x0878` | `0x2078` | huit octets `00` | alignement explicite |
| `0x0880` | `0x2080` | `4E 00 47 00 53 00 30 00 20 00 45 00 30 00 30 00 31 00 20 00 4C 00 30 00 30 00 30 00 30 00 20 00 43 00 30 00 30 00 30 00 30 00 20 00 4F 00 30 00 30 00 30 00 30 00 30 00 30 00 30 00 30 00 0D 00 0A 00 00 00` | diagnostic E001 CHAR16Z |
| `0x08C4` | `0x20C4` | quatre octets `00` | alignement explicite |
| `0x08C8` | `0x20C8` | `4E 00 47 00 53 00 30 00 20 00 45 00 30 00 30 00 32 00 20 00 4C 00 30 00 30 00 30 00 30 00 20 00 43 00 30 00 30 00 30 00 30 00 20 00 4F 00 30 00 30 00 30 00 30 00 30 00 30 00 30 00 30 00 0D 00 0A 00 00 00` | diagnostic E002 CHAR16Z |
| `0x090C` | `0x210C` | quatre octets `00` | alignement explicite |
| `0x0910` | `0x2110` | `4E 00 47 00 53 00 30 00 20 00 45 00 31 00 30 00 30 00 20 00 4C 00 30 00 30 00 30 00 30 00 20 00 43 00 30 00 30 00 30 00 30 00 20 00 4F 00 30 00 30 00 30 00 30 00 30 00 30 00 30 00 30 00 0D 00 0A 00 00 00` | diagnostic E100 CHAR16Z |
| `0x0954` | `0x2154` | quatre octets `00` | alignement explicite |
| `0x0958` | `0x2158` | `4E 00 47 00 53 00 30 00 20 00 45 00 32 00 30 00 30 00 20 00 4C 00 30 00 30 00 30 00 31 00 20 00 43 00 30 00 30 00 30 00 31 00 20 00 4F 00 30 00 30 00 30 00 30 00 30 00 30 00 30 00 30 00 0D 00 0A 00 00 00` | diagnostic E200 CHAR16Z |
| `0x099C` | `0x219C` | quatre octets `00` | alignement naturel du qword |
| `0x09A0` | `0x21A0` | `00 10 00 40 01 00 00 00` | ancre absolue `ImageBase + RVA(entry)` |

La taille virtuelle s'arrête à `0x21A8`. `0x09A8..0x09FF` est nul.

### 4.2 `.data`

`0x0A00..0x0A07` (RVA `0x3000..0x3007`) contient huit octets nuls. Cette
réserve non exécutable rend la section canonique B1 non vide sans état global
mutable. `0x0A08..0x0BFF` est nul.

### 4.3 `.reloc`

L'unique bloc à `0x0C00`, RVA `0x4000`, contient exactement :

```text
00 20 00 00  0C 00 00 00  A0 A1 00 00
```

- `PageRVA = 0x2000`;
- `BlockSize = 12`;
- entrée `0xA1A0` = `IMAGE_REL_BASED_DIR64` (type 10) à l'offset `0x1A0` de
  la page, donc RVA corrigée `0x21A0`;
- entrée de remplissage `IMAGE_REL_BASED_ABSOLUTE = 0`.

`0x0C0C..0x0DFF` est nul. La relocation est observable et l'image ne dépend pas
de son chargement à `0x0000000140000000`.

## 5. Discipline ABI et pile

Sept registres non volatils sont empilés. À l'entrée, `RSP mod 16 = 8`; après
56 octets d'empilement puis `sub rsp,0x70`, `RSP mod 16 = 0` avant chaque
`call`. Chaque appel dispose donc du shadow space de 32 octets.

| Offset depuis le `rsp` cadré | Taille | Usage |
|---:|---:|---|
| `0x00..0x1F` | 32 | shadow space |
| `0x20..0x27` | 8 | cinquième argument `Attributes` de `Open` |
| `0x30..0x37` | 8 | sortie `LoadedImage*` |
| `0x38..0x3F` | 8 | sortie `SimpleFS*` |
| `0x40..0x47` | 8 | `BufferSize` de `Read` |
| `0x48..0x54` | 13 | tampon source strictement borné |
| `0x58..0x5F` | 8 | compteur d'octets lus |
| `0x60..0x67` | 8 | sortie temporaire racine/fichier |
| autres | — | inutilisé |

Les non-volatils modifiés (`rbx`, `rsi`, `rdi`, `r12..r15`) sont restaurés sur
tous les retours. `r13` conserve `SystemTable` uniquement pour rendre le contrat
d'entrée explicite. Aucun accès réseau, port I/O, MMIO, allocation, import,
écriture disque ou section W+X n'existe.

### 5.1 Audit des neuf sites d'appel

`RSP` est aligné sur 16 et les 32 octets de shadow space sont disponibles à
chacun de ces sites.

| RVA du `call` | Cible | Arguments vérifiés avant l'appel |
|---:|---|---|
| `0x106F` | `HandleProtocol` | `RCX=ImageHandle`, `RDX=&LoadedImageGuid`, `R8=&slot30` |
| `0x10BA` | `HandleProtocol` | `RCX=DeviceHandle`, `RDX=&SimpleFsGuid`, `R8=&slot38` |
| `0x10EE` | `OpenVolume` | `RCX=SimpleFS`, `RDX=&slot60` |
| `0x113B` | `root->Open` | `RCX=root`, `RDX=&slot60`, `R8=source_name`, `R9=READ`, `[RSP+0x20]=Attributes=0` |
| `0x118F` | `file->Read` | `RCX=file`, `RDX=&BufferSize`, `R8=buffer+n`; demande `1` octet |
| `0x125B` | `file->Close` | `RCX=file` validé |
| `0x12A2` | `root->Close` | `RCX=root` validé |
| `0x1343` | `ConOut->OutputString` | `RCX=ConOut`, `RDX=message CHAR16Z sélectionné` |
| `0x137B` | `BootServices->Exit` | `RCX=ImageHandle`, `RDX=status`, `R8=0`, `R9=0` |

Les out-slots sont initialisés à zéro, mais cette initialisation n'est pas
considérée comme une validation : après `OpenVolume`, le statut est testé à
`0x10F0/0x10F3` et `RBX` n'est chargé qu'à `0x10F9`; après `Open`, le statut est
testé à `0x113D/0x1140` et `RSI` n'est chargé qu'à `0x1146`. Un appel en échec
ne peut donc jamais injecter un pointeur indéfini dans `cleanup`.

### 5.2 Audit des transferts relatifs

Les 60 branches relatives décodées ciblent toutes le premier octet d'une
instruction. Leurs cibles uniques sont : `0x115D`, `0x11DA`, `0x11F5`,
`0x120F`, `0x121D`, `0x1224`, `0x122E`, `0x1238`, `0x1242`, `0x127A`,
`0x1289`, `0x12C1`, `0x12D0`, `0x12E4`, `0x130B`, `0x1317`, `0x1323`,
`0x132A`, `0x1345`, `0x1359`, `0x1382` et `0x1385`.

Les neuf références RIP résolvent exactement vers `0x2000`, `0x2010`,
`0x2020`, `0x2040`, `0x2050`, `0x2080`, `0x20C8`, `0x2110` et `0x2158`.

## 6. Hex dump canonique complet

Ce dump est l'autorité de matérialisation directe. Chaque ligne contient
exactement seize octets; les offsets vont sans trou de `0x0000` à
`0x0DF0`, couvrent exactement `0x0E00` octets, et aucun octet ne doit être
ajouté après la dernière ligne.

```text
0000  4D 5A 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0010  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0030  00 00 00 00 00 00 00 00 00 00 00 00 80 00 00 00
0040  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0050  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0060  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0070  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0080  50 45 00 00 64 86 04 00 00 00 00 00 00 00 00 00
0090  00 00 00 00 F0 00 22 00 0B 02 00 00 00 04 00 00
00a0  00 06 00 00 00 00 00 00 00 10 00 00 00 10 00 00
00b0  00 00 00 40 01 00 00 00 00 10 00 00 00 02 00 00
00c0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00d0  00 50 00 00 00 04 00 00 00 00 00 00 0A 00 40 01
00e0  00 00 10 00 00 00 00 00 00 10 00 00 00 00 00 00
00f0  00 00 10 00 00 00 00 00 00 10 00 00 00 00 00 00
0100  00 00 00 00 10 00 00 00 00 00 00 00 00 00 00 00
0110  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0120  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0130  00 40 00 00 0C 00 00 00 00 00 00 00 00 00 00 00
0140  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0150  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0160  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0170  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0180  00 00 00 00 00 00 00 00 2E 74 65 78 74 00 00 00
0190  95 03 00 00 00 10 00 00 00 04 00 00 00 04 00 00
01a0  00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 60
01b0  2E 72 64 61 74 61 00 00 A8 01 00 00 00 20 00 00
01c0  00 02 00 00 00 08 00 00 00 00 00 00 00 00 00 00
01d0  00 00 00 00 40 00 00 40 2E 64 61 74 61 00 00 00
01e0  08 00 00 00 00 30 00 00 00 02 00 00 00 0A 00 00
01f0  00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 C0
0200  2E 72 65 6C 6F 63 00 00 0C 00 00 00 00 40 00 00
0210  00 02 00 00 00 0C 00 00 00 00 00 00 00 00 00 00
0220  00 00 00 00 40 00 00 42 00 00 00 00 00 00 00 00
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
0400  53 56 57 41 54 41 55 41 56 41 57 48 83 EC 70 49
0410  89 CC 49 89 D5 31 DB 31 F6 45 31 F6 45 31 FF BF
0420  01 00 00 00 48 85 D2 0F 84 15 02 00 00 4C 8B 7A
0430  40 4C 8B 72 60 4D 85 FF 0F 84 04 02 00 00 4D 85
0440  F6 0F 84 FB 01 00 00 49 8B 86 98 00 00 00 48 85
0450  C0 0F 84 EB 01 00 00 48 C7 44 24 30 00 00 00 00
0460  4C 89 E1 48 8D 15 96 0F 00 00 4C 8D 44 24 30 FF
0470  D0 48 85 C0 0F 85 C8 01 00 00 48 8B 44 24 30 48
0480  85 C0 0F 84 BA 01 00 00 48 8B 48 18 48 85 C9 0F
0490  84 AD 01 00 00 48 C7 44 24 38 00 00 00 00 49 8B
04a0  86 98 00 00 00 48 85 C0 0F 84 94 01 00 00 48 8D
04b0  15 5B 0F 00 00 4C 8D 44 24 38 FF D0 48 85 C0 0F
04c0  85 7D 01 00 00 48 8B 4C 24 38 48 85 C9 0F 84 6F
04d0  01 00 00 48 8B 41 08 48 85 C0 0F 84 62 01 00 00
04e0  48 C7 44 24 60 00 00 00 00 48 8D 54 24 60 FF D0
04f0  48 85 C0 0F 85 49 01 00 00 48 8B 5C 24 60 48 85
0500  DB 0F 84 3B 01 00 00 48 8B 43 08 48 85 C0 0F 84
0510  2E 01 00 00 48 C7 44 24 60 00 00 00 00 48 89 D9
0520  48 8D 54 24 60 4C 8D 05 F4 0E 00 00 41 B9 01 00
0530  00 00 48 C7 44 24 20 00 00 00 00 FF D0 48 85 C0
0540  0F 85 FC 00 00 00 48 8B 74 24 60 48 85 F6 0F 84
0550  EE 00 00 00 48 C7 44 24 58 00 00 00 00 4C 8B 54
0560  24 58 49 83 FA 0D 0F 83 CC 00 00 00 48 C7 44 24
0570  40 01 00 00 00 48 89 F1 48 8D 54 24 40 4E 8D 44
0580  14 48 48 8B 46 20 48 85 C0 0F 84 95 00 00 00 FF
0590  D0 48 85 C0 0F 85 8A 00 00 00 48 83 7C 24 40 00
05a0  0F 84 88 00 00 00 48 83 7C 24 40 01 0F 85 72 00
05b0  00 00 4C 8B 54 24 58 49 83 FA 0B 0F 82 34 00 00
05c0  00 0F 84 13 00 00 00 42 0F B6 44 14 48 3C 0A 0F
05d0  85 63 00 00 00 E9 43 00 00 00 42 0F B6 44 14 48
05e0  3C 0A 0F 84 35 00 00 00 3C 0D 0F 85 48 00 00 00
05f0  E9 1A 00 00 00 4C 8D 1D 44 0E 00 00 43 0F B6 04
0600  13 42 0F B6 54 14 48 39 C2 0F 85 29 00 00 00 49
0610  83 C2 01 4C 89 54 24 58 E9 40 FF FF FF 31 FF E9
0620  1E 00 00 00 BF 02 00 00 00 E9 14 00 00 00 BF 03
0630  00 00 00 E9 0A 00 00 00 BF 04 00 00 00 E9 00 00
0640  00 00 48 85 F6 0F 84 3E 00 00 00 48 8B 46 10 48
0650  85 C0 0F 84 22 00 00 00 48 89 F1 FF D0 31 F6 48
0660  85 C0 0F 84 21 00 00 00 85 FF 0F 85 19 00 00 00
0670  BF 02 00 00 00 E9 0F 00 00 00 31 F6 85 FF 0F 85
0680  05 00 00 00 BF 02 00 00 00 48 85 DB 0F 84 3E 00
0690  00 00 48 8B 43 10 48 85 C0 0F 84 22 00 00 00 48
06a0  89 D9 FF D0 31 DB 48 85 C0 0F 84 21 00 00 00 85
06b0  FF 0F 85 19 00 00 00 BF 02 00 00 00 E9 0F 00 00
06c0  00 31 DB 85 FF 0F 85 05 00 00 00 BF 02 00 00 00
06d0  85 FF 0F 85 0C 00 00 00 48 8D 15 71 0D 00 00 E9
06e0  46 00 00 00 83 FF 01 0F 84 1E 00 00 00 83 FF 02
06f0  0F 84 21 00 00 00 83 FF 03 0F 84 24 00 00 00 48
0700  8D 15 52 0E 00 00 E9 1F 00 00 00 48 8D 15 6E 0D
0710  00 00 E9 13 00 00 00 48 8D 15 AA 0D 00 00 E9 07
0720  00 00 00 48 8D 15 E6 0D 00 00 4D 85 FF 0F 84 12
0730  00 00 00 49 8B 47 08 48 85 C0 0F 84 05 00 00 00
0740  4C 89 F9 FF D0 48 BA 01 00 00 00 00 00 00 80 85
0750  FF 0F 85 02 00 00 00 31 D2 4D 85 F6 0F 84 20 00
0760  00 00 49 8B 86 D8 00 00 00 48 85 C0 0F 84 10 00
0770  00 00 4C 89 E1 45 31 C0 45 31 C9 FF D0 E9 03 00
0780  00 00 48 89 D0 48 83 C4 70 41 5F 41 5E 41 5D 41
0790  5C 5F 5E 5B C3 00 00 00 00 00 00 00 00 00 00 00
07a0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
07b0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
07c0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
07d0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
07e0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
07f0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0800  A1 31 1B 5B 62 95 D2 11 8E 3F 00 A0 C9 69 72 3B
0810  22 5B 4E 96 59 64 D2 11 8E 39 00 A0 C9 69 72 3B
0820  5C 00 4E 00 54 00 41 00 53 00 4D 00 31 00 2E 00
0830  4E 00 54 00 41 00 53 00 4D 00 00 00 00 00 00 00
0840  66 6F 72 6D 61 74 20 70 65 36 34 00 00 00 00 00
0850  4E 00 47 00 5F 00 42 00 31 00 5F 00 31 00 5F 00
0860  46 00 4F 00 52 00 4D 00 41 00 54 00 5F 00 4F 00
0870  4B 00 0D 00 0A 00 00 00 00 00 00 00 00 00 00 00
0880  4E 00 47 00 53 00 30 00 20 00 45 00 30 00 30 00
0890  31 00 20 00 4C 00 30 00 30 00 30 00 30 00 20 00
08a0  43 00 30 00 30 00 30 00 30 00 20 00 4F 00 30 00
08b0  30 00 30 00 30 00 30 00 30 00 30 00 30 00 0D 00
08c0  0A 00 00 00 00 00 00 00 4E 00 47 00 53 00 30 00
08d0  20 00 45 00 30 00 30 00 32 00 20 00 4C 00 30 00
08e0  30 00 30 00 30 00 20 00 43 00 30 00 30 00 30 00
08f0  30 00 20 00 4F 00 30 00 30 00 30 00 30 00 30 00
0900  30 00 30 00 30 00 0D 00 0A 00 00 00 00 00 00 00
0910  4E 00 47 00 53 00 30 00 20 00 45 00 31 00 30 00
0920  30 00 20 00 4C 00 30 00 30 00 30 00 30 00 20 00
0930  43 00 30 00 30 00 30 00 30 00 20 00 4F 00 30 00
0940  30 00 30 00 30 00 30 00 30 00 30 00 30 00 0D 00
0950  0A 00 00 00 00 00 00 00 4E 00 47 00 53 00 30 00
0960  20 00 45 00 32 00 30 00 30 00 20 00 4C 00 30 00
0970  30 00 30 00 31 00 20 00 43 00 30 00 30 00 30 00
0980  31 00 20 00 4F 00 30 00 30 00 30 00 30 00 30 00
0990  30 00 30 00 30 00 0D 00 0A 00 00 00 00 00 00 00
09a0  00 10 00 40 01 00 00 00 00 00 00 00 00 00 00 00
09b0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
09c0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
09d0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
09e0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
09f0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0a00  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0a10  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0a20  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0a30  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0a40  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0a50  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0a60  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0a70  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0a80  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0a90  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0aa0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0ab0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0ac0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0ad0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0ae0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0af0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0b00  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0b10  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0b20  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0b30  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0b40  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0b50  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0b60  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0b70  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0b80  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0b90  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0ba0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0bb0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0bc0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0bd0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0be0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0bf0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0c00  00 20 00 00 0C 00 00 00 A0 A1 00 00 00 00 00 00
0c10  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0c20  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0c30  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0c40  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0c50  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0c60  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0c70  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0c80  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0c90  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0ca0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0cb0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0cc0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0cd0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0ce0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0cf0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0d00  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0d10  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0d20  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0d30  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0d40  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0d50  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0d60  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0d70  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0d80  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0d90  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0da0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0db0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0dc0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0dd0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0de0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0df0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
```

## 7. Vérifications avant toute matérialisation

- recalculer chaque `rel32` et chaque déplacement RIP depuis l'octet suivant;
- confirmer la continuité `0x1000..0x1394` et `VirtualSize(.text)=0x395`;
- matérialiser exclusivement les octets de ce mapping, puis exiger une taille
  exacte de `0x0E00` avant écriture définitive;
- après matérialisation, exiger le SHA-256
  `dd69708d4ebb8a93659058e1c06d916e5c4d40a1e97b70e4b075bf3103d87fbe`;
- inspecter en lecture seule : PE32+ x86_64, entry `0x1000`, quatre sections,
  `.text` RX, `.rdata` R, `.data` RW, `.reloc` R/discardable, imports nuls,
  relocation `DIR64` à `0x21A0`, absence d'overlay et de W+X;
- exercer `E001` avec source/protocole/ouverture indisponible, `E002` avec erreur
  de lecture et de fermeture injectée, `E100` avec EOF avant EOL, `E200` avec
  premier octet/prefixe/EOL incorrect, puis les succès LF et CRLF;
- vérifier dans chaque cas la fermeture des handles validés, un marqueur unique,
  le retour vers le firmware et l'absence systématique de `\NTASM1.EFI`.

## 8. Résultat historique partiel

- candidat : `bootstrap/seed/b1/seed-b1.1.efi`;
- taille : 3 584 octets;
- SHA-256 : `dd69708d4ebb8a93659058e1c06d916e5c4d40a1e97b70e4b075bf3103d87fbe`;
- binaire identique aux 224 lignes de 16 octets du dump;
- PE32+ x86_64 avec `.text` RX, `.rdata` R, `.data` RW et `.reloc` R/discardable, sans import ni W+X;
- relocation `DIR64` observée à la RVA `0x21A0`;
- RED observé avant implémentation pour LF, CRLF, source absente, mauvais format et EOL absent;
- LF et CRLF donnent exactement `NG_B1_1_FORMAT_OK`;
- source absente donne E001, mauvais format E200 et EOL absent E100;
- aucun cas ne crée `NTASM1.EFI`; tous rendent la main à OVMF;
- preuve historique : `out/b1/step-1/20260902-143103-ff427edcd3324f31b456bd42d75443fa/green-matrix-canonical/manifest.md`;
- réserve : E002 n'avait pas de RED chronologiquement antérieur, donc ce candidat est rejeté comme livraison TDD finale.

La révision r1 et son manifeste ultérieur sont les seules autorités actives. La Gate B1 complète reste rouge.
