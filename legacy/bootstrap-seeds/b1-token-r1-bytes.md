# B1.1-r1 — ledger du premier token NTASM-S0

Statut : **matérialisé et validé B1.1-r1** le 2 septembre 2026. Cette révision ne
modifie et ne normalise ni `b1-token-bytes.md` ni son candidat
`seed-b1.1.efi`. Son binaire canonique `seed-b1.1-r1.efi` a été matérialisé exclusivement depuis le dump canonique complet de ce document.

SHA-256 attendu : `86d43044d32f000a89b1d66ccd134c7ba9308d59f434d70988ea6a8ef1d816b7`.

## 1. Chronologie TDD déjà rouge

Tous les comportements visés existaient en RED avant cette conception r1 :

- LF : `out/b1/step-1/20260902-141024-f51ec36e46fc47c7a6223cee268792c7/red/`;
- format invalide : `out/b1/step-1/20260902-141526-5872b7c8e5724304831fc4451ff65889/red-invalid-canonical/`;
- CRLF, source absente et EOL absent :
  `out/b1/step-1/20260902-142215-5614c23f0be944fa8144c74fa1118b62/red-matrix/`;
- erreur de lecture E002 avec `NTASM1.NTASM` réellement créé comme répertoire :
  `out/b1/step-1/20260902-144433-2ac1b5997c554d65a6f69436d7c8fe27/red-e002-directory/`.

Le dernier résultat conserve `b0-marker=1`, `e002=0`,
`input-is-directory=True`, `output-exists=False` et `qemu-exit=0`. Il
prouve que le nouveau comportement E002 n'était pas encore fourni par la racine
B0; il ne valide aucun octet r1.

## 2. Contrat comportemental r1

B1.1-r1 obtient le volume de sa propre image par
`LoadedImageProtocol -> DeviceHandle -> SimpleFileSystem -> OpenVolume`, puis
ouvre `\NTASM1.NTASM` en lecture seule. Il n'ouvre jamais
`\NTASM1.EFI`.

Après ouverture, il effectue exactement **un** appel
`EFI_FILE_PROTOCOL.Read(file, &size, buffer)` avec `size=13` et un tampon de
13 octets. Aucun appel `Read` n'existe dans la boucle de comparaison mémoire.

L'état interne dans `EDI` est `0=succès`, `1=E001`, `2=E002`,
`3=E100`, `4=E200` :

- erreur de protocole, volume, ouverture ou source absente : E001;
- statut non nul de `Read`, pointeur `Read` nul, ou compte rendu supérieur à
  13 : E002;
- préfixe disponible mais EOF avant ses onze octets, taille exactement 11 après
  préfixe exact, ou `CR` sans treizième octet : E100;
- premier octet disponible incompatible avec `format pe64`, suffixe avant EOL,
  EOL autre que LF/CRLF : E200;
- préfixe exact puis `LF` à l'octet 11 : succès, même si l'octet 12 a aussi été
  lu;
- préfixe exact puis `CR LF` aux octets 11 et 12 avec taille 13 : succès.

Le fichier puis la racine sont fermés avant l'affichage. Une erreur de fermeture
devient E002 seulement si aucune erreur antérieure n'a déjà gagné. Le succès
affiche `NG_B1_1_FORMAT_OK\r\n`; les erreurs affichent respectivement :

```text
NGS0 E001 L0000 C0000 O00000000\r\n
NGS0 E002 L0000 C0000 O00000000\r\n
NGS0 E100 L0000 C0000 O00000000\r\n
NGS0 E200 L0001 C0001 O00000000\r\n
```

Après affichage, `BootServices.Exit(ImageHandle,status,0,NULL)` est appelé.
S'il rend la main, son propre statut est retourné après restauration complète de
l'ABI. Si la console est indisponible, aucun déréférencement nul n'est tenté.

## 3. Layout PE32+ canonique

Tous les entiers multioctets sont little-endian. Tout champ non explicitement
utile vaut zéro.

| Zone | Offset fichier | RVA | Taille utile | Taille brute |
|---|---:|---:|---:|---:|
| En-têtes | `0x0000` | — | `0x0228` | `0x0400` |
| `.text` RX | `0x0400` | `0x1000` | `0x0377` | `0x0400` |
| `.rdata` R | `0x0800` | `0x2000` | `0x01A8` | `0x0200` |
| `.data` RW | `0x0A00` | `0x3000` | `0x0008` | `0x0200` |
| `.reloc` R/discardable | `0x0C00` | `0x4000` | `0x000C` | `0x0200` |

Taille fichier : `0x0E00` (3 584 octets). `SizeOfImage=0x5000`. Aucun
overlay.

### 3.1 DOS, COFF et Optional Header

| Offset | Taille | Champ | Valeur |
|---:|---:|---|---:|
| `0x0000` | 2 | `e_magic` | `4D 5A` |
| `0x0002` | 58 | autres champs DOS | `0` |
| `0x003C` | 4 | `e_lfanew` | `0x80` |
| `0x0040` | 64 | réserve DOS | `0` |
| `0x0080` | 4 | signature PE | `50 45 00 00` |
| `0x0084` | 2 | `Machine` | `0x8664` |
| `0x0086` | 2 | `NumberOfSections` | `4` |
| `0x0088` | 12 | timestamp/symboles | `0` |
| `0x0094` | 2 | `SizeOfOptionalHeader` | `0x00F0` |
| `0x0096` | 2 | `Characteristics` | `0x0022` |
| `0x0098` | 2 | PE32+ `Magic` | `0x020B` |
| `0x009A` | 2 | versions linker | `0` |
| `0x009C` | 4 | `SizeOfCode` | `0x0400` |
| `0x00A0` | 4 | `SizeOfInitializedData` | `0x0600` |
| `0x00A4` | 4 | `SizeOfUninitializedData` | `0` |
| `0x00A8` | 4 | `AddressOfEntryPoint` | `0x1000` |
| `0x00AC` | 4 | `BaseOfCode` | `0x1000` |
| `0x00B0` | 8 | `ImageBase` | `0x0000000140000000` |
| `0x00B8` | 4 | `SectionAlignment` | `0x1000` |
| `0x00BC` | 4 | `FileAlignment` | `0x0200` |
| `0x00C0` | 12 | versions OS/image/subsystem | `0` |
| `0x00CC` | 4 | `Win32VersionValue` | `0` |
| `0x00D0` | 4 | `SizeOfImage` | `0x5000` |
| `0x00D4` | 4 | `SizeOfHeaders` | `0x0400` |
| `0x00D8` | 4 | `CheckSum` | `0` |
| `0x00DC` | 2 | `Subsystem` | `10` |
| `0x00DE` | 2 | `DllCharacteristics` | `0x0140` |
| `0x00E0` | 8 | stack reserve | `0x100000` |
| `0x00E8` | 8 | stack commit | `0x1000` |
| `0x00F0` | 8 | heap reserve | `0x100000` |
| `0x00F8` | 8 | heap commit | `0x1000` |
| `0x0100` | 4 | `LoaderFlags` | `0` |
| `0x0104` | 4 | `NumberOfRvaAndSizes` | `16` |

Les répertoires sont nuls sauf l'index 5 à `0x0130` :
`RVA=0x4000, Size=0x000C`. Les 16 data directories occupent
`0x0108..0x0187`.

### 3.2 Table des sections

| Offset | Nom brut | VirtualSize | RVA | RawSize | RawPtr | Characteristics |
|---:|---|---:|---:|---:|---:|---:|
| `0x0188` | `2E 74 65 78 74 00 00 00` | `0x0377` | `0x1000` | `0x0400` | `0x0400` | `0x60000020` |
| `0x01B0` | `2E 72 64 61 74 61 00 00` | `0x01A8` | `0x2000` | `0x0200` | `0x0800` | `0x40000040` |
| `0x01D8` | `2E 64 61 74 61 00 00 00` | `0x0008` | `0x3000` | `0x0200` | `0x0A00` | `0xC0000040` |
| `0x0200` | `2E 72 65 6C 6F 63 00 00` | `0x000C` | `0x4000` | `0x0200` | `0x0C00` | `0x42000040` |

Les autres champs des section headers et `0x0228..0x03FF` sont nuls.

## 4. `.text` — mapping exact

L'offset fichier vaut `0x0400 + (RVA-0x1000)`. Les 204 instructions sont
contiguës de `0x1000` à `0x1376`; `0x1377..0x13FF` est nul.

| RVA | Octets | Instruction |
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
| `0x1027` | `0F 84 F7 01 00 00` | `je cleanup` |
| `0x102D` | `4C 8B 7A 40` | `mov r15, [rdx+0x40]` |
| `0x1031` | `4C 8B 72 60` | `mov r14, [rdx+0x60]` |
| `0x1035` | `4D 85 FF` | `test r15, r15` |
| `0x1038` | `0F 84 E6 01 00 00` | `je cleanup` |
| `0x103E` | `4D 85 F6` | `test r14, r14` |
| `0x1041` | `0F 84 DD 01 00 00` | `je cleanup` |
| `0x1047` | `49 8B 86 98 00 00 00` | `mov rax, [r14+0x98]` |
| `0x104E` | `48 85 C0` | `test rax, rax` |
| `0x1051` | `0F 84 CD 01 00 00` | `je cleanup` |
| `0x1057` | `48 C7 44 24 30 00 00 00 00` | `mov qword [rsp+0x30], 0` |
| `0x1060` | `4C 89 E1` | `mov rcx, r12` |
| `0x1063` | `48 8D 15 96 0F 00 00` | `lea rdx, [rip+loaded_image_guid]` |
| `0x106A` | `4C 8D 44 24 30` | `lea r8, [rsp+0x30]` |
| `0x106F` | `FF D0` | `call rax` |
| `0x1071` | `48 85 C0` | `test rax, rax` |
| `0x1074` | `0F 85 AA 01 00 00` | `jne cleanup` |
| `0x107A` | `48 8B 44 24 30` | `mov rax, [rsp+0x30]` |
| `0x107F` | `48 85 C0` | `test rax, rax` |
| `0x1082` | `0F 84 9C 01 00 00` | `je cleanup` |
| `0x1088` | `48 8B 48 18` | `mov rcx, [rax+0x18]` |
| `0x108C` | `48 85 C9` | `test rcx, rcx` |
| `0x108F` | `0F 84 8F 01 00 00` | `je cleanup` |
| `0x1095` | `48 C7 44 24 38 00 00 00 00` | `mov qword [rsp+0x38], 0` |
| `0x109E` | `49 8B 86 98 00 00 00` | `mov rax, [r14+0x98]` |
| `0x10A5` | `48 85 C0` | `test rax, rax` |
| `0x10A8` | `0F 84 76 01 00 00` | `je cleanup` |
| `0x10AE` | `48 8D 15 5B 0F 00 00` | `lea rdx, [rip+simple_fs_guid]` |
| `0x10B5` | `4C 8D 44 24 38` | `lea r8, [rsp+0x38]` |
| `0x10BA` | `FF D0` | `call rax` |
| `0x10BC` | `48 85 C0` | `test rax, rax` |
| `0x10BF` | `0F 85 5F 01 00 00` | `jne cleanup` |
| `0x10C5` | `48 8B 4C 24 38` | `mov rcx, [rsp+0x38]` |
| `0x10CA` | `48 85 C9` | `test rcx, rcx` |
| `0x10CD` | `0F 84 51 01 00 00` | `je cleanup` |
| `0x10D3` | `48 8B 41 08` | `mov rax, [rcx+0x08]` |
| `0x10D7` | `48 85 C0` | `test rax, rax` |
| `0x10DA` | `0F 84 44 01 00 00` | `je cleanup` |
| `0x10E0` | `48 C7 44 24 60 00 00 00 00` | `mov qword [rsp+0x60], 0` |
| `0x10E9` | `48 8D 54 24 60` | `lea rdx, [rsp+0x60]` |
| `0x10EE` | `FF D0` | `call rax` |
| `0x10F0` | `48 85 C0` | `test rax, rax` |
| `0x10F3` | `0F 85 2B 01 00 00` | `jne cleanup` |
| `0x10F9` | `48 8B 5C 24 60` | `mov rbx, [rsp+0x60]` |
| `0x10FE` | `48 85 DB` | `test rbx, rbx` |
| `0x1101` | `0F 84 1D 01 00 00` | `je cleanup` |
| `0x1107` | `48 8B 43 08` | `mov rax, [rbx+0x08]` |
| `0x110B` | `48 85 C0` | `test rax, rax` |
| `0x110E` | `0F 84 10 01 00 00` | `je cleanup` |
| `0x1114` | `48 C7 44 24 60 00 00 00 00` | `mov qword [rsp+0x60], 0` |
| `0x111D` | `48 89 D9` | `mov rcx, rbx` |
| `0x1120` | `48 8D 54 24 60` | `lea rdx, [rsp+0x60]` |
| `0x1125` | `4C 8D 05 F4 0E 00 00` | `lea r8, [rip+source_name]` |
| `0x112C` | `41 B9 01 00 00 00` | `mov r9d, 1` |
| `0x1132` | `48 C7 44 24 20 00 00 00 00` | `mov qword [rsp+0x20], 0` |
| `0x113B` | `FF D0` | `call rax` |
| `0x113D` | `48 85 C0` | `test rax, rax` |
| `0x1140` | `0F 85 DE 00 00 00` | `jne cleanup` |
| `0x1146` | `48 8B 74 24 60` | `mov rsi, [rsp+0x60]` |
| `0x114B` | `48 85 F6` | `test rsi, rsi` |
| `0x114E` | `0F 84 D0 00 00 00` | `je cleanup` |
| `0x1154` | `48 C7 44 24 40 0D 00 00 00` | `mov qword [rsp+0x40], 13` |
| `0x115D` | `48 89 F1` | `mov rcx, rsi` |
| `0x1160` | `48 8D 54 24 40` | `lea rdx, [rsp+0x40]` |
| `0x1165` | `4C 8D 44 24 48` | `lea r8, [rsp+0x48]` |
| `0x116A` | `48 8B 46 20` | `mov rax, [rsi+0x20]` |
| `0x116E` | `48 85 C0` | `test rax, rax` |
| `0x1171` | `0F 84 8F 00 00 00` | `je set_e002` |
| `0x1177` | `FF D0` | `call rax` |
| `0x1179` | `48 85 C0` | `test rax, rax` |
| `0x117C` | `0F 85 84 00 00 00` | `jne set_e002` |
| `0x1182` | `4C 8B 5C 24 40` | `mov r11, [rsp+0x40]` |
| `0x1187` | `49 83 FB 0D` | `cmp r11, 13` |
| `0x118B` | `0F 87 75 00 00 00` | `ja set_e002` |
| `0x1191` | `45 31 D2` | `xor r10d, r10d` |
| `0x1194` | `49 83 FA 0B` | `cmp r10, 11` |
| `0x1198` | `0F 83 2C 00 00 00` | `jae prefix_done` |
| `0x119E` | `4D 39 DA` | `cmp r10, r11` |
| `0x11A1` | `0F 83 69 00 00 00` | `jae set_e100` |
| `0x11A7` | `48 8D 05 92 0E 00 00` | `lea rax, [rip+format_ascii]` |
| `0x11AE` | `42 0F B6 0C 10` | `movzx ecx, byte [rax+r10]` |
| `0x11B3` | `42 0F B6 54 14 48` | `movzx edx, byte [rsp+r10+0x48]` |
| `0x11B9` | `39 CA` | `cmp edx, ecx` |
| `0x11BB` | `0F 85 59 00 00 00` | `jne set_e200` |
| `0x11C1` | `49 83 C2 01` | `add r10, 1` |
| `0x11C5` | `E9 CA FF FF FF` | `jmp prefix_loop` |
| `0x11CA` | `49 83 FB 0B` | `cmp r11, 11` |
| `0x11CE` | `0F 84 3C 00 00 00` | `je set_e100` |
| `0x11D4` | `80 7C 24 53 0A` | `cmp byte [rsp+0x53], 0x0a` |
| `0x11D9` | `0F 84 20 00 00 00` | `je valid` |
| `0x11DF` | `80 7C 24 53 0D` | `cmp byte [rsp+0x53], 0x0d` |
| `0x11E4` | `0F 85 30 00 00 00` | `jne set_e200` |
| `0x11EA` | `49 83 FB 0D` | `cmp r11, 13` |
| `0x11EE` | `0F 82 1C 00 00 00` | `jb set_e100` |
| `0x11F4` | `80 7C 24 54 0A` | `cmp byte [rsp+0x54], 0x0a` |
| `0x11F9` | `0F 85 1B 00 00 00` | `jne set_e200` |
| `0x11FF` | `31 FF` | `xor edi, edi` |
| `0x1201` | `E9 1E 00 00 00` | `jmp cleanup` |
| `0x1206` | `BF 02 00 00 00` | `mov edi, 2` |
| `0x120B` | `E9 14 00 00 00` | `jmp cleanup` |
| `0x1210` | `BF 03 00 00 00` | `mov edi, 3` |
| `0x1215` | `E9 0A 00 00 00` | `jmp cleanup` |
| `0x121A` | `BF 04 00 00 00` | `mov edi, 4` |
| `0x121F` | `E9 00 00 00 00` | `jmp cleanup` |
| `0x1224` | `48 85 F6` | `test rsi, rsi` |
| `0x1227` | `0F 84 3E 00 00 00` | `je close_root` |
| `0x122D` | `48 8B 46 10` | `mov rax, [rsi+0x10]` |
| `0x1231` | `48 85 C0` | `test rax, rax` |
| `0x1234` | `0F 84 22 00 00 00` | `je file_close_bad` |
| `0x123A` | `48 89 F1` | `mov rcx, rsi` |
| `0x123D` | `FF D0` | `call rax` |
| `0x123F` | `31 F6` | `xor esi, esi` |
| `0x1241` | `48 85 C0` | `test rax, rax` |
| `0x1244` | `0F 84 21 00 00 00` | `je close_root` |
| `0x124A` | `85 FF` | `test edi, edi` |
| `0x124C` | `0F 85 19 00 00 00` | `jne close_root` |
| `0x1252` | `BF 02 00 00 00` | `mov edi, 2` |
| `0x1257` | `E9 0F 00 00 00` | `jmp close_root` |
| `0x125C` | `31 F6` | `xor esi, esi` |
| `0x125E` | `85 FF` | `test edi, edi` |
| `0x1260` | `0F 85 05 00 00 00` | `jne close_root` |
| `0x1266` | `BF 02 00 00 00` | `mov edi, 2` |
| `0x126B` | `48 85 DB` | `test rbx, rbx` |
| `0x126E` | `0F 84 3E 00 00 00` | `je report` |
| `0x1274` | `48 8B 43 10` | `mov rax, [rbx+0x10]` |
| `0x1278` | `48 85 C0` | `test rax, rax` |
| `0x127B` | `0F 84 22 00 00 00` | `je root_close_bad` |
| `0x1281` | `48 89 D9` | `mov rcx, rbx` |
| `0x1284` | `FF D0` | `call rax` |
| `0x1286` | `31 DB` | `xor ebx, ebx` |
| `0x1288` | `48 85 C0` | `test rax, rax` |
| `0x128B` | `0F 84 21 00 00 00` | `je report` |
| `0x1291` | `85 FF` | `test edi, edi` |
| `0x1293` | `0F 85 19 00 00 00` | `jne report` |
| `0x1299` | `BF 02 00 00 00` | `mov edi, 2` |
| `0x129E` | `E9 0F 00 00 00` | `jmp report` |
| `0x12A3` | `31 DB` | `xor ebx, ebx` |
| `0x12A5` | `85 FF` | `test edi, edi` |
| `0x12A7` | `0F 85 05 00 00 00` | `jne report` |
| `0x12AD` | `BF 02 00 00 00` | `mov edi, 2` |
| `0x12B2` | `85 FF` | `test edi, edi` |
| `0x12B4` | `0F 85 0C 00 00 00` | `jne select_error` |
| `0x12BA` | `48 8D 15 8F 0D 00 00` | `lea rdx, [rip+success_message]` |
| `0x12C1` | `E9 46 00 00 00` | `jmp do_print` |
| `0x12C6` | `83 FF 01` | `cmp edi, 1` |
| `0x12C9` | `0F 84 1E 00 00 00` | `je use_e001` |
| `0x12CF` | `83 FF 02` | `cmp edi, 2` |
| `0x12D2` | `0F 84 21 00 00 00` | `je use_e002` |
| `0x12D8` | `83 FF 03` | `cmp edi, 3` |
| `0x12DB` | `0F 84 24 00 00 00` | `je use_e100` |
| `0x12E1` | `48 8D 15 70 0E 00 00` | `lea rdx, [rip+diagnostic_e200]` |
| `0x12E8` | `E9 1F 00 00 00` | `jmp do_print` |
| `0x12ED` | `48 8D 15 8C 0D 00 00` | `lea rdx, [rip+diagnostic_e001]` |
| `0x12F4` | `E9 13 00 00 00` | `jmp do_print` |
| `0x12F9` | `48 8D 15 C8 0D 00 00` | `lea rdx, [rip+diagnostic_e002]` |
| `0x1300` | `E9 07 00 00 00` | `jmp do_print` |
| `0x1305` | `48 8D 15 04 0E 00 00` | `lea rdx, [rip+diagnostic_e100]` |
| `0x130C` | `4D 85 FF` | `test r15, r15` |
| `0x130F` | `0F 84 12 00 00 00` | `je prepare_status` |
| `0x1315` | `49 8B 47 08` | `mov rax, [r15+0x08]` |
| `0x1319` | `48 85 C0` | `test rax, rax` |
| `0x131C` | `0F 84 05 00 00 00` | `je prepare_status` |
| `0x1322` | `4C 89 F9` | `mov rcx, r15` |
| `0x1325` | `FF D0` | `call rax` |
| `0x1327` | `48 BA 01 00 00 00 00 00 00 80` | `mov rdx, 0x8000000000000001` |
| `0x1331` | `85 FF` | `test edi, edi` |
| `0x1333` | `0F 85 02 00 00 00` | `jne status_ready` |
| `0x1339` | `31 D2` | `xor edx, edx` |
| `0x133B` | `4D 85 F6` | `test r14, r14` |
| `0x133E` | `0F 84 20 00 00 00` | `je no_exit` |
| `0x1344` | `49 8B 86 D8 00 00 00` | `mov rax, [r14+0xd8]` |
| `0x134B` | `48 85 C0` | `test rax, rax` |
| `0x134E` | `0F 84 10 00 00 00` | `je no_exit` |
| `0x1354` | `4C 89 E1` | `mov rcx, r12` |
| `0x1357` | `45 31 C0` | `xor r8d, r8d` |
| `0x135A` | `45 31 C9` | `xor r9d, r9d` |
| `0x135D` | `FF D0` | `call rax` |
| `0x135F` | `E9 03 00 00 00` | `jmp epilogue` |
| `0x1364` | `48 89 D0` | `mov rax, rdx` |
| `0x1367` | `48 83 C4 70` | `add rsp, 0x70` |
| `0x136B` | `41 5F` | `pop r15` |
| `0x136D` | `41 5E` | `pop r14` |
| `0x136F` | `41 5D` | `pop r13` |
| `0x1371` | `41 5C` | `pop r12` |
| `0x1373` | `5F` | `pop rdi` |
| `0x1374` | `5E` | `pop rsi` |
| `0x1375` | `5B` | `pop rbx` |
| `0x1376` | `C3` | `ret` |

## 5. Données exactes

### 5.1 `.rdata`

| Offset fichier | RVA | Octets | Rôle |
|---:|---:|---|---|
| `0x0800` | `0x2000` | `A1 31 1B 5B 62 95 D2 11 8E 3F 00 A0 C9 69 72 3B` | LoadedImage GUID |
| `0x0810` | `0x2010` | `22 5B 4E 96 59 64 D2 11 8E 39 00 A0 C9 69 72 3B` | SimpleFS GUID |
| `0x0820` | `0x2020` | `5C 00 4E 00 54 00 41 00 53 00 4D 00 31 00 2E 00 4E 00 54 00 41 00 53 00 4D 00 00 00` | source CHAR16Z |
| `0x083C` | `0x203C` | 4 octets `00` | alignement |
| `0x0840` | `0x2040` | `66 6F 72 6D 61 74 20 70 65 36 34` | `format pe64` ASCII |
| `0x084B` | `0x204B` | 5 octets `00` | alignement |
| `0x0850` | `0x2050` | `4E 00 47 00 5F 00 42 00 31 00 5F 00 31 00 5F 00 46 00 4F 00 52 00 4D 00 41 00 54 00 5F 00 4F 00 4B 00 0D 00 0A 00 00 00` | succès CHAR16Z |
| `0x0878` | `0x2078` | 8 octets `00` | alignement |
| `0x0880` | `0x2080` | `4E 00 47 00 53 00 30 00 20 00 45 00 30 00 30 00 31 00 20 00 4C 00 30 00 30 00 30 00 30 00 20 00 43 00 30 00 30 00 30 00 30 00 20 00 4F 00 30 00 30 00 30 00 30 00 30 00 30 00 30 00 30 00 0D 00 0A 00 00 00` | E001 CHAR16Z |
| `0x08C4` | `0x20C4` | 4 octets `00` | alignement |
| `0x08C8` | `0x20C8` | `4E 00 47 00 53 00 30 00 20 00 45 00 30 00 30 00 32 00 20 00 4C 00 30 00 30 00 30 00 30 00 20 00 43 00 30 00 30 00 30 00 30 00 20 00 4F 00 30 00 30 00 30 00 30 00 30 00 30 00 30 00 30 00 0D 00 0A 00 00 00` | E002 CHAR16Z |
| `0x090C` | `0x210C` | 4 octets `00` | alignement |
| `0x0910` | `0x2110` | `4E 00 47 00 53 00 30 00 20 00 45 00 31 00 30 00 30 00 20 00 4C 00 30 00 30 00 30 00 30 00 20 00 43 00 30 00 30 00 30 00 30 00 20 00 4F 00 30 00 30 00 30 00 30 00 30 00 30 00 30 00 30 00 0D 00 0A 00 00 00` | E100 CHAR16Z |
| `0x0954` | `0x2154` | 4 octets `00` | alignement |
| `0x0958` | `0x2158` | `4E 00 47 00 53 00 30 00 20 00 45 00 32 00 30 00 30 00 20 00 4C 00 30 00 30 00 30 00 31 00 20 00 43 00 30 00 30 00 30 00 31 00 20 00 4F 00 30 00 30 00 30 00 30 00 30 00 30 00 30 00 30 00 0D 00 0A 00 00 00` | E200 CHAR16Z |
| `0x099C` | `0x219C` | 4 octets `00` | alignement qword |
| `0x09A0` | `0x21A0` | `00 10 00 40 01 00 00 00` | `ImageBase+RVA(entry)` |

`0x09A8..0x09FF` est nul.

### 5.2 `.data` et `.reloc`

`0x0A00..0x0A07` contient huit octets nuls et `0x0A08..0x0BFF` est nul.
Le bloc de relocation à `0x0C00` est :

```text
00 20 00 00 0C 00 00 00 A0 A1 00 00
```

Il décrit `PageRVA=0x2000`, `BlockSize=12`, une entrée
`DIR64 0xA1A0` pour le qword RVA `0x21A0`, puis une entrée ABSOLUTE nulle.
`0x0C0C..0x0DFF` est nul.

## 6. ABI, appels et sûreté des handles

Sept non-volatils sont empilés; après 56 octets puis `sub rsp,0x70`, RSP est
aligné 16 avant chaque appel et 32 octets de shadow space sont réservés.

| Zone pile cadrée | Usage |
|---:|---|
| `0x00..0x1F` | shadow space |
| `0x20..0x27` | cinquième argument `Attributes=0` de `Open` |
| `0x30..0x37` | out-slot LoadedImage |
| `0x38..0x3F` | out-slot SimpleFS |
| `0x40..0x47` | `BufferSize=13`, puis compte retourné |
| `0x48..0x54` | tampon borné de 13 octets |
| `0x60..0x67` | out-slot racine/fichier |

| RVA | Appel | Arguments |
|---:|---|---|
| `0x106F` | HandleProtocol | ImageHandle, LoadedImage GUID, slot30 |
| `0x10BA` | HandleProtocol | DeviceHandle, SimpleFS GUID, slot38 |
| `0x10EE` | OpenVolume | SimpleFS, slot60 |
| `0x113B` | Open | root, slot60, source_name, READ, Attributes=0 |
| `0x1177` | Read unique | file, &size, buffer; size demandé 13 |
| `0x123D` | Close fichier | file |
| `0x1284` | Close racine | root |
| `0x1325` | OutputString | ConOut, message |
| `0x135D` | Exit | ImageHandle, status, 0, NULL |

Les out-slots ne sont lus qu'après statut nul. En particulier, `RBX` n'est
chargé qu'après le test `0x10F0/0x10F3`, et `RSI` qu'après
`0x113D/0x1140`. Aucun pointeur indéfini n'atteint `Close`.

Les 58 branches relatives ciblent toutes le début d'une instruction. Leurs
cibles uniques sont `0x1194`, `0x11CA`, `0x11FF`, `0x1206`,
`0x1210`, `0x121A`, `0x1224`, `0x125C`, `0x126B`, `0x12A3`,
`0x12B2`, `0x12C6`, `0x12ED`, `0x12F9`, `0x1305`, `0x130C`,
`0x1327`, `0x133B`, `0x1364`, `0x1367`.

Les neuf références RIP ciblent exactement `0x2000`, `0x2010`, `0x2020`,
`0x2040`, `0x2050`, `0x2080`, `0x20C8`, `0x2110`, `0x2158`.

## 7. Hex dump canonique complet

À insérer après calcul indépendant; il devra contenir exactement 224 lignes de
16 octets, offsets continus `0x0000..0x0DF0`.

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
0190  77 03 00 00 00 10 00 00 00 04 00 00 00 04 00 00
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
0420  01 00 00 00 48 85 D2 0F 84 F7 01 00 00 4C 8B 7A
0430  40 4C 8B 72 60 4D 85 FF 0F 84 E6 01 00 00 4D 85
0440  F6 0F 84 DD 01 00 00 49 8B 86 98 00 00 00 48 85
0450  C0 0F 84 CD 01 00 00 48 C7 44 24 30 00 00 00 00
0460  4C 89 E1 48 8D 15 96 0F 00 00 4C 8D 44 24 30 FF
0470  D0 48 85 C0 0F 85 AA 01 00 00 48 8B 44 24 30 48
0480  85 C0 0F 84 9C 01 00 00 48 8B 48 18 48 85 C9 0F
0490  84 8F 01 00 00 48 C7 44 24 38 00 00 00 00 49 8B
04a0  86 98 00 00 00 48 85 C0 0F 84 76 01 00 00 48 8D
04b0  15 5B 0F 00 00 4C 8D 44 24 38 FF D0 48 85 C0 0F
04c0  85 5F 01 00 00 48 8B 4C 24 38 48 85 C9 0F 84 51
04d0  01 00 00 48 8B 41 08 48 85 C0 0F 84 44 01 00 00
04e0  48 C7 44 24 60 00 00 00 00 48 8D 54 24 60 FF D0
04f0  48 85 C0 0F 85 2B 01 00 00 48 8B 5C 24 60 48 85
0500  DB 0F 84 1D 01 00 00 48 8B 43 08 48 85 C0 0F 84
0510  10 01 00 00 48 C7 44 24 60 00 00 00 00 48 89 D9
0520  48 8D 54 24 60 4C 8D 05 F4 0E 00 00 41 B9 01 00
0530  00 00 48 C7 44 24 20 00 00 00 00 FF D0 48 85 C0
0540  0F 85 DE 00 00 00 48 8B 74 24 60 48 85 F6 0F 84
0550  D0 00 00 00 48 C7 44 24 40 0D 00 00 00 48 89 F1
0560  48 8D 54 24 40 4C 8D 44 24 48 48 8B 46 20 48 85
0570  C0 0F 84 8F 00 00 00 FF D0 48 85 C0 0F 85 84 00
0580  00 00 4C 8B 5C 24 40 49 83 FB 0D 0F 87 75 00 00
0590  00 45 31 D2 49 83 FA 0B 0F 83 2C 00 00 00 4D 39
05a0  DA 0F 83 69 00 00 00 48 8D 05 92 0E 00 00 42 0F
05b0  B6 0C 10 42 0F B6 54 14 48 39 CA 0F 85 59 00 00
05c0  00 49 83 C2 01 E9 CA FF FF FF 49 83 FB 0B 0F 84
05d0  3C 00 00 00 80 7C 24 53 0A 0F 84 20 00 00 00 80
05e0  7C 24 53 0D 0F 85 30 00 00 00 49 83 FB 0D 0F 82
05f0  1C 00 00 00 80 7C 24 54 0A 0F 85 1B 00 00 00 31
0600  FF E9 1E 00 00 00 BF 02 00 00 00 E9 14 00 00 00
0610  BF 03 00 00 00 E9 0A 00 00 00 BF 04 00 00 00 E9
0620  00 00 00 00 48 85 F6 0F 84 3E 00 00 00 48 8B 46
0630  10 48 85 C0 0F 84 22 00 00 00 48 89 F1 FF D0 31
0640  F6 48 85 C0 0F 84 21 00 00 00 85 FF 0F 85 19 00
0650  00 00 BF 02 00 00 00 E9 0F 00 00 00 31 F6 85 FF
0660  0F 85 05 00 00 00 BF 02 00 00 00 48 85 DB 0F 84
0670  3E 00 00 00 48 8B 43 10 48 85 C0 0F 84 22 00 00
0680  00 48 89 D9 FF D0 31 DB 48 85 C0 0F 84 21 00 00
0690  00 85 FF 0F 85 19 00 00 00 BF 02 00 00 00 E9 0F
06a0  00 00 00 31 DB 85 FF 0F 85 05 00 00 00 BF 02 00
06b0  00 00 85 FF 0F 85 0C 00 00 00 48 8D 15 8F 0D 00
06c0  00 E9 46 00 00 00 83 FF 01 0F 84 1E 00 00 00 83
06d0  FF 02 0F 84 21 00 00 00 83 FF 03 0F 84 24 00 00
06e0  00 48 8D 15 70 0E 00 00 E9 1F 00 00 00 48 8D 15
06f0  8C 0D 00 00 E9 13 00 00 00 48 8D 15 C8 0D 00 00
0700  E9 07 00 00 00 48 8D 15 04 0E 00 00 4D 85 FF 0F
0710  84 12 00 00 00 49 8B 47 08 48 85 C0 0F 84 05 00
0720  00 00 4C 89 F9 FF D0 48 BA 01 00 00 00 00 00 00
0730  80 85 FF 0F 85 02 00 00 00 31 D2 4D 85 F6 0F 84
0740  20 00 00 00 49 8B 86 D8 00 00 00 48 85 C0 0F 84
0750  10 00 00 00 4C 89 E1 45 31 C0 45 31 C9 FF D0 E9
0760  03 00 00 00 48 89 D0 48 83 C4 70 41 5F 41 5E 41
0770  5D 41 5C 5F 5E 5B C3 00 00 00 00 00 00 00 00 00
0780  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0790  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
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

## 8. Vérifications obligatoires avant matérialisation

- décoder uniquement les 224 lignes du dump, sans reconstruire les champs;
- exiger taille `0x0E00` et SHA-256
  `86d43044d32f000a89b1d66ccd134c7ba9308d59f434d70988ea6a8ef1d816b7`;
- confirmer identité dump/mapping, PE32+ AMD64, quatre sections, import nul,
  aucune W+X, aucun overlay et relocation DIR64 à `0x21A0`;
- confirmer exactement neuf appels, dont un seul site `Read`, 58 branches
  valides et neuf références RIP valides;
- rejouer les RED antérieurs puis GREEN LF, CRLF, E001, E002, E100 et E200 avec
  magasins OVMF neufs;
- exiger fermeture des handles validés, retour firmware, marqueur unique et
  absence de `\NTASM1.EFI`.

## 9. Résultat vérifié B1.1-r1

- binaire : `bootstrap/seed/b1/seed-b1.1-r1.efi`;
- taille : 3 584 octets;
- SHA-256 : `86d43044d32f000a89b1d66ccd134c7ba9308d59f434d70988ea6a8ef1d816b7`;
- identité exacte avec les 224 lignes de ce dump;
- PE32+ à quatre sections, aucune importation ou W+X, relocation DIR64 à `0x21A0`;
- six RED antérieurs puis six GREEN : LF, CRLF, E001, E002, E100 et E200;
- E002 est exercé par un répertoire `NTASM1.NTASM` non vide;
- aucune exécution ne crée `NTASM1.EFI`;
- preuve canonique : `out/b1/step-1/20260902-145037-be452b87dbe44384bb360d6cdc6b7ded/green-matrix-r1/manifest.md`.

B1.1-r1 est vert; Gate B1 reste rouge.
