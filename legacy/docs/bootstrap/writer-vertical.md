# Verticale source → PE → execution UEFI

Entree preparee : legacy/ntasm-s0/hello.ntasm. Aucun PE de sortie de
notre assembleur n'existe encore; le source est le prochain oracle end-to-end.
Une validation syntaxique NG_S0_T12_OK ne prouve pas cette verticale.

## Golden fixe avant writer

Texte : 47 octets, entry RVA 0x1000. Les 11 instructions doivent etre :

```text
53
48 81 EC 20 00 00 00
48 89 D3
48 8B 4B 40
48 8B 41 08
48 8D 15 EE 0F 00 00
FF D0
48 81 C4 20 00 00 00
5B
48 B8 00 00 00 00 00 00 00 00
C3
```

Rdata : 50 octets. A RVA 0x2000, le qword ancre vaut 0x0000000140001000.
Le message a RVA 0x2008 contient NG_NTASM_OUTPUT_OK puis CR, LF, NUL en
UTF16LE. Data : 8 octets nuls a RVA 0x3000. Reloc : 12 octets a RVA 0x4000 :

```text
00 20 00 00 0C 00 00 00 00 A0 00 00
```

Selon spec/formats/seed-pe32.md, chaque raw size vaut 0x200; raw pointers
0x400, 0x600, 0x800, 0xA00; fichier 0xC00 (3072 octets), SizeOfImage 0x5000.
Headers de 0x400, timestamp/checksum zero, quatre sections et aucun overlay.

## Gate de production

1. Assembler cette source avec le producteur, pas avec NASM directement.
2. Exiger un vrai NTASM1.EFI de 3072 octets conforme au golden et aux headers.
3. Le lancer sous une nouvelle instance QEMU/OVMF; observer exactement
   NG_NTASM_OUTPUT_OK, retour firmware et exit propre du banc.
4. Reconstruire et comparer byte par byte. Refuser un fichier de sortie
   preexistant sans modification de son contenu (E700).
5. Tester les erreurs Write/Flush/Close et les canaris avant livraison.

Ne pas coder la sortie de hello en dur : une seconde source, des tailles et
relocations differentes doivent passer par les memes deux passes et le writer.
