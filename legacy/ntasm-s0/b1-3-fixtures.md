# Manifeste byte-exact — fixtures B1.3

Statut : les oracles ont été figés avant l'implémentation B1.3 et les campagnes
finales sont GREEN. La campagne RED
indépendante sur B1.2 est sous
`out/b1/step-3/agent-red-20260902-180451-eae138665ad5/`.

Preuve GREEN canonique :
`out/b1/step-3/20260902-185633-f6ba2d902cf048a6a51633dfb7651f77/manifest.md`.

## Frontière

B1.3 reconnaît seulement les deux premières lignes **sémantiques** :

```text
format WS+ pe64
abi WS+ efi_x64
```

SP/TAB périphériques sont ignorés, les lignes vides ou commentaire seul sont
sautées. Aucune chaîne n'est admise dans le préambule B1.3 : le premier `;`
coupe la ligne, tandis qu'un guillemet antérieur reste fautif E200. Après l'ABI valide, le
suffixe reste physiquement scanné mais sémantiquement hors périmètre jusqu'à
B1.4+. Le succès temporaire exact est `NG_S0_T03_OK\r\n`.

## Corpus cœur

| ID | Fichier/recette | Taille | SHA-256 | Oracle exact |
|---|---|---:|---|---|
| B13-00 | `b1-3/valid-exact.ntasm` | 24 | `0028d9969d3e1551a3f7d0f336dfa11d3c2216d0a0326eeb47c582e235284a24` | `NG_S0_T03_OK` |
| B13-01 | `golden/minimal-crlf.ntasm` | 183 | `0673bf592da93bfe785e7fd398bd832c6d746c44edf107efbde048da2cb4efcd` | `NG_S0_T03_OK` |
| B13-02 | `b1-3/comment-after-format.ntasm` | 43 | `2b146f10d43072169419b4661062c0bd476f1580156ccb1fbaa9dd39a920e0b1` | `NG_S0_T03_OK` |
| B13-03 | `b1-3/whitespace-tabs.ntasm` | 30 | `0400e5d2472245fd0916c26f561ba310453589584813e499da12a6fff82a23f7` | `NG_S0_T03_OK` |
| B13-04 | `b1-3/blank-comments.ntasm` | 48 | `0821d78425a3866b61242fea92c246bff21136197c0d9e22c11b1b4b24c53156` | `NG_S0_T03_OK` |
| B13-05 | `b1-3/missing-abi.ntasm` | 12 | `f6b71ed6b75803e8afc95684380526f8646d5e3afa42f0e27434f1b805526770` | `NGS0 E200 L0002 C0001 O0000000C` |
| B13-06 | `b1-3/abi-uppercase.ntasm` | 24 | `a189c8e41caee55fe4fdf3e17ba46506b593ae3a271c86426de292de8a40c6a8` | `NGS0 E200 L0002 C0001 O0000000C` |
| B13-07 | `b1-3/abi-sysv.ntasm` | 21 | `f7eb91db83219663ee146ea5213f8980a635c41d23634a81cf53ae48a85df31f` | `NGS0 E200 L0002 C0005 O00000010` |
| B13-08 | `b1-3/semantic-normalized.ntasm` | 45 | `cebcab289b65dc91de84d665670a5ce48242f18b86744a4d9faa4f8aef8b0b7c` | `NG_S0_T03_OK` |
| B13-09 | `b1-3/quoted-semicolon.ntasm` | 27 | `1ef3408ee9a0e0b994bfcc7800a79a94fe67125a964828ce2171cee9d39b9208` | `NGS0 E200 L0001 C0001 O00000000` |

B13-09 est un contrôle hérité, pas un nouveau RED. Il prouve qu'une apparence
de chaîne ne peut pas transformer le préambule en ligne valide avant le tracer
de chaînes dédié.

Le premier caractère fautif décide E200. Une ABI absente pointe l'EOF virtuel :
prochaine ligne physique, colonne 1, offset `source_len`. Une première ligne
sémantique incorrecte conserve la compatibilité B1.1 : position au premier
octet sémantique de cette ligne.

## Ponts de frontières physiques avec ABI valide

Définitions : `P = "format pe64\n"`, `Q = "abi efi_x64\n"`, `A = 0x41`.

| ID | Recette | Taille | SHA-256 | Oracle |
|---|---|---:|---|---|
| B13-P00 | `P || Q || ((A^255)||LF)^255 || A^230 || LF` | 65 535 | `714e49d35677835977a37f2c8764b2f29e054576f4d77fa111628cef76dc8a4f` | `NG_S0_T03_OK` |
| B13-P01 | `P || Q || A^255 || LF` | 280 | `622f799047e31024a9aa755edcdb0876c23625afc789ff2e8616325d9b36f1be` | `NG_S0_T03_OK` |
| B13-P02 | `P || Q || A^256 || LF` | 281 | `fba0d607f9179806ed6bb614e2efb16685b37b1a3e6506fe2370880ff089bac6` | `NGS0 E101 L0003 C0100 O00000117` |
| B13-P03 | `P || Q || LF^4094` | 4 118 | `d3da88cd92a6e71d8023f6f75a1845b05cbad97e2e84dcd4483ba12634f0d7a4` | `NG_S0_T03_OK` |
| B13-P04 | `P || Q || LF^4095` | 4 119 | `4976e185a26fa83b50a0429323c2caca52e4cee90a021f39246e5bf65a19b9d4` | `NGS0 E500 L1001 C0001 O00001016` |
| B13-P05 | `P || "abi efi_x64\r\n" || TAB || SP || TILDE || LF` | 29 | `15715dc2bc9677122ed1ae6d096d6c714a38b56f93f23fd70dcb0c3d825eba31` | `NG_S0_T03_OK` |

Ces six ponts n'altèrent jamais les fixtures B1.2 historiques. Ils préservent un
chemin de succès B1.3 aux bornes; les erreurs physiques B1.2 restent prioritaires
et byte-stables.

La sentinelle 65 536 et la ligne 255 terminée par CRLF restent couvertes par
B12-03/B12-22 et peuvent être rejouées en variance, sans alourdir le gate cœur.

## Conditions de run

- même binaire hashé pour tout le corpus ;
- ESP et magasin OVMF neufs par cas, `-nic none`, QEMU/OVMF seulement ;
- oracle unique puis retour firmware ;
- journaux QEMU sans faute ;
- `NTASM1.EFI` absent avant et après ;
- anciens marqueurs B1.1/B1.2 et marqueur final absents du candidat B1.3.
