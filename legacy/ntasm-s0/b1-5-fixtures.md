# Manifeste byte-exact — fixtures B1.5

| ID | Fichier | Taille | SHA-256 | Oracle |
|---|---|---:|---|---|
| B15-00 | préfixe seul B1.4 | 24 | `0028d9969d3e1551a3f7d0f336dfa11d3c2216d0a0326eeb47c582e235284a24` | T05 |
| B15-01 | `B15-01-zero.ntasm` | 39 | `65e9cfc83ebb323c66bed27ba57b34edfc8969c5847dcc888315f41a1f99ab5d` | T05 |
| B15-02 | `B15-02-u64max.ntasm` | 57 | `286a272665a36c4cfa459008bf940df68f038e90e3eb7bf1ef9a277804ef0b20` | T05 |
| B15-03 | `B15-03-hexmax.ntasm` | 58 | `2b529edb3a1313d31e54d56fcccabac323de1fe537192dee10dedcbc2d5fba68` | T05 |
| B15-04 | `B15-04-multi.ntasm` | 106 | `e13da7a89b2d00461b7d4d4821b0945fa0ccb17f3f91b233d8a4268254882db2` | T05 |
| B15-05 | `B15-05-dec-overflow.ntasm` | 55 | `612f4b19a45cd3d6de9ecee23e43cf07dda7c234658d75974de3b533d6f4850c` | E102 L3 C30 O35 |
| B15-06 | `B15-06-hex-overflow.ntasm` | 54 | `d95b5aa06e1d08440d953dabed2cd024c64670cd33e92c13b8e0d49325b002c1` | E102 L3 C29 O34 |
| B15-07 | `B15-07-leading-zero.ntasm` | 37 | `70b44fd6aad716fd30ce466ffd8fbc30166864e056e980c5043e657ad2bc30d2` | E102 L3 C12 O23 |
| B15-08 | `B15-08-empty-hex.ntasm` | 37 | `816d97e22c115e2e71b33bc8be7ce2904d9e7ee1215cb9920a0d1693d881e6bc` | E102 L3 C13 O24 |
| B15-09 | `B15-09-underscore.ntasm` | 38 | `ac52212e52ce95c1c5206045c973cb270aa1f5c16690a9a7edcd57797ab6a2b0` | E102 L3 C12 O23 |
| B15-10 | `B15-10-suffix.ntasm` | 39 | `95fbf362742e33c9ecf162bd0afcc037d9a2d92fb8c7c9de3e8d9794127bb0d5` | E102 L3 C12 O23 |
| B15-11 | `B15-11-bad-hex.ntasm` | 38 | `e57690921ff4389617e680450110a5b2c1f3780408b80888d88587b792d61727` | E102 L3 C13 O24 |
| B15-12 | `B15-12-extra-token.ntasm` | 38 | `20cd2751a514d5928a3753f325dcc795fe8f8b692b65329974faa9d6860b4cbc` | E201 L3 C13 O24 |
| B15-13 | `B15-13-crlf.ntasm` | 67 | `0b00c7d05e2cb1a532f1a26fd47145d83ae80a748aff001d4a7158a0edf6337e` | T05 |
| B15-14 | `B15-14-missing-value.ntasm` | 34 | `23638540b6732973ba903bcb0bc3e261225116e281e39f796c8c0591e954addd` | E201 L3 C10 O21 |
| B15-15 | `B15-15-minus.ntasm` | 37 | `89b159a939a49b9e63aa6724975c74c79f0010332487ef3b99dd0b6309df2637` | E201 L3 C11 O22 |
| B15-16 | `B15-16-plus.ntasm` | 37 | `34d51b36ab7508a5948674e4a95f939b16977f33c94e523c4e2bf06c2dc3bfc4` | E201 L3 C11 O22 |
| B15-17 | `B15-17-16-tokens.ntasm` | 63 | `66b109601f571615f799fe5a1267e0aa5658912cb186080dada1b212a3c8608f` | E201 L3 C13 O24 |
| B15-18 | `B15-18-17-tokens.ntasm` | 66 | `2fd4cc05c5239d53d390475cecd7bd86df0eab7982483fa3f2c9c6a16ee9926b` | E101 L3 C40 O3F |
| B15-19 | `B15-19-512.ntasm` | 8 618 | `1c02e8da226d660b25ad68efe7e641c896415b55b3f46cf6dfbb94aa343c4318` | T05 |
| B15-20 | `B15-20-513.ntasm` | 8 635 | `6db3369b807f7c1a4104bdaa59b23c685d94920af04e2591b8ffd3eec74724e6` | E500 L515 C7 O21B0 |
| B15-21 | `B15-21-punct-adjacent.ntasm` | 38 | `326bd9ed98b8a343674cbbce163c894aeffb09783f9cc470fd2024835616e4d6` | E201 L3 C12 O23 |

Les codes complets suivent `NGS0 Eddd Lhhhh Chhhh Ohhhhhhhh`. B15-21 verrouille
que la ponctuation est un token même sans whitespace : `1+2` doit échouer sur
`+`, pas être avalé comme un seul run lexical. B15-04 doit
produire trois records constants exacts avant cleanup.
