# NTASM lexer Nova bootstrap contract

`compiler/nova/frontend/lexer.nova` is the first production NTASM component ported to Nova. It performs no file, network, clock or diagnostic callback I/O. The caller supplies a byte buffer and one-based source index.

API:

- `lex(source:buf<u8>, source_index:u64) -> Result`
- `token_at(result:Result, index:u64) -> Token`
- `release(result:Result) -> u64`

`Token` contains `kind`, `value`, `source`, `line`, `column`, `start`, `end`, `text_start`, and `text_length`. Offsets are zero-based byte offsets; line and column are one-based. Kinds 0..255 are ASCII bytes. Named kinds are EOF256, NAME257, INT258, STRING259, NL260, ARROW261, EQ262, NE263, LE264, GE265, SHL266, SHR267.

`Result.token_words` stores nine u64 words per token. This flat representation is deliberate: Nova Bootstrap records are runtime handles, so `buf<Token>` would allocate a handle per token and violate the compiler-scale bound. `token_at` reconstructs a structured Token when needed. Frequent consumers should read the flat words directly or release reconstructed records through their owning runtime context.

On success, `count` includes one EOF token. On lexical or limit failure, `count` is zero and `token_words` is empty; no partial stream is usable. Diagnostic code is 100 for lexical errors and 201 for limits. Stable reasons 1..13 distinguish isolated CR, missing hex digits, bad underscore, u64 overflow, suffix, invalid string byte, bad hex escape, unknown escape, unterminated string, invalid source byte, source limit, token limit, and allocation/runtime failure.

Limits proven exact and first-excess:

- source bytes: 4,194,304;
- stored tokens including EOF: 262,143.

The large token proof uses the memory-green Nova runtime with 64 MiB per allocation. The lexer allocates one exact flat token buffer after a deterministic validation/count pass.

Parity evidence compares all token fields and exact diagnostic spans against an independent C transcription of `frontend.c` over owned fixtures, a real #GP NTASM module, every lexical error family, 128 deterministic fuzz inputs, and exact/+1 limits. The historical C behavior that accepts an escaped NUL through `strchr` before a later invalid string byte is preserved for byte-for-byte diagnostic parity.

## The type closer is a bare `>`, and `>=` folding is a frozen limitation

A generic type closes on a `>` token (62) or a `>>` token (267, split by
`parser.nova` `type_close`). It does **not** close on `>=`, because the lexer
folds `>=` into the single GE token 265 at `lexer.nova:201-202`. So
`data t:array<u8,4>="AB"` is not an alternative spelling of
`data t:array<u8,4> ="AB"`: the first cannot close the type, the second can.
The space is load-bearing.

This is an expressiveness limitation of the frozen lexer, not a defect in
`lexer.nova`. The C reference lexer folds `>=` at exactly the same place
(`frontend.c:441-443`) and its `expect_type_close` (`frontend.c:632-643`)
accepts only `>` and `TK_SHR`, so both frontends refuse the same spellings at
the same line and column. `tests_ntasm_parser.c` `type_closer_case` pins this
by asserting the Nova verdict, the C verdict and the column together: a
"fix" teaching the Nova parser to accept `>=` turns that gate red by
diverging from the oracle.

## Newlines carry no meaning

The lexer emits NL260 for a newline and both frontends treat it as ordinary
whitespace (`nova.c:232-240`, `frontend.c:323-325`); nothing downstream reads
it. A `fn` signature reflowed across lines parses to an identical tree, so
signature length and line shape are not a boundary at any length.
`tests_ntasm_parser.c` `signature_reflow_case` pins that, and `fixture_parses`
drives every owned positive fixture through the parser rather than only
through this parity comparison.
