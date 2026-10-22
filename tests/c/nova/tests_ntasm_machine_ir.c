/* tests_ntasm_machine_ir.c -- the Machine IR gate.
 *
 * The Machine IR (compiler/nova/ir/machine_ir.nova) is the second
 * intermediate representation: the level between the NTIR's typed TREE and
 * any target's instructions. Its central claim is that it is
 * TARGET-INDEPENDENT, and this file exists to make that claim falsifiable
 * rather than to confirm it.
 *
 * WHAT IS ASSERTED, AND AGAINST WHAT:
 *
 *  1. TARGET INDEPENDENCE, MEASURED. The same program is lowered twice, for
 *     `x86_64-nexora-none` and for `sparc64-nexora-none`. The two triples are
 *     BOTH EIGHTEEN CHARACTERS, chosen so that every byte offset in the
 *     source -- and therefore every span in the NTIR -- is identical, and the
 *     only thing that changed is the arch name. The two Machine IR images must
 *     then differ in EXACTLY ONE WORD, and that word must be the `aux` of a
 *     `mir_target` record, which is where the module puts a digest of the
 *     triple. One differing word out of several hundred is what separates a
 *     Machine IR from a second copy of the NTIR: it says the level names no
 *     register, selects no encoding, and resolves no block offset, because
 *     there is nothing in it left for a different machine to disagree about.
 *     If a second differing word appears the gate prints WHERE, because a
 *     level that is not target-independent is still worth having -- it is just
 *     a different claim, and the reader is entitled to know which one they
 *     have.
 *
 *  2. THE OPERATOR RECOVERY, PINNED AS FAR AS IT GOES. The NTIR DROPS the
 *     operator of an expression: ntir.nova:63-72 copies the AST kind and the
 *     AST id out of the twelve-word record and nothing else, and the AST's aux
 *     word -- where parser.nova:256 stores the operator token -- is not among
 *     the words NTIR carries. A Machine IR cannot select an opcode without
 *     one, so machine_ir.nova recovers it from the gap its own children leave
 *     between them (binary_op). THIS FILE MEASURES FOUR OPERATORS, NOT THE
 *     WHOLE SET: the three mnemonics `nop`, `mov` and `add`, and the binary
 *     `+`. The binary one is the real measurement, because its expectation is
 *     parser.nova:256's OWN aux word, read back through the entry's oracle
 *     probe, and not a constant typed here. THE VOCABULARY IS FOUR. The
 *     recovery is UNMEASURED BEYOND IT, and a recovery that is right for `+`
 *     and wrong for `shr` is a defect wearing a passing test.
 *
 * THE COUNTS ARE PRINTED, AND THAT IS PART OF THE CLAIM. Both loops end in a
 * `CHECK(matched == N)`, and a `CHECK` on a count reads identically whether
 * the loop examined thirty-two records and matched none of them, or examined
 * none at all. A loop that finds nothing is precisely the failure this gate
 * spent a wave sitting in -- two checks, two silent loops, two zeroes, and a
 * header comment claiming four operators were measured. So each loop prints
 * the number of records it walked before the CHECK runs:
 *
 *     OPERATOR-SCAN mnemonics examined=32 matched=3 expected=3
 *     OPERATOR-SCAN binary    examined=32 matched=1 expected=1
 *
 * `examined` is what makes a zero diagnosable. A mnemonic spelling outside
 * the pinned four is reported on stderr by name and by span rather than
 * skipped, for the same reason: a skipped one is indistinguishable from a
 * loop that is looking in the wrong place.
 *
 * BOTH CHECKS HAVE BEEN BROKEN ON PURPOSE AND SEEN RED. A green check nobody
 * has broken is not yet evidence, and these two sat green-shaped and
 * unexercised through a wave. Perturbing the expected opcode for `mov` drops
 * it out of the match, prints `matched=2`, and fails naming the mnemonic and
 * both opcodes. Widening the derived operator span by one byte makes the gap
 * `[+b]`, and the binary check fails naming the gap it derived. Both were
 * restored and both are green.
 *
 * THE FRAGILITY, STATED PLAINLY. The recovery depends entirely on NTIR spans
 * being source-accurate. Feed it an image whose spans do not point at source
 * and `gap_text` answers 0, `opcode_of` answers 0, and the lowering REFUSES
 * 940 at the expression's own position. It degrades loudly, not silently:
 * nothing decodes garbage, it refuses instead. That is a property of the code
 * and is asserted here so a later change that makes it degrade quietly is a
 * red on the next corpus that happens to contain an operator.
 *
 * The mnemonic cases have no such oracle, and saying so is part of the case:
 * for a mnemonic the SOURCE SPELLING is the only authority in the tree, so the
 * expectation is derived from the spelling the NTIR recorded, and what the
 * case pins is the mapping from that spelling to an opcode, not the spelling.
 * The spelling is read from where machine_ir.nova:1502-1505 reads it -- the
 * byte span of the instruction's FIRST CHILD -- and not from the Machine IR
 * record. An earlier version read it out of the record's `aux2`, which is not
 * where a mnemonic position lives, and the loop matched nothing in silence.
 *
 * ON THE OPCODE NUMBERS, precisely, because the claim here used to be
 * stronger than the code. They ARE typed in this file, and they are tied to
 * the module only by `op_limit`, which bounds them without identifying them.
 * `op_arity` does not close that gap: it answers min*16+max, so it is 0 for
 * every zero-operand opcode, and OP_NOP -- one of the three pinned -- is
 * exactly that. `arity[36]` is 0 on this module and would stay 0 for a
 * correct one, so a check of the form `arity[op] != 0` cannot be used for
 * `nop` and is not used for it. The honest statement is: the mapping from
 * spelling to opcode is measured, the numbers are typed, and `op_limit` says
 * they are inside the module's published range.
 *  3. THE STACK AND FRAME REGISTERS ARE NOT DESTINATIONS, measured against
     the oracle's rule and not against a reading of it. Twenty fixtures, ten
     refused and ten accepted, and the ten accepted ones are the half that
     matters: a rule that scanned OPERANDS instead of writes would have
     refused five valid programs.
 *
 *  4. THE OPERAND FORM OF A BINDING NAME, which is the only operand form
     whose legality depends on the mnemonic, asked of BOTH LEVELS on the same
     source text. `mov <reg>, <name>` is the mixed form: the one operand form
     that reaches a machine instruction through a lowering which evaluates it
     into RAX, parks RAX, RESTORES RAX and then loads the destination. That
     sequence can only implement an assignment, so the form is `mov`-only and
     source-only, and twenty-four fixtures pin exactly where the two levels
     agree. The expectations are the C oracle's OWN verdicts, obtained by
     running `nt_frontend_compile` and `nt_codegen_x64` on the same text this
     pipeline was handed; nothing in the table is a constant typed here.
 *
 *  4b. THE FOOTPRINT THE SCRATCH IS INVISIBLE TO, asked two-sided so that
 *     neither arm can pass alone. This one MEASURES a blindness rather than
 *     closing it, and says so where it is measured.
 *
 *  5. THE FORMAT TAG IS PINNED. The first bytes of every serialization are
 *     machine_ir.nova's `header_text`, and EXPECTED_TAG is written down once
 *     HERE as text and compared with the bytes `serialize` produced. A tag
 *     that moved in machine_ir.nova alone reds this gate on the text. THE
 *     FORM IS THE ONE tests_ntasm_ntir.c uses for `ntir.nova`'s own tag,
 *     because this is the same shape of thing: a `header_text` that
 *     `serialize` writes and nothing else reads.
 *
 *  8. THE ATTRIBUTION ORDER, READ OUT OF THE IMAGE AND CONFRONTED WITH THE
 *     NTIR. The header of this file used to list "the node-for-node
 *     confrontation against the NTIR" under WHAT IS NOT HERE, while
 *     machine_ir.nova's own comment said the gate existed. Those two
 *     documents contradicted each other and the contradiction was the
 *     finding: CASE 8 is the gate, it lives here, and it is the only place
 *     in this file where the two documents are reconciled.
 *
 * WHAT IS NOT HERE, ON PURPOSE, and is the honest list of what this gate does
 * not yet do: kind reachability over the 35 kinds, the two-image golden
 * digest, the adversarial damage set, and the superset measurement against
 * the owning passes. Every one of them is specified in machine_ir.nova's
 * header comment. None of them is implied by what is here. CASE 4b also does
 * NOT observe the emitted bytes, so nothing here can tell a lowering that
 * restores RAX from one that does not; see the case for the limit in its own
 * words.
 *
 * THE NODE-FOR-NODE CONFRONTATION WAS ON THAT LIST AND IS NOT ANY MORE, and
 * what came off the list is CASE 8 rather than the whole sentence. What CASE
 * 8 confronts is the ATTRIBUTION: every record's `ntir_node`/`origin`, read
 * out of the lowered image, against the NTIR image's own parent map and
 * `admits` answer, read out of the NTIR. What is still NOT confronted is a
 * record's OPERANDS -- every value, link, width, class and flag is still
 * unexamined by this file -- so the list is shortened and not emptied, and
 * CASE 8's own closing paragraph says which half of the header's sentence it
 * does and does not establish.
 *
 * ALL FOUR OF THE HEADER'S FAILURE MODES ARE BUILDABLE NOW, and the fourth
 *   was the one that was not.  This paragraph used to read "AND ONE OF THE
 *   HEADER'S FOUR FAILURE MODES IS NOT BUILDABLE" and to give its reason: a
 *   DROPPED node could not be detected, because `admits` admits 42 nodes on
 *   CORPUS where the image claims 29 -- the difference being nodes this level
 *   resolves without a record of their own -- so the admitted set is not the
 *   expected set, and a perturbation that skipped every instruction statement
 *   moved the census without reds.  Both halves of that were right and the
 *   conclusion drawn from them was wrong: the gap is NOT an undifferentiated
 *   residue.
 *
 *   AND THE PARAGRAPH THAT SAID SO WAS WRONG IN A DIRECTION NOBODY GUESSED.
 *   It claimed every node in the gap on all three fixtures is of NTIR table
 *   index 47 (`name`) or 48 (`qualified`), and it named `expr` among the kinds
 *   that could never appear there.  Measured node by node, `expr` (index 36) IS
 *   in the gap: one node on CORPUS and two on DIAMOND, so the counts are 13,
 *   16 and 1 and not the 12, 14 and 1 the fixture table carried.  A sentence
 *   and a typed list that disagree are a finding, and here the SENTENCE was
 *   the false half -- so the retraction is of the prose, not of the count, and
 *   neither number survived.  What stands is measured and is in the arm: each
 *   `expr` node sits directly above a `qualified` node that sits directly
 *   above a `name` node, all three sharing ONE span, and that span is the
 *   DESTINATION REGISTER of an instruction (`mov rax, n`, `mov rsi,b`,
 *   `mov rsi,c`) which the image resolves out of its register table without
 *   ever calling `expr` on it.
 *
 *   What is asserted now, and it is the module's own contract rather than a
 *   figure (machine_ir.nova, over `admits_index`: the gate "separately checks
 *   that every EXECUTABLE NTIR node in its fixtures is attributed"): the gap
 *   holds NO node of a kind that owns a record -- no `instruction`, `let`,
 *   `call`, `return`, `if`, `label`, `block`, `const`, `function`, `parameter`,
 *   `data`, `literal`, or `type` naming a space.  A dropped STATEMENT is such
 *   a node, so the predicate is CROSSED by the drop rather than merely moved
 *   by it.  The three that CAN stand in the gap are 36 `expr` and 48
 * `qualified` -- the two spellings the parser wraps an operand in -- and 47
 *   `name`, which a binding's own record carries.  The DUPLICATED, REORDERED
 *   and POSITIVE modes were already detected, each by its own named check, and
 *   each was seen red by perturbing the producer's traversal rather than the
 *   expectation.  See the case for the measurements.
 *
 * THE VERSION PIN WAS ON THAT LIST AND IS NOT ANY MORE. It was written here as
 * absent and it was absent: machine_ir.nova's `versions_of` builds a kind-2050
 * record carrying the version the source declares, and nothing in the tree
 * read it. `parse` and `serialize` do compare `words[1]`/`words[2]` against
 * FORMAT_MAJOR/FORMAT_MINOR, but they compare the image against the constants
 * of the module that just produced it, so no version change can fail them and
 * none can wrongly pass. CASE 7 now reads that record against two producers
 * that are not the module that wrote it.
 *
 * WHAT CASE 7 STILL DOES NOT DO, so the list above is not simply shortened:
 * the confront machine_ir.nova's own comment asks for -- `aux2` against this
 * module's FORMAT_MAJOR and FORMAT_MINOR -- is NOT buildable, because the two
 * are different quantities and are never equal. On a source declaring all six
 * domains at 0.1 the image's pin is 102 and `version_pin()` is 2. That half
 * of the comment is wrong rather than merely unimplemented, and the corrected
 * text is HELD by the lot that found it rather than applied here, because
 * machine_ir.nova is not this gate's to edit.
 *
 * WHAT CASE 5 DOES NOT DO, and this is the half that matters. `header_text`
 * is a STRING LITERAL and FORMAT_MINOR is a NUMBER, and the comment above
 * `header_text` says the tag "moves WITH FORMAT_MINOR". Nothing connects
 * them: this pin holds the seven bytes of the string and would go red if a
 * lot raised FORMAT_MINOR and FORGOT the string, but it stays GREEN if a lot
 * raises FORMAT_MINOR alone. That is measured, not argued -- see the case.
 * The two ways of naming the version are not one fact read twice, and a
 * check that pretends they are would be restating the producer's own
 * formula, which is the mistake this gate's own case 7 comment names.
 */
#include "../../../compiler/c/ntasm/backend/codegen.h"
#include "../../../compiler/c/ntasm/frontend/frontend.h"
#include "../../../compiler/c/nova/frontend/nova.h"
#include "../../../compiler/c/nova/runtime/run_host.h"
#include "../../../compiler/c/nova/runtime/runtime_v2.h"
#include "../../../compiler/c/ntasm/backend/x64.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define A4_CHECK(condition, ...) do { checks++; if(!(condition)) { failures++; fprintf(stderr,"FAIL "); fprintf(stderr,__VA_ARGS__); fprintf(stderr,"\n"); } } while(0)
static unsigned checks, failures, cases;
#define CHECK(c, m)                                                            \
  do {                                                                         \
    checks++;                                                                  \
    if (!(c)) {                                                                \
      failures++;                                                              \
      fprintf(stderr, "FAIL %s\n", m);                                        \
    }                                                                          \
  } while (0)

#define WORDS 262144
#define TEXT 1048576
#define REPORT 256
#define GUARD UINT64_C(0xcccccccccccccccc)

/* Two targets, eighteen characters each, so every offset and every span in the
 * source is identical and the only difference is the arch name. */
static const char X86[] = "x86_64-nexora-none";
/* The second triple must be the SAME LENGTH as the first, or every byte offset
 * in the source moves and with it every span in the NTIR, which would let the
 * comparison pass or fail for the wrong reason. `sparc64-nexora-none` was tried
 * and is NINETEEN characters, not eighteen: retarget returned NULL on the
 * length test before it ever reached the substitution, and the whole case read
 * as a mysterious null. The two triples the project actually supports are
 * `x86_64-nexora-none` and `x86_64-nexora-uefi`, both eighteen characters, and
 * targets.nova accepts both -- which also means the case exercises a target
 * pair the pipeline validates rather than one it tolerates. */
static const char SPARC[] = "x86_64-nexora-uefi";

static const char *const PATHS[] = {
    "tests/nova/tests/machine-ir-entry.nova",
    "compiler/nova/ir/machine_ir.nova",
    "compiler/nova/formats/ntir/ntir.nova",
    "compiler/nova/ir/ir_image.nova",
    "compiler/nova/formats/pe/pe.nova",
    "compiler/nova/frontend/parser.nova",
    "compiler/nova/frontend/lexer.nova",
    "compiler/nova/frontend/ast.nova",
    "compiler/nova/analysis/types/register_widths.nova",
    "compiler/nova/analysis/types/pointer_spaces.nova",
    "compiler/nova/frontend/versions.nova"};
#define PATHS_N ((unsigned)(sizeof PATHS / sizeof PATHS[0]))

/* The format tag, written down HERE and not read back out of
 * machine_ir.nova. Same form and same reason as tests_ntasm_ntir.c's
 * EXPECTED_TAG: an expectation derived from the module that produces the
 * bytes cannot fail on a change to that module, so it is typed here instead
 * and the module is free to disagree with it. */
static const char EXPECTED_TAG[] = "MIR/1.3";

/* The corpus. Two functions, a parameter, a virtual register, a binding, a
 * MIXED `mov` over a binding name, a register add and a return -- enough that
 * the image has a function, two blocks, a terminator, a binding, three
 * opcodes and a conversion, and few enough that a human can read the whole
 * golden.
 *
 * `nop` IS HERE AND WAS NOT BEFORE, and the reason is the same reason the two
 * operator loops found nothing: the gate names THREE mnemonics and asserted
 * that three were found, over a corpus that only ever contained two of them.
 * A check that counts three against a corpus holding two cannot pass, and a
 * check that cannot pass is a check nobody has run. The line is a `nop`
 * because it has no operands, so it contributes an `mir_asm` record with an
 * opcode and nothing else and does not perturb the shape of anything else.
 *
 * `add rax, n` WAS THE LAST NAME-SOURCE LINE HERE AND IS NOT ANY MORE, and
 * the reason is a rule, not a preference. A binding name is a legal operand
 * form only in `mov`'s source position (spec/ntasm/ntasm.md 6.1, frozen the 28th of
 * September 2026), because the mixed lowering that reaches a name evaluates it
 * into RAX, parks RAX, restores RAX and then loads the destination -- a
 * sequence whose only lasting effect is a write to the destination family, and
 * therefore one that can only implement a pure assignment. `add`'s destination
 * is also a source, so the same sequence would compute `dest = name`. The C
 * oracle refuses that form and so does this gate now, so a corpus carrying it
 * would not lower at all. The two lines are SWAPPED, not dropped: `mov rax, 1`
 * and `add rax, n` become `mov rax, n` and `add rax, 1`, which is the same
 * number of records, the same three opcodes in the same order (nop, OP_COPY,
 * OP_ADD) and the same single constant record -- it simply belongs to the
 * `add` now. That is why the record count below does not move, and the
 * target-independence case rests on it. */
static const char CORPUS[] =
    "module m\n"
    "target x86_64-nexora-none\n"
    "section .text {\n"
    "fn helper(in a:u64, in b:u64)->u64\n"
    "effects {}\n"
    "clobbers {} {\n"
    "return a+b\n"
    "}\n"
    "fn main(in w:u8)->u64\n"
    "effects {}\n"
    "clobbers {rax} {\n"
    "let n:u64=w\n"
    "nop\n"
    "mov rax, n\n"
    "add rax, 1\n"
    "return rax\n"
    "}\n"
    "}\n";


static char *loadf(const char *path, size_t *length) {
  FILE *f = fopen(path, "rb");
  if (!f)
    return NULL;
  fseek(f, 0, SEEK_END);
  long n = ftell(f);
  fseek(f, 0, SEEK_SET);
  char *p = n >= 0 ? (char *)malloc((size_t)n + 1) : NULL;
  if (!p || fread(p, 1, (size_t)n, f) != (size_t)n) {
    free(p);
    fclose(f);
    return NULL;
  }
  fclose(f);
  p[n] = 0;
  *length = (size_t)n;
  return p;
}

/* One run: ten parameters of which six are buffers, so SIXTEEN flat slots. Each
 * buffer takes a handle and an ELEMENT count; `ntir_count` and `out_count` are
 * plain u64s and still take a slot of their own. Dropping one of them shifts
 * every later slot and the boundary answers NV2_LIFETIME with RET 0 and
 * nothing written, which reads exactly like a buffer-lifetime bug and is an
 * argument-count bug. */
typedef struct {
  uint64_t returned, runtime;
  uint64_t records, values, blocks, line, column, code, node;
  uint64_t ntir_count;
  uint64_t *words;   /* the NTIR image */
  uint64_t *image;   /* the Machine IR image */
  uint64_t *report;
  uint64_t length[4];
  uint8_t *text;
  size_t text_len;
} Run;

static void run_init(Run *r) {
  r->words = (uint64_t *)malloc(WORDS * sizeof(uint64_t));
  r->image = (uint64_t *)malloc(WORDS * sizeof(uint64_t));
  r->report = (uint64_t *)malloc(REPORT * sizeof(uint64_t));
  r->text = (uint8_t *)malloc(TEXT);
  memset(r->text, 0xcc, TEXT);
  r->text_len = 0;
}
static void run_free(Run *r) {
  free(r->words);
  free(r->image);
  free(r->report);
  free(r->text);
}

static void run(const NovaHostImage *image, const char *source, size_t size,
                uint64_t mode, uint64_t index, Run *r) {
  NovaContextV2 c = {0};
  for (unsigned i = 0; i < REPORT; i++)
    r->report[i] = GUARD;
  for (unsigned i = 0; i < 4; i++)
    r->length[i] = GUARD;
  memset(r->text, 0xcc, TEXT);
  r->text_len = 0;
  CHECK(nova_context_init_v2(&c), "context init");
  uint64_t sh = nova_borrow_v2(&c, (void *)source, size, 0);
  uint64_t wh = nova_borrow_v2(&c, r->words, WORDS * sizeof(uint64_t), 1);
  uint64_t ih = nova_borrow_v2(&c, r->image, WORDS * sizeof(uint64_t), 1);
  uint64_t th = nova_borrow_v2(&c, r->text, TEXT, 1);
  uint64_t lh = nova_borrow_v2(&c, r->length, 4 * sizeof(uint64_t), 1);
  uint64_t rh = nova_borrow_v2(&c, r->report, REPORT * sizeof(uint64_t), 1);
  uint64_t args[] = {sh, size, mode, index, wh, WORDS, WORDS, ih, WORDS,
                     WORDS, th, TEXT, lh, 4, rh, REPORT};
  r->returned = image->entry(&c, args, 16);
  r->runtime = c.error;
  r->records = r->report[0];
  r->values = r->report[1];
  r->blocks = r->report[2];
  r->line = r->report[0];
  r->column = r->report[1];
  r->code = r->report[2];
  r->node = r->report[3];
  r->ntir_count = r->words[3];
  if (r->length[0] > 0 && r->length[0] < TEXT) {
    r->text_len = (size_t)r->length[0];
  }
  CHECK(nova_context_destroy_v2(&c), "context cleanup");
}

/* Swap the target triple in place, requiring the replacement to be the same
 * length so no offset in the source moves. */
static char *retarget(const char *source, size_t size, const char *from,
                      const char *to) {
  size_t n = strlen(from);
  /* A length mismatch is a bug in THIS file, not a condition to absorb. The
   * first version returned NULL here, which surfaced four lines away as an
   * unexplained failure and cost a debugging round. Anything this harness
   * knows is wrong must be loud at the point where it is wrong. */
  if (n != strlen(to)) {
    fprintf(stderr, "FAIL retarget: '%s' is %zu bytes and '%s' is %zu; the "
                    "substitution would move every offset in the source\n",
            from, n, to, strlen(to));
    exit(1);
  }
  char *out = (char *)malloc(size + 1);
  if (!out)
    exit(1);
  memcpy(out, source, size + 1);
  char *hit = strstr(out, from);
  if (!hit) {
    fprintf(stderr, "FAIL retarget: '%s' does not occur in the corpus\n", from);
    exit(1);
  }
  memcpy(hit, to, n);
  return out;
}

/* The record layout, learned from the module through mode 7 and used everywhere
 * below, so this file holds no second copy of it. */
static uint64_t header_words, node_words, kind_base, kind_count;
static uint64_t op_limit;
/* The module's own version pin, FORMAT_MAJOR*100+FORMAT_MINOR, read back
 * through mode 7. Case 7 prints it beside the version the IMAGE carries so
 * that the two are seen to be different numbers rather than assumed to be
 * one. */
static uint64_t version_pin_of_gate;
static uint64_t arity[128];

/* The NTIR layout, read the same way and for the same reason: ntir.nova
 * publishes HEADER_WORDS and NODE_WORDS and the gate reads them rather than
 * writing 8 and 16 down, so a stride that moves is a red here and not a
 * silently mis-indexed read of somebody else's array. */
static uint64_t ntir_header, ntir_stride, ntir_nodes;
/* The NTIR's OWN kind numbering, read through the entry's mode 7 rather than
 * written down here. The attribution census has to name the kind of every node
 * it finds unclaimed, and turning the image's raw kind word into a table index
 * is `raw - KIND_BASE + 1` -- a formula, so the base has to come from the
 * module that owns it. A harness holding 1024 would classify every node under
 * a stale offset and print a kind no node has, with every number around it
 * still plausible. */
static uint64_t ntir_kind_base, ntir_kind_count;

/* The number of records the image actually holds, which the header carries and
 * which a damaged image could disagree with; the loops below stop there. */
static uint64_t n_records(const Run *r) {
  return r->image[3] < WORDS / node_words ? r->image[3] : 0;
}

#define W(r, rec, field)                                                       \
  ((r)->image[header_words + ((rec) - 1) * node_words + (field)])

/* One NTIR record field. The bounds are the caller's business: every use
 * below checks the node id against ntir_nodes first, because an id that is out
 * of range is a DAMAGED image and this macro must not be what decides that. */
#define NW(r, id, field)                                                       \
  ((r)->words[ntir_header + ((id) - 1) * ntir_stride + (field)])

/* ---- the depth caps: two fixture shapes, one counter -------------------
 *
 * ONE COUNTER, TWO WALKS. `machine_ir.nova` threads a single `depth` word
 * through BOTH the statement walk and the expression walk, and both caps are
 * the same number, 64. The walk is `callable` -> `body(1)` -> `stmt(depth)` ->
 * `{let_stmt,call_stmt,return_stmt,if_stmt,instruction,align_stmt}(depth)`, and
 * the only statement form that recurses is `if_stmt`, which hands `body`
 * `depth+1`. A statement-shaped source therefore deepens the STATEMENT
 * counter and an expression-shaped one deepens the EXPRESSION counter, and
 * both end in a comparison against 64.
 *
 * WHICH OF THE TWO FIRED IS READ OFF THE SPAN THE REFUSAL NAMES, and never off
 * a name typed here. `refuse` copies `nline`/`ncolumn` of the node it was
 * handed, and the two callers hand it different things: `if_stmt` passes its
 * CONDITION to `expr` and its ARM BLOCK to `body`. A refusal raised in `body`
 * therefore names the arm block, whose span runs from the `{` of the arm down
 * to its last `}` -- for the fixture below, some sixty lines. A refusal raised
 * in `expr` names one token. `span_is` compares the named node's span against
 * the source text, so the check says WHICH NODE FIRED without this file
 * carrying a copy of the NTIR kind table it would then have to keep in step.
 */
static int span_is(const Run *r, uint64_t id, const char *src,
                   const char *text) {
  if (id == 0 || id > r->ntir_count)
    return 0;
  uint64_t start = NW(r, id, 4), end = NW(r, id, 5);
  size_t n = strlen(text);
  if (end < start || end > strlen(src) || end - start != n)
    return 0;
  return memcmp(src + start, text, n) == 0;
}

/* The text a published (line, column) points at, read back out of the source.
 * A refusal publishes TWO readings of one fact -- a position in report[0..1]
 * and a node id in report[3] -- and this file used to check them one at a
 * time. Read separately they are two checks that can each be satisfied while
 * the two disagree, and this is what confronts them: the position and the
 * node must be the SAME TOKEN. A refusal that names one node and points at
 * another is then red rather than believed.
 *
 * LINES ARE ONE-BASED AND COUNT THE LINE BEING ENTERED, so line 1 is the text
 * before the first newline. The first version incremented its line counter on
 * the newline it STOPPED at and therefore read line N as the text of line
 * N+1, which made every caller one line out and made this check red against a
 * refusal that was in fact correct.
 *
 * AND THE TOKEN HAS TO BE THE WHOLE TOKEN. The bytes on BOTH sides have to be
 * outside it, or `text_at(..,"a")` is satisfied by the `a` inside `rax`. The
 * second version compared the bytes and then demanded the token run to the end
 * of its line, which is a check on nothing: a condition in the middle of a
 * line is followed by a space, so it read red against a refusal that was in
 * fact correct.
 */
static int is_word_byte(int c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
         (c >= '0' && c <= '9') || c == '_';
}
static int text_at(const char *src, uint64_t line, uint64_t column,
                   const char *text) {
  if (line < 1 || column < 1)
    return 0;
  const char *p = src;
  for (uint64_t cur = 1; cur < line; cur++) {
    const char *nl = strchr(p, '\n');
    if (!nl)
      return 0;
    p = nl + 1;
  }
  size_t n = strlen(text), at = (size_t)column - 1, left = strlen(p);
  if (left < at + n)
    return 0;
  const char *tok = p + at;
  if (memcmp(tok, text, n) != 0)
    return 0;
  if (at > 0 && is_word_byte((unsigned char)tok[-1]))
    return 0;
  if (at + n < left && is_word_byte((unsigned char)tok[n]))
    return 0;
  return 1;
}

static const char CHAIN_HEAD[] = "module m\n"
                                 "target x86_64-nexora-none\n"
                                 "section .text {\n"
                                 "fn f()->u64\n"
                                 "effects {}\n"
                                 "clobbers {} {\n"
                                 "let x:u64=";
static const char CHAIN_TAIL[] = "\nreturn x\n}\n}\n";

/* Append, and REFUSE a truncation instead of absorbing one. `snprintf` returns
 * the length it WOULD have written, so a return at or above the space left is a
 * truncated write -- and a truncated write is the failure mode that leaves no
 * trace: the buffer holds a shorter program, the module refuses that for some
 * unrelated reason, and the fixture reports a boundary that is not the
 * boundary. The first version of `if_source` sized its buffer from a guessed
 * constant and wrote one byte past it; ASan caught THAT one, and nothing would
 * have caught a truncation. */
static void append(char *p, size_t n, size_t *at, const char *s) {
  int wrote = snprintf(p + *at, n - *at, "%s", s);
  if (wrote < 0 || (size_t)wrote >= n - *at) {
    fprintf(stderr, "FAIL the depth fixture does not fit: %zu bytes are gone "
                    "and %zu are left\n",
            *at, n - *at);
    exit(1);
  }
  *at += (size_t)wrote;
}

/* An EXPRESSION-shaped source: `terms` literals joined by `+`, so the AST is
 * terms-1 nested binary nodes and nothing else is nested. `let x:u64=` puts
 * the FIRST literal at column 11 of line 7 -- which is the position the
 * refusal is required to carry, and is a property of the source text rather
 * than of the module. The budget is `3 * terms` because a piece is `1+`, two
 * characters plus its own NUL; measured over terms 1..64 this leaves two
 * spare bytes at every count, and `append` is what turns that from an
 * assumption into a checked fact. */
static char *chain_source(unsigned terms) {
  size_t n = sizeof CHAIN_HEAD + 3 * terms + sizeof CHAIN_TAIL;
  char *p = (char *)malloc(n);
  if (!p)
    exit(1);
  size_t at = 0;
  append(p, n, &at, CHAIN_HEAD);
  for (unsigned i = 0; i < terms; i++)
    append(p, n, &at, i + 1 < terms ? "1+" : "1");
  append(p, n, &at, CHAIN_TAIL);
  return p;
}

/* A STATEMENT-shaped source: `depth` nested `if`s, each arm holding one
 * instruction so the arm is a block and not the value-level select that
 * `if_stmt` folds away without calling `body` at all. */
static char *if_source(unsigned depth) {
  static const char HEAD[] = "module m\n"
                              "target x86_64-nexora-none\n"
                              "section .text {\n"
                              "fn f(in a:u64)->u64\n"
                              "effects {}\n"
                              "clobbers {rax} {\n";
  static const char INNER[] = "mov rax, 1\n";
  static const char FOOT[] = "return rax\n}\n}\n";
  static const char OPEN[] = "if a {\n";
  static const char CLOSE[] = "}\n";
  size_t n = sizeof HEAD + depth * (sizeof OPEN + sizeof CLOSE) +
             sizeof INNER + sizeof FOOT;
  char *p = (char *)malloc(n);
  if (!p)
    exit(1);
  size_t at = 0;
  append(p, n, &at, HEAD);
  for (unsigned i = 0; i < depth; i++)
    append(p, n, &at, OPEN);
  append(p, n, &at, INNER);
  for (unsigned i = 0; i < depth; i++)
    append(p, n, &at, CLOSE);
  append(p, n, &at, FOOT);
  return p;
}

/* A MEMORY-DESTINATION fixture, for the THIRD EXPR_DEPTH_CAP site. The
 * condition is the literal `1` on purpose: a bare name costs TWO levels (the
 * parser wraps every name in an expression node) while a literal costs one, and
 * that single level is what lets the memory descriptor be the deepest node in
 * the program instead of the condition. `mov` with a memory DESTINATION is
 * the form `instruction` hands to `memory_value` at its first operand, so the
 * descriptor is walked before anything else in the statement. */
static char *mem_source(unsigned depth) {
  static const char HEAD[] = "module m\n"
                              "target x86_64-nexora-none\n"
                              "section .text {\n"
                              "fn f()->u64\n"
                              "effects {}\n"
                              "clobbers {rax} {\n";
  static const char INNER[] = "mov [rax]:ptr<user,u64>,1\n";
  static const char FOOT[] = "return rax\n}\n}\n";
  static const char OPEN[] = "if 1 {\n";
  static const char CLOSE[] = "}\n";
  size_t n = sizeof HEAD + depth * (sizeof OPEN + sizeof CLOSE) +
             sizeof INNER + sizeof FOOT;
  char *p = (char *)malloc(n);
  if (!p)
    exit(1);
  size_t at = 0;
  append(p, n, &at, HEAD);
  for (unsigned i = 0; i < depth; i++)
    append(p, n, &at, OPEN);
  append(p, n, &at, INNER);
  for (unsigned i = 0; i < depth; i++)
    append(p, n, &at, CLOSE);
  append(p, n, &at, FOOT);
  return p;
}


int main(void) {
  size_t sizes[PATHS_N] = {0};
  char *sources[PATHS_N] = {0};
  NtFInput inputs[PATHS_N];
  int all = 1;
  for (unsigned i = 0; i < PATHS_N; i++) {
    sources[i] = loadf(PATHS[i], &sizes[i]);
    if (!sources[i])
      all = 0;
    inputs[i] = (NtFInput){PATHS[i], sources[i], sizes[i]};
  }
  CHECK(all, "the nine Nova sources load");
  if (!all) {
    printf("NTASM_NOVA_MACHINE_IR checks=%u failures=%u cases=%u\n", checks,
           failures, cases);
    return 1;
  }

  /* TWO INDEPENDENTLY COMPILED IMAGES of the same sources. This is what a
   * rebuild means for a module interpreted into a host image: a second compile
   * of the same bytes and a second run of the result. */
  NtArtifact first = {0}, second = {0};
  int c1 = nova_compile_many_v2(inputs, PATHS_N, &first);
  int c2 = nova_compile_many_v2(inputs, PATHS_N, &second);
  CHECK(c1, "the Nova sources compile");
  CHECK(c2, "the Nova sources compile a second time");
  if (!c1 || !c2) {
    if (!c1)
      fprintf(stderr, "E%u %zu:%zu %s\n", first.error.code, first.error.line,
              first.error.column, first.error.message);
    if (!c2)
      fprintf(stderr, "E%u %zu:%zu %s\n", second.error.code, second.error.line,
              second.error.column, second.error.message);
    printf("NTASM_NOVA_MACHINE_IR checks=%u failures=%u cases=%u\n", checks,
           failures, cases);
    return 1;
  }
  NovaHostImage ia = {0}, ib = {0};
  CHECK(nova_host_map(&first, &ia), "the first image maps");
  CHECK(nova_host_map(&second, &ib), "the second image maps");
  if (!ia.memory || !ib.memory) {
    for (unsigned i = 0; i < PATHS_N; i++) free(sources[i]);
    printf("NTASM_NOVA_MACHINE_IR checks=%u failures=%u cases=%u\n", checks,
           failures, cases);
    return 1;
  }

  /* FOUR buffers, not three. The operator case needs the NTIR image and the
   * lowered image at the same time -- it reads a record's NTIR origin out of
   * one and the opcode out of the other, and they have different layouts. The
   * first version ran mode 2 into rb and then mode 4 into rb as well, so the
   * loop below was reading NTIR fields out of a Machine IR image.
   *
   * The fourth exists because the binary loop probes TWO child nodes, and the
   * left-child probe was landing in `rb`, which is where the NTIR image lives.
   * A mode-6 probe re-parses and re-builds the NTIR into its own ntir_out, so
   * `rb` came back holding an image the gate had rebuilt rather than the one
   * the lowering consumed. It was byte-identical, which is exactly why it
   * would have survived review: the loop was reading an image it no longer
   * controlled. `rb` is now written once, by mode 2, and never again. */
  Run ra, rb, rc, rd;
  run_init(&ra);
  run_init(&rb);
  run_init(&rc);
  run_init(&rd);

  /* ---- the layout and the opcode vocabulary, read back ------------------ */
  run(&ia, "\n", 1, 7, 0, &ra);
  kind_count = ra.report[0];
  kind_base = ra.report[1];
  header_words = ra.report[5];
  node_words = ra.report[6];
  op_limit = ra.report[9 + kind_count];
  /* The module's OWN version pin, which is what machine_ir.nova's versions_of
   * comment claims the image's aux2 is confronted against. It is captured here
   * and printed next to the measured aux2 in case 7, because the two are NOT
   * the same quantity and a reader who has only the comment would not know
   * that. Nothing is asserted on it: see case 7. */
  version_pin_of_gate = ra.report[7];
  CHECK(kind_count == 40, "MIR1.3 adds typed call_indirect after local_cell");
  CHECK(kind_base == 2048, "KIND_BASE is the one the module publishes");
  CHECK(header_words == 10 && node_words == 24,
        "the record stride is the one the module publishes");
  if (op_limit < 128) {
    for (uint64_t op = 0; op <= op_limit; op++)
      arity[op] = ra.report[10 + kind_count + op];
  }
  /* The opcodes this file names, tied to the module as far as the module
   * actually lets them be tied. `op_limit` is the real tie: it says the
   * numbers are inside the module's published range rather than invented
   * here.
   *
   * THE TWO CHECKS THAT WERE HERE COULD NOT FAIL. Both read
   * `arity[N] != 0 || N <= op_limit`, and the disjunction is satisfied by the
   * second arm for every N the file names, because `op_limit >= 36` is
   * asserted on the line above. They were two pieces of green that measured
   * nothing, which is the defect this gate exists to catch, sitting in the
   * gate. They are replaced by checks that assert what the module actually
   * says about each opcode's shape.
   *
   * `op_arity` answers min*16+max, so it is 0 for a zero-operand opcode and
   * cannot be used to RECOGNISE one. It can still be used to measure the
   * operand count, which is what these now do: OP_COPY takes ONE OR TWO
   * operands and OP_ADD takes exactly two, which is why OP_NOP's arity is 0
   * and why a `!= 0` recognition test could never have worked for it.
   *
   * WHY THESE READ THE ENCODING INSTEAD OF WRITING IT. This row used to assert
   * `2 * 16 + 2` for OP_COPY -- a hand-written literal five lines from the
   * module's own publication. `machine_ir.nova` changed OP_COPY to ONE OR TWO
   * operands, `1*16+2`, and wrote ten lines saying why: one operand is the
   * MATERIALISATION form (`mov rax, 5`) and two is the ASSIGNMENT form
   * (`mov rax, rcx`), the producer emits both, and a rule admitting only one
   * of two shapes the producer emits is not a constraint. The gate's literal
   * did not follow, and the row went red for a reason that had nothing to do
   * with the module. That is recorded as R431.
   *
   * THE MODULE WAS RIGHT AND THE C SAYS SO. `nt_frontend_compile` verifies
   * `mov rax, 5` (one operand) and `mov rax, rbx` (two operands), and refuses
   * `mov rax` and `mov rax, rbx, rcx` with NTF_E_TYPE 400 "mov: wrong operand
   * count". The reference admits exactly one or two. The module matches it.
   *
   * SO THE FIX IS NOT A NEW LITERAL. Writing `1 * 16 + 2` would leave the same
   * second convention that rotted once, and it would rot again the next time
   * the module admits a third shape. These rows therefore DECODE the
   * published encoding and assert the operand pair the module actually claims
   * -- one and two for OP_COPY, two and two for OP_ADD. If you are reading
   * this and about to "tidy" `min`/`max` back into a single compared constant:
   * do not. A number this file writes is a number this file can be wrong
   * about; a number it decodes is a number it was told. */
  CHECK(op_limit >= 36, "the module publishes at least the opcodes named here");
  {
    /* min*16+max, decoded. A 0 arity is the zero-operand opcode and is
     * asserted separately below, so the decode is only asked about opcodes
     * that take something. */
    const uint64_t copy_min = arity[1] / 16, copy_max = arity[1] % 16;
    const uint64_t add_min = arity[2] / 16, add_max = arity[2] % 16;
    CHECK(copy_min == 1 && copy_max == 2,
          "OP_COPY takes ONE OR TWO operands, as the C oracle verifies for "
          "`mov rax, 5` and `mov rax, rbx` and refuses outside that");
    CHECK(add_min == 2 && add_max == 2, "OP_ADD takes exactly two operands");
  }
  CHECK(arity[36] == 0, "OP_NOP takes no operands, which is why it is not "
                        "recognised by a non-zero arity");

  /* The kind NAMES, read back through mode 7 into the caller's buffer ONE BYTE
   * PER WORD, each name NUL-terminated, with the total byte length in the
   * return value. The one-byte-per-word form is why: a `buf<u8>` return does
   * not survive the cross-module export boundary of this bootstrap compiler,
   * which is the same reason parser.nova:81-82 has `keyword_read_back`. Byte
   * `j` of a name is therefore word `j` of the buffer, and a scan that casts
   * the buffer to `char*` and walks it as a string sees the low byte of each
   * u64 and compares against the wrong bytes.
   *
   * The gate looks the two kinds it needs up BY NAME rather than writing
   * `kind_base + 17`. The typed index was CORRECT -- 17 is `asm` and 22 is
   * `binary` -- so this is not a fix for a wrong number. It is here because a
   * typed index cannot be CHECKED by reading it: a reader comparing
   * `kind_base + 17` against `k_asm()` has to count, and the failure mode of
   * miscounting is a loop that matches nothing and reports a count of zero,
   * which is the failure this gate spent a wave sitting in. A name is
   * checkable by reading it. The names carry no `mir_` prefix, even though
   * the functions that build them are called `k_asm` and `k_binary`. */
  uint64_t k_asm_index = 0, k_binary_index = 0;
  uint64_t k_const_index = 0;
  /* `versions` is looked up for the same reason as the three above, and it
   * matters more here than it does for them: the whole case below is about
   * the record this name selects, so an index miscounted here would make
   * every arm of that case vacuous and every one of them would still be
   * green. It is looked up rather than written as `kind_base + 2` because the
   * number is not the claim -- the NAME is. */
  uint64_t k_versions_index = 0;
  {
    static const char ASM[] = "asm";
    static const char BINARY[] = "binary";
    /* `const` is looked up the same way and for the same reason as the two
     * above: a name is checkable by reading it, a typed index is not. Case 0
     * compares a record against it to attribute a differing word to the
     * magnitude, and an index that had been miscounted would make that
     * attribution silently vacuous -- the loop would find no matching word
     * and the count would read zero, which is a number and not a verdict. */
    static const char CONST[] = "const";
    static const char VERSIONS[] = "versions";
    size_t at = 0;
    for (uint64_t i = 1; i <= kind_count && at < (size_t)ra.returned; i++) {
      size_t len = 0;
      while (at + len < (size_t)ra.returned && ra.image[at + len])
        len++;
      int is_asm = len == sizeof ASM - 1;
      for (size_t j = 0; is_asm && j < sizeof ASM - 1; j++)
        is_asm = ra.image[at + j] == (uint64_t)(unsigned char)ASM[j];
      int is_bin = len == sizeof BINARY - 1;
      for (size_t j = 0; is_bin && j < sizeof BINARY - 1; j++)
        is_bin = ra.image[at + j] == (uint64_t)(unsigned char)BINARY[j];
      int is_const = len == sizeof CONST - 1;
      for (size_t j = 0; is_const && j < sizeof CONST - 1; j++)
        is_const = ra.image[at + j] == (uint64_t)(unsigned char)CONST[j];
      int is_ver = len == sizeof VERSIONS - 1;
      for (size_t j = 0; is_ver && j < sizeof VERSIONS - 1; j++)
        is_ver = ra.image[at + j] == (uint64_t)(unsigned char)VERSIONS[j];
      if (is_asm)
        k_asm_index = i;
      else if (is_bin)
        k_binary_index = i;
      else if (is_const)
        k_const_index = i;
      else if (is_ver)
        k_versions_index = i;
      at += len + 1;
    }
  }
  CHECK(k_asm_index != 0, "the kind table publishes the asm kind by that name");
  CHECK(k_binary_index != 0,
        "the kind table publishes the binary kind by that name");
  CHECK(k_const_index != 0, "the kind table publishes the const kind by that name");
  CHECK(k_versions_index != 0,
        "the kind table publishes the versions kind by that name");
  uint64_t k_asm = k_asm_index ? kind_base + k_asm_index - 1 : 0;
  uint64_t k_binary = k_binary_index ? kind_base + k_binary_index - 1 : 0;
  uint64_t const_kind = k_const_index ? kind_base + k_const_index - 1 : 0;
  uint64_t k_versions =
      k_versions_index ? kind_base + k_versions_index - 1 : 0;

  /* The NTIR record layout, read here while `ra` still holds mode 7's answer.
   * It is read HERE and not down in case 2 because case 1 runs mode 2 and
   * mode 4 through `ra` and overwrites the report; a layout read after that
   * would be read out of whatever the last run happened to leave behind.
   *
   * It is read at all, rather than written down as 8 and 16, because
   * machine_ir.nova indexes the NTIR through ntir.HEADER_WORDS() and
   * ntir.NODE_WORDS() rather than through constants and this gate indexes the
   * same image. A hard-coded pair here is a second copy of a layout, and a
   * second copy disagrees silently -- on every field, at every record. The
   * two slots sit immediately past the opcode table, whose last entry is at
   * 10+kind_count+OP_LIMIT. */
  {
    uint64_t table_end = 10 + kind_count + op_limit;
    ntir_header = ra.report[table_end + 1];
    ntir_stride = ra.report[table_end + 2];
    ntir_kind_base = ra.report[table_end + 3];
    ntir_kind_count = ra.report[table_end + 4];
  }
  CHECK(ntir_header != 0 && ntir_stride != 0,
        "the entry publishes the NTIR header and stride");
  CHECK(ntir_kind_base != 0 && ntir_kind_count != 0,
        "the entry publishes the NTIR kind base and count, so the census names "
        "kinds by the owner's numbering and not by an offset typed here");

  /* ---- CASE 0: THE CONSTANT ZERO -----------------------------------------
   *
   * WHY THIS CASE EXISTS, and it is a defect found by measurement rather than
   * a coverage request. Lot 10 asked whether the Machine IR can be put on the
   * executable producer's path, and the answer turned on one source: `return
   * 0`. That is the exact source the PE gate byte-compares against codegen.c
   * (tests_ntasm_x64_lower_nxo_pe.c's `ng5_build_source` writes `return 0` for
   * its with_import=0 twin), so an IR that refuses it cannot precede the
   * product's own emission.
   *
   * MEASURED, with the attribution separated stage by stage rather than read
   * off a single mode-0 answer:
   *
   *   ntir.build        accepts   21 records
   *   machine_ir.lower  accepts    9 records, 1 value, 1 block
   *   machine_ir.verify REFUSES  934 (E_SHAPE)
   *
   * So the lowering is right and the VERIFIER is wrong, and the two runs above
   * are what make that attribution a measurement: a mode-0 answer alone reads
   * as "the IR refuses `return 0`" and names no stage.
   *
   * THE CAUSE, to the word. `mir_const` stores its magnitude in `arg_a`.
   * machine_ir.literal reads the literal through `read_magnitude`, which
   * returns value+1 -- a ONE-BASED encoding -- and then subtracts one into
   * `amount` before writing it (machine_ir.nova:1103-1113). So the record for
   * `return 0` carries arg_a = 0, and for `return 1` it carries arg_a = 1.
   * Both are dumped and compared rather than inferred, and they differ in that
   * one word and in nothing else.
   *
   * The verifier's rule is `live==true && value==0 && arg_is(kind,slot)!=3`
   * (machine_ir.nova:2824): a LIVE slot holding 0 is malformed, because for
   * every kind whose slots are value references 0 means "no value". But
   * `arg_is` had NO ENTRY for k_const -- it returns 0, the default -- and a
   * constant's argument is not a value reference at all. It is a magnitude,
   * and magnitude zero is the constant zero, which is a perfectly good
   * machine value. The image `lower` built is correct and `verify` refuses it.
   *
   * THE SHAPE OF THE BUG IS THE POINT, and it is why this case asserts a
   * PARITY rather than a fixed count: the corpus above carries `add rax, 1`
   * and `mov rax, n`, and its constant is therefore magnitude 1. Nothing in
   * the gate ever built a constant ZERO, so the defect was unreachable by the
   * existing cases and the gate was green over it. A check that counts
   * records would have passed on the wrong image; the property is that the
   * constant of zero is admitted, and that is what is asked. */
  cases++;
  {
    static const char ZERO[] =
        "module m\n"
        "target x86_64-nexora-none\n"
        "section .text {\n"
        "export fn main()->u64\n"
        "effects {}\n"
        "clobbers {} {\n"
        "return 0\n"
        "}\n"
        "}\n";
    static const char ONE[] =
        "module m\n"
        "target x86_64-nexora-none\n"
        "section .text {\n"
        "export fn main()->u64\n"
        "effects {}\n"
        "clobbers {} {\n"
        "return 1\n"
        "}\n"
        "}\n";
    size_t zlen = strlen(ZERO), olen = strlen(ONE);
    /* STAGE 1, the NTIR. Mode 2 parses and builds the NTIR image and stops. */
    run(&ia, ZERO, zlen, 2, 0, &ra);
    CHECK(ra.returned == 0, "the NTIR admits a body returning the constant zero");
    run(&ia, ONE, olen, 2, 0, &rb);
    CHECK(rb.returned == 0, "the NTIR admits a body returning the constant one");
    /* STAGE 2, the LOWERING, with no verify in the way. Mode 4 lowers the
     * image ALREADY in that Run's ntir_out, so stage 2 and mode 4 must land in
     * the SAME Run: mode 2 writes ra.words and mode 4 reads ra.words. Sending
     * mode 4 to a different Run reads a buffer no stage wrote, and the
     * refusal that follows would be the probe's, not the module's. */
    run(&ia, ZERO, zlen, 4, 0, &ra);
    CHECK(ra.returned == 0, "the Machine IR lowering admits the constant zero");
    run(&ia, ONE, olen, 4, 0, &rb);
    CHECK(rb.returned == 0, "the Machine IR lowering admits the constant one");
    /* STAGE 3, the two images side by side. The property is that they differ in
     * EXACTLY ONE WORD, because that word is the whole of the claim: the
     * verifier's disagreement is about the magnitude and about nothing else.
     * A count of records would pass on the wrong image; a count of DIFFERING
     * WORDS cannot. */
    uint64_t zrec = ra.image[3];
    CHECK(zrec == 10, "MIR1.1 constant-zero image adds one signature type record");
    if (zrec == rb.image[3] && zrec > 0) {
      uint64_t span = header_words + zrec * node_words;
      uint64_t differing = 0, magnitude_words = 0;
      for (uint64_t i = 0; i < span; i++) {
        if (ra.image[i] == rb.image[i])
          continue;
        differing++;
        uint64_t rec = (i - header_words) / node_words + 1;
        uint64_t field = (i - header_words) % node_words;
        if (W(&ra, rec, 0) == const_kind && field == 5)
          magnitude_words++;
      }
      CHECK(differing == 1,
            "the constant-zero image differs from the constant-one image in "
            "exactly one word");
      CHECK(magnitude_words == 1,
            "and that one word is the mir_const magnitude");
      CHECK(W(&ra, zrec, 5) == 0, "the constant zero is stored as magnitude 0");
      CHECK(W(&rb, zrec, 5) == 1, "the constant one is stored as magnitude 1");
    }
    /* STAGE 4, the VERIFIER, and the check that was red. Mode 5 verifies the
     * image ALREADY in that Run's out, so it follows mode 4 into the same
     * Run. */
    run(&ia, ZERO, zlen, 5, 0, &ra);
    CHECK(ra.returned == 0,
          "the verifier admits an image whose constant is the magnitude zero");
    run(&ia, ONE, olen, 5, 0, &rb);
    CHECK(rb.returned == 0, "the verifier admits the constant one for comparison");
  }

  /* ---- CASE 1: target independence -------------------------------------- */
  cases++;
  size_t clen = strlen(CORPUS);
  char *alt = retarget(CORPUS, clen, X86, SPARC);
  CHECK(alt != NULL, "the corpus carries a target triple this gate can swap");
  if (alt) {
    run(&ia, CORPUS, clen, 2, 0, &ra);
    CHECK(ra.returned == 0, "the corpus builds an NTIR image for the first target");
    run(&ia, alt, clen, 2, 0, &rb);
    CHECK(rb.returned == 0, "the corpus builds an NTIR image for the second target");
    run(&ia, CORPUS, clen, 4, 0, &ra);
    CHECK(ra.runtime == 0, "the x86 lowering runs with no runtime error");
    CHECK(ra.returned == 0, "the x86 lowering is accepted");
    run(&ia, alt, clen, 4, 0, &rb);
    CHECK(rb.runtime == 0, "the second lowering runs with no runtime error");
    CHECK(rb.returned == 0, "the second lowering is accepted");
    uint64_t n = ra.image[3];
    CHECK(n > 0 && n == rb.image[3],
          "the two lowerings produce the same number of records");
    if (n > 0 && n == rb.image[3]) {
      uint64_t span = header_words + n * node_words;
      uint64_t differing = 0, header_differing = 0, target_digest = 0;
      uint64_t target_kind = kind_base + 1; /* the second published kind */
      for (uint64_t i = 0; i < span; i++) {
        if (ra.image[i] == rb.image[i])
          continue;
        differing++;
        if (i < header_words) {
          header_differing++;
          continue;
        }
        uint64_t rec = (i - header_words) / node_words + 1;
        uint64_t field = (i - header_words) % node_words;
        uint64_t kind = W(&ra, rec, 0);
        /* The one word that may differ is a mir_target record's `aux`, which is
         * where the module puts the digest of the triple. */
        if (kind == target_kind && field == 14)
          target_digest++;
        else
          fprintf(stderr,
                  "TARGET word %llu (record %llu, field %llu, kind %llu) "
                  "differs: %llu vs %llu\n",
                  (unsigned long long)i, (unsigned long long)rec,
                  (unsigned long long)field, (unsigned long long)kind,
                  (unsigned long long)ra.image[i],
                  (unsigned long long)rb.image[i]);
      }
      CHECK(differing == 1,
            "the two images differ in EXACTLY ONE word, and no more");
      CHECK(header_differing == 0, "no header word depends on the target");
      CHECK(target_digest == 1,
            "the one differing word is a mir_target record's digest");
      printf("TARGET-INDEPENDENT records=%llu words=%llu differing=%llu "
             "header_differing=%llu target_digest=%llu\n",
             (unsigned long long)n, (unsigned long long)span,
             (unsigned long long)differing,
             (unsigned long long)header_differing,
             (unsigned long long)target_digest);
    }
    free(alt);
  }

  /* ---- CASE 2: the operator recovery, four operators -------------------- */
  /* The three mnemonics and one binary operator. The binary one's expectation
   * is parser.nova:256's own aux word, read back through the entry's oracle
   * probe, and NOT a constant typed here: the probe hands back the AST aux for
   * a given NTIR node, and the gate maps THAT token kind to the opcode the
   * lowering must have chosen. */
  cases++;
  /* The NTIR image goes into rb and STAYS there: the loops below read a Machine
   * IR record's origin and then look the AST record up in it. */
  run(&ia, CORPUS, clen, 2, 0, &rb);
  CHECK(rb.returned == 0, "the corpus builds an NTIR image");
  ntir_nodes = rb.words[3];
  /* The lowered image goes into rc, and the loops read THAT. Mode 4 lowers
   * from an NTIR image ALREADY in the buffer and does not parse, so the same
   * buffer has to be built by mode 2 first. The target-independence case above
   * does exactly this and passes. */
  run(&ia, CORPUS, clen, 2, 0, &rc);
  run(&ia, CORPUS, clen, 4, 0, &rc);
  CHECK(rc.returned == 0, "the corpus lowers for the mnemonic cases");

  /* THE MNEMONIC SPELLING IS THE FIRST CHILD OF THE INSTRUCTION NODE. The
   * previous version read the byte offset out of the Machine IR record's
   * `aux2` (field 15), on the belief that the lowering wrote the mnemonic's
   * position there. IT DOES NOT: field 15 is `aux2`, and the only thing the
   * module writes there for a `mir_asm` is the flag saying the operands were
   * decomposed into a load and a store. On this corpus it is 0 on every
   * record, so the gate read the "spelling" at offset 0 of the corpus -- the
   * word `module` -- matched it against nop/mov/add, took the `else continue`
   * branch, and reported a count of zero. That is the whole reason this loop
   * was silent, and it is a guard firing on a field that never carried the
   * value it was being asked to check.
   *
   * The spelling lives where machine_ir.nova:1502-1505 reads it: `nstart` and
   * `nend` of the instruction's FIRST CHILD. The gate now reads the same
   * place, and that is the point rather than a consolation -- a gate reading
   * the same field the module reads is what makes the opcode comparison a
   * measurement of the MAPPING instead of a restatement of the lookup. */
  unsigned mnemonics = 0, binaries = 0;
  uint64_t examined_asm = 0;
  for (uint64_t rec = 1; rec <= n_records(&rc); rec++) {
    examined_asm++;
    if (W(&rc, rec, 0) != k_asm)
      continue;
    uint64_t attributed = W(&rc, rec, 1);
    if (attributed == 0)
      attributed = W(&rc, rec, 18);
    if (attributed == 0 || attributed > ntir_nodes)
      continue;
    /* The AST kind the NTIR copied. A `mir_asm` is an instruction, so this is
     * a cross-check that the record and the node it names agree rather than
     * the thing being looked for; it is kept because a `mir_asm` attributed
     * to a non-instruction would mean the attribution itself is wrong. */
    if (NW(&rb, attributed, 6) != 32)
      continue;
    run(&ia, CORPUS, clen, 6, attributed, &ra);
    if (ra.report[7] != 0) /* the AST aux: 0 an instruction, 1 a label */
      continue;
    uint64_t head = NW(&rb, attributed, 8);
    if (head == 0 || head > ntir_nodes)
      continue;
    uint64_t mstart = NW(&rb, head, 4), mend = NW(&rb, head, 5);
    if (mend <= mstart || mend > clen)
      continue;
    size_t mlen = (size_t)(mend - mstart);
    uint64_t want;
    if (mlen == 3 && memcmp(CORPUS + mstart, "nop", 3) == 0)
      want = 36;
    else if (mlen == 3 && memcmp(CORPUS + mstart, "mov", 3) == 0)
      want = 1;
    else if (mlen == 3 && memcmp(CORPUS + mstart, "add", 3) == 0)
      want = 2;
    else {
      /* A spelling outside the pinned four. It is REPORTED rather than
       * skipped, because a skipped one is how this loop sat empty for a whole
       * wave with nothing on stderr at all. */
      fprintf(stderr,
              "UNPINNED mnemonic [%.*s] at %llu..%llu carries opcode %llu, "
              "outside the four this gate measures\n",
              (int)mlen, CORPUS + mstart, (unsigned long long)mstart,
              (unsigned long long)mend, (unsigned long long)W(&rc, rec, 14));
      continue;
    }
    checks++;
    if (W(&rc, rec, 14) != want) {
      failures++;
      fprintf(stderr, "FAIL mnemonic %.*s: opcode %llu, wanted %llu\n",
              (int)mlen, CORPUS + mstart, (unsigned long long)W(&rc, rec, 14),
              (unsigned long long)want);
    } else {
      mnemonics++;
      printf("OPERATOR mnemonic=%.*s opcode=%llu line=%llu column=%llu\n",
             (int)mlen, CORPUS + mstart, (unsigned long long)W(&rc, rec, 14),
             (unsigned long long)W(&rc, rec, 2),
             (unsigned long long)W(&rc, rec, 3));
    }
  }
  /* HOW MANY RECORDS THE LOOP LOOKED AT. A loop that examines nothing and a
   * loop that examines thirty-one records and matches none of them otherwise
   * print the same `matched=0`, and telling those two apart is the entire
   * reason this line exists. It stays in the gate. */
  printf("OPERATOR-SCAN mnemonics examined=%llu matched=%u expected=%u\n",
         (unsigned long long)examined_asm, mnemonics, 3);
  CHECK(mnemonics == 3, "all three mnemonics resolve to the expected opcode");

  /* THE BINARY `+`. The expectation is parser.nova:256's OWN aux word, read
   * back through the entry's oracle probe, and not a constant typed here: the
   * probe hands back the AST aux for a given NTIR node, and the gate maps THAT
   * token kind to the opcode the lowering must have chosen. Token kind 43 is
   * `+` because the lexer numbers a token by its ASCII byte (lexer.nova:3).
   * A recovery keyed on the source gap and a recovery keyed on the parser's own
   * word are then required to agree.
   *
   * THE SECOND CHILD WAS THE WRONG FIELD. `report[15]` is `next`, the node's
   * NEXT SIBLING, not its second child; the second child is the first child's
   * `next`, which is `report[14]` = `last`. On this corpus the `a+b` node has
   * no next sibling, so `second` was 0, the `if (first == 0 || second == 0)`
   * guard fired on every expression in the image, and the loop reported a
   * count of zero having examined all of them. That guard was not protecting
   * against a damaged image; it was the field being read being the wrong one,
   * which is the same defect as the `aux2` span in the mnemonic loop and the
   * reason both loops are now written against the module's own derivation
   * (machine_ir.nova:912-923) rather than against a guess at its fields.
   *
   * The loop also no longer filters on the AST kind alone: it looks for the
   * record the module actually emits for a binary, `mir_binary`, by name. */
  uint64_t examined_bin = 0;
  for (uint64_t rec = 1; rec <= n_records(&rc); rec++) {
    examined_bin++;
    if (W(&rc, rec, 0) != k_binary)
      continue;
    uint64_t attributed = W(&rc, rec, 1);
    if (attributed == 0)
      attributed = W(&rc, rec, 18);
    if (attributed == 0 || attributed > ntir_nodes)
      continue;
    if (NW(&rb, attributed, 6) != 35) /* AST kind 35 is an expression */
      continue;
    run(&ia, CORPUS, clen, 6, attributed, &ra);
    uint64_t aux = ra.report[7];
    if (aux != 43)
      continue; /* not a `+` */
    /* The node's own two children: the operator is the ONLY thing between
     * them, so the gate derives the same gap the module derives it from.
     * `first` is the first child (report[13]) and `second` is the second,
     * which is the first child's own `next`. */
    uint64_t first = ra.report[13];
    if (first == 0 || first > ntir_nodes)
      continue;
    uint64_t second = NW(&rb, first, 10);
    if (second == 0 || second > ntir_nodes)
      continue;
    /* A third child means this is not the two-operand shape the module's
     * `binary_op` requires, and a gap derived from the wrong pair of children
     * would be a gap the module never looked at. */
    if (NW(&rb, second, 10) != 0)
      continue;
    /* The spans come out of the NTIR image, which is the same pair of fields
     * machine_ir.nova:919-920 reads. The left probe goes into `rd`, NOT `rb`:
     * a mode-6 probe re-builds the NTIR into its own ntir_out, so probing into
     * `rb` replaced the image the lowering consumed with one the gate had just
     * rebuilt, and every later iteration then read an image it did not
     * control. `rb` is written once, by mode 2, and never again. */
    uint64_t left_end = NW(&rb, first, 5);
    uint64_t right_start = NW(&rb, second, 4);
    run(&ia, CORPUS, clen, 6, first, &rd);
    /* The probe is the cross-check that the spans the gate read out of the
     * image are the spans the parser recorded for the same nodes. If they ever
     * disagree the gate says so instead of measuring a gap that is not the
     * module's. */
    checks++;
    if (rd.report[12] != left_end) {
      failures++;
      fprintf(stderr, "FAIL node %llu: the image says its end is %llu and the "
                      "parser says %llu\n",
              (unsigned long long)first, (unsigned long long)left_end,
              (unsigned long long)rd.report[12]);
      continue;
    }
    checks++;
    if (right_start <= left_end || right_start - left_end > 8) {
      failures++;
      fprintf(stderr, "FAIL the operator gap is %llu..%llu, which is not a "
                      "single operator\n",
              (unsigned long long)left_end, (unsigned long long)right_start);
      continue;
    }
    char gap[16];
    size_t glen = 0;
    for (uint64_t i = left_end; i < right_start && glen < sizeof gap - 1; i++)
      gap[glen++] = CORPUS[i];
    gap[glen] = 0;
    /* The gap the gate derived, trimmed, must be the operator the parser's aux
     * says, and the opcode the lowering chose must be OP_ADD. */
    while (glen && (gap[0] == ' ' || gap[0] == '\t')) {
      memmove(gap, gap + 1, glen);
      glen--;
    }
    while (glen && (gap[glen - 1] == ' ' || gap[glen - 1] == '\t'))
      gap[--glen] = 0;
    checks++;
    if (glen != 1 || gap[0] != '+') {
      failures++;
      fprintf(stderr, "FAIL the gap is [%s], the aux says token %llu\n", gap,
              (unsigned long long)aux);
      continue;
    }
    checks++;
    if (W(&rc, rec, 14) != 2) {
      failures++;
      fprintf(stderr, "FAIL the binary + lowered to opcode %llu, wanted %llu\n",
              (unsigned long long)W(&rc, rec, 14), (unsigned long long)2);
      continue;
    }
    binaries++;
    printf("OPERATOR binary=%s aux=%llu opcode=%llu recovered_from_gap=%llu\n",
           gap, (unsigned long long)aux, (unsigned long long)W(&rc, rec, 14),
           (unsigned long long)(right_start - left_end - 1));
  }
  /* The examined count, for the same reason as the one above. */
  printf("OPERATOR-SCAN binary examined=%llu matched=%u expected=%u\n",
         (unsigned long long)examined_bin, binaries, 1);
  CHECK(binaries == 1, "the binary + resolves from the parser's own aux word");

  /* ---- CASE 3: the stack and frame registers are not destinations -------- */
  /* A body may not WRITE rsp or rbp. Every local, spill, snapshot, call
   * argument and temporary slot of a lowered function is addressed through
   * RBP and the epilogue leaves through RSP, so a body that writes either
   * produces a frame the rest of the function then misaddresses. The oracle
   * says so at frontend.c:5491-5497, for EVERY machine instruction whose
   * computed write set meets either register, whatever the mnemonic:
   * "<mnemonic> requires unavailable stack/frame balance proof" at
   * NTF_E_CONTRACT, 503. codegen.c:1006 says the same thing again on the one
   * path the frontend's operand check cannot see, at NTCG_E_UNSUPPORTED, 702.
   *
   * WHERE THE RULE IS ENFORCED AND WHY IT IS HERE. `instruction` in
   * machine_ir.nova is the only function in the Nova tree that resolves an
   * instruction's DESTINATION operand, and it already draws the
   * source/destination boundary with `op!=OP_CMP() && op!=OP_TEST()`. The
   * rule is added to that one site, and to no other.
   *
   * THE BOUNDARY IS THE POINT OF HALF THIS CASE, AND IT IS THE HALF THAT
   * WOULD FAIL IF THE RULE SCANNED OPERANDS. `mov rax,rbp`, `mov rax,rsp`,
   * `add rax,rbp` and `cmp rax,rbp` all READ a frame register and all have to
   * keep lowering; measured against the C oracle, every one of them is
   * ACCEPTED there and falls through to the ordinary clobber/effect
   * accounting. A rule that refused an operand rather than a write would
   * refuse four valid programs, which is the direction this project keeps
   * paying for. Each boundary case therefore asserts ACCEPTANCE, and the
   * rbx/rsi/rdi/eax cases are the control group on the other side: they
   * prove the two family numbers are not a wider range than two. */
  static const char FRAME_FMT[] =
      "module m\n"
      "target x86_64-nexora-none\n"
      "section .text {\n"
      "fn f(in w:u8)->u64\n"
      "effects {}\n"
      "clobbers {%s} {\n"
      "let n:u64=w\n"
      "%s\n"
      "return n\n"
      "}\n"
      "}\n";
  /* E_FRAME, 947. It is written as a number because the entry fixture
   * (`tests/nova/tests/machine-ir-entry.nova`, not this gate's
   * file) publishes the opcode vocabulary through mode 7 and no refusal code
   * at all, so there is no channel to read 947 back through. The tie is the
   * band instead: machine_ir.nova owns 930..947 exclusively, its last
   * published code before this one was E_NTIR at 946, and the case below
   * asserts that 947 is neither 940 (E_INPUT, the code a mnemonic outside the
   * module's vocabulary already answers) nor 934 (E_SHAPE), so this refusal
   * is distinguishable from the two ways machine_ir already said no. */
  const uint64_t E_FRAME = 947;
  char frame[1024];
  /* One fixture, one verdict. `want` is the code the whole pipeline must
   * answer, and zero means the pipeline must ACCEPT. */
  struct {
    const char *name, *clobbers, *body;
    uint64_t want;
  } const FRAME_CASES[] = {
      /* a register destination, and the sub-register alias of it */
      {"mov rbp", "rsp,rbp", "mov rbp,n", E_FRAME},
      {"mov ebp alias", "rsp,rbp", "mov ebp,n", E_FRAME},
      {"mov rsp", "rsp", "mov rsp,n", E_FRAME},
      /* an arithmetic destination */
      {"add rbp", "rsp,rbp", "add rbp,n", E_FRAME},
      {"add rsp", "rsp", "add rsp,n", E_FRAME},
      /* a stack destination, both directions */
      {"pop rbp", "rsp,rbp", "pop rbp", E_FRAME},
      {"pop rsp", "rsp", "pop rsp", E_FRAME},
      {"push rbp", "rsp", "push rbp", E_FRAME},
      /* a lea destination */
      {"lea rbp", "rsp,rbp", "lea rbp,n", E_FRAME},
      /* a two-register form whose first operand is the destination */
      {"xchg rbp", "rsp,rbp", "xchg rbp,n", E_FRAME},
      /* THE BOUNDARY, half one: a frame register as a SOURCE is a read. */
      {"mov rax,rbp", "rax", "mov rax,rbp", 0},
      {"mov rax,rsp", "rax", "mov rax,rsp", 0},
      {"add rax,rbp", "rax", "add rax,rbp", 0},
      {"cmp rax,rbp", "", "cmp rax,rbp", 0},
      {"xchg rax,rbp", "rax", "xchg rax,rbp", 0},
      /* THE DECLARATION IS NOT A WRITE, half two: rbp and rsp named in the
       * clobbers set over a body with no instruction writing either. */
      {"declared not written", "rsi,rdi,rbp,rsp", "nop", 0},
      /* THE CONTROL GROUP: the families either side of the two, and one
       * sub-register of family 1, all of which must keep lowering. */
      {"mov rbx", "rbx", "mov rbx,n", 0},
      {"mov rsi", "rsi", "mov rsi,n", 0},
      {"mov rdi", "rdi", "mov rdi,n", 0},
      {"mov eax alias", "rax", "mov eax,n", 0},
  };
  unsigned frame_refused = 0, frame_accepted = 0;
  for (unsigned i = 0; i < sizeof FRAME_CASES / sizeof FRAME_CASES[0]; i++) {
    int n = snprintf(frame, sizeof frame, FRAME_FMT, FRAME_CASES[i].clobbers,
                     FRAME_CASES[i].body);
    if (n <= 0 || (size_t)n >= sizeof frame) {
      failures++;
      fprintf(stderr, "FAIL the %s fixture does not fit\n",
              FRAME_CASES[i].name);
      continue;
    }
    cases++;
    run(&ia, frame, (size_t)n, 0, 0, &ra);
    if (FRAME_CASES[i].want) {
      frame_refused++;
      if (ra.returned != FRAME_CASES[i].want || ra.runtime) {
        failures++;
        fprintf(stderr,
                "FAIL frame %s: `%s` answered %llu (runtime %llu), wanted "
                "E_FRAME %llu at %llu:%llu\n",
                FRAME_CASES[i].name, FRAME_CASES[i].body,
                (unsigned long long)ra.returned,
                (unsigned long long)ra.runtime,
                (unsigned long long)FRAME_CASES[i].want,
                (unsigned long long)ra.line, (unsigned long long)ra.column);
      }
    } else {
      frame_accepted++;
      if (ra.returned != 0 || ra.runtime) {
        failures++;
        fprintf(stderr,
                "FAIL frame %s: `%s` answered %llu (runtime %llu) and wanted "
                "acceptance\n",
                FRAME_CASES[i].name, FRAME_CASES[i].body,
                (unsigned long long)ra.returned,
                (unsigned long long)ra.runtime);
      }
    }
    printf("FRAME %-20s %-14s %s\n", FRAME_CASES[i].name, FRAME_CASES[i].body,
           ra.returned ? "refused" : "accepted");
  }
  /* The counts, for the reason the two loops above print theirs: a loop that
   * matched nothing is indistinguishable from a loop that never ran, and
   * that is the failure this gate spent a wave sitting in. */
  printf("FRAME-SCAN cases=%u refused=%u accepted=%u expected_refused=10\n",
         (unsigned)(sizeof FRAME_CASES / sizeof FRAME_CASES[0]), frame_refused,
         frame_accepted);
  CHECK(frame_refused == 10,
        "ten destinations of rbp or rsp are refused, one per spelling: mov, "
        "the ebp alias, add, pop, pop, push, lea and xchg over both registers");
  CHECK(frame_accepted == 10,
        "ten cases still lower: five frame reads, a declaration with no "
        "write, and four data-register writes either side of the two");

  /* ---- CASE 3b: E_VALUE, 941 — the undefined-name guard, and its control --
   *
   * WHY THIS BLOCK EXISTS, and the measurement is the reason: with the guard
   * at machine_ir.nova's name_value REPLACED by a fabricated value, this gate
   * still answered `checks=225 failures=0 cases=47` — bit for bit the banner
   * it answers with the guard in place. Every fixture in this file happens to
   * name something that IS defined, so no check in it could tell the guard
   * from its absence. That is the shape AGENTS.md calls a SILENT DOOR: a guard
   * that supplies the feeling of coverage while nothing exercises it.
   *
   * The four fixtures below are two PAIRS, and each pair differs by exactly
   * one thing — whether the name the read names is declared in a scope that
   * encloses the read. Nothing else about them moves, so if the guard stops
   * biting, the two "undefined" rows answer 0 and this block goes red.
   *
   * THE VERDICTS ARE NOT INVENTED HERE. Each was measured against the C
   * reference compiler (compiler/c/ntasm/frontend/frontend.c, nt_frontend_compile),
   * which shares no resolver with the Nova one: it answers 301 "unknown name"
   * on both refusal rows and accepts both control rows. machine_ir answering
   * 941 on the first two is therefore AGREEMENT with an independent producer
   * and not a Nova-side coincidence, and 941 is the code the module itself
   * publishes as E_VALUE — read through the same refusal-code function the
   * entry reaches, never as a literal typed in here.
   *
   * NONE OF THE FOUR CONTAINS A DIAMOND `if`. That is deliberate and it is a
   * separate finding, recorded so that this block is not mistaken for a
   * coverage of it: an `if` whose arm is not purely assignments refuses 936
   * E_SHARED on a program the C reference accepts, down to a program carrying
   * no name at all. Naming that here would make every row below answer 936 and
   * the guard would go untested again. */
  {
    static const char GC_FMT[] =
        "module m\n"
        "target x86_64-nexora-none\n"
        "section .text {\n"
        "fn f(in w:u8)->u64\n"
        "effects {}\n"
        "clobbers {} {\n"
        "%s\n"
        "}\n"
        "}\n";
    const uint64_t E_VALUE = 941;
    struct {
      const char *name, *body;
      uint64_t want;
    } const GC_CASES[] = {
        /* undefined: `a` is declared inside one arm and read by another */
        {"undefined, out of scope", "if w>0 {\nlet a:u64=1\n}\nif w>1 {\nlet b:u64=a\n}\nreturn 0\n", E_VALUE},
        /* undefined: a `let` whose initializer reads the name being declared */
        {"undefined, self read", "let a:u64=a\nreturn a\n", E_VALUE},
        /* CONTROL of row one: the same shape, `a` declared where it encloses */
        {"control, declared outside", "let a:u64=1\nif w>1 {\nlet b:u64=a\n}\nreturn 0\n", 0},
        /* CONTROL of row two: the same shape, the initializer reads `a` */
        {"control, declared before", "let a:u64=1\nlet b:u64=a\nreturn b\n", 0},
    };
    unsigned gc_refused = 0, gc_accepted = 0;
    char gc[1024];
    for (unsigned i = 0; i < sizeof GC_CASES / sizeof GC_CASES[0]; i++) {
      int n = snprintf(gc, sizeof gc, GC_FMT, GC_CASES[i].body);
      if (n <= 0 || (size_t)n >= sizeof gc) {
        failures++;
        fprintf(stderr, "FAIL the %s fixture does not fit\n", GC_CASES[i].name);
        continue;
      }
      cases++;
      run(&ia, gc, (size_t)n, 0, 0, &ra);
      if (GC_CASES[i].want) {
        gc_refused++;
        if (ra.returned != GC_CASES[i].want || ra.runtime) {
          failures++;
          fprintf(stderr,
                  "FAIL undefined-name %s: answered %llu (runtime %llu), "
                  "wanted E_VALUE %llu at %llu:%llu\n",
                  GC_CASES[i].name, (unsigned long long)ra.returned,
                  (unsigned long long)ra.runtime,
                  (unsigned long long)GC_CASES[i].want,
                  (unsigned long long)ra.line, (unsigned long long)ra.column);
        }
      } else {
        gc_accepted++;
        if (ra.returned != 0 || ra.runtime) {
          failures++;
          fprintf(stderr,
                  "FAIL undefined-name control %s: answered %llu (runtime "
                  "%llu) and wanted acceptance\n",
                  GC_CASES[i].name, (unsigned long long)ra.returned,
                  (unsigned long long)ra.runtime);
        }
      }
      printf("UNDEF %-28s %s\n", GC_CASES[i].name,
             ra.returned ? "refused" : "accepted");
    }
    printf("UNDEF-SCAN cases=%u refused=%u accepted=%u expected_refused=2\n",
           (unsigned)(sizeof GC_CASES / sizeof GC_CASES[0]), gc_refused,
           gc_accepted);
    CHECK(gc_refused == 2,
          "a name nothing defines is refused E_VALUE 941, the code the module "
          "publishes for a read of something never defined");
    CHECK(gc_accepted == 2,
          "the two controls — the same programs with the name declared in an "
          "enclosing scope — still lower, so the refusal above is the guard "
          "and not the shape");
  }

  /* ---- CASE 4: the operand form of a binding name, and the mixed `mov` --- */
  /* A BINDING NAME is a fourth operand form, distinct from a register, a
   * typed memory operand and a literal, and spec/ntasm/ntasm.md 6.1 admits it in one
   * place only: the source position of a `mov`.
   *
   * WHY, WHICH IS THE PART THAT HAD NO GATE. The name reaches a machine
   * instruction through the mixed lowering at codegen.c:984-1015, which
   * evaluates the source into RAX (1008), parks RAX in a snapshot slot
   * (1010-1011), RESTORES RAX (1012, `restore_expression_rax` loads RAX back
   * from the slot the expression prologue saved it in) and then loads the
   * destination at the destination's own width (1014-1015). The restore is
   * what makes the sequence sound, and it is also the whole of why the
   * sequence can only IMPLEMENT AN ASSIGNMENT: the destination's old value is
   * gone by the time the destination is written. For `add rax, answer` the
   * destination is also a source, so the same sequence computes
   * `rax = answer` and calls it an addition. The knowledge that the form is
   * `mov` therefore has to live somewhere, and until this case it lived in two
   * `strcmp(s->name, "mov")` tests in the C tree (frontend.c:5427 and
   * codegen.c:984) and NOWHERE in the Nova tree at all: `instruction` in
   * machine_ir.nova resolved a name operand through `expr` exactly as it
   * resolved a register, so the mixed form and the form that would be unsound
   * lowered to the same `mir_asm` with the same two values.
   *
   * WHERE THE REFUSAL LIVES, PINNED. It is at THIS level, in `instruction`,
   * and not upstream: the C oracle refuses the same shapes one pass earlier,
   * in `verify_statement`, and this gate runs the Nova pipeline's own answer
   * for the same source text. Both verdicts are printed for every row, so a
   * future divergence is a number in the log rather than a claim in a comment.
   *
   * THE ORACLE IS ASKED, NOT ASSUMED. Every row below is handed to
   * `nt_frontend_compile` and to `nt_codegen_x64` as well as to this pipeline,
   * and the check is that the two agree on WHETHER the form lowers at all. A
   * row whose oracle verdict moves is a red here for the reason it should be
   * one: the table was written from a reading and the reading was wrong.
   *
   * THE ORDER OF THE TWO REFUSALS IS A CHOICE AND IT IS STATED. `add rbp, n`
   * is refused by BOTH rules, and this gate answers E_FRAME for it, because
   * the frame rule is checked first and is the one already anchored by the
   * case above. The oracle reaches the opposite order (400 for the form before
   * 503 for the frame). Both are refusals either way, so the order decides
   * only which code a reader sees, and the anchored one wins. */
  static const char FORM_FMT[] =
      "module m\n"
      "target x86_64-nexora-none\n"
      "section .text {\n"
      "fn f()->u64\n"
      "effects {}\n"
      "clobbers {%s} {\n"
      "let n:u64=7\n"
      "%s\n"
      "return n\n"
      "}\n"
      "}\n";
  /* E_FORM, 948. It is a literal for the same reason E_FRAME above is: the
   * entry fixture publishes the opcode vocabulary through mode 7 and no
   * refusal code at all, so there is no channel to read 948 back through. The
   * tie is the band and the distinctness, both checked below: machine_ir.nova
   * owns 930..948 exclusively, its last published code before this one was
   * E_FRAME at 947, and 948 is asserted to be none of the four codes this
   * module already uses for a refusal a name operand could otherwise reach --
   * 940 (E_INPUT, a mnemonic outside the vocabulary), 934 (E_SHAPE), 941
   * (E_VALUE, a read of something never defined) and 947 (E_FRAME). */
  const uint64_t E_FORM = 948;
  struct {
    const char *name, *clobbers, *body;
  } const FORM_CASES[] = {
      /* THE MIXED FORM, four spellings of a legal destination, two of them
       * parenthesised. The parenthesised pairs are here because the rule has
       * to look THROUGH the wrapper, and the reason is measured rather than
       * assumed: a predicate that keyed on the node kind was tried and fired
       * on nothing at all, because primary() wraps every bare operand name in
       * an expression node and so ALL FOURTEEN refusals vanished together. The
       * parentheses are not a separate bypass to defend against; the wrapper
       * on the unparenthesised rows is the same wrapper. */
      {"mov reg,name", "rax", "mov rax, n"},
      {"mov other reg", "rbx", "mov rbx, n"},
      {"mov reg,(name)", "rax", "mov rax, (n)"},
      {"mov reg,(name) 2", "rbx", "mov rbx, (n)"},
      /* THE THREE OTHER LEGAL FORMS of a position, as the control group. */
      {"mov reg,reg", "rax", "mov rax, rbx"},
      {"mov reg,imm", "rax", "mov rax, 1"},
      {"mov other,imm", "rsi", "mov rsi, 7"},
      {"mov data-family", "rdi", "mov rdi, n"},
      {"no operand", "", "nop"},
      {"two regs", "rcx", "mov rcx, rsi"},
      /* THE ARITHMETIC GROUP, whose destination is also a source. Every one of
       * these is where the mixed lowering would be unsound rather than merely
       * unimplemented. */
      {"add reg,name", "rax", "add rax, n"},
      {"sub reg,name", "rax", "sub rax, n"},
      {"cmp reg,name", "", "cmp rax, n"},
      {"test reg,name", "", "test rax, n"},
      {"and reg,name", "rax", "and rax, n"},
      {"xor reg,name", "rax", "xor rax, n"},
      {"xchg reg,name", "rax", "xchg rax, n"},
      {"lea reg,name", "rax", "lea rax, n"},
      /* THE SAME RULE THROUGH THE WRAPPER. Not a bypass of its own -- see the
       * note above the four `mov` rows -- but it is the row that shows the
       * rule is looking through a wrapper and not merely at a node kind, and
       * it is the only refusal row whose spelling differs from its siblings
       * by anything other than the mnemonic. */
      {"add reg,(name)", "rax", "add rax, (n)"},
      /* THE NAME IN DESTINATION POSITION. `mov`'s case is a SOURCE case; a
       * name in position zero is a fourth thing the position cannot hold, and
       * the oracle refuses it with the same 400. */
      {"mov name,reg", "rax", "mov n, rax"},
      {"mov name,name", "rax", "mov n, n"},
      {"mov (name),reg", "rax", "mov (n), rax"},
      /* THE UNARY FORMS, whose only operand IS position zero. */
      {"push name", "rax", "push n"},
      {"pop name", "rax", "pop n"},
  };
  char form[1024];
  unsigned form_refused = 0, form_accepted = 0, form_agree = 0;
  for (unsigned i = 0; i < sizeof FORM_CASES / sizeof FORM_CASES[0]; i++) {
    int n = snprintf(form, sizeof form, FORM_FMT, FORM_CASES[i].clobbers,
                     FORM_CASES[i].body);
    if (n <= 0 || (size_t)n >= sizeof form) {
      failures++;
      fprintf(stderr, "FAIL the %s fixture does not fit\n",
              FORM_CASES[i].name);
      continue;
    }
    /* The oracle's own two answers on this exact text. */
    NtFInput in = {"form.nova", form, (size_t)n};
    NtFProgram oracle;
    memset(&oracle, 0, sizeof oracle);
    int oracle_ok = nt_frontend_compile(&in, 1, &oracle);
    unsigned oracle_code = oracle_ok || !oracle.diagnostic_count
                               ? 0u
                               : oracle.diagnostics[0].code;
    int oracle_lowered = -1;
    if (oracle_ok) {
      NtCodeImage img;
      memset(&img, 0, sizeof img);
      oracle_lowered = nt_codegen_x64(&oracle, &img, NULL) == 0;
      nt_code_image_free(&img);
    }
    uint64_t oracle_fp = 0;
    for (size_t f = 0; oracle_ok && f < oracle.function_count; f++)
      oracle_fp |= oracle.functions[f].write_footprint & 0xffffu;
    nt_frontend_free(&oracle);
    cases++;
    /* MODE 0, THE WHOLE PIPELINE, and not mode 4. Mode 4 lowers from the NTIR
     * image ALREADY in the buffer and never parses, so a caller that has not
     * run mode 2 first hands it whatever was left in the buffer and reads a
     * refusal about a node that is not in this program at all. The first
     * version of this case did exactly that and answered E_VALUE 941 at the
     * `7` of the fixture on all twenty-four rows, which is the shape of a gate
     * that measures the wrong thing and still prints a table. */
    run(&ia, form, (size_t)n, 0, 0, &ra);
    int pipeline_ok = (ra.returned == 0 && ra.runtime == 0);
    /* THE ASSERTION. The two levels must agree on whether the form lowers, and
     * when it does not, this level must answer E_FORM. A pipeline that is
     * WEAKER than the oracle here is the defect this case was written for, and
     * a pipeline that is STRICTER is the same finding with the sign flipped, so
     * neither passes silently. */
    checks++;
    if (pipeline_ok != (oracle_ok != 0)) {
      failures++;
      fprintf(stderr,
              "FAIL form %s: `%s` the oracle says %s (code %u, lowered %d) and "
              "the pipeline says %s (code %llu at %llu:%llu)\n",
              FORM_CASES[i].name, FORM_CASES[i].body,
              oracle_ok ? "ACCEPT" : "REFUSE", oracle_code, oracle_lowered,
              pipeline_ok ? "ACCEPT" : "REFUSE",
              (unsigned long long)ra.returned,
              (unsigned long long)ra.line, (unsigned long long)ra.column);
    } else {
      form_agree++;
    }
    if (!pipeline_ok) {
      form_refused++;
      checks++;
      if (ra.returned != E_FORM) {
        failures++;
        fprintf(stderr,
                "FAIL form %s: `%s` was refused with %llu, and the operand form "
                "is what refuses it, so it must answer E_FORM %llu at "
                "%llu:%llu\n",
                FORM_CASES[i].name, FORM_CASES[i].body,
                (unsigned long long)ra.returned, (unsigned long long)E_FORM,
                (unsigned long long)ra.line, (unsigned long long)ra.column);
      }
    } else {
      form_accepted++;
    }
    printf("FORM %-18s %-16s oracle=%-6s code=%3u lowered=%d fp=0x%04llx "
           "pipeline=%s %llu\n",
           FORM_CASES[i].name, FORM_CASES[i].body,
           oracle_ok ? "ACCEPT" : "REFUSE", oracle_code, oracle_lowered,
           (unsigned long long)oracle_fp,
           pipeline_ok ? "accepted" : "refused",
           (unsigned long long)ra.returned);
  }
  printf("FORM-SCAN cases=%u agreed=%u refused=%u accepted=%u "
         "expected_refused=14\n",
         (unsigned)(sizeof FORM_CASES / sizeof FORM_CASES[0]), form_agree,
         form_refused, form_accepted);
  CHECK(form_agree == sizeof FORM_CASES / sizeof FORM_CASES[0],
        "the pipeline and the C oracle agree, row for row, on whether each of "
        "these operand forms lowers");
  CHECK(form_refused == 14,
        "fourteen rows are refused: eight arithmetic destinations that are also "
        "sources, the parenthesised bypass of the same rule, three names in "
        "destination position and the two unary forms");
  CHECK(form_accepted == 10,
        "ten rows still lower: four spellings of the mixed mov and the five "
        "other legal operand forms");
  /* The code has to be one a reader can tell apart from the four this module
   * already uses, or the count above would pass on the wrong refusal. */
  CHECK(E_FORM != 940 && E_FORM != 934 && E_FORM != 941 && E_FORM != 947,
        "E_FORM is distinguishable from E_INPUT, E_SHAPE, E_VALUE and "
        "E_FRAME, so a refused row is refused for the operand form");

  /* ---- CASE 4b: THE FOOTPRINT HALF, MEASURED ----------------------------- */
  /* nt_x64_effects (x64.h:114, x64.c:838) publishes the architectural
   * footprint of ONE EXACT VALIDATED OPERAND FORM, and it derives it from the
   * operand list alone. It therefore cannot see a register the LOWERING
   * touches and the source did not declare. That is not a criticism of the
   * oracle; it is the shape of the question. What it means for this case is
   * that the mixed lowering's scratch is invisible by construction, and the
   * only thing standing between that and a wrong `write_footprint` is the
   * RESTORE at codegen.c:1012.
   *
   * SO THIS IS ASKED BOTH WAYS, which is the only way a "the bit is clear"
   * check is worth anything. The invisible arm uses a destination that is NOT
   * rax; the declared arm uses one that is. If the oracle ever began charging
   * a scratch, the first arm goes red and this comment becomes false, which is
   * the point of asking at run time instead of writing `CLEAR` down. The two
   * arms are independent queries over different operand lists, so neither is
   * reading the other's answer.
   *
   * AND IT WAS BROKEN ON PURPOSE AND SEEN RED. The first row's destination was
   * moved from rcx to rax, which is the only change that can make the claim
   * false, and BOTH checks below went red together: the invisible count fell
   * to one and the declared count rose to three. A check that only counted
   * "invisible" could not have told, which is the whole reason the second
   * check is here and not decoration.
   *
   * WHAT IT DOES NOT REACH, said plainly: nothing here observes the emitted
   * bytes, so this case cannot tell a lowering that restores RAX from one that
   * does not. It measures the BLINDNESS, which is a property of the footprint
   * question, and the restore stays a fact about codegen.c:1012 that a reader
   * of this comment has to go and check. */
  static const NtX64Context ORACLE_CTX = {NT_X64_ALL_FEATURES, 0};
  unsigned scratch_invisible = 0, scratch_declared = 0;
  {
    struct {
      const char *mnemonic, *label;
      unsigned dest, src;
    } const rows[] = {
        {"mov", "pure assignment", 1, 3},  /* rcx, rbx: rax is not declared */
        {"add", "destination is a source", 1, 3},
        {"mov", "pure assignment, rax", 0, 3},  /* rax IS declared here */
        {"add", "destination is a source, rax", 0, 3},
    };
    for (unsigned i = 0; i < sizeof rows / sizeof rows[0]; i++) {
      NtX64Operand ops[2];
      memset(ops, 0, sizeof ops);
      for (unsigned k = 0; k < 2; k++) {
        ops[k].kind = NT_X64_REG;
        ops[k].width = 64;
        ops[k].reg = k ? rows[i].src : rows[i].dest;
      }
      NtX64Effects fx;
      memset(&fx, 0, sizeof fx);
      unsigned refused = nt_x64_effects(rows[i].mnemonic, ops, 2, ORACLE_CTX,
                                         &fx) != NT_X64_OK;
      int sees_rax = (fx.registers_written & 1u) != 0; /* bit 0 is rax */
      checks++;
      if (refused) {
        failures++;
        fprintf(stderr, "FAIL scratch %s: nt_x64_effects refuses the form, so "
                        "the probe is measuring nothing\n",
                rows[i].label);
      } else if (sees_rax) {
        scratch_declared++;
      } else {
        scratch_invisible++;
      }
      printf("SCRATCH %-12s %-28s dest=%u src=%u written=0x%04llx rax=%s\n",
             rows[i].mnemonic, rows[i].label, rows[i].dest, rows[i].src,
             (unsigned long long)fx.registers_written,
             sees_rax ? "DECLARED" : "INVISIBLE");
    }
  }
  CHECK(scratch_invisible == 2,
        "with a destination that is not rax, the footprint the oracle "
        "publishes cannot see rax, so a lowering that used it as a scratch "
        "would under-declare");
  CHECK(scratch_declared == 2,
        "with rax as the destination the same query declares it, so the two "
        "arms are discriminating and the first is not vacuous");

  /* ---- CASE 7: THE VERSIONS RECORD -- ITS COUNT AND ITS PIN -------------
   *
   * machine_ir.nova's `versions_of` builds a kind-2050 record whose `aux` is
   * the number of entries in the source's `versions` block and whose `aux2`
   * is a pin built from the version that block declares for the machine_ir
   * domain. Its comment promises that "the gate confronts aux2 with this
   * module's FORMAT_MAJOR and FORMAT_MINOR and with versions.check's own
   * verdict on the same block". The second half of that is the half that can
   * be built and it is built here. The FIRST HALF CANNOT BE, and the reason is
   * measured rather than argued, so it is stated where a reader will meet it:
   *
   *   `aux2` is built from the version the SOURCE declares. `version_pin()` is
   *   this module's own FORMAT_MAJOR*100+FORMAT_MINOR. They are not the same
   *   quantity and they are not equal: on a source declaring all six domains
   *   at 0.1, aux2 is 102 and version_pin() is 2. A gate written on the first
   *   half of that sentence would therefore be red on every correct image and
   *   green on none -- which is worse than the tautology it was meant to
   *   replace, because a permanently red gate is one nobody reads. The
   *   corrected comment is HELD, not applied; machine_ir.nova is not this
   *   lot's to edit.
   *
   * WHY A VERSIONS BLOCK AT ALL, and this is measured rather than stylistic.
   * Every other case in this file runs on CORPUS, which carries no versions
   * block, and on CORPUS the lowering emits ZERO kind-2050 records. A check
   * written against the field on that corpus would have been reading a word
   * nobody wrote and comparing it -- or the 0xcccccccc guard this file fills
   * its buffers with -- against an expectation. The fixtures below carry the
   * block, and the first CHECK is what stops the arms after it from passing
   * on an absent datum.
   *
   * THE TWO READERS ARE NOT THE SAME THING, which is what makes each arm
   * worth having:
   *
   *   aux/entries  machine_ir.nova counts by walking NTIR RECORDS (nindex,
   *                nfirst, nnext) over the image the lowering was handed;
   *                versions.nova counts by walking the AST (node_at,
   *                first_child, next_sibling) over its own parse of the same
   *                text. Two modules, two data structures, one fact. A span
   *                that drifts between the AST and the NTIR moves one count
   *                and not the other, and that is a red here.
   *
   *   aux2/major   versions_of builds the pin out of `scale_of`, which is
   *                `read_magnitude` over the source SPAN the parser recorded;
   *                versions.check reads `major` off the AST node's own aux
   *                word and PUBLISHES it, in its third output word, on the
   *                348 refusal. Same version, two routes, and the routes can
   *                disagree.
   *
   * Neither side is read back out of the module that computed it, which is
   * the property that separates these arms from the header self-checks this
   * lot started from: parse and serialize both compare the image against the
   * constants of the module that just wrote it, so no version change can
   * fail them and none can wrongly pass. */
  cases++;
  {
    /* The six domains of spec/ntasm/ntasm.md 17.1, and ONLY the machine_ir version
     * varies between the three fixtures. The block sits AFTER `target`
     * because source_tree reads the module and the target first and only then
     * loops over the remaining top-level declarations; the first version of
     * this fixture put it first and mode 2 answered 800, which says nothing
     * about why, so the position is a measured requirement and not a style. */
    static const char V_FMT[] =
        "module m\n"
        "target x86_64-nexora-none\n"
        "versions {\n"
        "ntir 0.1\n"
        "machine_ir %s\n"
        "sections 0.1\n"
        "symbols 0.1\n"
        "relocations 0.1\n"
        "nxo 0.1\n"
        "}\n"
        "section .text {\n"
        "fn helper(in a:u64, in b:u64)->u64\n"
        "effects {}\n"
        "clobbers {} {\n"
        "return a+b\n"
        "}\n"
        "fn main(in w:u8)->u64\n"
        "effects {}\n"
        "clobbers {rax} {\n"
        "let n:u64=w\n"
        "nop\n"
        "mov rax, n\n"
        "add rax, 1\n"
        "return rax\n"
        "}\n"
        "}\n";
    /* THE POPULATION: one row per DISTINCT declared machine_ir version this
     * case hands the module, and the bound is DERIVED from the table rather
     * than written beside it. That derivation is the whole of this edit's
     * structural half: the table and the bound were two hand-maintained
     * numbers that agreed by coincidence, so a fourth declared version could
     * have been appended to the table and read by no arm below. `PATHS_N` is
     * the same idiom already used at the top of this file.
     *
     * WHAT THE NUMBER IS, because "4" is not a bound, it is a count. The rows
     * are the distinct OUTCOME CLASSES of the pin arithmetic that the
     * declaring literal is able to select, enumerated from the two
     * predicates the mechanism actually has rather than from a wish for a
     * larger number:
     *   0.1                   minor reads nonzero, major reads nonzero
     *   0.2                   the minor moves, the major does not
     *   1.1                   the major moves, the minor does not
     *   0.18446744073709551615
     *                         the minor is the u64 maximum, so the magnitude
     *                         the pin arm tests is value+1 and that successor
     *                         WRAPS TO ZERO. This is the only class the first
     *                         three cannot reach, and it is the class in
     *                         which the arm at versions_of does not fire at
     *                         all -- so before this row every fixture the
     *                         arms below read was a fixture whose arm FIRED.
     * Every declared version the module can be asked to encode falls in one
     * of these four classes, so four rows IS the population the module can
     * produce, not a sample of it. */
    static const char *const V_DECL[] = {"0.1", "0.2", "1.1",
                                         "0.18446744073709551615"};
#define V_DECL_N ((unsigned)(sizeof V_DECL / sizeof V_DECL[0]))
    char vbuf[V_DECL_N][1024];
    uint64_t v_seen[V_DECL_N] = {0}, v_aux[V_DECL_N] = {0},
             v_aux2[V_DECL_N] = {0}, v_verdict[V_DECL_N] = {0},
             v_entries[V_DECL_N] = {0}, v_major[V_DECL_N] = {0};
    unsigned prepared = 0;
    for (unsigned i = 0; i < V_DECL_N; i++) {
      int n = snprintf(vbuf[i], sizeof vbuf[i], V_FMT, V_DECL[i]);
      if (n <= 0 || (size_t)n >= sizeof vbuf[i]) {
        failures++;
        fprintf(stderr, "FAIL the versions fixture %u does not fit\n", i);
        continue;
      }
      prepared++;
      /* mode 2 builds the NTIR and mode 4 lowers it WITHOUT verifying, so what
       * is read below is the producer's own output rather than something a
       * verifier could have blessed on the way past.
       *
       * BOTH THROUGH `rb`, and that is not tidiness. mode 4 reads its NTIR out
       * of the SAME buffer mode 2 wrote -- the entry's fifth parameter is the
       * same handle either way -- so splitting them across two Runs hands the
       * lowering an image that was never built and it answers 940 E_INPUT.
       * The first version of this case did exactly that and reported two
       * fixtures that "do not lower", which reads like a producer defect and
       * is an argument-count error in the harness instead. */
      run(&ia, vbuf[i], (size_t)n, 2, 0, &rb);
      if (rb.returned != 0) {
        failures++;
        fprintf(stderr,
                "FAIL versions fixture %u builds no NTIR image (ret=%llu)\n", i,
                (unsigned long long)rb.returned);
        continue;
      }
      run(&ia, vbuf[i], (size_t)n, 4, 0, &rb);
      if (rb.returned != 0) {
        failures++;
        fprintf(stderr, "FAIL versions fixture %u does not lower (ret=%llu)\n",
                i, (unsigned long long)rb.returned);
        continue;
      }
      for (uint64_t rec = 1; rec <= n_records(&rb); rec++) {
        if (W(&rb, rec, 0) != k_versions)
          continue;
        v_seen[i]++;
        v_aux[i] = W(&rb, rec, 14);
        v_aux2[i] = W(&rb, rec, 15);
      }
      /* mode 6 is the entry's ORACLE probe; it runs versions.nova's own check
       * over the AST of this same source and publishes the verdict in
       * report[23], the second output word in report[25] and the third in
       * report[26]. */
      run(&ia, vbuf[i], (size_t)n, 6, 1, &rc);
      v_verdict[i] = rc.report[23];
      v_entries[i] = rc.report[25];
      v_major[i] = rc.report[26];
      printf("VERSIONS declared=%-4s records=%llu aux_entries=%llu aux2_pin=%llu "
             "check_verdict=%llu check_out1=%llu check_out2=%llu\n",
             V_DECL[i], (unsigned long long)v_seen[i],
             (unsigned long long)v_aux[i], (unsigned long long)v_aux2[i],
             (unsigned long long)v_verdict[i],
             (unsigned long long)v_entries[i],
             (unsigned long long)v_major[i]);
    }
    CHECK(prepared == V_DECL_N,
          "every declared version fixture builds and lowers");

    /* THE POPULATION, asserted before a single word is read out of it. Every
     * source that carries a versions block must yield EXACTLY ONE kind-2050
     * record: zero would leave every arm below comparing a sentinel against an
     * expectation, and two would mean the scan is matching some record other
     * than the one it names. The loop covers EVERY row rather than three
     * named indices, because a row added to the table is a row whose record
     * count this check must also speak to. */
    unsigned v_one_record_each = 1;
    for (unsigned i = 0; i < V_DECL_N; i++) {
      if (v_seen[i] != 1) {
        v_one_record_each = 0;
      }
    }
    CHECK(v_one_record_each,
          "a source carrying a versions block lowers to exactly one versions "
          "record, so the arms below read a written field and not a guard");

    /* ARM ONE -- cross-producer on the entry count. versions.nova admits the
     * all-0.1 block, so its second output word is a count and not a column,
     * and the count it publishes must be the count machine_ir.nova wrote into
     * the image. Two modules, two structures, one fact. */
    CHECK(v_verdict[0] == 0,
          "the source declaring all six domains at 0.1 is the one "
          "versions.check admits, so its count is a count");
    CHECK(v_aux[0] != 0 && v_aux[0] == v_entries[0],
          "the versions record's entry count is the count versions.check "
          "publishes for the same block");

    /* ARM TWO -- the pin is not a constant. The sources differ in one declared
     * version and in nothing else, so a writer that stamped a fixed number, or
     * that read the wrong entry, repeats a value here and would pass every
     * other check in this file. ALL PAIRS, over the whole table: three named
     * pairwise comparisons covered three rows and would have kept covering
     * three after a fourth was added, which is the same vacuity the loop
     * bound above had. */
    unsigned v_pins_distinct = 1;
    for (unsigned i = 0; i < V_DECL_N; i++) {
      for (unsigned j = i + 1; j < V_DECL_N; j++) {
        if (v_aux2[i] == v_aux2[j]) {
          v_pins_distinct = 0;
        }
      }
    }
    CHECK(v_pins_distinct,
          "the pin follows the version the source declares, so it is a "
          "computed field and not a constant wearing a version's name");

    /* ARM THREE -- cross-producer on the version itself. On the fixtures
     * versions.check REFUSES with 348 it publishes the offending major in its
     * third output word, and mode 6 hands that back as report[26]. The pin
     * carries the same major. `read_magnitude` answers value+1, so the pin's
     * hundred digit is the major's successor; the decode subtracts one and is
     * WRITTEN DOWN here so that a change to that convention is a red on this
     * line rather than a silent agreement between two shifted numbers. */
    for (unsigned i = 1; i < V_DECL_N; i++) {
      if (v_verdict[i] != 348) {
        failures++;
        fprintf(stderr,
                "FAIL versions fixture %u: expected versions.check to refuse it "
                "with 348 and it answered %llu, so there is no published major "
                "to confront the pin with\n",
                i, (unsigned long long)v_verdict[i]);
        continue;
      }
      checks++;
      /* A pin below 101 cannot carry a major at all: the smallest legal
       * encoding is (0+1)*100+(0+1). Decoding one anyway wraps an unsigned
       * subtraction to 18446744073709551615, which is a true red wearing a
       * number that hides its cause -- and a producer that had stopped
       * computing the pin and started stamping version_pin() is exactly the
       * defect this arm exists to name, so it gets named. */
      if (v_aux2[i] < 101) {
        failures++;
        fprintf(stderr,
                "FAIL versions fixture %u: the image's pin is %llu, which "
                "carries no major at all -- the smallest encoding is 101 -- so "
                "the field is not carrying the version versions.check reports "
                "(major %llu)\n",
                i, (unsigned long long)v_aux2[i],
                (unsigned long long)v_major[i]);
        continue;
      }
      uint64_t decoded_major = v_aux2[i] / 100 - 1;
      if (decoded_major != v_major[i]) {
        failures++;
        fprintf(stderr,
                "FAIL versions fixture %u: the image's pin %llu decodes to major "
                "%llu and versions.check publishes major %llu\n",
                i, (unsigned long long)v_aux2[i],
                (unsigned long long)decoded_major,
                (unsigned long long)v_major[i]);
      }
    }
    printf("VERSIONS-PIN module_pin=%llu source_pin_0.1=%llu "
           "pin_equals_module_pin=%d\n",
           (unsigned long long)version_pin_of_gate,
           (unsigned long long)v_aux2[0],
           v_aux2[0] == version_pin_of_gate);
  }

  /* ---- CASE 5: THE FORMAT TAG ------------------------------------------ */
  /* `header_text` is written down in EXPECTED_TAG above and compared here
   * against the bytes `machine_ir.serialize` produced. Mode 1 is the whole
   * pipeline and then the serialization, so the bytes read below are the
   * module's own output and not something this file composed.
   *
   * BOTH IMAGES, because a single sample of a module interpreted into a host
   * image is one sample, and this file already compiles the sources twice on
   * purpose. The tag is compared on each separately, so a disagreement
   * between the two is a red naming which one.
   *
   * THE POPULATION IS ASSERTED BEFORE THE BYTES ARE READ. `ra.text_len` is 0
   * when the entry refused and the buffer is still the 0xcc fill, and a
   * memcmp over a guard is a comparison of two absences that happens to
   * agree. So the length is checked first and the tag comparison is only
   * reached when there is a byte count to compare against.
   *
   * THE COMPARISON IS THE SEVEN BYTES, not the whole line: `serialize` writes
   * the tag and then " records=N ...", so the tag is a PREFIX of the first
   * line and not the line. That is the form tests_ntasm_ntir.c uses. */
  cases++;
  {
    size_t tlen = strlen(CORPUS);
    size_t want = strlen(EXPECTED_TAG);
    /* The count of arms that actually reached the comparison and agreed, so
     * the line below reports a measurement rather than a constant. */
    unsigned compared = 0;
    Run *two[2];
    two[0] = &ra;
    two[1] = &rb;
    for (unsigned k = 0; k < 2; k++) {
      run(k == 0 ? &ia : &ib, CORPUS, tlen, 1, 0, two[k]);
      if (two[k]->returned != 0 || two[k]->runtime != 0) {
        failures++;
        fprintf(stderr,
                "FAIL the corpus does not serialize on the %s image "
                "(ret=%llu runtime=%llu), so there are no tag bytes to "
                "compare and this case measured nothing\n",
                k == 0 ? "first" : "second",
                (unsigned long long)two[k]->returned,
                (unsigned long long)two[k]->runtime);
        continue;
      }
      checks++;
      if (two[k]->text_len < want) {
        failures++;
        fprintf(stderr,
                "FAIL the serialization on the %s image is %zu bytes and the "
                "tag is %zu, so the tag is not fully present to compare\n",
                k == 0 ? "first" : "second", two[k]->text_len, want);
        continue;
      }
      /* `checks++` runs whether or not the comparison holds, because a
       * counter that only moves on the passing branch is a counter whose
       * value depends on the answer and a reader cannot tell an arm that
       * failed from an arm that was never reached. */
      checks++;
      if (memcmp(two[k]->text, EXPECTED_TAG, want) != 0) {
        failures++;
        fprintf(stderr,
                "FAIL the serialization on the %s image begins [%.*s] and "
                "this file pins [%s]\n",
                k == 0 ? "first" : "second", (int)want,
                (const char *)two[k]->text, EXPECTED_TAG);
      } else {
        compared++;
      }
    }
    /* `compared` is counted, not asserted, and printed beside the
     * expectation: a line reading `measured_on_both=1` typed here would read
     * the same on a run where both arms were skipped. */
    printf("TAG pinned=%s images=2 compared=%u\n", EXPECTED_TAG, compared);
  }

  /* WHAT THIS DOES NOT MEASURE, and it is the half that a reader of the
   * header comment above would otherwise assume. The tag is a string
   * literal and FORMAT_MINOR is a number; nothing in the module joins them.
   * Raising FORMAT_MINOR alone leaves EXPECTED_TAG satisfied and this gate
   * GREEN, and that was measured: the mutation and its green run are in the
   * lot's record. So the claim this case makes is about the seven bytes and
   * nothing else -- it does not establish that the tag tracks the version. */

  /* ---- CASE 8: THE ATTRIBUTION ORDER, READ OUT OF THE IMAGE -------------
   *
   * WHAT machine_ir.nova's header asks for, verbatim: "ATTRIBUTION ORDER IS A
   * PROPERTY OF THE IMAGE, NOT OF THE TRAVERSAL. Records are emitted in NTIR
   * traversal order, so the sequence of FIRST attributions over the image is
   * strictly increasing in NTIR node id. A node dropped leaves a hole in the
   * sequence, a node duplicated claims it twice in a row, and a reordering
   * moves a first attribution backwards; the gate reads the sequence out of
   * the image and compares it with the sequence the NTIR admits."
   *
   * THE TWO SIDES, and they are NOT the same thing.
   *
   *   SIDE A, THE IMAGE.  The attribution of every record, read out of the
   *   lowered image's own words: word 1 (`ntir_node`) when it is set, word 18
   *   (`origin`) otherwise.  Every element of Side A was written by
   *   machine_ir.nova's `emit`.
   *
   *   SIDE B, THE NTIR.  The NTIR image's own structure -- the parent of
   *   every node, read by walking the NTIR image's `first` (word 8) and
   *   `next` (word 10) links, which ntir.nova wrote and machine_ir.nova only
   *   reads -- and, through the entry's mode-6 probe, machine_ir's own
   *   `admits` answer per node, which the probe obtains by re-parsing the
   *   source and rebuilding the NTIR itself.
   *
   *   WHY THEY ARE NOT THE SAME THING.  Side A is an ORDER over records, and
   *   it exists only because the traversal called `emit` in the order it did.
   *   Side B is a SET of relations over NTIR nodes, and it is the same set
   *   whatever order the traversal emitted in -- it is computable with
   *   machine_ir.nova deleted.  So a perturbation of `unit`, `callable`,
   *   `body` or `stmt` moves Side A and cannot move Side B, which is exactly
   *   what makes every arm below able to go red.  An expectation built from
   *   Side A would move with the traversal and could not fail.
   *
   * THREE FIXTURES, because one program cannot tell an ordering rule from a
   *   coincidence about one program.  CORPUS carries a binary expression, so
   *   it has records emitted AFTER the operands they belong to; ATTR_DIAMOND
   *   carries two `let`s inside two arms of an `if`, so it has the same shape
   *   twice and in two different blocks; ATTR_ZERO is nine records and a
   *   single return, so a rule that only holds on a large image is visible.
   *
   * MODE 4, NOT MODE 0.  Mode 4 lowers without verifying, so what is read
   *   below is the producer's own output and not something `verify` could
   *   have blessed on the way past.  Mode 2 writes the NTIR and mode 4 reads
   *   it out of the SAME Run's buffer, so the two stages go to `rc` together
   *   while `rb` keeps the NTIR image the checks below read -- the argument
   *   case 7 already records for the same reason.  The mode-6 probes go to
   *   `ra` and `rd` and never to `rb`, because a probe rebuilds the NTIR into
   *   the Run it is given and would replace the image Side B is read from. */
  cases++;
  {
    static const char ATTR_ZERO[] =
        "module m\n"
        "target x86_64-nexora-none\n"
        "section .text {\n"
        "export fn main()->u64\n"
        "effects {}\n"
        "clobbers {} {\n"
        "return 0\n"
        "}\n"
        "}\n";
    static const char ATTR_DIAMOND[] =
        "module m\n"
        "target x86_64-nexora-none\n"
        "section .text {\n"
        "fn f(in w:u8)->u64\n"
        "effects {}\n"
        "clobbers {rax,rsi} {\n"
        "let a:u64=1\n"
        "if w>0 {\n"
        "let b:u64=a+2\n"
        "mov rsi,b\n"
        "}\n"
        "else {\n"
        "let c:u64=a*3\n"
        "mov rsi,c\n"
        "}\n"
        "return rsi\n"
        "}\n"
        "}\n";
    /* THE EXPECTED GAP IS NOT WRITTEN DOWN HERE ANY MORE, and that is the
     * repair rather than a deletion.  This column carried 12, 14 and 1, and the
     * arm below measured 13, 16 and 1 on this tree: the typed figure had
     * stopped describing the thing it was written beside.  The paragraph above
     * it said the gap holds only `name` (47) and `qualified` (48), and named
     * `expr` among the kinds that could never appear in it -- and `expr` (36)
     * is in the gap, one node on CORPUS and two on DIAMOND.  A sentence and a
     * list that disagree are a finding, and here the sentence was the false
     * half.  What replaces the column is a PREDICATE over the kind of every
     * node the gap holds, which is the module's own contract rather than a
     * figure the last run happened to produce; see the arm. */
    struct {
      const char *label, *src;
    } const ATTR_FIXTURES[] = {
        {"CORPUS", CORPUS},
        {"DIAMOND", ATTR_DIAMOND},
        {"ZERO", ATTR_ZERO},
    };
    for (unsigned f = 0; f < sizeof ATTR_FIXTURES / sizeof ATTR_FIXTURES[0];
         f++) {
      const char *src = ATTR_FIXTURES[f].src;
      size_t slen = strlen(src);
      run(&ia, src, slen, 2, 0, &rb);
      CHECK(rb.returned == 0,
            "an attribution fixture builds an NTIR image");
      run(&ia, src, slen, 2, 0, &rc);
      run(&ia, src, slen, 4, 0, &rc);
      CHECK(rc.returned == 0, "an attribution fixture lowers");
      uint64_t nodes = rb.words[3];
      uint64_t n = n_records(&rc);
      /* THE POPULATION, asserted before a single word is read out of either
       * side.  An absent datum is not a zero: a zero-record image would make
       * every arm below vacuously true, and the arms that PRINT would print
       * a count of nothing as though it were a measurement. */
      CHECK(nodes > 0 && n > 0,
            "the fixture has an NTIR and a lowered image to compare");
      if (nodes == 0 || n == 0)
        continue;
      ntir_nodes = nodes;
      uint64_t *first = (uint64_t *)calloc(nodes + 1, sizeof(uint64_t));
      uint64_t *last = (uint64_t *)calloc(nodes + 1, sizeof(uint64_t));
      uint64_t *npar = (uint64_t *)calloc(nodes + 1, sizeof(uint64_t));
      uint64_t *attr = (uint64_t *)calloc(n + 1, sizeof(uint64_t));
      uint8_t *claimed = (uint8_t *)calloc(nodes + 1, 1);
      uint8_t *admitted = (uint8_t *)calloc(nodes + 1, 1);
      if (!first || !last || !npar || !attr || !claimed || !admitted) {
        failures++;
        fprintf(stderr, "FAIL attribution %s: the scratch tables did not "
                        "allocate, so the case measured nothing\n",
                ATTR_FIXTURES[f].label);
        free(first); free(last); free(npar); free(attr); free(claimed);
        free(admitted);
        continue;
      }
      /* SIDE B, the NTIR's own parent map, from the NTIR image's own links.
       * ntir.nova wrote them; machine_ir.nova only ever reads them. */
      for (uint64_t id = 1; id <= nodes; id++) {
        uint64_t kid = NW(&rb, id, 8);
        while (kid != 0 && kid <= nodes) {
          npar[kid] = id;
          kid = NW(&rb, kid, 10);
        }
      }
      /* SIDE A, the attribution stream, read out of the image's own words. */
      for (uint64_t rec = 1; rec <= n; rec++) {
        uint64_t node = W(&rc, rec, 1);
        uint64_t origin = W(&rc, rec, 18);
        uint64_t a = node ? node : origin;
        attr[rec] = a;
        if (a == 0 || a > nodes)
          continue;
        if (!claimed[a]) {
          claimed[a] = 1;
          first[a] = rec;
        }
        last[a] = rec;
      }
      /* FOUNDATION, and it is the node-for-node confrontation the header
       * above used to list as absent.  Three checks, and each is a check
       * ABOUT THE PRODUCER'S OWN OUTPUT rather than about this file:
       *
       *   EXACTLY ONE OF `ntir_node` AND `origin`.  The header says never
       *   both and never neither; `verify` refuses both (939) but the arms
       *   below read mode 4's output, which no verifier has blessed, so the
       *   property is measured here rather than assumed.
       *
       *   THE ATTRIBUTED ID IS INSIDE THE NTIR.  An id of 0 or an id past
       *   the NTIR's own count is a claim on a node that does not exist, and
       *   this file's buffers are filled with the 0xcc guard, so a claim that
       *   was never written reads as a number rather than as an absence.
       *
       *   LINE AND COLUMN ARE THE ATTRIBUTED NODE'S OWN.  `emit` copies them
       *   out of the NTIR record of `ntir_node` or `origin`, so this is a
       *   second module's words read back through the first module's copy:
       *   if the attribution is right and the copy is right, both agree with
       *   the NTIR, and a traversal that attributed a record to the wrong
       *   node is named by the record that disagrees. */
      unsigned both = 0, neither = 0, out_of_range = 0, line_col_bad = 0;
      for (uint64_t rec = 1; rec <= n; rec++) {
        uint64_t node = W(&rc, rec, 1);
        uint64_t origin = W(&rc, rec, 18);
        if (node && origin) {
          both++;
          failures++;
          fprintf(stderr,
                  "FAIL attribution %s record %llu carries BOTH ntir_node %llu "
                  "and origin %llu, and the header says never both\n",
                  ATTR_FIXTURES[f].label, (unsigned long long)rec,
                  (unsigned long long)node, (unsigned long long)origin);
          continue;
        }
        if (!node && !origin) {
          neither++;
          failures++;
          fprintf(stderr,
                  "FAIL attribution %s record %llu carries NEITHER ntir_node "
                  "NOR origin, so the record claims nothing\n",
                  ATTR_FIXTURES[f].label, (unsigned long long)rec);
          continue;
        }
        uint64_t a = attr[rec];
        if (a == 0 || a > nodes) {
          out_of_range++;
          failures++;
          fprintf(stderr,
                  "FAIL attribution %s record %llu is attributed to NTIR node "
                  "%llu and the NTIR holds %llu nodes, so the claim names "
                  "nothing\n",
                  ATTR_FIXTURES[f].label, (unsigned long long)rec,
                  (unsigned long long)a, (unsigned long long)nodes);
          continue;
        }
        checks++;
        if (W(&rc, rec, 2) != NW(&rb, a, 2) ||
            W(&rc, rec, 3) != NW(&rb, a, 3)) {
          line_col_bad++;
          failures++;
          fprintf(stderr,
                  "FAIL attribution %s record %llu is attributed to NTIR node "
                  "%llu and carries %llu:%llu where that node stands at "
                  "%llu:%llu\n",
                  ATTR_FIXTURES[f].label, (unsigned long long)rec,
                  (unsigned long long)a, (unsigned long long)W(&rc, rec, 2),
                  (unsigned long long)W(&rc, rec, 3),
                  (unsigned long long)NW(&rb, a, 2),
                  (unsigned long long)NW(&rb, a, 3));
        }
      }
      /* ARM ONE -- POSITIVE, AND THE REORDERED ARM.  The first-attribution
       * sequence, read out of the image in ascending record id, must not go
       * backwards -- with ONE measured exception, which is why this is not
       * the check the header's sentence would give.
       *
       * THE HEADER'S SENTENCE IS REFUTED BY THE TREE, and this is the
       * measurement rather than a reading.  "Strictly increasing in NTIR node
       * id" is FALSE on this module's own CORPUS: record 12 is attributed to
       * NTIR node 33 and record 13 to NTIR node 32, because `expression`
       * lowers the operands of a binary and only then emits the binary's own
       * record, and the operands' ids are lower than the expression's.  A
       * gate written on the literal sentence is RED on a correct image, and a
       * permanently red gate is one nobody reads.
       *
       * WHAT IS TRUE, and what this checks, is the property the header is
       * reaching for: a step back is legal exactly when it lands on an
       * ANCESTOR of the node it left, which is what a depth-first walk that
       * emits a record after its own operands does.  The ancestor test reads
       * Side B -- the NTIR image's parent map -- and never the image's own
       * traversal, so a reordering that moved a first attribution backwards
       * onto a node that is NOT its ancestor is red here. */
      unsigned back_ok = 0, back_bad = 0, firsts = 0;
      uint64_t prev = 0;
      for (uint64_t rec = 1; rec <= n; rec++) {
        uint64_t a = attr[rec];
        if (a == 0 || a > nodes || first[a] != rec)
          continue;
        firsts++;
        if (prev == 0) {
          prev = a;
          continue;
        }
        if (a > prev) {
          prev = a;
          continue;
        }
        if (a == prev) {
          back_bad++;
          failures++;
          fprintf(stderr,
                  "FAIL attribution %s record %llu first-attributes NTIR node "
                  "%llu, which record %llu already attributed\n",
                  ATTR_FIXTURES[f].label, (unsigned long long)rec,
                  (unsigned long long)a, (unsigned long long)first[a]);
          continue;
        }
        unsigned is_ancestor = 0;
        for (uint64_t q = prev; q != 0 && q <= nodes; q = npar[q])
          if (q == a) {
            is_ancestor = 1;
            break;
          }
        checks++;
        if (!is_ancestor) {
          back_bad++;
          failures++;
          fprintf(stderr,
                  "FAIL attribution %s record %llu first-attributes NTIR node "
                  "%llu after node %llu, a step BACKWARDS onto a node that is "
                  "not its NTIR ancestor\n",
                  ATTR_FIXTURES[f].label, (unsigned long long)rec,
                  (unsigned long long)a, (unsigned long long)prev);
        } else {
          back_ok++;
        }
        prev = a;
      }
      /* ARM TWO -- THE DUPLICATED ARM.  A node's records must be ONE
       * CONTIGUOUS RUN: between a node's first attribution and its last,
       * every record must attribute that node or a node the NTIR image says
       * is its DESCENDANT.  This is the check that catches a duplicate, and
       * it is the check that has to exist because the header's own sentence
       * cannot be the one that catches it.
       *
       * WHY "TWICE IN A ROW" IS NOT THE TEST, and it is measured.  Adjacent
       * records attributing the SAME node are ordinary and correct: CORPUS
       * records 18 and 19 are both attributed to NTIR node 47, one a
       * `mir_bind` and one a `mir_vreg`, and ATTR_DIAMOND has three such
       * pairs.  A gate that refused an adjacent repeat would be red on a
       * correct image for the same reason the literal sentence is.  What a
       * duplicate actually does is SPLIT the node's run -- claim it, walk
       * away, and claim it again -- and that is what this measures. */
      unsigned splits = 0;
      for (uint64_t a = 1; a <= nodes; a++) {
        if (!claimed[a])
          continue;
        for (uint64_t rec = first[a]; rec <= last[a]; rec++) {
          uint64_t o = attr[rec];
          if (o == a)
            continue;
          unsigned inside = 0;
          for (uint64_t q = o; q != 0 && q <= nodes; q = npar[q])
            if (q == a) {
              inside = 1;
              break;
            }
          checks++;
          if (!inside) {
            splits++;
            failures++;
            fprintf(stderr,
                    "FAIL attribution %s node %llu is attributed at records "
                    "%llu..%llu and record %llu carries node %llu, which the "
                    "NTIR image says is NOT inside it: the node's run is split\n",
                    ATTR_FIXTURES[f].label, (unsigned long long)a,
                    (unsigned long long)first[a], (unsigned long long)last[a],
                    (unsigned long long)rec, (unsigned long long)o);
          }
        }
      }
      /* ARM THREE -- THE DROPPED ARM, AND THE CENSUS IT IS BOUNDED BY.  The
       * header says a dropped node "leaves a hole in the sequence" and that
       * the gate "compares it with the sequence the NTIR admits".  The
       * containment below is that comparison, and it is two-sided: every node
       * the IMAGE claims must be a node `admits` admits, where the admission
       * answer comes from the mode-6 probe's own re-parse and rebuild and not
       * from the lowering that produced the image.
       *
       * AND THE OTHER DIRECTION IS PUBLISHED AS A NUMBER, not asserted,
       * because it is NOT TRUE and saying so is the point.  `admits` is an
       * over-approximation: on CORPUS it admits 42 nodes and the image claims
       * 30, and the 12 it admits and the image does not claim are name nodes
       * that this level folds into their binding's own record.  So there is
       * no population that makes "a hole" a red, and the census line below is
       * what a reader needs in order to see that rather than take it. */
      unsigned admitted_count = 0, claimed_count = 0, claimed_not_admitted = 0;
      for (uint64_t id = 1; id <= nodes; id++) {
        run(&ia, src, slen, 6, id, &ra);
        if (ra.report[17])
          admitted[id] = 1;
        if (claimed[id])
          claimed_count++;
      }
      for (uint64_t id = 1; id <= nodes; id++) {
        if (admitted[id])
          admitted_count++;
        if (claimed[id] && !admitted[id]) {
          claimed_not_admitted++;
          failures++;
          fprintf(stderr,
                  "FAIL attribution %s: the image claims NTIR node %llu and "
                  "machine_ir.admits refuses it, so the image claims a node "
                  "this level does not admit\n",
                  ATTR_FIXTURES[f].label, (unsigned long long)id);
        }
      }
      CHECK(claimed_count > 0,
            "the image claims at least one NTIR node, so the admission "
            "containment below is a measurement and not a comparison of two "
            "absences");
      CHECK(admitted_count >= claimed_count,
            "the sequence the NTIR admits is at least as long as the sequence "
            "the image claims, which is the shape an over-approximating "
            "admission predicate has");
      /* ARM THREE-B -- THE DROPPED ARM'S THRESHOLD, AND WHY IT IS NOT ZERO.
       * The fourth of the header's four failure modes is "a node dropped
       * leaves a hole in the sequence".  This is the arm that makes that a
       * red, and the number it is written against is the census's own
       * `admitted_not_claimed`, read here off the two counts above.
       *
       * WHY NOT `== 0`.  Because zero is FALSE on a correct image, and it is
       * false for a reason the module states about itself: `admits` admits a
       * NAME the NTIR typed as a register (machine_ir.nova:527-531) and a
       * QUALIFIED node outright (machine_ir.nova:517), and neither of those
       * is the record a name becomes -- a name is an `origin` folded into the
       * binding's own record, and a qualified spelling is a spelling.  So
       * every node `admits` admits is not a node the image must claim, and a
       * zero threshold would be red on every correct run and would be an
       * instrument nobody reads.  machine_ir.nova:481-483 is the contract
       * that settles it: the gate "separately checks that every EXECUTABLE
       * NTIR node in its fixtures is attributed" -- EXECUTABLE, not admitted.
       *
       * WHY A PER-FIXTURE EXPECTED VALUE IS RIGHT RATHER THAN A HELD CHANGE.
       * Because the gap is NOT free-floating, and this is measured rather
       * than argued: on this tree, every single node in the gap of all three
       * fixtures is of NTIR table index 47 (`name`) or 48 (`qualified`) --
       * CORPUS 9 qualified + 3 name, DIAMOND 11 qualified + 3 name, ZERO 1
       * qualified.  No `instruction`, `expr`, `call`, `return`, `let`, `if`,
       * `label`, `block` or `memory_operand` node is in the gap on any
       * fixture, which is exactly machine_ir.nova:481-483 holding.  A dropped
       * STATEMENT is therefore an executable node entering the gap, and the
       * gap's floor rises.  That is the whole threshold: the non-executable
       * residue is written down, and anything that lands on top of it is red.
       *
       * AND IT CROSSES.  Perturbing machine_ir.nova's `stmt` so that every
       * instruction statement returns before the dispatch -- the drop, and
       * only the drop -- moves CORPUS from 12 to 19 and reds this line.  The
       * perturbation is the negative control on the threshold: a bound no
       * perturbation can cross is not a threshold.
       *
       * AND THE HONEST REST OF IT, HELD RATHER THAN APPLIED.  A count is a
       * symptom; the twelve names are the fact.  The census should print the
       * nodes in the gap -- their ids and their kinds -- so that "twelve" is
       * twelve NAMED things a reader can confront, and so that a ninth
       * `instruction` in the gap is distinguishable from a thirteenth
       * `qualified` by the line itself.  That is a change to the census's
       * PRINTED FORMAT, which peers and the suite read, so it is NOT made
       * here: it is held, and stated, for the lot that owns the format.  What
       * is asserted below is the count, and the count's composition is
       * written down in the paragraph above so the count is not a bare
       * number. */
      uint64_t gap = admitted_count - claimed_count;
      /* THE GAP'S SHAPE, WHICH IS A PREDICATE AND NOT A COUNT, and the reason
       * is a measurement rather than a preference.
       *
       * THE THREE NUMBERS THAT STOOD HERE -- 12, 14 and 1 -- ARE RETRACTED.
       * The paragraph above them said every node in the gap is a `name`
       * (index 47) or a `qualified` (index 48). On this tree it is not: the gap
       * also holds `expr` (index 36), one node on CORPUS and two on DIAMOND, so
       * the counts are 13, 16 and 1. The numbers moved because the tree moved
       * under a figure that described it, and a figure that has to be
       * re-derived after every legitimate change is not a threshold -- it is a
       * copy of the last answer.
       *
       * WHAT IS ASSERTED INSTEAD is the thing the figure stood in for: no node
       * the gap holds is a kind that OWNS a record. Measured node by node on
       * all three fixtures, the gap holds exactly three kinds --
       *
       *   36 expr       the wrapper parser.nova puts around every operand
       *   47 name       a binding the image resolved through its own table
       *   48 qualified  a module-qualified spelling
       *
       * -- and the `expr` ones are not arbitrary. Each sits directly above a
       * `qualified` node that directly sits above a `name` node, all three
       * sharing ONE span, and that span is the DESTINATION REGISTER of an
       * instruction (`mov rax, n` on CORPUS, `mov rsi,b` and `mov rsi,c` on
       * DIAMOND). `instruction` resolves a destination out of the register
       * table and never calls `expr` on it, so both wrappers are walked past.
       * That is a fold rather than a drop: the register is in the image, as
       * the instruction's own destination operand.
       *
       * WHY A COUNT WAS WEAKER THAN THIS, which is not a matter of taste: the
       * old arm was `gap == 12`, and a gap of twelve NAMES with no qualified
       * and no expr in it satisfies it exactly as well as the measured one
       * does. The predicate below cannot be satisfied by a dropped statement
       * at all, because `instruction` is index 32 and is none of the three. */
      static const uint64_t GAP_KINDS[] = {36, 47, 48};
      unsigned offenders = 0, gap_expr = 0, gap_name = 0, gap_qual = 0;
      for (uint64_t id = 1; id <= nodes; id++) {
        if (!admitted[id] || claimed[id])
          continue;
        uint64_t raw = NW(&rb, id, 0);
        uint64_t index = raw >= ntir_kind_base ? raw - ntir_kind_base + 1 : 0;
        if (index == 36)
          gap_expr++;
        if (index == 47)
          gap_name++;
        if (index == 48)
          gap_qual++;
        unsigned known = 0;
        for (unsigned k = 0; k < sizeof GAP_KINDS / sizeof GAP_KINDS[0]; k++)
          if (index == GAP_KINDS[k])
            known = 1;
        if (!known) {
          offenders++;
          fprintf(stderr,
                  "FAIL attribution %s: NTIR node %llu is admitted and not "
                  "claimed and its kind index is %llu, which is none of "
                  "expr(36), name(47) or qualified(48), so a node that OWNS a "
                  "record is not attributed to one\n",
                  ATTR_FIXTURES[f].label, (unsigned long long)id,
                  (unsigned long long)index);
        }
      }
      checks++;
      if (offenders != 0)
        failures++;
      CHECK(gap > 0 && (uint64_t)(gap_expr + gap_name + gap_qual) == gap,
            "every node the gap holds is one of the three kinds that own no "
            "record, so the count and the classification are the same number");
      CHECK(gap_qual > 0,
            "the gap holds at least one qualified node on every fixture, so "
            "the classification is not satisfied by two kinds happening to be "
            "absent");
      printf("ATTRIBUTION %-8s records=%llu ntir=%llu firsts=%llu "
             "claimed=%llu admitted=%llu admitted_not_claimed=%llu "
             "back_to_ancestor=%u back_not_ancestor=%u splits=%u "
             "line_col_bad=%u gap_expr=%u gap_name=%u gap_qualified=%u "
             "gap_offenders=%u\n",
             ATTR_FIXTURES[f].label, (unsigned long long)n,
             (unsigned long long)nodes, (unsigned long long)firsts,
             (unsigned long long)claimed_count,
             (unsigned long long)admitted_count,
             (unsigned long long)gap, back_ok, back_bad, splits, line_col_bad,
             gap_expr, gap_name, gap_qual, offenders);
      free(first); free(last); free(npar); free(attr); free(claimed);
      free(admitted);
    }
  }

  /* WHAT THIS DOES NOT ESTABLISH, and it is the half a reader of the header
   * above would otherwise assume.
   *
   *   A DROPPED NODE IS DETECTED, AND NOT BY A POPULATION OF ZERO.  This
   *   paragraph used to say it was not detected at all, and that was true of
   *   the file as it stood; the arm in case 8 now makes it red, so the
   *   paragraph is corrected rather than left to contradict the code it
   *   describes.  The structural objection it raised still stands and is the
   *   reason the threshold is not what the objection implied: `admits` admits
   *   42 nodes on CORPUS where the image claims 30, so the admitted SET
   *   cannot be the expected set, and a zero threshold would be red on a
   *   correct image forever.  What the objection missed is that the gap is
   *   not a free-floating residue: measured, every node in it on all three
   *   fixtures is a NAME or a QUALIFIED spelling, never an executable one,
   *   which is machine_ir.nova:481-483 holding.  So the threshold is the
   *   PER-FIXTURE expected gap -- 12, 14, 1 -- typed in the fixture table, and
   *   it crosses: dropping every instruction statement in `stmt` moves CORPUS
   *   from 12 to 19 and reds arm three-b.
   *
   *   WHAT IS STILL NOT DETECTED IS THE RESIDUE ITSELF.  The census counts
   *   the admitted-and-unclaimed nodes and does not say which they are, so a
   *   thirteenth `qualified` and a ninth `instruction` are the same number
   *   on the line.  Printing their ids and kinds is the honest census and is
   *   HELD, not applied, because the format is published and read by peers.
   *
   *   "STRICTLY INCREASING IN NTIR NODE ID" IS NOT WHAT IS CHECKED, because
   *   it is false of this module's own CORPUS: records 12 and 13 attribute
   *   NTIR nodes 33 then 32.  What is checked is non-decreasing with every
   *   step back landing on an NTIR ancestor, which is the depth-first shape
   *   the producer actually has.  The header's sentence is wider than the
   *   code, and the corrected text is HELD rather than applied, because
   *   machine_ir.nova is not this gate's to edit. */


  /* ---- THE DEPTH CAPS, BOTH SIDES OF THE BOUNDARY ---------------------
   *
   * EXPR_DEPTH_CAP is checked in THREE places, not one: `expr`,
   * `memory_value` and `instruction`, all three against the same 64. Two of
   * them are unreachable from any source, and the third is the one these cases
   * exercise. The reason is the call graph, and it is three lines long:
   * `instruction` is called from `stmt` and from nowhere else; `stmt` is called
   * from `body` and from nowhere else; and `body` checks
   * `depth>STMT_DEPTH_CAP()` at its own entrance BEFORE it calls `stmt`, with
   * the SAME depth. Both caps are 64, so `instruction` can only ever be
   * entered with depth<=64 and its own check can never be the one that fires.
   * `memory_value` is entered at depth+1 from `instruction` and so can fire.
   *
   * THE CAP IS 940, E_INPUT, and it is TYPED HERE rather than read back, for
   * the same reason EXPECTED_TAG is: an expectation this file derived from the
   * module could not fail on a change to the module. What makes it a check and
   * not a copy is that the same refusal has to arrive at a stated POSITION
   * naming a stated NODE, and those two are not free.
   */
  {
    /* THE EXPRESSION FIXTURE. `let_stmt` hands its initializer to `expr` at
     * depth+1 and every binary level adds one, so a chain of `terms` literals
     * puts its leftmost literal at depth terms+1. Depth 64 is admitted and
     * depth 65 is refused, and with the statement counter pinned at 1 that
     * makes 63 the deepest chain that lowers and 64 the shallowest that does
     * not. Both numbers were measured by running the module, not derived from
     * the arithmetic, and the arithmetic is what the two agree on. */
    char *src = chain_source(63);
    run(&ia, src, strlen(src), 0, 0, &ra);
    cases++;
    uint64_t under = ra.returned;
    CHECK(under == 0, "a 63-term sum lowers AND verifies: the expression cap "
                      "admits depth 64, so a refusal here would be something "
                      "other than the cap");
    free(src);

    src = chain_source(64);
    run(&ia, src, strlen(src), 0, 0, &ra);
    cases++;
    uint64_t over = ra.returned;
    CHECK(over == 940, "a 64-term sum is refused with E_INPUT: depth 65 is one "
                       "past the cap and the refusal is the cap");
    CHECK(ra.code == 940, "the refusal code is published as report[2] and not "
                          "only returned");
    CHECK(ra.line == 7 && ra.column == 11,
          "the refusal carries the position of the node that broke the cap, "
          "7:11, which is the leftmost literal and not the `let`");
    CHECK(ra.node >= 1 && ra.node <= ra.ntir_count,
          "the refusal names a node inside the NTIR image it refused");
    CHECK(NW(&ra, ra.node, 2) == 7 && NW(&ra, ra.node, 3) == 11,
          "the position the refusal published is the named node's own line and "
          "column, read back out of the image");
    CHECK(span_is(&ra, ra.node, src, "1"),
          "the node the refusal names spans exactly one literal");
    /* The pair is the boundary. Either half alone would pass on a cap that
     * refuses everything, and a cap that refuses nothing would pass the
     * refusal half too. */
    CHECK(under == 0 && over == 940,
          "the cap is a boundary and not a blanket: 63 terms lower, 64 do not");
    printf("DEPTH-CAPS expr_under_terms=63 expr_over_terms=64 "
           "expr_under_ret=%llu expr_over_ret=%llu\n",
           (unsigned long long)under, (unsigned long long)over);
    free(src);

    /* THE STATEMENT FIXTURE, AND THE BOUNDARY FOUND RATHER THAN TYPED.
     *
     * `if_stmt` walks its CONDITION through `expr` at depth+1 and only then
     * hands its ARM BLOCK to `body` at the same depth+1, and `body` guards
     * `depth>STMT_DEPTH_CAP()` at its own entrance before it calls `stmt`.
     * Both caps are 64 and `callable` enters a function body at depth 1, so D
     * nested `if`s put the D-th CONDITION at depth D+2, and a refusal needs
     * D+2>64. D=63 is therefore the shallowest nesting that can refuse and D=62
     * the deepest that cannot. That is a derivation from the module's own
     * published cap and its own call graph, and the sweep below is the
     * instrument that says whether the module agrees with the derivation.
     *
     * THE TWO TYPED DEPTHS THAT WERE HERE ARE GONE, and the reason is not
     * taste. They were 61 and 62 with 62 expected to be REFUSED, the gate went
     * red on all three, and the measurement says 62 LOWERS and 63 refuses.
     * A typed depth is a copy of an answer, so when the module moved the copy
     * stayed and the gate reported the module against itself. The sweep finds
     * the boundary, and what is asserted is the property the cap has --
     * ADJACENT sides, and the admitted side at least as deep as the
     * derivation says -- rather than the number the last run happened to give.
     */
    {
      unsigned deepest = 0, shallow = 0;
      /* `deepest` is the LAST admitted depth, not the first: the sweep walks
       * upward from 1 and every depth below the cap is admitted, so recording
       * the first one pins `deepest` at 1 and every comparison against the cap
       * below is then a comparison against the depth of the simplest fixture
       * that exists. `shallow` is the FIRST refused depth, which is the other
       * half of the same boundary. */
      for (unsigned d = 1; d <= 80; d++) {
        char *s = if_source(d);
        run(&ia, s, strlen(s), 0, 0, &ra);
        if (ra.returned == 0) {
          deepest = d;
        } else if (shallow == 0) {
          shallow = d;
        }
        free(s);
      }
      cases++;
      CHECK(shallow != 0 && deepest != 0 && shallow == deepest + 1,
            "the statement shape refuses at ONE nesting and lowers at the one "
            "below it, so the cap is a boundary and not a blanket");
      CHECK(deepest >= 62,
            "the deepest nesting of `if` that lowers is at least the 62 that "
            "the cap and the call graph put it at");

      /* THE ACCEPTED SIDE, AND THE CHANNEL IT LEAVES EMPTY. report[3] is the
       * REFUSAL's NTIR node and zero when nothing refused -- an assertion
       * machine_ir.nova used to break by publishing the NTIR NODE COUNT
       * there. This file read that count as a node id, found a node whose
       * span is "rax", and reported "the refusal names the `rax` operand"
       * on a run that had refused nothing at all. */
      char *admitted_src = if_source(deepest);
      run(&ia, admitted_src, strlen(admitted_src), 0, 0, &ra);
      uint64_t stmt_under = ra.returned, under_node = ra.node;
      cases++;
      CHECK(stmt_under == 0,
            "the deepest admitted nesting lowers and verifies");
      CHECK(under_node == 0,
            "a run that refused nothing leaves the refusal's node slot at zero, "
            "so a node id read out of it can only have come from a refusal");

      /* THE REFUSED SIDE. */
      unsigned over_depth = shallow;
      src = if_source(over_depth);
      run(&ia, src, strlen(src), 0, 0, &ra);
      uint64_t stmt_over = ra.returned;
      uint64_t over_line = ra.line, over_column = ra.column,
               over_node = ra.node;
      CHECK(stmt_over == 940,
            "one nesting past the boundary is refused with E_INPUT");
      CHECK(ra.code == 940,
            "the refusal code is published as report[2] and not only returned");
      CHECK(over_node >= 1 && over_node <= ra.ntir_count,
            "the refusal names a node inside the NTIR image it refused");
      CHECK(span_is(&ra, over_node, src, "a"),
            "the named node spans the CONDITION the cap fired on, which is one "
            "token and not an arm block");
      CHECK(over_line == 6 + over_depth && over_column == 4,
            "the refusal sits on the innermost `if`'s condition, which this "
            "fixture's own text places on line 6+nesting at column 4");
      CHECK(text_at(src, over_line, over_column, "a"),
            "the position the refusal published and the node it named are the "
            "same token, read back out of the fixture");
      CHECK(!span_is(&ra, over_node, src, "rax"),
            "the refusal does NOT name the arm's destination operand, which is "
            "exactly what an accepted run's leftover node id named before");
      CHECK(!span_is(&ra, over_node, src, "{"),
            "the named node is not an arm block, so the STATEMENT cap did not "
            "fire: the EXPRESSION cap did, on a STATEMENT-shaped source");
      printf("DEPTH-CAPS stmt_under_ifs=%u stmt_over_ifs=%u stmt_under_ret=%llu "
             "stmt_over_ret=%llu stmt_over_node=%llu "
             "refused_node_span_is_an_operand stmt_depth_cap_sites_fired=0 "
             "stmt_accepted_node_slot=%llu\n",
             deepest, over_depth, (unsigned long long)stmt_under,
             (unsigned long long)stmt_over, (unsigned long long)over_node,
             (unsigned long long)under_node);
      free(admitted_src);
      free(src);
    }

    /* THE THIRD EXPR_DEPTH_CAP SITE, `memory_value`, with its own boundary.
     * MODE 4 AND NOT MODE 0, and the reason is measured rather than chosen: a
     * literal `if` condition is not a predicate class, so the VERIFIER refuses
     * this image 934 E_SHAPE at every depth that gets past the cap, which
     * would leave an over-side refusal and no accepted side at all, and a cap
     * that refuses everything proves nothing.
     *
     * THAT 934 IS A REAL VERDICT AND NOT A HALF-BUILT BUFFER, and the way to
     * know is that mode 4, which lowers and does not verify, answers 0 at the
     * same depth: the image the verifier refused was complete. It is a finding
     * of its own -- the verifier refusing something the emitter emits -- and it
     * is HELD in this comment rather than pinned, because it is not this
     * site's question. Mode 4 asks the question this site answers, which is
     * whether the LOWERING refuses.
     *
     * MODE 2 FIRST, INTO THE SAME RUN. Mode 4 lowers from the NTIR image
     * already in the entry's fifth buffer and never parses, so a Run that has
     * not written that buffer hands the lowering GUARD values; that is the
     * harness's own documented trap and it reads as a producer defect. */
    src = mem_source(62);
    run(&ia, src, strlen(src), 2, 0, &ra);
    CHECK(ra.returned == 0, "the memory fixture builds an NTIR image at all");
    run(&ia, src, strlen(src), 4, 0, &ra);
    cases++;
    uint64_t mem_under = ra.returned;
    CHECK(mem_under == 0,
          "62 nested ifs over a memory destination lower: the descriptor is "
          "walked one level inside the cap here");
    free(src);

    src = mem_source(63);
    run(&ia, src, strlen(src), 2, 0, &ra);
    CHECK(ra.returned == 0, "the memory fixture builds an NTIR image at the "
                            "refusing depth too, so the refusal below is the "
                            "cap's and not the build's");
    run(&ia, src, strlen(src), 4, 0, &ra);
    cases++;
    uint64_t mem_over = ra.returned;
    CHECK(mem_over == 940, "63 lower to E_INPUT");
    CHECK(ra.line == 70 && ra.column == 5,
          "and the refusal names the memory descriptor at 70:5, which is the "
          "node `memory_value` was handed and not the literal `1` beside it");
    CHECK(span_is(&ra, ra.node, src, "[rax]:ptr<user,u64>"),
          "the named node is the memory descriptor, so the third EXPR_DEPTH_CAP "
          "site is reached and not the first");
    CHECK(mem_under == 0 && mem_over == 940,
          "the memory site has a boundary of its own, one level deeper than the "
          "operand one for the same cap");
    printf("DEPTH-CAPS mem_under_ifs=62 mem_over_ifs=63 mem_under_ret=%llu "
           "mem_over_ret=%llu mem_over_node=%llu mem_site_reached=1\n",
           (unsigned long long)mem_under, (unsigned long long)mem_over,
           (unsigned long long)ra.node);
    free(src);
  }

  /* Import declarations have an optional body link of zero. Never dereference it. */
  {
    const char *import_src = "module m\ntarget x86_64-nexora-uefi\n"
      "import api.echo as ext: fn()->u64\neffects {}\nclobbers {}\n"
      "section .text {\nexport fn main()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";
    for (unsigned which = 0; which < 2; which++) {
      const NovaHostImage *im = which ? &ib : &ia;
      run(im, import_src, strlen(import_src), 0, 0, &ra);
      CHECK(ra.returned == 0 && ra.runtime == 0, "import with optional zero body verifies without runtime fault");
      uint64_t target = 0;
      if (ra.returned == 0 && ra.runtime == 0) {
        for (uint64_t id = 1; id <= ra.image[3]; id++) {
          uint64_t at = header_words + (id - 1) * node_words;
          if (ra.image[at] == kind_base + 3 && ra.image[at + 5] == 0) { target = at; break; }
        }
      }
      CHECK(target != 0, "the import has a function record with no body");
      if (target) {
        ra.image[target + 5] = ra.image[3] + 1;
        run(im, import_src, strlen(import_src), 5, 0, &ra);
        CHECK(ra.returned == 933 && ra.runtime == 0, "nonzero optional body outside the image is E_LINK");
        ra.image[target + 5] = 1;
        run(im, import_src, strlen(import_src), 5, 0, &ra);
        CHECK(ra.returned == 933 && ra.runtime == 0, "nonzero optional body must name a block, not the root");
        ra.image[target + 5] = 0;
        run(im, import_src, strlen(import_src), 5, 0, &ra);
        CHECK(ra.returned == 0 && ra.runtime == 0, "restoring the absent body restores a valid import");
      }
    }
  }
  /* MIR/1.0 DECLARATION FACTS (A7, 6 October 2026). machine_emit.nova builds
   * object symbols and contracts from these, and the corpus gate compares the
   * result with the C reference; THIS block is the unit measurement of the
   * facts themselves and of the verifier rules that hold each bit to its kinds.
   * Written before anything else reads them, so a lowering that dropped one is
   * red here and not only as a contract mismatch three modules later. */
  {
    static const char decl_src[] =
        "module decl.facts\n"
        "target x86_64-nexora-uefi\n"
        "features {sse2,tsc}\n"
        "import other.lib as lib: fn(in a:u64 @rcx)->u64\n"
        "effects {}\n"
        "clobbers {}\n"
        "section .rdata {\n"
        "    data base:u64=30\n"
        "}\n"
        "section .data {\n"
        "    export data total:u64=12\n"
        "}\n"
        "section .text {\n"
        "    fn helper(in a:u64 @rcx,out b:u64 @rdx,inout c:u64 @r8)->u64\n"
        "    effects {}\n"
        "    clobbers {rax,rbx,rflags}\n"
        "    requires {stack_aligned(16)} {\n"
        "        return a\n"
        "    }\n"
        "    export fn main()->u64\n"
        "    effects {}\n"
        "    clobbers {} {\n"
        "        return lib(1)\n"
        "    }\n"
        "}\n";
    const uint64_t F_EXPORT = 1024, F_RDATA = 2048, F_WDATA = 4096, F_OUT = 8192,
                   F_INOUT = 16384, F_PRED = 32768, F_UNREAD = 65536;
    cases++;
    run(&ia, decl_src, strlen(decl_src), 0, 0, &ra);
    CHECK(ra.returned == 0 && ra.runtime == 0,
          "the declaration-facts fixture lowers and verifies");
    uint64_t n = ra.returned == 0 ? n_records(&ra) : 0;
    uint64_t helper = 0, mainf = 0, lib = 0, base = 0, total = 0;
    uint64_t pin = 0, pout = 0, pinout = 0, clob_helper = 0, clob_main = 0;
    for (uint64_t rec = 1; rec <= n; rec++) {
      uint64_t kind = W(&ra, rec, 0);
      uint64_t s0 = W(&ra, rec, 6), s1 = W(&ra, rec, 7);
      int named = s1 >= s0 && s1 <= sizeof decl_src;
      if (kind == 2051 && named && s1 - s0 == 6 && !memcmp(decl_src + s0, "helper", 6)) helper = rec;
      if (kind == 2051 && named && s1 - s0 == 4 && !memcmp(decl_src + s0, "main", 4)) mainf = rec;
      if (kind == 2051 && named && s1 - s0 == 3 && !memcmp(decl_src + s0, "lib", 3)) lib = rec;
      if (kind == 2060 && named && s1 - s0 == 4 && !memcmp(decl_src + s0, "base", 4)) base = rec;
      if (kind == 2060 && named && s1 - s0 == 5 && !memcmp(decl_src + s0, "total", 5)) total = rec;
    }
    for (uint64_t rec = 1; rec <= n; rec++) {
      uint64_t kind = W(&ra, rec, 0), parent = W(&ra, rec, 16);
      if (kind == 2054 && parent == helper && helper) {
        if (W(&ra, rec, 14) == 0) pin = rec;
        if (W(&ra, rec, 14) == 1) pout = rec;
        if (W(&ra, rec, 14) == 2) pinout = rec;
      }
      if (kind == 2064 && parent == helper && helper) clob_helper = rec;
      if (kind == 2064 && parent == mainf && mainf) clob_main = rec;
    }
    printf("MIR_FACTS records=%llu helper=%llu main=%llu lib=%llu base=%llu total=%llu "
           "params=%llu/%llu/%llu clobbers=%llu/%llu features=%llu\n",
           (unsigned long long)n, (unsigned long long)helper, (unsigned long long)mainf,
           (unsigned long long)lib, (unsigned long long)base, (unsigned long long)total,
           (unsigned long long)pin, (unsigned long long)pout, (unsigned long long)pinout,
           (unsigned long long)clob_helper, (unsigned long long)clob_main,
           (unsigned long long)(n ? W(&ra, 1, 15) : 0));
    CHECK(helper && mainf && lib && base && total && pin && pout && pinout && clob_helper && clob_main,
          "every declaration of the fixture is found by its name span");
    if (helper && mainf && lib && base && total && pin && pout && pinout && clob_helper && clob_main) {
      CHECK(W(&ra, 1, 15) == 1 + 8 + 16, "the unit carries the feature mask lm|sse2|tsc = 25");
      CHECK((W(&ra, mainf, 13) & F_EXPORT) && !(W(&ra, helper, 13) & F_EXPORT),
            "`export fn main` carries FLAG_EXPORT and `fn helper` does not");
      CHECK((W(&ra, helper, 13) & F_PRED) && !(W(&ra, mainf, 13) & F_PRED),
            "a non-empty requires sets FLAG_PREDICATED, and a function without one does not carry it");
      CHECK((W(&ra, base, 13) & (F_RDATA | F_WDATA | F_EXPORT)) == F_RDATA,
            "`data base` in .rdata carries FLAG_RDATA alone");
      CHECK((W(&ra, total, 13) & (F_RDATA | F_WDATA | F_EXPORT)) == (F_WDATA | F_EXPORT),
            "`export data total` in .data carries FLAG_WDATA and FLAG_EXPORT");
      CHECK(W(&ra, base, 8) == 3, "a data record has three live slots: value, name start, name end");
      /* The lowering holds no AST and does not read the direction word (the
       * rule has one owner, abi.nova's direction): every parameter it lowers
       * says FLAG_DIR_UNREAD, and machine_pipeline.lower_tree replaces the
       * bit. The resolved bits are measured by tests_ntasm_machine_pipeline.c
       * (PARAM_MODES, the same parameters through the pipeline). */
      CHECK((W(&ra, pin, 13) & (F_OUT | F_INOUT | F_UNREAD)) == F_UNREAD &&
                (W(&ra, pout, 13) & (F_OUT | F_INOUT | F_UNREAD)) == F_UNREAD &&
                (W(&ra, pinout, 13) & (F_OUT | F_INOUT | F_UNREAD)) == F_UNREAD,
            "the lowering marks every parameter's direction unread, whatever the word");
      CHECK(W(&ra, clob_helper, 8) == 1 && W(&ra, clob_helper, 5) == (1u | 8u | 131072u),
            "clobbers {rax,rbx,rflags} is the oracle mask rax bit 0 | rbx bit 3 | rflags bit 17");
      CHECK(W(&ra, clob_main, 8) == 1 && W(&ra, clob_main, 5) == 0,
            "clobbers {} is a live zero mask, not an absence");
      uint64_t t = lib + 1;
      CHECK(W(&ra, lib, 5) == 0 && W(&ra, t, 0) == 2057 && W(&ra, t, 16) == lib &&
                W(&ra, t, 6) - W(&ra, t, 5) == 9 && !memcmp(decl_src + W(&ra, t, 5), "other.lib", 9),
            "the import's first child is a mir_symbol spelling its qualified target `other.lib`");
      /* Each bit on a kind that may not carry it: the verifier must refuse the
       * image with E_SHAPE (934) AT that record, and the undamaged image must
       * verify again afterwards, so the refusals are the damage's and not a
       * broken image's. */
      struct { const char *what; uint64_t rec, bits; } damage[] = {
          {"FLAG_EXPORT on the unit", 1, F_EXPORT},
          {"FLAG_RDATA on a parameter", pin, F_RDATA},
          {"FLAG_DIR_OUT on a function", mainf, F_OUT},
          {"FLAG_PREDICATED on a data", base, F_PRED},
          {"FLAG_RDATA and FLAG_WDATA together", base, F_WDATA},
          {"two direction bits together", pout, F_INOUT},
          {"FLAG_DIR_UNREAD on a data", base, F_UNREAD},
      };
      for (unsigned d = 0; d < sizeof damage / sizeof damage[0]; d++) {
        uint64_t *word = &ra.image[header_words + (damage[d].rec - 1) * node_words + 13];
        uint64_t saved = *word;
        *word = saved | damage[d].bits;
        run(&ia, decl_src, strlen(decl_src), 5, 0, &ra);
        printf("MIR_FACTS_DAMAGE %-40s record=%llu verify=%llu at=%llu\n", damage[d].what,
               (unsigned long long)damage[d].rec, (unsigned long long)ra.returned,
               (unsigned long long)ra.report[3]);
        CHECK(ra.returned == 934 && ra.runtime == 0 && ra.report[3] == damage[d].rec,
              "the verifier refuses a declaration bit on the wrong kind with E_SHAPE at that record");
        *word = saved;
      }
      run(&ia, decl_src, strlen(decl_src), 5, 0, &ra);
      CHECK(ra.returned == 0 && ra.runtime == 0, "the restored image verifies again");
    }
  }
  /* MIR/1.0 negative image tests. These mutate the real lowered cells;
   * unchanged source cannot repair the damaged image. */
  {
    const char *src = "module cells\ntarget x86_64-nexora-uefi\nsection .text {\n"
        "fn g()->u64\neffects {}\nclobbers {rax,rcx} {\nmov rcx,9\nreturn 1\n}\n"
        "export fn main(in x:u64 @rcx)->u64\neffects {changes_flags}\nclobbers {rax,rflags} {\n"
        "mov rax,4660\nmov al,0\ncall g()\ncmp rcx,0\nje done\nmov rax,7\ndone:\nreturn rax\n}\n}\n";
    run(&ia, src, strlen(src), 0, 0, &ra);
    CHECK(ra.returned == 0 && ra.runtime == 0, "MIR/1.0 cell fixture verifies");
    uint64_t read = 0, write = 0, flags = 0, branch = 0, call = 0;
    for (uint64_t r = 1; r <= n_records(&ra); r++) {
      if (W(&ra,r,22) == 1) read = r;
      if ((W(&ra,r,22) & 2) && W(&ra,r,9) == 8) write = r;
      if ((W(&ra,r,22) & 4) && W(&ra,r,14) == 35) flags = r;
      if (W(&ra,r,22) == 8) branch = r;
      if (W(&ra,r,0) == 2076) call = r;
    }
    CHECK(read && write && flags && branch && call, "cell mutation population is nonempty");
    const struct { uint64_t r, field, value, code; const char *name; } muts[] = {
      {read,20,17,934,"family-outside-gpr"}, {read,20,0,934,"missing-family"},
      {read,21,8,938,"high-byte-on-wide-read"}, {read,9,80,938,"cell-width-80"},
      {write,21,1,934,"unaligned-cell-slice"}, {write,22,0,934,"missing-write-mode"},
      {flags,22,0,934,"missing-flags-definition"}, {branch,22,0,934,"missing-flags-read"},
      {call,23,1048576,934,"call-unknown-clobber"}, {read,23,1,934,"effect-on-read"}
    };
    for (unsigned m = 0; m < sizeof muts / sizeof muts[0]; m++) {
      if (!muts[m].r) continue;
      const uint64_t old = W(&ra,muts[m].r,muts[m].field);
      W(&ra,muts[m].r,muts[m].field) = muts[m].value;
      run(&ia, src, strlen(src), 5, 0, &ra);
      char message[240];
      snprintf(message,sizeof message,"%s: mutation record %llu got code %llu at record %llu",muts[m].name,
               (unsigned long long)muts[m].r,(unsigned long long)ra.returned,(unsigned long long)ra.node);
      CHECK(ra.runtime == 0 && ra.returned == muts[m].code && ra.node == muts[m].r,message);
      W(&ra,muts[m].r,muts[m].field) = old;
    }
    run(&ia, src, strlen(src), 5, 0, &ra);
    CHECK(ra.returned == 0 && ra.runtime == 0, "restored cell image verifies");
  }
  /* A CFG mutation of the premise: one arm defines flags, the other does
   * not. A runtime w=1 example cannot substitute for the all-path contract. */
  {
    const char *src="module flags_join\ntarget x86_64-nexora-uefi\nsection .text {\n"
        "export fn main(in w:u64 @rcx)->u64\neffects {changes_flags}\nclobbers {rax,rflags} {\n"
        "mov rax,0\nif w>0 {\ncmp rax,0\n}\nje zero\nreturn 1\nzero:\nreturn 42\n}\n}\n";
    run(&ia,src,strlen(src),0,0,&ra);
    CHECK(ra.returned==940&&ra.runtime==0,"flags missing on one CFG path are refused");
  }
  /* Minus is unary OP_NEG, not the binary OP_SUB mapping for '-'. The
   * image, not a second source parse, must carry that distinction. */
  {
    const char *src="module unary_minus\ntarget x86_64-nexora-uefi\nsection .text {\n"
        "export fn main()->u64\neffects {}\nclobbers {rax} {\nmov rax,-1\nreturn rax\n}\n}\n";
    run(&ia,src,strlen(src),0,0,&ra);
    CHECK(ra.returned==0&&ra.runtime==0,"negative immediate fixture verifies");
    unsigned neg=0;
    for(uint64_t r=1;r<=n_records(&ra);r++)if(W(&ra,r,0)==2071){
      CHECK(W(&ra,r,14)==23&&W(&ra,r,9)==64,"unary minus publishes OP_NEG23 at width64");neg++;
    }
    CHECK(neg==1,"negative immediate has one real unary definition");
  }
  printf("OPERATOR-VOCABULARY pinned=4 (nop, mov, add, binary +) "
         "unmeasured=beyond_this_set\n");

  /* A6 (13 October 2026): lower_with_calls. The AST's call marks are a TYPED
   * fact handed to the lowering; they can add a call the text does not spell
   * (a stub_table graft) and must never turn a name into a call. Three cases:
   * a written call lowers to the same image through both entries; a source
   * with no call accepts an empty table; and a table that names a bare-name
   * expression node of that source is refused 940 with that node. */
  {
    static const char CALLS_WRITTEN[] =
        "module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\n"
        "return 9\n}\nfn main()->u64\neffects {}\nclobbers {} {\nreturn f()\n}\n}\n";
    static const char CALLS_NONE[] =
        "module m\ntarget x86_64-nexora-none\nsection .text {\nfn main()->u64\neffects {}\nclobbers {} {\n"
        "let x:u64=5\nreturn x\n}\n}\n";
    run(&ia, CALLS_WRITTEN, sizeof CALLS_WRITTEN - 1, 0, 0, &ra);
    uint64_t plain_records = ra.records, plain_returned = ra.returned;
    run(&ia, CALLS_WRITTEN, sizeof CALLS_WRITTEN - 1, 11, 0, &rb);
    cases++;
    fprintf(stderr, "A6_CALLS written lower=%llu with=%llu records %llu/%llu\n",
            (unsigned long long)plain_returned, (unsigned long long)rb.returned,
            (unsigned long long)plain_records, (unsigned long long)rb.records);
    CHECK(plain_returned == 0 && rb.returned == 0 && rb.records == plain_records,
          "a6 calls: a written call lowers the same through lower and lower_with_calls");
    run(&ia, CALLS_NONE, sizeof CALLS_NONE - 1, 11, 0, &rb);
    cases++;
    fprintf(stderr, "A6_CALLS none with=%llu\n", (unsigned long long)rb.returned);
    CHECK(rb.returned == 0, "a6 calls: a source with no call lowers with an empty table");
    run(&ia, CALLS_NONE, sizeof CALLS_NONE - 1, 2, 0, &rc);
    uint64_t bare = 0;
    for (uint64_t id = 1; id <= rc.ntir_count && !bare; id++) {
      uint64_t at = 8 + (id - 1) * 16; /* ntir HEADER_WORDS 8, NODE_WORDS 16 */
      uint64_t b0 = rc.words[at + 4], b1 = rc.words[at + 5];
      if (rc.words[at + 6] == 35 && b1 == b0 + 1 && b1 <= sizeof CALLS_NONE - 1 && CALLS_NONE[b0] == 'x' &&
          b0 >= 7 && !memcmp(CALLS_NONE + b0 - 7, "return ", 7))
        bare = id;
    }
    cases++;
    fprintf(stderr, "A6_CALLS bare node=%llu\n", (unsigned long long)bare);
    CHECK(bare != 0, "a6 calls: the no-call source has the bare-name expression node of `return x`");
    if (bare) {
      run(&ia, CALLS_NONE, sizeof CALLS_NONE - 1, 11, bare, &rb);
      fprintf(stderr, "A6_CALLS bare imposed node=%llu got=%llu at=%llu\n", (unsigned long long)bare,
              (unsigned long long)rb.returned, (unsigned long long)rb.node);
      CHECK(rb.returned == 940 && rb.node == bare,
            "a6 calls: a table naming the bare-name node of `return x` is refused 940 at that node");
    }
  }

  /* MIR1.1 call argument metadata is checked AT the call site. */
  {
    size_t size=0;char *source=loadf("examples/ntasm-v0/abi-efi/dominance-mir.ntasm",&size);
    Run extra={0};run_init(&extra);cases++;
    A4_CHECK(source!=NULL,"A4 MIR dominance fixture exists");
    if(source) {
      run(&ia,source,size,0,0,&extra);
      A4_CHECK(extra.returned==0 && extra.runtime==0,"A4 MIR baseline code=%llu runtime=%llu",(unsigned long long)extra.returned,(unsigned long long)extra.runtime);
      if(!extra.returned && !extra.runtime) {
        size_t bytes=(size_t)(header_words+n_records(&extra)*node_words)*8;
        uint64_t *clean=malloc(bytes);A4_CHECK(clean!=NULL,"A4 MIR image backup");
        if(clean) {
          memcpy(clean,extra.image,bytes);
          uint64_t call=0,metadata=0,future=0,branch_value=0;
          for(uint64_t r=1;r<=n_records(&extra);r++) {
            if(W(&extra,r,0)==2076 && W(&extra,r,14)==5)call=r;
          }
          for(uint64_t r=1;r<=n_records(&extra);r++) {
            if(W(&extra,r,0)==2083 && W(&extra,r,6)==call && W(&extra,r,14)==2)metadata=r;
            if(r>call && W(&extra,r,0)==2058 && W(&extra,r,4)!=0)future=W(&extra,r,4);
            if(r<call && W(&extra,r,0)==2076 && W(&extra,r,14)==0 && W(&extra,r,16)!=W(&extra,call,16))branch_value=W(&extra,r,4);
          }
          fprintf(stderr,"A4_MIR_WITNESS call=%llu metadata=%llu future=%llu branch=%llu records=%llu\n",(unsigned long long)call,(unsigned long long)metadata,(unsigned long long)future,(unsigned long long)branch_value,(unsigned long long)n_records(&extra));
          for(uint64_t r=1;r<=n_records(&extra);r++) if(W(&extra,r,0)==2076 || W(&extra,r,0)==2083 || W(&extra,r,0)==2058) fprintf(stderr,"A4_REC id=%llu kind=%llu value=%llu aux=%llu parent=%llu\n",(unsigned long long)r,(unsigned long long)W(&extra,r,0),(unsigned long long)W(&extra,r,4),(unsigned long long)W(&extra,r,14),(unsigned long long)W(&extra,r,16));
          A4_CHECK(call && metadata && future && branch_value,"A4 MIR mutation witnesses call/metadata/future/branch all present");
          if(call && metadata && future && branch_value) {
            for(unsigned mutation=0;mutation<9;mutation++) {
              memcpy(extra.image,clean,bytes);
              if(mutation==0) W(&extra,metadata,5)=future;
              if(mutation==1) W(&extra,metadata,5)=branch_value;
              if(mutation==2) W(&extra,metadata+1,14)=2; /* duplicate */
              if(mutation==3) W(&extra,metadata,14)=3; /* order/gap */
              if(mutation==4) W(&extra,metadata,6)=call+1; /* wrong site */
              if(mutation==5) W(&extra,metadata,5)=extra.image[6]+1;
              if(mutation==6) extra.image[2]=extra.image[2]+1;
              if(mutation==7) W(&extra,call,14)=6; /* absent extra */
              if(mutation==8) { W(&extra,metadata,5)=0;W(&extra,metadata+1,14)=2; }
              run(&ia,source,size,5,0,&extra);cases++;
              A4_CHECK(extra.runtime==0 && extra.returned!=0,"A4 MIR mutant%u refused code=%llu runtime=%llu",mutation,(unsigned long long)extra.returned,(unsigned long long)extra.runtime);
            }
            memcpy(extra.image,clean,bytes);run(&ia,source,size,5,0,&extra);
            A4_CHECK(extra.returned==0 && extra.runtime==0,"A4 MIR restored positive image accepted");
          }
          free(clean);
        }
      }
    }
    free(source);run_free(&extra);
  }
  /* Contract metadata is a typed graph, not text trusted by the emitter. */
  {
    size_t size=0;char *src=loadf("examples/ntasm-v0/a4-contracts/mir-contract-tree.ntasm",&size);
    Run ct={0};run_init(&ct);cases++;
    A4_CHECK(src!=NULL,"contract graph fixture exists");
    if(src){
      run(&ia,src,size,0,0,&ct);
      A4_CHECK(ct.returned==0 && ct.runtime==0,"contract graph baseline code=%llu runtime=%llu",(unsigned long long)ct.returned,(unsigned long long)ct.runtime);
      if(!ct.returned && !ct.runtime){
        uint64_t root=0,param=0,lit=0,op=0;
        for(uint64_t r=1;r<=n_records(&ct);r++)if(W(&ct,r,0)==2085){
          if(!root && W(&ct,r,15)==2)root=r;
          if(!param && W(&ct,r,15)==3)param=r;
          if(!lit && W(&ct,r,15)==4)lit=r;
          if(!op && W(&ct,r,15)==6)op=r;
        }
        A4_CHECK(root && param && lit && op,"contract graph has predicate/parameter/literal/operator witnesses");
        size_t bytes=(size_t)(header_words+n_records(&ct)*node_words)*8;
        uint64_t *clean=malloc(bytes);A4_CHECK(clean!=NULL,"contract graph snapshot allocated");
        if(clean && root && param && lit && op){
          memcpy(clean,ct.image,bytes);
          for(unsigned m=0;m<13;m++){
            memcpy(ct.image,clean,bytes);
            uint64_t owner=W(&ct,root,5);
            if(m==0)W(&ct,root,5)=root;
            if(m==1)W(&ct,root,13)=0;
            if(m==2)W(&ct,param,20)=param;
            if(m==3)W(&ct,param,5)=root;
            if(m==4)W(&ct,root,15)=99;
            if(m==5)W(&ct,root,7)=0;
            if(m==6)W(&ct,root,9)=64;
            if(m==7)W(&ct,lit,7)=2;
            if(m==8)W(&ct,op,6)=op;
            if(m==9)W(&ct,op,21)=99;
            if(m==10)W(&ct,op,7)=W(&ct,op,6);
            if(m==11)W(&ct,root,23)=1;
            if(m==12)W(&ct,param,6)=W(&ct,owner,14);
            run(&ia,src,size,5,0,&ct);cases++;
            A4_CHECK(ct.returned!=0 && ct.runtime==0,"contract mutation %u refused structurally code=%llu runtime=%llu",m,(unsigned long long)ct.returned,(unsigned long long)ct.runtime);
          }
          memcpy(ct.image,clean,bytes);run(&ia,src,size,5,0,&ct);
          A4_CHECK(ct.returned==0 && ct.runtime==0,"restored contract graph accepted");
        }
        free(clean);
      }
    }
    free(src);run_free(&ct);
  }
  /* Parenthesised comparisons preserve predicate identity through copies. */
  {
    const char *src="module a8.predicate_copy\ntarget x86_64-nexora-uefi\nsection .text { export fn main(in x:u64 @rcx)->u64 effects {} clobbers {rax} { if ((x==0)) {return 42;} else {return 43;} } }";
    Run pc={0};run_init(&pc);cases++;
    run(&ia,src,strlen(src),2,0,&pc);
    A4_CHECK(pc.returned==0 && pc.runtime==0,"predicate copy NTIR accepted");
    if(pc.returned==0 && pc.runtime==0) {
      run(&ia,src,strlen(src),4,0,&pc);
      A4_CHECK(pc.returned==0 && pc.runtime==0,"predicate copy lowering accepted");
      uint64_t n=(node_words && header_words<WORDS) ? n_records(&pc):0;
      A4_CHECK(n>0 && n<=(WORDS-header_words)/node_words,"predicate copy image bounded");
      if(n && n<=(WORDS-header_words)/node_words) {
        uint64_t copy=0,comparison=0,constant=0,copies=0;
        for(uint64_t r=1;r<=n;r++) {
          if(W(&pc,r,0)==2069 && W(&pc,r,12)==3 && W(&pc,r,9)==1 && W(&pc,r,4)>0 && W(&pc,r,5)>0) { copies++;copy=r; }
          if(W(&pc,r,0)==2070 && W(&pc,r,12)==3)comparison=r;
          if(W(&pc,r,0)==2058 && W(&pc,r,4)>0)constant=r;
        }
        A4_CHECK(copies>=2 && comparison && constant,"predicate copy witnesses copies=%llu comparison=%llu constant=%llu",(unsigned long long)copies,(unsigned long long)comparison,(unsigned long long)constant);
        run(&ia,src,strlen(src),5,0,&pc);
        A4_CHECK(pc.returned==0 && pc.runtime==0,"nested predicate copies verify code=%llu runtime=%llu",(unsigned long long)pc.returned,(unsigned long long)pc.runtime);
        size_t bytes=(size_t)(header_words+n*node_words)*sizeof(uint64_t);
        uint64_t *clean=malloc(bytes);
        A4_CHECK(clean!=NULL,"predicate copy snapshot allocated");
        if(clean && copies>=2 && comparison && constant) {
          memcpy(clean,pc.image,bytes);
          for(unsigned m=0;m<11;m++) {
            memcpy(pc.image,clean,bytes);
            if(m==0)W(&pc,copy,5)=W(&pc,copy,4);
            if(m==1)W(&pc,copy,5)=pc.image[6]+1;
            if(m==2)W(&pc,copy,9)=64;
            if(m==3)W(&pc,copy,10)=W(&pc,copy,10)==0?1:0;
            if(m==4)W(&pc,copy,11)=1;
            if(m==5)W(&pc,copy,14)=2;
            if(m==6){W(&pc,copy,8)=2;W(&pc,copy,6)=W(&pc,copy,5);}
            if(m==7)W(&pc,copy,12)=16;
            if(m==8){W(&pc,copy,5)=W(&pc,constant,4);W(&pc,constant,9)=1;W(&pc,constant,10)=W(&pc,copy,10);W(&pc,constant,11)=W(&pc,copy,11);}
            if(m==9)W(&pc,comparison,14)=2;
            if(m==10)W(&pc,copy,4)=0;
            run(&ia,src,strlen(src),5,0,&pc);cases++;
            A4_CHECK(pc.returned!=0 && pc.runtime==0,"predicate copy mutation %u refused code=%llu runtime=%llu",m,(unsigned long long)pc.returned,(unsigned long long)pc.runtime);
          }
          memcpy(pc.image,clean,bytes);run(&ia,src,strlen(src),5,0,&pc);
          A4_CHECK(pc.returned==0 && pc.runtime==0,"restored predicate copies verify");
        }
        free(clean);
      }
    }
    run_free(&pc);
  }
  for (unsigned i = 0; i < PATHS_N; i++)
    free(sources[i]);
  run_free(&ra);
  run_free(&rb);
  run_free(&rc);
  run_free(&rd);
  nova_host_unmap(&ia);
  nova_host_unmap(&ib);
  nt_artifact_free(&first);
  nt_artifact_free(&second);
  printf("NTASM_NOVA_MACHINE_IR checks=%u failures=%u cases=%u\n", checks,
         failures, cases);
  return failures ? 1 : 0;
}
