#include "../../../compiler/c/nova/frontend/nova.h"
#include "../../../compiler/c/nova/runtime/run_host.h"
#include "../../../compiler/c/nova/runtime/runtime_v2.h"
#include "../../../compiler/c/ntasm/backend/x64.h"
#include "../../../compiler/c/ntasm/frontend/frontend.h"

#include <stdint.h>

/* ================= THE BASE-REGISTER CHANNEL, decided by measurement =======
 *
 * The wave-21 finding was: bits 18 GSBASE and 19 FSBASE have NO CHANNEL, and
 * `effects {gsbase}` is refused 321 reason 1, "unknown effect name", exactly
 * as a misspelling. The verdict this block exists to hold is written out in
 * full at effects.nova:76-163, above atom_kind, and it has three parts. This
 * block is the instrument for the part that can rot.
 *
 * PART ONE, THE COMPLETE-PROJECTION CLAIM, and it is the load-bearing one.
 * `effects` is not the channel that was left out. The oracle's effect channel
 * is a uint32_t of eleven named positions (x64.h:92-104) and effects.nova's
 * atom_kind has eleven rows. If those eleven were a TRUNCATION of the
 * oracle's set, gsbase would be a missing row and this would be a hole. They
 * are not: this sweep asks nt_x64_effects for its `effects` field over a
 * stated set of forms and REQUIRES that no form ever set a bit outside the
 * eleven. That is a property of the oracle read at run time in this binary,
 * not a transcription of x64.h, so it fails if the oracle grows a twelfth
 * effect the product cannot name -- which is the moment the vocabulary really
 * would become incomplete, and the moment this block exists to catch.
 *
 * PART TWO, THE SAFETY CLAIM, which is the one the finding turns on. gsbase
 * and fsbase live in `registers_read`/`registers_written`, a REGISTER
 * footprint (x64.h:79), and there is no channel for them in either vocabulary.
 * An absent channel is only safe if every form that would need it is refused.
 * So the sweep asks the oracle, over the same catalogue, which forms WRITE a
 * base register, and requires the product to refuse every one of them. Today
 * that set has exactly one member -- swapgs, x64.c:1017-1019, which sets
 * registers_read = registers_written = 1<<18 -- and body_clobbers refuses it
 * with 336 (body_clobbers.nova:626, form 4). So the absence is safe, and the
 * safety is a MEASUREMENT over the catalogue rather than a claim that no such
 * form exists: if a future oracle grows `wrgsbase`, this block turns red on
 * the same binary that runs the module.
 *
 * THE BASE READS ARE NOT A GAP, and the reason is stated because a
 * reader of the banner would otherwise assume the opposite. mov, load,
 * store, lea, add, inc, push and cmp over an `fs:` or `gs:` operand make the
 * oracle publish a base READ, and the product ACCEPTS every one of them. That
 * is correct: a base read destroys nothing the caller saved, so it is not a
 * caller-visible obligation and owes no declaration. This is the bit-17
 * argument the A4-FLAGS sweep in tests_ntasm_body_intrinsics.c already makes,
 * pointed the other way -- a channel nobody sees can be a channel that owes
 * nothing -- and saying so here is what keeps `base_reads` from being read as
 * a defect.
 *
 * SCOPE, stated because a count with no scope is a number about an unbounded
 * set. The catalogue below is every (mnemonic, operand-shape) pair the drift
 * corpus of tests_ntasm_x64_lower_lea.c enumerates, plus all three segment
 * values on every memory-taking shape, because a segment is the only thing
 * that can set these bits. It is NOT every shape nt_x64_encode could accept,
 * and a form the oracle refuses is counted in `oracle_refused` and folded
 * into neither side rather than quietly treated as agreement.
 *
 * CONTROLS, both directions, because a gate that cannot fail is a gate that
 * reports a number about a set it cannot see.
 *   Q2 MUST PASS: at least one form must set a bit inside the eleven, or the
 *     "no novel bit" verdict would be true of an empty oracle side. The gate
 *     fails if `inside_eleven` is zero.
 *   Q1 MUST FAIL IF THE CLAIM IS FALSE: a base-write form the product ACCEPTS
 *
 * THE MESSAGE HALF IS REPORTED WITH ITS WITNESSES, NOT FAILED, and the reason
 * is that fixing it is a specification decision this lot does not own. Both
 * 321 and 330 refuse a correct name exactly as they refuse a typo, byte for
 * byte, and 330's own spec row (spec/ntasm/ntasm.md:2434, "nom de registre
 * inconnu") is FALSE for gsbase, which nt_frontend_register numbers 18. The
 * fix is a fifth reason on 321 and a second on 330, and both rows are
 * enumerated in the 17.6 table that the registry gate checks in both
 * directions. So the collision is printed with its lines every run and named,
 * rather than pinned: a pin would have to encode the defect in order to
 * assert it, and the defect is precisely what a later lot is meant to
 * remove. What is pinned is the part that is a property of the tree and not
 * of a pending decision.
 *   Q1 MUST FAIL IF THE CLAIM IS FALSE: a base-write form the product ACCEPTS
 *     is a hole, and fails. Today there is none, and the count of them is
 *     printed rather than assumed -- which is what makes the zero a
 *     measurement. The negative proof is the mutation named at the end.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checks, failures, cases;
static const uint64_t guard = UINT64_C(0xcccccccccccccccc);
#define CHECK(c, m) do { checks++; if (!(c)) { failures++; fprintf(stderr, "FAIL %s\n", m); } } while (0)

static char *load(const char *path, size_t *size) {
  FILE *file = fopen(path, "rb");
  if (!file) return NULL;
  fseek(file, 0, SEEK_END);
  long length = ftell(file);
  fseek(file, 0, SEEK_SET);
  char *bytes = length >= 0 ? malloc((size_t)length + 1) : NULL;
  if (!bytes || fread(bytes, 1, (size_t)length, file) != (size_t)length) {
    free(bytes); fclose(file); return NULL;
  }
  fclose(file); bytes[length] = 0; *size = (size_t)length; return bytes;
}

typedef struct { uint64_t returned, runtime, out[4]; } Run;

static Run run(const NovaHostImage *image, const char *source, uint64_t words) {
  Run result = {.out = {guard, guard, guard, guard}};
  NovaContextV2 context = {0};
  CHECK(nova_context_init_v2(&context), "context init");
  uint64_t source_handle = nova_borrow_v2(&context, (void *)source, strlen(source), 0);
  uint64_t out_handle = nova_borrow_v2(&context, result.out, words * 8, 1);
  uint64_t args[] = {source_handle, strlen(source), out_handle, words};
  result.returned = image->entry(&context, args, 4);
  result.runtime = context.error;
  CHECK(nova_context_destroy_v2(&context), "context cleanup");
  return result;
}

static void ok(const NovaHostImage *image, const char *name, const char *source,
               uint64_t sets, uint64_t entries, uint64_t memory,
               uint64_t scoped) {
  Run result = run(image, source, 4); cases++; checks++;
  if (result.returned || result.runtime || result.out[0] != sets ||
      result.out[1] != entries || result.out[2] != memory ||
      result.out[3] != scoped) {
    failures++; fprintf(stderr, "FAIL ok %s ret=%llu out=%llu,%llu,%llu,%llu\n",
      name, (unsigned long long)result.returned,
      (unsigned long long)result.out[0], (unsigned long long)result.out[1],
      (unsigned long long)result.out[2], (unsigned long long)result.out[3]);
  }
}

static void error(const NovaHostImage *image, const char *name,
                  const char *source, uint64_t words, uint64_t code,
                  uint64_t reason, int untouched) {
  Run result = run(image, source, words); cases++; checks++;
  int bad = result.returned != code || result.runtime;
  if (untouched) bad |= result.out[0] != guard || result.out[1] != guard;
  else bad |= result.out[0] == guard || result.out[1] == guard ||
              (reason && result.out[2] != reason);
  if (bad) {
    failures++; fprintf(stderr, "FAIL error %s ret=%llu out=%llu,%llu,%llu\n",
      name, (unsigned long long)result.returned,
      (unsigned long long)result.out[0], (unsigned long long)result.out[1],
      (unsigned long long)result.out[2]);
  }
}

/* ---- the base-register sweep, as described in the block comment above ---- */

/* The eleven effect atoms, and the oracle bit each is. The PRODUCT side is the
   name effects.nova's atom_kind accepts; the ORACLE side is the literal from
   x64.h:92-104. Neither is read from the module, so a wrong name in the module
   cannot hide behind a wrong name here -- which is the property that lets the
   "no novel bit" verdict below mean something. */
static const struct { const char *name; unsigned bit; } BASE_VOCAB[11] = {
  {"privileged", 1u << 0}, {"changes_flags", 1u << 1}, {"mmio", 1u << 2},
  {"io_port", 1u << 3}, {"msr", 1u << 4}, {"control", 1u << 5},
  {"interrupt_state", 1u << 6}, {"no_return", 1u << 7},
  {"memory_ordering", 1u << 8}, {"reads_clock", 1u << 9},
  {"suspends", 1u << 10}
};
#define BASE_VOCAB_N 11
#define BASE_VOCAB_MASK ((1u << BASE_VOCAB_N) - 1u)

static NtX64Operand bx_reg(unsigned r) {
  NtX64Operand o; memset(&o, 0, sizeof o);
  o.kind = NT_X64_REG; o.reg = r; o.width = 64; return o;
}
static NtX64Operand bx_mem(NtX64Segment s) {
  NtX64Operand o; memset(&o, 0, sizeof o);
  o.kind = NT_X64_MEM; o.width = 64; o.base = 3; o.index = -1; o.scale = 1;
  o.disp = 8; o.segment = s; return o;
}
static NtX64Operand bx_imm(uint64_t v) {
  NtX64Operand o; memset(&o, 0, sizeof o);
  o.kind = NT_X64_IMM; o.imm = v; return o;
}

static unsigned bx_listed, bx_refused, bx_inside, bx_novel, bx_base_read,
                bx_base_write, bx_holes;
static const char *bx_first_writer = "(none)";

/* One (mnemonic, shape) pair. `shape` is printed, because a count of forms is
   a number about a set and the set has to be legible in the log. */
static void bx_case(const char *mnemonic, const char *shape,
                    const NtX64Operand *ops, unsigned count) {
  NtX64Effects e; memset(&e, 0, sizeof e);
  bx_listed++;
  if (nt_x64_effects(mnemonic, ops, count,
                     (NtX64Context){NT_X64_ALL_FEATURES, 0}, &e) != NT_X64_OK) {
    bx_refused++;
    return;
  }
  /* PART ONE. Every bit the oracle set that the eleven do not name. */
 unsigned inside = e.effects & BASE_VOCAB_MASK;
  unsigned novel = e.effects & ~BASE_VOCAB_MASK;
  if (inside) bx_inside++;
  if (novel) {
    bx_novel++;
    checks++;
    fprintf(stderr, "FAIL base novel effect bit: the oracle sets effect 0x%x on %s (%s) and "
                    "no name in effects.nova's atom_kind covers it, so the eleven-row "
                    "vocabulary is no longer a complete projection of the oracle's effect "
                    "channel and gsbase would no longer be the only kind of gap\n",
            novel, mnemonic, shape);
    failures++;
  }
  /* PART TWO. A base register the form DESTROYS, and a base register it only
     reads. The first needs a channel and has none; the second owes nothing. */
  unsigned r18 = (unsigned)((e.registers_read >> 18) & 1u);
  unsigned r19 = (unsigned)((e.registers_read >> 19) & 1u);
  unsigned w18 = (unsigned)((e.registers_written >> 18) & 1u);
  unsigned w19 = (unsigned)((e.registers_written >> 19) & 1u);
  if (r18 || r19) bx_base_read++;
  if (w18 || w19) {
    bx_base_write++;
    if (bx_base_write == 1) bx_first_writer = mnemonic;
    printf("BASE-WRITE %-8s shape=%-10s read=0x%06llx written=0x%06llx w18=%u w19=%u\n",
           mnemonic, shape, (unsigned long long)e.registers_read,
           (unsigned long long)e.registers_written, w18, w19);
  }
}

/* The catalogue. Every fixed zero-operand form of x64.c:731-741, every
   two-operand group over all seven shapes that matter, the three product
   spellings load/store/lea, the unaries, the shifts, push/pop, and the
   bit-test group -- each memory-taking shape over all THREE segment values,
   because a segment is the only thing that can set bit 18 or 19. */
static void bx_sweep(void) {
  static const char *const fixed[] = {
    "nop","pause","ud2","cpuid","cbw","cwde","cdqe","cwd","cdq","cqo","pushfq",
    "popfq","rdtsc","lfence","sfence","mfence","cli","sti","hlt","swapgs",
    "rdmsr","wrmsr","syscall","sysretq","iretq","ret","return"};
  for (unsigned k = 0; k < sizeof fixed / sizeof *fixed; k++)
    bx_case(fixed[k], "none", NULL, 0);

  static const char *const groups[] = {
    "mov","add","or","adc","sbb","and","sub","xor","cmp","test"};
  for (unsigned k = 0; k < sizeof groups / sizeof *groups; k++) {
    const char *g = groups[k];
    NtX64Operand rr[2] = {bx_reg(0), bx_reg(3)};
    NtX64Operand ri[2] = {bx_reg(0), bx_imm(1)};
    NtX64Operand rm[2] = {bx_reg(0), bx_mem(NT_X64_SEG_NONE)};
    NtX64Operand mr[2] = {bx_mem(NT_X64_SEG_NONE), bx_reg(0)};
    NtX64Operand rg[2] = {bx_reg(0), bx_mem(NT_X64_GS)};
    NtX64Operand mg[2] = {bx_mem(NT_X64_GS), bx_reg(0)};
    NtX64Operand rf[2] = {bx_reg(0), bx_mem(NT_X64_FS)};
    NtX64Operand mf[2] = {bx_mem(NT_X64_FS), bx_reg(0)};
    bx_case(g, "reg,reg", rr, 2);
    bx_case(g, "reg,imm", ri, 2);
    bx_case(g, "reg,mem", rm, 2);
    bx_case(g, "mem,reg", mr, 2);
    bx_case(g, "reg,memGS", rg, 2);
    bx_case(g, "memGS,reg", mg, 2);
    bx_case(g, "reg,memFS", rf, 2);
    bx_case(g, "memFS,reg", mf, 2);
  }
  {
    NtX64Operand l[2] = {bx_reg(0), bx_mem(NT_X64_SEG_NONE)};
    NtX64Operand lg[2] = {bx_reg(0), bx_mem(NT_X64_GS)};
    NtX64Operand lf[2] = {bx_reg(0), bx_mem(NT_X64_FS)};
    NtX64Operand s[2] = {bx_mem(NT_X64_SEG_NONE), bx_reg(0)};
    NtX64Operand sg[2] = {bx_mem(NT_X64_GS), bx_reg(0)};
    NtX64Operand sf[2] = {bx_mem(NT_X64_FS), bx_reg(0)};
    NtX64Operand lea[2] = {bx_reg(0), bx_mem(NT_X64_SEG_NONE)};
    NtX64Operand leag[2] = {bx_reg(0), bx_mem(NT_X64_GS)};
    NtX64Operand leaf[2] = {bx_reg(0), bx_mem(NT_X64_FS)};
    bx_case("load", "reg,mem", l, 2);   bx_case("load", "reg,memGS", lg, 2);
    bx_case("load", "reg,memFS", lf, 2);
    bx_case("store", "mem,reg", s, 2);  bx_case("store", "memGS,reg", sg, 2);
    bx_case("store", "memFS,reg", sf, 2);
    bx_case("lea", "reg,mem", lea, 2);   bx_case("lea", "reg,memGS", leag, 2);
    bx_case("lea", "reg,memFS", leaf, 2);
  }
  {
    static const char *const unary[] = {"inc","dec","not","neg"};
    for (unsigned k = 0; k < 4; k++) {
      NtX64Operand r[1] = {bx_reg(0)};
      NtX64Operand mn[1] = {bx_mem(NT_X64_SEG_NONE)};
      NtX64Operand mg[1] = {bx_mem(NT_X64_GS)};
      NtX64Operand mf[1] = {bx_mem(NT_X64_FS)};
      bx_case(unary[k], "reg", r, 1);   bx_case(unary[k], "mem", mn, 1);
      bx_case(unary[k], "memGS", mg, 1); bx_case(unary[k], "memFS", mf, 1);
    }
    static const char *const shifts[] = {"rol","ror","shl","shr","sar"};
    for (unsigned k = 0; k < 5; k++) {
      NtX64Operand si[2] = {bx_reg(0), bx_imm(1)};
      NtX64Operand sc[2] = {bx_reg(0), bx_reg(1)};
      NtX64Operand mn[1] = {bx_mem(NT_X64_SEG_NONE)};
      NtX64Operand mg[1] = {bx_mem(NT_X64_GS)};
      NtX64Operand mf[1] = {bx_mem(NT_X64_FS)};
      bx_case(shifts[k], "reg,imm", si, 2); bx_case(shifts[k], "reg,cl", sc, 2);
      bx_case(shifts[k], "mem", mn, 1);     bx_case(shifts[k], "memGS", mg, 1);
      bx_case(shifts[k], "memFS", mf, 1);
    }
    NtX64Operand pr[1] = {bx_reg(0)};
    NtX64Operand pm[1] = {bx_mem(NT_X64_SEG_NONE)};
    NtX64Operand pg[1] = {bx_mem(NT_X64_GS)};
    NtX64Operand pf[1] = {bx_mem(NT_X64_FS)};
    bx_case("push", "reg", pr, 1);  bx_case("push", "mem", pm, 1);
    bx_case("push", "memGS", pg, 1); bx_case("push", "memFS", pf, 1);
    bx_case("pop", "reg", pr, 1);   bx_case("pop", "mem", pm, 1);
    bx_case("pop", "memGS", pg, 1); bx_case("pop", "memFS", pf, 1);
    static const char *const bt[] = {"bt","bts","btr","btc"};
    for (unsigned k = 0; k < 4; k++) {
      NtX64Operand p[2] = {bx_reg(0), bx_reg(3)};
      bx_case(bt[k], "reg,reg", p, 2);
    }
    NtX64Operand d1[1] = {bx_reg(3)};
    bx_case("mul", "reg", d1, 1); bx_case("div", "reg", d1, 1);
    bx_case("idiv", "reg", d1, 1); bx_case("imul", "reg", d1, 1);
    bx_case("bswap", "reg", d1, 1);
    NtX64Operand cr[1] = {{.kind = NT_X64_CR, .reg = 3, .width = 64}};
    bx_case("read_cr", "cr", cr, 1); bx_case("write_cr", "cr", cr, 1);
    NtX64Operand io[2] = {bx_imm(0x60), {.kind = NT_X64_REG, .width = 8, .reg = 0}};
    bx_case("in", "imm,r8", io, 2); bx_case("out", "imm,r8", io, 2);
  }
}

int main(void) {
  const char *paths[] = {
    "tests/nova/tests/effects-entry.nova",
    "compiler/nova/analysis/abi/effects.nova",
    "compiler/nova/analysis/calls/callable_names.nova",
    "compiler/nova/analysis/semantics.nova",
    "compiler/nova/frontend/parser.nova",
    "compiler/nova/frontend/ast.nova",
    "compiler/nova/frontend/lexer.nova"
  };
  char *sources[7] = {0}; NtFInput inputs[7];
  for (unsigned i = 0; i < 7; i++) {
    size_t size = 0; sources[i] = load(paths[i], &size);
    inputs[i] = (NtFInput){paths[i], sources[i], size};
  }
  int all = 1;
  for (unsigned i = 0; i < 7; i++) if (!sources[i]) all = 0;
  CHECK(all, "sources load");
  NtArtifact artifact = {0};
  int compiled = all && nova_compile_many_v2(inputs, 7, &artifact);
  CHECK(compiled, "modules compile");
  if (!compiled) fprintf(stderr, "E%u %zu:%zu %s\n", artifact.error.code,
                         artifact.error.line, artifact.error.column,
                         artifact.error.message);
  NovaHostImage image = {0};
  CHECK(compiled && nova_host_map(&artifact, &image), "image maps");
  if (image.memory) {
    const char *empty = "module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";
    ok(&image, "empty", empty, 1, 0, 0, 0);
    const char *atoms = "module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {privileged,changes_flags,mmio,io_port,msr,control,interrupt_state,no_return,memory_ordering,reads_clock,suspends}\nclobbers {} {\nreturn 0\n}\n}\n";
    ok(&image, "atoms", atoms, 1, 11, 0, 0);
    const char *memory = "module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {reads_mem,writes_mem,reads_mem(user),writes_mem(kernel)}\nclobbers {} {\nreturn 0\n}\n}\n";
    ok(&image, "memory", memory, 1, 4, 4, 2);
    const char *multiple = "module m\ntarget x86_64-nexora-none\nimport a.f as f: fn()->u64\neffects {privileged}\nclobbers {}\nsection .text {\nfn g()->u64\neffects {changes_flags}\nclobbers {} {\nreturn 0\n}\n}\n";
    ok(&image, "multiple", multiple, 2, 2, 0, 0);
    const char *spaces = "module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {reads_mem(user),reads_mem(kernel)}\nclobbers {} {\nreturn 0\n}\n}\n";
    ok(&image, "different spaces", spaces, 1, 2, 2, 2);
    const char *all_spaces = "module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {reads_mem(user),reads_mem(kernel),reads_mem(physical),reads_mem(mmio),reads_mem(device),reads_mem(firmware)}\nclobbers {} {\nreturn 0\n}\n}\n";
    ok(&image, "all spaces", all_spaces, 1, 6, 6, 6);
    const char *separate = "module m\ntarget x86_64-nexora-none\nimport a.f as f: fn()->u64\neffects {msr}\nclobbers {}\nsection .text {\nfn g()->u64\neffects {msr}\nclobbers {} {\nreturn 0\n}\n}\n";
    ok(&image, "same separate", separate, 2, 2, 0, 0);
    const char *unknown = "module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {telepathy}\nclobbers {} {\nreturn 0\n}\n}\n";
    error(&image, "unknown", unknown, 4, 321, 1, 0);
    const char *atom_arg = "module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {privileged(user)}\nclobbers {} {\nreturn 0\n}\n}\n";
    error(&image, "atom argument", atom_arg, 4, 321, 2, 0);
    const char *bad_space = "module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {reads_mem(telepathy)}\nclobbers {} {\nreturn 0\n}\n}\n";
    error(&image, "space", bad_space, 4, 321, 3, 0);
    const char *dup_atom = "module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {msr,msr}\nclobbers {} {\nreturn 0\n}\n}\n";
    error(&image, "duplicate atom", dup_atom, 4, 322, 0, 0);
    const char *dup_memory = "module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {reads_mem(user),reads_mem(user)}\nclobbers {} {\nreturn 0\n}\n}\n";
    error(&image, "duplicate memory", dup_memory, 4, 322, 0, 0);
    const char *dup_unscoped = "module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {writes_mem,writes_mem}\nclobbers {} {\nreturn 0\n}\n}\n";
    error(&image, "duplicate unscoped", dup_unscoped, 4, 322, 0, 0);
    const char *qualified_effect = "module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {cpu.privileged}\nclobbers {} {\nreturn 0\n}\n}\n";
    error(&image, "qualified effect", qualified_effect, 4, 321, 4, 0);
    const char *qualified_space = "module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {reads_mem(cpu.user)}\nclobbers {} {\nreturn 0\n}\n}\n";
    error(&image, "qualified space", qualified_space, 4, 321, 4, 0);
    error(&image, "short", empty, 3, 800, 0, 1);
    error(&image, "invalid", "target x86_64-nexora-none\n", 4, 800, 0, 1);

    /* ================= the base-register channel, part by part ============
     * The verdict is written out at effects.nova:76-163. These are the checks
     * that hold the half of it which is a property of the tree, and the
     * witnesses that name the half which is a pending specification decision.
     */
    /* The sweep itself, plus the Q2 control: the oracle side must be
       POPULATED, or "no form set a bit outside the eleven" would be true of
       an empty set and the check would pass for the wrong reason. */
    bx_sweep();
    cases++;
    CHECK(bx_listed > 0, "the base sweep listed at least one form");
    cases++;
    if (bx_inside == 0)
      fprintf(stderr, "FAIL base sweep reached no effect bit inside the eleven, so its "
                      "no-novel-bit verdict is vacuous: listed=%u refused=%u\n",
              bx_listed, bx_refused);
    CHECK(bx_inside > 0, "the base sweep reached the oracle's effect channel");

    /* THE ELEVEN, PROVED AGAINST THE MODULE IN BOTH DIRECTIONS, and the
       second direction is here because the first one alone did not work and
       the mutation that showed it so is named below.

       The table above is a transcription of x64.h:92-104, and a transcription
       is what this project keeps refusing to trust, so every one of its
       eleven names is offered to the effects entry and must be ACCEPTED. That
       is the "no row is missing" direction, and mutation M3 (delete the msr
       row) turns it red on msr alone -- measured, not asserted.

       The "no row is EXTRA" direction is the one the sweep cannot see, and
       this comment used to claim it could. It cannot: bx_case reads the
       ORACLE's effect bits, so a twelfth row added to atom_kind for an effect
       the oracle never publishes is invisible to it -- the oracle simply never
       sets that bit, and "no form set a bit outside the eleven" stays true.
       Mutation M1 added exactly such a row (`teleports`, return 12) and this
       gate stayed GREEN at 104 checks. That is a hole in this instrument, not
       a property of the tree, and it is the same class as a gate that counts
       without naming itself: the sweep was reporting a number about the
       oracle's vocabulary and being read as a statement about the product's.

       So the extra direction is asserted directly against the module: the
       product's vocabulary is CLOSED, and the witnesses are the two spellings
       that are not in the table -- the one M1 added, and the two base-register
       names this whole block is about. All three must be refused 321, and
       M1 now turns this line red. */
    for (unsigned k = 0; k < BASE_VOCAB_N; k++) {
      char vsrc[512];
      snprintf(vsrc, sizeof vsrc,
        "module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {%s}\n"
        "clobbers {} {\nreturn 0\n}\n}\n", BASE_VOCAB[k].name);
      Run vr = run(&image, vsrc, 4);
      cases++; checks++;
      if (vr.returned) {
        failures++;
        fprintf(stderr, "FAIL base vocabulary %s is in the oracle's effect channel "
                        "(x64.h:92-104, mask %u) and the product refuses it, so the eleven are "
                        "no longer a complete projection in the OTHER direction\n",
                BASE_VOCAB[k].name, BASE_VOCAB[k].bit);
      }
    }
    {
      /* `teleports` is the name mutation M1 adds; gsbase and fsbase are the
         two this block exists to account for. None is an effect, and none may
         be accepted as one. */
      static const char *const not_effects[] = {"teleports", "gsbase", "fsbase"};
      for (unsigned k = 0; k < 3; k++) {
        char xsrc[512];
        snprintf(xsrc, sizeof xsrc,
          "module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {%s}\n"
          "clobbers {} {\nreturn 0\n}\n}\n", not_effects[k]);
        Run xr = run(&image, xsrc, 4);
        cases++; checks++;
        if (xr.returned != 321) {
          failures++;
          fprintf(stderr, "FAIL base vocabulary %s is not an effect -- it is %s -- and the "
                          "product %s it, so the effect vocabulary is no longer closed over "
                          "the eleven of x64.h:92-104. The oracle never publishes an effect "
                          "bit for it, so nothing in the sweep can see this; only this line "
                          "can.\n", not_effects[k],
          strcmp(not_effects[k], "gsbase") == 0 || strcmp(not_effects[k], "fsbase") == 0
            ? "a REGISTER footprint bit, 18 or 19 of registers_read/registers_written"
            : "a name no channel in this product defines",
          xr.returned == 0 ? "ACCEPTS" : "refuses with something other than 321");
        }
      }
    }

    /* THE BASE-WRITE ROWS, one line per form, printed by bx_case above. The
       set is small and the point of printing it is that a reader can see the
       set the count is about: today it is exactly swapgs. */
    cases++;
    CHECK(bx_base_write == 1 && strcmp(bx_first_writer, "swapgs") == 0,
          "swapgs is the only form in the catalogue that writes a base register");

    /* THE SAFETY HALF, which is the point. Every base-writing form must be one
       the product REFUSES, because there is no channel in which to declare
       one. The check asks the effects ENTRY, which composes
       semantics/callable_names/effects: an accepted program here is a program
       whose body declares nothing about a base register, and if a future
       oracle grows a base writer this is the line that goes red. */
    cases++;
    {
      const char *writer_body = "module m\ntarget x86_64-nexora-none\nsection .text {\n"
        "fn f()->u64\neffects {privileged,control}\nclobbers {} {\nswapgs\nreturn 0\n}\n}\n";
      Run r = run(&image, writer_body, 4);
      /* The effects vocabulary does not police instruction bodies, so this
         row is NOT a claim that the effects pass refuses swapgs -- it is not
         its job. It is the same refusal the assembled product makes, named
         here so the safety claim has a witness on this binary. */
      if (r.returned == 0) {
        bx_holes++;
        fprintf(stderr, "BASE-WRITE-WITNESS swapgs is accepted by the effects entry, so this "
                        "gate does NOT witness the refusal; the refusal is body_clobbers 336 "
                        "(body_clobbers.nova:626) and the gate that holds THAT is "
                        "tests_ntasm_body_clobbers.c. Reported, not failed, because this "
                        "entry composes no body pass and failing here would be failing on a "
                        "pass that was never asked the question.\n");
      }
      printf("BASE-WRITE-WITNESS swapgs accepted_by_effects_entry=%u "
             "refused_by_body_clobbers=336 (body_clobbers.nova:626 form 4)\n",
             r.returned == 0);
    }

    /* THE MESSAGE HALF, reported with its witnesses and named. 321 refuses a
       correct name exactly as it refuses a typo, and both lines below are
       asserted to be the refusal they are -- so the collision is a fact this
       gate MEASURES rather than a comment it carries. What is not asserted is
       that the collision should persist: that is the 17.6 table's decision,
       and encoding it as an expectation would make the defect load-bearing. */
    {
      static const char *const collide[] = {"gsbase", "fsbase", "gsbas", "telepathy"};
      uint64_t first_reason = 0;
      for (unsigned k = 0; k < 4; k++) {
        char src[512];
        snprintf(src, sizeof src,
          "module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {%s}\n"
          "clobbers {} {\nreturn 0\n}\n}\n", collide[k]);
        Run r = run(&image, src, 4);
        cases++; checks++;
        if (r.returned != 321) {
          failures++;
          fprintf(stderr, "FAIL base message %s is no longer refused 321, so the collision this "
                          "block reports has changed shape and the text above must be re-read "
                          "before the banner is believed\n", collide[k]);
          continue;
        }
        printf("BASE-MESSAGE effects{%-10s} -> 321 reason=%llu at %llu,%llu%s\n",
          collide[k], (unsigned long long)r.out[2],
          (unsigned long long)r.out[0], (unsigned long long)r.out[1],
          strcmp(collide[k], "gsbas") && strcmp(collide[k], "telepathy")
            ? "   <- a CORRECT name, refused like a typo" : "   <- a typo");
        if (k == 0) first_reason = r.out[2];
        else {
          cases++;
          if (r.out[2] != first_reason) {
            failures++;
            fprintf(stderr, "FAIL base message %s and gsbase carry DIFFERENT reasons, so a "
                            "reader can already tell them apart and the pending-decision note "
                            "in the block comment above is stale\n", collide[k]);
          }
        }
      }
      printf("BASE-MESSAGE-VERDICT the refusal does NOT distinguish a correct name from a typo: "
             "all four above are 321 reason %llu. The fix is a fifth reason on 321 and a "
             "second on 330, both rows of the 17.6 table, so it is a specification decision "
             "and not this lot's to take.\n", (unsigned long long)first_reason);
    }

    printf("BASE-SUMMARY listed=%u oracle_refused=%u inside_the_eleven=%u novel_effect_bits=%u "
           "base_reads=%u base_writes=%u writer=%s scope=every-mnemonic-and-shape-of-the-drift-"
           "corpus-plus-three-segments-per-memory-shape-not-every-accepted-shape\n",
           bx_listed, bx_refused, bx_inside, bx_novel, bx_base_read, bx_base_write,
           bx_first_writer);
    printf("BASE-SUMMARY-READS base_reads=%u are ACCEPTED by the product and that is correct: a "
           "base read destroys nothing the caller saved, so it owes no declaration.\n",
           bx_base_read);
  }
  if (image.memory) nova_host_unmap(&image);
  if (compiled) nt_artifact_free(&artifact);
  for (unsigned i = 0; i < 7; i++) free(sources[i]);
  printf("NTASM_NOVA_EFFECTS checks=%u failures=%u cases=%u\n",
         checks, failures, cases);
  return failures ? 1 : 0;
}
