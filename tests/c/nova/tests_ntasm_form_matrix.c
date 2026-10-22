/* tests_ntasm_form_matrix.c -- the x86-64 FORM coverage matrix, keyed by the
 * operand shape the C encoder actually accepts.
 *
 * WHY THIS FILE EXISTS. docs/status/ntasm-completion.md A2 asserted « les 10 formes
 * structurelles x 4 largeurs sont couvertes ». That sentence occurred once in
 * the project, zero times in spec/ntasm/ntasm.md, and nothing in the tree could
 * falsify it: the spec never names ten forms, and no harness mentions both a
 * form and an encoding field. An affirmation whose verifying artefact does not
 * exist is an affirmation wearing the clothes of a measurement, which
 * docs/status/ntasm-completion.md itself forbids. So the forms are here derived from
 * the operands and printed, and the count is a measured number rather than a
 * sentence.
 *
 * WHAT A FORM IS, AND WHY NOT THE MNEMONIC. A form is the SHAPE of an operand
 * list: its arity, the sequence of operand KINDS, and the WIDTH each operand
 * carries. The encoder decides it -- nt_x64_encode in x64.c, the frozen C
 * quarantine, which x64_fixed.nova is compared against byte for byte. Nothing
 * here re-implements the encoder and no byte in this file is a literal: every
 * expected byte in the printed matrix is whatever the oracle returned on this
 * run.
 *
 * HOW THE SET IS DERIVED, and the three blind instruments that preceded it.
 * All three were measured on earlier revisions of this file, and each one
 * printed a complete, confident, wrong number:
 *
 *   v1 asked « is (kind,width) accepted by ANY mnemonic » and admitted arity 0.
 *   A fixed[] mnemonic takes count==0 and never reads the operand array --
 *   x64.c:757 returns NT_X64_COUNT for any nonzero count, so the operand is
 *   never examined. v1 was therefore answered `nop` for every shape and printed
 *   30 of 30 accepted. A fixed[] mnemonic is not evidence about an operand it
 *   does not read, so v1 admitted arity>=1.
 *
 *   v2 then applied ONE width to every position. The encoder admits
 *   heterogeneous lists -- movzx r32, r/m8 carries two widths in one form -- so
 *   a uniform-width reading cannot see them at all. v2 printed 52.
 *
 *   v3 enumerated per-position widths and printed 149 accepted of 47988, of
 *   which 97 are heterogeneous. That is the number a uniform reading loses.
 *
 *   v4/v5 then asked the question the form count actually depends on and
 *   published its own limits. THE COUNT IS A FUNCTION OF THE INSTANTIATION
 *   SET, and that is not a caveat, it is the measurement: with a single
 *   register (rax) the set is 149 forms, and with the twelve registers that
 *   reach the accumulator, the shift count cl, the port dx and the REX range,
 *   it is 154. Five forms exist only because the encoder names a register.
 *   An instrument that published one of these two numbers without saying which
 *   set produced it would be reporting a property of its own fixture.
 *
 * BOTH HALVES OF EVERY ROW. Each row carries the bytes of a NAMED
 * representative and at least one case that must be REFUSED. A form with no
 * forbidden case is a form nothing constrains: the bytes would then be a
 * sample rather than a boundary, and a sample cannot be falsified.
 *
 * THE MATRIX IS WRITTEN BY A RUN. The path is given by the first argument; the
 * file is the evidence, and this harness is what fills it. A cell that cannot
 * be filled says why in the row itself rather than being omitted, which is the
 * discipline the census already uses per cell.
 */
#include "../../../compiler/c/ntasm/backend/x64.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checks, failures, cases;

/* The catalogue the sweep runs against, in TWO classes, because they are not
 * the same kind of evidence and using them as one is the blindness this file
 * was born from.
 *
 * FIXED_CATALOGUE is fixed[] of x64.c:729-743. Every member takes count==0 and
 * returns NT_X64_COUNT for any nonzero count WITHOUT READING THE OPERAND
 * (x64.c:757). At the arity>=1 this matrix uses, a fixed[] mnemonic can
 * therefore never accept, and as a REFUSAL it is worthless: "nop refused this
 * shape with 402" is a fact about nop, not about the shape. MEASURED on the
 * first revision of this file: `nop` was the named refuser on 148 of 154 rows,
 * and six rows had no refusal at all.
 *
 * VARIABLE_CATALOGUE is what variable() dispatches on. Only these can accept a
 * form, and only these can refuse one in a way that says something about the
 * shape. */
static const char *FIXED_CATALOGUE[] = {
    "nop", "pause", "ud2", "cpuid", "cbw", "cwde", "cdqe", "cwd", "cdq", "cqo",
    "pushfq", "popfq", "rdtsc", "lfence", "sfence", "mfence", "cli", "sti",
    "hlt", "swapgs", "rdmsr", "wrmsr", "syscall", "sysretq", "iretq", "ret",
    "return"};
#define NFIXED (sizeof FIXED_CATALOGUE / sizeof *FIXED_CATALOGUE)
static const char *VARIABLE_CATALOGUE[] = {
    "mov", "load", "store", "lea", "add", "or", "adc", "sbb", "and", "sub",
    "xor", "cmp", "test", "inc", "dec", "not", "neg", "shl", "shr", "sar",
    "rol", "ror", "imul", "mul", "div", "idiv", "push", "pop", "call", "jmp",
    "jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja", "js", "jns", "jp",
    "jnp", "jl", "jge", "jle", "jg", "read_cr", "write_cr", "movzx", "movsx",
    "movsxd", "sete", "setne", "setb", "setae", "setbe", "seta", "sets",
    "setns", "setp", "setnp", "setl", "setge", "setle", "setg", "seto",
    "setno", "cmove", "cmovne", "cmovb", "cmovae", "cmovbe", "cmova", "cmovs",
    "cmovns", "cmovp", "cmovnp", "cmovl", "cmovge", "cmovle", "cmovg",
    "cmovo", "cmovno", "bswap", "bt", "bts", "btr", "btc", "bsf", "bsr",
    "xchg", "sgdt", "sidt", "lgdt", "lidt", "ltr", "invlpg", "in", "out"};
#define NFIXED (sizeof FIXED_CATALOGUE / sizeof *FIXED_CATALOGUE)
#define NVARIABLE (sizeof VARIABLE_CATALOGUE / sizeof *VARIABLE_CATALOGUE)
#define NCATALOGUE (NFIXED + NVARIABLE)

static const char *KIND_NAME[] = {"NONE", "REG", "IMM", "MEM", "REL", "CR"};
#define NKIND 6

/* The width candidates. 0 and 80 are not decoration: 0 is the optional
 * immediate width of x64.h:70 and the address-only memory of invlpg, and 80
 * is the descriptor width of sgdt/sidt/lgdt/lidt. The scalar widths are
 * scalar_width() of x64.c:10. */
static const unsigned WIDTHS[] = {0, 8, 16, 32, 64, 80};
#define NWIDTH (sizeof WIDTHS / sizeof *WIDTHS)

/* The instantiation set. See the header: the count is a function of this, so
 * it is named, sized, and printed rather than left implicit. r0 is the
 * accumulator, r1 the shift count cl, r2 the port dx, r8..r15 the REX range. */
static const unsigned INSTANTIATION[] = {0, 1, 2, 3, 8, 9, 10, 11, 12, 13, 14, 15};
#define NINST (sizeof INSTANTIATION / sizeof *INSTANTIATION)

/* The single-register set, kept so the header's 149 claim stays checkable. */
static const unsigned SINGLE_REG[] = {0};
#define NSINGLE 1

static NtX64Operand operand_of(int kind, unsigned width, unsigned reg) {
  NtX64Operand o;
  memset(&o, 0, sizeof o);
  o.kind = (NtX64Kind)kind;
  o.width = width;
  o.base = -1;
  o.index = -1;
  o.scale = 1;
  switch (kind) {
  case NT_X64_REG: o.reg = reg & 15u; break;
  case NT_X64_CR:  o.reg = 0; break;            /* cr0, the one that is present */
  case NT_X64_IMM: o.imm = 4; break;            /* imm32 range: fits at every width */
  case NT_X64_REL: o.imm = 4; o.is_signed = 1; break;
  case NT_X64_MEM: o.base = 3; o.index = -1; o.scale = 1; o.disp = 8; break;
  default: break;
  }
  return o;
}

/* One accepted form, as the matrix holds it. */
typedef struct {
  unsigned arity;
  int kind[3];
  unsigned width[3];
  const char *representative;   /* the mnemonic the bytes come from */
  unsigned reg;                 /* the instantiation that made it encode */
  unsigned length;
  unsigned char bytes[16];
  const char *refused_mnemonic; /* a case the oracle REFUSES for this shape */
  NtX64Error refused_code;
  char refused_why[192];
} Form;

static void print_bytes(const unsigned char *b, unsigned n, char *out, size_t cap) {
  size_t at = 0;
  out[0] = 0;
  for (unsigned i = 0; i < n && at + 3 < cap; i++)
    at += (size_t)snprintf(out + at, cap - at, "%02x", b[i]);
}

static void shape_name(const Form *f, char *out, size_t cap) {
  char k[3][8];
  for (unsigned i = 0; i < f->arity; i++)
    snprintf(k[i], sizeof k[i], "%s", KIND_NAME[f->kind[i]]);
  if (f->arity == 1)
    snprintf(out, cap, "%s/%u", k[0], f->width[0]);
  else if (f->arity == 2)
    snprintf(out, cap, "%s,%s/%u,%u", k[0], k[1], f->width[0], f->width[1]);
  else
    snprintf(out, cap, "%s,%s,%s/%u,%u,%u", k[0], k[1], k[2], f->width[0],
             f->width[1], f->width[2]);
}

/* Ask the oracle about one shape under one instantiation. Returns NT_X64_OK
 * and fills out, or the refusal. */
static NtX64Error ask(const int *kind, const unsigned *width, unsigned arity,
                      unsigned reg, NtX64Instruction *out,
                      const char **which_mnemonic) {
  NtX64Operand ops[3];
  for (unsigned i = 0; i < arity; i++) ops[i] = operand_of(kind[i], width[i], reg);
  NtX64Context ctx = {NT_X64_ALL_FEATURES, 0};
  memset(out, 0, sizeof *out);
  *which_mnemonic = 0;
  /* Only variable() mnemonics. A fixed[] mnemonic cannot accept at arity>=1
   * (x64.c:757), so including it here could only ever return a refusal, and a
   * refusal from a mnemonic that never read the operand is not evidence. */
  for (unsigned c = 0; c < NVARIABLE; c++) {
    memset(out, 0, sizeof *out);
    if (nt_x64_encode(VARIABLE_CATALOGUE[c], ops, arity, ctx, out) == NT_X64_OK) {
      *which_mnemonic = VARIABLE_CATALOGUE[c];
      return NT_X64_OK;
    }
  }
  for (unsigned c = 0; c < NVARIABLE; c++) {
    memset(out, 0, sizeof *out);
    NtX64Error e = nt_x64_encode(VARIABLE_CATALOGUE[c], ops, arity, ctx, out);
    if (e != NT_X64_OK) {
      *which_mnemonic = VARIABLE_CATALOGUE[c];
      return e;
    }
  }
  /* Nothing in variable() recognised the shape at all. Reported as UNKNOWN
   * rather than dressed up as a refusal: « no mnemonic knows this name » is a
   * different fact from « a mnemonic read this operand and said no ». */
  return NT_X64_UNKNOWN;
}
/* Ask ONE named mnemonic. This is the refusal a row should report: the
 * encoder that ACCEPTS the row, asked about a near-miss of the row, saying no.
 * A refusal from some other mnemonic can be an arity fact (see the 402 that
 * 148 rows reported before this existed) rather than a fact about the form. */
static NtX64Error ask_one(const char *name, const int *kind,
                          const unsigned *width, unsigned arity, unsigned reg,
                          NtX64Instruction *out) {
  NtX64Operand ops[3];
  for (unsigned i = 0; i < arity; i++) ops[i] = operand_of(kind[i], width[i], reg);
  NtX64Context ctx = {NT_X64_ALL_FEATURES, 0};
  memset(out, 0, sizeof *out);
  return nt_x64_encode(name, ops, arity, ctx, out);
}


/* The refused half of a row: the NEAREST shape the oracle refuses, searched
 * over three axes in a fixed order, so the refusal is a boundary of the row
 * and not an unrelated form.
 *
 * WHY THREE AXES, MEASURED. The first version perturbed WIDTH only, and six
 * rows came back with no refusal at all -- every MEM row. The reason is real
 * and worth keeping: the memory width is not a property of the FORM but of
 * the mnemonic, so across the catalogue every memory width is accepted by
 * SOME mnemonic (inc takes 0/8/16/32/64, sgdt takes 80) and a width
 * perturbation of a MEM row always lands on another accepted form. The
 * boundary of a memory form is its ADDRESS, not its width, and the encoder
 * says so: operand_valid refuses base > 15, index == 4 (rsp cannot be an
 * index) and a scale outside 1/2/4/8 with NT_X64_ADDRESS (x64.c:59-65).
 *
 * The order is width, then kind, then address, and it is stated rather than
 * implied because a reader comparing two rows needs to know which boundary
 * each row is reporting. */
static void find_refusal(Form *f) {
  NtX64Instruction probe;
  const char *which = 0;
  char nm[96];

  /* axis 0: the row's OWN representative, asked about a near-miss. This is the
   * tightest boundary available and the one that says something about the
   * form: the mnemonic that ACCEPTS this shape is the one that refuses the
   * shape one step away. Tried first because the axes below can answer with a
   * fact about arity instead.
   *
   * MEASURED on the revision that lacked it: 148 of 154 rows reported `mov`
   * refusing with 402 wrong operand count, which is true and useless -- mov is
   * a two-operand mnemonic, so every row of arity 1 or 3 is a count it rejects
   * before it ever looks at a width. */
  if (f->representative)
    for (unsigned pos = 0; pos < f->arity && !f->refused_mnemonic; pos++)
      for (unsigned wi = 0; wi < NWIDTH && !f->refused_mnemonic; wi++) {
        if (WIDTHS[wi] == f->width[pos]) continue;
        unsigned saved = f->width[pos];
        f->width[pos] = WIDTHS[wi];
        NtX64Error e = ask_one(f->representative, f->kind, f->width, f->arity,
                               f->reg, &probe);
        f->width[pos] = saved;
        if (e == NT_X64_OK || e == NT_X64_UNKNOWN) continue;
        f->refused_mnemonic = f->representative;
        f->refused_code = e;
        shape_name(f, nm, sizeof nm);
        snprintf(f->refused_why, sizeof f->refused_why,
                 "axis=representative position %u width %u->%u: the row's own %s "
                 "refuses %s with %u %s", pos, saved, WIDTHS[wi],
                 f->refused_mnemonic, nm, (unsigned)e, nt_x64_error_string(e));
      }

  /* axis 1: width of one position */
  for (unsigned pos = 0; pos < f->arity && !f->refused_mnemonic; pos++)
    for (unsigned wi = 0; wi < NWIDTH && !f->refused_mnemonic; wi++) {
      if (WIDTHS[wi] == f->width[pos]) continue;
      unsigned saved = f->width[pos];
      f->width[pos] = WIDTHS[wi];
      NtX64Error e = ask(f->kind, f->width, f->arity, f->reg, &probe, &which);
      f->width[pos] = saved;
      if (e == NT_X64_OK || e == NT_X64_UNKNOWN) continue;
      f->refused_mnemonic = which;
      f->refused_code = e;
      shape_name(f, nm, sizeof nm);
      snprintf(f->refused_why, sizeof f->refused_why,
               "axis=width position %u width %u->%u: %s refuses %s with %u %s",
               pos, saved, WIDTHS[wi], f->refused_mnemonic, nm, (unsigned)e,
               nt_x64_error_string(e));
    }

  /* axis 2: the ADDRESS of a memory position, tried BEFORE the kind axis for
   * rows that have one. Reordering is the whole point and it is measured: with
   * the kind axis first, a unary MEM row was refused by `mov` with 402 wrong
   * operand count -- a fact about mov's arity, true of every unary row in the
   * matrix, and therefore constraining nothing about this one. The address
   * axis asks operand_valid the question the form actually turns on
   * (x64.c:59-65) and gets 411 invalid address, which IS about this operand.
   * MEASURED: the 6 unary MEM rows went from 402-arbitrary to 411-substantive
   * on the same run, with no other row changed. */
  int has_mem = 0;
  for (unsigned pos = 0; pos < f->arity; pos++)
    if (f->kind[pos] == NT_X64_MEM) has_mem = 1;
  if (has_mem)
    for (unsigned pos = 0; pos < f->arity && !f->refused_mnemonic; pos++) {
      if (f->kind[pos] != NT_X64_MEM) continue;
      static const struct { const char *what; int field; int value; } BAD[] = {
          {"base 3->16, outside the 0..15 register file", 'b', 16},
          {"index -1->4, rsp cannot be an index", 'i', 4},
          {"scale 1->3, only 1/2/4/8 are encodable", 's', 3}};
      for (unsigned b = 0; b < sizeof BAD / sizeof *BAD && !f->refused_mnemonic; b++) {
        NtX64Operand ops[3];
        for (unsigned i = 0; i < f->arity; i++)
          ops[i] = operand_of(f->kind[i], f->width[i], f->reg);
        if (BAD[b].field == 'b') ops[pos].base = BAD[b].value;
        if (BAD[b].field == 'i') { ops[pos].index = BAD[b].value; ops[pos].scale = 1; }
        if (BAD[b].field == 's') ops[pos].scale = (unsigned)BAD[b].value;
        /* The row's OWN representative is asked FIRST here too, for the same
         * reason as axis 0. The sweep below takes the FIRST variable() entry
         * that refuses, and that is `mov` -- a two-operand mnemonic -- so a
         * unary row got 402 wrong operand count even on the address axis, which
         * is the same arity fact wearing a different label. The representative
         * is the mnemonic that accepted the row, so its refusal is the one that
         * is about the operand: 411 invalid address. */
        NtX64Error e = NT_X64_UNKNOWN;
        which = 0;
        if (f->representative) {
          NtX64Context rctx = {NT_X64_ALL_FEATURES, 0};
          memset(&probe, 0, sizeof probe);
          e = nt_x64_encode(f->representative, ops, f->arity, rctx, &probe);
          if (e != NT_X64_OK) which = f->representative;
        }
        if (e == NT_X64_OK || e == NT_X64_UNKNOWN) {
          NtX64Context ctx = {NT_X64_ALL_FEATURES, 0};
          e = NT_X64_UNKNOWN;
          which = 0;
          for (unsigned c = 0; c < NVARIABLE && e == NT_X64_UNKNOWN; c++) {
            memset(&probe, 0, sizeof probe);
            NtX64Error r = nt_x64_encode(VARIABLE_CATALOGUE[c], ops, f->arity, ctx, &probe);
            if (r != NT_X64_OK) { e = r; which = VARIABLE_CATALOGUE[c]; }
          }
        }
        if (e == NT_X64_OK || e == NT_X64_UNKNOWN) continue;
        f->refused_mnemonic = which;
        f->refused_code = e;
        shape_name(f, nm, sizeof nm);
        snprintf(f->refused_why, sizeof f->refused_why,
                 "axis=address position %u %s: %s refuses %s with %u %s", pos,
                 BAD[b].what, f->refused_mnemonic, nm, (unsigned)e,
                 nt_x64_error_string(e));
      }
    }

  /* axis 3: kind of one position. Reached when every width of every position
   * of this kind sequence is accepted, and no memory position had an address
   * the encoder refused. */
  for (unsigned pos = 0; pos < f->arity && !f->refused_mnemonic; pos++)
    for (int k = 1; k < NKIND && !f->refused_mnemonic; k++) {
      if (k == f->kind[pos]) continue;
      int saved = f->kind[pos];
      f->kind[pos] = k;
      NtX64Error e = ask(f->kind, f->width, f->arity, f->reg, &probe, &which);
      f->kind[pos] = saved;
      if (e == NT_X64_OK || e == NT_X64_UNKNOWN) continue;
      f->refused_mnemonic = which;
      f->refused_code = e;
      shape_name(f, nm, sizeof nm);
      snprintf(f->refused_why, sizeof f->refused_why,
               "axis=kind position %u kind %s->%s: %s refuses %s with %u %s",
               pos, KIND_NAME[saved], KIND_NAME[k], f->refused_mnemonic, nm,
               (unsigned)e, nt_x64_error_string(e));
    }

  if (!f->refused_mnemonic) {
    f->refused_mnemonic = "-";
    f->refused_code = NT_X64_OK;
    snprintf(f->refused_why, sizeof f->refused_why,
             "UNFILLED: no width, kind or address perturbation of this shape is "
             "refused under this instantiation, so the row declares its forbidden "
             "half empty rather than borrowing one from another form");
  }
}

/* Walk the whole (arity, kinds, per-position widths) space and collect the
 * forms the oracle accepts, under the given instantiation set. */
static unsigned collect(Form *out, unsigned cap, const unsigned *regs,
                        unsigned nregs) {
  unsigned found = 0;
  for (unsigned arity = 1; arity <= 3; arity++) {
    unsigned combos = 1;
    for (unsigned i = 0; i < arity; i++) combos *= (NWIDTH * NKIND);
    for (unsigned idx = 0; idx < combos; idx++) {
      unsigned t = idx;
      int kind[3];
      unsigned width[3];
      for (unsigned i = 0; i < arity; i++) {
        unsigned slot = t % (NWIDTH * NKIND);
        t /= (NWIDTH * NKIND);
        kind[i] = (int)(slot / NWIDTH) + 1;   /* kind 0 is NONE, never accepted */
        width[i] = WIDTHS[slot % NWIDTH];
      }
      NtX64Instruction bytes;
      const char *which = 0;
      NtX64Error e = NT_X64_UNKNOWN;
      for (unsigned r = 0; r < nregs && e != NT_X64_OK; r++)
        e = ask(kind, width, arity, regs[r], &bytes, &which);
      if (e != NT_X64_OK) continue;
      if (found >= cap) break;
      Form *f = &out[found];
      memset(f, 0, sizeof *f);
      f->arity = arity;
      for (unsigned i = 0; i < arity; i++) { f->kind[i] = kind[i]; f->width[i] = width[i]; }
      /* Re-run under the instantiation that produced it, so the row names the
       * register its bytes are for. */
      for (unsigned r = 0; r < nregs; r++) {
        NtX64Instruction b2;
        const char *w2 = 0;
        if (ask(kind, width, arity, regs[r], &b2, &w2) == NT_X64_OK) {
          f->representative = w2;
          f->reg = regs[r];
          f->length = (unsigned)b2.length;
          memcpy(f->bytes, b2.bytes, b2.length);
          break;
        }
      }
      find_refusal(f);
      found++;
    }
  }
  return found;
}

/* Count the distinct KIND SEQUENCES among a form set: the width-free axis. */
static unsigned structural_axis(const Form *forms, unsigned n) {
  static struct { int k[3]; unsigned arity; } seen[4096];
  unsigned nseen = 0;
  for (unsigned i = 0; i < n; i++) {
    unsigned s;
    for (s = 0; s < nseen; s++) {
      if (seen[s].arity != forms[i].arity) continue;
      int same = 1;
      for (unsigned j = 0; j < forms[i].arity; j++)
        if (seen[s].k[j] != forms[i].kind[j]) same = 0;
      if (same) break;
    }
    if (s == nseen) {
      for (unsigned j = 0; j < forms[i].arity; j++) seen[s].k[j] = forms[i].kind[j];
      seen[s].arity = forms[i].arity;
      nseen++;
    }
  }
  return nseen;
}

static unsigned hetero_count(const Form *forms, unsigned n) {
  unsigned h = 0;
  for (unsigned i = 0; i < n; i++) {
    for (unsigned a = 0; a < forms[i].arity; a++)
      for (unsigned b = a + 1; b < forms[i].arity; b++)
        if (forms[i].width[a] != forms[i].width[b]) { h++; a = forms[i].arity; break; }
  }
  return h;
}

/* The width multiplicity of each structural form: how many accepted
 * (kind,width) rows sit under one kind sequence. A2 asserted this number is 4
 * for every form. It is DERIVED here, and the distribution is what makes the
 * assertion checkable rather than merely doubted. */
static void width_variants(const Form *forms, unsigned n, unsigned *vmin,
                           unsigned *vmax, unsigned *exactly_four) {
  static struct { int kind[3]; unsigned arity, count; } groups[4096];
  unsigned nc = 0;
  *vmin = 0;
  *vmax = 0;
  *exactly_four = 0;
  for (unsigned i = 0; i < n; i++) {
    unsigned slot = nc;
    int seen = 0;
    for (unsigned s = 0; s < nc; s++) {
      if (groups[s].arity != forms[i].arity) continue;
      int same = 1;
      for (unsigned j = 0; j < forms[i].arity; j++)
        if (groups[s].kind[j] != forms[i].kind[j]) same = 0;
      if (same) { slot = s; seen = 1; break; }
    }
    if (!seen) {
      for (unsigned j = 0; j < forms[i].arity; j++) groups[nc].kind[j] = forms[i].kind[j];
      groups[nc].arity = forms[i].arity;
      groups[nc].count = 0;
      nc++;
    }
    groups[slot].count++;
  }
  for (unsigned s = 0; s < nc; s++) {
    unsigned v = groups[s].count;
    if (!*vmin || v < *vmin) *vmin = v;
    if (v > *vmax) *vmax = v;
    if (v == 4) (*exactly_four)++;
  }
}

/* One row of the matrix, as it is rendered. The stored file and the freshly
 * derived rows are compared as these strings, keyed by the shape, so a
 * difference is attributable to a NAMED ROW and not to a line number that
 * moves. */
typedef struct { char shape[96]; char line[512]; } Row;

/* VERIFY MODE. The matrix on disk is confronted, cell by cell, with what the
 * oracle says on this run. This is what makes the file evidence rather than
 * output: without it the check only ever writes, so nothing in the tree could
 * contradict the file, and a hand-edited byte would be indistinguishable from
 * a generated one until the next run silently overwrote it.
 *
 * A row missing from the file, a row in the file the oracle does not produce,
 * and a row whose text differs are THREE DIFFERENT FAILURES and are reported
 * as three, because a check that collapses them into one count cannot say
 * which of the three happened. */
static int verify(const char *path, const Form *forms, unsigned n) {
  FILE *f = fopen(path, "r");
  if (!f) { fprintf(stderr, "FAIL FORM_VERIFY cannot open %s\n", path); return 1; }
  static Row stored[4096];
  unsigned ns = 0;
  char buf[600];
  while (ns < 4096 && fgets(buf, sizeof buf, f)) {
    if (buf[0] == '#' || buf[0] == '\n') continue;
    char *tab = strchr(buf, '\t');
    if (!tab) continue;
    *tab = 0;
    size_t len = strlen(buf);
    while (len && (buf[len - 1] == '\r' || buf[len - 1] == '\n')) buf[--len] = 0;
    snprintf(stored[ns].shape, sizeof stored[ns].shape, "%.*s",
             (int)(len < sizeof stored[ns].shape - 1 ? len
                                                    : sizeof stored[ns].shape - 1),
             buf);
    char *rest = tab + 1;
    size_t rl = strlen(rest);
    while (rl && (rest[rl - 1] == '\r' || rest[rl - 1] == '\n')) rest[--rl] = 0;
    snprintf(stored[ns].line, sizeof stored[ns].line, "%.*s",
             (int)(rl < sizeof stored[ns].line - 1 ? rl
                                                  : sizeof stored[ns].line - 1),
             rest);
    ns++;
  }
  fclose(f);

  char hex[64], shape[96], derived[512];
  unsigned matched = 0, missing = 0, extra = 0, mismatched = 0;
  for (unsigned i = 0; i < n; i++) {
    const Form *fm = &forms[i];
    print_bytes(fm->bytes, fm->length, hex, sizeof hex);
    shape_name(fm, shape, sizeof shape);
    /* The shape is the KEY and is compared separately, so it must not also be
     * inside the value: the first version of this comparison built `derived`
     * WITH the shape and compared it against a stored line that had the shape
     * already split off, so all 154 rows reported mismatched on a matrix the
     * oracle had just written. The instrument disagreed with itself. */
    snprintf(derived, sizeof derived, "%s\tr%u\t%s\t%u\t%s\t%u\t%s",
             fm->representative, fm->reg, hex, fm->length,
             fm->refused_mnemonic, (unsigned)fm->refused_code, fm->refused_why);
    int found = 0;
    for (unsigned s = 0; s < ns; s++)
      if (strcmp(stored[s].shape, shape) == 0) {
        found = 1;
        checks++;
        cases++;
        if (strcmp(stored[s].line, derived) != 0) {
          mismatched++;
          failures++;
          fprintf(stderr, "FAIL FORM_ROW_MISMATCH row=%s\n  stored   %s\n"
                          "  derived  %s\n", shape, stored[s].line, derived);
        } else matched++;
        break;
      }
    if (!found) {
      missing++;
      failures++;
      checks++;
      cases++;
      fprintf(stderr, "FAIL FORM_ROW_MISSING row=%s derived=%s\n", shape, derived);
    }
  }
  for (unsigned s = 0; s < ns; s++) {
    int seen = 0;
    for (unsigned i = 0; i < n; i++) {
      shape_name(&forms[i], shape, sizeof shape);
      if (strcmp(shape, stored[s].shape) == 0) { seen = 1; break; }
    }
    if (!seen) {
      extra++;
      failures++;
      checks++;
      cases++;
      fprintf(stderr, "FAIL FORM_ROW_EXTRA row=%s stored=%s\n", stored[s].shape,
              stored[s].line);
    }
  }
  printf("FORM_VERIFY file=%s rows_stored=%u rows_derived=%u matched=%u "
         "mismatched=%u missing=%u extra=%u\n",
         path, ns, n, matched, mismatched, missing, extra);
  return failures ? 1 : 0;
}

int main(int argc, char **argv) {
  int do_verify = (argc > 2 && strcmp(argv[1], "--verify") == 0);
  const char *path = do_verify ? argv[2]
                               : (argc > 1 ? argv[1]
                                           : "out/c-bootstrap/nova/form-matrix.tsv");
  char hex[64], shape[96];
  unsigned unfilled = 0;
  static Form forms[4096];
  unsigned n = collect(forms, 4096, INSTANTIATION, NINST);
  static Form single[4096];
  unsigned nsingle = collect(single, 4096, SINGLE_REG, NSINGLE);

  unsigned structural = structural_axis(forms, n);
  unsigned heterogeneous = hetero_count(forms, n);

  /* The banner. Every number here is counted in this process, on this run, by
   * calling the oracle. None is transcribed. */
  printf("FORM_MATRIX file=%s\n", path);
  printf("FORM_MATRIX catalogue_variable=%u catalogue_fixed_arity0=%u catalogue_total=%u\n",
         (unsigned)NVARIABLE, (unsigned)NFIXED, (unsigned)NCATALOGUE);
  printf("FORM_MATRIX instantiation_registers=%u\n", (unsigned)NINST);
  printf("FORM_MATRIX forms_accepted=%u structural_kind_sequences=%u heterogeneous=%u\n",
         n, structural, heterogeneous);
  printf("FORM_MATRIX forms_single_register=%u instantiation_registers_single=1\n",
         nsingle);
  printf("FORM_MATRIX delta_from_instantiation=%u\n", n - nsingle);

  /* In verify mode nothing is written: the file already on disk is the
   * subject, and a gate that rewrites its subject cannot be contradicted by
   * it. This is the mode the red proof uses, and the mode a reader uses to
   * ask « is the matrix still true ». */
  if (do_verify) {
    int rc = verify(path, forms, n);
    printf("FORM_MATRIX checks=%u failures=%u cases=%u\n", checks, failures, cases);
    return rc;
  }
  /* The matrix. */
  FILE *f = fopen(path, "w");
  if (!f) { fprintf(stderr, "FAIL cannot write %s\n", path); return 1; }
  fprintf(f, "# x86-64 form coverage matrix -- generated by tests_ntasm_form_matrix.c\n");
  fprintf(f, "# every expected byte below is nt_x64_encode's own answer on this run\n");
  fprintf(f, "# kind,width\tmnemonic\treg\tbytes\tlen\trefused_by\trefused_code\trefusal\n");
  for (unsigned i = 0; i < n; i++) {
    Form *fm = &forms[i];
    print_bytes(fm->bytes, fm->length, hex, sizeof hex);
    shape_name(fm, shape, sizeof shape);
    fprintf(f, "%s\t%s\tr%u\t%s\t%u\t%s\t%u\t%s\n", shape, fm->representative,
            fm->reg, hex, fm->length, fm->refused_mnemonic,
            (unsigned)fm->refused_code, fm->refused_why);
    checks++;
    cases++;
    /* The row is only a row if it has BOTH halves. */
    if (!fm->representative || !fm->length) {
      failures++;
      fprintf(stderr, "FAIL row %s has no expected bytes\n", shape);
    }
    if (fm->refused_mnemonic[0] == '-') {
      /* Not a failure -- an unfilled cell, DECLARED as one. Counted, printed,
       * and never silently passed: a matrix that hides an empty cell is the
       * defect this whole file exists to remove. */
      unfilled++;
      printf("FORM_UNFILLED %s %s\n", shape, fm->refused_why);
    }
  }
  fclose(f);
  printf("FORM_MATRIX rows_written=%u rows_unfilled_refusal=%u\n", n, unfilled);

  /* The claim under examination, as a check rather than a sentence.
   *
   * A2 of docs/status/ntasm-completion.md said « les 10 formes structurelles x 4
   * largeurs sont couvertes ». Both halves are compared against the
   * measurement, and BOTH NUMBERS BELOW ARE COUNTED IN THIS PROCESS. The first
   * revision of this block printed measured_width_variants_min=4 and max=30 as
   * literals -- the very defect this lot exists to remove, reintroduced by the
   * instrument built to remove it. They are derived now.
   *
   * The document is OWNED BY W53OneVerdict, so this gate states the number and
   * does not edit the document. The correction is a handoff. */
  unsigned vmin = 0, vmax = 0, at_four = 0;
  width_variants(forms, n, &vmin, &vmax, &at_four);
  printf("FORM_CLAIM a2_asserted_structural_forms=10 measured_structural=%u verdict=%s\n",
         structural, structural == 10 ? "HOLDS" : "REFUTED");
  printf("FORM_CLAIM a2_asserted_widths_per_form=4 measured_min=%u measured_max=%u "
         "structural_forms_with_exactly_4=%u verdict=%s\n",
         vmin, vmax, at_four, (vmin == 4 && vmax == 4) ? "HOLDS" : "REFUTED");
  printf("FORM_CLAIM a2_phrase_refuted=%d\n",
         (structural == 10 && vmin == 4 && vmax == 4) ? 0 : 1);

  printf("FORM_MATRIX checks=%u failures=%u cases=%u\n", checks, failures, cases);
  return failures ? 1 : 0;
}
