/* NTASM gate for the memory destination of the shift/rotate family and of
 * call/jmp: catalogue row I12 forms M_1, M_CL and M_I8, and row I19 form M.
 * Neither x64_fixed.encode_shift_imm nor x64_fixed.encode_shift_cl accepts a
 * memory destination, and neither does x64_fixed.encode_control, so those three
 * spellings of the v0 catalogue had no encoder channel at all until this lot
 * added two exports:
 *   family 0 x64_fixed.encode_shift_memory   rol/ror/shl/shr/sar over memory
 *   family 1 x64_fixed.encode_control_memory call/jmp through memory
 *
 * Every case is encoded a second time by the native oracle nt_x64_encode and
 * compared byte for byte, and every refusal is compared against the oracle
 * diagnostic, so no expected byte and no expected code is written in this file:
 * the harness states the operand shape and the oracle decides length, bytes and
 * diagnostic. The gate therefore flips by itself if the oracle ever changes.
 *
 * kind1 is a register and kind3 is memory, the native enum numbering. The memory
 * descriptor is base 0..15 with 16 no base and 17 RIP, index 0..15 with 16 none,
 * scale, the displacement bits and segment 0/1/2. count_kind is the native kind
 * of the second operand, 1 for the cl count and 2 for the literal count, whose
 * amount word is the folded two's complement the native shift block tests
 * against 255. I21 form M is not under test here: it is already carried by
 * x64_fixed.encode_setcc_operand and pinned by the x64_high8 gate, which prints
 * sete [rbx+8] u8 as 0f944308 from the oracle.
 *
 * Families 2 to 6 are the five unchanged historical exports of the very
 * instructions these two families complete, re-driven through this same entry.
 * A literal byte table taken from the oracle pins them, so a change to any of
 * them fails here and not only in the gate that owns it. */
#include "../../../compiler/c/nova/frontend/nova.h"
#include "../../../compiler/c/nova/runtime/run_host.h"
#include "../../../compiler/c/nova/runtime/runtime_v2.h"
#include "../../../compiler/c/ntasm/backend/x64.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned checks, failures, cases;
#define CHECK(c, m) do { checks++; if (!(c)) { failures++; fprintf(stderr, "FAIL %s\n", m); } } while (0)
static const uint8_t guard = 0xcc;
static char *loadf(const char *p, size_t *n) {
    FILE *f = fopen(p, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long z = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *b = z >= 0 ? malloc((size_t)z + 1) : NULL;
    if (!b || fread(b, 1, (size_t)z, f) != (size_t)z) { free(b); fclose(f); return NULL; }
    fclose(f);
    b[z] = 0;
    *n = (size_t)z;
    return b;
}
#define FAMILIES 7
static unsigned family_cases[FAMILIES];
static void bump(uint64_t f) { if (f < FAMILIES) family_cases[f]++; }

/* One address descriptor in the native numbering, plus the words every family
 * reads out of the same entry frame. */
typedef struct { uint64_t base, index, scale, disp, segment; } Desc;
typedef struct {
    uint64_t family, count, kind, reg, high8, width, count_kind, count_register, amount, features,
        cpl, words;
    Desc d;
} Ask;
static Ask ask(uint64_t family) {
    Ask a;
    memset(&a, 0, sizeof a);
    a.family = family;
    a.count = 1;
    a.kind = 3;
    a.count_kind = 1;
    a.count_register = 1;
    a.width = 64;
    a.features = 1;
    a.cpl = 3;
    a.words = 16;
    a.d.base = 0;
    a.d.index = 16;
    a.d.scale = 1;
    return a;
}
static Ask at(Ask a, Desc d) { a.d = d; return a; }

typedef struct { uint64_t returned, runtime; uint8_t out[16]; } Run;
/* A buf parameter takes two words, its handle and its length, so the eighteen
 * parameters of the entry are twenty words in declaration order. */
static Run run(const NovaHostImage *i, const char *name, Ask a) {
    Run r;
    memset(&r, 0, sizeof r);
    memset(r.out, guard, sizeof r.out);
    NovaContextV2 c = {0};
    CHECK(nova_context_init_v2(&c), "context init");
    uint64_t nh = nova_borrow_v2(&c, (void *)name, strlen(name), 0);
    uint64_t oh = nova_borrow_v2(&c, r.out, a.words, 1);
    uint64_t w[] = {a.family,   nh,          strlen(name), a.count,  a.kind,   a.reg,
                    a.high8,    a.width,     a.count_kind, a.count_register, a.amount,
                    a.d.base,   a.d.index,   a.d.scale,    a.d.disp,  a.d.segment,
                    a.features, a.cpl,       oh,           a.words};
    r.returned = i->entry(&c, w, 20);
    r.runtime = c.error;
    CHECK(nova_context_destroy_v2(&c), "context cleanup");
    return r;
}
static NtX64Operand native(uint64_t kind, uint64_t reg, uint64_t high8, uint64_t width, uint64_t imm,
                           Desc d) {
    NtX64Operand o = {0};
    o.kind = (NtX64Kind)kind;
    o.reg = (unsigned)reg;
    o.high8 = (unsigned)high8;
    o.width = (unsigned)width;
    o.imm = imm;
    o.base = d.base == 16 ? -1 : d.base == 17 ? -2 : (int)d.base;
    o.index = d.index == 16 ? -1 : (int)d.index;
    o.scale = (unsigned)d.scale;
    memcpy(&o.disp, &d.disp, sizeof o.disp);
    o.segment = (NtX64Segment)d.segment;
    return o;
}
/* The second operand of the shift family, built from the same count_kind word
 * the entry receives, so a refused count kind is compared against the oracle
 * answer for that same kind rather than against a hard written code. */
static NtX64Operand count_native(uint64_t count_kind, uint64_t count_register, uint64_t amount) {
    NtX64Operand o = {0};
    (void)0;
    o.kind = (NtX64Kind)count_kind;
    switch (count_kind) {
    case 1: o.reg = (unsigned)count_register; o.width = 8; break;
    case 2: o.imm = amount; break;
    /* A well formed memory count, so the native encoder reaches the form answer
     * 409 instead of stopping on a scale of zero. */
    case 3: o.width = 64; o.base = 3; o.index = -1; o.scale = 1; o.disp = 8; break;
    case 4: o.imm = amount; o.is_signed = 1; break;
    case 5: o.reg = 0; o.width = 64; break;
    default: break;
    }
    return o;
}
static void show(const char *tag, const char *name, Ask a, Run r, unsigned e) {
    fprintf(stderr,
            "FAIL %s %s family=%llu count=%llu dst=(kind%llu,reg%llu,high8%llu,width%llu) "
            "cnt=(kind%llu,reg%llu,amount%llu) mem=(%llu,%llu,%llu,%lld,%llu) f=%llu p=%llu "
            "ret=%llu oracle=%u out=%u,%u,%u,%u,%u,%u\n",
            tag, name, (unsigned long long)a.family, (unsigned long long)a.count,
            (unsigned long long)a.kind, (unsigned long long)a.reg, (unsigned long long)a.high8,
            (unsigned long long)a.width, (unsigned long long)a.count_kind,
            (unsigned long long)a.count_register, (unsigned long long)a.amount,
            (unsigned long long)a.d.base, (unsigned long long)a.d.index, (unsigned long long)a.d.scale,
            (long long)(int64_t)a.d.disp, (unsigned long long)a.d.segment,
            (unsigned long long)a.features, (unsigned long long)a.cpl, (unsigned long long)r.returned,
            e, r.out[0], r.out[1], r.out[2], r.out[3], r.out[4], r.out[5]);
}
/* The two new exports own the whole sixteen byte frame and clear it, so a
 * success leaves a zero tail. The five historical exports each own a narrower
 * frame, so the tail rule is asked of families 0 and 1 only. */
static int owns_frame(uint64_t family) { return family < 2; }
/* Parity on the accepted stream and on the diagnostic alike. */
static void parity(const NovaHostImage *i, const char *name, Ask a) {
    NtX64Operand o[2] = {native(a.kind, a.reg, a.high8, a.width, 0, a.d),
                         count_native(a.count_kind, a.count_register, a.amount)};
    NtX64Instruction x = {0};
    NtX64Context ctx = {(uint32_t)a.features, (unsigned)a.cpl};
    NtX64Error e = nt_x64_encode(name, o, a.count, ctx, &x);
    Run r = run(i, name, a);
    cases++;
    checks++;
    bump(a.family);
    int bad = r.returned != (uint64_t)e || r.runtime;
    if (!e) {
        if (r.out[0] != x.length) bad = 1;
        for (unsigned k = 0; k < x.length; k++)
            if (r.out[1 + k] != x.bytes[k]) bad = 1;
        if (owns_frame(a.family))
            for (unsigned k = x.length; k < 15; k++)
                if (r.out[1 + k] != 0) bad = 1;
    } else {
        for (unsigned k = 0; k < sizeof r.out; k++)
            if (r.out[k] != guard) bad = 1;
    }
    if (bad) {
        failures++;
        show("parity", name, a, r, (unsigned)e);
    }
}
/* A short output frame is 800 whatever the operand is, and every byte stays
 * untouched: the exports answer the buffer before they read the mnemonic. */
static void short_frame(const NovaHostImage *i, const char *name, Ask a) {
    a.words = 15;
    Run r = run(i, name, a);
    cases++;
    checks++;
    bump(a.family);
    int bad = r.returned != 800 || r.runtime;
    for (unsigned k = 0; k < sizeof r.out; k++)
        if (r.out[k] != guard) bad = 1;
    if (bad) {
        failures++;
        show("short", name, a, r, 800);
    }
}
/* The two families under test own the memory direction only. A register
 * destination of the shift family and a high8 alias of any destination belong to
 * encode_shift_imm, encode_shift_cl and encode_setcc_operand, and the native
 * encoder answers both of them with real bytes, so these are 409 on purpose and
 * the native answer is printed next to the refusal instead of hidden behind an
 * expected byte. Same for a count register that is not cl, which the native
 * encoder also answers 406. */
static void boundary(const NovaHostImage *i, const char *name, Ask a, uint64_t want) {
    NtX64Operand o[2] = {native(a.kind, a.reg, a.high8, a.width, 0, a.d),
                         count_native(a.count_kind, a.count_register, a.amount)};
    NtX64Instruction x = {0};
    NtX64Context ctx = {(uint32_t)a.features, (unsigned)a.cpl};
    NtX64Error e = nt_x64_encode(name, o, a.count, ctx, &x);
    Run r = run(i, name, a);
    cases++;
    checks++;
    bump(a.family);
    int bad = r.returned != want || r.runtime;
    for (unsigned k = 0; k < sizeof r.out; k++)
        if (r.out[k] != guard) bad = 1;
    if (bad) {
        failures++;
        show("boundary", name, a, r, (unsigned)e);
    }
}
/* I19 in its relative and register directions, which family 6 drives through
 * encode_control: there the count_kind word is the control operand kind, the
 * amount word is the value and the width word the control width, so the oracle
 * operand is built from those three and not from the destination words. want is
 * -1 to demand the oracle answer, or the code this export is expected to answer
 * when it knowingly differs. */
static NtX64Operand control_native(Ask a) {
    NtX64Operand o;
    memset(&o, 0, sizeof o);
    if (a.count_kind == 1) {
        o.kind = NT_X64_REG;
        o.reg = (unsigned)a.amount;
        o.width = (unsigned)a.width;
    } else if (a.count_kind == 4) {
        o.kind = NT_X64_REL;
        o.width = (unsigned)a.width;
        o.imm = a.amount;
        o.is_signed = 1;
    } else if (a.count_kind == 2) {
        o.kind = NT_X64_IMM;
        o.imm = a.amount;
    } else {
        o.kind = NT_X64_MEM;
        o.width = 64;
        o.base = 0;
        o.index = -1;
        o.scale = 1;
    }
    return o;
}
static void control_case(const NovaHostImage *i, const char *name, Ask a, int64_t want) {
    NtX64Operand o[1] = {control_native(a)};
    NtX64Instruction x = {0};
    NtX64Context ctx = {(uint32_t)a.features, (unsigned)a.cpl};
    NtX64Error e = nt_x64_encode(name, o, a.count, ctx, &x);
    Run r = run(i, name, a);
    cases++;
    checks++;
    bump(a.family);
    int bad = r.returned != (want < 0 ? (uint64_t)e : (uint64_t)want) || r.runtime;
    if (want < 0 && !e) {
        if (r.out[0] != x.length) bad = 1;
        for (unsigned k = 0; k < x.length; k++)
            if (r.out[1 + k] != x.bytes[k]) bad = 1;
    } else {
        for (unsigned k = 0; k < sizeof r.out; k++)
            if (r.out[k] != guard) bad = 1;
    }
    if (bad) {
        failures++;
        show("parity", name, a, r, (unsigned)e);
    }
}
static void control_parity(const NovaHostImage *i, const char *name, Ask a) {
    control_case(i, name, a, -1);
}

/* --- the five unchanged historical exports, pinned to oracle bytes -------- */
/* Every length and every byte below was printed by nt_x64_encode before this lot
 * touched x64_fixed.nova; the table exists so the historical surface is pinned
 * here as well as in the gate that owns it. */
typedef struct {
    uint64_t family, count, kind, reg, high8, width, count_kind, count_register, amount;
    const char *name, *tag;
    uint8_t bytes[8];
    unsigned length;
} Frozen;
static const Frozen frozen[] = {
    {2, 2, 1, 0, 0, 64, 2, 0, 5, "shl", "I12 R_I8 shl rax,5", {0x48, 0xc1, 0xe0, 0x05}, 4},
    {2, 2, 1, 1, 0, 8, 2, 0, 1, "rol", "I12 R_1 rol cl,1", {0xd0, 0xc1}, 2},
    {2, 2, 1, 9, 0, 32, 2, 0, 31, "sar", "I12 R_I8 sar r9d,31", {0x41, 0xc1, 0xf9, 0x1f}, 4},
    {3, 2, 1, 0, 0, 64, 1, 1, 0, "sar", "I12 R_CL sar rax,cl", {0x48, 0xd3, 0xf8}, 3},
    {3, 2, 1, 7, 0, 8, 1, 1, 0, "shr", "I12 R_CL shr bl,cl", {0x40, 0xd2, 0xef}, 3},
    {4, 1, 1, 0, 0, 64, 0, 0, 0, "not", "unary not rax", {0x48, 0xf7, 0xd0}, 3},
    {4, 1, 1, 15, 0, 16, 0, 0, 0, "dec", "unary dec r15w", {0x66, 0x41, 0xff, 0xcf}, 4},
    {5, 1, 1, 0, 0, 8, 0, 0, 0, "seto", "I21 R seto al", {0x0f, 0x90, 0xc0}, 3},
    {5, 1, 1, 10, 0, 8, 0, 0, 0, "setl", "I21 R setl r10b", {0x41, 0x0f, 0x9c, 0xc2}, 4},
    {6, 1, 1, 0, 0, 64, 1, 0, 0, "call", "I19 R call rax", {0xff, 0xd0}, 2},
    {6, 1, 1, 0, 0, 0, 4, 0, 0, "jmp", "I19 LABEL jmp rel 0", {0xe9, 0, 0, 0, 0}, 5},
};
static void non_regression(const NovaHostImage *i) {
    for (unsigned k = 0; k < sizeof frozen / sizeof *frozen; k++) {
        const Frozen *f = &frozen[k];
        Ask a = ask(f->family);
        a.count = f->count;
        a.kind = f->kind;
        a.reg = f->reg;
        a.high8 = f->high8;
        a.width = f->width;
        a.count_kind = f->count_kind;
        a.count_register = f->count_register;
        a.amount = f->amount;
        Run r = run(i, f->name, a);
        cases++;
        checks++;
        bump(f->family);
        /* Length and bytes only. These five exports each own a narrower frame
         * than the two new ones and clear only that frame, so a zero tail is not
         * part of their contract; the two new exports are held to it above. */
        int bad = r.returned != 0 || r.runtime;
        if (r.out[0] != f->length) bad = 1;
        for (unsigned b = 0; b < f->length; b++)
            if (r.out[1 + b] != f->bytes[b]) bad = 1;
        if (bad) {
            failures++;
            show("frozen", f->name, a, r, 0);
            fprintf(stderr, "     expected %s len=%u\n", f->tag, f->length);
        }
    }
}
/* The same five exports against the oracle, so the frozen table and the oracle
 * cannot drift apart either. */
static void non_regression_parity(const NovaHostImage *i) {
    /* Seven, not four: encode_unary also answers mul, div and idiv, and a
     * negative control proved this array was not covering them. Perturbing the
     * div digit in encode_unary left THIS gate green while the lowering gate went
     * red -- a name an export answers and no check exercised, which is the silent
     * door, and it was opened by my own lot three edits earlier. */
    static const char *const unary[] = {"inc", "dec", "not", "neg", "mul", "div", "idiv"};
    static const char *const shifts[] = {"rol", "ror", "shl", "shr", "sar"};
    static const char *const setcc[] = {"sete", "setne", "setb",  "setae", "setbe", "seta", "sets",
                                        "setns", "setp", "setnp", "setl",  "setge", "setle", "setg",
                                        "seto", "setno"};
    static const uint64_t widths[] = {8, 16, 32, 64};
    static const uint64_t regs[] = {0, 4, 7, 8, 15};
    const Desc unused = {0, 16, 1, 0, 0};
    /* Families 2 to 5 are register families, so the native first operand of
     * every case below is kind1 and the memory descriptor stays unread. */
    for (unsigned n = 0; n < 7; n++)
        for (unsigned w = 0; w < 4; w++)
            for (unsigned r = 0; r < 5; r++) {
                Ask a = ask(4);
                a.kind = 1;
                a.reg = regs[r];
                a.width = widths[w];
                a.d = unused;
                parity(i, unary[n], a);
            }
    for (unsigned n = 0; n < 5; n++)
        for (unsigned w = 0; w < 4; w++)
            for (unsigned r = 0; r < 5; r++)
                for (unsigned m = 0; m < 5; m++) {
                    static const uint64_t amounts[] = {0, 1, 2, 255, 256};
                    Ask a = ask(2);
                    a.kind = 1;
                    a.count = 2;
                    a.reg = regs[r];
                    a.width = widths[w];
                    a.count_kind = 2;
                    a.amount = amounts[m];
                    a.d = unused;
                    parity(i, shifts[n], a);
                }
    for (unsigned n = 0; n < 5; n++)
        for (unsigned w = 0; w < 4; w++)
            for (unsigned r = 0; r < 5; r++) {
                Ask a = ask(3);
                a.kind = 1;
                a.count = 2;
                a.reg = regs[r];
                a.high8 = 0;
                a.width = widths[w];
                a.count_kind = 1;
                a.count_register = 1;
                a.d = unused;
                parity(i, shifts[n], a);
            }
    /* The four high8 aliases of the shift family, and the refusals around them. */
    for (unsigned n = 0; n < 5; n++)
        for (unsigned h = 0; h < 4; h++) {
            Ask a = ask(3);
            a.kind = 1;
            a.count = 2;
            a.reg = h;
            a.high8 = 1;
            a.width = 8;
            a.count_kind = 1;
            a.count_register = 1;
            a.d = unused;
            parity(i, shifts[n], a);
        }
    for (unsigned n = 0; n < 16; n++)
        for (unsigned r = 0; r < 5; r++) {
            Ask a = ask(5);
            a.kind = 1;
            a.reg = regs[r];
            a.width = 8;
            a.d = unused;
            parity(i, setcc[n], a);
        }
    for (unsigned n = 0; n < 5; n++) {
        Ask a = ask(6);
        a.count_kind = 1;
        a.width = 64;
        a.amount = regs[n];
        a.d = unused;
        control_parity(i, n & 1 ? "jmp" : "call", a);
    }
    /* Every GPR, at the only width the native encoder accepts, plus the
     * register and width answers around it. */
    for (unsigned n = 0; n < 16; n++) {
        Ask a = ask(6);
        a.count_kind = 1;
        a.width = 64;
        a.amount = n;
        a.d = unused;
        control_parity(i, n & 1 ? "jmp" : "call", a);
    }
    {
        static const uint64_t narrow[] = {0, 8, 16, 32};
        for (unsigned n = 0; n < 4; n++) {
            Ask a = ask(6);
            a.count_kind = 1;
            a.width = narrow[n];
            a.amount = 3;
            a.d = unused;
            control_parity(i, n & 1 ? "jmp" : "call", a);
        }
    }
    {
        Ask a = ask(6);
        a.count_kind = 1;
        a.width = 64;
        a.amount = 16;
        a.d = unused;
        control_parity(i, "call", a);
    }
    /* The immediate operand is 409 on both sides. The memory operand is the gap
     * row I19 form M: the oracle encodes it through modrm and encode_control
     * answers 409, which is exactly what encode_control_memory now states, so
     * the refusal is asserted here and the oracle answer is printed with it. */
    for (unsigned n = 0; n < 2; n++) {
        const char *control[2] = {"call", "jmp"};
        for (unsigned c = 0; c < 2; c++) {
            Ask a = ask(6);
            a.count_kind = c ? 2 : 3;
            a.width = 64;
            a.amount = 4;
            a.d = unused;
            control_case(i, control[n], a, c ? -1 : 409);
        }
        for (unsigned c = 0; c < 6; c++) {
            static const int64_t disps[] = {-1000, -1, 0, 1, 2147483647, -2147483648};
            Ask a = ask(6);
            a.count_kind = 4;
            a.width = 0;
            memcpy(&a.amount, &disps[c], sizeof a.amount);
            a.d = unused;
            control_parity(i, control[n], a);
        }
        Ask a = ask(6);
        a.count_kind = 4;
        a.width = 0;
        a.amount = 0xFFFFFFFF80000000ULL;
        a.d = unused;
        control_parity(i, control[n], a);
        a.width = 8;
        a.amount = 0x100;
        control_parity(i, control[n], a);
    }
}

int main(void) {
    const char *paths[] = {"tests/nova/tests/x64-shift-mem-entry.nova",
                           "compiler/nova/backend/x64/x64_fixed.nova"};
    char *sources[2] = {0};
    NtFInput inputs[2];
    for (unsigned k = 0; k < 2; k++) {
        size_t n = 0;
        sources[k] = loadf(paths[k], &n);
        inputs[k] = (NtFInput){paths[k], sources[k], n};
    }
    int all = sources[0] && sources[1];
    CHECK(all, "sources load");
    NtArtifact a = {0};
    int compiled = all && nova_compile_many_v2(inputs, 2, &a);
    CHECK(compiled, "modules compile");
    if (!compiled)
        fprintf(stderr, "E%u %zu:%zu %s\n", a.error.code, a.error.line, a.error.column, a.error.message);
    NovaHostImage image = {0};
    CHECK(compiled && nova_host_map(&a, &image), "image maps");
    if (image.memory) {
        const char *const shifts[] = {"rol", "ror", "shl", "shr", "sar"};
        /* Fourteen accepted address shapes: both displacement classes, the SIB
         * only bases, rbp and rsp, a high base and a high index, RIP, a no-base
         * index-only form and both segments. */
        const Desc descs[] = {{3, 16, 1, 0, 0},        {3, 16, 1, 8, 0},        {3, 16, 1, 127, 0},
                              {3, 16, 1, 128, 0},      {3, 16, 1, UINT64_MAX - 7, 0},
                              {3, 1, 4, 64, 0},        {4, 16, 1, 8, 0},        {5, 16, 1, 0, 0},
                              {12, 13, 8, UINT64_MAX - 127, 0}, {13, 15, 4, UINT64_MAX - 1, 0},
                              {17, 16, 1, 16, 0},      {16, 3, 2, 8, 0},        {0, 16, 1, 1, 1},
                              {0, 16, 1, 1, 2}};
        const unsigned desc_count = sizeof descs / sizeof *descs;
        /* Nine refused address shapes: base above 15, an index above 15, rsp as
         * an index, a scale that is not 1/2/4/8, a scale with no index, RIP with
         * an index, a displacement past int32 on both sides, and a segment 3. */
        const Desc bad[] = {{18, 16, 1, 0, 0},           {0, 17, 1, 0, 0},
                            {0, 4, 1, 0, 0},             {0, 16, 3, 0, 0},
                            {0, 16, 2, 0, 0},            {17, 1, 1, 0, 0},
                            {0, 16, 1, 2147483648ULL, 0}, {0, 16, 1, 0xFFFFFFFF80000000ULL, 0},
                            {0, 16, 1, 0, 3}};
        const unsigned bad_count = sizeof bad / sizeof *bad;
        /* The three count forms of I12 over a memory destination, at every width
         * the catalogue lists and at both descriptor widths a shift never
         * spells but the oracle accepts. */
        const uint64_t widths[] = {8, 16, 32, 64};
        const uint64_t odd_widths[] = {0, 80};

        /* --- family 0: the five shift mnemonics over memory ---------------- */
        for (unsigned n = 0; n < 5; n++)
            for (unsigned c = 0; c < 3; c++)
                for (unsigned w = 0; w < 4; w++)
                    for (unsigned m = 0; m < desc_count; m++) {
                        /* c 0 is M_1, c 1 is M_CL and c 2 is M_I8. */
                        Ask a = ask(0);
                        a.count = 2;
                        a.width = widths[w];
                        a.count_kind = c == 2 ? 2 : 1;
                        a.count_register = 1;
                        a.amount = c == 0 ? 1 : (c == 2 ? 5 : 0);
                        parity(&image, shifts[n], at(a, descs[m]));
                    }
        /* amount 1 selects the M_1 opcode, everything else the M_I8 one. */
        for (unsigned n = 0; n < 5; n++)
            for (unsigned m = 0; m < 5; m++) {
                static const uint64_t amounts[] = {0, 1, 2, 255, 256};
                for (unsigned w = 0; w < 4; w++)
                    for (unsigned s = 0; s < 2; s++) {
                        Ask a = ask(0);
                        a.count = 2;
                        a.width = widths[w];
                        a.count_kind = 2;
                        a.amount = amounts[m];
                        parity(&image, shifts[n], a);
                    }
            }
        /* The two descriptor widths a shift never spells: 0 and 80 both reach
         * the memory frame and both must come out without a 0x66. */
        for (unsigned n = 0; n < 5; n++)
            for (unsigned c = 0; c < 3; c++)
                for (unsigned w = 0; w < 2; w++)
                    for (unsigned m = 0; m < 3; m++) {
                        Ask a = ask(0);
                        a.count = 2;
                        a.width = odd_widths[w];
                        a.count_kind = c == 2 ? 2 : 1;
                        a.amount = c == 2 ? 5 : (c == 0 ? 1 : 0);
                        parity(&image, shifts[n], at(a, descs[m]));
                    }
        /* Every refused address, at every count form. */
        for (unsigned n = 0; n < 5; n++)
            for (unsigned c = 0; c < 2; c++)
                for (unsigned m = 0; m < bad_count; m++) {
                    Ask a = ask(0);
                    a.count = 2;
                    a.count_kind = c + 1;
                    a.amount = c ? 5 : 0;
                    parity(&image, shifts[n], at(a, bad[m]));
                }
        /* A count register that is not cl is 406, whatever it is. */
        for (unsigned n = 0; n < 5; n++)
            for (unsigned c = 0; c < 4; c++) {
                static const uint64_t others[] = {0, 2, 10, 16};
                Ask a = ask(0);
                a.count = 2;
                a.count_kind = 1;
                a.count_register = others[c];
                parity(&image, shifts[n], a);
            }
        /* A count that is neither a register nor a literal is 409. */
        for (unsigned n = 0; n < 5; n++)
            for (unsigned c = 0; c < 5; c++) {
                static const uint64_t kinds[] = {0, 3, 4, 5, 6};
                Ask a = ask(0);
                a.count = 2;
                a.count_kind = kinds[c];
                parity(&image, shifts[n], a);
            }
        /* Diagnostics the oracle states before it ever looks at an operand. */
        for (unsigned n = 0; n < 5; n++) {
            Ask a = ask(0);
            a.count = 2;
            parity(&image, "telepathy", a);
            a.count = 0;
            parity(&image, shifts[n], a);
            a.count = 1;
            parity(&image, shifts[n], a);
            a.count = 3;
            parity(&image, shifts[n], a);
            a.count = 2;
            a.features = 0;
            parity(&image, shifts[n], a);
            a.features = 1;
            a.cpl = 4;
            parity(&image, shifts[n], a);
        }
        /* A width the memory descriptor cannot carry, and a segment word 3. */
        for (unsigned n = 0; n < 5; n++) {
            Ask a = ask(0);
            a.count = 2;
            a.width = 24;
            parity(&image, shifts[n], a);
            a.width = 64;
            a.d.segment = 3;
            parity(&image, shifts[n], a);
        }
        /* Register and high8 forms share the complete ModRM.rm channel now.
         * Preserve the former boundary rows, comparing their real bytes to C. */
        for (unsigned n = 0; n < 5; n++) {
            Ask a = ask(0);
            a.count = 2;
            a.kind = 1;
            a.reg = 0;
            a.high8 = 0;
            parity(&image, shifts[n], a);
            a.kind = 1;
            a.reg = 0;
            a.high8 = 1;
            a.width = 8;
            parity(&image, shifts[n], a);
            a.kind = 1;
            a.reg = 3;
            a.high8 = 1;
            a.width = 8;
            parity(&image, shifts[n], a);
            /* The native memory branch ignores the unused high8 word. */
            a.kind = 3;
            a.high8 = 1;
            a.width = 8;
            parity(&image, shifts[n], a);
            a.high8 = 1;
            a.d.scale = 3;
            boundary(&image, shifts[n], a, 411);
        }
        /* A short output frame, once per count form, and once for a mnemonic the
         * entry does not know: the buffer answer precedes the name. */
        for (unsigned c = 0; c < 3; c++) {
            Ask a = ask(0);
            a.count = 2;
            a.count_kind = c == 2 ? 2 : 1;
            a.amount = c == 2 ? 5 : (c == 0 ? 1 : 0);
            short_frame(&image, "shl", a);
        }
        {
            Ask a = ask(0);
            a.count = 2;
            short_frame(&image, "telepathy", a);
        }

        /* --- family 1: call and jmp through memory, I19 form M -------------- */
        for (unsigned n = 0; n < 2; n++) {
            const char *control[2] = {"call", "jmp"};
            for (unsigned m = 0; m < desc_count; m++) {
                Ask a = ask(1);
                parity(&image, control[n], at(a, descs[m]));
            }
            for (unsigned m = 0; m < bad_count; m++) {
                Ask a = ask(1);
                parity(&image, control[n], at(a, bad[m]));
            }
            /* A native memory width other than 64 is 403, and the address is
             * checked first, so a bad address of a narrow memory is 411. */
            for (unsigned w = 0; w < 5; w++) {
                static const uint64_t narrow[] = {0, 8, 16, 32, 80};
                Ask a = ask(1);
                a.width = narrow[w];
                parity(&image, control[n], a);
                a.d.base = 0;
                a.d.index = 4;
                parity(&image, control[n], a);
            }
            Ask a = ask(1);
            parity(&image, "telepathy", a);
            a.count = 0;
            parity(&image, control[n], a);
            a.count = 2;
            parity(&image, control[n], a);
            a.count = 1;
            a.features = 0;
            parity(&image, control[n], a);
            a.features = 1;
            a.cpl = 4;
            parity(&image, control[n], a);
            short_frame(&image, control[n], a);
        }

        /* --- families 2 to 6: the five unchanged historical exports -------- */
        non_regression(&image);
        non_regression_parity(&image);
    }
    if (image.memory) nova_host_unmap(&image);
    if (compiled) nt_artifact_free(&a);
    for (unsigned k = 0; k < 2; k++) free(sources[k]);
    /* The case floor this gate exists to hold, asserted by the gate itself. */
    for (unsigned f = 0; f < FAMILIES; f++) {
        char label[64];
        snprintf(label, sizeof label, "family %u carries cases", f);
        CHECK(family_cases[f] >= 24, label);
    }
    printf("HIGH8-COUNT");
    for (unsigned f = 0; f < FAMILIES; f++) printf(" family=%u cases=%u", f, family_cases[f]);
    printf("\n");
    printf("NTASM_NOVA_X64_SHIFT_MEM checks=%u failures=%u cases=%u\n", checks, failures, cases);
    return failures ? 1 : 0;
}
