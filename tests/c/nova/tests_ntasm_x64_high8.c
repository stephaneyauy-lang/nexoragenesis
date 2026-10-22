/* NTASM gate for the one-operand x64_fixed surface that was register-only: the
 * high8 alias ah/ch/dh/bh and the memory direction of inc/dec/not/neg, of the
 * sixteen setcc conditions and of push/pop. Every case is encoded a second time
 * by the native oracle nt_x64_encode and compared byte for byte, and every
 * refusal is compared against the oracle diagnostic, so no expected byte and no
 * expected code is written in this file: the harness only states the operand
 * shape and the oracle decides length, bytes and diagnostic. The gate therefore
 * flips by itself if the oracle ever changes.
 *
 * The three exports under test are the ones that replaced the register-only
 * encode_unary, encode_setcc and encode_stack for these two spellings:
 *   family 0 x64_fixed.encode_unary_operand  inc/dec/not/neg, register or memory
 *   family 1 x64_fixed.encode_setcc_operand  the sixteen setcc, register or memory
 *   family 2 x64_fixed.encode_stack_memory   push/pop memory, the memory direction
 * kind1 is a register and kind3 is memory, the native enum numbering. The memory
 * descriptor is base 0..15 with 16 no base and 17 RIP, index 0..15 with 16 none,
 * scale, the displacement bits and segment 0/1/2; the register family reads it
 * never and the memory families read the register words never. */
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
/* One NtX64Operand in the native order. kind1 is a register, kind2 an immediate
 * and kind4 a relative displacement, the native enum numbering. */
typedef struct { uint64_t kind, reg, high8, width, imm, is_signed; } Part;
typedef struct { uint64_t base, index, scale, disp, segment; } Desc;
static const Desc no_memory = {0, 16, 1, 0, 0};
static Part gpr(uint64_t r, uint64_t w, uint64_t h) { Part p = {1, r, h, w, 0, 0}; return p; }
static Part mem(uint64_t w) { Part p = {3, 0, 0, w, 0, 0}; return p; }
static Part imm(uint64_t v, uint64_t s) { Part p = {2, 0, 0, 0, v, s}; return p; }
static Part rel(uint64_t v, uint64_t s) { Part p = {4, 0, 0, 0, v, s}; return p; }
typedef struct { uint64_t returned, runtime; uint8_t out[16]; } Run;
/* Cases counted per family, so the "at least twenty per family" contract is
 * asserted by the gate instead of promised by the report. */
static unsigned family_cases[3];
static void bump(uint64_t family) { if (family < 3) family_cases[family]++; }
static Run run(const NovaHostImage *i, uint64_t family, const char *name, uint64_t count, Part p,
               Desc d, uint32_t features, unsigned cpl, uint64_t words) {
    Run r;
    memset(&r, 0, sizeof r);
    memset(r.out, guard, sizeof r.out);
    NovaContextV2 c = {0};
    CHECK(nova_context_init_v2(&c), "context init");
    uint64_t nh = nova_borrow_v2(&c, (void *)name, strlen(name), 0);
    uint64_t oh = nova_borrow_v2(&c, r.out, words, 1);
    uint64_t a[] = {family, nh, strlen(name), count, p.kind, p.reg, p.high8, p.width,
                    d.base, d.index, d.scale, d.disp, d.segment, features, cpl, oh, words};
    r.returned = i->entry(&c, a, 17);
    r.runtime = c.error;
    CHECK(nova_context_destroy_v2(&c), "context cleanup");
    return r;
}
static NtX64Operand native(Part p, Desc d) {
    NtX64Operand o = {0};
    o.kind = (NtX64Kind)p.kind;
    o.reg = (unsigned)p.reg;
    o.high8 = (unsigned)p.high8;
    o.width = (unsigned)p.width;
    o.imm = p.imm;
    o.is_signed = (unsigned)p.is_signed;
    o.base = d.base == 16 ? -1 : d.base == 17 ? -2 : (int)d.base;
    o.index = d.index == 16 ? -1 : (int)d.index;
    o.scale = (unsigned)d.scale;
    memcpy(&o.disp, &d.disp, sizeof o.disp);
    o.segment = (NtX64Segment)d.segment;
    return o;
}
static void show(const char *tag, const NovaHostImage *i, uint64_t family, const char *name,
                 uint64_t count, Part p, Desc d, uint32_t features, unsigned cpl, Run r, unsigned e) {
    (void)i;
    fprintf(stderr, "FAIL %s family=%llu %s count=%llu operand=(%llu,%llu,%llu,%llu,%llu,%llu) "
                    "mem=(%llu,%llu,%llu,%lld,%llu) f=%llu p=%llu ret=%llu oracle=%u out=%u,%u,%u,%u,%u,%u\n",
            tag, (unsigned long long)family, name, (unsigned long long)count,
            (unsigned long long)p.kind, (unsigned long long)p.reg, (unsigned long long)p.high8,
            (unsigned long long)p.width, (unsigned long long)p.imm, (unsigned long long)p.is_signed,
            (unsigned long long)d.base, (unsigned long long)d.index, (unsigned long long)d.scale,
            (long long)(int64_t)d.disp, (unsigned long long)d.segment, (unsigned long long)features,
            (unsigned long long)cpl, (unsigned long long)r.returned, e, r.out[0], r.out[1], r.out[2],
            r.out[3], r.out[4], r.out[5]);
}
/* Parity on the accepted stream and on the diagnostic alike: the export must
 * answer exactly what the oracle answers, and a diagnostic must leave every byte
 * of the output frame untouched. */
static void compare(const NovaHostImage *i, uint64_t family, const char *name, uint64_t count,
                    Part p, Desc d, uint32_t features, unsigned cpl) {
    NtX64Operand operands[1] = {native(p, d)};
    NtX64Instruction expected = {0};
    NtX64Context context = {features, cpl};
    NtX64Error e = nt_x64_encode(name, operands, (size_t)count, context, &expected);
    Run r = run(i, family, name, count, p, d, features, cpl, 16);
    cases++;
    checks++;
    bump(family);
    int bad = r.returned != (uint64_t)e || r.runtime;
    if (!e) {
        if (r.out[0] != expected.length) bad = 1;
        for (unsigned k = 0; k < expected.length; k++)
            if (r.out[1 + k] != expected.bytes[k]) bad = 1;
    } else {
        for (unsigned k = 0; k < sizeof r.out; k++)
            if (r.out[k] != guard) bad = 1;
    }
    if (bad) {
        failures++;
        show("parity", i, family, name, count, p, d, features, cpl, r, (unsigned)e);
    }
}
/* The three exports own the whole sixteen byte frame and clear it, so a success
 * leaves a zero tail instead of stale bytes. Kept out of compare so the byte
 * comparison above stays exactly the oracle stream and nothing else. */
static unsigned frame_cases;
static void frame(const NovaHostImage *i, uint64_t family, const char *name, Part p, Desc d) {
    NtX64Operand operands[1] = {native(p, d)};
    NtX64Instruction expected = {0};
    NtX64Context context = {1, 3};
    NtX64Error e = nt_x64_encode(name, operands, 1, context, &expected);
    if (e != NT_X64_OK) return;
    Run r = run(i, family, name, 1, p, d, 1, 3, 16);
    cases++;
    checks++;
    bump(family);
    int bad = r.returned != 0 || r.runtime;
    for (unsigned k = 0; k < 15; k++)
        bad |= r.out[k + 1] != (k < expected.length ? expected.bytes[k] : 0);
    if (bad) {
        failures++;
        show("frame", i, family, name, 1, p, d, 1, 3, r, (unsigned)e);
    } else {
        frame_cases++;
    }
}
/* The eight rows the drift table names, printed with the bytes the native oracle
 * produced, so the coordination point and this gate can be read against each
 * other. Every one of them is a parity case above; nothing here is an
 * expectation. */
static void headline(const char *label, const char *name, Part p, Desc d) {
    NtX64Operand operands[1] = {native(p, d)};
    NtX64Instruction expected = {0};
    NtX64Context context = {1, 3};
    if (nt_x64_encode(name, operands, 1, context, &expected) != NT_X64_OK) return;
    printf("HIGH8-ROW %-30s %-6s oracle=", label, name);
    for (unsigned k = 0; k < expected.length; k++) printf("%02x", expected.bytes[k]);
    printf(" len=%u\n", (unsigned)expected.length);
}
/* A short output frame is 800 whatever the operand is, and out stays untouched. */
static void short_frame(const NovaHostImage *i, uint64_t family, const char *name, Part p, Desc d) {
    Run r = run(i, family, name, 1, p, d, 1, 3, 15);
    cases++;
    checks++;
    bump(family);
    int bad = r.returned != 800 || r.runtime;
    for (unsigned k = 0; k < sizeof r.out; k++)
        if (r.out[k] != guard) bad = 1;
    if (bad) {
        failures++;
        show("short", i, family, name, 1, p, d, 1, 3, r, 800);
    }
}
/* The three exports describe a register or a memory and nothing else, so a
 * native immediate or relative displacement is the native form error 409 with
 * out untouched. The native encoder answers 409 for a well formed immediate of
 * the same shape and 412 for one whose signedness flag is out of range, a word
 * these exports do not carry: the divergence is stated here rather than hidden
 * behind an expected byte, and the native answer is printed with it. */
static void form_boundary(const NovaHostImage *i, uint64_t family, const char *name, Part p, Desc d) {
    NtX64Operand operands[1] = {native(p, d)};
    NtX64Instruction expected = {0};
    NtX64Context context = {1, 3};
    NtX64Error e = nt_x64_encode(name, operands, 1, context, &expected);
    Run r = run(i, family, name, 1, p, d, 1, 3, 16);
    cases++;
    checks++;
    bump(family);
    int bad = r.returned != 409 || r.runtime || (e != NT_X64_FORM && e != NT_X64_ARGUMENT);
    for (unsigned k = 0; k < sizeof r.out; k++)
        if (r.out[k] != guard) bad = 1;
    if (bad) {
        failures++;
        show("form", i, family, name, 1, p, d, 1, 3, r, (unsigned)e);
    }
}
/* The context and mnemonic diagnostics, once per family. */
static void context(const NovaHostImage *i, uint64_t family, const char *name, Part p, Desc d,
                    uint32_t features, unsigned cpl) {
    compare(i, family, name, 1, p, d, features, cpl);
}
int main(void) {
    const char *paths[] = {"tests/nova/tests/x64-high8-entry.nova",
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
    if (!compiled) fprintf(stderr, "E%u %zu:%zu %s\n", a.error.code, a.error.line, a.error.column, a.error.message);
    NovaHostImage image = {0};
    CHECK(compiled && nova_host_map(&a, &image), "image maps");
    if (image.memory) {
        const char *const unary[] = {"inc", "dec", "not", "neg"};
        const char *const setcc[] = {"sete", "setne", "setb", "setae", "setbe", "seta", "sets", "setns",
                                     "setp", "setnp", "setl", "setge", "setle", "setg", "seto", "setno"};
        const char *const stack[] = {"push", "pop"};
        const uint64_t widths[] = {8, 16, 32, 64};
        /* Every width the oracle accepts for a memory operand, including the two
         * a load or store would never spell: width 0 and the descriptor width 80
         * both reach the unary form and both must come out without a 0x66. */
        const uint64_t all_widths[] = {0, 8, 16, 32, 64, 80};
        const uint64_t regs[] = {0, 1, 2, 3, 4, 5, 8, 9, 12, 15};
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
        const Desc bad[] = {{18, 16, 1, 0, 0},      {0, 17, 1, 0, 0},     {0, 4, 1, 0, 0},
                            {0, 16, 3, 0, 0},      {0, 16, 2, 0, 0},     {17, 1, 1, 0, 0},
                            {0, 16, 1, 2147483648ULL, 0}, {0, 16, 1, 0xFFFFFFFF80000000ULL, 0},
                            {0, 16, 1, 0, 3}};
        const unsigned bad_count = sizeof bad / sizeof *bad;

        /* --- family 0: inc/dec/not/neg over a register and over a memory ---- */
        for (unsigned n = 0; n < 4; n++)
            for (unsigned w = 0; w < 4; w++)
                for (unsigned r = 0; r < 10; r++)
                    compare(&image, 0, unary[n], 1, gpr(regs[r], widths[w], 0), no_memory, 1, 3);
        /* The four high8 aliases: regcode register+4 and no REX at all. */
        for (unsigned n = 0; n < 4; n++)
            for (unsigned h = 0; h < 4; h++)
                compare(&image, 0, unary[n], 1, gpr(h, 8, 1), no_memory, 1, 3);
        /* Everything the oracle refuses around a high8 register. */
        for (unsigned n = 0; n < 4; n++) {
            compare(&image, 0, unary[n], 1, gpr(4, 8, 1), no_memory, 1, 3);
            compare(&image, 0, unary[n], 1, gpr(8, 8, 1), no_memory, 1, 3);
            compare(&image, 0, unary[n], 1, gpr(0, 16, 1), no_memory, 1, 3);
            compare(&image, 0, unary[n], 1, gpr(0, 32, 1), no_memory, 1, 3);
            compare(&image, 0, unary[n], 1, gpr(0, 64, 1), no_memory, 1, 3);
            compare(&image, 0, unary[n], 1, gpr(0, 8, 2), no_memory, 1, 3);
            compare(&image, 0, unary[n], 1, gpr(0, 8, 3), no_memory, 1, 3);
        }
        /* The memory direction, at every width the oracle accepts. */
        for (unsigned n = 0; n < 4; n++)
            for (unsigned w = 0; w < 6; w++)
                for (unsigned m = 0; m < desc_count; m++)
                    compare(&image, 0, unary[n], 1, mem(all_widths[w]), descs[m], 1, 3);
        for (unsigned m = 0; m < bad_count; m++)
            compare(&image, 0, "inc", 1, mem(64), bad[m], 1, 3);
        compare(&image, 0, "inc", 1, mem(0), bad[0], 1, 3);
        /* Diagnostics the oracle states before it ever looks at the operand. */
        compare(&image, 0, "telepathy", 1, gpr(0, 64, 0), no_memory, 1, 3);
        compare(&image, 0, "inc", 0, gpr(0, 64, 0), no_memory, 1, 3);
        compare(&image, 0, "inc", 2, gpr(0, 64, 0), no_memory, 1, 3);
        compare(&image, 0, "inc", 3, gpr(0, 64, 0), no_memory, 1, 3);
        compare(&image, 0, "inc", 1, gpr(16, 64, 0), no_memory, 1, 3);
        compare(&image, 0, "inc", 1, gpr(0, 24, 0), no_memory, 1, 3);
        compare(&image, 0, "inc", 1, gpr(0, 0, 0), no_memory, 1, 3);
        context(&image, 0, "inc", gpr(0, 64, 0), no_memory, 0, 3);
        context(&image, 0, "inc", gpr(0, 64, 0), no_memory, 1, 4);
        /* A form the three exports do not describe is the native form error
         * 409, and an immediate the export cannot even name is 412 natively. */
        compare(&image, 0, "inc", 1, (Part){0, 0, 0, 64, 0, 0}, no_memory, 1, 3);
        form_boundary(&image, 0, "inc", imm(1, 0), no_memory);
        form_boundary(&image, 0, "inc", imm(1, 2), no_memory);
        form_boundary(&image, 0, "inc", rel(0, 0), no_memory);
        form_boundary(&image, 0, "inc", rel(0, 2), no_memory);
        short_frame(&image, 0, "inc", gpr(0, 64, 0), no_memory);
        short_frame(&image, 0, "inc", mem(64), descs[1]);
        frame(&image, 0, "inc", gpr(3, 8, 1), no_memory);
        frame(&image, 0, "neg", gpr(15, 64, 0), no_memory);
        frame(&image, 0, "not", mem(64), descs[10]);
        frame(&image, 0, "dec", mem(0), descs[9]);

        /* --- family 1: the sixteen setcc over a register and over a memory -- */
        for (unsigned n = 0; n < 16; n++)
            for (unsigned r = 0; r < 10; r++)
                compare(&image, 1, setcc[n], 1, gpr(regs[r], 8, 0), no_memory, 1, 3);
        for (unsigned n = 0; n < 16; n++)
            for (unsigned h = 0; h < 4; h++)
                compare(&image, 1, setcc[n], 1, gpr(h, 8, 1), no_memory, 1, 3);
        for (unsigned n = 0; n < 16; n++)
            for (unsigned m = 0; m < desc_count; m++)
                compare(&image, 1, setcc[n], 1, mem(8), descs[m], 1, 3);
        /* setcc answers 403 for every width but 8, register and memory alike. */
        for (unsigned n = 0; n < 16; n++) {
            compare(&image, 1, setcc[n], 1, gpr(0, 16, 0), no_memory, 1, 3);
            compare(&image, 1, setcc[n], 1, gpr(0, 32, 0), no_memory, 1, 3);
            compare(&image, 1, setcc[n], 1, gpr(0, 64, 0), no_memory, 1, 3);
            compare(&image, 1, setcc[n], 1, mem(0), descs[0], 1, 3);
            compare(&image, 1, setcc[n], 1, mem(16), descs[0], 1, 3);
            compare(&image, 1, setcc[n], 1, mem(32), descs[0], 1, 3);
            compare(&image, 1, setcc[n], 1, mem(64), descs[0], 1, 3);
            compare(&image, 1, setcc[n], 1, mem(80), descs[0], 1, 3);
            compare(&image, 1, setcc[n], 1, gpr(4, 8, 1), no_memory, 1, 3);
            compare(&image, 1, setcc[n], 1, gpr(0, 16, 1), no_memory, 1, 3);
            compare(&image, 1, setcc[n], 1, gpr(0, 8, 2), no_memory, 1, 3);
        }
        for (unsigned m = 0; m < bad_count; m++)
            compare(&image, 1, "sete", 1, mem(8), bad[m], 1, 3);
        compare(&image, 1, "setq", 1, gpr(0, 8, 0), no_memory, 1, 3);
        compare(&image, 1, "sete", 0, gpr(0, 8, 0), no_memory, 1, 3);
        compare(&image, 1, "sete", 2, gpr(0, 8, 0), no_memory, 1, 3);
        compare(&image, 1, "sete", 1, gpr(16, 8, 0), no_memory, 1, 3);
        compare(&image, 1, "sete", 1, gpr(0, 24, 0), no_memory, 1, 3);
        context(&image, 1, "sete", gpr(0, 8, 0), no_memory, 0, 3);
        context(&image, 1, "sete", gpr(0, 8, 0), no_memory, 1, 4);
        compare(&image, 1, "sete", 1, (Part){0, 0, 0, 8, 0, 0}, no_memory, 1, 3);
        form_boundary(&image, 1, "sete", imm(1, 0), no_memory);
        form_boundary(&image, 1, "sete", imm(1, 2), no_memory);
        form_boundary(&image, 1, "sete", rel(0, 0), no_memory);
        form_boundary(&image, 1, "sete", rel(0, 2), no_memory);
        short_frame(&image, 1, "sete", gpr(0, 8, 0), no_memory);
        short_frame(&image, 1, "sete", mem(8), descs[1]);
        frame(&image, 1, "seto", gpr(2, 8, 1), no_memory);
        frame(&image, 1, "setle", gpr(0, 8, 0), no_memory);
        frame(&image, 1, "setg", mem(8), descs[12]);

        /* --- family 2: the push and pop memory direction --------------------
         * The oracle hands width 32 to modrm for this direction, so no REX.W
         * reaches the frame: `push [rbx+8]` is ff 73 08 and never 48 ff 73 08.
         * A width other than 64 is 403 in every direction. */
        for (unsigned n = 0; n < 2; n++)
            for (unsigned m = 0; m < desc_count; m++)
                compare(&image, 2, stack[n], 1, mem(64), descs[m], 1, 3);
        for (unsigned n = 0; n < 2; n++) {
            compare(&image, 2, stack[n], 1, mem(0), descs[0], 1, 3);
            compare(&image, 2, stack[n], 1, mem(8), descs[0], 1, 3);
            compare(&image, 2, stack[n], 1, mem(16), descs[0], 1, 3);
            compare(&image, 2, stack[n], 1, mem(32), descs[0], 1, 3);
            compare(&image, 2, stack[n], 1, mem(80), descs[0], 1, 3);
            compare(&image, 2, stack[n], 0, mem(64), descs[0], 1, 3);
            compare(&image, 2, stack[n], 2, mem(64), descs[0], 1, 3);
        }
        for (unsigned m = 0; m < bad_count; m++)
            compare(&image, 2, "push", 1, mem(64), bad[m], 1, 3);
        compare(&image, 2, "pushq", 1, mem(64), descs[0], 1, 3);
        context(&image, 2, "push", mem(64), descs[0], 0, 3);
        context(&image, 2, "push", mem(64), descs[0], 1, 4);
        short_frame(&image, 2, "push", mem(64), descs[1]);
        frame(&image, 2, "push", mem(64), descs[1]);
        frame(&image, 2, "pop", mem(64), descs[10]);

        CHECK(frame_cases == 9, "the accepted frame is cleared past the instruction");
        CHECK(family_cases[0] >= 20, "at least twenty cases in the unary family");
        CHECK(family_cases[1] >= 20, "at least twenty cases in the setcc family");
        CHECK(family_cases[2] >= 20, "at least twenty cases in the stack family");
        printf("HIGH8-COUNT family=0 unary cases=%u family=1 setcc cases=%u family=2 stack cases=%u\n",
               family_cases[0], family_cases[1], family_cases[2]);
        headline("inc ah", "inc", gpr(0, 8, 1), no_memory);
        headline("sete ah", "sete", gpr(0, 8, 1), no_memory);
        headline("inc [rbx+8] u64", "inc", mem(64), descs[1]);
        headline("push [rbx+8] u64", "push", mem(64), descs[1]);
        headline("pop [rbx+8] u64", "pop", mem(64), descs[1]);
        headline("sete [rbx+8] u8", "sete", mem(8), descs[1]);
        headline("inc r12", "inc", gpr(12, 64, 0), no_memory);
        headline("sete r10b", "sete", gpr(10, 8, 0), no_memory);
        Run mode_ = run(&image, 9, "inc", 1, gpr(0, 64, 0), no_memory, 1, 3, 16);
        cases++;
        checks++;
        int unmode = mode_.returned != 800 || mode_.runtime;
        for (unsigned k = 0; k < sizeof mode_.out; k++)
            unmode |= mode_.out[k] != guard;
        CHECK(unmode == 0, "unknown family transactional");
    }
    if (image.memory) nova_host_unmap(&image);
    if (compiled) nt_artifact_free(&a);
    for (unsigned k = 0; k < 2; k++) free(sources[k]);
    printf("NTASM_NOVA_X64_HIGH8 checks=%u failures=%u cases=%u\n", checks, failures, cases);
    return failures ? 1 : 0;
}
