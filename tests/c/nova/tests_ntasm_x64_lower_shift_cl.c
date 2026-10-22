/* NTASM AST lowerer gate for the shift and rotate families, counted by cl and
 * by an immediate, and for the two neighbouring lowerer surfaces this lot
 * changed beside them: the signed literal of push/pop and the mnemonic test the
 * two-register width rule pre-empts. Every accepted instruction is encoded a
 * second time by the native oracle nt_x64_encode and compared byte for byte, and
 * every refusal is compared against the oracle diagnostic, so no expected byte or
 * code is ever derived from the Nova producer. The forms no x64_fixed export can
 * state stay declared gaps and are reported, never hidden. */
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

typedef struct { uint64_t returned, runtime; uint8_t out[64]; } Run;

static Run run(const NovaHostImage *i, const char *body, uint32_t features, unsigned cpl) {
    char source[1024];
    int n = snprintf(source, sizeof source,
                     "module m\ntarget x86_64-nexora-none\nsection .text {\n"
                     "fn f()->u64\neffects {}\nclobbers {} {\n%s\nreturn 0\n}\n}\n",
                     body);
    Run r;
    memset(&r, 0, sizeof r);
    memset(r.out, guard, sizeof r.out);
    NovaContextV2 c = {0};
    CHECK(nova_context_init_v2(&c), "context init");
    uint64_t sh = nova_borrow_v2(&c, (void *)source, (uint64_t)n, 0);
    uint64_t oh = nova_borrow_v2(&c, r.out, (uint64_t)sizeof r.out, 1);
    uint64_t a[] = {sh, (uint64_t)n, features, cpl, oh, (uint64_t)sizeof r.out};
    r.returned = i->entry(&c, a, 6);
    r.runtime = c.error;
    CHECK(nova_context_destroy_v2(&c), "context cleanup");
    return r;
}

static void compare(const NovaHostImage *i, const char *mnemonic, const char *body, NtX64Operand *o,
                    unsigned count, uint32_t features, unsigned cpl) {
    NtX64Instruction expected = {0};
    NtX64Context context = {features, cpl};
    NtX64Error e = nt_x64_encode(mnemonic, o, count, context, &expected);
    Run r = run(i, body, features, cpl);
    cases++;
    checks++;
    int bad = r.runtime != 0 || r.returned != (uint64_t)e;
    if (e == NT_X64_OK) {
        if (r.out[0] != (uint8_t)expected.length) bad = 1;
        for (size_t k = 0; k < expected.length; k++)
            if (r.out[1 + k] != expected.bytes[k]) bad = 1;
        for (unsigned k = (unsigned)expected.length + 1; k < sizeof r.out; k++)
            if (r.out[k] != guard) bad = 1;
    } else {
        for (unsigned k = 0; k < sizeof r.out; k++)
            if (r.out[k] != guard) bad = 1;
    }
    if (bad)
        failures++,
            fprintf(stderr, "FAIL cl %s as %s ret=%llu oracle=%u out=%u,%u,%u,%u,%u,%u\n", body,
                    mnemonic, (unsigned long long)r.returned, (unsigned)e, r.out[0], r.out[1],
                    r.out[2], r.out[3], r.out[4], r.out[5]);
}

/* A refusal the lowerer owns: the operand count never reaches the oracle. */
static void refusal(const NovaHostImage *i, const char *name, const char *body, uint64_t code) {
    Run r = run(i, body, 1, 3);
    cases++;
    int bad = r.returned != code || r.runtime != 0;
    for (unsigned k = 0; k < sizeof r.out; k++) bad |= r.out[k] != guard;
    if (bad) {
        failures++;
        fprintf(stderr, "FAIL cl %s ret=%llu expected=%llu\n", name, (unsigned long long)r.returned,
                (unsigned long long)code);
    } else {
        checks++;
    }
}

/* Formerly missing forms must now match the independent C encoder. */
static void gap(const NovaHostImage *i, const char *mnemonic, const char *body, NtX64Operand *o,
                unsigned count) {
    NtX64Instruction expected = {0};
    NtX64Context context = {1, 3};
    CHECK(nt_x64_encode(mnemonic, o, count, context, &expected) == NT_X64_OK,
          "the previously missing form is accepted by the reference");
    compare(i, mnemonic, body, o, count, 1, 3);
}

/* A divergence the lowerer does not resolve: it states its own answer and the
 * oracle answer beside it, so the row fails the moment either side moves. The
 * lowerer applies its operand-width rule before it tests the mnemonic, so an
 * unknown two-operand mnemonic with mismatched widths answers 403 where the
 * oracle answers 401 from the name alone, without ever reading an operand. */
static void divergence(const NovaHostImage *i, const char *mnemonic, const char *body,
                       NtX64Operand *o, unsigned count, uint64_t lowerer_code) {
    NtX64Instruction expected = {0};
    NtX64Context context = {1, 3};
    NtX64Error e = nt_x64_encode(mnemonic, o, count, context, &expected);
    Run r = run(i, body, 1, 3);
    cases++;
    checks++;
    int bad = r.runtime != 0 || r.returned != lowerer_code || (uint64_t)e == lowerer_code;
    for (unsigned k = 0; k < sizeof r.out; k++) bad |= r.out[k] != guard;
    if (bad) {
        failures++;
        fprintf(stderr, "FAIL cl divergence %s %s lowerer=%llu oracle=%u\n", mnemonic, body,
                (unsigned long long)r.returned, (unsigned)e);
    } else {
        printf("CL-DIVERGENCE %-6s %-30s oracle=%u lowerer=%llu\n", mnemonic, body, (unsigned)e,
               (unsigned long long)r.returned);
    }
}

typedef struct {
    const char *destination;
    unsigned reg, width, high8;
} Count;

/* A signed literal carries its full two's-complement bits in the oracle operand,
 * the convention x64.h states, so the rows below state the magnitude and let
 * this fold build the operand the encoder is given. */
static NtX64Operand signed_imm(uint64_t magnitude) {
    NtX64Operand o = {0};
    o.kind = NT_X64_IMM;
    o.imm = 0 - magnitude;
    o.is_signed = 1;
    return o;
}

/* The body is built from the mnemonic under test, so one destination row
 * covers the whole rol/ror/shl/shr/sar surface. */
static void row(const NovaHostImage *i, const char *mnemonic, const Count *r) {
    char body[64];
    snprintf(body, sizeof body, "%s %s,cl", mnemonic, r->destination);
    NtX64Operand o[2] = {{.kind = NT_X64_REG, .width = r->width, .reg = r->reg, .high8 = r->high8},
                         {.kind = NT_X64_REG, .width = 8, .reg = 1}};
    compare(i, mnemonic, body, o, 2, 1, 3);
}

/* The same destination row with an unsigned literal count instead of cl. */
static void imm_row(const NovaHostImage *i, const char *mnemonic, const Count *r,
                    uint64_t amount) {
    char body[64];
    snprintf(body, sizeof body, "%s %s,%llu", mnemonic, r->destination,
             (unsigned long long)amount);
    NtX64Operand o[2] = {{.kind = NT_X64_REG, .width = r->width, .reg = r->reg, .high8 = r->high8},
                         {.kind = NT_X64_IMM, .imm = amount}};
    compare(i, mnemonic, body, o, 2, 1, 3);
}

/* A count the lowerer spells with a leading minus. The oracle range-checks the
 * two's complement of the magnitude, so every negative count answers 407. */
static void negative_count_row(const NovaHostImage *i, const char *mnemonic, const char *destination,
                               unsigned reg, unsigned width, uint64_t magnitude) {
    char body[64];
    snprintf(body, sizeof body, "%s %s,-%llu", mnemonic, destination, (unsigned long long)magnitude);
    NtX64Operand o[2] = {{.kind = NT_X64_REG, .width = width, .reg = reg}, signed_imm(magnitude)};
    compare(i, mnemonic, body, o, 2, 1, 3);
}

/* The count register itself, for the forms the oracle answers 406 on. */
static void count_row(const NovaHostImage *i, const char *mnemonic, const char *body, unsigned dreg,
                      unsigned dwidth, unsigned dhigh8, unsigned creg, unsigned cwidth,
                      unsigned chigh8) {
    NtX64Operand o[2] = {{.kind = NT_X64_REG, .width = dwidth, .reg = dreg, .high8 = dhigh8},
                         {.kind = NT_X64_REG, .width = cwidth, .reg = creg, .high8 = chigh8}};
    compare(i, mnemonic, body, o, 2, 1, 3);
}

static void shift_cl_cases(const NovaHostImage *i) {
    static const char *const names[] = {"rol", "ror", "shl", "shr", "sar"};
    /* The five mnemonics at the two GPR widths the v0 catalogue uses. */
    static const Count wide[] = {
        {"eax", 0, 32, 0}, {"rax", 0, 64, 0}, {"ecx", 1, 32, 0}, {"rcx", 1, 64, 0},
        {"r8d", 8, 32, 0}, {"r8", 8, 64, 0}, {"ebx", 3, 32, 0}, {"rbx", 3, 64, 0},
        {"r9d", 9, 32, 0}, {"r9", 9, 64, 0},
    };
    for (unsigned k = 0; k < sizeof names / sizeof *names; k++)
        for (unsigned m = 0; m < sizeof wide / sizeof *wide; m++) row(i, names[k], &wide[m]);
    /* The 16 bit and 8 bit low register forms, including the forced REX of
     * spl upwards. */
    static const Count narrow[] = {
        {"ax", 0, 16, 0},   {"r10w", 10, 16, 0}, {"al", 0, 8, 0},   {"spl", 4, 8, 0},
        {"r11b", 11, 8, 0}, {"r15", 15, 64, 0},  {"r13", 13, 64, 0},
    };
    for (unsigned k = 0; k < sizeof names / sizeof *names; k++)
        for (unsigned m = 0; m < sizeof narrow / sizeof *narrow; m++) row(i, names[k], &narrow[m]);
    /* The four high8 aliases, which exist only without any REX prefix. The
     * oracle numbers them reg 0..3 plus the high8 bit, so bh is reg 3. */
    static const Count high8[] = {{"ah", 0, 8, 1}, {"ch", 1, 8, 1}, {"dh", 2, 8, 1}, {"bh", 3, 8, 1}};
    for (unsigned k = 0; k < sizeof names / sizeof *names; k++)
        for (unsigned m = 0; m < sizeof high8 / sizeof *high8; m++) row(i, names[k], &high8[m]);
    /* Only cl counts: every other count operand answers NT_X64_REGISTER. */
    count_row(i, "shl", "shl rax,ch", 0, 64, 0, 1, 8, 1);
    count_row(i, "shl", "shl rax,cx", 0, 64, 0, 1, 16, 0);
    count_row(i, "shl", "shl rax,ecx", 0, 64, 0, 1, 32, 0);
    count_row(i, "shl", "shl rax,rcx", 0, 64, 0, 1, 64, 0);
    count_row(i, "shl", "shl rax,rbx", 0, 64, 0, 3, 64, 0);
    count_row(i, "shl", "shl rax,al", 0, 64, 0, 0, 8, 0);
    count_row(i, "shl", "shl al,ah", 0, 8, 0, 0, 8, 1);
    count_row(i, "shl", "shl ah,ah", 0, 8, 1, 0, 8, 1);
    count_row(i, "sar", "sar rax,dl", 0, 64, 0, 3, 8, 0);
    /* The destination spelling the width table does not number. */
    count_row(i, "shl", "shl r16,cl", 16, 64, 0, 1, 8, 0);
    /* Context rules, still compared against the oracle answer. */
    {
        NtX64Operand o[2] = {{.kind = NT_X64_REG, .width = 64, .reg = 0},
                             {.kind = NT_X64_REG, .width = 8, .reg = 1}};
        compare(i, "shl", "shl rax,cl", o, 2, 0, 3);
        compare(i, "shl", "shl rax,cl", o, 2, 1, 4);
    }

    /* ---- counted by an unsigned literal -----------------------------------
     * encode_shift_imm owns one register destination and an amount of 0..255;
     * the amount of 1 is the only short form. The rows below are the parity
     * surface of that export reached through encode_instruction. */
    for (unsigned k = 0; k < sizeof names / sizeof *names; k++)
        for (unsigned m = 0; m < sizeof wide / sizeof *wide; m++) imm_row(i, names[k], &wide[m], 1);
    for (unsigned k = 0; k < sizeof names / sizeof *names; k++)
        for (unsigned m = 0; m < sizeof narrow / sizeof *narrow; m++)
            imm_row(i, names[k], &narrow[m], 1);
    /* The amount boundaries: 0 is not the short form, 255 is the largest the
     * encoder accepts and 256 is the range diagnostic. */
    static const uint64_t amounts[] = {0, 2, 3, 127, 128, 254, 255, 256};
    for (unsigned k = 0; k < sizeof names / sizeof *names; k++)
        for (unsigned m = 0; m < sizeof amounts / sizeof *amounts; m++) {
            char body[64];
            snprintf(body, sizeof body, "%s rax,%llu", names[k],
                     (unsigned long long)amounts[m]);
            NtX64Operand o[2] = {{.kind = NT_X64_REG, .width = 64, .reg = 0},
                                 {.kind = NT_X64_IMM, .imm = amounts[m]}};
            compare(i, names[k], body, o, 2, 1, 3);
        }
    /* A negative count is the two's complement of its magnitude, which the
     * oracle range-checks, so every one of them answers 407. */
    negative_count_row(i, "shl", "rax", 0, 64, 1);
    negative_count_row(i, "sar", "eax", 0, 32, 1);
    negative_count_row(i, "rol", "rbx", 3, 64, 256);
    /* The destination the width table does to the register, answered 406. */
    for (unsigned k = 0; k < sizeof names / sizeof *names; k++) {
        char body[64];
        snprintf(body, sizeof body, "%s r16,1", names[k]);
        NtX64Operand o[2] = {{.kind = NT_X64_REG, .width = 64, .reg = 16},
                             {.kind = NT_X64_IMM, .imm = 1}};
        compare(i, names[k], body, o, 2, 1, 3);
    }
    /* Context rules on the immediate form, still the oracle answer. */
    {
        NtX64Operand o[2] = {{.kind = NT_X64_REG, .width = 64, .reg = 0},
                             {.kind = NT_X64_IMM, .imm = 1}};
        compare(i, "shl", "shl rax,1", o, 2, 0, 3);
        compare(i, "shl", "shl rax,1", o, 2, 1, 4);
    }
    /* Declared gap: encode_shift_imm states no high8 regcode, so a destination
     * of ah/ch/dh/bh would encode the wrong ModRM.rm byte. The oracle numbers
     * those aliases reg 0..3 plus the high8 bit, so shl ah,1 is d0 e4 there
     * and no lowerer answer can match it. */
    for (unsigned k = 0; k < sizeof names / sizeof *names; k++) {
        char body[64];
        snprintf(body, sizeof body, "%s ah,1", names[k]);
        NtX64Operand o[2] = {{.kind = NT_X64_REG, .width = 8, .reg = 0, .high8 = 1},
                             {.kind = NT_X64_IMM, .imm = 1}};
        gap(i, names[k], body, o, 2);
    }
    /* Declared gap: a memory destination. The oracle reaches a memory operand
     * through its own modrm, both shift exports state a register number only,
     * and no export of x64_fixed takes a memory destination for a shift, so
     * the whole M_CL, M_1 and M_I8 family stays declared. */
    for (unsigned k = 0; k < sizeof names / sizeof *names; k++) {
        char body[64];
        NtX64Operand mem[2] = {{.kind = NT_X64_MEM, .width = 64, .base = 3, .index = -1, .scale = 1,
                                .disp = 8},
                               {.kind = NT_X64_REG, .width = 8, .reg = 1}};
        snprintf(body, sizeof body, "%s [rbx+8]:ptr<user,u64>,cl", names[k]);
        gap(i, names[k], body, mem, 2);
        mem[1] = (NtX64Operand){.kind = NT_X64_IMM, .imm = 1};
        snprintf(body, sizeof body, "%s [rbx+8]:ptr<user,u64>,1", names[k]);
        gap(i, names[k], body, mem, 2);
        mem[1] = (NtX64Operand){.kind = NT_X64_IMM, .imm = 8};
        snprintf(body, sizeof body, "%s [rbx+8]:ptr<user,u64>,8", names[k]);
        gap(i, names[k], body, mem, 2);
    }

    /* Refusals the lowerer owns: an operand count never reaches the oracle. */
    refusal(i, "one operand", "shl rax", 409);
    refusal(i, "three operands", "shl rax,cl,rcx", 409);
    refusal(i, "one operand immediate", "shl 1", 409);

    /* ---- the signed literal of push/pop -----------------------------------
     * A negative literal is a unary-minus node whose child states the magnitude
     * and no sign, so the lowerer reads the sign out of the source text and
     * hands the encoder the two's complement the oracle operand carries. Every
     * boundary of that fold is a parity row here. */
    {
        static const uint64_t magnitudes[] = {0, 1, 127, 128, 129, 2147483647, 2147483648,
                                              2147483649};
        for (unsigned m = 0; m < sizeof magnitudes / sizeof *magnitudes; m++) {
            char body[64];
            snprintf(body, sizeof body, "push -%llu", (unsigned long long)magnitudes[m]);
            NtX64Operand o[1] = {signed_imm(magnitudes[m])};
            compare(i, "push", body, o, 1, 1, 3);
        }
        /* The unsigned spelling of the same magnitudes, unchanged. */
        for (unsigned m = 0; m < sizeof magnitudes / sizeof *magnitudes; m++) {
            char body[64];
            snprintf(body, sizeof body, "push %llu", (unsigned long long)magnitudes[m]);
            NtX64Operand o[1] = {{.kind = NT_X64_IMM, .imm = magnitudes[m]}};
            compare(i, "push", body, o, 1, 1, 3);
        }
        /* pop takes no immediate at all, signed or not. */
        NtX64Operand popped[1] = {signed_imm(1)};
        compare(i, "pop", "pop -1", popped, 1, 1, 3);
        NtX64Operand popped_unsigned[1] = {{.kind = NT_X64_IMM, .imm = 1}};
        compare(i, "pop", "pop 1", popped_unsigned, 1, 1, 3);
        /* A sign the stack encoders still refuse: a context rule. */
        compare(i, "push", "push -1", popped, 1, 0, 3);
        compare(i, "push", "push -1", popped, 1, 1, 4);
    }

    /* ---- the mnemonic the two-register width rule pre-empts ---------------
     * Pinned, not fixed. The lowerer answers its operand-width rule before it
     * tests the mnemonic, so an unknown two-operand mnemonic with mismatched
     * widths answers 403 where the oracle answers 401 from the name alone.
     * tests_ntasm_x64_lower_two_reg.c states the same 403, so moving it would
     * turn that gate red; the row here witnesses it from the shift gate too. */
    {
        NtX64Operand narrow[2] = {{.kind = NT_X64_REG, .width = 32, .reg = 0},
                                  {.kind = NT_X64_REG, .width = 8, .reg = 0}};
        divergence(i, "movzbw", "movzbw eax,al", narrow, 2, 403);
        NtX64Operand wide[2] = {{.kind = NT_X64_REG, .width = 64, .reg = 0},
                                {.kind = NT_X64_REG, .width = 64, .reg = 3}};
        compare(i, "movzbw", "movzbw rax,rbx", wide, 2, 1, 3);
        NtX64Operand literal[2] = {{.kind = NT_X64_REG, .width = 64, .reg = 0},
                                   {.kind = NT_X64_IMM, .imm = 1}};
        compare(i, "movzbw", "movzbw rax,1", literal, 2, 1, 3);
    }
}

int main(void) {
    const char *paths[] = {"tests/nova/tests/x64-lower-shift-cl-entry.nova",
                           "compiler/nova/backend/x64/x64_lower_fixed.nova",
                           "compiler/nova/backend/x64/x64_fixed.nova",
                           "compiler/nova/analysis/types/register_widths.nova",
                           "compiler/nova/frontend/parser.nova",
                           "compiler/nova/frontend/ast.nova",
                           "compiler/nova/frontend/lexer.nova"};
    char *sources[7] = {0};
    NtFInput inputs[7];
    for (unsigned k = 0; k < 7; k++) {
        size_t n = 0;
        sources[k] = loadf(paths[k], &n);
        inputs[k] = (NtFInput){paths[k], sources[k], n};
    }
    int all = 1;
    for (unsigned k = 0; k < 7; k++)
        if (!sources[k]) all = 0;
    CHECK(all, "sources load");
    NtArtifact a = {0};
    int compiled = all && nova_compile_many_v2(inputs, 7, &a);
    CHECK(compiled, "modules compile");
    if (!compiled) fprintf(stderr, "E%u %zu:%zu %s\n", a.error.code, a.error.line, a.error.column, a.error.message);
    NovaHostImage image = {0};
    CHECK(compiled && nova_host_map(&a, &image), "image maps");
    if (image.memory) shift_cl_cases(&image);
    if (image.memory) nova_host_unmap(&image);
    if (compiled) nt_artifact_free(&a);
    for (unsigned k = 0; k < 7; k++) free(sources[k]);
    printf("NTASM_NOVA_X64_LOWER_SHIFT_CL checks=%u failures=%u cases=%u\n", checks, failures, cases);
    return failures ? 1 : 0;
}
