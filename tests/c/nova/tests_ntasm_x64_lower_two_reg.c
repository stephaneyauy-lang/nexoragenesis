/* NTASM AST lowerer gate for the two-register families of the v0 catalogue
 * that x64_fixed already encodes but encode_instruction could not reach:
 * xchg (I26), the sixteen cmov conditions (I22), bsf/bsr (I25), the three
 * width-conversion moves (I05/I06/I07) and test (I09 R_R and M_R), plus the
 * one-operand forms the same dispatch owns: inc/dec/not/neg, push/pop and the
 * sixteen setcc conditions.
 *
 * Every accepted instruction is encoded a second time by the native oracle
 * nt_x64_encode and compared byte for byte, and every refusal is compared
 * against the oracle diagnostic, so no expected byte or code is ever derived
 * from the Nova producer. The spelling and the native descriptors of a case
 * come from one table row, so the two cannot drift apart inside the harness
 * either.
 *
 * The forms the oracle encodes and the lowerer still cannot reach are declared
 * as gaps of the drift table in tests_ntasm_x64_lower_lea.c and are not
 * duplicated here: one declaration ledger, and an undeclared refusal stays a
 * hard failure there.
 *
 * The one-operand group is covered in all three of the shapes the three exports
 * of x64_fixed now take: a low8 register, a high8 alias (ah/ch/dh/bh) and a
 * memory operand at every access width the pointer element type states. The two
 * widths the setcc and the stack exports refuse are compared against the oracle
 * diagnostic rather than stated, so a lowerer that answered 409 there would fail
 * instead of passing unnoticed. */
#include "../../../compiler/c/nova/frontend/nova.h"
#include "../../../compiler/c/nova/runtime/run_host.h"
#include "../../../compiler/c/nova/runtime/runtime_v2.h"
#include "../../../compiler/c/ntasm/backend/x64.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checks, failures, cases;
/* Per-family case counts, so the coverage of every target family is visible in
 * the log of the gate itself and not only in its source. */
static unsigned count_xchg, count_cmov, count_scan, count_convert, count_test, count_one, count_imul, count_bswap, count_muldiv, count_bits, count_desc;
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

/* One statement inside an otherwise empty function body, so the only kind 32
 * node in the tree is the instruction under test. */
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

/* Encode the same instruction with the native oracle and require the lowerer to
 * agree on the bytes, or on the diagnostic, and to leave out untouched on every
 * failure. Both byte strings are printed on a mismatch, so a wrong expectation
 * and a wrong producer are distinguishable from the log alone. */
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
    if (bad) {
        failures++;
        fprintf(stderr,
                "FAIL %s as %s ret=%llu oracle=%u out=%u,%u,%u,%u,%u,%u want=%u,%u,%u,%u,%u,%u\n",
                mnemonic, body, (unsigned long long)r.returned, (unsigned)e, r.out[0], r.out[1], r.out[2],
                r.out[3], r.out[4], r.out[5], (unsigned)expected.length, expected.bytes[0],
                expected.bytes[1], expected.bytes[2], expected.bytes[3], expected.bytes[4]);
    }
}

/* A refusal the lowerer owns by itself: the expected code is stated here. out
 * must stay untouched. */
static void own(const NovaHostImage *i, const char *label, const char *body, uint64_t code) {
    Run r = run(i, body, 1, 3);
    cases++;
    int bad = r.returned != code || r.runtime != 0;
    for (unsigned k = 0; k < sizeof r.out; k++) bad |= r.out[k] != guard;
    if (bad) {
        failures++;
        fprintf(stderr, "FAIL own %s (%s) ret=%llu expected=%llu\n", label, body,
                (unsigned long long)r.returned, (unsigned long long)code);
    } else {
        checks++;
    }
}

/* One register spelling and the native descriptor it stands for. ah/ch/dh/bh
 * are reg 0..3 plus the high8 bit, the oracle numbering. The enum below
 * indexes this table. */
typedef struct { const char *text; unsigned reg, width, high8; } Reg;
static const Reg regs[] = {
    {"rax", 0, 64, 0},  {"rbx", 3, 64, 0},  {"rcx", 1, 64, 0},  {"rdx", 2, 64, 0},
    {"rsi", 6, 64, 0},  {"rdi", 7, 64, 0},  {"rsp", 4, 64, 0},  {"rbp", 5, 64, 0},
    {"r8", 8, 64, 0},   {"r9", 9, 64, 0},   {"r12", 12, 64, 0}, {"r13", 13, 64, 0},
    {"r15", 15, 64, 0},
    {"eax", 0, 32, 0},  {"ebx", 3, 32, 0},  {"ecx", 1, 32, 0},  {"edx", 2, 32, 0},
    {"esi", 6, 32, 0},  {"edi", 7, 32, 0},  {"esp", 4, 32, 0},  {"ebp", 5, 32, 0},
    {"r8d", 8, 32, 0},  {"r9d", 9, 32, 0},  {"r12d", 12, 32, 0}, {"r13d", 13, 32, 0},
    {"r15d", 15, 32, 0},
    {"ax", 0, 16, 0},   {"bx", 3, 16, 0},   {"cx", 1, 16, 0},   {"dx", 2, 16, 0},
    {"si", 6, 16, 0},   {"di", 7, 16, 0},   {"sp", 4, 16, 0},   {"bp", 5, 16, 0},
    {"r8w", 8, 16, 0},  {"r9w", 9, 16, 0},  {"r12w", 12, 16, 0}, {"r13w", 13, 16, 0},
    {"r15w", 15, 16, 0},
    {"al", 0, 8, 0},    {"bl", 3, 8, 0},    {"cl", 1, 8, 0},    {"dl", 2, 8, 0},
    {"sil", 6, 8, 0},   {"dil", 7, 8, 0},   {"spl", 4, 8, 0},   {"bpl", 5, 8, 0},
    {"r8b", 8, 8, 0},   {"r9b", 9, 8, 0},   {"r12b", 12, 8, 0}, {"r13b", 13, 8, 0},
    {"r15b", 15, 8, 0},
    {"ah", 0, 8, 1},    {"ch", 1, 8, 1},    {"dh", 2, 8, 1},    {"bh", 3, 8, 1},
};
#define NREGS (sizeof regs / sizeof *regs)
enum {
    I_RAX = 0, I_RBX, I_RCX, I_RDX, I_RSI, I_RDI, I_RSP, I_RBP, I_R8, I_R9, I_R12, I_R13,
    I_R15, I_EAX, I_EBX, I_ECX, I_EDX, I_ESI, I_EDI, I_ESP, I_EBP, I_R8D, I_R9D, I_R12D,
    I_R13D, I_R15D, I_AX, I_BX, I_CX, I_DX, I_SI, I_DI, I_SP, I_BP, I_R8W, I_R9W, I_R12W,
    I_R13W, I_R15W, I_AL, I_BL, I_CL, I_DL, I_SIL, I_DIL, I_SPL, I_BPL, I_R8B, I_R9B,
    I_R12B, I_R13B, I_R15B, I_AH, I_CH, I_DH, I_BH
};

/* One memory spelling and the native descriptor it stands for. The pointer
 * element type is the access width the two-register encoders compare with the
 * register width, so it belongs to the row. */
typedef struct {
    const char *text;
    int base, index;
    unsigned scale;
    int64_t disp;
    unsigned width, segment;
} Mem;
static const Mem mems[] = {
    {"[rbx+8]:ptr<user,u64>", 3, -1, 1, 8, 64, 0},
    {"[rbx]:ptr<user,u64>", 3, -1, 1, 0, 64, 0},
    {"[rsp+8]:ptr<user,u64>", 4, -1, 1, 8, 64, 0},
    {"[r12+r13*8-128]:ptr<user,u64>", 12, 13, 8, -128, 64, 0},
    {"[r12+r13*8+2147483647]:ptr<user,u64>", 12, 13, 8, 2147483647, 64, 0},
    {"[rbx+rcx*4+64]:ptr<user,u64>", 3, 1, 4, 64, 64, 0},
    {"[rip+16]:ptr<user,u64>", -2, -1, 1, 16, 64, 0},
    {"[fs:rbx+8]:ptr<user,u64>", 3, -1, 1, 8, 64, 1},
    {"[gs:rbx+8]:ptr<user,u64>", 3, -1, 1, 8, 64, 2},
    {"[rbx+8]:ptr<user,u32>", 3, -1, 1, 8, 32, 0},
    {"[rbx+8]:ptr<user,u16>", 3, -1, 1, 8, 16, 0},
    {"[rbx+8]:ptr<user,u8>", 3, -1, 1, 8, 8, 0},
};
#define NMEMS (sizeof mems / sizeof *mems)

static NtX64Operand reg_operand(const Reg *r) {
    NtX64Operand o = {0};
    o.kind = NT_X64_REG;
    o.reg = r->reg;
    o.width = r->width;
    o.high8 = r->high8;
    return o;
}

static NtX64Operand mem_operand(const Mem *m) {
    NtX64Operand o = {0};
    o.kind = NT_X64_MEM;
    o.width = m->width;
    o.base = m->base;
    o.index = m->index;
    o.scale = m->scale;
    o.disp = m->disp;
    o.segment = (NtX64Segment)m->segment;
    return o;
}

/* mnemonic reg,reg */
static void reg_pair(const NovaHostImage *i, const char *mnemonic, const Reg *a, const Reg *b,
                     uint32_t features, unsigned cpl) {
    char body[96];
    snprintf(body, sizeof body, "%s %s,%s", mnemonic, a->text, b->text);
    NtX64Operand o[2] = {reg_operand(a), reg_operand(b)};
    compare(i, mnemonic, body, o, 2, features, cpl);
}

/* mnemonic reg,mem */
static void reg_mem(const NovaHostImage *i, const char *mnemonic, const Reg *a, const Mem *m,
                    uint32_t features, unsigned cpl) {
    char body[128];
    snprintf(body, sizeof body, "%s %s,%s", mnemonic, a->text, m->text);
    NtX64Operand o[2] = {reg_operand(a), mem_operand(m)};
    compare(i, mnemonic, body, o, 2, features, cpl);
}

/* mnemonic mem,reg: only test spells a memory first operand. */
static void mem_reg(const NovaHostImage *i, const char *mnemonic, const Mem *m, const Reg *b,
                    uint32_t features, unsigned cpl) {
    char body[128];
    snprintf(body, sizeof body, "%s %s,%s", mnemonic, m->text, b->text);
    NtX64Operand o[2] = {mem_operand(m), reg_operand(b)};
    compare(i, mnemonic, body, o, 2, features, cpl);
}

/* mnemonic operand: the one-operand forms, so the spelling and the native
 * descriptor still come from one table entry. */
static void one_operand(const NovaHostImage *i, const char *mnemonic, const char *text,
                        NtX64Operand *o, uint32_t features, unsigned cpl) {
    char body[128];
    snprintf(body, sizeof body, "%s %s", mnemonic, text);
    compare(i, mnemonic, body, o, 1, features, cpl);
}

/* mnemonic reg,reg,imm and mnemonic reg,mem,imm: the THREE-operand imul, the
 * one arity in this gate that no other family has. The immediate carries no
 * declared width, which is exactly what an NTASM literal is, and the value
 * sweeps both sides of the 6B/69 compact switch. */
static void reg_reg_imm(const NovaHostImage *i, const Reg *a, const Reg *b, uint64_t value) {
    char body[96];
    snprintf(body, sizeof body, "imul %s,%s,%llu", a->text, b->text, (unsigned long long)value);
    NtX64Operand o[3] = {reg_operand(a), reg_operand(b), {0}};
    o[2].kind = NT_X64_IMM;
    o[2].imm = value;
    compare(i, "imul", body, o, 3, 1, 3);
}
static void reg_mem_imm(const NovaHostImage *i, const Reg *a, const Mem *m, uint64_t value) {
    char body[128];
    snprintf(body, sizeof body, "imul %s,%s,%llu", a->text, m->text, (unsigned long long)value);
    NtX64Operand o[3] = {reg_operand(a), mem_operand(m), {0}};
    o[2].kind = NT_X64_IMM;
    o[2].imm = value;
    compare(i, "imul", body, o, 3, 1, 3);
}

/* imul is family 6 of the two-register dispatch AND the only family with a
 * third operand, so it is swept here rather than inside two_register_cases.
 * Every row is a row against the oracle on the SAME operands, which is the
 * witness this gate already uses: a lowerer that answered something else, or
 * refused a form the oracle accepts, is red by name and not by count. */
static void imul_cases(const NovaHostImage *i) {
    static const uint64_t imms[] = {0, 1, 127, 128, 255, 256, 2147483647u};
    for (unsigned a = 0; a < NREGS; a++)
        for (unsigned b = 0; b < NREGS; b++) { reg_pair(i, "imul", &regs[a], &regs[b], 1, 3); count_imul++; }
    for (unsigned a = 0; a < NREGS; a++)
        for (unsigned m = 0; m < NMEMS; m++) { reg_mem(i, "imul", &regs[a], &mems[m], 1, 3); count_imul++; }
    for (unsigned k = 0; k < sizeof imms / sizeof *imms; k++)
        for (unsigned b = 0; b < NREGS; b++) {
            reg_reg_imm(i, &regs[0], &regs[b], imms[k]); count_imul++;
            reg_mem_imm(i, &regs[0], &mems[0], imms[k]); count_imul++;
        }
    /* One NEGATIVE literal, on its own, because an NTASM negative literal is a
     * unary-minus node rather than a signed token: the sign has to survive the
     * parser for the compact 6B form to be reachable at all, and a sweep of
     * non-negative magnitudes above cannot see whether it does. */
    {
        char body[96];
        snprintf(body, sizeof body, "imul %s,%s,-1", regs[0].text, regs[1].text);
        NtX64Operand o[3] = {reg_operand(&regs[0]), reg_operand(&regs[1]), {0}};
        o[2].kind = NT_X64_IMM;
        o[2].imm = UINT64_MAX;
        o[2].is_signed = 1;
        compare(i, "imul", body, o, 3, 1, 3);
        count_imul++;
    }
}

/* bswap: one register, and the memory spelling. The memory rows are here on
 * purpose -- the oracle has no memory form for this mnemonic, so every one of
 * them is a refusal, and a lowerer that answered bytes for a memory operand
 * would be red by name rather than by count. This family reached the encoder
 * only because its own lowering branch was written; the imul rows below are
 * what proved that an export can exist and stay unreachable, and this is the
 * same instrument pointed at the next mnemonic. */
static void bswap_cases(const NovaHostImage *i) {
    for (unsigned a = 0; a < NREGS; a++) {
        NtX64Operand o = reg_operand(&regs[a]);
        one_operand(i, "bswap", regs[a].text, &o, 1, 3);
        count_bswap++;
    }
    for (unsigned m = 0; m < NMEMS; m++) {
        NtX64Operand o = mem_operand(&mems[m]);
        one_operand(i, "bswap", mems[m].text, &o, 1, 3);
        count_bswap++;
    }
}

/* mul, div and idiv: the F6/F7 digits 4, 6 and 7. They get their own sweep
 * rather than a line in the four unaries', because there are three names over
 * one frame and a sweep naming one would have measured the other two by
 * assumption. The memory rows are here because these three DO have a memory
 * form in the oracle, unlike bswap -- which is the difference the two sweeps
 * make visible. */
static void muldiv_cases(const NovaHostImage *i) {
    static const char *const mdiv[3] = {"mul", "div", "idiv"};
    for (unsigned n = 0; n < 3; n++)
        for (unsigned a = 0; a < NREGS; a++) {
            NtX64Operand o = reg_operand(&regs[a]);
            one_operand(i, mdiv[n], regs[a].text, &o, 1, 3);
            count_muldiv++;
        }
    for (unsigned n = 0; n < 3; n++)
        for (unsigned m = 0; m < NMEMS; m++) {
            NtX64Operand o = mem_operand(&mems[m]);
            one_operand(i, mdiv[n], mems[m].text, &o, 1, 3);
            count_muldiv++;
        }
}

/* bt, bts, btr and btc. The bit string may be a memory and the index may be a
 * register OR a literal, and those are two different instructions, so both are
 * swept. These rows go through the LOWERER, which is the point: a family the
 * export answers but no source can spell cannot pass here, and that is the
 * check that caught imul's dead encode_imul_three. */
static void bit_test_cases(const NovaHostImage *i) {
    static const char *const bits[4] = {"bt", "bts", "btr", "btc"};
    static const uint64_t offsets[] = {0, 1, 255};
    for (unsigned n = 0; n < 4; n++) {
        for (unsigned a = 0; a < NREGS; a++)
            for (unsigned b = 0; b < NREGS; b++) {
                char body[96];
                snprintf(body, sizeof body, "%s %s,%s", bits[n], regs[a].text, regs[b].text);
                NtX64Operand o[2] = {reg_operand(&regs[a]), reg_operand(&regs[b])};
                compare(i, bits[n], body, o, 2, 1, 3);
                count_bits++;
            }
        for (unsigned m = 0; m < NMEMS; m++)
            for (unsigned b = 0; b < NREGS; b++) {
                char body[128];
                snprintf(body, sizeof body, "%s %s,%s", bits[n], mems[m].text, regs[b].text);
                NtX64Operand o[2] = {mem_operand(&mems[m]), reg_operand(&regs[b])};
                compare(i, bits[n], body, o, 2, 1, 3);
                count_bits++;
            }
        for (unsigned a = 0; a < NREGS; a++)
            for (unsigned k = 0; k < 3; k++) {
                char body[96];
                snprintf(body, sizeof body, "%s %s,%llu", bits[n], regs[a].text,
                         (unsigned long long)offsets[k]);
                NtX64Operand o[2] = {reg_operand(&regs[a]), {0}};
                o[1].kind = NT_X64_IMM;
                o[1].imm = offsets[k];
                compare(i, bits[n], body, o, 2, 1, 3);
                count_bits++;
            }
    }
}

/* sgdt, sidt, lgdt and lidt: ONE memory operand whose access width the native
 * demands to be exactly 80 -- and NO machine scalar states 80, so every row here
 * is a REFUSAL. They are rows anyway: a gate that skipped the family would be
 * blind to all four names, and the refusal has to be the oracle's reason (403
 * on the width, or 405 on privilege) rather than the lowerer's convenience.
 * cpl is swept over BOTH levels because half the family is privileged, and a
 * sweep at one cpl cannot see that half at all -- a deleted privilege check
 * would leave a cpl-0-only sweep completely green. */
static void descriptor_cases(const NovaHostImage *i) {
    static const char *const desc[4] = {"sgdt", "sidt", "lgdt", "lidt"};
    for (unsigned n = 0; n < 4; n++)
        for (unsigned r = 0; r < 2; r++)
            for (unsigned m = 0; m < NMEMS; m++) {
                NtX64Operand o = mem_operand(&mems[m]);
                one_operand(i, desc[n], mems[m].text, &o, 1, r == 0 ? 3 : 0);
                count_desc++;
            }
}
static void two_register_cases(const NovaHostImage *i) {
    static const char *const cmovs[] = {"cmove", "cmovne", "cmovb", "cmovae", "cmovbe", "cmova",
                                        "cmovs", "cmovns", "cmovp", "cmovnp", "cmovl", "cmovge",
                                        "cmovle", "cmovg", "cmovo", "cmovno"};
    static const char *const setccs[] = {"sete", "setne", "setb", "setae", "setbe", "seta",
                                          "sets", "setns", "setp", "setnp", "setl", "setge",
                                          "setle", "setg", "seto", "setno"};
    static const char *const unaries[] = {"inc", "dec", "not", "neg"};
    static const char *const scans[] = {"bsf", "bsr"};
    static const char *const widens[] = {"movzx", "movsx"};

    /* ---- I26 xchg: register/register at every width and every high8 partner,
     * both memory directions, and every refusal the oracle states. ---- */
    {
        static const unsigned pairs[][2] = {
            {I_RAX, I_RBX},  {I_EAX, I_EBX}, {I_AX, I_BX},    {I_AL, I_BL},   {I_R8, I_R15},
            {I_R8D, I_R15D}, {I_R8W, I_R15W}, {I_R8B, I_R15B}, {I_RAX, I_RAX}, {I_RSP, I_RBP},
            {I_RSI, I_RDI},  {I_ECX, I_EDX},  {I_AL, I_AH},   {I_AH, I_CH},   {I_BH, I_DH},
            {I_CH, I_CL},    {I_SPL, I_AL},   {I_R8B, I_AL},  {I_SIL, I_BL},  {I_DL, I_BH},
            {I_AH, I_BPL},   {I_BH, I_R15B},
        };
        for (unsigned k = 0; k < sizeof pairs / sizeof *pairs; k++)
            reg_pair(i, "xchg", &regs[pairs[k][0]], &regs[pairs[k][1]], 1, 3);
        /* 408: a high8 operand next to a second register operand that forces
         * REX, the condition no single-register operand can reach. */
        static const unsigned conflict[][2] = {
            {I_AH, I_R8B}, {I_R8B, I_AH}, {I_CH, I_R9B}, {I_BH, I_R12B}, {I_R13B, I_DH},
        };
        for (unsigned k = 0; k < sizeof conflict / sizeof *conflict; k++)
            reg_pair(i, "xchg", &regs[conflict[k][0]], &regs[conflict[k][1]], 1, 3);
        static const unsigned mem_dst[] = {I_RAX, I_EAX, I_AX, I_AL};
        static const unsigned mem_of_dst[] = {0, 9, 10, 11};
        for (unsigned k = 0; k < 4; k++)
            reg_mem(i, "xchg", &regs[mem_dst[k]], &mems[mem_of_dst[k]], 1, 3);
        for (unsigned k = 0; k < 9; k++)
            reg_mem(i, "xchg", &regs[I_RAX], &mems[k], 1, 3);
        /* The memory destination the oracle refuses, and the width mismatches
         * it refuses on either operand. */
        mem_reg(i, "xchg", &mems[0], &regs[I_RAX], 1, 3);
        mem_reg(i, "xchg", &mems[9], &regs[I_EAX], 1, 3);
        reg_pair(i, "xchg", &regs[I_RAX], &regs[I_EBX], 1, 3);
        reg_pair(i, "xchg", &regs[I_EAX], &regs[I_RAX], 1, 3);
        reg_mem(i, "xchg", &regs[I_RAX], &mems[9], 1, 3);
        reg_mem(i, "xchg", &regs[I_RAX], &mems[8], 1, 3);
        reg_pair(i, "xchg", &regs[I_RAX], &regs[I_RBX], 0, 3);
        reg_pair(i, "xchg", &regs[I_RAX], &regs[I_RBX], 1, 4);
        {
            NtX64Operand o[2] = {{.kind = NT_X64_REG, .width = 64, .reg = 16},
                                 {.kind = NT_X64_REG, .width = 64, .reg = 3}};
            compare(i, "xchg", "xchg r16,rbx", o, 2, 1, 3);
            o[0] = (NtX64Operand){.kind = NT_X64_REG, .width = 64, .reg = 0};
            o[1] = (NtX64Operand){.kind = NT_X64_REG, .width = 64, .reg = 16};
            compare(i, "xchg", "xchg rax,r16", o, 2, 1, 3);
            o[1] = (NtX64Operand){.kind = NT_X64_REG, .width = 64, .reg = 0};
            o[0] = (NtX64Operand){.kind = NT_X64_REG, .width = 64, .reg = 16};
            compare(i, "xchg", "xchg r16,rax", o, 2, 1, 3);
            o[0] = (NtX64Operand){.kind = NT_X64_REG, .width = 64, .reg = 0};
            o[1] = (NtX64Operand){.kind = NT_X64_IMM, .imm = 1};
            compare(i, "xchg", "xchg rax,1", o, 2, 1, 3);
        }
        compare(i, "xchg", "xchg rax,foo",
                (NtX64Operand[2]){{.kind = NT_X64_REG, .width = 64, .reg = 0},
                                  {.kind = NT_X64_REG, .width = 64, .reg = 16}},
                2, 1, 3);
        compare(i, "xchg", "xchg foo,rax",
                (NtX64Operand[2]){{.kind = NT_X64_REG, .width = 64, .reg = 16},
                                  {.kind = NT_X64_REG, .width = 64, .reg = 0}},
                2, 1, 3);
        own(i, "xchg one operand", "xchg rax", 409);
        own(i, "xchg three operands", "xchg rax,rbx,rcx", 409);
        own(i, "xchg one memory operand", "xchg [rbx+8]:ptr<user,u64>", 409);
    }
    count_xchg = cases;

    /* ---- I22 cmov: the sixteen conditions in every legal direction, and the
     * four shapes every one of them refuses. ---- */
    for (unsigned n = 0; n < 16; n++) {
        reg_pair(i, cmovs[n], &regs[I_RAX], &regs[I_RBX], 1, 3);
        reg_pair(i, cmovs[n], &regs[I_EAX], &regs[I_EBX], 1, 3);
        reg_pair(i, cmovs[n], &regs[I_AX], &regs[I_BX], 1, 3);
        reg_pair(i, cmovs[n], &regs[I_R8], &regs[I_R15], 1, 3);
        reg_mem(i, cmovs[n], &regs[I_RAX], &mems[0], 1, 3);
        reg_mem(i, cmovs[n], &regs[I_EAX], &mems[9], 1, 3);
        reg_mem(i, cmovs[n], &regs[I_RAX], &mems[3], 1, 3);
        reg_mem(i, cmovs[n], &regs[I_RAX], &mems[7], 1, 3);
        reg_pair(i, cmovs[n], &regs[I_AL], &regs[I_BL], 1, 3);
        reg_pair(i, cmovs[n], &regs[I_AH], &regs[I_CH], 1, 3);
        reg_pair(i, cmovs[n], &regs[I_RAX], &regs[I_EBX], 1, 3);
        reg_mem(i, cmovs[n], &regs[I_RAX], &mems[9], 1, 3);
        mem_reg(i, cmovs[n], &mems[9], &regs[I_EAX], 1, 3);
    }
    own(i, "cmov one operand", "cmove rax", 409);
    own(i, "cmov three operands", "cmove rax,rbx,rcx", 409);
    reg_pair(i, "cmovq", &regs[I_RAX], &regs[I_RBX], 1, 3);
    reg_pair(i, "cmove", &regs[I_RAX], &regs[I_RBX], 0, 3);
    reg_pair(i, "cmove", &regs[I_RAX], &regs[I_RBX], 1, 4);
    count_cmov = cases - count_xchg;

    /* ---- I25 bsf/bsr: register and memory sources, width 16/32/64 only. ---- */
    for (unsigned n = 0; n < 2; n++) {
        static const unsigned pairs[][2] = {
            {I_RAX, I_RBX}, {I_EAX, I_EBX}, {I_AX, I_BX},   {I_R8, I_R15},
            {I_R8D, I_R15D}, {I_R12, I_R13}, {I_RSI, I_RDI}, {I_RAX, I_RAX},
        };
        for (unsigned k = 0; k < sizeof pairs / sizeof *pairs; k++)
            reg_pair(i, scans[n], &regs[pairs[k][0]], &regs[pairs[k][1]], 1, 3);
        for (unsigned k = 0; k < 9; k++)
            reg_mem(i, scans[n], &regs[I_R8], &mems[k], 1, 3);
        reg_mem(i, scans[n], &regs[I_EAX], &mems[9], 1, 3);
        reg_mem(i, scans[n], &regs[I_AX], &mems[10], 1, 3);
        reg_pair(i, scans[n], &regs[I_AL], &regs[I_BL], 1, 3);
        reg_pair(i, scans[n], &regs[I_AH], &regs[I_CL], 1, 3);
        reg_pair(i, scans[n], &regs[I_RAX], &regs[I_EBX], 1, 3);
        mem_reg(i, scans[n], &mems[0], &regs[I_RAX], 1, 3);
        reg_pair(i, scans[n], &regs[I_RAX], &regs[I_RBX], 0, 3);
        own(i, "bsf one operand", "bsf rax", 409);
        own(i, "bsf three operands", "bsf rax,rbx,rcx", 409);
    }
    reg_pair(i, "bsz", &regs[I_RAX], &regs[I_RBX], 1, 3);
    count_scan = cases - count_xchg - count_cmov;

    /* ---- I05/I06/I07 movzx/movsx/movsxd: every legal width pair in both
     * source kinds, every high8 source, and every illegal pair. ---- */
    for (unsigned n = 0; n < 2; n++) {
        static const unsigned legal[][2] = {
            {I_AX, I_AL},   {I_R8W, I_CL},  {I_AX, I_SPL},   {I_R8W, I_R9B}, {I_R8W, I_R15B},
            {I_EAX, I_AL},  {I_EAX, I_CL},  {I_EAX, I_SPL},  {I_EAX, I_R9B}, {I_EAX, I_R15B},
            {I_EAX, I_AX},  {I_EAX, I_BX},  {I_EAX, I_R9W},  {I_EAX, I_R13W},
            {I_RAX, I_AL},  {I_RAX, I_CL},  {I_RAX, I_SPL},  {I_RAX, I_R9B}, {I_RAX, I_R15B},
            {I_RAX, I_AX},  {I_RAX, I_BX},  {I_RAX, I_R9W},  {I_RAX, I_R13W},
            {I_R8D, I_AL},  {I_R8D, I_R15B}, {I_R8D, I_AX},  {I_R8D, I_R9W},
            {I_R8, I_AL},   {I_R8, I_R15B}, {I_R8, I_AX},   {I_R8, I_R13W},
        };
        for (unsigned k = 0; k < sizeof legal / sizeof *legal; k++)
            reg_pair(i, widens[n], &regs[legal[k][0]], &regs[legal[k][1]], 1, 3);
        reg_mem(i, widens[n], &regs[I_AX], &mems[11], 1, 3);
        reg_mem(i, widens[n], &regs[I_EAX], &mems[11], 1, 3);
        reg_mem(i, widens[n], &regs[I_RAX], &mems[11], 1, 3);
        reg_mem(i, widens[n], &regs[I_RAX], &mems[10], 1, 3);
        reg_mem(i, widens[n], &regs[I_R8D], &mems[10], 1, 3);
        reg_mem(i, widens[n], &regs[I_EAX], &mems[7], 1, 3);
        reg_mem(i, widens[n], &regs[I_RAX], &mems[3], 1, 3);
        static const unsigned high8[] = {I_AH, I_CH, I_DH, I_BH};
        for (unsigned k = 0; k < 4; k++) {
            reg_pair(i, widens[n], &regs[I_AX], &regs[high8[k]], 1, 3);
            reg_pair(i, widens[n], &regs[I_EAX], &regs[high8[k]], 1, 3);
            reg_pair(i, widens[n], &regs[I_RAX], &regs[high8[k]], 1, 3);
            reg_pair(i, widens[n], &regs[I_R8D], &regs[high8[k]], 1, 3);
            reg_pair(i, widens[n], &regs[I_R8], &regs[high8[k]], 1, 3);
        }
        static const unsigned bad_dst[] = {I_AL, I_AX, I_R8W, I_EAX, I_RAX, I_R8D};
        static const unsigned bad_src[] = {I_AL, I_CL, I_AX, I_BX, I_EAX, I_RAX};
        for (unsigned k = 0; k < 6; k++)
            for (unsigned m = 0; m < 6; m++)
                reg_pair(i, widens[n], &regs[bad_dst[k]], &regs[bad_src[m]], 1, 3);
        mem_reg(i, widens[n], &mems[9], &regs[I_EAX], 1, 3);
        mem_reg(i, widens[n], &mems[0], &regs[I_RAX], 1, 3);
        reg_pair(i, widens[n], &regs[I_RAX], &regs[I_RBX], 0, 3);
        reg_pair(i, widens[n], &regs[I_RAX], &regs[I_RBX], 1, 4);
        own(i, "movzx one operand", "movzx eax", 409);
        own(i, "movzx three operands", "movzx eax,al,cl", 409);
    }
    /* An unknown two-operand mnemonic of equal width reaches encode_rr and is
     * refused as the unknown mnemonic, which is the oracle answer. The
     * unequal-width spelling of the same mnemonic is answered by the width
     * rule of that path before any mnemonic test, a pre-existing hole of the
     * register/register path that is outside this lot: the code is stated here
     * rather than compared, and the divergence is reported as a remaining
     * limit. */
    reg_pair(i, "movzbw", &regs[I_EAX], &regs[I_EBX], 1, 3);
    own(i, "unknown mnemonic unequal widths", "movzbw eax,al", 403);
    {
        static const unsigned src32[] = {I_EAX, I_EBX, I_R8D, I_R9D, I_R15D};
        static const unsigned dst64[] = {I_RAX, I_R8, I_R12, I_R15, I_RSP};
        for (unsigned k = 0; k < 5; k++)
            reg_pair(i, "movsxd", &regs[I_RAX], &regs[src32[k]], 1, 3);
        for (unsigned k = 0; k < 5; k++)
            reg_pair(i, "movsxd", &regs[dst64[k]], &regs[I_EAX], 1, 3);
        for (unsigned k = 0; k < 9; k++)
            reg_mem(i, "movsxd", &regs[I_RAX], &mems[k], 1, 3);
        static const unsigned bad_dst[] = {I_AL, I_AX, I_EAX, I_R8D, I_R8W};
        static const unsigned bad_src[] = {I_AL, I_AX, I_EAX, I_RAX, I_R8D};
        for (unsigned k = 0; k < 5; k++)
            for (unsigned m = 0; m < 5; m++)
                reg_pair(i, "movsxd", &regs[bad_dst[k]], &regs[bad_src[m]], 1, 3);
        reg_pair(i, "movsxd", &regs[I_RAX], &regs[I_EAX], 0, 3);
        mem_reg(i, "movsxd", &mems[0], &regs[I_EAX], 1, 3);
    }
    count_convert = cases - count_xchg - count_cmov - count_scan;

    /* ---- I09 test: register/register, memory/register, the 408 both
     * directions reach, and the register-memory spelling the oracle refuses. ---- */
    {
        static const unsigned pairs[][2] = {
            {I_RAX, I_RBX},  {I_EAX, I_EBX}, {I_AX, I_BX},    {I_AL, I_BL},   {I_R8, I_R15},
            {I_R8D, I_R15D}, {I_R8W, I_R15W}, {I_R8B, I_R15B}, {I_RAX, I_RAX}, {I_RSP, I_RBP},
            {I_AL, I_AH},    {I_AH, I_CH},   {I_BH, I_DH},   {I_SPL, I_AL},  {I_SIL, I_BL},
        };
        for (unsigned k = 0; k < sizeof pairs / sizeof *pairs; k++)
            reg_pair(i, "test", &regs[pairs[k][0]], &regs[pairs[k][1]], 1, 3);
        for (unsigned k = 0; k < 9; k++)
            mem_reg(i, "test", &mems[k], &regs[I_RAX], 1, 3);
        mem_reg(i, "test", &mems[9], &regs[I_EAX], 1, 3);
        mem_reg(i, "test", &mems[10], &regs[I_AX], 1, 3);
        mem_reg(i, "test", &mems[11], &regs[I_AL], 1, 3);
        mem_reg(i, "test", &mems[3], &regs[I_R12], 1, 3);
        mem_reg(i, "test", &mems[7], &regs[I_R8], 1, 3);
        static const unsigned high8[] = {I_AH, I_CH, I_DH, I_BH};
        for (unsigned k = 0; k < 4; k++) {
            reg_pair(i, "test", &regs[high8[k]], &regs[I_R8B], 1, 3);
            reg_pair(i, "test", &regs[high8[k]], &regs[I_SPL], 1, 3);
            mem_reg(i, "test", &mems[0], &regs[high8[k]], 1, 3);
            mem_reg(i, "test", &mems[3], &regs[high8[k]], 1, 3);
        }
        reg_pair(i, "test", &regs[I_RAX], &regs[I_EBX], 1, 3);
        reg_pair(i, "test", &regs[I_EAX], &regs[I_RAX], 1, 3);
        reg_mem(i, "test", &regs[I_RAX], &mems[9], 1, 3);
        reg_mem(i, "test", &regs[I_RAX], &mems[0], 1, 3);
        mem_reg(i, "test", &mems[0], &regs[I_EBX], 1, 3);
        reg_pair(i, "test", &regs[I_RAX], &regs[I_RBX], 0, 3);
        reg_pair(i, "test", &regs[I_RAX], &regs[I_RBX], 1, 4);
        own(i, "test one operand", "test rax", 409);
        own(i, "test three operands", "test rax,rbx,rcx", 409);
    }
    count_test = cases - count_xchg - count_cmov - count_scan - count_convert;

    /* ---- the one-operand forms: inc/dec/not/neg, push/pop and setcc. ---- */
    {
        static const unsigned unary_dst[] = {I_RAX, I_EAX, I_AX, I_AL, I_R8,  I_R8D,  I_R8W,
                                             I_R8B, I_RSP, I_SPL, I_SIL, I_R12, I_R12D, I_RSP};
        for (unsigned n = 0; n < 4; n++)
            for (unsigned k = 0; k < sizeof unary_dst / sizeof *unary_dst; k++) {
                const Reg *r = &regs[unary_dst[k]];
                char body[64];
                snprintf(body, sizeof body, "%s %s", unaries[n], r->text);
                NtX64Operand o[1] = {reg_operand(r)};
                compare(i, unaries[n], body, o, 1, 1, 3);
            }
        static const unsigned stack_dst[] = {I_RAX, I_R8, I_R15, I_RSP, I_RBX, I_R12, I_R9};
        for (unsigned k = 0; k < sizeof stack_dst / sizeof *stack_dst; k++) {
            const Reg *r = &regs[stack_dst[k]];
            char body[64];
            NtX64Operand o[1] = {reg_operand(r)};
            snprintf(body, sizeof body, "push %s", r->text);
            compare(i, "push", body, o, 1, 1, 3);
            snprintf(body, sizeof body, "pop %s", r->text);
            compare(i, "pop", body, o, 1, 1, 3);
        }
        static const uint64_t immediates[] = {0, 1, 127, 128, 255, 256};
        for (unsigned k = 0; k < sizeof immediates / sizeof *immediates; k++) {
            char body[64];
            NtX64Operand o[1] = {{.kind = NT_X64_IMM, .imm = immediates[k]}};
            snprintf(body, sizeof body, "push %llu", (unsigned long long)immediates[k]);
            compare(i, "push", body, o, 1, 1, 3);
            snprintf(body, sizeof body, "pop %llu", (unsigned long long)immediates[k]);
            compare(i, "pop", body, o, 1, 1, 3);
        }
        static const unsigned narrow[] = {I_EAX, I_AX, I_AL, I_R8D, I_R8W, I_R8B};
        for (unsigned k = 0; k < sizeof narrow / sizeof *narrow; k++) {
            const Reg *r = &regs[narrow[k]];
            char body[64];
            NtX64Operand o[1] = {reg_operand(r)};
            snprintf(body, sizeof body, "push %s", r->text);
            compare(i, "push", body, o, 1, 1, 3);
            snprintf(body, sizeof body, "pop %s", r->text);
            compare(i, "pop", body, o, 1, 1, 3);
        }
        static const unsigned setcc_dst[] = {I_AL, I_CL, I_SPL, I_R8B, I_DL, I_SIL, I_R15B, I_BPL};
        for (unsigned n = 0; n < 16; n++)
            for (unsigned k = 0; k < sizeof setcc_dst / sizeof *setcc_dst; k++) {
                const Reg *r = &regs[setcc_dst[k]];
                char body[64];
                snprintf(body, sizeof body, "%s %s", setccs[n], r->text);
                NtX64Operand o[1] = {reg_operand(r)};
                compare(i, setccs[n], body, o, 1, 1, 3);
            }
        static const unsigned setcc_wide[] = {I_EAX, I_AX, I_RAX, I_R8D, I_R8W};
        for (unsigned k = 0; k < sizeof setcc_wide / sizeof *setcc_wide; k++) {
            const Reg *r = &regs[setcc_wide[k]];
            char body[64];
            NtX64Operand o[1] = {reg_operand(r)};
            snprintf(body, sizeof body, "sete %s", r->text);
            compare(i, "sete", body, o, 1, 1, 3);
        }
        /* The high8 alias of the same two families, over the four byte registers
         * that exist without a REX prefix. The oracle operand carries the high8
         * bit, so the ModRM.rm regcode and the REX-free frame are the oracle's
         * and not the producer's: one unresolved flag is one wrong byte. */
        {
            static const unsigned high8_regs[] = {I_AH, I_CH, I_DH, I_BH};
            for (unsigned n = 0; n < 4; n++)
                for (unsigned k = 0; k < 4; k++) {
                    const Reg *r = &regs[high8_regs[k]];
                    char body[64];
                    NtX64Operand o[1] = {reg_operand(r)};
                    snprintf(body, sizeof body, "%s %s", unaries[n], r->text);
                    compare(i, unaries[n], body, o, 1, 1, 3);
                }
            for (unsigned n = 0; n < 16; n++)
                for (unsigned k = 0; k < 4; k++) {
                    const Reg *r = &regs[high8_regs[k]];
                    char body[64];
                    NtX64Operand o[1] = {reg_operand(r)};
                    snprintf(body, sizeof body, "%s %s", setccs[n], r->text);
                    compare(i, setccs[n], body, o, 1, 1, 3);
                }
        }
        /* The memory direction of the unaries: the access width is read out of
         * the pointer element type, so all four widths of the address grammar
         * are legal rows. The nine 64 bit addresses of the table carry the
         * SIB, the RIP, the negative and the fs/gs forms the two-register
         * families already exercise. */
        {
            static const unsigned every_mem[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
            for (unsigned n = 0; n < 4; n++)
                for (unsigned k = 0; k < sizeof every_mem / sizeof *every_mem; k++) {
                    const Mem *m = &mems[every_mem[k]];
                    char body[128];
                    NtX64Operand o[1] = {mem_operand(m)};
                    snprintf(body, sizeof body, "%s %s", unaries[n], m->text);
                    compare(i, unaries[n], body, o, 1, 1, 3);
                }
        }
        /* push and pop take a memory operand at 64 bits only, so the nine 64 bit
         * addresses are parity rows and the three narrower ones are the oracle
         * refusal the export states as 403. The width 32 the oracle hands to
         * modrm for this direction, and the REX.W byte the access width would
         * otherwise force, are reproduced by the export and pinned here. */
        for (unsigned k = 0; k < NMEMS; k++) {
            const Mem *m = &mems[k];
            char body[128];
            NtX64Operand o[1] = {mem_operand(m)};
            snprintf(body, sizeof body, "push %s", m->text);
            compare(i, "push", body, o, 1, 1, 3);
            snprintf(body, sizeof body, "pop %s", m->text);
            compare(i, "pop", body, o, 1, 1, 3);
        }
        /* setcc states width 8 to modrm whatever the operand is, so the memory
         * direction is an 8 bit address for every condition and a 403 for every
         * other width. Both halves are compared, never stated. */
        for (unsigned n = 0; n < 16; n++) {
            char body[128];
            NtX64Operand o[1] = {mem_operand(&mems[11])};
            snprintf(body, sizeof body, "%s %s", setccs[n], mems[11].text);
            compare(i, setccs[n], body, o, 1, 1, 3);
        }
        for (unsigned k = 0; k < 4; k++) {
            char body[128];
            NtX64Operand o[1] = {mem_operand(&mems[k])};
            snprintf(body, sizeof body, "sete %s", mems[k].text);
            compare(i, "sete", body, o, 1, 1, 3);
        }
        /* The context rules of the three new branches, still compared against
         * the oracle answer and never against a number written here. */
        {
            NtX64Operand wide[1] = {mem_operand(&mems[0])};
            NtX64Operand narrow[1] = {mem_operand(&mems[11])};
            NtX64Operand alias[1] = {reg_operand(&regs[I_AH])};
            one_operand(i, "inc", mems[0].text, wide, 0, 3);
            one_operand(i, "inc", mems[0].text, wide, 1, 4);
            one_operand(i, "sete", mems[11].text, narrow, 0, 3);
            one_operand(i, "push", mems[0].text, wide, 0, 3);
            one_operand(i, "pop", mems[0].text, wide, 1, 4);
            one_operand(i, "inc", regs[I_AH].text, alias, 0, 3);
            one_operand(i, "sete", regs[I_AH].text, alias, 1, 4);
        }
        for (unsigned k = 0; k < 3; k++) {
            const char *spelling = (const char *[]){"sete", "inc", "push"}[k];
            const char *body = (const char *[]){"sete r16", "inc r16", "push r16"}[k];
            NtX64Operand o[1] = {{.kind = NT_X64_REG, .width = 8, .reg = 16}};
            compare(i, spelling, body, o, 1, 1, 3);
        }
        /* A mnemonic the register/register path does not own answers 401 there:
         * the two-operand form of a one-operand mnemonic never reaches an
         * oracle call, so the code is the lowerer's own. */
        own(i, "unary with two operands", "neg rax,rbx", 401);
        own(i, "setcc with two operands", "sete al,bl", 401);
        own(i, "push with two operands", "push rax,rbx", 401);
    }
    count_one = cases - count_xchg - count_cmov - count_scan - count_convert - count_test;
    /* The coverage this gate is required to carry, checked on its own counts. */
    CHECK(count_xchg >= 25, "xchg cases");
    CHECK(count_cmov >= 40, "cmov cases");
    CHECK(count_scan >= 20, "bsf/bsr cases");
    CHECK(count_convert >= 35, "movzx/movsx/movsxd cases");
    CHECK(count_test >= 20, "test cases");
    CHECK(count_one >= 8, "one-operand cases");
    /* The high8 and memory shapes of the one-operand group are what this lot
     * added, so the floor is the one-operand count with those rows included: a
     * silent removal of any of them turns the gate red. */
    CHECK(count_one >= 360, "one-operand high8 and memory cases");
}

int main(void) {
    const char *paths[] = {"tests/nova/tests/x64-lower-two-reg-entry.nova",
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
    if (image.memory) two_register_cases(&image);
    if (image.memory) imul_cases(&image);
    if (image.memory) bswap_cases(&image);
    if (image.memory) muldiv_cases(&image);
    if (image.memory) bit_test_cases(&image);
    if (image.memory) descriptor_cases(&image);
    if (image.memory) nova_host_unmap(&image);
    if (compiled) nt_artifact_free(&a);
    for (unsigned k = 0; k < 7; k++) free(sources[k]);
    printf("NTASM_NOVA_X64_LOWER_TWO_REG xchg=%u cmov=%u bsf_bsr=%u convert=%u test=%u one_operand=%u imul=%u\n",
           count_xchg, count_cmov, count_scan, count_convert, count_test, count_one, count_imul);
    printf("bswap=%u\n", count_bswap);
    printf("mul_div_idiv=%u\n", count_muldiv);
    printf("bit_test=%u\n", count_bits);
    printf("descriptor=%u\n", count_desc);
    printf("NTASM_NOVA_X64_LOWER_TWO_REG checks=%u failures=%u cases=%u\n", checks, failures, cases);
    return failures ? 1 : 0;
}
