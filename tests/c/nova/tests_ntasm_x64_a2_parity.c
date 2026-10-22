/* NTASM A2 parity corpus: source text to bytes, against the native oracle
 * nt_x64_encode, byte for byte.
 *
 * One descriptor per case, and BOTH halves of the case are generated from it.
 * The native operands go to nt_x64_encode; the same operands are printed as an
 * NTASM statement and go through the Nova parser and
 * x64_lower_fixed.encode_instruction. There is no hand-written source text and
 * no hand-written oracle operand for the same case, so the two paths cannot
 * drift apart in their operand and neither can carry a width the other does
 * not have. That is the defect this lot exists to not repeat: an earlier
 * harness drove a width-80 memory descriptor with a u64 source and compared
 * that run against an oracle built from a register.
 *
 * The oracle decides. A case states, when it must, that the oracle ACCEPTS
 * (must_encode) or that it refuses with one named diagnostic (want_code), so a
 * negative row cannot pass by turning into a positive one. On acceptance the
 * bytes are compared; on refusal the diagnostic is compared and out is required
 * untouched. Rows the oracle accepts but the lowerer cannot express are
 * reported as named gaps rather than hidden, and a gap that stops being a gap
 * is a failure naming itself.
 *
 * The A2 surface: high8 operands, immediates that do not fit and then some
 * that do, memory in both directions, test and shift immediates, conversions
 * and three-operand imul, control registers including the refused cr5, in/out
 * with an immediate port and with dx, ltr/invlpg, the four descriptor forms
 * with ptr<user,array<u8,10>>, and the refusals a source spelling earns for
 * itself. */
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

/* Fingerprint of a module text, printed in the banner so a counter read here
 * names the bytes it was measured on. FNV-1a/64, offset basis, no library. */
static uint64_t fingerprint(const char *p, size_t n) {
    uint64_t h = UINT64_C(14695981039346656037);
    for (size_t i = 0; i < n; i++) { h ^= (unsigned char)p[i]; h *= UINT64_C(1099511628211); }
    return h;
}

typedef struct { uint64_t returned, runtime; uint8_t out[64]; } Run;

/* One statement inside an otherwise empty body, so the only statement node in
 * the tree is the instruction of the case and the entry can refuse a body that
 * carries a second one. */
static Run run(const NovaHostImage *i, const char *statement, uint32_t features, unsigned cpl) {
    char source[1024];
    int n = snprintf(source, sizeof source,
                     "module m\ntarget x86_64-nexora-none\nsection .text {\n"
                     "fn f()->u64\neffects {}\nclobbers {} {\n%s\nreturn 0\n}\n}\n",
                     statement);
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

/* Register spellings by encoding number: 0 is the first argument register, 4
 * is rsp and 4..7 have no r/m forms below rsp. */
static const char *const R64[16] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                                    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"};
static const char *const R32[16] = {"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
                                    "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"};
static const char *const R16[16] = {"ax", "cx", "dx", "bx", "sp", "bp", "si", "di",
                                    "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w"};
static const char *const R8[16] = {"al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil",
                                   "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b"};
static const char *const HIGH8[4] = {"ah", "ch", "dh", "bh"};

static const char *regname(unsigned reg, unsigned width, unsigned high8) {
    if (high8) return HIGH8[reg & 3u];
    switch (width) {
    case 8: return R8[reg & 15u];
    case 16: return R16[reg & 15u];
    case 32: return R32[reg & 15u];
    default: return R64[reg & 15u];
    }
}

/* The pointer element a memory operand's access width is spelled with. Only a
 * descriptor form has no machine scalar to name it, and it says so. */
static const char *element(unsigned width) {
    switch (width) {
    case 8: return "u8";
    case 16: return "u16";
    case 32: return "u32";
    case 64: return "u64";
    default: return "array<u8,10>";
    }
}

/* Print one operand as the source spells it. The address is written from the
 * same fields the oracle reads: a 64-bit base by name, rip by name, an index
 * with its scale, and a displacement with its own sign. A descriptor with no
 * base has no spelling on this path at all, so it is written as the bare
 * displacement the native descriptor would carry. */
static size_t spell(char *dst, size_t cap, const NtX64Operand *o, const char *space) {
    if (o->kind == NT_X64_REG) return (size_t)snprintf(dst, cap, "%s", regname(o->reg, o->width, o->high8));
    if (o->kind == NT_X64_CR) return (size_t)snprintf(dst, cap, "cr%u", o->reg);
    if (o->kind == NT_X64_IMM) {
        if (o->is_signed)
            return (size_t)snprintf(dst, cap, "-%llu", (unsigned long long)(0u - o->imm));
        return (size_t)snprintf(dst, cap, "%llu", (unsigned long long)o->imm);
    }
    char expr[256];
    size_t n = 0;
    if (o->segment == NT_X64_FS) n += (size_t)snprintf(expr + n, sizeof expr - n, "fs:");
    else if (o->segment == NT_X64_GS) n += (size_t)snprintf(expr + n, sizeof expr - n, "gs:");
    if (o->base == -2) n += (size_t)snprintf(expr + n, sizeof expr - n, "rip");
    else if (o->base >= 0) n += (size_t)snprintf(expr + n, sizeof expr - n, "%s", R64[o->base & 15u]);
    if (o->index >= 0) n += (size_t)snprintf(expr + n, sizeof expr - n, "+%s*%u", R64[o->index & 15u], o->scale);
    if (o->disp > 0) n += (size_t)snprintf(expr + n, sizeof expr - n, "+%lld", (long long)o->disp);
    else if (o->disp < 0) n += (size_t)snprintf(expr + n, sizeof expr - n, "%lld", (long long)o->disp);
    return (size_t)snprintf(dst, cap, "[%s]:ptr<%s,%s>", expr, space, element(o->width));
}

static size_t spell_case(char *dst, size_t cap, const char *mnemonic, const NtX64Operand *o,
                         unsigned count, const char *space) {
    size_t n = (size_t)snprintf(dst, cap, "%s ", mnemonic);
    for (unsigned i = 0; i < count; i++) {
        if (i) n += (size_t)snprintf(dst + n, cap - n, "%s", ",");
        n += spell(dst + n, cap - n, &o[i], space);
    }
    return n;
}

/* One case. want_code is the diagnostic the native oracle must answer, zero
 * when the row asserts nothing about the verdict; must_encode says the oracle
 * must accept, so a refusal row cannot pass as an acceptance. */
typedef struct {
    const char *name;
    const char *mnemonic;
    unsigned count;
    NtX64Operand o[3];
    uint32_t features;
    unsigned cpl;
    unsigned want_code;
    unsigned must_encode;
    const char *space;
} Case;

#define OP_REG(w, r, h) {.kind = NT_X64_REG, .width = (w), .reg = (r), .high8 = (h)}
#define OP_CR(r) {.kind = NT_X64_CR, .width = 64, .reg = (r)}
#define OP_IMM(v, s) {.kind = NT_X64_IMM, .imm = (v), .is_signed = (s)}
#define OP_MEM(w, b, i, s, d) {.kind = NT_X64_MEM, .width = (w), .base = (b), .index = (i), .scale = (s), .disp = (d)}
#define OP_MEMS(w, b, i, s, d, g) {.kind = NT_X64_MEM, .width = (w), .base = (b), .index = (i), .scale = (s), .disp = (d), .segment = (g)}
/* ---- A2 corpus. One row per operand shape; the name is what a red line
 * prints, so it names the shape and never the expectation. ---- */
static const Case corpus[] = {
    /* high8: a register with no r/m form, beside another and beside an
     * immediate, in the group1 and the shift frames. */
    {"high8.mov_ah_bh", "mov", 2, {OP_REG(8, 0, 1), OP_REG(8, 3, 1)}, 1, 3, 0, 1, "user"},
    {"high8.mov_ah_al", "mov", 2, {OP_REG(8, 0, 1), OP_REG(8, 0, 1)}, 1, 3, 0, 1, "user"},
    {"high8.mov_ch_dl", "mov", 2, {OP_REG(8, 1, 1), OP_REG(8, 2, 1)}, 1, 3, 0, 1, "user"},
    {"high8.mov_al_ah", "mov", 2, {OP_REG(8, 0, 0), OP_REG(8, 0, 1)}, 1, 3, 0, 1, "user"},
    {"high8.mov_ah_to_bh", "mov", 2, {OP_REG(8, 3, 1), OP_REG(8, 0, 1)}, 1, 3, 0, 1, "user"},
    {"high8.add_ah_1", "add", 2, {OP_REG(8, 0, 1), OP_IMM(1, 0)}, 1, 3, 0, 1, "user"},
    {"high8.add_bh_neg1", "add", 2, {OP_REG(8, 3, 1), OP_IMM(UINT64_MAX, 1)}, 1, 3, 0, 1, "user"},
    {"high8.sub_ch_127", "sub", 2, {OP_REG(8, 1, 1), OP_IMM(127, 0)}, 1, 3, 0, 1, "user"},
    {"high8.mov_dh_255", "mov", 2, {OP_REG(8, 2, 1), OP_IMM(255, 0)}, 1, 3, 0, 1, "user"},
    {"high8.mov_ah_neg1", "mov", 2, {OP_REG(8, 0, 1), OP_IMM(UINT64_MAX, 1)}, 1, 3, 0, 1, "user"},
    {"high8.xor_ah_neg1", "xor", 2, {OP_REG(8, 0, 1), OP_IMM(UINT64_MAX, 1)}, 1, 3, 0, 1, "user"},
    {"high8.test_ah_ah", "test", 2, {OP_REG(8, 0, 1), OP_REG(8, 0, 1)}, 1, 3, 0, 1, "user"},
    {"high8.shl_ah_1", "shl", 2, {OP_REG(8, 0, 1), OP_IMM(1, 0)}, 1, 3, 0, 1, "user"},
    {"high8.shl_ah_cl", "shl", 2, {OP_REG(8, 0, 1), OP_REG(8, 1, 0)}, 1, 3, 0, 1, "user"},
    {"high8.rol_dl_3", "rol", 2, {OP_REG(8, 2, 1), OP_IMM(3, 0)}, 1, 3, 0, 1, "user"},
    /* immediates: -1 and the width boundaries, one accepted and one refused
     * on each side of every edge the native states. */
    {"imm.mov_eax_neg1", "mov", 2, {OP_REG(32, 0, 0), OP_IMM(UINT64_MAX, 1)}, 1, 3, 0, 1, "user"},
    {"imm.mov_rax_neg1", "mov", 2, {OP_REG(64, 0, 0), OP_IMM(UINT64_MAX, 1)}, 1, 3, 0, 1, "user"},
    {"imm.mov_al_neg1", "mov", 2, {OP_REG(8, 0, 0), OP_IMM(UINT64_MAX, 1)}, 1, 3, 0, 1, "user"},
    {"imm.mov_ax_neg1", "mov", 2, {OP_REG(16, 0, 0), OP_IMM(UINT64_MAX, 1)}, 1, 3, 0, 1, "user"},
    {"imm.mov_eax_int32max", "mov", 2, {OP_REG(32, 0, 0), OP_IMM(2147483647u, 0)}, 1, 3, 0, 1, "user"},
    {"imm.mov_eax_int32min", "mov", 2, {OP_REG(32, 0, 0), OP_IMM(0xFFFFFFFF80000000ull, 1)}, 1, 3, 0, 1, "user"},
    {"imm.mov_eax_over32", "mov", 2, {OP_REG(32, 0, 0), OP_IMM(2147483648u, 0)}, 1, 3, 0, 1, "user"},
    {"imm.mov_eax_over_u32", "mov", 2, {OP_REG(32, 0, 0), OP_IMM(4294967296ull, 0)}, 1, 3, NT_X64_RANGE, 0, "user"},
    {"imm.mov_al_255", "mov", 2, {OP_REG(8, 0, 0), OP_IMM(255, 0)}, 1, 3, 0, 1, "user"},
    {"imm.mov_al_256", "mov", 2, {OP_REG(8, 0, 0), OP_IMM(256, 0)}, 1, 3, NT_X64_RANGE, 0, "user"},
    {"imm.mov_al_neg128", "mov", 2, {OP_REG(8, 0, 0), OP_IMM(0xFFFFFFFFFFFFFF80ull, 1)}, 1, 3, 0, 1, "user"},
    {"imm.mov_al_neg129", "mov", 2, {OP_REG(8, 0, 0), OP_IMM(0xFFFFFFFFFFFFFF7Full, 1)}, 1, 3, NT_X64_RANGE, 0, "user"},
    {"imm.mov_eax_neg1_high", "mov", 2, {OP_REG(32, 11, 0), OP_IMM(UINT64_MAX, 1)}, 1, 3, 0, 1, "user"},
    {"imm.add_rax_neg1", "add", 2, {OP_REG(64, 0, 0), OP_IMM(UINT64_MAX, 1)}, 1, 3, 0, 1, "user"},
    {"imm.add_rax_int32max", "add", 2, {OP_REG(64, 0, 0), OP_IMM(2147483647u, 0)}, 1, 3, 0, 1, "user"},
    {"imm.add_rax_over32", "add", 2, {OP_REG(64, 0, 0), OP_IMM(2147483648u, 0)}, 1, 3, NT_X64_RANGE, 0, "user"},
    {"imm.add_rax_neg_int32min", "add", 2, {OP_REG(64, 0, 0), OP_IMM(0xFFFFFFFF80000000ull, 1)}, 1, 3, 0, 1, "user"},
    {"imm.add_rax_nonzero", "add", 2, {OP_REG(64, 1, 0), OP_IMM(UINT64_MAX, 1)}, 1, 3, 0, 1, "user"},
    {"imm.add_eax_32767", "add", 2, {OP_REG(32, 0, 0), OP_IMM(32767, 0)}, 1, 3, 0, 1, "user"},
    {"imm.add_ax_32768", "add", 2, {OP_REG(16, 0, 0), OP_IMM(32768, 0)}, 1, 3, 0, 1, "user"},
    {"imm.add_ax_over16", "add", 2, {OP_REG(16, 0, 0), OP_IMM(65536, 0)}, 1, 3, NT_X64_RANGE, 0, "user"},
    {"imm.cmp_mem_u32_100", "cmp", 2, {OP_MEM(32, 3, -1, 1, 0), OP_IMM(100, 0)}, 1, 3, 0, 1, "user"},
    {"imm.add_mem_u8_200", "add", 2, {OP_MEM(8, 3, -1, 1, 0), OP_IMM(200, 0)}, 1, 3, 0, 1, "user"},
    {"imm.mov_mem_u8_5", "mov", 2, {OP_MEM(8, 3, -1, 1, 0), OP_IMM(5, 0)}, 1, 3, 0, 1, "user"},
    {"imm.mov_mem_u16_4095", "mov", 2, {OP_MEM(16, 3, 1, 1, 8), OP_IMM(4095, 0)}, 1, 3, 0, 1, "user"},
    {"imm.mov_mem_u32_int32max", "mov", 2, {OP_MEM(32, 3, -1, 1, 0), OP_IMM(2147483647u, 0)}, 1, 3, 0, 1, "user"},
    {"imm.mov_mem_u64_neg1", "mov", 2, {OP_MEM(64, 3, -1, 1, 0), OP_IMM(UINT64_MAX, 1)}, 1, 3, 0, 1, "user"},
    {"imm.mov_mem_u64_int32max", "mov", 2, {OP_MEM(64, 3, -1, 1, 0), OP_IMM(2147483647u, 0)}, 1, 3, 0, 1, "user"},
    {"imm.mov_mem_u64_over32", "mov", 2, {OP_MEM(64, 3, -1, 1, 0), OP_IMM(2147483648u, 0)}, 1, 3, NT_X64_RANGE, 0, "user"},
    {"imm.mov_mem_kernel_u32_7", "mov", 2, {OP_MEM(32, 12, -1, 1, 0), OP_IMM(7, 0)}, 1, 3, 0, 1, "kernel"},
    /* memory in both directions, the address shapes, and the address defects
     * the native answers 411 for. */
    {"mem.add_rax_from_mem64", "add", 2, {OP_REG(64, 0, 0), OP_MEM(64, 3, -1, 1, 0)}, 1, 3, 0, 1, "user"},
    {"mem.add_mem64_by_rax", "add", 2, {OP_MEM(64, 3, -1, 1, 0), OP_REG(64, 0, 0)}, 1, 3, 0, 1, "user"},
    {"mem.sub_mem32_by_ecx", "sub", 2, {OP_MEM(32, 3, -1, 1, 0), OP_REG(32, 1, 0)}, 1, 3, 0, 1, "user"},
    {"mem.sub_ecx_from_mem32", "sub", 2, {OP_REG(32, 1, 0), OP_MEM(32, 3, -1, 1, 0)}, 1, 3, 0, 1, "user"},
    {"mem.and_mem16_by_dx", "and", 2, {OP_MEM(16, 3, 1, 1, 8), OP_REG(16, 2, 0)}, 1, 3, 0, 1, "user"},
    {"mem.or_dx_from_mem16", "or", 2, {OP_REG(16, 2, 0), OP_MEM(16, 3, 1, 1, 8)}, 1, 3, 0, 1, "user"},
    {"mem.xor_mem64_kernel_by_r13", "xor", 2, {OP_MEM(64, 12, -1, 1, 0), OP_REG(64, 13, 0)}, 1, 3, 0, 1, "kernel"},
    {"mem.cmp_rbx_from_mem64", "cmp", 2, {OP_REG(64, 3, 0), OP_MEM(64, 12, -1, 1, 0)}, 1, 3, 0, 1, "user"},
    {"mem.sbb_rax_from_mem64", "sbb", 2, {OP_REG(64, 0, 0), OP_MEM(64, 3, -1, 1, 0)}, 1, 3, 0, 1, "user"},
    {"mem.adc_mem32_by_edx", "adc", 2, {OP_MEM(32, 3, -1, 1, 0), OP_REG(32, 1, 0)}, 1, 3, 0, 1, "user"},
    {"mem.mov_rax_from_mem64", "mov", 2, {OP_REG(64, 0, 0), OP_MEM(64, 3, -1, 1, 0)}, 1, 3, 0, 1, "user"},
    {"mem.mov_mem64_by_r9", "mov", 2, {OP_MEM(64, 3, -1, 1, 0), OP_REG(64, 9, 0)}, 1, 3, 0, 1, "user"},
    {"mem.mov_r8w_from_mem16_r13", "mov", 2, {OP_REG(16, 8, 0), OP_MEM(16, 13, -1, 1, 0)}, 1, 3, 0, 1, "user"},
    {"mem.mov_r9d_from_mem32_r12", "mov", 2, {OP_REG(32, 9, 0), OP_MEM(32, 12, -1, 1, 0)}, 1, 3, 0, 1, "user"},
    {"mem.mov_al_from_mem8_rbp", "mov", 2, {OP_REG(8, 0, 0), OP_MEM(8, 5, -1, 1, 0)}, 1, 3, 0, 1, "user"},
    {"mem.load_rax_from_mem32", "load", 2, {OP_REG(64, 0, 0), OP_MEM(32, 3, -1, 1, 0)}, 1, 3, NT_X64_WIDTH, 0, "user"},
    {"mem.store_mem64_by_imm5", "store", 2, {OP_MEM(64, 3, -1, 1, 0), OP_IMM(5, 0)}, 1, 3, 0, 1, "user"},
    {"mem.rip_mem64", "mov", 2, {OP_REG(64, 0, 0), OP_MEM(64, -2, -1, 1, 16)}, 1, 3, 0, 1, "user"},
    {"mem.rip_only", "mov", 2, {OP_REG(64, 0, 0), OP_MEM(64, -2, -1, 1, 0)}, 1, 3, 0, 1, "user"},
    {"mem.fs_mem64", "mov", 2, {OP_REG(64, 0, 0), OP_MEMS(64, 3, -1, 1, 8, NT_X64_FS)}, 1, 3, 0, 1, "user"},
    {"mem.gs_mem64", "mov", 2, {OP_REG(64, 0, 0), OP_MEMS(64, 3, 1, 1, 8, NT_X64_GS)}, 1, 3, 0, 1, "user"},
    {"mem.base_r12_index_r15", "mov", 2, {OP_REG(64, 0, 0), OP_MEM(64, 12, 15, 8, 0)}, 1, 3, 0, 1, "user"},
    {"mem.base_rbp_index_r14", "mov", 2, {OP_REG(64, 0, 0), OP_MEM(64, 5, 14, 1, 0)}, 1, 3, 0, 1, "user"},
    {"mem.scale_three", "mov", 2, {OP_REG(64, 0, 0), OP_MEM(64, 3, 1, 3, 0)}, 1, 3, NT_X64_ADDRESS, 0, "user"},
    {"mem.index_rsp", "mov", 2, {OP_REG(64, 0, 0), OP_MEM(64, 3, 4, 1, 0)}, 1, 3, NT_X64_ADDRESS, 0, "user"},
    {"mem.disp_min", "mov", 2, {OP_REG(64, 0, 0), OP_MEM(64, 3, -1, 1, -2147483647 - 1)}, 1, 3, 0, 1, "user"},
    {"mem.disp_max", "mov", 2, {OP_REG(64, 0, 0), OP_MEM(64, 3, -1, 1, 2147483647)}, 1, 3, 0, 1, "user"},
    {"mem.disp_over32", "mov", 2, {OP_REG(64, 0, 0), OP_MEM(64, 3, -1, 1, 2147483647LL + 1)}, 1, 3, NT_X64_ADDRESS, 0, "user"},
    {"mem.test_mem_u32_255", "test", 2, {OP_MEM(32, 3, -1, 1, 0), OP_IMM(255, 0)}, 1, 3, 0, 1, "user"},
    {"mem.test_mem_u8_255", "test", 2, {OP_MEM(8, 3, -1, 1, 0), OP_IMM(255, 0)}, 1, 3, 0, 1, "user"},
    {"mem.test_mem_u16_65536", "test", 2, {OP_MEM(16, 3, -1, 1, 0), OP_IMM(65536, 0)}, 1, 3, NT_X64_RANGE, 0, "user"},
    /* test and the shift frames, immediate and cl, register and memory. */
    {"test.al_1", "test", 2, {OP_REG(8, 0, 0), OP_IMM(1, 0)}, 1, 3, 0, 1, "user"},
    {"test.al_255", "test", 2, {OP_REG(8, 0, 0), OP_IMM(255, 0)}, 1, 3, 0, 1, "user"},
    {"test.ax_65535", "test", 2, {OP_REG(16, 0, 0), OP_IMM(65535, 0)}, 1, 3, 0, 1, "user"},
    {"test.ax_over16", "test", 2, {OP_REG(16, 0, 0), OP_IMM(65536, 0)}, 1, 3, NT_X64_RANGE, 0, "user"},
    {"test.eax_bit31", "test", 2, {OP_REG(32, 0, 0), OP_IMM(2147483648u, 0)}, 1, 3, 0, 1, "user"},
    {"test.rax_int32max", "test", 2, {OP_REG(64, 0, 0), OP_IMM(2147483647u, 0)}, 1, 3, 0, 1, "user"},
    {"test.rax_over32", "test", 2, {OP_REG(64, 0, 0), OP_IMM(2147483648u, 0)}, 1, 3, NT_X64_RANGE, 0, "user"},
    {"test.rbx_rcx", "test", 2, {OP_REG(64, 3, 0), OP_REG(64, 1, 0)}, 1, 3, 0, 1, "user"},
    {"test.ebx_over32", "test", 2, {OP_REG(32, 3, 0), OP_IMM(4294967295u, 0)}, 1, 3, 0, 1, "user"},
    {"shift.shr_rax_63", "shr", 2, {OP_REG(64, 0, 0), OP_IMM(63, 0)}, 1, 3, 0, 1, "user"},
    {"shift.sar_ax_3", "sar", 2, {OP_REG(16, 0, 0), OP_IMM(3, 0)}, 1, 3, 0, 1, "user"},
    {"shift.shl_mem_u32_5", "shl", 2, {OP_MEM(32, 3, -1, 1, 0), OP_IMM(5, 0)}, 1, 3, 0, 1, "user"},
    {"shift.shl_mem_u32_cl", "shl", 2, {OP_MEM(32, 3, -1, 1, 0), OP_REG(8, 1, 0)}, 1, 3, 0, 1, "user"},
    {"shift.ror_mem64_kernel_1", "ror", 2, {OP_MEM(64, 12, -1, 1, 0), OP_IMM(1, 0)}, 1, 3, 0, 1, "kernel"},
    {"shift.sar_rax_256", "sar", 2, {OP_REG(64, 0, 0), OP_IMM(256, 0)}, 1, 3, NT_X64_RANGE, 0, "user"},
    {"shift.shl_rax_dl", "shl", 2, {OP_REG(64, 0, 0), OP_REG(8, 2, 0)}, 1, 3, NT_X64_REGISTER, 0, "user"},
    {"shift.shr_mem64_by_rax", "shr", 2, {OP_MEM(64, 3, -1, 1, 0), OP_REG(64, 0, 0)}, 1, 3, NT_X64_REGISTER, 0, "user"},
    /* conversions and the three-operand imul. */
    {"conv.movzx_eax_bl", "movzx", 2, {OP_REG(32, 0, 0), OP_REG(8, 3, 0)}, 1, 3, 0, 1, "user"},
    {"conv.movzx_rax_cl", "movzx", 2, {OP_REG(64, 0, 0), OP_REG(8, 1, 0)}, 1, 3, 0, 1, "user"},
    {"conv.movzx_eax_cx", "movzx", 2, {OP_REG(32, 0, 0), OP_REG(16, 1, 0)}, 1, 3, 0, 1, "user"},
    {"conv.movzx_ax_cx", "movzx", 2, {OP_REG(16, 0, 0), OP_REG(16, 1, 0)}, 1, 3, NT_X64_WIDTH, 0, "user"},
    {"conv.movsx_r8w_r9b", "movsx", 2, {OP_REG(16, 8, 0), OP_REG(8, 9, 0)}, 1, 3, 0, 1, "user"},
    {"conv.movsx_rax_cx", "movsx", 2, {OP_REG(64, 0, 0), OP_REG(16, 1, 0)}, 1, 3, 0, 1, "user"},
    {"conv.movzx_al_ah", "movzx", 2, {OP_REG(8, 0, 0), OP_REG(8, 0, 1)}, 1, 3, NT_X64_WIDTH, 0, "user"},
    {"conv.movsxd_rax_ecx", "movsxd", 2, {OP_REG(64, 0, 0), OP_REG(32, 1, 0)}, 1, 3, 0, 1, "user"},
    {"conv.movsxd_eax_ecx", "movsxd", 2, {OP_REG(32, 0, 0), OP_REG(32, 1, 0)}, 1, 3, NT_X64_WIDTH, 0, "user"},
    {"conv.imul_eax_ecx", "imul", 2, {OP_REG(32, 0, 0), OP_REG(32, 1, 0)}, 1, 3, 0, 1, "user"},
    {"conv.imul_rax_rbx", "imul", 2, {OP_REG(64, 0, 0), OP_REG(64, 3, 0)}, 1, 3, 0, 1, "user"},
    {"conv.imul_rax_mem64", "imul", 2, {OP_REG(64, 0, 0), OP_MEM(64, 3, -1, 1, 0)}, 1, 3, 0, 1, "user"},
    {"conv.imul_al_cl", "imul", 2, {OP_REG(8, 0, 0), OP_REG(8, 1, 0)}, 1, 3, NT_X64_WIDTH, 0, "user"},
    {"conv.imul_eax_ecx_5", "imul", 3, {OP_REG(32, 0, 0), OP_REG(32, 1, 0), OP_IMM(5, 0)}, 1, 3, 0, 1, "user"},
    {"conv.imul_eax_ecx_128", "imul", 3, {OP_REG(32, 0, 0), OP_REG(32, 1, 0), OP_IMM(128, 0)}, 1, 3, 0, 1, "user"},
    {"conv.imul_eax_ecx_neg1", "imul", 3, {OP_REG(32, 0, 0), OP_REG(32, 1, 0), OP_IMM(UINT64_MAX, 1)}, 1, 3, 0, 1, "user"},
    {"conv.imul_eax_mem32_7", "imul", 3, {OP_REG(32, 0, 0), OP_MEM(32, 3, -1, 1, 0), OP_IMM(7, 0)}, 1, 3, 0, 1, "user"},
    {"conv.imul_eax_ecx_over32", "imul", 3, {OP_REG(32, 0, 0), OP_REG(32, 1, 0), OP_IMM(2147483648u, 0)}, 1, 3, NT_X64_RANGE, 0, "user"},
    /* control registers: the five the native names, and the ones it refuses. */
    {"cr.read_cr0", "read_cr", 2, {OP_REG(64, 0, 0), OP_CR(0)}, 1, 0, 0, 1, "user"},
    {"cr.read_cr2", "read_cr", 2, {OP_REG(64, 0, 0), OP_CR(2)}, 1, 0, 0, 1, "user"},
    {"cr.read_cr3", "read_cr", 2, {OP_REG(64, 0, 0), OP_CR(3)}, 1, 0, 0, 1, "user"},
    {"cr.read_cr4", "read_cr", 2, {OP_REG(64, 0, 0), OP_CR(4)}, 1, 0, 0, 1, "user"},
    {"cr.read_cr8", "read_cr", 2, {OP_REG(64, 0, 0), OP_CR(8)}, 1, 0, 0, 1, "user"},
    {"cr.read_r9_cr8", "read_cr", 2, {OP_REG(64, 9, 0), OP_CR(8)}, 1, 0, 0, 1, "user"},
    {"cr.write_cr0", "write_cr", 2, {OP_CR(0), OP_REG(64, 0, 0)}, 1, 0, 0, 1, "user"},
    {"cr.write_cr4", "write_cr", 2, {OP_CR(4), OP_REG(64, 0, 0)}, 1, 0, 0, 1, "user"},
    {"cr.write_r8_cr8", "write_cr", 2, {OP_CR(8), OP_REG(64, 8, 0)}, 1, 0, 0, 1, "user"},
    {"cr.read_cr5", "read_cr", 2, {OP_REG(64, 0, 0), OP_CR(5)}, 1, 0, NT_X64_REGISTER, 0, "user"},
    {"cr.read_cr1", "read_cr", 2, {OP_REG(64, 0, 0), OP_CR(1)}, 1, 0, NT_X64_REGISTER, 0, "user"},
    {"cr.write_cr9", "write_cr", 2, {OP_CR(9), OP_REG(64, 0, 0)}, 1, 0, NT_X64_REGISTER, 0, "user"},
    {"cr.read_cr0_ring3", "read_cr", 2, {OP_REG(64, 0, 0), OP_CR(0)}, 1, 3, NT_X64_PRIVILEGE, 0, "user"},
    {"cr.write_cr0_nolm", "write_cr", 2, {OP_CR(0), OP_REG(64, 0, 0)}, 0, 0, NT_X64_FEATURE, 0, "user"},
    {"cr.read_cr0_nolm", "read_cr", 2, {OP_REG(64, 0, 0), OP_CR(0)}, 0, 0, NT_X64_FEATURE, 0, "user"},
    /* in and out: an immediate port and dx, the three accumulator widths, and
     * the port bounds and the privilege the native states. */
    {"io.in_al_60", "in", 2, {OP_REG(8, 0, 0), OP_IMM(60, 0)}, 1, 0, 0, 1, "user"},
    {"io.in_al_255", "in", 2, {OP_REG(8, 0, 0), OP_IMM(255, 0)}, 1, 0, 0, 1, "user"},
    {"io.in_al_256", "in", 2, {OP_REG(8, 0, 0), OP_IMM(256, 0)}, 1, 0, NT_X64_RANGE, 0, "user"},
    {"io.in_ax_3", "in", 2, {OP_REG(16, 0, 0), OP_IMM(3, 0)}, 1, 0, 0, 1, "user"},
    {"io.in_eax_60", "in", 2, {OP_REG(32, 0, 0), OP_IMM(60, 0)}, 1, 0, 0, 1, "user"},
    {"io.in_al_dx", "in", 2, {OP_REG(8, 0, 0), OP_REG(16, 2, 0)}, 1, 0, 0, 1, "user"},
    {"io.in_eax_dx", "in", 2, {OP_REG(32, 0, 0), OP_REG(16, 2, 0)}, 1, 0, 0, 1, "user"},
    {"io.out_dx_al", "out", 2, {OP_REG(16, 2, 0), OP_REG(8, 0, 0)}, 1, 0, 0, 1, "user"},
    {"io.out_dx_ax", "out", 2, {OP_REG(16, 2, 0), OP_REG(16, 0, 0)}, 1, 0, 0, 1, "user"},
    {"io.out_dx_eax", "out", 2, {OP_REG(16, 2, 0), OP_REG(32, 0, 0)}, 1, 0, 0, 1, "user"},
    {"io.out_60_al", "out", 2, {OP_IMM(60, 0), OP_REG(8, 0, 0)}, 1, 0, 0, 1, "user"},
    {"io.in_al_60_ring3", "in", 2, {OP_REG(8, 0, 0), OP_IMM(60, 0)}, 1, 3, NT_X64_PRIVILEGE, 0, "user"},
    {"io.in_cl_60", "in", 2, {OP_REG(8, 1, 0), OP_IMM(60, 0)}, 1, 0, NT_X64_REGISTER, 0, "user"},
    {"io.in_rax_60", "in", 2, {OP_REG(64, 0, 0), OP_IMM(60, 0)}, 1, 0, NT_X64_REGISTER, 0, "user"},
    {"io.in_al_bx", "in", 2, {OP_REG(8, 0, 0), OP_REG(16, 3, 0)}, 1, 0, NT_X64_REGISTER, 0, "user"},
    /* ltr takes a 16 bit task register in a register or a memory operand,
     * invlpg an address-only memory operand, and both are privileged. */
    /* invlpg is an address-only form and is spelled in both halves further
     * down, because its oracle width is one a pointer cannot state. */
    {"sys.ltr_cx", "ltr", 1, {OP_REG(16, 1, 0)}, 1, 0, 0, 1, "user"},
    {"sys.ltr_r8w", "ltr", 1, {OP_REG(16, 8, 0)}, 1, 0, 0, 1, "user"},
    {"sys.ltr_mem_u16", "ltr", 1, {OP_MEM(16, 3, -1, 1, 0)}, 1, 0, 0, 1, "user"},
    {"sys.ltr_rax", "ltr", 1, {OP_REG(64, 0, 0)}, 1, 0, NT_X64_WIDTH, 0, "user"},
    {"sys.ltr_al", "ltr", 1, {OP_REG(8, 0, 0)}, 1, 0, NT_X64_WIDTH, 0, "user"},
    {"sys.ltr_mem_u32", "ltr", 1, {OP_MEM(32, 3, -1, 1, 0)}, 1, 0, NT_X64_WIDTH, 0, "user"},
    {"sys.ltr_cx_ring3", "ltr", 1, {OP_REG(16, 1, 0)}, 1, 3, NT_X64_PRIVILEGE, 0, "user"},
    /* the four descriptor forms. Their access width is 80 and no machine
     * scalar spells it, so the source states an array<u8,10> element. */
    {"desc.sgdt_rbx", "sgdt", 1, {OP_MEM(80, 3, -1, 1, 0)}, 1, 3, 0, 1, "user"},
    {"desc.sgdt_rbx_8", "sgdt", 1, {OP_MEM(80, 3, -1, 1, 8)}, 1, 3, 0, 1, "user"},
    {"desc.sidt_r12", "sidt", 1, {OP_MEM(80, 12, -1, 1, 0)}, 1, 3, 0, 1, "user"},
    {"desc.sidt_sib", "sidt", 1, {OP_MEM(80, 12, 13, 8, 0)}, 1, 3, 0, 1, "user"},
    {"desc.lgdt_rbx", "lgdt", 1, {OP_MEM(80, 3, -1, 1, 0)}, 1, 0, 0, 1, "user"},
    {"desc.lidt_r12", "lidt", 1, {OP_MEM(80, 12, -1, 1, 0)}, 1, 0, 0, 1, "user"},
    {"desc.lgdt_ring3", "lgdt", 1, {OP_MEM(80, 3, -1, 1, 0)}, 1, 3, NT_X64_PRIVILEGE, 0, "user"},
    {"desc.lidt_ring3", "lidt", 1, {OP_MEM(80, 3, -1, 1, 0)}, 1, 3, NT_X64_PRIVILEGE, 0, "user"},
    {"desc.sgdt_scalar", "sgdt", 1, {OP_MEM(64, 3, -1, 1, 0)}, 1, 3, NT_X64_WIDTH, 0, "user"},
    {"desc.sgdt_rax", "sgdt", 1, {OP_REG(64, 0, 0)}, 1, 3, NT_X64_FORM, 0, "user"},
    {"desc.sgdt_mem_u32", "sgdt", 1, {OP_MEM(32, 3, -1, 1, 0)}, 1, 3, NT_X64_WIDTH, 0, "user"},
    /* load and store are the two spellings of the same two frames. */
    {"ldst.load_r13_from_mem16", "load", 2, {OP_REG(16, 13, 0), OP_MEM(16, 3, -1, 1, 0)}, 1, 3, 0, 1, "user"},
    {"ldst.store_mem32_by_ebx", "store", 2, {OP_MEM(32, 3, -1, 1, 0), OP_REG(32, 3, 0)}, 1, 3, 0, 1, "user"},
    {"ldst.store_mem64_by_imm", "store", 2, {OP_MEM(64, 3, -1, 1, 0), OP_IMM(1, 0)}, 1, 3, 0, 1, "user"},
    {"ldst.store_mem8_by_rsi", "store", 2, {OP_MEM(8, 3, -1, 1, 0), OP_REG(64, 6, 0)}, 1, 3, NT_X64_WIDTH, 0, "user"},
};

/* ---- refusals the lowerer owns by itself ----
 * An address register is spelled by name, so a 32-bit base or index is a
 * source the operand descriptor has no representation for: the native address
 * fields hold 64-bit GPR numbers and nothing else, and it is never asked. The
 * diagnostic is stated here and is the lowerer's own 406, the register the
 * memory address is read from. */
static const struct { const char *name, *text; uint32_t features; unsigned cpl; uint64_t code; } owned[] = {
    {"addr.eax_base", "mov rax,[eax]:ptr<user,u64>", 1, 3, NT_X64_REGISTER},
    {"addr.ax_base", "mov rax,[ax]:ptr<user,u64>", 1, 3, NT_X64_REGISTER},
    {"addr.ecx_index", "mov rax,[rbx+ecx*4]:ptr<user,u64>", 1, 3, NT_X64_REGISTER},
    {"addr.ecx_index_noscale", "mov rax,[rbx+ecx]:ptr<user,u64>", 1, 3, NT_X64_REGISTER},
    {"addr.eax_base_index", "mov rax,[rax+eax*4+8]:ptr<user,u64>", 1, 3, NT_X64_REGISTER},
    {"addr.ltr_eax_base", "ltr [eax]:ptr<user,u16>", 1, 0, NT_X64_REGISTER},
    {"desc.sgdt_eax_base", "sgdt [eax]:ptr<user,array<u8,10>>", 1, 3, NT_X64_REGISTER},
    {"entry.two_statements", "mov rax,rbx\nmov rcx,rdx", 1, 3, NT_X64_FORM},
};

/* The oracle decides: bytes on acceptance, the same diagnostic on refusal, and
 * out untouched on every refusal. must_encode and want_code keep a refusal row
 * from passing as an acceptance. */
static void compare(const NovaHostImage *i, const char *name, const char *text, const char *mnemonic,
                    const NtX64Operand *o, unsigned count, uint32_t features, unsigned cpl,
                    unsigned want_code, unsigned must_encode) {
    NtX64Instruction expected = {0};
    NtX64Context context = {features, cpl};
    NtX64Error e = nt_x64_encode(mnemonic, o, (size_t)count, context, &expected);
    Run r = run(i, text, features, cpl);
    cases++;
    checks++;
    int bad = r.runtime != 0 || r.returned != (uint64_t)e;
    if (must_encode && e != NT_X64_OK) bad = 1;
    if (want_code != 0 && (uint64_t)e != want_code) bad = 1;
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
        fprintf(stderr, "FAIL %s '%s' ret=%llu oracle=%u want=%u out=%u,%u,%u,%u\n", name, text,
                (unsigned long long)r.returned, (unsigned)e, want_code, r.out[0], r.out[1], r.out[2],
                r.out[3]);
    }
}

/* A corpus row: both halves are printed from one descriptor, so the operands
 * the oracle reads and the operands the source states cannot differ. */
static void parity(const NovaHostImage *i, const Case *c) {
    char text[512];
    spell_case(text, sizeof text, c->mnemonic, c->o, c->count, c->space);
    compare(i, c->name, text, c->mnemonic, c->o, c->count, c->features, c->cpl, c->want_code,
            c->must_encode);
}

/* invlpg is the one row whose two halves cannot be printed from one descriptor,
 * and the reason is a property of the form rather than a hole in this file.
 * The native reads its memory operand with width 0: that field means the
 * address alone and no access width, and x64.h says so at the operand
 * declaration. A pointer always names an element, so the source says u64 where
 * the oracle operand says 0, and both halves are written out here. The oracle
 * operand stays the authority, because the width is the field the native
 * actually reads -- and that is the rule this row exists to hold, so it must
 * not be papered over by printing the oracle's 0 as if it were an element. */
static const struct {
    const char *name, *text;
    NtX64Operand o[1];
    uint32_t features;
    unsigned cpl;
    unsigned want_code;
} address_only[] = {
    {"sys.invlpg_mem64", "invlpg [rbx]:ptr<user,u64>",
     {{.kind = NT_X64_MEM, .width = 0, .base = 3, .index = -1, .scale = 1, .disp = 0}}, 1, 0, 0},
    {"sys.invlpg_sib", "invlpg [rbx+rcx*4+8]:ptr<user,u64>",
     {{.kind = NT_X64_MEM, .width = 0, .base = 3, .index = 1, .scale = 4, .disp = 8}}, 1, 0, 0},
    {"sys.invlpg_mem64_ring3", "invlpg [rbx]:ptr<user,u64>",
     {{.kind = NT_X64_MEM, .width = 0, .base = 3, .index = -1, .scale = 1, .disp = 0}}, 1, 3,
     NT_X64_PRIVILEGE},
    {"sys.invlpg_nolm", "invlpg [rbx]:ptr<user,u64>",
     {{.kind = NT_X64_MEM, .width = 0, .base = 3, .index = -1, .scale = 1, .disp = 0}}, 0, 0,
     NT_X64_FEATURE},
};

static void address_only_rows(const NovaHostImage *i) {
    for (unsigned k = 0; k < sizeof address_only / sizeof *address_only; k++)
        compare(i, address_only[k].name, address_only[k].text, "invlpg", address_only[k].o, 1,
                address_only[k].features, address_only[k].cpl, address_only[k].want_code, 0);
}

static void refusal(const NovaHostImage *i, const char *name, const char *text, uint32_t features,
                    unsigned cpl, uint64_t code) {
    Run r = run(i, text, features, cpl);
    cases++;
    checks++;
    int bad = r.returned != code || r.runtime != 0;
    for (unsigned k = 0; k < sizeof r.out; k++) bad |= r.out[k] != guard;
    if (bad) {
        failures++;
        fprintf(stderr, "FAIL refusal %s '%s' ret=%llu want=%llu\n", name, text,
                (unsigned long long)r.returned, (unsigned long long)code);
    }
}

/* Absolute addressing is supported and must match C, like every other row. */
static void report_pair(const NovaHostImage *i,const char *name,const char *mnemonic,
                        const char *text,const NtX64Operand *o,unsigned count,uint32_t features,unsigned cpl) {
    compare(i,name,text,mnemonic,o,count,features,cpl,0,1);
}

int main(void) {
    const char *paths[] = {"tests/nova/tests/x64-a2-parity-entry.nova",
                           "compiler/nova/backend/x64/x64_lower_fixed.nova",
                           "compiler/nova/backend/x64/x64_fixed.nova",
                           "compiler/nova/analysis/types/register_widths.nova",
                           "compiler/nova/frontend/parser.nova",
                           "compiler/nova/frontend/ast.nova",
                           "compiler/nova/frontend/lexer.nova"};
    char *sources[7] = {0};
    NtFInput inputs[7];
    int all = 1;
    for (unsigned k = 0; k < 7; k++) {
        size_t n = 0;
        sources[k] = loadf(paths[k], &n);
        inputs[k] = (NtFInput){paths[k], sources[k], n};
        if (!sources[k]) all = 0;
        printf("A2-SOURCE %-56s bytes=%zu fnv=%016llx\n", paths[k], n,
               (unsigned long long)fingerprint(sources[k] ? sources[k] : "", n));
    }
    CHECK(all, "sources load");
    NtArtifact a = {0};
    int compiled = all && nova_compile_many_v2(inputs, 7, &a);
    CHECK(compiled, "modules compile");
    if (!compiled)
        fprintf(stderr, "E%u %zu:%zu %s\n", a.error.code, a.error.line, a.error.column, a.error.message);
    NovaHostImage image = {0};
    CHECK(compiled && nova_host_map(&a, &image), "image maps");
    if (image.memory) {
        for (unsigned k = 0; k < sizeof corpus / sizeof *corpus; k++) parity(&image, &corpus[k]);
        address_only_rows(&image);
        for (unsigned k = 0; k < sizeof owned / sizeof *owned; k++)
            refusal(&image, owned[k].name, owned[k].text, owned[k].features, owned[k].cpl, owned[k].code);
        NtX64Operand no_base[2] = {{.kind = NT_X64_REG, .width = 64, .reg = 0},
                                   {.kind = NT_X64_MEM, .width = 64, .base = -1, .index = -1, .scale = 1,
                                    .disp = 16}};
        report_pair(&image, "addr.no_base", "mov", "mov rax,[16]:ptr<user,u64>", no_base, 2, 1, 3);
        nova_host_unmap(&image);
    }
    if (compiled) nt_artifact_free(&a);
    for (unsigned k = 0; k < 7; k++) free(sources[k]);
    printf("NTASM_NOVA_X64_A2_PARITY checks=%u failures=%u cases=%u\n", checks,
           failures, cases);
    return failures ? 1 : 0;
}