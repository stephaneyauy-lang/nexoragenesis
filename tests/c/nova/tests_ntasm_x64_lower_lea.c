/* NTASM AST lowerer gate for lea: every accepted instruction is encoded a
 * second time by the native oracle nt_x64_encode and compared byte for byte,
 * and every refusal is compared against the oracle diagnostic. The expected
 * bytes and codes are never derived from the Nova producer. The gate also
 * carries the encoder/lowerer drift detector, which enumerates the mnemonic
 * surface of x64_fixed and refuses to let a form the encoder can emit be
 * silently unreachable from encode_instruction.
 *
 * The drift table is no longer trusted to be complete on its own. A closure
 * check reads the module text this gate already loads, machine-extracts the
 * `export fn` headers and every string literal of x64_fixed, and requires the
 * sets to be exact bijections: exports against a manifest, literals against
 * the manifest entry of their owning export, and row mnemonics against the
 * literals plus four small declared sets (1 alias, 2 statement-owned, 3
 * lowerer pseudo spellings, 19 with no encoder at all). Adding an encoder is
 * now a gate failure until the table accounts for it, whether the addition is
 * a new export, a new mnemonic inside an existing export, or a renamed one.
 *
 * The closure above reads one side of the pair. The other side is the C
 * encoder itself, and it is the side a pinned row equation cannot see: 177
 * rows that add up is also true of 177 rows that never mention a mnemonic the
 * encoder emits. So the gate also reads x64.c, offers every identifier literal
 * in it, and asks nt_x64_encode which of those names it knows, in both
 * directions against the drift table. That axis found twelve mnemonics the
 * hand-kept absence list had never been told about, and they are rows now.
 *
 * The one direction that took the longest is the fourth: the tokens the
 * candidate filter *refused*. Those were offered by nothing, so no direction
 * could see them and the axis reported a closed alphabet that was short by
 * them. The scan keeps them now and the closure asks the encoder about each,
 * and the names that are not literals at all — a builder call, an escaped
 * byte, a name split across two literals — each refuse the scan by naming
 * itself rather than passing through it. */
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

/* One instruction inside a function; branch rows also define a target label. */
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

/* Encode the same instruction with the native oracle and require the lowerer
 * to agree on the bytes, or on the diagnostic, and to leave out untouched on
 * every failure. */
static void parity(const NovaHostImage *i, const char *body, NtX64Operand *o, unsigned count,
                   uint32_t features, unsigned cpl) {
    NtX64Instruction expected = {0};
    NtX64Context context = {features, cpl};
    NtX64Error e = nt_x64_encode("lea", o, count, context, &expected);
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
            fprintf(stderr, "FAIL lea %s ret=%llu oracle=%u out=%u,%u,%u,%u,%u,%u\n", body,
                    (unsigned long long)r.returned, (unsigned)e, r.out[0], r.out[1], r.out[2],
                    r.out[3], r.out[4], r.out[5]);
}

/* A refusal the lowerer owns by itself: the operand count is not an oracle
 * call, so the expected code is stated here. out must stay untouched. */
static void refusal(const NovaHostImage *i, const char *name, const char *body, uint64_t code,
                    uint32_t features, unsigned cpl) {
    Run r = run(i, body, features, cpl);
    cases++;
    int bad = r.returned != code || r.runtime != 0;
    for (unsigned k = 0; k < sizeof r.out; k++) bad |= r.out[k] != guard;
    if (bad) {
        failures++;
        fprintf(stderr, "FAIL lea %s ret=%llu expected=%llu\n", name, (unsigned long long)r.returned,
                (unsigned long long)code);
    } else {
        checks++;
    }
}

/* The index-only form is now required, and must differ from base+disp. */
static void gap(const NovaHostImage *i, const char *name, const char *body, NtX64Operand *o,
                unsigned count, NtX64Operand *plain) {
    (void)name;
    NtX64Instruction expected={0},base={0};NtX64Context context={1,3};
    CHECK(nt_x64_encode("lea",o,count,context,&expected)==NT_X64_OK,"index-only reference accepts");
    CHECK(nt_x64_encode("lea",plain,count,context,&base)==NT_X64_OK,"base reference accepts");
    CHECK(base.length!=expected.length||memcmp(base.bytes,expected.bytes,expected.length),"index-only must not silently become base+disp");
    parity(i,body,o,count,1,3);
}

typedef struct {
    const char *body;
    unsigned reg, width;
    int base, index;
    unsigned scale;
    int64_t disp;
} Lea;

static void row(const NovaHostImage *i, const Lea *r) {
    NtX64Operand o[2] = {{.kind = NT_X64_REG, .width = r->width, .reg = r->reg},
                         {.kind = NT_X64_MEM, .width = 64, .base = r->base, .index = r->index,
                          .scale = r->scale, .disp = r->disp}};
    parity(i, r->body, o, 2, 1, 3);
}

static void lea_cases(const NovaHostImage *i) {
    /* Accepted shapes: every width of the address form, every scale, the two
     * displacement classes, the SIB-only bases and RIP. */
    static const Lea accepted[] = {
        {"lea rax,[rbx]:ptr<user,u64>", 0, 64, 3, -1, 1, 0},
        {"lea rax,[rbx+8]:ptr<user,u64>", 0, 64, 3, -1, 1, 8},
        {"lea rax,[rbx+127]:ptr<user,u64>", 0, 64, 3, -1, 1, 127},
        {"lea rax,[rbx+128]:ptr<user,u64>", 0, 64, 3, -1, 1, 128},
        {"lea rax,[rbx-8]:ptr<user,u64>", 0, 64, 3, -1, 1, -8},
        {"lea rax,[rbx+rcx]:ptr<user,u64>", 0, 64, 3, 1, 1, 0},
        {"lea rax,[rbx+rcx*2]:ptr<user,u64>", 0, 64, 3, 1, 2, 0},
        {"lea rax,[rbx+rcx*4]:ptr<user,u64>", 0, 64, 3, 1, 4, 0},
        {"lea rax,[rbx+rcx*8]:ptr<user,u64>", 0, 64, 3, 1, 8, 0},
        {"lea rax,[rbx+rcx*4+64]:ptr<user,u64>", 0, 64, 3, 1, 4, 64},
        {"lea rax,[rsp+8]:ptr<user,u64>", 0, 64, 4, -1, 1, 8},
        {"lea rax,[rsp]:ptr<user,u64>", 0, 64, 4, -1, 1, 0},
        {"lea r12,[r13+r14*8-128]:ptr<user,u64>", 12, 64, 13, 14, 8, -128},
        {"lea r15,[r14+r15*8+2147483647]:ptr<user,u64>", 15, 64, 14, 15, 8, 2147483647},
        {"lea rax,[rip+16]:ptr<user,u64>", 0, 64, -2, -1, 1, 16},
        {"lea rax,[rcx+rcx*2]:ptr<user,u64>", 0, 64, 1, 1, 2, 0},
        {"lea r9,[r10]:ptr<user,u64>", 9, 64, 10, -1, 1, 0},
        {"lea rax,[r12+rbx*8+2147483646]:ptr<user,u64>", 0, 64, 12, 3, 8, 2147483646},
    };
    for (unsigned k = 0; k < sizeof accepted / sizeof *accepted; k++) row(i, &accepted[k]);
    /* Refusals: the expected code is whatever nt_x64_encode answers for the
     * same operand shape, never a number written by hand. */
    static const Lea refused[] = {
        {"lea eax,[rbx+8]:ptr<user,u64>", 0, 32, 3, -1, 1, 8},
        {"lea ax,[rbx+8]:ptr<user,u64>", 0, 16, 3, -1, 1, 8},
        {"lea al,[rbx+8]:ptr<user,u64>", 0, 8, 3, -1, 1, 8},
        {"lea ah,[rbx+8]:ptr<user,u64>", 0, 8, 3, -1, 1, 8},
        {"lea r16,[rbx+8]:ptr<user,u64>", 16, 64, 3, -1, 1, 8},
        {"lea rax,[rbx+rsp*2]:ptr<user,u64>", 0, 64, 3, 4, 2, 0},
        {"lea rax,[rbx+rcx*3]:ptr<user,u64>", 0, 64, 3, 1, 3, 0},
        {"lea rax,[rip+rcx]:ptr<user,u64>", 0, 64, -2, 1, 1, 0},
        {"lea rax,[rbx+2147483648]:ptr<user,u64>", 0, 64, 3, -1, 1, 2147483648},
    };
    for (unsigned k = 0; k < sizeof refused / sizeof *refused; k++)
        row(i, &refused[k]);
    static const Lea refused_form[] = {{"lea rax,rbx", 0, 64, 3, -1, 1, 0}};
    for (unsigned k = 0; k < sizeof refused_form / sizeof *refused_form; k++) {
        NtX64Operand o[2] = {{.kind = NT_X64_REG, .width = 64, .reg = 0},
                             {.kind = NT_X64_REG, .width = 64, .reg = 3}};
        parity(i, refused_form[k].body, o, 2, 1, 3);
    }
    /* Context rules, still compared against the oracle answer. */
    {
        NtX64Operand o[2] = {{.kind = NT_X64_REG, .width = 64, .reg = 0},
                             {.kind = NT_X64_MEM, .width = 64, .base = 3, .index = -1, .scale = 1,
                              .disp = 8}};
        parity(i, "lea rax,[rbx+8]:ptr<user,u64>", o, 2, 0, 3);
        parity(i, "lea rax,[rbx+8]:ptr<user,u64>", o, 2, 1, 4);
    }
    /* Refusals the lowerer owns: an operand count the AST lowerer never
     * forwards to the oracle, whatever the mnemonic. */
    refusal(i, "one operand", "lea rax", 409, 1, 3);
    refusal(i, "three operands", "lea rax,rbx,rcx", 409, 1, 3);
    /* The fs/gs channel. These two were declared gaps: the oracle emitted
     * 64 48 8d 03 and 65 48 8d 03 and encode_lea had no way to ask for either,
     * so the lowerer refused. encode_lea now takes the segment like every
     * other memory export, so they are parity rows and the bytes are compared
     * against the oracle rather than declared away. The gap helper is still
     * used below for the form it is still the right tool for. */
    {
        static const NtX64Segment segs[2] = {NT_X64_FS, NT_X64_GS};
        static const char *const bodies[2] = {"lea rax,[fs:rbx+8]:ptr<user,u64>",
                                             "lea rax,[gs:rbx+8]:ptr<user,u64>"};
        for (unsigned k = 0; k < 2; k++) {
            NtX64Operand o[2] = {{.kind = NT_X64_REG, .width = 64, .reg = 0},
                                 {.kind = NT_X64_MEM, .width = 64, .base = 3, .index = -1,
                                  .scale = 1, .disp = 8, .segment = segs[k]}};
            parity(i, bodies[k], o, 2, 1, 3);
        }
    }
    /* Declared gaps: forms the oracle encodes and encode_lea cannot express.
     * They are reported here so a future encoder fix shows up as a closed
     * gap instead of a silent difference. */
    NtX64Operand plain[2] = {{.kind = NT_X64_REG, .width = 64, .reg = 0},
                             {.kind = NT_X64_MEM, .width = 64, .base = 3, .index = -1,
                              .scale = 1, .disp = 8}};
    NtX64Operand nobase[2] = {{.kind = NT_X64_REG, .width = 64, .reg = 0},
                              {.kind = NT_X64_MEM, .width = 64, .base = -1, .index = 3, .scale = 2,
                               .disp = 8}};
    gap(i, "index only", "lea rax,[rbx*2+8]:ptr<user,u64>", nobase, 2, plain);
}

/* ------------------------------------------------------------- surface ----
 * Closure over the encoder itself. The Nova compiler is not asked: nova.h
 * offers nova_compile, nova_compile_many, the v2 pair and nova_check_many, and
 * nothing else, so there is no way for a host program to ask it for the export
 * list of a compiled module. The internal compiler does mark every function
 * with an `exported` flag, but that flag never leaves nova.c. So the gate reads
 * the module text it already loads for the compiler and extracts the surface
 * itself, and the manifest below is the only thing a human maintains.
 *
 * The extraction is deliberately narrow. x64_fixed names a mnemonic in exactly
 * one way, a string literal compared by `same`, and it holds no byte in any
 * other shape, so the set of literals is the module's whole mnemonic alphabet.
 * Scanning literals rather than `same` call sites also closes the pipe-style
 * dispatch other modules use (`member(source,start,end,"bts|btr|btc")`), which
 * a call-site scan would miss. A record is a `fn` or `export fn` header at
 * brace depth zero, which is the shape the compiler itself parses. */
#define SURF_MAX_RECORDS 64
#define SURF_MAX_LITERALS 256
#define SURF_NAME_MAX 40
#define SURF_ERROR_MAX 192
#define GAP_REASON_MAX 16
#define ROW_MAX 512
#define SPELLING_MAX 64
/* The number of module-text mutants this gate executes. The figure DRIFT-CLOSURE
 * prints is stringified from here and the two are checked against the counter
 * mutant_case maintains at run time, so announcing a count needs three edits
 * instead of one and a prose count cannot survive a change of the list. */
#define MUTANT_CASE_COUNT 14
#define SURF_STR_(x) #x
#define SURF_STR(x) SURF_STR_(x)

typedef struct {
    unsigned records;
    char record_name[SURF_MAX_RECORDS][SURF_NAME_MAX];
    int record_exported[SURF_MAX_RECORDS];
    unsigned exports;
    char export_name[SURF_MAX_RECORDS][SURF_NAME_MAX];
    /* The parameter axis. Every other field here is a name or a string
     * literal, so the closure below is blind to a parameter: an export that
     * keeps its name and its mnemonics while losing a channel the oracle
     * honours is invisible to it. encode_lea has been missing `segment:u64`
     * since it was written, and all 177 drift rows stayed green through it.
     * These two flags give the surface check an axis it can fail on:
     * record_memory is set when the parameter list names `base:u64`, which is
     * exactly the seven memory exports, and record_segment when it names
     * `segment:u64`, which is the fs/gs channel. */
    int record_memory[SURF_MAX_RECORDS];
    int record_segment[SURF_MAX_RECORDS];
    unsigned literals;
    char literal[SURF_MAX_LITERALS][SURF_NAME_MAX];
    int literal_owner[SURF_MAX_LITERALS];
    /* Why the scan refused the text, naming the field and the limit that was
     * crossed. Empty when the scan succeeded. Both ceilings below used to be
     * silent skips, so a surface larger than the capacity declared here was
     * measured as if the excess did not exist, and the export bijection passed
     * on a module that had an export nobody had recorded. */
    char scan_error[SURF_ERROR_MAX];
} Surface;

/* Bounded substring search over a length, so the parameter scan cannot read
 * past the line it was handed. memmem is a GNU extension and this tree builds
 * with -std=c11 -Werror, so it is spelled out rather than assumed. */
static const char *find_token(const char *hay, size_t n, const char *needle,
                              size_t m) {
    if (m == 0 || m > n) return 0;
    for (size_t k = 0; k + m <= n; k++)
        if (!memcmp(hay + k, needle, m)) return hay + k;
    return 0;
}

static int ident_char(int c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_';
}

static int surface_scan(const char *text, Surface *s) {
    memset(s, 0, sizeof *s);
    int depth = 0, current = -1;
    for (const char *line = text; *line;) {
        const char *nl = strchr(line, '\n');
        size_t len = nl ? (size_t)(nl - line) : strlen(line);
        size_t k = 0;
        while (k < len && (line[k] == ' ' || line[k] == '\t' || line[k] == '\r')) k++;
        if (depth == 0) {
            int exported = 0;
            const char *kw = 0;
            if (len - k >= 10 && !memcmp(line + k, "export fn ", 10)) {
                exported = 1;
                kw = line + k + 10;
            } else if (len - k >= 3 && !memcmp(line + k, "fn ", 3)) {
                kw = line + k + 3;
            }
            if (kw) {
                unsigned n = 0;
                const char *q = kw;
                /* The name is read to its real end before any store is
                 * attempted. A name that does not fit is refused loudly
                 * instead of being truncated: a truncated name still matches
                 * the export bijection on the part it kept, and a header
                 * dropped entirely leaves its body's literals attributed to
                 * whichever record came before it, so both are fail-open. */
                while (q < line + len && ident_char(*q)) {
                    if (n + 1 >= SURF_NAME_MAX) {
                        snprintf(s->scan_error, sizeof s->scan_error,
                                 "a depth-0 record name needs %u characters or more, the "
                                 "SURF_NAME_MAX limit is %u",
                                 n + 1, (unsigned)SURF_NAME_MAX);
                        return 0;
                    }
                    n++, q++;
                }
                if (n == 0 || (q < line + len && *q != '(')) kw = 0;
                else {
                    if (s->records >= SURF_MAX_RECORDS) {
                        snprintf(s->scan_error, sizeof s->scan_error,
                                 "the module has more depth-0 headers than the "
                                 "SURF_MAX_RECORDS ceiling of %u, record %u is not counted",
                                 (unsigned)SURF_MAX_RECORDS, s->records + 1);
                        return 0;
                    }
                    unsigned at = s->records++;
                    memcpy(s->record_name[at], kw, n);
                    s->record_name[at][n] = 0;
                    s->record_exported[at] = exported;
                    /* The header is required to open its parameter list on its
                     * own line above, so the list runs to the end of the line
                     * and no wrapping can hide a parameter from this scan. The
                     * return type is `->u64` and every parameter is `name:u64`
                     * or `name:buf<u8>`, so the two tokens below can only be
                     * parameters; neither appears in a body. */
                    s->record_memory[at] =
                        find_token(line + k, len - k, "base:u64", 8) != 0;
                    s->record_segment[at] =
                        find_token(line + k, len - k, "segment:u64", 11) != 0;
                    if (exported) {
                        if (s->exports >= SURF_MAX_RECORDS) {
                            snprintf(s->scan_error, sizeof s->scan_error,
                                     "the module has more exports than the SURF_MAX_RECORDS "
                                     "ceiling of %u, export %u is not counted",
                                     (unsigned)SURF_MAX_RECORDS, s->exports + 1);
                            return 0;
                        }
                        memcpy(s->export_name[s->exports++], s->record_name[at], n + 1);
                    }
                    current = (int)at;
                }
            }
        }
        for (size_t j = k; j < len;) {
            if (line[j] == '/' && j + 1 < len && line[j + 1] == '/') break;
            if (line[j] == '"') {
                if (s->literals >= SURF_MAX_LITERALS) {
                    snprintf(s->scan_error, sizeof s->scan_error,
                             "the module has more literals than the SURF_MAX_LITERALS ceiling "
                             "of %u, literal %u is not counted",
                             (unsigned)SURF_MAX_LITERALS, s->literals + 1);
                    return 0;
                }
                unsigned at = s->literals++;
                size_t n = 0;
                j++;
                /* A literal longer than the field truncates, and that is not
                 * fail-open here: the truncated value is still matched against
                 * the manifest below and matches none of its entries, so it is
                 * reported as an unknown literal instead of passing. */
                while (j < len && line[j] != '"' && n + 1 < SURF_NAME_MAX) s->literal[at][n++] = line[j++];
                s->literal[at][n] = 0;
                s->literal_owner[at] = current;
                if (j < len && line[j] == '"') j++;
                continue;
            }
            if (line[j] == '{') depth++;
            else if (line[j] == '}' && depth) depth--;
            j++;
        }
        line = nl ? nl + 1 : line + len;
    }
    return depth == 0;
}

/* One entry per export of x64_fixed: the export name, and the exact set of
 * mnemonics its body dispatches on. An empty list is an export that takes no
 * name, so the lowerer owns the spelling and routes to it by role instead. */
typedef struct {
    const char *export_name;
    const char *mnemonics;
    /* 1 when the parameter list of this export carries `segment:u64`, the
     * fs/gs channel the native modrm() honours. Declared here rather than
     * read off the module so that gaining or losing the parameter is a
     * disagreement the gate reports, not a silent change of behaviour. */
    int takes_segment;
} SurfaceManifest;

static const SurfaceManifest surface_manifest[] = {
    {"encode", "nop pause ud2 cpuid cbw cwde cdqe cwd cdq cqo pushfq popfq rdtsc lfence sfence "
               "mfence cli sti hlt swapgs rdmsr wrmsr syscall sysretq iretq ret return", 0},
    {"encode_rr", "mov add or adc sbb and sub xor cmp", 0},
    {"encode_ri", "mov add or adc sbb and sub xor cmp", 0},
    {"encode_unary", "inc dec not neg mul div idiv", 0},
    {"encode_shift_imm", "rol ror shl shr sar", 0},
    {"encode_control", "call jmp", 0},
    {"encode_stack", "push pop", 0},
    {"encode_jcc", "jo jno jb jae je jne jbe ja js jns jp jnp jl jge jle jg", 0},
    {"encode_mov_memory", "", 1},
    {"encode_lea", "", 1},
    {"encode_shift_cl", "rol ror shl shr sar", 0},
    {"encode_xchg", "xchg", 1},
    {"encode_cmov", "cmove cmovne cmovb cmovae cmovbe cmova cmovs cmovns cmovp cmovnp cmovl cmovge "
                    "cmovle cmovg cmovo cmovno", 1},
    {"encode_bit_scan", "bsf bsr", 1},
    {"encode_bit_test", "bt bts btr btc", 1},
    {"encode_descriptor", "sgdt sidt lgdt lidt", 1},
    {"encode_system_one", "ltr invlpg", 1},
    {"encode_binary", "mov load store test read_cr write_cr in out add or adc sbb and sub xor cmp", 1},
    {"encode_move_convert", "movzx movsx movsxd", 1},
    {"encode_test_two", "test", 1},
    {"encode_imul", "imul", 1},
    {"encode_setcc", "sete setne setb setae setbe seta sets setns setp setnp setl setge setle setg seto setno", 0},
    {"encode_bswap", "bswap", 0},
    {"encode_unary_operand", "inc dec not neg mul div idiv", 1},
    {"encode_setcc_operand", "sete setne setb setae setbe seta sets setns setp setnp setl setge setle setg seto setno", 1},
    {"encode_stack_memory", "push pop", 1},
    {"encode_shift_memory", "rol ror shl shr sar", 1},
    {"encode_control_memory", "call jmp", 1},
};
#define SURFACE_MANIFEST_COUNT (sizeof surface_manifest / sizeof *surface_manifest)

/* A mnemonic the module dispatches on, with no row, because it is a spelling
 * of a row mnemonic rather than an encoder capability of its own. The target
 * must carry rows, and tests_ntasm_x64_fixed.c pins the two spellings produce
 * the same length and the same bytes, so the declaration is a proof and not a
 * way to park a hole. */
static const char *const alias_manifest[][2] = {{"return", "ret"}};
#define ALIAS_MANIFEST_COUNT (sizeof alias_manifest / sizeof *alias_manifest)

/* A row mnemonic no export of x64_fixed names, so no export can match it. The
 * closure check proves the absence against the module text on every run; the
 * reason printed here is what the absence means for the encoder.
 *
 * This list used to be seven names long and hand-kept, which made it the one
 * set in the gate that was not derived from either surface: every other set is
 * a bijection against a scanned text, and this one was whatever a reader
 * remembered to copy down. It was short by twelve. oracle_closed below closes
 * it against the encoder's own alphabet, in both directions, so the list can
 * no longer be padded with a name the encoder has forgotten and no longer miss
 * a name the encoder can emit. */
/* imul left this list when the encode_imul export landed; the closure check
 * below is what proved the move was owed rather than merely made. Before it,
 * "imul is declared absent" and "imul is a literal of the module" were both
 * true at once, and the gate said so by name instead of choosing one. */
static const char *const *absent_manifest = NULL;
static const unsigned ABSENT_MANIFEST_COUNT = 0;


/* A row mnemonic no export names because no export takes a name at all: the
 * lowerer spells these and routes them to a manifest entry with an empty
 * mnemonic list. */
static const char *const pseudo_manifest[][2] = {
    {"lea", "encode_lea"},
};
#define PSEUDO_MANIFEST_COUNT (sizeof pseudo_manifest / sizeof *pseudo_manifest)

/* A mnemonic x64_fixed dispatches on, for which no kind 32 node exists at all:
 * the parser gives it a statement form that x64_lower_control owns, so the
 * instruction lowerer never sees it and a drift row would compare a statement
 * against an instruction. The declaration is re-derived on every run by
 * statement_cases instead of being trusted: the raw spelling must make the
 * instruction lowerer emit no instruction at all. A later lowerer that reaches
 * one of them makes the check fail, which is the point: the owner then owes the
 * table a real row. */
static const char *const statement_manifest[] = {"call", "jmp"};
#define STATEMENT_MANIFEST_COUNT (sizeof statement_manifest / sizeof *statement_manifest)

/* ------------------------------------------------- the encoder's own side --
 * Every check above closes over x64_fixed. The half the drift table is really
 * about is the other side of the pair: a form `nt_x64_encode` emits and the
 * lowerer cannot reach is the defect the table exists to name, and until this
 * block nothing in the gate asked the encoder what its own alphabet was. The
 * absent list was hand-kept for that, and it was short by twelve.
 *
 * The scan is a generator, never an authority: it offers every identifier
 * literal of x64.c, split on the '|' the oracle's own member() splits on, and
 * oracle_encodes below decides which of them the encoder really knows. So the
 * set this gate closes over is the oracle's answer, taken at run time from the
 * C the rows already compare against, and not a list someone wrote down. */
#define ORACLE_MAX_NAMES 256
#define ORACLE_NAME_MAX 40
/* Direction four walks the tokens the candidate filter *turned away*, so those
 * are a list with a ceiling of their own rather than a number. The field has to
 * hold a sentence as well as a name, because the longest token the filter
 * refuses in x64.c today is the 32 character diagnostic "high 8-bit register
 * requires no REX", and asking the encoder about that token is the point. */
#define ORACLE_MAX_REFUSED 256
#define ORACLE_REFUSED_MAX 72
/* The alphanumeric character constants in code regions, with the offset each
 * was read at. A name spelled one character at a time is the one assembly
 * shape a literal scan cannot rule out by reading, so its sites are counted
 * and pinned rather than left to prose. */
#define ORACLE_MAX_CHAR_SITES 16

typedef struct {
    unsigned names;
    char name[ORACLE_MAX_NAMES][ORACLE_NAME_MAX];
    unsigned refused;
    char refused_name[ORACLE_MAX_REFUSED][ORACLE_REFUSED_MAX];
    unsigned char_sites;
    size_t char_offset[ORACLE_MAX_CHAR_SITES];
    char char_value[ORACLE_MAX_CHAR_SITES];
    char scan_error[SURF_ERROR_MAX];
} Oracle;

/* Whether the encoder names this mnemonic at all. The two arguments are the
 * only pair that keeps both pre-checks in nt_x64_encode from answering before
 * the name is looked at: count must not exceed three and cpl must not exceed
 * three. Every branch of variable() tests its operand count before it touches
 * an operand, so a known name answers its own count or width diagnostic and a
 * name the encoder does not have falls through to NT_X64_UNKNOWN and nothing
 * else. The count is a zero, not a spelling, because no operand vector has to
 * be right for the answer to be about the name. */
static int oracle_encodes(const char *name) {
    NtX64Instruction x = {0};
    NtX64Context context = {NT_X64_ALL_FEATURES, 3};
    return nt_x64_encode(name, 0, 0, context, &x) != NT_X64_UNKNOWN;
}

static int oracle_candidate(const char *s, size_t n) {
    /* Two characters or more, so the single letters the C text carries are not
     * offered, and lower case letters, digits and the underscore only, so the
     * diagnostic sentences in the same file are not. */
    if (n < 2) return 0;
    for (size_t k = 0; k < n; k++) {
        char c = s[k];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_')) return 0;
    }
    return 1;
}

/* What the candidate filter turns away, kept rather than dropped. A token the
 * filter rejects is invisible to every direction of the closure, and the filter
 * is exactly where a name that exists in neither view as a literal goes
 * missing: a mnemonic spelled with a byte the filter does not accept is
 * offered by nothing and accounted for by nothing, and the axis reports
 * holes=0 over an alphabet short by it. So the refusals are a list, the
 * closure asks the encoder about every one of them, and a refusal the encoder
 * answers for is a hole. */
static void oracle_refuse(Oracle *o, const char *s, size_t n) {
    for (unsigned k = 0; k < o->refused; k++)
        if (!strncmp(o->refused_name[k], s, n) && !o->refused_name[k][n]) return;
    if (n >= ORACLE_REFUSED_MAX) {
        snprintf(o->scan_error, sizeof o->scan_error,
                 "a refused token of %zu bytes is past the ORACLE_REFUSED_MAX of %u, so it is "
                 "neither offered nor accounted for",
                 n, (unsigned)ORACLE_REFUSED_MAX);
        return;
    }
    if (o->refused >= ORACLE_MAX_REFUSED) {
        snprintf(o->scan_error, sizeof o->scan_error,
                 "the encoder text refuses more names than the ORACLE_MAX_REFUSED ceiling of %u, "
                 "refusal %u is not counted",
                 (unsigned)ORACLE_MAX_REFUSED, o->refused + 1);
        return;
    }
    memcpy(o->refused_name[o->refused], s, n);
    o->refused_name[o->refused][n] = 0;
    o->refused++;
}

/* The C library calls that write into a caller buffer. A mnemonic assembled by
 * one of these is the residual the report named: it is invisible to a scan
 * that reads literals and visible to a probe that calls the compiled encoder,
 * so it passes between the two views. The scan does not parse which of them
 * writes a name and must not have to: any of them in the encoder text means
 * some name is no longer a literal, so the alphabet the closure runs over is
 * no longer the encoder's own. The scan therefore names the call and refuses,
 * and the refusal is a refusal of the scan, never of the encoder. */
static int oracle_builder(const char *s, size_t n) {
    static const char *const builders[] = {"snprintf", "sprintf",  "vsnprintf", "vsprintf",
                                           "strcpy",   "strncpy", "strcat",    "strncat",
                                           "strlcpy",  "strlcat", "stpcpy",    "memcpy",
                                           "memmove",  "bcopy",   "wcscpy",    "wcscat"};
    for (unsigned k = 0; k < sizeof builders / sizeof *builders; k++) {
        size_t m = strlen(builders[k]);
        if (m == n && !memcmp(builders[k], s, n)) return 1;
    }
    return 0;
}

/* A character constant in a code region is how a name is spelled one byte at a
 * time. The two the file carries are the '|' member separator and the 'j' of
 * the n[0]=='j' branch, and neither spells a name. They are counted rather
 * than dismissed so the count is a measurement: a third alphanumeric one is a
 * name the scan cannot see, and it goes red by being counted rather than by a
 * human reading the file and noticing. */
static void oracle_char_site(Oracle *o, size_t at, char value) {
    if (!((value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') ||
          (value >= '0' && value <= '9')))
        return;
    if (o->char_sites >= ORACLE_MAX_CHAR_SITES) {
        snprintf(o->scan_error, sizeof o->scan_error,
                 "the encoder text carries more alphanumeric character constants than the "
                 "ORACLE_MAX_CHAR_SITES ceiling of %u, site %u is not counted",
                 (unsigned)ORACLE_MAX_CHAR_SITES, o->char_sites + 1);
        return;
    }
    o->char_offset[o->char_sites] = at;
    o->char_value[o->char_sites] = value;
    o->char_sites++;
}

static void oracle_offer(Oracle *o, const char *s, size_t n) {
    for (unsigned k = 0; k < o->names; k++)
        if (!strncmp(o->name[k], s, n) && !o->name[k][n]) return;
    if (o->names >= ORACLE_MAX_NAMES) {
        snprintf(o->scan_error, sizeof o->scan_error,
                 "the encoder text offers more names than the ORACLE_MAX_NAMES ceiling of %u, "
                 "offer %u is not counted",
                 (unsigned)ORACLE_MAX_NAMES, o->names + 1);
        return;
    }
    memcpy(o->name[o->names], s, n);
    o->name[o->names][n] = 0;
    o->names++;
}

/* The comment states are honoured, so a name quoted in a doc comment is not
 * offered. An unterminated literal refuses the scan rather than ending it: a
 * quote the scan cannot close is a text it has not read, and reading half of
 * one is a smaller alphabet that still looks closed.
 *
 * The same argument now covers the three ways a name stops being one literal
 * while the compiler still sees one: a backslash inside it, a second literal
 * concatenated onto it, and a builder call that writes a name the scan never
 * held. Each refuses the scan by naming itself and its offset, because each is
 * a name the text view does not have and the probe does. */
static int oracle_scan(const char *text, size_t n, Oracle *o) {
    memset(o, 0, sizeof *o);
    for (size_t k = 0; k < n;) {
        if (text[k] == '/' && k + 1 < n && text[k + 1] == '/') {
            while (k < n && text[k] != '\n') k++;
            continue;
        }
        if (text[k] == '/' && k + 1 < n && text[k + 1] == '*') {
            k += 2;
            while (k + 1 < n && !(text[k] == '*' && text[k + 1] == '/')) k++;
            if (k + 1 >= n) {
                snprintf(o->scan_error, sizeof o->scan_error,
                         "the encoder text opens a block comment it never closes");
                return 0;
            }
            k += 2;
            continue;
        }
        /* A character constant, read whole so a quote inside one does not open
         * a string, and counted when it is alphanumeric. */
        if (text[k] == '\'') {
            size_t j = k + 1;
            char value = 0;
            if (j < n && text[j] == '\\') {
                if (j + 1 < n) value = text[j + 1];
                j += 2;
            } else if (j < n) {
                value = text[j];
                j += 1;
            }
            if (j < n && text[j] == '\'') j++;
            oracle_char_site(o, k, value);
            k = j;
            continue;
        }
        /* A builder call. The identifier is read whole so `xsnprintf` does not
         * match, and the '(' is required so a variable named `sprintf` does
         * not either. */
        if ((text[k] >= 'a' && text[k] <= 'z') || (text[k] >= 'A' && text[k] <= 'Z') ||
            text[k] == '_') {
            size_t j = k;
            while (j < n && ident_char(text[j])) j++;
            if (j < n && text[j] == '(' && oracle_builder(text + k, j - k)) {
                snprintf(o->scan_error, sizeof o->scan_error,
                         "the encoder text calls %.*s at offset %zu, so a name can be assembled at "
                         "run time and the literal alphabet is no longer the encoder's own",
                         (int)(j - k), text + k, k);
                return 0;
            }
            k = j;
            continue;
        }
        if (text[k] != '"') {
            k++;
            continue;
        }
        size_t start = k + 1, j = start;
        while (j < n && text[j] != '"' && text[j] != '\n') {
            /* A backslash means the bytes the compiler sees are not the bytes
             * the scan reads, so this is not the literal that reaches the
             * comparison and offering its half would be offering a name the
             * encoder never sees. */
            if (text[j] == '\\') {
                snprintf(o->scan_error, sizeof o->scan_error,
                         "the encoder text opens an escaped byte at offset %zu inside a string "
                         "literal, and the bytes it names are not the bytes a scan reads",
                         j);
                return 0;
            }
            j++;
        }
        if (j >= n || text[j] != '"') {
            snprintf(o->scan_error, sizeof o->scan_error,
                     "the encoder text opens a string literal at offset %zu it never closes",
                     start - 1);
            return 0;
        }
        size_t p = start;
        for (size_t q = start; q <= j; q++)
            if (q == j || text[q] == '|') {
                if (oracle_candidate(text + p, q - p)) oracle_offer(o, text + p, q - p);
                else oracle_refuse(o, text + p, q - p);
                p = q + 1;
            }
        /* A second literal, whitespace and comments apart, is one string to the
         * compiler and two to the scan. The scan has just offered the first
         * half, so the name the encoder compares against is not in the alphabet
         * it offered, which is the residual in its shortest form. */
        k = j + 1;
        for (;;) {
            while (k < n && (text[k] == ' ' || text[k] == '\t' || text[k] == '\r' ||
                             text[k] == '\n'))
                k++;
            if (k + 1 < n && text[k] == '/' && text[k + 1] == '/') {
                while (k < n && text[k] != '\n') k++;
                continue;
            }
            if (k + 1 < n && text[k] == '/' && text[k + 1] == '*') {
                k += 2;
                while (k + 1 < n && !(text[k] == '*' && text[k + 1] == '/')) k++;
                if (k + 1 >= n) {
                    snprintf(o->scan_error, sizeof o->scan_error,
                             "the encoder text opens a block comment it never closes");
                    return 0;
                }
                k += 2;
                continue;
            }
            break;
        }
        if (k < n && text[k] == '"') {
            snprintf(o->scan_error, sizeof o->scan_error,
                     "the encoder text concatenates a second string literal at offset %zu onto the "
                     "one above, and the scan offers the halves rather than the name",
                     k);
            return 0;
        }
    }
    if (o->scan_error[0]) return 0;
    return 1;
}

static int manifest_index(const char *name) {
    for (unsigned k = 0; k < SURFACE_MANIFEST_COUNT; k++)
        if (!strcmp(surface_manifest[k].export_name, name)) return (int)k;
    return -1;
}

static int list_has(const char *list, const char *name) {
    size_t n = strlen(name);
    for (const char *p = list; *p;) {
        while (*p == ' ') p++;
        const char *q = p;
        while (*q && *q != ' ') q++;
        if ((size_t)(q - p) == n && !memcmp(p, name, n)) return 1;
        p = q;
    }
    return 0;
}

static int list_size(const char *list) {
    int n = 0;
    for (const char *p = list; *p; p++)
        if (*p == ' ') n++;
    return n ? n + 1 : (*list ? 1 : 0);
}

static const char *module_text;
static size_t module_len;
/* The text of the C encoder the rows already compare against, loaded by main
 * from the same file the oracle object is compiled from. The gate reads that
 * text rather than a table because the one set in this gate that was a table
 * was the set that turned out to be short. */
static const char *oracle_source;
static size_t oracle_source_len;
static char row_mnemonic[ROW_MAX][SURF_NAME_MAX];
static char row_spelling[ROW_MAX][SPELLING_MAX];
static unsigned row_count;

static void row_record(const char *m, const char *s) {
    if (row_count >= ROW_MAX) {
        failures++;
        fprintf(stderr, "FAIL drift row registry overflow\n");
        return;
    }
    snprintf(row_mnemonic[row_count], SURF_NAME_MAX, "%s", m);
    snprintf(row_spelling[row_count], SPELLING_MAX, "%s", s);
    row_count++;
}

static int row_has_mnemonic(const char *m) {
    for (unsigned k = 0; k < row_count; k++)
        if (!strcmp(row_mnemonic[k], m)) return 1;
    return 0;
}

/* The encoder side of the same bijection surface_closed closes on the module
 * side, and it is the axis the pinned 177-row equation could never see: an
 * equation is satisfied by any set of rows that adds up, including one that
 * never mentions a mnemonic the encoder can emit.
 *
 * Four directions now, and all four are needed. The first is the absence one
 * this axis exists for. The second is what keeps the first honest: a list
 * padded with a name the encoder has dropped is a hole too, and without it a
 * list could be made to pass by growing. The third is the module naming a
 * mnemonic the oracle refuses, which no count of rows can see either. The
 * fourth is the one this wave added and it is the only one that looks at the
 * tokens the scan *refused*: a name the candidate filter turned away was
 * offered by nothing, so before the refusals were kept it was accounted for by
 * nothing either, and a mnemonic reachable only through one passed between the
 * two views as a silent gap rather than a hole. Taken together they cannot be
 * satisfied by a scan that found nothing, so the check is not vacuous when the
 * scan is empty.
 *
 * `withheld` hides one live name from every accounting path, and the live
 * scan runs with it null. The gate calls it once more with a real name to show
 * the accounting predicate is reached over the live alphabet and not only
 * over a fixture. It touches no global the module-side closure counts, so the
 * two calls cannot disturb each other. */
static unsigned oracle_closed(const Oracle *o, const Surface *s, const char *tag,
                              const char *withheld) {
    unsigned holes = 0;
#define OHOLE(...)                                                                                   \
    do {                                                                                            \
        holes++;                                                                                    \
        fprintf(stderr, "OH[%s] ", tag);                                                            \
        fprintf(stderr, __VA_ARGS__);                                                               \
        fprintf(stderr, "\n");                                                                       \
    } while (0)
    for (unsigned k = 0; k < o->names; k++) {
        const char *name = o->name[k];
        if (!oracle_encodes(name)) continue;
        if (withheld && !strcmp(name, withheld)) {
            OHOLE("the encoder can encode \"%s\" and the drift table was made to forget it", name);
            continue;
        }
        int accounted = row_has_mnemonic(name);
        for (unsigned a = 0; a < ALIAS_MANIFEST_COUNT && !accounted; a++)
            if (!strcmp(alias_manifest[a][0], name)) accounted = 1;
        for (unsigned a = 0; a < STATEMENT_MANIFEST_COUNT && !accounted; a++)
            if (!strcmp(statement_manifest[a], name)) accounted = 1;
        for (unsigned a = 0; a < PSEUDO_MANIFEST_COUNT && !accounted; a++)
            if (!strcmp(pseudo_manifest[a][0], name)) accounted = 1;
        for (unsigned a = 0; a < ABSENT_MANIFEST_COUNT && !accounted; a++)
            if (!strcmp(absent_manifest[a], name)) accounted = 1;
        if (!accounted)
            OHOLE("the encoder can encode \"%s\" and no row, alias, statement-owned spelling, "
                  "pseudo spelling or declared absence names it",
                  name);
    }
    for (unsigned a = 0; a < ABSENT_MANIFEST_COUNT; a++) {
        if (!oracle_encodes(absent_manifest[a]))
            OHOLE("absent \"%s\" is declared but the encoder does not know the name",
                  absent_manifest[a]);
        int offered = 0;
        for (unsigned k = 0; k < o->names; k++)
            if (!strcmp(o->name[k], absent_manifest[a])) offered = 1;
        if (!offered)
            OHOLE("absent \"%s\" is a name the encoder text does not offer, so the scan has lost it",
                  absent_manifest[a]);
    }
    for (unsigned k = 0; k < s->literals; k++)
        if (!oracle_encodes(s->literal[k]))
            OHOLE("x64_fixed dispatches on \"%s\" and the encoder does not know the name", s->literal[k]);
    /* The fourth direction, and the one the residual asked for. A token the
     * candidate filter refused is a token the scan read and did not offer, so
     * the first three directions cannot see it: it is neither a name the
     * encoder answered for, nor a declared absence, nor a module literal. If
     * the encoder does answer for it, the mnemonic is reachable and named by
     * nothing, and the axis was reporting holes=0 over an alphabet short by
     * exactly it. Every refusal is asked about, so the filter cannot be a
     * place a name goes missing without a hole naming it. */
    for (unsigned k = 0; k < o->refused; k++) {
        const char *token = o->refused_name[k];
        if (!oracle_encodes(token)) continue;
        if (withheld && !strcmp(token, withheld)) {
            OHOLE("the encoder can encode the refused token \"%s\" and the drift table was made "
                  "to forget it", token);
            continue;
        }
        OHOLE("the encoder can encode \"%s\" and the candidate filter refused the token, so no "
              "row, alias, statement-owned spelling, pseudo spelling or declared absence could "
              "name it", token);
    }
    return holes;
}

static unsigned oracle_alphabet_size(const Oracle *o) {
    unsigned n = 0;
    for (unsigned k = 0; k < o->names; k++)
        if (oracle_encodes(o->name[k])) n++;
    return n;
}

/* How many names the encoder answers for exist only where the scan cannot look:
 * as a token the candidate filter refused, or as a proper prefix of one it
 * offered that the alphabet holds nowhere. Both are the residual stated as a
 * number rather than a sentence.
 *
 * The prefix direction exists because the character-constant site x64.c
 * carries is a prefix test, `n[0]=='j'` at x64.c:961, and a prefix test is the
 * one place an encoder can be handed a name it never matched a literal for. An
 * earlier version of this function probed each site as a one byte mnemonic
 * instead, and that was a check which could not fail: no mnemonic on this
 * target is one byte long, so the answer was always "no" and the zero said
 * nothing at all about the encoder. A prefix is reachable, a one byte name is
 * not, so the direction is the prefixes.
 *
 * The predicate is deliberately narrow. A prefix the encoder answers for is
 * not by itself a hole: `bt` is a proper prefix of `btr`, and `bt` is a
 * mnemonic in its own right with a literal of its own, so it is offered and
 * accounted for like any other name. What is a hole is a prefix the alphabet
 * holds nowhere, offered by no literal and refused by no token either, because
 * then no direction of the closure can see it at all. That is the only thing
 * counted here, and it is counted over the live scan on every run.
 *
 * It is a count rather than a boolean so a scan that offered nothing is
 * distinguishable from one whose names are all clean: the difference between
 * "this axis measured nothing" and "this axis measured and found nothing". */
static unsigned oracle_assembled(const Oracle *o, const char *tag) {
    unsigned assembled = 0;
    for (unsigned k = 0; k < o->refused; k++)
        if (oracle_encodes(o->refused_name[k])) {
            assembled++;
            fprintf(stderr, "AH[%s] the encoder answers for \"%s\", which exists only as a token "
                            "the candidate filter refused\n", tag, o->refused_name[k]);
        }
    for (unsigned k = 0; k < o->names; k++) {
        size_t length = strlen(o->name[k]);
        for (size_t p = 1; p < length; p++) {
            char prefix[ORACLE_NAME_MAX];
            memcpy(prefix, o->name[k], p);
            prefix[p] = 0;
            if (!oracle_encodes(prefix)) continue;
            int held = 0;
            for (unsigned a = 0; a < o->names && !held; a++)
                if (!strcmp(o->name[a], prefix)) held = 1;
            for (unsigned a = 0; a < o->refused && !held; a++)
                if (!strcmp(o->refused_name[a], prefix)) held = 1;
            if (held) continue;
            assembled++;
            fprintf(stderr, "AH[%s] the encoder answers for \"%s\", a proper prefix of the offered "
                            "name \"%s\" that the alphabet holds nowhere, so no direction of the "
                            "closure can see it\n", tag, prefix, o->name[k]);
        }
    }
    return assembled;
}

/* The executed rows and the manifest must be the same list in the same order.
 * Kept as a pure comparison so both directions, a row deleted from the table
 * and a row added to it, are pinned here directly. */
static int rows_match(const char *const *executed, unsigned n, const char *const *declared, unsigned m) {
    if (n != m) return 0;
    for (unsigned k = 0; k < n; k++)
        if (strcmp(executed[k], declared[k])) return 0;
    return 1;
}

/* Returns the number of holes. Every hole is printed with its own name, so a
 * future encoder cannot be added without the gate saying which set it missed. */
static unsigned segment_memory_exports, segment_memory_exports_with_channel;
/* The live scan's two counts, carried out of surface_cases because the
 * CHECK that pins them runs in drift_surface, after it. */
static unsigned live_segment_exports, live_with_channel;

static unsigned surface_closed(const Surface *s, const char *tag) {
    unsigned holes = 0;
    /* Reset per scan: surface_closed also runs for the fourteen mutants,
     * and a counter that accumulated across them would pin nothing. The
     * live scan runs first, so live_segment_exports keeps its value. */
    segment_memory_exports = 0;
    segment_memory_exports_with_channel = 0;
#define HOLE(...)                                                                                    \
    do {                                                                                            \
        holes++;                                                                                    \
        fprintf(stderr, "HOLE[%s] ", tag);                                                         \
        fprintf(stderr, __VA_ARGS__);                                                              \
        fprintf(stderr, "\n");                                                                      \
    } while (0)
    if (s->exports != SURFACE_MANIFEST_COUNT)
        HOLE("the module has %u exports, the manifest declares %u", s->exports,
             (unsigned)SURFACE_MANIFEST_COUNT);
    for (unsigned k = 0; k < s->exports; k++)
        if (manifest_index(s->export_name[k]) < 0)
            HOLE("export %s is not in the manifest", s->export_name[k]);
    for (unsigned k = 0; k < SURFACE_MANIFEST_COUNT; k++) {
        int found = 0;
        for (unsigned e = 0; e < s->exports; e++)
            if (!strcmp(s->export_name[e], surface_manifest[k].export_name)) found = 1;
        if (!found) HOLE("manifest export %s is not in the module", surface_manifest[k].export_name);
    }
    for (unsigned k = 0; k < s->literals; k++) {
        int owner = s->literal_owner[k];
        if (owner < 0 || !s->record_exported[owner]) {
            HOLE("literal \"%s\" is outside every export body", s->literal[k]);
            continue;
        }
        int m = manifest_index(s->record_name[owner]);
        if (m < 0) continue;
        if (!list_has(surface_manifest[m].mnemonics, s->literal[k]))
            HOLE("literal \"%s\" is in %s but the manifest does not list it", s->literal[k],
                 s->record_name[owner]);
    }
    for (unsigned k = 0; k < SURFACE_MANIFEST_COUNT; k++) {
        const char *list = surface_manifest[k].mnemonics;
        int seen = 0;
        for (const char *p = list; *p;) {
            while (*p == ' ') p++;
            const char *q = p;
            while (*q && *q != ' ') q++;
            char one[SURF_NAME_MAX];
            size_t n = (size_t)(q - p);
            if (n && n + 1 < SURF_NAME_MAX) {
                memcpy(one, p, n);
                one[n] = 0;
                int found = 0;
                for (unsigned e = 0; e < s->literals; e++)
                    if (s->literal_owner[e] >= 0 && s->record_exported[s->literal_owner[e]] &&
                        !strcmp(s->record_name[s->literal_owner[e]], surface_manifest[k].export_name) &&
                        !strcmp(s->literal[e], one))
                        found = 1;
                if (!found) HOLE("manifest lists \"%s\" under %s but the body does not dispatch on it", one,
                                 surface_manifest[k].export_name);
            }
            seen++;
            p = q;
        }
        if (seen != list_size(list)) HOLE("the mnemonic list of %s is malformed",
                                          surface_manifest[k].export_name);
    }
    /* Every literal is a mnemonic the encoder can match, so it must be either
     * covered by a row, declared as an alias of one, or declared as a spelling
     * the parser never turns into a kind 32 node. This is the check the
     * bypass used to walk through. */
    for (unsigned k = 0; k < s->literals; k++) {
        const char *name = s->literal[k];
        if (row_has_mnemonic(name)) continue;
        int declared = 0;
        for (unsigned a = 0; a < ALIAS_MANIFEST_COUNT; a++)
            if (!strcmp(alias_manifest[a][0], name)) declared = 1;
        for (unsigned a = 0; a < STATEMENT_MANIFEST_COUNT; a++)
            if (!strcmp(statement_manifest[a], name)) declared = 1;
        if (!declared) HOLE("the module can encode \"%s\" and no drift row names it", name);
    }
    for (unsigned a = 0; a < STATEMENT_MANIFEST_COUNT; a++) {
        int literal = 0;
        for (unsigned k = 0; k < s->literals; k++)
            if (!strcmp(s->literal[k], statement_manifest[a])) literal = 1;
        if (!literal)
            HOLE("statement-owned \"%s\" is not a literal of the module", statement_manifest[a]);
    }
    for (unsigned a = 0; a < ALIAS_MANIFEST_COUNT; a++) {
        int literal = 0;
        for (unsigned k = 0; k < s->literals; k++)
            if (!strcmp(s->literal[k], alias_manifest[a][0])) literal = 1;
        if (!literal) HOLE("alias \"%s\" is not a literal of the module any more", alias_manifest[a][0]);
        if (row_has_mnemonic(alias_manifest[a][0]))
            HOLE("alias \"%s\" has rows, so the alias declaration is void", alias_manifest[a][0]);
        if (!row_has_mnemonic(alias_manifest[a][1]))
            HOLE("alias \"%s\" points at \"%s\", which has no row", alias_manifest[a][0],
                 alias_manifest[a][1]);
    }
    /* Every row mnemonic must be a literal, a pseudo spelling, or a declared
     * absence, so a row cannot invent a mnemonic the encoder never knew. */
    for (unsigned k = 0; k < row_count; k++) {
        const char *name = row_mnemonic[k];
        int literal = 0;
        for (unsigned e = 0; e < s->literals; e++)
            if (!strcmp(s->literal[e], name)) literal = 1;
        int pseudo = 0, absent = 0;
        for (unsigned p = 0; p < PSEUDO_MANIFEST_COUNT; p++)
            if (!strcmp(pseudo_manifest[p][0], name)) pseudo = 1;
        for (unsigned p = 0; p < ABSENT_MANIFEST_COUNT; p++)
            if (!strcmp(absent_manifest[p], name)) absent = 1;
        if (literal) {
            if (absent)
                HOLE("\"%s\" is declared absent but the module dispatches on it", name);
            if (pseudo) HOLE("pseudo \"%s\" must never reach the encoder", name);
            continue;
        }
        if (absent) continue;
        if (pseudo) {
            int m = -1;
            for (unsigned p = 0; p < PSEUDO_MANIFEST_COUNT; p++)
                if (!strcmp(pseudo_manifest[p][0], name)) m = manifest_index(pseudo_manifest[p][1]);
            if (m < 0 || surface_manifest[m].mnemonics[0])
                HOLE("pseudo \"%s\" does not name a manifest export that takes no mnemonic", name);
            continue;
        }
        HOLE("row mnemonic \"%s\" is not a literal of the module", name);
    }
    for (unsigned a = 0; a < ABSENT_MANIFEST_COUNT; a++) {
        for (unsigned k = 0; k < s->literals; k++)
            if (!strcmp(s->literal[k], absent_manifest[a]))
                HOLE("absent \"%s\" is a literal of the module", absent_manifest[a]);
        if (!row_has_mnemonic(absent_manifest[a]))
            HOLE("absent \"%s\" has no drift row", absent_manifest[a]);
    }
    /* The parameter axis. A memory export is one whose parameter list names
     * `base:u64`; every one of them owes the caller the fs/gs channel unless it
     * is declared here. This is the check the surface had no way to make, and
     * the reason the encode_lea gap survived every earlier wave: the closure
     * was over names and literals, so a lost parameter was not a hole in it. */
    for (unsigned k = 0; k < s->exports; k++) {
        const char *name = s->export_name[k];
        int record = -1;
        for (unsigned r = 0; r < s->records; r++)
            if (!strcmp(s->record_name[r], name)) record = (int)r;
        if (record < 0) continue;
        int m = manifest_index(name);
        if (m < 0) continue;
        int declared = surface_manifest[m].takes_segment;
        if (s->record_segment[record] != declared)
            HOLE("%s %s `segment:u64` but the manifest declares it %s", name,
                 s->record_segment[record] ? "takes" : "does not take",
                 declared ? "takes it" : "does not");
        if (!s->record_memory[record]) continue;
        segment_memory_exports++;
        if (s->record_segment[record]) segment_memory_exports_with_channel++;
        if (!s->record_segment[record])
            HOLE("%s is a memory export with no `segment:u64`: the oracle takes "
                 "rm->segment and this export cannot ask for one", name);
    }
#undef HOLE
    return holes;
}

static char *surface_splice(const char *anchor, const char *with) {
    size_t n = strlen(anchor);
    const char *at = 0;
    for (size_t k = 0; k + n <= module_len; k++)
        if (!memcmp(module_text + k, anchor, n)) {
            at = module_text + k;
            break;
        }
    if (!at) return 0;
    size_t head = (size_t)(at - module_text), tail = module_len - head - n, w = strlen(with);
    char *out = malloc(head + w + tail + 1);
    if (!out) return 0;
    memcpy(out, module_text, head);
    memcpy(out + head, with, w);
    memcpy(out + head + w, at + n, tail);
    out[head + w + tail] = 0;
    return out;
}

/* The same splice at the end of the module, for a mutant that only appends.
 * A mutant that has to cross the record ceiling must land after every real
 * header: if the header the old scan dropped is a real export, the closure
 * rejects the mutant for the export it lost rather than for the ceiling, and
 * the case stops being about what it claims to be about. */
static char *surface_append(const char *with) {
    size_t w = strlen(with);
    char *out = malloc(module_len + w + 1);
    if (!out) return 0;
    memcpy(out, module_text, module_len);
    memcpy(out + module_len, with, w);
    out[module_len + w] = 0;
    return out;
}

/* A mutant of the module text, spliced in memory. The closure has to reject
 * every one of them, so the check that keeps a future export out of the table
 * is itself pinned rather than assumed.
 *
 * "Reject" is the whole surface check, so it counts in two ways and both are
 * success: a mutant the scan reads but whose closure reports a hole, and a
 * mutant the scan itself refuses because it crosses a declared capacity. The
 * second kind used to be a gate failure instead, which meant a capacity the
 * scan refuses could not be pinned as a mutant at all; the two counters below
 * are what the announced count is checked against, so the number printed by
 * DRIFT-CLOSURE is the number of mutants that actually ran. */
static unsigned mutant_cases_run, mutant_cases_rejected;

static void mutant_verdict(const char *label, char *text, const char *no_text) {
    cases++;
    checks++;
    mutant_cases_run++;
    if (!text) {
        failures++;
        fprintf(stderr, "FAIL mutant %s: %s\n", label, no_text);
        return;
    }
    Surface m;
    int ok = surface_scan(text, &m);
    unsigned holes = ok ? surface_closed(&m, label) : 1u;
    if (ok && holes == 0) {
        failures++;
        fprintf(stderr, "FAIL mutant %s: the closure accepts a hole\n", label);
    } else {
        mutant_cases_rejected++;
        printf("MUTANT-REJECTED %2u/%2u %-52s by %s\n", mutant_cases_rejected,
               (unsigned)MUTANT_CASE_COUNT, label, ok ? "the closure" : "the scan capacity");
    }
    free(text);
}

static void mutant_case(const char *label, const char *anchor, const char *with) {
    mutant_verdict(label, surface_splice(anchor, with), "the anchor is no longer in the module");
}

/* The statement-owned declaration, re-derived instead of asserted: the raw
 * spelling must make the instruction lowerer emit no instruction at all. The
 * sixteen jcc rows above are the other half of this story and are real rows,
 * because the parser does hand those to kind 32 and the lowerer refuses them. */
static void statement_cases(const NovaHostImage *i) {
    for (unsigned k = 0; k < STATEMENT_MANIFEST_COUNT; k++) {
        char body[64];
        snprintf(body, sizeof body, "%s target", statement_manifest[k]);
        Run r = run(i, body, 1, 3);
        cases++;
        checks++;
        int emitted = r.runtime != 0 || (r.returned == 0 && r.out[0] != 0);
        for (unsigned b = 1; b < sizeof r.out; b++)
            if (r.out[b] != guard) emitted = 1;
        if (emitted) {
            failures++;
            fprintf(stderr, "FAIL closure %s is declared statement-owned but the lowerer emitted an "
                            "instruction (ret=%llu)\n",
                    statement_manifest[k], (unsigned long long)r.returned);
        } else {
            printf("DRIFT-STMT %-6s %-30s no kind 32 node, lowerer emitted nothing (ret=%llu)\n",
                   statement_manifest[k], body, (unsigned long long)r.returned);
        }
    }
}

/* The rows the detector claims to cover, one `mnemonic|spelling` per
 * executed drift row, in execution order. The sum of the three counters
 * cannot notice a dropped row on its own, so the executed rows are closed
 * against this independent list: a row deleted from the table, a row added
 * to it, and a row whose spelling changed are all a mismatch, and they stay
 * a mismatch when the three counters are edited to agree with the loss. */
static const char *const row_manifest[] = {

    "nop|nop", "pause|pause", "ud2|ud2",
    "cpuid|cpuid", "cbw|cbw", "cwde|cwde",
    "cdqe|cdqe", "cwd|cwd", "cdq|cdq",
    "cqo|cqo", "pushfq|pushfq", "popfq|popfq",
    "rdtsc|rdtsc", "lfence|lfence", "sfence|sfence",
    "mfence|mfence", "cli|cli", "sti|sti",
    "hlt|hlt", "swapgs|swapgs", "rdmsr|rdmsr",
    "wrmsr|wrmsr", "syscall|syscall", "sysretq|sysretq",
    "iretq|iretq", "ret|ret", "mov|mov rax,rbx",
    "add|add rax,rbx", "or|or rax,rbx", "adc|adc rax,rbx",
    "sbb|sbb rax,rbx", "and|and rax,rbx", "sub|sub rax,rbx",
    "xor|xor rax,rbx", "cmp|cmp rax,rbx", "mov|mov rax,1",
    "add|add rax,1", "or|or rax,1", "adc|adc rax,1",
    "sbb|sbb rax,1", "and|and rax,1", "sub|sub rax,1",
    "xor|xor rax,1", "cmp|cmp rax,1", "load|load rax,[rbx+8]:ptr<user,u64>",
    "store|store [rbx+8]:ptr<kernel,u64>,rax", "lea|lea rax,[rbx]:ptr<user,u64>", "rol|rol rax,cl",
    "ror|ror rax,cl", "shl|shl rax,cl", "shr|shr rax,cl",
    "sar|sar rax,cl", "inc|inc rax", "dec|dec rax",
    "not|not rax", "neg|neg rax", "rol|rol rax,1",
    "ror|ror rax,1", "shl|shl rax,1", "shr|shr rax,1",
    "sar|sar rax,1", "push|push rax", "pop|pop rax",
    "push|push 1", "jo|jo target\ntarget:", "jno|jno target\ntarget:",
    "jb|jb target\ntarget:", "jae|jae target\ntarget:", "je|je target\ntarget:",
    "jne|jne target\ntarget:", "jbe|jbe target\ntarget:", "ja|ja target\ntarget:",
    "js|js target\ntarget:", "jns|jns target\ntarget:", "jp|jp target\ntarget:",
    "jnp|jnp target\ntarget:", "jl|jl target\ntarget:", "jge|jge target\ntarget:",
    "jle|jle target\ntarget:", "jg|jg target\ntarget:", "sete|sete al",
    "setne|setne al", "setb|setb al", "setae|setae al",
    "setbe|setbe al", "seta|seta al", "sets|sets al",
    "setns|setns al", "setp|setp al", "setnp|setnp al",
    "setl|setl al", "setge|setge al", "setle|setle al",
    "setg|setg al", "seto|seto al", "setno|setno al",
    "xchg|xchg rax,rbx", "test|test rax,rbx", "cmove|cmove rax,rbx",
    "cmovne|cmovne rax,rbx", "cmovb|cmovb rax,rbx", "cmovae|cmovae rax,rbx",
    "cmovbe|cmovbe rax,rbx", "cmova|cmova rax,rbx", "cmovs|cmovs rax,rbx",
    "cmovns|cmovns rax,rbx", "cmovp|cmovp rax,rbx", "cmovnp|cmovnp rax,rbx",
    "cmovl|cmovl rax,rbx", "cmovge|cmovge rax,rbx", "cmovle|cmovle rax,rbx",
    "cmovg|cmovg rax,rbx", "cmovo|cmovo rax,rbx", "cmovno|cmovno rax,rbx",
    "bsf|bsf rax,rbx", "bsr|bsr rax,rbx", "movzx|movzx eax,al",
    "movsx|movsx eax,al", "movsxd|movsxd rax,eax", "xchg|xchg rax,[rbx+8]:ptr<user,u64>",
    "cmovne|cmovne eax,[rbx+8]:ptr<user,u32>", "bsr|bsr rax,[rbx+8]:ptr<user,u64>", "movzx|movzx eax,[rbx+8]:ptr<user,u8>",
    "movsx|movsx eax,[rbx+8]:ptr<user,u8>", "movsxd|movsxd rax,[rbx+8]:ptr<user,u32>", "test|test [rbx+8]:ptr<user,u64>,rax",
    "add|add rax,[rbx+8]:ptr<user,u64>", "add|add [rbx+8]:ptr<user,u64>,rax", "mov|mov [rbx+8]:ptr<user,u64>,1",
    "test|test rax,1", "test|test [rbx+8]:ptr<user,u64>,1", "inc|inc ah",
    "dec|dec ah", "not|not ah", "neg|neg ah",
    "sete|sete ah", "setne|setne ah", "setb|setb ah",
    "setae|setae ah", "setbe|setbe ah", "seta|seta ah",
    "sets|sets ah", "setns|setns ah", "setp|setp ah",
    "setnp|setnp ah", "setl|setl ah", "setge|setge ah",
    "setle|setle ah", "setg|setg ah", "seto|seto ah",
    "setno|setno ah", "inc|inc [rbx+8]:ptr<user,u64>", "dec|dec [rbx+8]:ptr<user,u64>",
    "not|not [rbx+8]:ptr<user,u64>", "neg|neg [rbx+8]:ptr<user,u64>", "push|push [rbx+8]:ptr<user,u64>",
    "pop|pop [rbx+8]:ptr<user,u64>", "sete|sete [rbx+8]:ptr<user,u8>", "sete|sete [rbx+8]:ptr<user,u64>",
    "push|push [rbx+8]:ptr<user,u8>", "push|push -1", "shl|shl ah,1",
    "shl|shl [rbx+8]:ptr<user,u64>,cl", "shl|shl [rbx+8]:ptr<user,u64>,1", "bswap|bswap rax",
    "mul|mul rax", "div|div rax", "idiv|idiv rax",
    "bts|bts rax,rbx", "btr|btr rax,rbx", "btc|btc rax,rbx",
    "bt|bt rax,rbx", "imul|imul rax,rbx", "read_cr|read_cr rax,cr0", "write_cr|write_cr cr0,rax",
    "sgdt|sgdt [rbx+8]:ptr<user,array<u8,10>>", "sidt|sidt [rbx+8]:ptr<user,array<u8,10>>",
    "lgdt|lgdt [rbx+8]:ptr<user,array<u8,10>>", "lidt|lidt [rbx+8]:ptr<user,array<u8,10>>", "ltr|ltr ax",
    "invlpg|invlpg [rbx+8]:ptr<user,u64>", "in|in al,96", "out|out 96,al",
    "xchg|xchg [rbx+8]:ptr<user,u64>,rax", "cmove|cmove [rbx+8]:ptr<user,u32>,eax", "bsf|bsf [rbx+8]:ptr<user,u64>,rax",
    "movzx|movzx [rbx+8]:ptr<user,u64>,eax", "test|test rax,[rbx+8]:ptr<user,u64>", "xchg|xchg rax,1",
};
#define ROW_MANIFEST_COUNT (sizeof row_manifest / sizeof *row_manifest)

static void row_closure(void) {
    const char *executed[ROW_MAX];
    for (unsigned k = 0; k < row_count && k < ROW_MAX; k++) {
        char *cell = malloc(strlen(row_mnemonic[k]) + strlen(row_spelling[k]) + 2);
        /* An allocation that fails is a failure, and a failure a reader cannot
           find is worse than one they can: this path used to charge
           `failures` and print nothing, so an exhausted host turned the run
           red with a banner number and no line anywhere that said which check
           had stopped. The name says which row, and how much of the closure
           was therefore never judged, because "it did not run" and "it ran and
           agreed" must not print the same thing. */
        if (!cell) {
            failures++;
            fprintf(stderr,
                    "FAIL closure row %u (%s|%s): the manifest cell could not be "
                    "allocated, so this closure judged %u rows and declared %u\n",
                    k, row_mnemonic[k], row_spelling[k], row_count,
                    (unsigned)ROW_MANIFEST_COUNT);
            return;
        }
        sprintf(cell, "%s|%s", row_mnemonic[k], row_spelling[k]);
        executed[k] = cell;
    }
    cases++;
    checks++;
    int same = rows_match(executed, row_count, row_manifest, (unsigned)ROW_MANIFEST_COUNT);
    for (unsigned k = 0; k < row_count && k < ROW_MAX; k++) free((void *)executed[k]);
    if (!same) {
        failures++;
        fprintf(stderr, "FAIL closure the executed rows and the row manifest differ "
                        "(%u executed, %u declared)\n",
                row_count, (unsigned)ROW_MANIFEST_COUNT);
    }
}

static void surface_cases(void) {
    Surface live;
    int ok = surface_scan(module_text, &live);
    CHECK(ok, "x64_fixed text scans into a surface");
    if (!ok) {
        if (live.scan_error[0])
            fprintf(stderr, "FAIL the x64_fixed surface scan refused the module text: %s\n",
                    live.scan_error);
        return;
    }
    unsigned holes = surface_closed(&live, "live");
    live_segment_exports = segment_memory_exports;
    live_with_channel = segment_memory_exports_with_channel;
    /* Taken here, next to the scan that produced it. It used to sit in
     * drift_surface, which main() calls BEFORE surface_cases, so it compared
     * two zeroed counters against a constant and the axis was pinned by
     * nothing. Thirteen, not seven: a header naming `base:u64` is a memory
     * export, and that is the seven pure memory ones plus the six
     * two-operand families whose second operand may be memory. encode_imul is
     * the sixth of them: it takes a memory source and an fs/gs segment, exactly
     * like cmov and bsf, so the channel is owed rather than optional. */
    CHECK(live_segment_exports == 17 && live_with_channel == 17,
          "all seventeen memory exports of x64_fixed carry a segment channel");
    CHECK(holes == 0, "the drift table is closed over the x64_fixed export surface");
    CHECK(live.exports == 28, "x64_fixed exports exactly the 28 declared entries");
    /* OCCURRENCES, not distinct values: mul, div and idiv are declared in BOTH
     * encode_unary and encode_unary_operand, so three new names added SIX
     * literals. The distinct count is the manifest's, pinned in the other gate;
     * reading this one as a set size is what makes it look like 152 should. */
    CHECK(live.literals == 181, "x64_fixed holds the 181 declared mnemonic literal occurrences");
    /* The encoder side of the same closure, and the axis the pinned row
     * equation cannot see: 177 rows that add up is also true of 177 rows that
     * never mention a mnemonic the encoder emits. The scan runs here, after
     * drift_surface has filled the row registry, and the CHECK that pins it
     * runs after the scan that filled the alphabet, so neither sits before the
     * thing it measures. */
    Oracle alphabet;
    int scanned = oracle_scan(oracle_source, oracle_source_len, &alphabet);
    CHECK(scanned, "the x64.c encoder text scans into a name alphabet");
    if (!scanned) {
        if (alphabet.scan_error[0])
            fprintf(stderr, "FAIL the encoder name scan refused x64.c: %s\n", alphabet.scan_error);
        return;
    }
    unsigned encoders = oracle_alphabet_size(&alphabet);
    /* The floor, and it is not what keeps the axis honest: a scan that offered
     * no name at all would report the nineteen declared absences as names the
     * encoder has lost and the module literals as names it never had, so the
     * two opposite directions below are red on an empty alphabet. The floor is
     * there only so an empty scan is named rather than counted twice. */
    CHECK(encoders > 0, "the encoder scan offers at least one name the encoder knows");
    /* The residual this wave closed, as three measurements over the live scan
     * rather than as a sentence. A name assembled at run time is invisible to a
     * scan that reads literals and visible to a probe that calls the compiled
     * encoder, so it used to pass between the two views and the axis reported
     * holes=0 over an alphabet short by it. Each count below is a count of a
     * shape that shape would leave behind, and each is pinned, so the next one
     * to appear is a red gate rather than a silently shorter alphabet. */
    CHECK(alphabet.refused > 0,
          "the candidate filter refuses at least one token, so the fourth direction has something "
          "to walk");
    /* Exactly one, and the count is a measurement rather than a reading of the
     * file. x64.c carries two character constants, the '|' member separator and
     * the 'j' of the n[0]=='j' branch, and only the second is a byte a name
     * could be spelled from: a '|' is the separator the scan itself splits on,
     * so it is not counted and cannot be one byte of an assembled mnemonic. A
     * second alphanumeric one would be a name no literal scan can read. */
    CHECK(alphabet.char_sites == 1 && alphabet.char_value[0] == 'j',
          "the encoder text carries exactly the one alphanumeric character constant it always did");
    unsigned assembled = oracle_assembled(&alphabet, "live");
    CHECK(assembled == 0, "no name the encoder answers for exists only as a token the scan refused");
    printf("DRIFT-ASSEMBLY offered=%u refused=%u chars=%u assembled=%u\n", alphabet.names,
           alphabet.refused, alphabet.char_sites, assembled);
    unsigned oholes = oracle_closed(&alphabet, &live, "live", 0);
    CHECK(oholes == 0, "the drift table is closed over the encoder's own mnemonic alphabet");
    /* The same closure over the same live alphabet, once with a live name
     * withheld from every accounting path and once with a name the alphabet
     * does not hold. The pair says the accounting predicate is reached over
     * the live rows and is keyed on the alphabet, rather than counting a hole
     * for anything at all or for nothing. */
    CHECK(oracle_closed(&alphabet, &live, "withheld", "imul") == 1,
          "the encoder closure reports the one live mnemonic it was told to forget");
    CHECK(oracle_closed(&alphabet, &live, "withheld", "notanmnemonic") == 0,
          "the encoder closure withholds against the alphabet it scanned");
    printf("DRIFT-ORACLE offered=%u names=%u literals=%u pseudo=%u absent=%u holes=%u refused=%u\n",
           alphabet.names, encoders, live.literals, (unsigned)PSEUDO_MANIFEST_COUNT,
           (unsigned)ABSENT_MANIFEST_COUNT, oholes, alphabet.refused);
    /* The scan and the probe, on fixtures, because both of them are what the
     * axis above rests on and neither is a tautology: the probe is a call into
     * the C oracle and the answers below are its own. A splitter that dropped
     * the '|' lists would offer "mov" alone and the alphabet would be short by
     * every name the oracle reaches that way, which is most of them. */
    {
        Oracle f;
        static const char *const split = "member(n, \"aa|bb|cc\");\n";
        int sok = oracle_scan(split, strlen(split), &f);
        cases++; checks++;
        if (!sok || f.names != 3 || strcmp(f.name[0], "aa") || strcmp(f.name[1], "bb") ||
            strcmp(f.name[2], "cc")) {
            failures++;
            fprintf(stderr, "FAIL oracle scan the pipe list offers %u names, want aa bb cc\n", f.names);
        }
        /* A doc comment is not a literal: x64.c quotes names in prose and an
         * offered name the encoder has dropped would be a permanent hole. */
        static const char *const commented = "/* \"zz\" */ \"aa\"; // \"yy\"\n";
        int cok = oracle_scan(commented, strlen(commented), &f);
        cases++; checks++;
        if (!cok || f.names != 1 || strcmp(f.name[0], "aa")) {
            failures++;
            fprintf(stderr, "FAIL oracle scan a comment offers %u names, want aa alone\n", f.names);
        }
        /* An unterminated literal refuses the scan. Reading half of one gives a
         * smaller alphabet that still looks closed. */
        static const char *const open = "\"aa";
        cases++; checks++;
        if (oracle_scan(open, strlen(open), &f) || !f.scan_error[0]) {
            failures++;
            fprintf(stderr, "FAIL oracle scan an unterminated literal is accepted\n");
        }
        /* The candidate ceiling, the same lesson the surface scan was taught:
         * a name past the limit used to be a silent skip, which leaves a
         * smaller alphabet that still passes. */
        {
            char *flood = malloc((size_t)ORACLE_MAX_NAMES * 12 + 32);
            cases++; checks++;
            if (!flood) {
                failures++;
                fprintf(stderr, "FAIL oracle scan the candidate flood did not allocate\n");
            } else {
                size_t used = 0;
                for (unsigned k = 0; k <= ORACLE_MAX_NAMES; k++)
                    used += (size_t)snprintf(flood + used, (size_t)ORACLE_MAX_NAMES * 12 + 32 - used,
                                             "\"zz%u\" ", k);
                Oracle g;
                int refused = !oracle_scan(flood, used, &g);
                cases++; checks++;
                if (!refused || !g.scan_error[0]) {
                    failures++;
                    fprintf(stderr, "FAIL oracle scan %u names cross the ceiling unnoticed\n", g.names);
                }
                free(flood);
            }
        }
        /* The probe itself, against the real encoder: a name it knows and a
         * name it does not, and the second one must be exactly NT_X64_UNKNOWN,
         * because the two directions of the closure above rest on the claim
         * that nothing but an unknown name answers 401. */
        cases += 2;
        checks += 2;
        if (!oracle_encodes("mov")) {
            failures++;
            fprintf(stderr, "FAIL oracle probe the encoder does not know mov\n");
        }
        if (oracle_encodes("notanmnemonic")) {
            failures++;
            fprintf(stderr, "FAIL oracle probe the encoder claims notanmnemonic\n");
        }
        /* The residual, as three cases that must go red. Each one is a text the
         * scan cannot turn into the encoder's alphabet, and each is the shape
         * the report named: a name that is not a literal. Without these the
         * three refusals are unverified prose, and a check that cannot fail is
         * the defect rather than the fix. */
        {
            static const char *const assembled =
                "static int member(const char*n,const char*l){char b[8];snprintf(b,8,\"%s\",n);"
                "return !strcmp(b,\"mov\");}\n";
            cases++; checks++;
            if (oracle_scan(assembled, strlen(assembled), &f) || !f.scan_error[0]) {
                failures++;
                fprintf(stderr, "FAIL oracle scan a name assembled by snprintf is accepted\n");
            }
        }
        {
            static const char *const joined = "if (!strcmp(n, \"mo\" \"v\")) { }\n";
            cases++; checks++;
            if (oracle_scan(joined, strlen(joined), &f) || !f.scan_error[0]) {
                failures++;
                fprintf(stderr, "FAIL oracle scan a name split across two literals is accepted\n");
            }
        }
        {
            static const char *const escaped = "if (!strcmp(n, \"m\\x6fv\")) { }\n";
            cases++; checks++;
            if (oracle_scan(escaped, strlen(escaped), &f) || !f.scan_error[0]) {
                failures++;
                fprintf(stderr, "FAIL oracle scan a name carrying an escaped byte is accepted\n");
            }
        }
        /* The fourth direction, driven by a refused token the real encoder
         * does answer for. The alphabet is a copy of the live one and not a
         * fresh empty struct: an empty alphabet makes the declared-absence
         * direction fire nineteen times on its own, so the count this case
         * asserts would be measuring the wrong direction entirely. Copying the
         * live alphabet and adding one refusal isolates the fourth loop, and
         * the hole it reports has to be exactly that refused token. Without the
         * fourth loop this is 0 and the residual is open. */
        {
            Oracle *copy = malloc(sizeof *copy);
            cases++; checks++;
            if (!copy) {
                failures++;
                fprintf(stderr, "FAIL oracle closure the alphabet copy did not allocate\n");
            } else {
                memcpy(copy, &alphabet, sizeof *copy);
                oracle_refuse(copy, "mov", 3);
                if (oracle_assembled(copy, "refused") != 1) {
                    failures++;
                    fprintf(stderr, "FAIL oracle assembled a refused token the encoder answers for "
                                    "is not counted\n");
                }
                if (oracle_closed(copy, &live, "refused", 0) != 1) {
                    failures++;
                    fprintf(stderr, "FAIL oracle closure a refused token the encoder answers for is "
                                    "not the one hole it reports\n");
                }
                free(copy);
            }
        }
        /* And the other side of the same predicate: a refused token the
         * encoder does not know is not a hole, or the fourth direction would
         * count the twenty diagnostic sentences and the file name as names. */
        {
            Oracle *copy = malloc(sizeof *copy);
            cases++; checks++;
            if (!copy) {
                failures++;
                fprintf(stderr, "FAIL oracle closure the alphabet copy did not allocate\n");
            } else {
                memcpy(copy, &alphabet, sizeof *copy);
                oracle_refuse(copy, "notanmnemonic", 14);
                if (oracle_assembled(copy, "clean") != 0 ||
                    oracle_closed(copy, &live, "clean", 0) != 0) {
                    failures++;
                    fprintf(stderr, "FAIL oracle closure a refused token the encoder refuses is a "
                                    "hole\n");
                }
                free(copy);
            }
        }
        /* The prefix direction, and the one that replaced a check that could
         * not fail. The live alphabet is copied and `bt` is removed from it, so
         * `bt` is a proper prefix of the offered `btr` that the alphabet holds
         * nowhere: the encoder answers for it, and nothing in the closure can
         * see it. The count must be exactly one. On the unperturbed copy it is
         * zero, which is the state the negative proof perturbs. */
        {
            Oracle *copy = malloc(sizeof *copy);
            cases++; checks++;
            if (!copy) {
                failures++;
                fprintf(stderr, "FAIL oracle assembled the alphabet copy did not allocate\n");
            } else {
                memcpy(copy, &alphabet, sizeof *copy);
                /* Drop the name in place, shifting the rest down, so the copy
                 * is the live alphabet minus exactly one entry. `at` is the
                 * guard as well as the index: if the live alphabet does not
                 * offer `bt`, the shift would compact the wrong entry and the
                 * case would be measuring a hole it had just made up. The count
                 * is three and not one because `bt` is a proper prefix of three
                 * offered names, `bts`, `btr` and `btc`, and the direction
                 * counts the pairs rather than the distinct prefixes. */
                unsigned at = 0;
                for (; at < copy->names && strcmp(copy->name[at], "bt"); at++) {}
                if (at == copy->names) {
                    failures++;
                    fprintf(stderr, "FAIL oracle assembled the live alphabet does not offer bt, so "
                                    "the prefix case is measuring nothing\n");
                } else {
                    for (unsigned a = at + 1; a < copy->names; a++)
                        memcpy(copy->name[a - 1], copy->name[a], ORACLE_NAME_MAX);
                    copy->names--;
                    if (oracle_assembled(copy, "prefix") != 3) {
                        failures++;
                        fprintf(stderr, "FAIL oracle assembled a prefix the alphabet holds nowhere "
                                        "is not counted\n");
                    }
                }
                free(copy);
            }
        }
    }
    /* The bypass itself, as a case: a brand new export for a mnemonic no row
     * names, spliced into the module the gate just accepted. */
    mutant_case("a new export for an uncovered mnemonic", "export fn encode_xchg(",
                "export fn encode_bswap(name:buf<u8>,operand_count:u64,register:u64,high8:u64,"
                "width:u64,features:u64,cpl:u64,out:buf<u8>)->u64 { if len(out)<4 { return 800; } "
                "let bswap:buf<u8>=\"bswap\"; if same(name,bswap)==false { return 401; } "
                "out[0]=3;out[1]=0;out[2]=0;out[3]=0; return 0; }\nexport fn encode_xchg(");
    /* The parameter axis. Stripping `segment:u64` from a memory export that
     * owes it keeps the name, keeps every mnemonic and keeps every byte the
     * rows compare, and used to be invisible here. */
    mutant_case("a memory export loses its segment parameter",
                "a1_width:u64,base:u64,index:u64,scale:u64,displacement:u64,segment:u64,",
                "a1_width:u64,base:u64,index:u64,scale:u64,displacement:u64,");
    /* The one this axis was built for: encode_lea losing the segment
     * parameter it now has. Before the axis existed this kept the name, kept
     * every mnemonic and kept every byte, and no check in the gate could see
     * it. */
    mutant_case("encode_lea loses its segment parameter",
                "export fn encode_lea(source_register:u64,width:u64,base:u64,index:u64,scale:u64,displacement:u64,segment:u64,",
                "export fn encode_lea(source_register:u64,width:u64,base:u64,index:u64,scale:u64,displacement:u64,");
    /* A new mnemonic inside an export that already exists, which is the same
     * hole without a new name to notice. */
    mutant_case("a new mnemonic inside an existing export", "let mnemonic:buf<u8>=\"xchg\";",
                "let mnemonic:buf<u8>=\"xchg\";let bswap:buf<u8>=\"bswap\";");
    /* A mnemonic the manifest declares the module has no channel for. */
    mutant_case("a declared absent mnemonic becomes a literal", "let mnemonic:buf<u8>=\"xchg\";",
                "let mnemonic:buf<u8>=\"xchg\";let mul:buf<u8>=\"mul\";");
    /* A pseudo spelling of the lowerer, which must never reach the encoder. */
    mutant_case("a pseudo spelling becomes a literal", "let mnemonic:buf<u8>=\"xchg\";",
                "let mnemonic:buf<u8>=\"xchg\";let load:buf<u8>=\"load\";");
    /* One of two mnemonics removed from an export body. */
    mutant_case("a mnemonic is dropped from an export", "let bsf:buf<u8>=\"bsf\";let bsr:buf<u8>=\"bsr\";",
                "let bsf:buf<u8>=\"bsf\";");
    /* An export renamed, and an export made private: both change the export
     * count the manifest pins. */
    mutant_case("an export is renamed", "export fn encode_test_two(", "export fn encode_test_three(");
    mutant_case("an export loses its visibility", "export fn encode_xchg(", "fn encode_xchg(");
    /* A literal in a private body, which no export can reach and no manifest
     * entry owns. */
    mutant_case("a literal lands in a private body",
                "fn operand_valid(kind:u64,width:u64,reg:u64,high8:u64,base:u64,index:u64,scale:u64,"
                "displacement:u64,segment:u64)->u64 {",
                "fn operand_valid(kind:u64,width:u64,reg:u64,high8:u64,base:u64,index:u64,scale:u64,"
                "displacement:u64,segment:u64)->u64 { let bswap:buf<u8>=\"bswap\";");
    /* A literal in an export the manifest says takes no mnemonic at all. */
    mutant_case("a literal lands in a name-less export",
                "export fn encode_lea(source_register:u64,width:u64,base:u64,index:u64,scale:u64,"
                "displacement:u64,segment:u64,features:u64,cpl:u64,out:buf<u8>)->u64 {",
                "export fn encode_lea(source_register:u64,width:u64,base:u64,index:u64,scale:u64,"
                "displacement:u64,segment:u64,features:u64,cpl:u64,out:buf<u8>)->u64 { let bswap:buf<u8>=\"bswap\";");
    /* The alias loses its literal, so the declaration is stale. */
    mutant_case("the return alias loses its literal", "let return_:buf<u8>=\"return\";", "");
    /* Mutant 11, the record ceiling. The module has live.records depth-0
     * headers today, so this appends exactly enough private ones to make header
     * SURF_MAX_RECORDS + 1 exist. The scan used to skip that header without a
     * word, which left the export count at 22 and the literal count at 147 on
     * a module that had grown: the closure passed the surface it had not
     * measured. The block is appended rather than spliced over an anchor so
     * the header the ceiling drops is one of these fillers and not a real
     * export, and the count is derived from the live scan so the mutant keeps
     * crossing the ceiling however many headers the module has. */
    {
        char block[SURF_MAX_RECORDS * 48];
        size_t used = 0;
        unsigned want = SURF_MAX_RECORDS + 1 - live.records;
        int built = 1;
        for (unsigned k = 0; k < want; k++) {
            int w = snprintf(block + used, sizeof block - used,
                             "fn filler_%u()->u64 { return 0; }\n", k);
            if (w < 0 || (size_t)w >= sizeof block - used) {
                built = 0;
                break;
            }
            used += (size_t)w;
        }
        if (built)
            mutant_verdict("the depth-0 record ceiling is crossed", surface_append(block),
                           "the module text is not loaded");
        else {
            cases++;
            checks++;
            failures++;
            fprintf(stderr, "FAIL mutant the depth-0 record ceiling is crossed: the %u filler "
                            "headers did not fit in the block\n",
                    want);
        }
    }
    /* Mutant 12, the name ceiling. The name below is SURF_NAME_MAX identifier
     * characters, one more than the field can store, so the scan used to drop
     * the whole header: the export bijection still saw exactly the 22 exports
     * of the unmutated module, and the closure could not tell the difference. */
    {
        char name[SURF_NAME_MAX * 2];
        for (unsigned k = 0; k < SURF_NAME_MAX; k++) name[k] = (char)('a' + k % 26);
        name[SURF_NAME_MAX] = 0;
        /* The block is sized from the fixed text it carries, not from
         * SURF_NAME_MAX, so lowering the limit cannot turn this case into a
         * compile error: the limit is exactly what the case is about. */
        char block[SURF_NAME_MAX + 128];
        int w = snprintf(block, sizeof block, "export fn %s()->u64 { return 0; }\nexport fn encode(",
                         name);
        if (w > 0 && (size_t)w < sizeof block)
            mutant_case("a depth-0 record name is longer than SURF_NAME_MAX", "export fn encode(",
                        block);
        else {
            cases++;
            checks++;
            failures++;
            fprintf(stderr, "FAIL mutant a depth-0 record name is longer than SURF_NAME_MAX: the "
                            "header did not fit in the block\n");
        }
    }
    /* Both directions of the row list, as pure comparisons. */
    {
        static const char *const executed[] = {"nop|pause", "ret|ret", "add rax,rbx|add rax,rbx"};
        static const char *const dropped[] = {"nop|pause", "ret|ret"};
        static const char *const invented[] = {"nop|pause", "ret|ret", "add rax,rbx|add rax,rbx",
                                               "mov rax,rcx|mov rax,rcx"};
        static const char *const renamed[] = {"nop|pause", "ret|ret", "add rcx,rbx|add rax,rbx"};
        cases += 2;
        checks += 2;
        if (rows_match(executed, 3, dropped, 2)) {
            failures++;
            fprintf(stderr, "FAIL closure a dropped drift row is accepted\n");
        }
        if (rows_match(executed, 3, invented, 4) || rows_match(executed, 3, renamed, 3)) {
            failures++;
            fprintf(stderr, "FAIL closure an invented or renamed drift row is accepted\n");
        }
    }
    /* The count DRIFT-CLOSURE announces, against the number that ran. The
     * figure used to be a word in a printf, so it was wrong by one for a whole
     * wave: it said eleven over ten call sites. */
    CHECK(mutant_cases_run == MUTANT_CASE_COUNT,
          "the module-text mutant count DRIFT-CLOSURE announces is the count that executed");
    CHECK(mutant_cases_rejected == mutant_cases_run,
          "every executed module-text mutant is rejected by the surface check");
}

/* ------------------------------------------------------------- drift ------
 * x64_fixed and the AST lowerer are two independent surfaces and nothing in
 * the build noticed when one grew without the other. Every row below is one
 * (mnemonic, form) pair the pair of surfaces has an opinion about. A row must
 * land in exactly one of three counted outcomes, and the header below is the
 * definition the code enforces, not a description of it.
 *
 *   DRIFT_REACHABLE  the oracle encodes the form, code 0, and the lowerer
 *                    answers 0 with the oracle bytes, byte for byte, and
 *                    touches nothing after the length. This is the only
 *                    outcome that proves the two surfaces agree.
 *   DRIFT_GAP        the oracle encodes the form and the lowerer answers a
 *                    real diagnostic instead of bytes, and the row carries a
 *                    non-empty reason. So `refused` cannot hide a form the
 *                    encoder can emit, and a gap cannot be declared silently:
 *                    a row that answers non-zero with no reason is a failure,
 *                    not a gap. A gap answered with something that is not an
 *                    oracle diagnostic, 800 included, is a failure too.
 *   DRIFT_REFUSED    the oracle refuses the form and the lowerer answers that
 *                    exact code. A row may not declare a gap in this outcome,
 *                    so the declaration is checked rather than ignored, and
 *                    the code equality is what makes the row a refusal at all.
 *
 * The three counters plus the row count are pinned, but the pins cannot
 * detect a drop on their own: removing a row lowers `rows` and its counter
 * together, so the sum still holds and only the absolute pin notices. That is
 * a check that fires when somebody remembers to edit the pin, so the row list
 * is closed against a second, independent list instead (see row_manifest), and
 * the set of mnemonics the table covers is closed against the module itself
 * (see surface_closed). */

/* The declared gap reasons, one string per family. A gap row states which of
 * these it is, so a gap cannot be a bare number in a table, and the distinct
 * family count is pinned below. */
#define GAP_JCC "the parser gives a branch a statement form, so no kind 32 node reaches encode_jcc"
#define GAP_GROUP_MEMORY \
    "x64_fixed exports the register/register and register/immediate halves of the eight groups only, " \
    "so the I08 R_M and M_R forms have no channel"
#define GAP_MOV_IMMEDIATE "no export of x64_fixed states a memory/immediate form of mov"
#define GAP_TEST_IMMEDIATE "encode_test_two owns the register second operand alone, so I09 is unreachable"
#define GAP_SHIFT_HIGH8 "encode_shift_imm states a plain register number and no high8 regcode"
#define GAP_SHIFT_MEMORY "neither shift export takes a memory destination"
#define GAP_NO_ENCODER "no export of x64_fixed names this mnemonic, so the encoder cannot emit it"
/* The descriptor group is the first declared gap whose reason is NOT a missing
 * encoder. encode_descriptor emits all four names, and the lowerer reaches it --
 * the answer moved from 409 to 403, which is the proof. What is missing is a
 * SPELLING: the access width these four demand is 80, no machine scalar states
 * 80, and the native row below is built with width 80 on the oracle side while
 * the source can only spell u64. That is a language question and not an encoder
 * one, and a gate that kept printing GAP_NO_ENCODER here would be naming a
 * cause the measurement has already contradicted. */
#define GAP_DESCRIPTOR_WIDTH "the access width is 80 and no machine scalar states 80, so a source spelling reaches the encoder and is refused 403 where the oracle row is built at width 80 and answers"

enum {
    DRIFT_REACHABLE = 0,
    DRIFT_GAP = 1,
    DRIFT_REFUSED = 2,
    DRIFT_WRONG_BYTES = 16,
    DRIFT_NO_REASON = 17,
    DRIFT_NOT_A_DIAGNOSTIC = 18,
    DRIFT_VOID_GAP = 19,
    DRIFT_WRONG_CODE = 20
};

static unsigned drift_rows, drift_reachable, drift_declared, drift_refused;
static unsigned drift_closed_gaps, drift_reasons;
static const char *gap_reason_kind[GAP_REASON_MAX];
static unsigned gap_reason_kind_count;

/* A real encoder diagnostic: exactly the NtX64Error codes. 800 is the harness
 * short-output answer, never a diagnostic, so a gap may not be declared on it. */
static int diagnostic(unsigned code) { return code >= 401u && code <= 412u; }

/* Classify one row. Returns 0 and the counted outcome, or one of the
 * DRIFT_* error codes and leaves *outcome untouched. Kept pure so the ways of
 * mislabelling a row are pinned directly, without a deliberately broken
 * encoder. */
static int drift_verdict(unsigned oracle_code, unsigned lowerer_code, int bytes_match,
                         const char *reason, unsigned *outcome) {
    if (oracle_code == 0) {
        if (lowerer_code == 0) {
            if (!bytes_match) return DRIFT_WRONG_BYTES;
            *outcome = DRIFT_REACHABLE;
            return 0;
        }
        if (!reason || !reason[0]) return DRIFT_NO_REASON;
        if (!diagnostic(lowerer_code)) return DRIFT_NOT_A_DIAGNOSTIC;
        *outcome = DRIFT_GAP;
        return 0;
    }
    if (reason && reason[0]) return DRIFT_VOID_GAP;
    if (lowerer_code != oracle_code) return DRIFT_WRONG_CODE;
    *outcome = DRIFT_REFUSED;
    return 0;
}

static const char *verdict_text(int code) {
    switch (code) {
    case DRIFT_WRONG_BYTES: return "reachable bytes differ from the oracle";
    case DRIFT_NO_REASON: return "the encoder can emit it, the lowerer refuses it, the row declares no reason";
    case DRIFT_NOT_A_DIAGNOSTIC: return "the declared gap is answered with a code that is not an oracle diagnostic";
    case DRIFT_VOID_GAP: return "a gap is declared on a form the oracle refuses";
    case DRIFT_WRONG_CODE: return "the refusal code is not the oracle code";
    default: return "?";
    }
}

static void drift(const NovaHostImage *i, const char *mnemonic, const char *spelling, NtX64Operand *o,
                  unsigned count, uint32_t features, unsigned cpl, const char *reason) {
    NtX64Instruction expected = {0};
    NtX64Context context = {features, cpl};
    NtX64Error e = nt_x64_encode(mnemonic, o, count, context, &expected);
    Run r = run(i, spelling, features, cpl);
    cases++;
    checks++;
    drift_rows++;
    row_record(mnemonic, spelling);
    int bytes_match = 1;
    if (e == NT_X64_OK)
        bytes_match = r.out[0] == (uint8_t)expected.length &&
                      memcmp(r.out + 1, expected.bytes, expected.length) == 0;
    unsigned outcome = DRIFT_REACHABLE;
    int bad = drift_verdict((unsigned)e, (unsigned)r.returned, bytes_match, reason, &outcome);
    if (r.runtime != 0) bad = DRIFT_WRONG_CODE;
    printf("DRIFT-ROW id=%u mnemonic=%s oracle=%u lowerer=%llu outcome=%u bytes_equal=%d source=",drift_rows,mnemonic,(unsigned)e,(unsigned long long)r.returned,outcome,bytes_match);
    for(const char *p=spelling;*p;p++){if(*p=='\n')fputs("\\n",stdout);else putchar(*p);}
    putchar('\n');
    /* Transactional: a form that produces no bytes must leave out untouched,
     * so a refusal or a declared gap can never be a silent write. */
    if (outcome != DRIFT_REACHABLE)
        for (unsigned k = 0; k < sizeof r.out; k++)
            if (r.out[k] != guard) bad = DRIFT_WRONG_CODE;
    if (bad) {
        failures++;
        fprintf(stderr, "FAIL drift %s %s %s (oracle=%u lowerer=%llu)\n", mnemonic, spelling,
                verdict_text(bad), (unsigned)e, (unsigned long long)r.returned);
        if (bad == DRIFT_WRONG_BYTES && e == NT_X64_OK) {
            fprintf(stderr, "     oracle ");
            for (size_t k = 0; k < expected.length; k++) fprintf(stderr, "%02x", expected.bytes[k]);
            fprintf(stderr, " len=%u lowerer out=", (unsigned)expected.length);
            for (unsigned k = 0; k < 4; k++) fprintf(stderr, "%02x", r.out[k]);
            fprintf(stderr, "\n");
        }
    }
    if (outcome == DRIFT_REACHABLE) {
        drift_reachable++;
        if (reason) {
            drift_closed_gaps++;
            printf("DRIFT-CLOSED %-6s %-30s the declared gap no longer refuses\n", mnemonic, spelling);
        }
    } else if (outcome == DRIFT_GAP) {
        drift_declared++;
        drift_reasons++;
        unsigned k;
        for (k = 0; k < gap_reason_kind_count; k++)
            if (!strcmp(gap_reason_kind[k], reason)) break;
        if (k == gap_reason_kind_count) {
            if (gap_reason_kind_count >= GAP_REASON_MAX) {
                failures++;
                fprintf(stderr, "FAIL drift gap reason registry overflow\n");
            } else {
                gap_reason_kind[gap_reason_kind_count++] = reason;
            }
        }
        printf("DRIFT-GAP %-6s %-30s oracle=ok(%u) lowerer=%llu reason=%s\n", mnemonic, spelling,
               (unsigned)expected.length, (unsigned long long)r.returned, reason);
    } else {
        drift_refused++;
    }
}

static void drift_surface(const NovaHostImage *i) {
    static const char *const fixed[] = {
        "nop", "pause", "ud2", "cpuid", "cbw", "cwde", "cdqe", "cwd", "cdq", "cqo",
        "pushfq", "popfq", "rdtsc", "lfence", "sfence", "mfence", "cli", "sti", "hlt",
        "swapgs", "rdmsr", "wrmsr", "syscall", "sysretq", "iretq", "ret"};
    for (unsigned k = 0; k < sizeof fixed / sizeof *fixed; k++)
        drift(i, fixed[k], fixed[k], NULL, 0, 31, 0, NULL);
    static const char *const groups[] = {"mov", "add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"};
    for (unsigned k = 0; k < sizeof groups / sizeof *groups; k++) {
        char body[64];
        snprintf(body, sizeof body, "%s rax,rbx", groups[k]);
        NtX64Operand o[2] = {{.kind = NT_X64_REG, .width = 64, .reg = 0},
                             {.kind = NT_X64_REG, .width = 64, .reg = 3}};
        drift(i, groups[k], body, o, 2, 1, 3, NULL);
    }
    for (unsigned k = 0; k < sizeof groups / sizeof *groups; k++) {
        char body[64];
        snprintf(body, sizeof body, "%s rax,1", groups[k]);
        NtX64Operand o[2] = {{.kind = NT_X64_REG, .width = 64, .reg = 0},
                             {.kind = NT_X64_IMM, .imm = 1}};
        drift(i, groups[k], body, o, 2, 1, 3, NULL);
    }
    {
        NtX64Operand load[2] = {{.kind = NT_X64_REG, .width = 64, .reg = 0},
                                {.kind = NT_X64_MEM, .width = 64, .base = 3, .index = -1, .scale = 1,
                                 .disp = 8}};
        drift(i, "load", "load rax,[rbx+8]:ptr<user,u64>", load, 2, 1, 3, NULL);
        NtX64Operand store[2] = {{.kind = NT_X64_MEM, .width = 64, .base = 3, .index = -1, .scale = 1,
                                  .disp = 8},
                                 {.kind = NT_X64_REG, .width = 64, .reg = 0}};
        drift(i, "store", "store [rbx+8]:ptr<kernel,u64>,rax", store, 2, 1, 3, NULL);
        NtX64Operand lea[2] = {{.kind = NT_X64_REG, .width = 64, .reg = 0},
                               {.kind = NT_X64_MEM, .width = 64, .base = 3, .index = -1, .scale = 1}};
        drift(i, "lea", "lea rax,[rbx]:ptr<user,u64>", lea, 2, 1, 3, NULL);
    }
    static const char *const shifts[] = {"rol", "ror", "shl", "shr", "sar"};
    for (unsigned k = 0; k < sizeof shifts / sizeof *shifts; k++) {
        char body[64];
        snprintf(body, sizeof body, "%s rax,cl", shifts[k]);
        NtX64Operand cl[2] = {{.kind = NT_X64_REG, .width = 64, .reg = 0},
                              {.kind = NT_X64_REG, .width = 8, .reg = 1}};
        drift(i, shifts[k], body, cl, 2, 1, 3, NULL);
    }
    /* The one-operand register forms, reachable since the one-operand
     * dispatch was added: the four unaries, push/pop with a register and with
     * an unsigned literal, and the sixteen setcc conditions over a low8 GPR. */
    static const char *const unary[] = {"inc", "dec", "not", "neg"};
    for (unsigned k = 0; k < sizeof unary / sizeof *unary; k++) {
        char body[64];
        snprintf(body, sizeof body, "%s rax", unary[k]);
        NtX64Operand o[1] = {{.kind = NT_X64_REG, .width = 64, .reg = 0}};
        drift(i, unary[k], body, o, 1, 1, 3, NULL);
    }
    /* Shift and rotate counted by an unsigned literal: reachable since
     * encode_instruction forwards a literal count to encode_shift_imm, which
     * owns the amount of 1..255 and the single-byte short form of 1. One row
     * per mnemonic, all five of them, at the width the row above uses. */
    for (unsigned k = 0; k < sizeof shifts / sizeof *shifts; k++) {
        char body[64];
        snprintf(body, sizeof body, "%s rax,1", shifts[k]);
        NtX64Operand o[2] = {{.kind = NT_X64_REG, .width = 64, .reg = 0},
                             {.kind = NT_X64_IMM, .imm = 1}};
        drift(i, shifts[k], body, o, 2, 1, 3, NULL);
    }
    {
        NtX64Operand push[1] = {{.kind = NT_X64_REG, .width = 64, .reg = 0}};
        drift(i, "push", "push rax", push, 1, 1, 3, NULL);
        drift(i, "pop", "pop rax", push, 1, 1, 3, NULL);
        NtX64Operand pushi[1] = {{.kind = NT_X64_IMM, .imm = 1}};
        drift(i, "push", "push 1", pushi, 1, 1, 3, NULL);
    }
    static const char *const jcc[] = {"jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja",
                                      "js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg"};
    for (unsigned k = 0; k < sizeof jcc / sizeof *jcc; k++) {
        char body[64];
        snprintf(body, sizeof body, "%s target\ntarget:", jcc[k]);
        NtX64Operand o[1] = {{.kind = NT_X64_REL, .imm = 0, .is_signed = 1}};
        drift(i, jcc[k], body, o, 1, 1, 3, GAP_JCC);
    }
    static const char *const setcc[] = {"sete", "setne", "setb", "setae", "setbe", "seta",
                                        "sets", "setns", "setp", "setnp", "setl", "setge",
                                        "setle", "setg", "seto", "setno"};
    for (unsigned k = 0; k < sizeof setcc / sizeof *setcc; k++) {
        char body[64];
        snprintf(body, sizeof body, "%s al", setcc[k]);
        NtX64Operand o[1] = {{.kind = NT_X64_REG, .width = 8, .reg = 0}};
        drift(i, setcc[k], body, o, 1, 1, 3, NULL);
    }
    /* The two-operand register families, reachable since encode_instruction
     * forwards them to the export that owns each of them: xchg, the sixteen
     * cmov conditions, the two bit scans, the three width-conversion moves
     * and test. The memory direction of each family is a row of its own,
     * because the lowerer has to read the access width out of the pointer
     * element type to state it. */
    {
        NtX64Operand pair[2] = {{.kind = NT_X64_REG, .width = 64, .reg = 0},
                                {.kind = NT_X64_REG, .width = 64, .reg = 3}};
        drift(i, "xchg", "xchg rax,rbx", pair, 2, 1, 3, NULL);
        drift(i, "test", "test rax,rbx", pair, 2, 1, 3, NULL);
        static const char *const cmov[] = {"cmove", "cmovne", "cmovb", "cmovae", "cmovbe", "cmova",
                                           "cmovs", "cmovns", "cmovp", "cmovnp", "cmovl", "cmovge",
                                           "cmovle", "cmovg", "cmovo", "cmovno"};
        for (unsigned k = 0; k < sizeof cmov / sizeof *cmov; k++) {
            char body[64];
            snprintf(body, sizeof body, "%s rax,rbx", cmov[k]);
            drift(i, cmov[k], body, pair, 2, 1, 3, NULL);
        }
        static const char *const scan[] = {"bsf", "bsr"};
        for (unsigned k = 0; k < sizeof scan / sizeof *scan; k++) {
            char body[64];
            snprintf(body, sizeof body, "%s rax,rbx", scan[k]);
            drift(i, scan[k], body, pair, 2, 1, 3, NULL);
        }
        NtX64Operand widen[2] = {{.kind = NT_X64_REG, .width = 32, .reg = 0},
                                 {.kind = NT_X64_REG, .width = 8, .reg = 0}};
        drift(i, "movzx", "movzx eax,al", widen, 2, 1, 3, NULL);
        drift(i, "movsx", "movsx eax,al", widen, 2, 1, 3, NULL);
        NtX64Operand signed_widen[2] = {{.kind = NT_X64_REG, .width = 64, .reg = 0},
                                        {.kind = NT_X64_REG, .width = 32, .reg = 0}};
        drift(i, "movsxd", "movsxd rax,eax", signed_widen, 2, 1, 3, NULL);
        /* The memory direction of the same five families, one row each. */
        NtX64Operand mem64[2] = {{.kind = NT_X64_REG, .width = 64, .reg = 0},
                                 {.kind = NT_X64_MEM, .width = 64, .base = 3, .index = -1, .scale = 1,
                                  .disp = 8}};
        drift(i, "xchg", "xchg rax,[rbx+8]:ptr<user,u64>", mem64, 2, 1, 3, NULL);
        NtX64Operand mem32[2] = {{.kind = NT_X64_REG, .width = 32, .reg = 0},
                                 {.kind = NT_X64_MEM, .width = 32, .base = 3, .index = -1, .scale = 1,
                                  .disp = 8}};
        drift(i, "cmovne", "cmovne eax,[rbx+8]:ptr<user,u32>", mem32, 2, 1, 3, NULL);
        drift(i, "bsr", "bsr rax,[rbx+8]:ptr<user,u64>", mem64, 2, 1, 3, NULL);
        NtX64Operand mem8[2] = {{.kind = NT_X64_REG, .width = 32, .reg = 0},
                                {.kind = NT_X64_MEM, .width = 8, .base = 3, .index = -1, .scale = 1,
                                 .disp = 8}};
        drift(i, "movzx", "movzx eax,[rbx+8]:ptr<user,u8>", mem8, 2, 1, 3, NULL);
        drift(i, "movsx", "movsx eax,[rbx+8]:ptr<user,u8>", mem8, 2, 1, 3, NULL);
        NtX64Operand mem32_to_64[2] = {{.kind = NT_X64_REG, .width = 64, .reg = 0},
                                      {.kind = NT_X64_MEM, .width = 32, .base = 3, .index = -1,
                                       .scale = 1, .disp = 8}};
        drift(i, "movsxd", "movsxd rax,[rbx+8]:ptr<user,u32>", mem32_to_64, 2, 1, 3, NULL);
        NtX64Operand test_mem[2] = {{.kind = NT_X64_MEM, .width = 64, .base = 3, .index = -1, .scale = 1,
                                     .disp = 8},
                                    {.kind = NT_X64_REG, .width = 64, .reg = 0}};
        drift(i, "test", "test [rbx+8]:ptr<user,u64>,rax", test_mem, 2, 1, 3, NULL);
    }
    /* Declared gaps: the oracle emits bytes and no x64_fixed export can express
     * the form, so the lowerer must refuse instead of emitting something else.
     * Two families of gap are declared below. The first needs an encoder
     * export that does not exist yet. */
    {
        /* I08 register/memory and memory/register, and the mov
         * memory/immediate form: x64_fixed exports only the register/register
         * and register/immediate halves of the eight arithmetic groups, and no
         * memory/immediate form of mov at all. */
        NtX64Operand group_reg_mem[2] = {{.kind = NT_X64_REG, .width = 64, .reg = 0},
                                         {.kind = NT_X64_MEM, .width = 64, .base = 3, .index = -1,
                                          .scale = 1, .disp = 8}};
        drift(i, "add", "add rax,[rbx+8]:ptr<user,u64>", group_reg_mem, 2, 1, 3, GAP_GROUP_MEMORY);
        NtX64Operand group_mem_reg[2] = {{.kind = NT_X64_MEM, .width = 64, .base = 3, .index = -1,
                                          .scale = 1, .disp = 8},
                                         {.kind = NT_X64_REG, .width = 64, .reg = 0}};
        drift(i, "add", "add [rbx+8]:ptr<user,u64>,rax", group_mem_reg, 2, 1, 3, GAP_GROUP_MEMORY);
        NtX64Operand mov_mem_imm[2] = {{.kind = NT_X64_MEM, .width = 64, .base = 3, .index = -1,
                                        .scale = 1, .disp = 8},
                                       {.kind = NT_X64_IMM, .imm = 1}};
        drift(i, "mov", "mov [rbx+8]:ptr<user,u64>,1", mov_mem_imm, 2, 1, 3, GAP_MOV_IMMEDIATE);
        /* I09 immediate test, in both directions: encode_test_two reaches only
         * the register second operand, the oracle reaches the immediate
         * through a different operand kind. */
        NtX64Operand test_imm[2] = {{.kind = NT_X64_REG, .width = 64, .reg = 0},
                                    {.kind = NT_X64_IMM, .imm = 1}};
        drift(i, "test", "test rax,1", test_imm, 2, 1, 3, GAP_TEST_IMMEDIATE);
        drift(i, "test", "test [rbx+8]:ptr<user,u64>,1", mov_mem_imm, 2, 1, 3, GAP_TEST_IMMEDIATE);
    }
    {
        /* The second family, after the encoder lot that added
         * encode_unary_operand, encode_setcc_operand and encode_stack_memory and
         * the lowerer lot that routed the spelling to them. Every row below is a
         * parity row now: encode_one_operand resolves the operand itself, answers
         * 1 the register kind with the resolved high8 boolean and 3 the memory
         * kind with the address descriptor and the access width, and the oracle
         * bytes are compared here. The declared flag is 0 on all of them, so a
         * lowerer that answered 409 again would fail the gate instead of being
         * counted as a gap. */
        /* The high8 alias over the four unaries, one row per mnemonic because
         * every mnemonic is a row of its own in this table. */
        for (unsigned k = 0; k < sizeof unary / sizeof *unary; k++) {
            char body[64];
            snprintf(body, sizeof body, "%s ah", unary[k]);
            NtX64Operand high8[1] = {{.kind = NT_X64_REG, .width = 8, .reg = 0, .high8 = 1}};
            drift(i, unary[k], body, high8, 1, 1, 3, NULL);
        }
        /* The high8 alias over the sixteen setcc conditions, one row each, the
         * whole family of sixteen the same way the low8 rows above are. */
        for (unsigned k = 0; k < sizeof setcc / sizeof *setcc; k++) {
            char body[64];
            snprintf(body, sizeof body, "%s ah", setcc[k]);
            NtX64Operand high8[1] = {{.kind = NT_X64_REG, .width = 8, .reg = 0, .high8 = 1}};
            drift(i, setcc[k], body, high8, 1, 1, 3, NULL);
        }
        /* The memory direction of the same three exports: the four unaries over
         * a 64 bit address, push and pop over a 64 bit address, and one setcc
         * over an 8 bit address. One row per mnemonic family, the same
         * granularity the memory row of each two-register family above uses. */
        NtX64Operand mem_operand[1] = {{.kind = NT_X64_MEM, .width = 64, .base = 3, .index = -1,
                                        .scale = 1, .disp = 8}};
        for (unsigned k = 0; k < sizeof unary / sizeof *unary; k++) {
            char body[64];
            snprintf(body, sizeof body, "%s [rbx+8]:ptr<user,u64>", unary[k]);
            drift(i, unary[k], body, mem_operand, 1, 1, 3, NULL);
        }
        drift(i, "push", "push [rbx+8]:ptr<user,u64>", mem_operand, 1, 1, 3, NULL);
        drift(i, "pop", "pop [rbx+8]:ptr<user,u64>", mem_operand, 1, 1, 3, NULL);
        NtX64Operand mem8_operand[1] = {{.kind = NT_X64_MEM, .width = 8, .base = 3, .index = -1,
                                         .scale = 1, .disp = 8}};
        drift(i, "sete", "sete [rbx+8]:ptr<user,u8>", mem8_operand, 1, 1, 3, NULL);
        /* The two widths each of those three exports refuses, kept here as the
         * matching rows: a memory operand the encoder states a width for, with a
         * width the export refuses, is an oracle refusal and not a gap. setcc
         * takes 8 bits only and push/pop take 64, so each of the two spellings
         * below is answered with the oracle diagnostic by the lowerer. */
        drift(i, "sete", "sete [rbx+8]:ptr<user,u64>", mem_operand, 1, 1, 3, NULL);
        drift(i, "push", "push [rbx+8]:ptr<user,u8>", mem8_operand, 1, 1, 3, NULL);
        /* A signed literal is a unary-minus node whose child carries only the
         * magnitude. The lowerer now reads the sign out of the source text, the
         * discipline memory_descriptor already uses for a displacement, and
         * hands encode_stack the two's complement the oracle operand carries, so
         * `push -1` is reachable. The unsigned spelling is the push row above. */
        NtX64Operand signed_imm[1] = {{.kind = NT_X64_IMM, .imm = 18446744073709551615ULL,
                                       .is_signed = 1}};
        drift(i, "push", "push -1", signed_imm, 1, 1, 3, NULL);
    }
    {
        /* The third family: the boundary of the two shift exports. The register
         * destination of a shift is now reachable, and the two forms those two
         * exports cannot state stay declared here so the new branch cannot grow
         * a silent hole. */
        /* A high8 destination of the immediate form: encode_shift_imm states a
         * plain register number and no high8 regcode, so `shl ah,1` would
         * answer d0 e0 where the oracle answers d0 e4. The by-cl form does
         * carry a high8 word and is a reachable row of x64_lower_lea above. */
        NtX64Operand shift_high8[2] = {{.kind = NT_X64_REG, .width = 8, .reg = 0, .high8 = 1},
                                       {.kind = NT_X64_IMM, .imm = 1}};
        drift(i, "shl", "shl ah,1", shift_high8, 2, 1, 3, GAP_SHIFT_HIGH8);
        /* A memory destination: neither encode_shift_imm nor encode_shift_cl
         * takes a memory operand, so the whole M_CL, M_1 and M_I8 family of
         * every shift mnemonic has no encoder channel at all. */
        NtX64Operand shift_mem_cl[2] = {{.kind = NT_X64_MEM, .width = 64, .base = 3, .index = -1,
                                         .scale = 1, .disp = 8},
                                        {.kind = NT_X64_REG, .width = 8, .reg = 1}};
        drift(i, "shl", "shl [rbx+8]:ptr<user,u64>,cl", shift_mem_cl, 2, 1, 3, GAP_SHIFT_MEMORY);
        NtX64Operand shift_mem_imm[2] = {{.kind = NT_X64_MEM, .width = 64, .base = 3, .index = -1,
                                         .scale = 1, .disp = 8},
                                        {.kind = NT_X64_IMM, .imm = 1}};
        drift(i, "shl", "shl [rbx+8]:ptr<user,u64>,1", shift_mem_imm, 2, 1, 3, GAP_SHIFT_MEMORY);
    }
    {
        /* The fourth family, and the one the DRIFT-NOTE used to leave as prose:
         * the oracle mnemonics no export of x64_fixed names. None of them is a
         * literal anywhere in x64_fixed, so no export can match the name and
         * the encoder has no channel for the form at all. surface_closed
         * re-derives that absence from the module text on every run, and
         * oracle_closed re-derives the membership of the family from the
         * encoder itself, so the seven this table used to name by hand are no
         * longer the family: it is every mnemonic nt_x64_encode answers for and
         * x64_fixed does not spell. The module-side half of that is measured
         * here and not by a prose claim: surface_closed proves on every run
         * that no literal of the module is any of these nineteen, so no export
         * body can match the name at all. tests_ntasm_x64_fixed.c answers 401
         * directly for the seven it lists and does not yet name the twelve this
         * lot added, so on the module side those twelve rest on the absence of
         * the literal alone. The lowerer must refuse rather than invent bytes. */
        NtX64Operand unary64[1] = {{.kind = NT_X64_REG, .width = 64, .reg = 0}};
        drift(i, "bswap", "bswap rax", unary64, 1, 1, 3, GAP_NO_ENCODER);
        drift(i, "mul", "mul rax", unary64, 1, 1, 3, GAP_NO_ENCODER);
        drift(i, "div", "div rax", unary64, 1, 1, 3, GAP_NO_ENCODER);
        drift(i, "idiv", "idiv rax", unary64, 1, 1, 3, GAP_NO_ENCODER);
        NtX64Operand bit_pair[2] = {{.kind = NT_X64_REG, .width = 64, .reg = 0},
                                    {.kind = NT_X64_REG, .width = 64, .reg = 3}};
        drift(i, "bts", "bts rax,rbx", bit_pair, 2, 1, 3, GAP_NO_ENCODER);
        drift(i, "btr", "btr rax,rbx", bit_pair, 2, 1, 3, GAP_NO_ENCODER);
        drift(i, "btc", "btc rax,rbx", bit_pair, 2, 1, 3, GAP_NO_ENCODER);
        /* The twelve the hand-kept list had missed, one row each, in the order
         * oracle_closed finds them so the family reads the same either way.
         * Each is a form the oracle encodes: a form x64_fixed cannot state, and
         * the lowerer must answer a diagnostic rather than bytes. The eight that
         * need cpl 0 say so, because the oracle refuses them at cpl 3 and a row
         * declared on a form the oracle refuses is a void gap. */
        drift(i, "bt", "bt rax,rbx", bit_pair, 2, 1, 3, GAP_NO_ENCODER);
        drift(i, "imul", "imul rax,rbx", bit_pair, 2, 1, 3, GAP_NO_ENCODER);
        {
            /* read_cr takes the control register second and write_cr takes it
             * first, and the oracle's operand_valid is what decides that, so
             * the two rows are not mirror images of one another. A control
             * register is a 64 bit field; a narrower one is 403 before the
             * mnemonic is ever looked at. */
            NtX64Operand control[2] = {{.kind = NT_X64_REG, .width = 64, .reg = 0},
                                        {.kind = NT_X64_CR, .width = 64, .reg = 0}};
            drift(i, "read_cr", "read_cr rax,cr0", control, 2, 1, 0, GAP_NO_ENCODER);
            NtX64Operand control_first[2] = {{.kind = NT_X64_CR, .width = 64, .reg = 0},
                                             {.kind = NT_X64_REG, .width = 64, .reg = 0}};
            drift(i, "write_cr", "write_cr cr0,rax", control_first, 2, 1, 0, GAP_NO_ENCODER);
        }
        {
            /* The four descriptor instructions, two rows each way round the
             * privilege: the oracle refuses lgdt and lidt above cpl 0 and
             * encodes sgdt and sidt at any cpl, so the two pairs differ. The
             * operand is a memory descriptor, which the oracle calls width 80
             * and which no pointer element type in the language can spell; the
             * spelling below is the closest one that parses, and it is the
             * lowerer's refusal that the row measures. */
            NtX64Operand descriptor[1] = {{.kind = NT_X64_MEM, .width = 80, .base = 3, .index = -1,
                                           .scale = 1, .disp = 8}};
            drift(i, "sgdt", "sgdt [rbx+8]:ptr<user,array<u8,10>>", descriptor, 1, 1, 3, GAP_DESCRIPTOR_WIDTH);
            drift(i, "sidt", "sidt [rbx+8]:ptr<user,array<u8,10>>", descriptor, 1, 1, 3, GAP_DESCRIPTOR_WIDTH);
            drift(i, "lgdt", "lgdt [rbx+8]:ptr<user,array<u8,10>>", descriptor, 1, 1, 0, GAP_DESCRIPTOR_WIDTH);
            drift(i, "lidt", "lidt [rbx+8]:ptr<user,array<u8,10>>", descriptor, 1, 1, 0, GAP_DESCRIPTOR_WIDTH);
            /* ltr takes a 16 bit task register, register or memory, and invlpg
             * takes the address alone, which the oracle calls width 0. Both are
             * cpl 0 only. */
            NtX64Operand task[1] = {{.kind = NT_X64_REG, .width = 16, .reg = 0}};
            drift(i, "ltr", "ltr ax", task, 1, 1, 0, GAP_NO_ENCODER);
            NtX64Operand address_only[1] = {{.kind = NT_X64_MEM, .width = 0, .base = 3, .index = -1,
                                             .scale = 1, .disp = 8}};
            drift(i, "invlpg", "invlpg [rbx+8]:ptr<user,u64>", address_only, 1, 1, 0,
                  GAP_NO_ENCODER);
            /* in and out, both cpl 0: the accumulator is al, and the port is a
             * literal below 256. The oracle wants the accumulator first for in
             * and the port first for out, which is the operand order the two
             * rows state. */
            NtX64Operand port_imm[2] = {{.kind = NT_X64_REG, .width = 8, .reg = 0},
                                        {.kind = NT_X64_IMM, .imm = 96}};
            drift(i, "in", "in al,96", port_imm, 2, 1, 0, GAP_NO_ENCODER);
            NtX64Operand imm_first[2] = {{.kind = NT_X64_IMM, .imm = 96},
                                         {.kind = NT_X64_REG, .width = 8, .reg = 0}};
            drift(i, "out", "out 96,al", imm_first, 2, 1, 0, GAP_NO_ENCODER);
        }
    }
    /* Refusals: the oracle refuses the form and the lowerer must answer the
     * same diagnostic. The memory destination of the four register-destination
     * families, the register-memory spelling of test, and a literal where the
     * two-register families require a register or a memory. */
    {
        NtX64Operand mem_then_reg[2] = {{.kind = NT_X64_MEM, .width = 64, .base = 3, .index = -1,
                                         .scale = 1, .disp = 8},
                                        {.kind = NT_X64_REG, .width = 64, .reg = 0}};
        drift(i, "xchg", "xchg [rbx+8]:ptr<user,u64>,rax", mem_then_reg, 2, 1, 3, NULL);
        NtX64Operand mem32_then_reg[2] = {{.kind = NT_X64_MEM, .width = 32, .base = 3, .index = -1,
                                           .scale = 1, .disp = 8},
                                          {.kind = NT_X64_REG, .width = 32, .reg = 0}};
        drift(i, "cmove", "cmove [rbx+8]:ptr<user,u32>,eax", mem32_then_reg, 2, 1, 3, NULL);
        drift(i, "bsf", "bsf [rbx+8]:ptr<user,u64>,rax", mem_then_reg, 2, 1, 3, NULL);
        drift(i, "movzx", "movzx [rbx+8]:ptr<user,u64>,eax", mem_then_reg, 2, 1, 3, NULL);
        NtX64Operand reg_then_mem[2] = {{.kind = NT_X64_REG, .width = 64, .reg = 0},
                                        {.kind = NT_X64_MEM, .width = 64, .base = 3, .index = -1,
                                         .scale = 1, .disp = 8}};
        drift(i, "test", "test rax,[rbx+8]:ptr<user,u64>", reg_then_mem, 2, 1, 3, NULL);
        NtX64Operand reg_then_imm[2] = {{.kind = NT_X64_REG, .width = 64, .reg = 0},
                                        {.kind = NT_X64_IMM, .imm = 1}};
        drift(i, "xchg", "xchg rax,1", reg_then_imm, 2, 1, 3, NULL);
    }
    printf("DRIFT rows=%u reachable=%u declared_gaps=%u refused=%u gaps=%u kinds=%u closed=%u\n",
           drift_rows, drift_reachable, drift_declared, drift_refused, drift_reasons,
           gap_reason_kind_count, drift_closed_gaps);
    /* Pinned after the two-register lot: 46 rows moved from declared_gaps to
     * reachable (the four unaries, push and pop with a register, push with a
     * literal, the sixteen setcc conditions, xchg, test, the sixteen cmov
     * conditions, the two bit scans and the three width-conversion moves), 7
     * rows were added for the memory direction of those families, 15 rows were
     * added as declared gaps and 6 as refusals.
     * Pinned after the shift-immediate lot: 6 rows moved from declared_gaps to
     * reachable (the five shift and rotate mnemonics counted by the literal 1,
     * and the signed literal of push), and 3 rows were added as declared gaps
     * for the two forms the two shift exports cannot state: a high8
     * destination of the immediate form, and a memory destination counted by
     * cl or by a literal.
     * Pinned after the high8 and memory encoder lot: 18 rows were added, all of
     * them declared gaps, and none moved to reachable. The 18 are the high8
     * alias over the four unaries (3 new rows, `inc ah` was already there) and
     * the high8 alias over the sixteen setcc conditions (15 new rows, `sete ah`
     * was already there). The seven memory rows of the same three exports were
     * already enumerated, so they were left in place and only their reason
     * changed: the encoder can now emit every one of them. Reachable did not
     * move because this lot touches no lowerer file.
     * Pinned after the one-operand lowering lot: 27 rows moved from
     * declared_gaps to reachable and 2 rows were added as refusals.
     * The 27 that moved are the high8 alias over the four unaries (4 rows,
     * `inc ah`, `dec ah`, `not ah`, `neg ah`), the high8 alias over the sixteen
     * setcc conditions (16 rows, `sete ah` .. `setno ah`), the memory direction
     * of the four unaries (4 rows over `ptr<user,u64>`), and the memory
     * direction of push and pop (2 rows). The 2 rows added are the two widths
     * those three exports refuse: `sete [rbx+8]:ptr<user,u64>` and
     * `push [rbx+8]:ptr<user,u8>`, both 403 on the oracle side and both
     * answered 403 by the lowerer, so they are counted as refusals.
     * Pinned after the closure lot: 7 rows were added, all of them declared
     * gaps, and none moved to reachable. The 7 are the oracle mnemonics bswap,
     * bts, btr, btc, mul, div and idiv: none of them is a literal anywhere in
     * x64_fixed, so no export can match the name and the encoder has no
     * channel for the form at all. surface_closed re-derives that absence from
     * the module text on every run, and tests_ntasm_x64_fixed.c answers 401
     * for each of them, so the reason is two measurements and not this note.
     * Reachable and refused did not move because this lot touches no lowerer
     * and no encoder file. The table is no longer trusted to be complete: the
     * closure check, the row manifest and the eleven verdict cases are what
     * make the header claim true now, not the size of the table.
     * Pinned after the encoder-axis lot: 12 rows were added, all of them
     * declared gaps, and none moved to reachable or to refused. The 12 are the
     * oracle mnemonics the hand-kept absence list had simply not been told
     * about: bt, imul, read_cr, write_cr, sgdt, sidt, lgdt, lidt, ltr, invlpg,
     * in and out. The equation 138+31+8=177 was true and the table was still
     * incomplete, because an equation is satisfied by any set of rows that
     * adds up, including one that never names a mnemonic the encoder emits.
     * The absent list is no longer a list: oracle_closed re-derives it from
     * nt_x64_encode on every run, so 19 is what the two surfaces have between
     * them today and not a figure anyone chose.
     * Pinned after the imul encoder landed: ONE row moved, from declared_gaps to
     * reachable, and `imul rax,rbx` is the row. So 138 becomes 139, 43 becomes
     * 42, and drift_closed_gaps becomes 1 instead of 0 -- the gate counts the
     * closure itself, which is why that counter existed at zero. The absent list
     * is 17 now: imul left it, then bswap. The equation still adds up,
     * 147+34+8=189, and it is no longer the only thing holding. */
    CHECK(drift_rows == 189, "drift enumerates the whole x64_fixed surface");
    CHECK(drift_reachable == 181, "drift reachable forms");
    CHECK(drift_declared == 0, "drift declared gaps");
    CHECK(drift_refused == 8, "drift refusals that match the oracle diagnostic");
    CHECK(drift_reasons == drift_declared, "every declared gap carries a reason");
    CHECK(gap_reason_kind_count == 0, "no unresolved gap families remain");
    /* Nine, not thirteen: the descriptor lot did NOT move four rows out of the
     * declared gaps, and predicting that it would was my prediction and not a
     * measurement. The gate said so before I did. What moved was the REASON of
     * those four rows -- from "no export names it" to "no scalar states 80" --
     * which is why the family count went from 7 to 8 and the declared count did
     * not move at all. A gap whose cause changed has not closed. */
    CHECK(drift_closed_gaps == 43, "all 43 previously declared gaps are closed");
    CHECK(drift_reachable + drift_declared + drift_refused == drift_rows,
          "every drift row has exactly one counted outcome");
    CHECK(ROW_MANIFEST_COUNT == 189, "the row manifest holds one entry per row");
    CHECK(SURFACE_MANIFEST_COUNT == 28, "the export manifest holds one entry per export");
    CHECK(ALIAS_MANIFEST_COUNT == 1, "exactly one module literal is an alias of a row mnemonic");
    CHECK(STATEMENT_MANIFEST_COUNT == 2, "exactly two module literals are statement-owned");
    CHECK(PSEUDO_MANIFEST_COUNT == 1, "LEA is the remaining unnamed lowerer pseudo spelling");
    CHECK(ABSENT_MANIFEST_COUNT == 0, "no row mnemonic lacks an encoder");
}

/* The three counted outcomes, pinned directly. A detector that cannot be
 * observed to reject a mislabelled row is not a detector, so each way of
 * getting the label wrong is a case here instead of a hope. */
static void verdict_cases(void) {
    struct {
        unsigned oracle, lowerer, outcome;
        int match, expect_bad;
        const char *reason;
    } t[] = {
        {0, 0, DRIFT_REACHABLE, 1, 0, 0},
        {0, 0, DRIFT_REACHABLE, 1, 0, "a gap that is closed"},
        {0, 0, DRIFT_REACHABLE, 0, 1, 0},
        {0, 409, DRIFT_GAP, 0, 0, "the encoder has no channel for the form"},
        {0, 409, DRIFT_REACHABLE, 0, 1, 0},
        {0, 409, DRIFT_REACHABLE, 0, 1, ""},
        {0, 800, DRIFT_REACHABLE, 0, 1, "the harness buffer is too short"},
        {403, 403, DRIFT_REFUSED, 0, 0, 0},
        {403, 409, DRIFT_REFUSED, 0, 1, 0},
        {403, 0, DRIFT_REFUSED, 0, 1, 0},
        {403, 403, DRIFT_REFUSED, 0, 1, "a gap on a form the oracle refuses"},
    };
    for (unsigned k = 0; k < sizeof t / sizeof *t; k++) {
        unsigned outcome = 0xdead;
        int bad = drift_verdict(t[k].oracle, t[k].lowerer, t[k].match, t[k].reason, &outcome);
        cases++;
        checks++;
        if ((bad != 0) != (t[k].expect_bad != 0) || (!bad && outcome != t[k].outcome)) {
            failures++;
            fprintf(stderr, "FAIL verdict case %u: bad=%d outcome=%u\n", k, bad, outcome);
        }
    }
}

int main(void) {
    setvbuf(stdout,NULL,_IOLBF,0);
    verdict_cases();
    const char *paths[] = {"tests/nova/tests/x64-lower-lea-entry.nova",
                           "compiler/nova/backend/x64/x64_lower_fixed.nova",
                           "compiler/nova/backend/x64/x64_fixed.nova",
                           "compiler/nova/analysis/types/register_widths.nova",
                           "compiler/nova/frontend/parser.nova",
                           "compiler/nova/frontend/ast.nova",
                           "compiler/nova/frontend/lexer.nova", "compiler/nova/backend/x64/x64_lower_control.nova"};
    char *sources[8] = {0};
    NtFInput inputs[8];
    for (unsigned k = 0; k < 8; k++) {
        size_t n = 0;
        sources[k] = loadf(paths[k], &n);
        inputs[k] = (NtFInput){paths[k], sources[k], n};
    }
    int all = 1;
    for (unsigned k = 0; k < 8; k++)
        if (!sources[k]) all = 0;
    CHECK(all, "sources load");
    /* The C encoder, read as text and not compiled here: this gate already
     * links it and already compares every row against it, so the file the
     * expectations come from is the file the answers come from. A missing or
     * relocated file has to be a failure, not an empty alphabet the closure
     * would then find reasons in. */
    char *oracle_text = loadf("compiler/c/ntasm/backend/x64.c", &oracle_source_len);
    CHECK(oracle_text != 0, "the C encoder text loads for the encoder-side closure");
    oracle_source = oracle_text;
    NtArtifact a = {0};
    int compiled = all && nova_compile_many_v2(inputs, 8, &a);
    CHECK(compiled, "modules compile");
    if (!compiled) fprintf(stderr, "E%u %zu:%zu %s\n", a.error.code, a.error.line, a.error.column, a.error.message);
    NovaHostImage image = {0};
    CHECK(compiled && nova_host_map(&a, &image), "image maps");
    if (image.memory) {
        lea_cases(&image);
        drift_surface(&image);
        module_text = sources[2];
        module_len = sources[2] ? strlen(sources[2]) : 0;
        statement_cases(&image);
        row_closure();
        surface_cases();
    }
    if (image.memory) nova_host_unmap(&image);
    if (compiled) nt_artifact_free(&a);
    for (unsigned k = 0; k < 8; k++) free(sources[k]);
    free(oracle_text);
    printf("NTASM_NOVA_X64_LOWER_LEA checks=%u failures=%u cases=%u\n", checks, failures, cases);
    return failures ? 1 : 0;
}
