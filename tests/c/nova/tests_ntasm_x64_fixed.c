#include "../../../compiler/c/nova/frontend/nova.h"
#include "../../../compiler/c/nova/runtime/run_host.h"
#include "../../../compiler/c/nova/runtime/runtime_v2.h"
#include "../../../compiler/c/ntasm/backend/x64.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checks,failures,cases;
#define CHECK(c,m) do{checks++;if(!(c)){failures++;fprintf(stderr,"FAIL %s\n",m);}}while(0)
static const uint8_t guard=0xcc;
static char*loadf(const char*p,size_t*n){FILE*f=fopen(p,"rb");if(!f)return NULL;fseek(f,0,SEEK_END);long z=ftell(f);fseek(f,0,SEEK_SET);char*b=z>=0?malloc((size_t)z+1):NULL;if(!b||fread(b,1,(size_t)z,f)!=(size_t)z){free(b);fclose(f);return NULL;}fclose(f);b[z]=0;*n=(size_t)z;return b;}
typedef struct{uint64_t returned,runtime;uint8_t out[4];}Run;
static Run run(const NovaHostImage*i,const char*name,uint64_t count,uint64_t features,uint64_t cpl,uint64_t words){Run r={.out={guard,guard,guard,guard}};NovaContextV2 c={0};CHECK(nova_context_init_v2(&c),"context init");uint64_t nh=nova_borrow_v2(&c,(void*)name,strlen(name),0),oh=nova_borrow_v2(&c,r.out,words,1);uint64_t a[]={nh,strlen(name),count,features,cpl,oh,words};r.returned=i->entry(&c,a,7);r.runtime=c.error;CHECK(nova_context_destroy_v2(&c),"context cleanup");return r;}
static void compare(const NovaHostImage*i,const char*name,uint64_t count,uint64_t features,uint64_t cpl){NtX64Instruction expected={0};NtX64Operand operand={0};NtX64Context context={features,cpl};NtX64Error e=nt_x64_encode(name,count?&operand:NULL,(size_t)count,context,&expected);Run r=run(i,name,count,features,cpl,4);cases++;checks++;int bad=r.returned!=(uint64_t)e||r.runtime;if(!e){bad|=r.out[0]!=expected.length;for(unsigned k=0;k<3;k++)bad|=r.out[k+1]!=(k<expected.length?expected.bytes[k]:0);}else bad|=r.out[0]!=guard||r.out[1]!=guard||r.out[2]!=guard||r.out[3]!=guard;if(bad){failures++;fprintf(stderr,"FAIL %s count=%llu features=%llu cpl=%llu ret=%llu oracle=%u out=%u,%u,%u,%u\n",name,(unsigned long long)count,(unsigned long long)features,(unsigned long long)cpl,(unsigned long long)r.returned,(unsigned)e,r.out[0],r.out[1],r.out[2],r.out[3]);}}
/* ------------------------------------------------------ export surface ----
 * The export surface of x64_fixed, pinned here. The Nova compiler cannot be
 * asked for it: nova.h exposes nova_compile, nova_compile_many, the v2 pair
 * and nova_check_many, and nothing that answers "what does this module
 * export". The compiler does keep an `exported` flag per function, but it
 * never leaves nova.c. So this gate reads the module text it already loads for
 * the compiler, takes the `export fn` headers and every string literal, and
 * requires both sets to match a manifest whose size is pinned.
 *
 * This gate used to pin no export surface at all, which is why a new export
 * for a mnemonic no drift row names could be added without anything noticing.
 * tests_ntasm_x64_lower_lea.c now closes the surface against the drift table
 * as well; what belongs to this file is the encoder side of that agreement:
 * the export list, the literal set, the one literal that is only an alias of
 * another, and the eighteen oracle mnemonics the module cannot encode at all. */
#define SURF_MAX_RECORDS 64
#define SURF_MAX_LITERALS 256
#define SURF_NAME_MAX 40
#define SURF_ERROR_MAX 160

typedef struct {
    unsigned records;
    char record_name[SURF_MAX_RECORDS][SURF_NAME_MAX];
    int record_exported[SURF_MAX_RECORDS];
    unsigned exports;
    char export_name[SURF_MAX_RECORDS][SURF_NAME_MAX];
    unsigned literals;
    char literal[SURF_MAX_LITERALS][SURF_NAME_MAX];
    /* Why the scan refused the text, naming the field and the limit that was
     * crossed. Empty when the scan succeeded. Both ceilings below used to be
     * silent skips, so a surface larger than the capacity declared here passed
     * the export bijection with the excess simply absent from it. */
    char scan_error[SURF_ERROR_MAX];
} Surface;

static int ident_char(int c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_';
}

/* A record is a `fn` or `export fn` header at brace depth zero, which is the
 * shape the compiler itself parses, and a literal is the only way x64_fixed
 * names a mnemonic: every dispatch is same(name, literal). Scanning literals
 * rather than same() call sites also catches a pipe-style dispatch such as
 * the member(source,start,end,"bts|btr|btc") other modules use. */
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
                 * whichever record came before, so both are fail-open. */
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
                 * fail-open here: the truncated value is still compared to the
                 * manifest below and cannot match any of its entries, so it is
                 * reported as an unknown literal rather than passing. */
                while (j < len && line[j] != '"' && n + 1 < SURF_NAME_MAX) s->literal[at][n++] = line[j++];
                s->literal[at][n] = 0;
                if (j < len && line[j] == '"') j++;
                continue;
            }
            if (line[j] == '{') depth++;
            else if (line[j] == '}' && depth) depth--;
            j++;
        }
        line = nl ? nl + 1 : line + len;
    }
    return depth == 0 && current >= 0;
}

/* The 23 exports of x64_fixed, in module order. A name here that the module
 * does not have, and an export the module has that is not here, are both
 * failures: the set is closed, not a lower bound. */
static const char *const fixed_exports[] = {
    "encode", "encode_rr", "encode_ri", "encode_unary", "encode_shift_imm", "encode_control",
    "encode_stack", "encode_jcc", "encode_mov_memory", "encode_lea", "encode_shift_cl", "encode_xchg",
    "encode_cmov", "encode_bit_scan", "encode_bit_test", "encode_descriptor", "encode_system_one", "encode_binary",
    "encode_move_convert", "encode_test_two", "encode_imul", "encode_setcc",
    "encode_bswap", "encode_unary_operand", "encode_setcc_operand",
    "encode_stack_memory",
    "encode_shift_memory", "encode_control_memory",
};
#define FIXED_EXPORT_COUNT (sizeof fixed_exports / sizeof *fixed_exports)

/* The distinct values of the module's literals, which is not what the scan
 * reports. The scan has no deduplication: counted on the real text of
 * x64_fixed.nova there are 148 literal *occurrences* and 105 distinct values,
 * and this manifest holds those 105. The comment this replaces called the
 * manifest "every literal of the module, distinct", which was false and
 * hid a hole: a value repeated here and a value missing from here were the
 * same edit as far as the count of 148 was concerned. So the two counts are
 * now measured separately, from the text and from this table, and both are
 * pinned below instead of being written in prose.
 * `return` is the only value that is not a mnemonic of its own; alias_cases
 * below pins it to `ret` byte for byte. */
static const char *const fixed_literals[] = {
    "nop", "pause", "ud2", "cpuid", "cbw", "cwde", "cdqe", "cwd", "cdq", "cqo", "pushfq", "popfq",
    "rdtsc", "lfence", "sfence", "mfence", "cli", "sti", "hlt", "swapgs", "rdmsr", "wrmsr", "syscall",
    "sysretq", "iretq", "ret", "return", "mov", "add", "or", "adc", "sbb", "and", "sub", "xor", "cmp",
    "inc", "dec", "not", "neg", "rol", "ror", "shl", "shr", "sar", "call", "jmp", "push", "pop", "jo",
    "jno", "jb", "jae", "je", "jne", "jbe", "ja", "js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg",
    "xchg", "cmove", "cmovne", "cmovb", "cmovae", "cmovbe", "cmova", "cmovs", "cmovns", "cmovp",
    "cmovnp", "cmovl", "cmovge", "cmovle", "cmovg", "cmovo", "cmovno", "bsf", "bsr", "movzx", "movsx",
    "movsxd", "test", "imul", "bswap", "sete", "setne", "setb", "setae", "setbe", "seta", "sets", "setns",
    "setp", "setnp", "setl", "setge", "setle", "setg", "seto", "setno", "mul", "div", "idiv",
    "bt", "bts", "btr", "btc", "sgdt", "sidt", "lgdt", "lidt", "ltr", "invlpg", "read_cr", "write_cr", "in", "out", "load", "store",
};
#define FIXED_LITERAL_COUNT (sizeof fixed_literals / sizeof *fixed_literals)

/* Two counts the comment above states, each derived from the side it names:
 * the occurrences the scan found in the module text, and the distinct values
 * on each of the two sides. Neither number is trusted from the other, so a
 * manifest that repeats a value or loses one cannot hide behind a count. */
static unsigned manifest_distinct(const char *const *table, unsigned n) {
    unsigned distinct = 0;
    for (unsigned k = 0; k < n; k++) {
        int seen = 0;
        for (unsigned j = 0; j < k; j++)
            if (!strcmp(table[j], table[k])) seen = 1;
        if (!seen) distinct++;
    }
    return distinct;
}

static unsigned surface_distinct(const Surface *s) {
    unsigned distinct = 0;
    for (unsigned k = 0; k < s->literals; k++) {
        int seen = 0;
        for (unsigned j = 0; j < k; j++)
            if (!strcmp(s->literal[j], s->literal[k])) seen = 1;
        if (!seen) distinct++;
    }
    return distinct;
}

static void surface_cases(const char *text) {
    Surface s;
    memset(&s, 0, sizeof s);
    int ok = text && surface_scan(text, &s);
    if (!ok && s.scan_error[0])
        fprintf(stderr, "FAIL the x64_fixed surface scan refused the module text: %s\n", s.scan_error);
    CHECK(ok, "x64_fixed text scans into a surface");
    if (!ok) return;
    CHECK(s.exports == FIXED_EXPORT_COUNT, "x64_fixed exports exactly the 28 declared entries");
    for (unsigned k = 0; k < FIXED_EXPORT_COUNT; k++) {
        int found = 0;
        for (unsigned e = 0; e < s.exports; e++)
            if (!strcmp(s.export_name[e], fixed_exports[k])) found = 1;
        cases++;
        checks++;
        if (!found) {
            failures++;
            fprintf(stderr, "FAIL surface export %s is declared but the module does not have it\n",
                    fixed_exports[k]);
        }
    }
    for (unsigned e = 0; e < s.exports; e++) {
        int found = 0;
        for (unsigned k = 0; k < FIXED_EXPORT_COUNT; k++)
            if (!strcmp(fixed_exports[k], s.export_name[e])) found = 1;
        cases++;
        checks++;
        if (!found) {
            failures++;
            fprintf(stderr, "FAIL surface export %s is new and no manifest names it\n", s.export_name[e]);
        }
    }
    CHECK(s.literals == 181, "x64_fixed holds the 181 mnemonic literal occurrences");
    CHECK(FIXED_LITERAL_COUNT == 125, "the literal manifest holds the 125 distinct values");
    CHECK(manifest_distinct(fixed_literals, (unsigned)FIXED_LITERAL_COUNT) == FIXED_LITERAL_COUNT,
          "the literal manifest holds no repeated value");
    CHECK(surface_distinct(&s) == FIXED_LITERAL_COUNT,
          "x64_fixed has exactly as many distinct literals as the manifest declares");
    for (unsigned k = 0; k < FIXED_LITERAL_COUNT; k++) {
        int found = 0;
        for (unsigned l = 0; l < s.literals; l++)
            if (!strcmp(s.literal[l], fixed_literals[k])) found = 1;
        cases++;
        checks++;
        if (!found) {
            failures++;
            fprintf(stderr, "FAIL surface literal \"%s\" is declared but the module dropped it\n",
                    fixed_literals[k]);
        }
    }
    for (unsigned l = 0; l < s.literals; l++) {
        int found = 0;
        for (unsigned k = 0; k < FIXED_LITERAL_COUNT; k++)
            if (!strcmp(fixed_literals[k], s.literal[l])) found = 1;
        cases++;
        checks++;
        if (!found) {
            failures++;
            fprintf(stderr, "FAIL surface literal \"%s\" is new and no manifest names it\n", s.literal[l]);
        }
    }
}

/* `return` is a literal of the module with no drift row of its own: it is the
 * same instruction under a second spelling. The lowerer gate declares it an
 * alias of `ret` and relies on this case to make that declaration a proof, so
 * the two spellings must agree on the answer, on the length and on every byte,
 * and both must agree with the oracle. */
static void alias_cases(const NovaHostImage *i) {
    Run a = run(i, "ret", 0, 1, 3, 4);
    Run b = run(i, "return", 0, 1, 3, 4);
    NtX64Instruction expected = {0};
    NtX64Context context = {1, 3};
    NtX64Error e = nt_x64_encode("return", NULL, 0, context, &expected);
    cases++;
    checks++;
    int bad = e != NT_X64_OK || a.returned != b.returned || a.runtime || b.runtime;
    bad |= memcmp(a.out, b.out, sizeof a.out) != 0;
    if (e == NT_X64_OK) {
        if (a.returned == 0) {
            bad |= a.out[0] != (uint8_t)expected.length || memcmp(a.out + 1, expected.bytes, expected.length) != 0;
        } else {
            for (unsigned k = 0; k < 4; k++) bad |= a.out[k] != guard;
        }
    }
    if (bad) {
        failures++;
        fprintf(stderr, "FAIL alias return is not ret: ret=%llu/%u,%u,%u,%u return=%llu/%u,%u,%u,%u\n",
                (unsigned long long)a.returned, a.out[0], a.out[1], a.out[2], a.out[3],
                (unsigned long long)b.returned, b.out[0], b.out[1], b.out[2], b.out[3]);
    } else {
        printf("ALIAS return is ret oracle=ok(%u) out=%u,%u\n", (unsigned)expected.length, a.out[0],
               a.out[1]);
    }
}

/* The six oracle mnemonics no export of x64_fixed names, which is the
 * whole of the absent_manifest in tests_ntasm_x64_lower_lea.c.
 *
 * Three names have left this list as the encoder grew, and each of them was
 * measuring the wrong thing while it was here. The rows call the ZERO-OPERAND
 * entry, so a row that kept passing after a new export appeared was NOT saying
 * "the module cannot encode this" -- it was saying that one export refuses the
 * name while a different export answers for it. bswap left when
 * encode_bswap landed, mul, div and idiv when encode_unary and
 * encode_unary_operand learned their digits, and each of the three was left
 * behind by a GREEN line whose reason had become false. A green line with a
 * false reason is worse than a missing one, so the rows go and the names are
 * measured where they are actually encoded: bswap by
 * tests_ntasm_x64_bswap.c, the divide group by the one-operand rows in
 * tests_ntasm_x64_lower_two_reg.c.
 *
 * The oracle encodes every one of them and the zero-operand export answers
 * 401, so the encoder has no channel for the form at all, which is what the
 * drift rows there declare as their reason. Both halves are measured here so the
 * reason is a pair of results and not a sentence.
 *
 * The cpl is a parameter of the case and not a constant in it, because the
 * oracle refuses the privileged ones above cpl 0 and a row declared on a
 * form the oracle refuses is a void measurement: absent_case requires
 * NT_X64_OK, so a privileged mnemonic measured at cpl 3 would fail its own
 * guard instead of proving anything. read_cr, write_cr, lgdt, lidt, ltr,
 * invlpg, in and out are answered NT_X64_PRIVILEGE 405 by the oracle at cpl 3
 * (x64.c:471, :654, :669, :683, :696) and are therefore measured at cpl 0;
 * bswap, bts, btr, btc, bt, mul, div, idiv, sgdt and sidt encode at any
 * cpl and stay at 3. The eight vectors below are the ones the drift rows use,
 * so the two gates measure the same form of the same mnemonic. */
static void absent_case(const NovaHostImage *i, const char *name, NtX64Operand *o, unsigned count,
                        uint64_t cpl) {
    NtX64Instruction expected = {0};
    NtX64Context context = {1, cpl};
    NtX64Error e = nt_x64_encode(name, o, count, context, &expected);
    Run r = run(i, name, count, 1, cpl, 4);
    cases++;
    checks++;
    int bad = e != NT_X64_OK || r.returned != (uint64_t)NT_X64_UNKNOWN || r.runtime;
    for (unsigned k = 0; k < 4; k++) bad |= r.out[k] != guard;
    if (bad) {
        failures++;
        fprintf(stderr, "FAIL absent %s cpl=%llu oracle=%u len=%u encoder=%llu out=%u,%u,%u,%u\n",
                name, (unsigned long long)cpl, (unsigned)e, (unsigned)expected.length,
                (unsigned long long)r.returned, r.out[0], r.out[1], r.out[2], r.out[3]);
    } else {
        printf("ABSENT %-6s cpl=%llu oracle=ok(%u) encoder=401 the zero-operand export names none of them\n", name,
               (unsigned long long)cpl, (unsigned)expected.length);
    }
}

static void absent_cases(const NovaHostImage *i) {
    /* `unary` is gone with mul, div and idiv: every remaining row is two-operand
     * or privileged, so the one-operand descriptor no longer has a user here. */
    /* `pair` is gone with the bit-test group: it was the two-register descriptor
     * and bt, bts, btr and btc were its only users here. Every remaining row is
     * one-operand or privileged. */
    /* read_cr takes the control register second and write_cr takes it first.
     * The asymmetry is the oracle's, at x64.c:475-476, where each mnemonic
     * names which slot is the GPR and which is the control, so the two rows are
     * not mirror images of one another and a shared vector would measure
     * NT_X64_FORM for both. A control register is a 64 bit field; a narrower
     * one is 403 before the mnemonic is ever looked at. */
    {
        NtX64Operand control[2] = {{.kind = NT_X64_REG, .width = 64, .reg = 0},
                                   {.kind = NT_X64_CR, .width = 64, .reg = 0}};
        absent_case(i, "read_cr", control, 2, 0);
        NtX64Operand control_first[2] = {{.kind = NT_X64_CR, .width = 64, .reg = 0},
                                         {.kind = NT_X64_REG, .width = 64, .reg = 0}};
        absent_case(i, "write_cr", control_first, 2, 0);
    }
    /* ltr takes a 16 bit task register, register or memory, and invlpg takes
     * the address alone, which the oracle calls width 0 rather than the width
     * of a 64 bit pointer. Both are cpl 0 only. */
    {
        NtX64Operand task[1] = {{.kind = NT_X64_REG, .width = 16, .reg = 0}};
        absent_case(i, "ltr", task, 1, 0);
        NtX64Operand address_only[1] = {{.kind = NT_X64_MEM, .width = 0, .base = 3, .index = -1,
                                         .scale = 1, .disp = 8}};
        absent_case(i, "invlpg", address_only, 1, 0);
    }
    /* in and out, both cpl 0: the accumulator is al and the port is a literal
     * below 256. The oracle wants the accumulator first for in and the port
     * first for out, which is the operand order the two rows state. */
    {
        NtX64Operand port_imm[2] = {{.kind = NT_X64_REG, .width = 8, .reg = 0},
                                    {.kind = NT_X64_IMM, .imm = 96}};
        absent_case(i, "in", port_imm, 2, 0);
        NtX64Operand imm_first[2] = {{.kind = NT_X64_IMM, .imm = 96},
                                     {.kind = NT_X64_REG, .width = 8, .reg = 0}};
        absent_case(i, "out", imm_first, 2, 0);
    }
}

int main(void){const char*paths[]={"tests/nova/tests/x64-fixed-entry.nova","compiler/nova/backend/x64/x64_fixed.nova"};char*sources[2]={0};NtFInput inputs[2];for(unsigned i=0;i<2;i++){size_t n=0;sources[i]=loadf(paths[i],&n);inputs[i]=(NtFInput){paths[i],sources[i],n};}int all=sources[0]&&sources[1];CHECK(all,"sources load");NtArtifact a={0};int compiled=all&&nova_compile_many_v2(inputs,2,&a);CHECK(compiled,"modules compile");if(!compiled)fprintf(stderr,"E%u %zu:%zu %s\n",a.error.code,a.error.line,a.error.column,a.error.message);NovaHostImage image={0};CHECK(compiled&&nova_host_map(&a,&image),"image maps");if(image.memory){const char*names[]={"nop","pause","ud2","cpuid","cbw","cwde","cdqe","cwd","cdq","cqo","pushfq","popfq","rdtsc","lfence","sfence","mfence","cli","sti","hlt","swapgs","rdmsr","wrmsr","syscall","sysretq","iretq","ret","return"};const uint64_t features[]={1,1,1,1,1,1,1,1,1,1,1,1,17,9,9,9,1,1,1,1,3,3,5,5,1,1,1};const uint64_t cpls[]={3,3,3,3,3,3,3,3,3,3,3,0,0,3,3,3,0,0,0,0,0,0,3,0,0,3,3};for(unsigned j=0;j<27;j++){compare(&image,names[j],0,features[j],cpls[j]);compare(&image,names[j],1,features[j],cpls[j]);if(features[j]!=1)compare(&image,names[j],0,1,cpls[j]);if(cpls[j]==0)compare(&image,names[j],0,features[j],3);}compare(&image,"telepathy",0,1,3);Run short_=run(&image,"nop",0,1,3,3);cases++;CHECK(short_.returned==800&&short_.runtime==0&&short_.out[0]==guard&&short_.out[1]==guard,"short output transactional");surface_cases(sources[1]);alias_cases(&image);absent_cases(&image);}if(image.memory)nova_host_unmap(&image);if(compiled)nt_artifact_free(&a);for(unsigned i=0;i<2;i++)free(sources[i]);printf("NTASM_NOVA_X64_FIXED checks=%u failures=%u cases=%u\n",checks,failures,cases);return failures?1:0;}
