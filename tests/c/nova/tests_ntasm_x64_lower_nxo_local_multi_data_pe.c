#include "../../../compiler/c/nova/frontend/nova.h"
#include "../../../compiler/c/nova/runtime/run_host.h"
#include "../../../compiler/c/nova/runtime/runtime_v2.h"
#include "../../../compiler/c/ntasm/formats/object.h"
#include "../../../compiler/c/ntasm/frontend/frontend.h"
#include "../../../compiler/c/ntasm/backend/codegen.h"
#include "../../../compiler/c/ntasm/backend/x64.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Multi-call + scalar-data producer to PE, measured against the real C pipeline.
 *
 * This gate used to build its expectation by hand: make_object packed the data
 * items back to back in declaration order, summing the widths into ro_bytes and
 * data_bytes, then nt_object_materialize and nt_make_pe over that. The golden
 * encodes the pre-spec layout, and the 64 item fixture summed widths to 120/120
 * where the canonical layout is 128/128 with alpha-style alignment padding. The
 * per item "materialized data little-endian in source order" loop re-asserted
 * the same packed offsets, so the gate confirmed whatever the producer emitted.
 *
 * The data half of the expectation now comes from the C frontend and codegen,
 * nt_frontend_compile_object + nt_codegen_x64_object + nt_object_write, which
 * lays items out by ascending byte-wise unsigned name and aligns each one to
 * min(width,8) exactly as spec/formats/nxo-v0.md requires. The .text half stays the
 * producer's own documented instruction stream, encoded by nt_x64_encode, the C
 * x64 oracle: build_local_data_core emits bare calls and rets and the C frontend
 * refuses that body (503), so no C parity is claimed for it. The assembled object
 * is cross checked field by field against the data half of nt_object_compile, the
 * canonical builder of the same C frontend, so the expectation is proven to carry
 * the canonical layout rather than asserted to.
 *
 * This entry writes only a PE, so the producer's own layout is read back out of
 * the produced image: the .rdata and .data section virtual sizes and payload
 * bytes. A symbol offset is a function of that layout, so a payload that matches
 * the canonical payload byte for byte carries the canonical offsets. The row
 * therefore reports C_off from the C table and no nova_off, because a PE holds no
 * symbol table.
 *
 * One row per fixture, verbatim:
 *   DATA <label> scope=data pe_rdata=<n> pe_data=<n> C_rdata=<n> C_data=<n>
 *        C_off=<name@off,...> verdict=IDENTICAL|DIVERGES first=<n> <detail>
 */

enum { MODE_DATA_FIRST=1, MODE_ARITY=2, MODE_BAD_FIRST=4, MODE_BAD_LAST=8,
       MODE_AFTER_RET=16, MODE_EXTRA_FN=32, MODE_EXTRA_SEC=64 };

static unsigned checks,failures,cases;
#define CHECK(c,m) do{checks++;if(!(c)){failures++;fprintf(stderr,"FAIL %s\n",m);}}while(0)
#define CHECKL(c,m,l) do{checks++;if(!(c)){failures++; \
    fprintf(stderr,"FAIL %s [%s]\n",(l),(m));}}while(0)
static char *loadf(const char*p,size_t*n){FILE*f=fopen(p,"rb");if(!f)return NULL;fseek(f,0,SEEK_END);long z=ftell(f);fseek(f,0,SEEK_SET);char*b=z>=0?malloc((size_t)z+1):NULL;if(!b||fread(b,1,(size_t)z,f)!=(size_t)z){free(b);fclose(f);return NULL;}fclose(f);b[z]=0;*n=(size_t)z;return b;}
static uint64_t r64(const uint8_t*b){uint64_t v=0;for(unsigned i=0;i<8;i++)v|=(uint64_t)b[i]<<(i*8);return v;}
static uint16_t rd16(const uint8_t*b){return (uint16_t)(b[0]|((uint16_t)b[1]<<8));}
static uint32_t rd32(const uint8_t*b){return (uint32_t)rd16(b)|((uint32_t)rd16(b+2)<<16);}
static uint64_t width_of(unsigned i){static const unsigned w[4]={1,2,4,8};return w[i%4];}
static uint64_t value_of(unsigned i){return (uint64_t)(i*3+1);}
static size_t encode_(uint8_t*out,const char*name,NtX64Operand*op,size_t n){
    NtX64Instruction encoded={0};NtX64Context ctx={1,3};
    CHECK(nt_x64_encode(name,op,n,ctx,&encoded)==0,"C x64 oracle");
    memcpy(out,encoded.bytes,encoded.length);return encoded.length;
}

/* ------------------------------------------------------------------ *
 * Contract oracle.
 *
 * Every contract text this gate expects is read out of the C object writer,
 * never copied out of the Nova producer. nt_object_compile is
 * nt_frontend_compile_object + nt_codegen_x64_object + nt_object_write, so
 * the text it hands back is what object_build.c contract_text builds for the
 * declaration in the probe. A probe is a module written here, never a
 * recording of producer output, so a producer that drifted fails the
 * comparison instead of confirming itself. Where the two disagree the case
 * fails and prints both strings.
 * ------------------------------------------------------------------ */

typedef struct { const char *label, *probe, *name; } ContractProbe;

/* Every field contract_text prints is varied below: target, abi, features,
 * section, return type, bound and unbound parameters, the effects triple,
 * the clobbers mask, requires and ensures, and the data form over both data
 * sections and all four widths. stack_aligned is absent on purpose: its
 * literal argument carries no type, so object_build.c cannot print it and
 * nt_object_compile refuses such a module with 800. */
static const ContractProbe contract_probes[] = {
    {"fn_uefi_plain",
     "module d\ntarget x86_64-nexora-uefi\nsection .text {\nexport fn f()->u64\n"
     "effects {}\nclobbers {} {\nreturn 0\n}\n}\n", "f"},
    {"fn_none_plain",
     "module d\ntarget x86_64-nexora-none\nsection .text {\nexport fn f()->u64\n"
     "effects {}\nclobbers {} {\nreturn 0\n}\n}\n", "f"},
    {"fn_abi_efi",
     "module d\ntarget x86_64-nexora-uefi\nsection .text {\nexport fn f()->u64\n"
     "abi efi-x64-v0\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n", "f"},
    {"fn_return_u32",
     "module d\ntarget x86_64-nexora-uefi\nsection .text {\n"
     "export fn f(in p:u64 @rdi)->u32\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n", "f"},
    {"fn_features_sse2",
     "module d\ntarget x86_64-nexora-uefi\nfeatures {sse2}\nsection .text {\n"
     "export fn f()->u64\neffects {}\nclobbers {}\n"
     "requires {feature(sse2)}\nensures {feature(sse2)} {\nreturn 0\n}\n}\n", "f"},
    {"fn_clobbers_mask",
     "module d\ntarget x86_64-nexora-uefi\nsection .text {\nexport fn f()->u64\n"
     "effects {}\nclobbers {rax,rbx,r12} {\nreturn 0\n}\n}\n", "f"},
    {"fn_effects_flags",
     "module d\ntarget x86_64-nexora-uefi\nsection .text {\nexport fn f()->u64\n"
     "effects {privileged,changes_flags,mmio,io_port,msr,control,interrupt_state,"
     "reads_mem,writes_mem}\nclobbers {} {\nreturn 0\n}\n}\n", "f"},
    {"fn_effects_spaces",
     "module d\ntarget x86_64-nexora-uefi\nsection .text {\nexport fn f()->u64\n"
     "effects {reads_mem(user),reads_mem(mmio),writes_mem(kernel)}\nclobbers {} {\n"
     "return 0\n}\n}\n", "f"},
    {"fn_params_bound",
     "module d\ntarget x86_64-nexora-uefi\nsection .text {\n"
     "export fn f(in a:ptr<user,u64> @rdi,in b:u64 @rsi,out c:u64 @r8)->u64\n"
     "effects {}\nclobbers {} {\nmov r8, 0\nreturn 0\n}\n}\n", "f"},
    {"fn_params_unbound",
     "module d\ntarget x86_64-nexora-uefi\nsection .text {\n"
     "export fn f(in a:u64,in b:u32,in c:ptr<user,u64>)->u64\n"
     "effects {}\nclobbers {} {\nreturn 0\n}\n}\n", "f"},
    {"fn_params_mixed",
     "module d\ntarget x86_64-nexora-uefi\nsection .text {\n"
     "export fn f(in a:ptr<user,u64> @rdi,in b:u64,out c:u64 @r8)->u64\n"
     "effects {writes_mem}\nclobbers {rax} {\nmov r8, 0\nreturn 0\n}\n}\n", "f"},
    {"fn_predicates",
     "module d\ntarget x86_64-nexora-uefi\nsection .text {\n"
     "export fn f(in p:ptr<mmio,u8> @rdi)->u64\neffects {}\nclobbers {}\n"
     "requires {non_null(p)}\nensures {non_null(p)} {\nreturn 0\n}\n}\n", "f"},
    {"fn_predicates_sorted",
     "module d\ntarget x86_64-nexora-uefi\nfeatures {sse2}\nsection .text {\n"
     "export fn f(in p:ptr<user,u64> @rdi,in q:ptr<user,u64> @rsi)->u64\n"
     "effects {}\nclobbers {}\n"
     "requires {non_null(q),non_null(p),feature(sse2)}\n"
     "ensures {non_null(p),non_null(q)} {\nreturn 0\n}\n}\n", "f"},
    {"fn_everything",
     "module d\ntarget x86_64-nexora-uefi\nfeatures {sse2}\nsection .text {\n"
     "export fn f(in p:ptr<user,u64> @rdi,in q:u64,out r:u64 @r8)->u64\n"
     "effects {privileged,changes_flags,reads_mem,writes_mem}\nclobbers {rax,rbx,r12}\n"
     "requires {feature(sse2),non_null(p)}\nensures {non_null(p)} {\nmov r8, 0\nreturn 0\n}\n}\n",
     "f"},
    {"fn_everything_bare",
     "module d\ntarget x86_64-nexora-none\nfeatures {sse2}\nsection .text {\n"
     "export fn f(in p:ptr<user,u64> @rdi,in q:u64,out r:u64 @r8)->u64\n"
     "effects {privileged,changes_flags,reads_mem,writes_mem}\nclobbers {rax,rbx,r12}\n"
     "requires {feature(sse2),non_null(p)}\nensures {non_null(p)} {\nmov r8, 0\nreturn 0\n}\n}\n",
     "f"},
    {"data_rdata_u8",
     "module d\ntarget x86_64-nexora-uefi\nsection .rdata {\nexport data item:u8=1\n}\n"
     "section .text {\nexport fn f()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n", "item"},
    {"data_rdata_u16",
     "module d\ntarget x86_64-nexora-uefi\nsection .rdata {\nexport data item:u16=1\n}\n"
     "section .text {\nexport fn f()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n", "item"},
    {"data_rdata_u32",
     "module d\ntarget x86_64-nexora-uefi\nsection .rdata {\nexport data item:u32=1\n}\n"
     "section .text {\nexport fn f()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n", "item"},
    {"data_rdata_u64",
     "module d\ntarget x86_64-nexora-uefi\nsection .rdata {\nexport data item:u64=1\n}\n"
     "section .text {\nexport fn f()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n", "item"},
    {"data_data_u8",
     "module d\ntarget x86_64-nexora-uefi\nsection .data {\nexport data item:u8=1\n}\n"
     "section .text {\nexport fn f()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n", "item"},
    {"data_data_u16",
     "module d\ntarget x86_64-nexora-uefi\nsection .data {\nexport data item:u16=1\n}\n"
     "section .text {\nexport fn f()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n", "item"},
    {"data_data_u32",
     "module d\ntarget x86_64-nexora-uefi\nsection .data {\nexport data item:u32=1\n}\n"
     "section .text {\nexport fn f()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n", "item"},
    {"data_data_u64",
     "module d\ntarget x86_64-nexora-uefi\nsection .data {\nexport data item:u64=1\n}\n"
     "section .text {\nexport fn f()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n", "item"},
    {NULL, NULL, NULL}};
#define CONTRACT_PROBE_COUNT ((unsigned)(sizeof contract_probes / sizeof contract_probes[0] - 1))

/* The bare source name inside a module qualified C symbol name. */
static const char *contract_tail(const char *qualified)
{
    const char *dot = strrchr(qualified, '.');
    return dot ? dot + 1 : qualified;
}

static char *contract_dup(const char *s)
{
    size_t n = s ? strlen(s) : 0;
    char *copy = malloc(n + 1);
    if (!copy) { CHECK(0, "contract text copy allocated"); return NULL; }
    if (n) memcpy(copy, s, n);
    copy[n] = 0;
    return copy;
}

/* The contract the C object writer built for the symbol whose qualified name
 * ends in "." + name, searched inside a C built object. */
static const char *c_symbol_contract(const NtObject *o, const char *name)
{
    size_t k, nl = strlen(name);
    for (k = 0; k < o->symbol_count; k++) {
        const char *written = o->symbols[k].name;
        size_t l = written ? strlen(written) : 0;
        if (l > nl && written[l - 1 - nl] == '.' && !memcmp(written + l - nl, name, nl))
            return o->symbols[k].contract;
    }
    return NULL;
}

/* The name the C object writer gave that symbol, in full, inside the object `o`
 * it already built. The writer qualifies every symbol with the module of the
 * source it was given (object_build.c nt_object_compile), so the bare name the
 * frontend image carries is NOT the name the object carries, and the qualified
 * string is also the sort key object.c line 65 checks the table against. The
 * expectations this gate serialises are compared to the producer byte for
 * byte, so they take the name from the writer rather than from a literal. NULL
 * when the C object declares no such symbol. */
static const char *c_symbol_name(const NtObject *o, const char *name)
{
    size_t k, nl = strlen(name);
    for (k = 0; k < o->symbol_count; k++) {
        const char *written = o->symbols[k].name;
        size_t l = written ? strlen(written) : 0;
        if (l > nl && written[l - 1 - nl] == '.' && !memcmp(written + l - nl, name, nl))
            return written;
    }
    return NULL;
}

/* A private copy of that text, for an object the C pipeline already built. */
static char *c_contract_of(const NtObject *o, const char *name)
{
    const char *written = o->symbol_count ? c_symbol_contract(o, name) : NULL;
    if (!written)
        fprintf(stderr, "C_CONTRACT_MISSING name=%s symbols=%zu\n", name, o->symbol_count);
    return written ? contract_dup(written) : NULL;
}

/* The same text from a fresh nt_object_compile of `probe`. */
static char *c_contract(const char *probe, const char *name)
{
    NtFInput input = {"d", probe, strlen(probe)};
    NtObject object;
    NtDiagnostic error;
    char *found = NULL;
    memset(&object, 0, sizeof object);
    memset(&error, 0, sizeof error);
    if (!nt_object_compile(&input, 1, &object, &error)) {
        fprintf(stderr, "C_CONTRACT_REFUSED name=%s code=%u %s\n", name, error.code,
                error.message);
        return NULL;
    }
    found = c_contract_of(&object, name);
    nt_object_free(&object);
    return found;
}

/* A second image holding only the Nova NXO text accessors, so the contract
 * texts the C writer produced can be read back by a Nova producer without
 * disturbing the entry this gate drives. */
static int contract_image(NovaHostImage *image, NtArtifact *artifact)
{
    const char *paths[] = {"tests/nova/tests/nxo-inspect-text-entry.nova",
                           "compiler/nova/inspectors/nxo_inspect.nova",
                           "compiler/nova/formats/nxo/nxo.nova",
                           "compiler/nova/formats/pe/pe.nova"};
    char *sources[4] = {0};
    NtFInput inputs[4];
    unsigned i;
    int all = 1, compiled;
    for (i = 0; i < 4; i++) {
        size_t n = 0;
        sources[i] = loadf(paths[i], &n);
        inputs[i] = (NtFInput){paths[i], sources[i], n};
        if (!sources[i]) all = 0;
    }
    CHECK(all, "contract accessor sources load");
    compiled = all && nova_compile_many_v2(inputs, 4, artifact);
    CHECK(compiled, "contract accessor modules compile");
    if (!compiled) {
        fprintf(stderr, "E%u %zu:%zu %s\n", artifact->error.code, artifact->error.line,
                artifact->error.column, artifact->error.message);
        for (i = 0; i < 4; i++) free(sources[i]);
        return 0;
    }
    if (!nova_host_map(artifact, image)) {
        CHECK(0, "contract accessor image maps");
        for (i = 0; i < 4; i++) free(sources[i]);
        return 0;
    }
    for (i = 0; i < 4; i++) free(sources[i]);
    CHECK(image->memory != NULL, "contract accessor image is mapped");
    return image->memory != NULL;
}

#define CONTRACT_OUT_CAPACITY 2048

/* One probe: the C object writer builds it, nt_object_write serialises it,
 * nt_object_read reads it back, and the Nova text accessor reads the same
 * bytes out of the same file. All of them must return the same string, and
 * that string must be longer than the two byte placeholder the producer used
 * to write, so a regression to the placeholder cannot pass here. */
static void contract_round_trip(const NovaHostImage *ci, const ContractProbe *p)
{
    static uint8_t text[CONTRACT_OUT_CAPACITY];
    uint64_t length[1];
    NtObject canon = {0}, read = {0};
    NtBuffer file = {0};
    NtDiagnostic error = {0};
    NtFInput input = {"d", p->probe, strlen(p->probe)};
    char *expected = NULL;
    size_t want = 0, index = 0, k;
    int found = 0;

    cases++;
    if (!nt_object_compile(&input, 1, &canon, &error)) {
        CHECK(0, "contract probe: the C object writer builds the probe");
        fprintf(stderr, "CONTRACT_ORACLE_REFUSED %s code=%u %s\n", p->label, error.code,
                error.message);
        return;
    }
    CHECK(1, "contract probe: the C object writer builds the probe");
    expected = c_contract_of(&canon, p->name);
    CHECK(expected != NULL, "contract probe: the C object writer wrote the contract");
    if (!expected) { nt_object_free(&canon); return; }
    want = strlen(expected);
    CHECK(want > 2, "contract probe: the C contract is longer than the v0 placeholder");
    CHECK(nt_object_write(&canon, &file, &error), "contract probe: nt_object_write serialises it");
    CHECK(file.bytes && nt_object_read(file.bytes, file.size, &read, &error),
          "contract probe: nt_object_read reads it back");
    for (k = 0; read.symbols && k < read.symbol_count; k++)
        if (!strcmp(contract_tail(read.symbols[k].name), p->name)) { index = k; found = 1; break; }
    CHECK(found, "contract probe: nt_object_read kept the probed symbol");
    if (found)
        CHECK(!strcmp(read.symbols[index].contract, expected),
              "contract probe: nt_object_read recovers the C contract byte for byte");
    if (file.bytes && found) {
        NovaContextV2 c = {0};
        uint64_t args[8], code = UINT64_C(0xffffffffffffffff);
        memset(text, 0xcc, sizeof text);
        length[0] = UINT64_C(0xcccccccccccccccc);
        CHECK(nova_context_init_v2(&c), "contract probe: accessor context init");
        args[0] = nova_borrow_v2(&c, file.bytes, file.size, 0);
        args[1] = file.size;
        args[2] = (uint64_t)index;
        args[3] = nova_borrow_v2(&c, text, sizeof text, 1);
        args[4] = (uint64_t)sizeof text;
        args[5] = nova_borrow_v2(&c, length, sizeof length, 1);
        args[6] = 1; /* the flat slot carries the element count of a buf<u64> */
        args[7] = 1; /* mode 1 copies the contract, mode 0 the name */
        code = ci->entry(&c, args, 8);
        CHECK(c.error == 0, "contract probe: accessor runtime clean");
        CHECK(nova_context_destroy_v2(&c), "contract probe: accessor context cleanup");
        CHECK(code == 0, "contract probe: the Nova accessor returns the contract");
        if (code == 0) {
            CHECK(length[0] == want, "contract probe: the accessor reports the C length");
            CHECK(length[0] == want && !memcmp(text, expected, want),
                  "contract probe: the Nova accessor returns the C contract byte for byte");
        }
    }
    if (read.symbols) nt_object_free(&read);
    free(file.bytes);
    nt_object_free(&canon);
    free(expected);
}

/* Two probes whose declarations differ must not collapse onto one contract
 * string, so the table is variation and not decoration. */
static void contract_distinct(void)
{
    char *texts[64];
    unsigned k, j;
    unsigned collisions = 0, refusals = 0;
    for (k = 0; k < CONTRACT_PROBE_COUNT; k++) texts[k] = NULL;
    for (k = 0; k < CONTRACT_PROBE_COUNT; k++) {
        NtFInput input = {"d", (char *)contract_probes[k].probe,
                          strlen(contract_probes[k].probe)};
        NtObject canon = {0};
        NtDiagnostic error = {0};
        if (!nt_object_compile(&input, 1, &canon, &error)) { refusals++; continue; }
        texts[k] = c_contract_of(&canon, contract_probes[k].name);
        nt_object_free(&canon);
    }
    for (k = 0; k < CONTRACT_PROBE_COUNT; k++)
        for (j = k + 1; j < CONTRACT_PROBE_COUNT; j++)
            if (texts[k] && texts[j] && !strcmp(texts[k], texts[j])) {
                collisions++;
                fprintf(stderr, "CONTRACT_COLLISION %s == %s [%s]\n",
                        contract_probes[k].label, contract_probes[j].label, texts[k]);
            }
    CHECK(refusals == 0, "contract probes: the C object writer builds every probe");
    CHECK(collisions == 0, "contract probes: distinct declarations give distinct texts");
    for (k = 0; k < CONTRACT_PROBE_COUNT; k++) free(texts[k]);
}

/* The whole table, then the distinctness sweep. */
static void contract_suite(const NovaHostImage *ci)
{
    unsigned k;
    for (k = 0; k < CONTRACT_PROBE_COUNT; k++) contract_round_trip(ci, contract_probes + k);
    contract_distinct();
    cases++;
}
/* The local fixtures declare two functions, main and helper. The C expressible
 * twin this harness measures against declares main only, so the helper text is
 * read from a module carrying exactly the helper declaration and the same
 * target. contract_text reads no body text and no export flag, so that is the
 * contract of the helper the producer writes; the bytes still come from the C
 * object writer. */
static const char *const LOCAL_HELPER_PROBE =
    "module d\ntarget x86_64-nexora-uefi\nsection .text {\n"
    "fn helper()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";
/* ------------------------------------------------------------------ *
 * C frontend oracle
 * ------------------------------------------------------------------ */

typedef struct {
    NtObject object;
    void *symbols,*sorted,*order,*relocations,*names;
} Assembly;
static void assembly_free(Assembly *a){free(a->sorted);free(a->symbols);free(a->order);
    free(a->relocations);free(a->names);memset(a,0,sizeof *a);}

/* object.c rejects a symbol table that is not strictly ascending by strcmp, so
 * the table is sorted here by name with the declaration index as the final
 * tiebreak, exactly as spec/formats/nxo-v0.md orders the names. */
typedef struct { const char *name; size_t index; } NameOrder;
static int name_compare(const void*x,const void*y){
    int order=strcmp(((const NameOrder *)x)->name,((const NameOrder *)y)->name);
    if(order)return order;
    return ((const NameOrder *)x)->index<((const NameOrder *)y)->index?-1:1;
}

static int assemble(const NtCodeImage *image,const NtObject *canon,Assembly *a,char *why,size_t cap){
    size_t j,exported=0,total=image->symbol_count?image->symbol_count:1;
    NtObjectSymbol *symbols=calloc(total,sizeof *symbols);
    NtObjectReloc *relocs=calloc(image->relocation_count?image->relocation_count:1,sizeof *relocs);
    char (*names)[512]=calloc(total,sizeof *names);
    NameOrder *order=calloc(total,sizeof *order);
    memset(a,0,sizeof *a);
    if(!symbols||!relocs||!names||!order){
        free(symbols);free(relocs);free(names);free(order);
        snprintf(why,cap,"assembly allocation failed");return 0;
    }
    for(j=0;j<image->symbol_count;j++){
        const NtCodeSymbol *s=image->symbols+j;
        const char *qualified=c_symbol_name(canon,s->name);
        int n;
        if(!qualified){
            free(symbols);free(relocs);free(names);free(order);
            snprintf(why,cap,"assembly: the C object writer names no symbol %s",s->name);
            return 0;
        }
        n=snprintf(names[j],sizeof names[j],"%s",qualified);
        if(n<=0||(size_t)n>=sizeof names[j]){
            free(symbols);free(relocs);free(names);free(order);
            snprintf(why,cap,"assembly name overflow");return 0;
        }
        symbols[j].name=names[j];
        symbols[j].contract=(char*)c_symbol_contract(canon,contract_tail(s->name));
        if(!symbols[j].contract){
            free(symbols);free(relocs);free(names);free(order);
            snprintf(why,cap,"assembly: the C object writer has no contract for %s",
                     s->name);return 0;}
        symbols[j].section=s->section;symbols[j].offset=s->offset;symbols[j].size=s->size;
        symbols[j].flags=(s->function_id?NT_OBJECT_FUNCTION:NT_OBJECT_VARIABLE)|
                         ((s->flags&1u)?NT_OBJECT_EXPORT:0u);
        order[j].name=names[j];order[j].index=j;
        if(s->function_id&&(s->flags&1u)&&s->section==NT_CODE_SECTION_TEXT)exported++;
    }
    if(exported!=1){
        free(symbols);free(relocs);free(names);free(order);
        snprintf(why,cap,"assembly: %zu exported .text functions",exported);return 0;
    }
    qsort(order,image->symbol_count,sizeof *order,name_compare);
    a->symbols=symbols;a->order=order;a->relocations=relocs;a->names=names;
    a->object.target=1;
    a->sorted=calloc(total,sizeof *symbols);
    if(!a->sorted){assembly_free(a);snprintf(why,cap,"assembly table allocation failed");return 0;}
    a->object.symbols=a->sorted;
    for(j=0;j<image->symbol_count;j++){
        a->object.symbols[j]=symbols[order[j].index];
        if(symbols[order[j].index].section==NT_OBJECT_TEXT&&
           (symbols[order[j].index].flags&NT_OBJECT_EXPORT)&&
           (symbols[order[j].index].flags&NT_OBJECT_FUNCTION))
            a->object.entry_symbol=(uint32_t)j+1;
    }
    a->object.symbol_count=image->symbol_count;
    a->object.relocation_count=image->relocation_count;
    a->object.relocations=relocs;
    for(j=0;j<image->relocation_count;j++){
        const NtCodeReloc *r=image->relocations+j;
        size_t k;uint32_t target=0;
        for(k=0;k<image->symbol_count;k++)
            if(r->target_function&&image->symbols[k].function_id==r->target_function){
                target=(uint32_t)k+1;break;
            }
        if(!target){assembly_free(a);snprintf(why,cap,"assembly: relocation has no target");return 0;}
        relocs[j]=(NtObjectReloc){r->source_section,r->kind,r->offset,target,r->addend};
    }
    a->object.sections[0]=(NtBuffer){image->bytes,image->size,image->capacity};
    a->object.sections[1]=(NtBuffer){image->rdata.bytes,image->rdata.size,image->rdata.capacity};
    a->object.sections[2]=(NtBuffer){image->data.bytes,image->data.size,image->data.capacity};
    return 1;
}

typedef struct { int ok; NtBuffer file; NtObject canonical; char why[256]; } Reference;
static void reference_free(Reference *r){free(r->file.bytes);r->file.bytes=NULL;
    if(r->canonical.symbols)nt_object_free(&r->canonical);
    r->ok=0;}

static const char *tail_of(const char *name){const char *dot=strrchr(name,'.');return dot?dot+1:name;}

static int same_layout(const NtObject *a,const NtObject *b){
    size_t j,k;
    if(a->target!=b->target||a->symbol_count!=b->symbol_count||
       a->relocation_count!=b->relocation_count)return 0;
    for(j=0;j<3;j++)
        if(a->sections[j].size!=b->sections[j].size||
           (a->sections[j].size&&memcmp(a->sections[j].bytes,b->sections[j].bytes,
                                        a->sections[j].size)))return 0;
    for(j=0;j<a->symbol_count;j++){
        for(k=0;k<b->symbol_count;k++){
            if(strcmp(tail_of(a->symbols[j].name),tail_of(b->symbols[k].name)))continue;
            if(a->symbols[j].section!=b->symbols[k].section||
               a->symbols[j].offset!=b->symbols[k].offset||
               a->symbols[j].size!=b->symbols[k].size||
               a->symbols[j].flags!=b->symbols[k].flags)return 0;
            break;
        }
        if(k==b->symbol_count)return 0;
    }
    for(j=0;j<a->relocation_count;j++){
        for(k=0;k<b->relocation_count;k++)
            if(a->relocations[j].section==b->relocations[k].section&&
               a->relocations[j].kind==b->relocations[k].kind&&
               a->relocations[j].offset==b->relocations[k].offset&&
               a->relocations[j].addend==b->relocations[k].addend)break;
        if(k==b->relocation_count)return 0;
    }
    return 1;
}

static int reference_for(const char *source,Reference *ref){
    NtFInput input={"m",source,strlen(source)};
    NtFProgram program;NtCodeImage image;NtCodeDiagnostic cd;NtDiagnostic error;
    Assembly assembly;uint32_t canonical_entry=0;size_t k;
    memset(ref,0,sizeof *ref);
    memset(&program,0,sizeof program);memset(&image,0,sizeof image);
    memset(&cd,0,sizeof cd);memset(&error,0,sizeof error);memset(&assembly,0,sizeof assembly);
    { NtFInput again={"m",source,strlen(source)};
      if(!nt_object_compile(&again,1,&ref->canonical,&error)){
        snprintf(ref->why,sizeof ref->why,"nt_object_compile %u %s",error.code,error.message);
        return 0;
      } }
    if(!nt_frontend_compile_object(&input,1,&program)){
        snprintf(ref->why,sizeof ref->why,"frontend %u %s",
                 program.diagnostic_count?program.diagnostics[0].code:0u,
                 program.diagnostic_count?program.diagnostics[0].message:"no diagnostic");
        nt_frontend_free(&program);return 0;
    }
    if(!nt_codegen_x64_object(&program,&image,&cd)){
        snprintf(ref->why,sizeof ref->why,"codegen %u %s",cd.code,cd.message);
        nt_code_image_free(&image);nt_frontend_free(&program);return 0;
    }
    if(!assemble(&image,&ref->canonical,&assembly,ref->why,sizeof ref->why)){
        nt_code_image_free(&image);nt_frontend_free(&program);return 0;
    }
    if(!nt_object_write(&assembly.object,&ref->file,&error)){
        snprintf(ref->why,sizeof ref->why,"nt_object_write %u %s",error.code,error.message);
        assembly_free(&assembly);nt_code_image_free(&image);nt_frontend_free(&program);return 0;
    }
    assembly_free(&assembly);nt_code_image_free(&image);nt_frontend_free(&program);
    for(k=0;k<ref->canonical.symbol_count;k++)
        if((ref->canonical.symbols[k].flags&(NT_OBJECT_EXPORT|NT_OBJECT_FUNCTION))==
           (NT_OBJECT_EXPORT|NT_OBJECT_FUNCTION)&&ref->canonical.symbols[k].section==NT_OBJECT_TEXT)
            canonical_entry=(uint32_t)k+1;
    if(!canonical_entry){
        snprintf(ref->why,sizeof ref->why,"nt_object_compile: no exported .text function");
        free(ref->file.bytes);ref->file.bytes=NULL;nt_object_free(&ref->canonical);return 0;
    }
    ref->ok=1;
    return 1;
}

static int is_data(const NtObjectSymbol *s){return s->section==NT_OBJECT_RDATA||s->section==NT_OBJECT_DATA;}

static void offsets_of(const NtObject *o,char *dst,size_t room){
    size_t used=0,j;dst[0]=0;
    for(j=0;j<o->symbol_count;j++){
        int n;
        if(!is_data(o->symbols+j))continue;
        n=snprintf(dst+used,room-used,"%s%s@%llu",used?",":"",o->symbols[j].name,
                   (unsigned long long)o->symbols[j].offset);
        if(n<0||(size_t)n>=room-used)break;
        used+=(size_t)n;
    }
}
static int data_symbols_match(const NtObject *a,const NtObject *b,int by_tail,char *detail,size_t room){
    size_t j,k,da=0,db=0;
    detail[0]=0;
    for(j=0;j<a->symbol_count;j++)if(is_data(a->symbols+j))da++;
    for(j=0;j<b->symbol_count;j++)if(is_data(b->symbols+j))db++;
    if(da!=db){snprintf(detail,room,"data symbol count %zu vs %zu",da,db);return 0;}
    for(j=0;j<a->symbol_count;j++){
        if(!is_data(a->symbols+j))continue;
        for(k=0;k<b->symbol_count;k++){
            const char *an=a->symbols[j].name,*bn=b->symbols[k].name;
            if(!is_data(b->symbols+k))continue;
            if(by_tail){an=tail_of(an);bn=tail_of(bn);}
            if(strcmp(an,bn))continue;
            if(a->symbols[j].section!=b->symbols[k].section||
               a->symbols[j].offset!=b->symbols[k].offset||
               a->symbols[j].size!=b->symbols[k].size||
               a->symbols[j].flags!=b->symbols[k].flags){
                snprintf(detail,room,"%s sec=%u/%u off=%llu/%llu size=%llu/%llu flags=%u/%u",
                         a->symbols[j].name,a->symbols[j].section,b->symbols[k].section,
                         (unsigned long long)a->symbols[j].offset,
                         (unsigned long long)b->symbols[k].offset,
                         (unsigned long long)a->symbols[j].size,
                         (unsigned long long)b->symbols[k].size,
                         a->symbols[j].flags,b->symbols[k].flags);
                return 0;
            }
            break;
        }
        if(k==b->symbol_count){snprintf(detail,room,"%s absent from the C table",a->symbols[j].name);return 0;}
    }
    return 1;
}
static long first_data_byte(const NtObject *a,const NtObject *b){
    size_t i;
    for(i=0;i<a->sections[1].size||i<b->sections[1].size;i++){
        uint8_t x=i<a->sections[1].size?a->sections[1].bytes[i]:0xcc;
        uint8_t y=i<b->sections[1].size?b->sections[1].bytes[i]:0xcc;
        if(x!=y)return (long)i;
    }
    for(i=0;i<a->sections[2].size||i<b->sections[2].size;i++){
        uint8_t x=i<a->sections[2].size?a->sections[2].bytes[i]:0xcc;
        uint8_t y=i<b->sections[2].size?b->sections[2].bytes[i]:0xcc;
        if(x!=y)return (long)(a->sections[1].size+i);
    }
    return -1;
}

/* ------------------------------------------------------------------ *
 * Reading the produced PE back
 * ------------------------------------------------------------------ */

/* The .rdata and .data payload of a produced PE. pe_layout.h is the authority
 * for the two offsets: nt_pe_logical_rva puts section 2 at rdata+8, so .rdata
 * carries an eight byte anchor ahead of the payload, and nt_pe_layout reserves
 * eight bytes for .data when the payload is empty. A symbol offset is a function
 * of exactly this payload, so comparing it is comparing the layout. */
static int pe_payload(const uint8_t *pe,size_t size,const char *want,size_t skip,
                      size_t canonical,const uint8_t **bytes,char *detail,size_t room){
    uint32_t nt;uint16_t count,opt;size_t table;unsigned s;
    if(size<64){snprintf(detail,room,"PE too small");return 0;}
    nt=rd32(pe+60);
    if((size_t)nt+24>size){snprintf(detail,room,"PE header out of range");return 0;}
    count=rd16(pe+nt+6);opt=rd16(pe+nt+20);
    table=(size_t)nt+24+opt;
    if(table+(size_t)count*40>size){snprintf(detail,room,"PE section table out of range");return 0;}
    for(s=0;s<count;s++){
        const uint8_t *h=pe+table+(size_t)s*40;
        uint32_t vs=rd32(h+8),raw=rd32(h+20);
        if(strncmp((const char *)h,want,strlen(want)))continue;
        if((size_t)raw+vs>size||vs<skip){snprintf(detail,room,"%s payload out of range",want);return 0;}
        if(vs!=skip+canonical&&!(canonical==0&&vs==8)){
            snprintf(detail,room,"%s virtual size %u, expected %zu",want,vs,skip+canonical);
            return 0;
        }
        *bytes=pe+raw+skip;
        return 1;
    }
    snprintf(detail,room,"PE has no %s section",want);
    return 0;
}

/* Compares the produced PE data payloads against the C pipeline twin. Returns 1
 * when they agree and prints the divergence row. */
static int layout_verdict(const char *label,const uint8_t *pe,size_t pe_size,const char *twin,
                          char *detail,size_t room){
    const uint8_t *rdata=0,*data=0;
    size_t rdata_size,data_size;
    Reference ref;NtObject cref={0};NtDiagnostic error={0};
    char c_offsets[2048];long first;int same;
    detail[0]=0;
    if(!reference_for(twin,&ref)){
        snprintf(detail,room,"ORACLE_FREE twin: %s",ref.why);
        reference_free(&ref);return 0;
    }
    /* the hand assembly inside reference_for is proven against the canonical
     * nt_object_compile builder before it is used as the expectation */
    if(nt_object_read(ref.file.bytes,ref.file.size,&cref,&error)&&
       !same_layout(&ref.canonical,&cref))
        snprintf(detail,room,"hand assembly differs from the canonical C builder");
    if(cref.symbols)nt_object_free(&cref);
    rdata_size=ref.canonical.sections[1].size;
    data_size=ref.canonical.sections[2].size;
    if(!pe_payload(pe,pe_size,".rdata",8,rdata_size,&rdata,detail,room)||
       !pe_payload(pe,pe_size,".data",0,data_size,&data,detail,room)){
        reference_free(&ref);return 0;
    }
    first=-1;
    for(size_t i=0;i<rdata_size;i++)
        if(rdata[i]!=ref.canonical.sections[1].bytes[i]){first=(long)i;break;}
    if(first<0)
        for(size_t i=0;i<data_size;i++)
            if(data[i]!=ref.canonical.sections[2].bytes[i]){first=(long)(rdata_size+i);break;}
    same=first<0&&!detail[0];
    if(!same&&!detail[0])
        snprintf(detail,room,"payload differs from the C canonical payload");
    offsets_of(&ref.canonical,c_offsets,sizeof c_offsets);
    fprintf(stderr,"DATA %s scope=data pe_rdata=%zu pe_data=%zu C_rdata=%zu C_data=%zu "
                    "C_off=%s verdict=%s first=%ld %s\n",
            label,rdata_size,data_size,rdata_size,data_size,c_offsets,
            same?"IDENTICAL":"DIVERGES",first,same?"":detail);
    reference_free(&ref);
    return same;
}

/* ------------------------------------------------------------------ *
 * The expected object: canonical data, x64 oracle code stream
 * ------------------------------------------------------------------ */

typedef struct {
    NtObject object;
    uint8_t *text,*rdata,*data;
    size_t text_size;
    NtObjectSymbol *symbols,*sorted;
    NtObjectReloc *relocs;
    char (*names)[64];
    NameOrder *order;
    char *contracts;
} Expected;

static void expected_free(Expected *e){
    free(e->text);free(e->rdata);free(e->data);free(e->symbols);free(e->sorted);
    free(e->relocs);free(e->names);free(e->order);free(e->contracts);
    memset(e,0,sizeof *e);
}
static void free_artifact(NtArtifact *a){
    if(a->pe.bytes){free(a->pe.bytes);a->pe.bytes=NULL;}
    if(a->text.bytes){free(a->text.bytes);a->text.bytes=NULL;}
    if(a->rdata.bytes){free(a->rdata.bytes);a->rdata.bytes=NULL;}
    if(a->data.bytes){free(a->data.bytes);a->data.bytes=NULL;}
    free(a->base_relocations);
    memset(a,0,sizeof *a);
}

/* Every data byte and every data symbol field is copied from the canonical C
 * object; the .text stream, the function offsets and the REL32 sites are the
 * producer's own documented stream, encoded by nt_x64_encode: call_count five
 * byte calls, the main RET, then the helper RET. */
static int expected_build(const NtObject *canon,const char *helper_text,
                          const char *main_text,unsigned calls,int helper_first,Expected *e){
    size_t data_symbols=0,j,used=0,calls_at;
    memset(e,0,sizeof *e);
    for(j=0;j<canon->symbol_count;j++)if(is_data(canon->symbols+j))data_symbols++;
    calls_at=helper_first?1:0;
    e->text_size=(size_t)calls*5+2;
    e->text=calloc(e->text_size,1);
    e->relocs=calloc(calls?calls:1,sizeof *e->relocs);
    e->symbols=calloc(data_symbols+2,sizeof *e->symbols);
    e->sorted=calloc(data_symbols+2,sizeof *e->sorted);
    e->names=calloc(data_symbols+2,sizeof *e->names);
    e->order=calloc(data_symbols+2,sizeof *e->order);
    e->rdata=calloc(canon->sections[1].size?canon->sections[1].size:1,1);
    e->data=calloc(canon->sections[2].size?canon->sections[2].size:1,1);
    if(!e->text||!e->relocs||!e->symbols||!e->sorted||!e->names||!e->order||!e->rdata||!e->data){
        expected_free(e);return 0;
    }
    /* the symbol table borrows the two contract strings, so they are copied
     * into the expectation and released with it */
    {
        size_t hn=strlen(helper_text),mn=strlen(main_text);
        e->contracts=calloc(hn+mn+2,1);
        if(!e->contracts){expected_free(e);return 0;}
        memcpy(e->contracts,helper_text,hn+1);
        memcpy(e->contracts+hn+1,main_text,mn+1);
        helper_text=e->contracts;
        main_text=e->contracts+hn+1;
    }
    if(canon->sections[1].size)memcpy(e->rdata,canon->sections[1].bytes,canon->sections[1].size);
    if(canon->sections[2].size)memcpy(e->data,canon->sections[2].bytes,canon->sections[2].size);
    for(j=0;j<canon->symbol_count;j++){
        const NtObjectSymbol *c=canon->symbols+j;
        if(!is_data(c))continue;
        snprintf(e->names[used],sizeof e->names[used],"%s",tail_of(c->name));
        e->symbols[used]=(NtObjectSymbol){e->names[used],(char*)c->contract,c->section,c->flags,c->offset,c->size};
        e->order[used].name=e->names[used];e->order[used].index=used;
        used++;
    }
    {
        uint64_t helper_at=helper_first?0:(uint64_t)(calls*5+1),main_at=helper_first?1:0;
        snprintf(e->names[used],sizeof e->names[used],"helper");
        e->symbols[used]=(NtObjectSymbol){e->names[used],(char*)helper_text,NT_OBJECT_TEXT,
                                          NT_OBJECT_FUNCTION,helper_at,1};
        e->order[used].name=e->names[used];e->order[used].index=used;used++;
        snprintf(e->names[used],sizeof e->names[used],"main");
        e->symbols[used]=(NtObjectSymbol){e->names[used],(char*)main_text,NT_OBJECT_TEXT,
                                          NT_OBJECT_FUNCTION|NT_OBJECT_EXPORT,main_at,calls*5+1};
        e->order[used].name=e->names[used];e->order[used].index=used;used++;
    }
    /* the producer's own code stream, five byte calls then two RETs */
    for(j=0;j<calls;j++){
        NtX64Operand forward={.kind=NT_X64_REL,.imm=0,.is_signed=1};
        e->text_size-=encode_(e->text+calls_at+j*5,"call",&forward,1);
    }
    e->text_size-=encode_(e->text+calls_at+(size_t)calls*5,"ret",NULL,0);
    e->text_size-=encode_(e->text+(helper_first?0:(size_t)calls*5+1),"ret",NULL,0);
    e->text_size=(size_t)calls*5+2;
    qsort(e->order,used,sizeof *e->order,name_compare);
    for(j=0;j<used;j++){
        e->sorted[j]=e->symbols[e->order[j].index];
        if(!strcmp(e->sorted[j].name,"main"))e->object.entry_symbol=(uint32_t)j+1;
    }
    for(j=0;j<calls;j++){
        uint32_t target=0;size_t k;
        for(k=0;k<used;k++)if(!strcmp(e->sorted[k].name,"helper")){target=(uint32_t)k+1;break;}
        if(!target){expected_free(e);return 0;}
        /* named fields: NtObjectReloc orders target before offset */
        e->relocs[j].section=NT_OBJECT_TEXT;
        e->relocs[j].kind=NT_OBJECT_REL32;
        e->relocs[j].offset=calls_at+(uint64_t)j*5+1;
        e->relocs[j].target=target;
        e->relocs[j].addend=0;
    }
    if(!e->object.entry_symbol){expected_free(e);return 0;}
    e->object.target=1;
    e->object.symbols=e->sorted;
    e->object.symbol_count=used;
    e->object.relocations=e->relocs;
    e->object.relocation_count=calls;
    e->object.sections[0]=(NtBuffer){e->text,e->text_size,e->text_size};
    e->object.sections[1]=(NtBuffer){e->rdata,canon->sections[1].size,canon->sections[1].size};
    e->object.sections[2]=(NtBuffer){e->data,canon->sections[2].size,canon->sections[2].size};
    /* the hand assembly must carry the canonical C data half, proven here and
     * not asserted: the same payload bytes and the same symbol fields as the
     * nt_object_compile object this expectation was derived from */
    {
        char detail[256];
        detail[0]=0;
        if(e->object.sections[1].size!=canon->sections[1].size||
           e->object.sections[2].size!=canon->sections[2].size||
           first_data_byte(&e->object,canon)>=0||
           !data_symbols_match(&e->object,canon,1,detail,sizeof detail)||detail[0]){
            fprintf(stderr,"expected_build reason ro=%zu/%zu data=%zu/%zu first=%ld %s\n",
                    e->object.sections[1].size,canon->sections[1].size,
                    e->object.sections[2].size,canon->sections[2].size,
                    first_data_byte(&e->object,canon),detail);
            expected_free(e);return 0;
        }
    }
    /* the string table is not a layout field either, so the contract text the
     * expectation carries is compared with the C object writer here */
    for(j=0;j<used;j++){
        const char *want=!strcmp(e->sorted[j].name,"helper")
            ?helper_text:c_symbol_contract(canon,tail_of(e->sorted[j].name));
        if(!want||!e->sorted[j].contract||strcmp(e->sorted[j].contract,want)){
            fprintf(stderr,"EXPECTED_CONTRACT name=%s got=[%s] C=[%s]\n",
                    e->sorted[j].name,e->sorted[j].contract?e->sorted[j].contract:"",
                    want?want:"");
            expected_free(e);return 0;
        }
    }
    return 1;
}

/* ------------------------------------------------------------------ *
 * Source generation
 * ------------------------------------------------------------------ */

static char *name_of(unsigned i){static char names[80][8];snprintf(names[i],8,"d%02u",i);return names[i];}
static char *item_text(char*dst,size_t room,unsigned i,unsigned exported){
    int n=snprintf(dst,room,"%sdata %s:u%u=%llu\n",exported?"export ":"",name_of(i),
                   (unsigned)(width_of(i)*8),(unsigned long long)value_of(i));
    if(n<0||(size_t)n>=room)return dst;
    return dst+(size_t)n;
}
static char *text_section(char*dst,size_t room,unsigned calls,int helper_first,unsigned mode){
    size_t used=(size_t)snprintf(dst,room,"section .text {\n");
    if(helper_first)used+=(size_t)snprintf(dst+used,room-used,"fn helper()->u64\neffects {}\nclobbers {} {\nret\n}\n");
    /* WHY `export fn main` HERE. The reference sets NT_OBJECT_EXPORT from the
     * declaration's own `exported` bit (object_build.c:317) and names the entry
     * only for an EXPORTED main (object_build.c:343-347, codegen.c:1557-1562),
     * so a main without the modifier is a legal object with entry_symbol = 0 and
     * flags = NT_OBJECT_FUNCTION alone. The C reference REFUSES this body (a
     * bare ret has no available stack/frame balance proof: 503), so the oracle
     * is the twin_for/custom_twin export fn main + return 0 source, and producer
     * and twin must declare the SAME program. The producer used to hardcode the
     * export bit on main, which made the two agree in the output even though
     * they declared different programs; that was hiding the difference, not
     * proving layout parity. This same generator emits the negative shapes too,
     * which are refused for their own reasons, not for the export. */
    used+=(size_t)snprintf(dst+used,room-used,"export fn main()->u64\neffects {}\nclobbers {} {\n");
    for(unsigned i=0;i<calls;i++){
        if((mode&MODE_ARITY)&&i==0)used+=(size_t)snprintf(dst+used,room-used,"call helper(1)\n");
        else if((mode&MODE_BAD_FIRST)&&i==0)used+=(size_t)snprintf(dst+used,room-used,"call missing()\n");
        else if((mode&MODE_BAD_LAST)&&(int)i==(int)calls-1)used+=(size_t)snprintf(dst+used,room-used,"call missing()\n");
        else used+=(size_t)snprintf(dst+used,room-used,"call helper()\n");
    }
    used+=(size_t)snprintf(dst+used,room-used,"ret\n");
    if(mode&MODE_AFTER_RET)used+=(size_t)snprintf(dst+used,room-used,"call helper()\n");
    used+=(size_t)snprintf(dst+used,room-used,"}\n");
    if(mode&MODE_EXTRA_FN)used+=(size_t)snprintf(dst+used,room-used,"fn spare()->u64\neffects {}\nclobbers {} {\nret\n}\n");
    if(!helper_first)used+=(size_t)snprintf(dst+used,room-used,"fn helper()->u64\neffects {}\nclobbers {} {\nret\n}\n");
    used+=(size_t)snprintf(dst+used,room-used,"}\n");
    CHECK(used<room,"generated text section bounded");
    return dst+used;
}
static char *data_section(char*dst,size_t room,unsigned first,unsigned count,const char*name){
    size_t used=(size_t)snprintf(dst,room,"section %s {\n",name);
    for(unsigned i=0;i<count;i++)used=(size_t)(item_text(dst+used,room-used,first+i,(first+i)%2==0)-dst);
    used+=(size_t)snprintf(dst+used,room-used,"}\n");
    CHECK(used<room,"generated data section bounded");
    return dst+used;
}
/* split is the number of leading items placed in .rdata; the rest go to .data. */
static char *source_for(unsigned calls,unsigned items,unsigned split,int helper_first,unsigned mode){
    size_t room=131072;char*s=malloc(room);if(!s)return NULL;char*at=s;
    at+=snprintf(at,room-(size_t)(at-s),"module m\ntarget x86_64-nexora-uefi\n");
    if(mode&MODE_EXTRA_SEC)at+=snprintf(at,room-(size_t)(at-s),"section .bss {\ndata d00:u8=1\n}\n");
    if((mode&MODE_DATA_FIRST)&&!(mode&MODE_EXTRA_SEC)&&items>0){
        if(split>0)at=data_section(at,room-(size_t)(at-s),0,split,".rdata");
        if(items>split)at=data_section(at,room-(size_t)(at-s),split,items-split,".data");
    }
    at=text_section(at,room-(size_t)(at-s),calls,helper_first,mode);
    if(!(mode&MODE_DATA_FIRST)&&!(mode&MODE_EXTRA_SEC)&&items>0){
        if(split>0)at=data_section(at,room-(size_t)(at-s),0,split,".rdata");
        if(items>split)at=data_section(at,room-(size_t)(at-s),split,items-split,".data");
    }
    CHECK((size_t)(at-s)<room,"generated source bounded");
    return s;
}
/* The same data declarations with a C expressible body: identical layout input,
 * a body the C frontend accepts. */
static char *twin_for(unsigned items,unsigned split){
    size_t room=131072;char*s=malloc(room);if(!s)return NULL;char*at=s;
    at+=snprintf(at,room-(size_t)(at-s),"module m\ntarget x86_64-nexora-uefi\n");
    if(split>0)at=data_section(at,room-(size_t)(at-s),0,split,".rdata");
    if(items>split)at=data_section(at,room-(size_t)(at-s),split,items-split,".data");
    at+=snprintf(at,room-(size_t)(at-s),"section .text {\n"
                 "export fn main()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n");
    CHECK((size_t)(at-s)<room,"generated twin bounded");
    return s;
}
/* A free form fixture: explicit item names, widths, values and sections, so the
 * gate can state names that sort differently from declaration order. */
typedef struct { const char *name; unsigned width; uint64_t value; unsigned section; } Item;
static char *custom_source(char*dst,size_t room,const Item*items,size_t count,unsigned calls){
    char*at=dst;unsigned sec;size_t i;
    at+=snprintf(at,room-(size_t)(at-dst),"module m\ntarget x86_64-nexora-uefi\n");
    for(sec=2;sec<=3;sec++){
        at+=snprintf(at,room-(size_t)(at-dst),"section %s {\n",sec==2?".rdata":".data");
        for(i=0;i<count;i++)if(items[i].section==sec)
            at+=snprintf(at,room-(size_t)(at-dst),"%sdata %s:u%u=%llu\n",i%2?"":"export ",
                         items[i].name,items[i].width*8,(unsigned long long)items[i].value);
        at+=snprintf(at,room-(size_t)(at-dst),"}\n");
    }
    at=text_section(at,room-(size_t)(at-dst),calls,0,0);
    if((size_t)(at-dst)>=room)return NULL;
    *at=0;
    CHECK((size_t)(at-dst)<room,"custom fixture bounded");
    return dst;
}
static char *custom_twin(char*dst,size_t room,const Item*items,size_t count){
    char*at=dst;unsigned sec;size_t i;
    at+=snprintf(at,room-(size_t)(at-dst),"module m\ntarget x86_64-nexora-uefi\n");
    for(sec=2;sec<=3;sec++){
        at+=snprintf(at,room-(size_t)(at-dst),"section %s {\n",sec==2?".rdata":".data");
        for(i=0;i<count;i++)if(items[i].section==sec)
            at+=snprintf(at,room-(size_t)(at-dst),"%sdata %s:u%u=%llu\n",i%2?"":"export ",
                         items[i].name,items[i].width*8,(unsigned long long)items[i].value);
        at+=snprintf(at,room-(size_t)(at-dst),"}\n");
    }
    at+=snprintf(at,room-(size_t)(at-dst),"section .text {\n"
                 "export fn main()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n");
    if((size_t)(at-dst)>=room)return NULL;
    *at=0;
    return dst;
}

static uint64_t run(const NovaHostImage*i,const char*source,uint8_t*out,size_t cap){
    NovaContextV2 c={0};CHECK(nova_context_init_v2(&c),"context init");
    uint64_t sh=nova_borrow_v2(&c,(void*)source,strlen(source),0),oh=nova_borrow_v2(&c,out,cap,1);
    uint64_t args[]={sh,strlen(source),oh,cap};uint64_t code=i->entry(&c,args,4);
    if(c.error)fprintf(stderr,"Nova runtime error=%llu source=%llu offset=%llu\n",(unsigned long long)c.error,(unsigned long long)c.error_source,(unsigned long long)c.error_offset);
    CHECK(c.error==0,"runtime clean");CHECK(nova_context_destroy_v2(&c),"context cleanup");cases++;return code;
}
static void rejected(const NovaHostImage*i,char*source,size_t cap,uint64_t expected,const char*label){
    CHECK(source!=NULL,"negative source allocation");if(!source)return;
    uint8_t out[65536];memset(out,0xcc,sizeof out);
    uint64_t code=run(i,source,out,cap);int intact=code==expected;
    for(size_t j=0;j<cap;j++)intact&=out[j]==0xcc;
    CHECK(intact,label);
}
static void rejected_owned(const NovaHostImage*i,char*source,size_t cap,uint64_t expected,const char*label){
    rejected(i,source,cap,expected,label);free(source);
}
static void rejected_text(const NovaHostImage*i,const char*source,size_t cap,uint64_t expected,const char*label){
    rejected(i,(char*)source,cap,expected,label);
}

/* The producer's own instruction stream after materialization: call_count five
 * byte calls, then the main RET, then the helper RET, each REL32 resolved. */
static void check_text(const char *label,NtArtifact *art,unsigned calls,int helper_first){
    size_t call_at=helper_first?1:0;
    uint64_t helper=helper_first?0:(uint64_t)(calls*5+1);
    unsigned k;
    CHECKL(art->text.size==(size_t)calls*5+2,"materialized text size",label);
    for(k=0;k<calls;k++){
        uint8_t*imm=art->text.bytes+call_at+(size_t)k*5+1;
        uint32_t raw=(uint32_t)imm[0]|((uint32_t)imm[1]<<8)|((uint32_t)imm[2]<<16)|((uint32_t)imm[3]<<24);
        int32_t rel=(int32_t)raw;
        CHECKL(art->text.bytes[call_at+(size_t)k*5]==0xe8,"patched call opcode",label);
        CHECKL((uint64_t)((int64_t)(call_at+(uint64_t)k*5+5)+(int64_t)rel)==helper,
               "patched REL32 resolves to helper",label);
    }
    CHECKL(art->entry==(helper_first?1:0),"entry matches main position",label);
}

/* Measures the produced PE against the C pipeline, then against the expectation
 * the C pipeline and the x64 oracle build together. */
static void positive(const NovaHostImage*i,unsigned calls,int helper_first,
                     const char *label,const char *source,const char *twin){
    uint8_t out[65536];
    Reference ref;Expected expected;
    NtDiagnostic error={0};
    char detail[512];
    memset(out,0xcc,sizeof out);
    {
        uint64_t code=run(i,source,out,sizeof out),pe_size=r64(out);
        if(code!=0||pe_size>sizeof out-8)
            fprintf(stderr,"%s producer code=%llu pe=%llu\n",label,(unsigned long long)code,
                    (unsigned long long)pe_size);
        CHECKL(code==0&&pe_size>0&&pe_size<=sizeof out-8,"producer returns a PE",label);
        if(code!=0||pe_size==0||pe_size>sizeof out-8)return;
        detail[0]=0;
        CHECKL(layout_verdict(label,out+8,(size_t)pe_size,twin,detail,sizeof detail),
               "data layout parity with the C frontend pipeline",label);
    }
    memset(&ref,0,sizeof ref);
    if(!reference_for(twin,&ref)){
        CHECKL(0,"C reference for the twin",label);
        fprintf(stderr,"PE %s reference reason=%s\n",label,ref.why);
        reference_free(&ref);return;
    }
    memset(&expected,0,sizeof expected);
    {   /* neither contract is named by the twin in the form the expectation
         * uses, so both texts are read from the C object writer and copied
         * into the expectation by expected_build */
        char *helper=c_contract(LOCAL_HELPER_PROBE,"helper");
        char *main_text=c_contract(twin,"main");
        int built=helper&&main_text&&
                  expected_build(&ref.canonical,helper,main_text,calls,helper_first,&expected);
        free(helper);free(main_text);
        if(!built){
            CHECKL(0,"expected object carries the canonical C data half",label);
            reference_free(&ref);return;
        }
    }
    {
        NtArtifact art={0};
        if(!nt_object_materialize(&expected.object,&art,&error)){
            CHECKL(0,"C materialize",label);
        }else{
            CHECKL(nt_make_pe(&art),"C PE writer",label);
            if(art.pe.bytes){
                uint64_t pe_size=r64(out);
                CHECKL(pe_size==art.pe.size&&!memcmp(out+8,art.pe.bytes,art.pe.size),
                       "PE byte parity",label);
                if(pe_size!=art.pe.size||memcmp(out+8,art.pe.bytes,art.pe.size)){
                    size_t lim=pe_size<art.pe.size?(size_t)pe_size:art.pe.size,off=0;
                    while(off<lim&&out[8+off]==art.pe.bytes[off])off++;
                    fprintf(stderr,"PE mismatch at=%zu actual=%u expected=%u\n",off,
                            off<pe_size?out[8+off]:0,off<art.pe.size?art.pe.bytes[off]:0);
                }
                /* the materialized payloads are the canonical payload, unchanged */
                CHECKL(art.rdata.size==ref.canonical.sections[1].size&&
                       (ref.canonical.sections[1].size==0||
                        !memcmp(art.rdata.bytes,ref.canonical.sections[1].bytes,
                                ref.canonical.sections[1].size)),
                       "materialized .rdata is the canonical payload",label);
                CHECKL(art.data.size==ref.canonical.sections[2].size&&
                       (ref.canonical.sections[2].size==0||
                        !memcmp(art.data.bytes,ref.canonical.sections[2].bytes,
                                ref.canonical.sections[2].size)),
                       "materialized .data is the canonical payload",label);
                check_text(label,&art,calls,helper_first);
            }
        }
        free_artifact(&art);
    }
    expected_free(&expected);
    reference_free(&ref);
}

static void generated(const NovaHostImage*i,unsigned calls,unsigned items,unsigned split,
                      int helper_first,unsigned mode,const char*label){
    char*source=source_for(calls,items,split,helper_first,mode);
    char*twin=twin_for(items,split);
    CHECK(source!=NULL,"positive source allocation");
    CHECK(twin!=NULL,"positive twin allocation");
    if(!source||!twin){free(source);free(twin);return;}
    positive(i,calls,helper_first,label,source,twin);
    free(twin);free(source);
}

static void custom(const NovaHostImage*i,const char*label,const Item*items,size_t count){
    static char source[65536],twin[65536];
    if(!custom_source(source,sizeof source,items,count,1)){CHECKL(0,"custom fixture fits",label);return;}
    if(!custom_twin(twin,sizeof twin,items,count)){CHECKL(0,"custom twin fits",label);return;}
    positive(i,1,0,label,source,twin);
}

int main(void){
    const char*paths[]={
        "tests/nova/tests/x64-lower-nxo-local-multi-data-pe-entry.nova",
        "compiler/nova/backend/x64/x64_lower_nxo_pe.nova","compiler/nova/backend/x64/x64_lower_nxo.nova",
        "compiler/nova/backend/x64/x64_lower_control.nova","compiler/nova/backend/x64/x64_lower_fixed.nova",
        "compiler/nova/backend/x64/x64_fixed.nova","compiler/nova/analysis/types/register_widths.nova",
        "compiler/nova/formats/nxo/nxo_link_pe.nova","compiler/nova/formats/nxo/nxo_merge.nova",
        "compiler/nova/formats/nxo/nxo_pe.nova","compiler/nova/formats/nxo/nxo.nova",
        "compiler/nova/formats/pe/pe.nova","compiler/nova/frontend/parser.nova",
        "compiler/nova/frontend/ast.nova","compiler/nova/frontend/lexer.nova"
    ,
        "compiler/nova/macros/macro_splice.nova",
        "compiler/nova/macros/macro_expand.nova",
        "compiler/nova/macros/constant_eval.nova"};
    char*sources[18]={0};NtFInput inputs[18];int all=1;
    for(unsigned i=0;i<18;i++){size_t n=0;sources[i]=loadf(paths[i],&n);inputs[i]=(NtFInput){paths[i],sources[i],n};if(!sources[i])all=0;}
    CHECK(all,"sources load");NtArtifact compiler={0};int compiled=all&&nova_compile_many_v2(inputs,18,&compiler);
    CHECK(compiled,"Nova modules compile");
    if(!compiled)fprintf(stderr,"E%u %zu:%zu %s\n",compiler.error.code,compiler.error.line,compiler.error.column,compiler.error.message);
    NovaHostImage image={0};CHECK(compiled&&nova_host_map(&compiler,&image),"host map");
    if(image.memory){
        /* ---- the four retained positive fixtures ---- */
        generated(&image,1,1,1,0,0,"n=1,d=1 main-first");
        generated(&image,2,64,32,1,MODE_DATA_FIRST,"n=2,d=64 helper-first data-first");
        generated(&image,64,1,1,1,0,"n=64,d=1 helper-first");
        generated(&image,64,64,32,0,0,"n=64,d=64 main-first split");
        /* ---- the 1..64 item sweep, mixed widths, ascending names ---- */
        for(unsigned n=1;n<=64;n++){
            char label[32];snprintf(label,sizeof label,"sweep_%u",n);
            generated(&image,1,n,n,0,0,label);
        }
        /* ---- the same sweep split across .rdata and .data ---- */
        for(unsigned n=1;n<=64;n+=3){
            char label[32];snprintf(label,sizeof label,"split_%u",n);
            generated(&image,2,n,n/2,0,0,label);
        }
        /* ---- names that sort differently from declaration order ---- */
        {
            static const Item rev_u8_u64[]={{"zz",1,0x11,2},{"aa",8,0x2233445566778899ull,2}};
            static const Item rev_u64_u8[]={{"zz",8,0x2233445566778899ull,2},{"aa",1,0x11,2}};
            static const Item rev_u16_u32[]={{"bb",2,0x1122,2},{"aa",4,0x33445566u,2}};
            static const Item rev_u32_u16[]={{"bb",4,0x33445566u,2},{"aa",2,0x1122,2}};
            static const Item four_up[]={{"a",1,1,2},{"b",2,2,2},{"c",4,3,2},{"d",8,4,2}};
            static const Item four_down[]={{"d",8,4,2},{"c",4,3,2},{"b",2,2,2},{"a",1,1,2}};
            static const Item four_swap[]={{"d",8,4,2},{"b",2,2,2},{"c",4,3,2},{"a",1,1,2}};
            custom(&image,"reversed_u8_u64",rev_u8_u64,2);
            custom(&image,"reversed_u64_u8",rev_u64_u8,2);
            custom(&image,"reversed_u16_u32",rev_u16_u32,2);
            custom(&image,"reversed_u32_u16",rev_u32_u16,2);
            custom(&image,"four_widths_ascending",four_up,4);
            custom(&image,"four_widths_descending",four_down,4);
            custom(&image,"four_widths_mid_swap",four_swap,4);
        }
        /* ---- every alignment boundary a wider item can land on ---- */
        {
            static const Item p1[]={{"a",1,1,2},{"z",2,2,2}};
            static const Item p2[]={{"a",1,1,2},{"b",1,2,2},{"z",4,3,2}};
            static const Item p3[]={{"a",1,1,2},{"b",1,2,2},{"c",1,3,2},{"z",8,4,2}};
            static const Item p4[]={{"a",1,1,2},{"b",1,2,2},{"c",1,3,2},{"d",1,4,2},{"z",8,5,2}};
            static const Item p5[]={{"a",1,1,2},{"b",1,2,2},{"c",1,3,2},{"d",1,4,2},
                                    {"e",1,5,2},{"z",8,6,2}};
            static const Item p7[]={{"a",1,1,2},{"b",1,2,2},{"c",1,3,2},{"d",1,4,2},
                                    {"e",1,5,2},{"f",1,6,2},{"g",1,7,2},{"z",8,8,2}};
            static const Item p8[]={{"a",1,1,2},{"b",1,2,2},{"c",1,3,2},{"d",1,4,2},
                                    {"e",1,5,2},{"f",1,6,2},{"g",1,7,2},{"h",1,8,2},{"z",8,9,2}};
            static const Item u16x3[]={{"a",2,1,2},{"b",2,2,2},{"c",2,3,2},{"z",8,4,2}};
            static const Item u16x5[]={{"a",2,1,2},{"b",2,2,2},{"c",2,3,2},{"d",2,4,2},
                                       {"e",2,5,2},{"z",8,6,2}};
            static const Item u32x1[]={{"a",4,1,2},{"z",8,2,2}};
            static const Item u32x3[]={{"a",4,1,2},{"b",4,2,2},{"c",4,3,2},{"z",8,4,2}};
            static const Item u32u8[]={{"a",4,1,2},{"b",1,2,2},{"c",1,3,2},{"d",1,4,2},{"z",8,5,2}};
            static const Item u16u8[]={{"a",2,1,2},{"b",1,2,2},{"z",8,3,2}};
            custom(&image,"align2_after_1_u8",p1,2);
            custom(&image,"align4_after_2_u8",p2,3);
            custom(&image,"align8_after_3_u8",p3,4);
            custom(&image,"align8_after_4_u8",p4,5);
            custom(&image,"align8_after_5_u8",p5,6);
            custom(&image,"align8_after_7_u8",p7,8);
            custom(&image,"align8_at_8_u8",p8,9);
            custom(&image,"align8_after_3_u16",u16x3,4);
            custom(&image,"align8_after_5_u16",u16x5,6);
            custom(&image,"align8_after_1_u32",u32x1,2);
            custom(&image,"align8_after_3_u32",u32x3,4);
            custom(&image,"align8_after_u32_3_u8",u32u8,5);
            custom(&image,"align8_after_u16_u8",u16u8,3);
        }
        /* ---- homogeneous runs of eight, forwards and backwards ---- */
        {
            static const unsigned widths[4]={1,2,4,8};
            static const char alphabet[8]={'a','b','c','d','e','f','g','h'};
            char names[8][2];
            for(unsigned w=0;w<4;w++){
                Item forward[8],backward[8];
                for(unsigned i=0;i<8;i++){
                    names[i][0]=alphabet[i];names[i][1]=0;
                    forward[i]=(Item){names[i],widths[w],(uint64_t)(i+1)*7u+1u,2};
                    backward[7-i]=forward[i];
                }
                char label[40];
                snprintf(label,sizeof label,"u%u_x8_ascending",widths[w]*8);
                custom(&image,label,forward,8);
                snprintf(label,sizeof label,"u%u_x8_descending",widths[w]*8);
                custom(&image,label,backward,8);
            }
        }
        /* ---- byte order and both sections at once ---- */
        {
            static const Item ascii[]={{"Z",1,1,2},{"_x",4,2,2},{"abc",2,3,2},{"a",8,4,2}};
            static const Item digits[]={{"e0",1,1,2},{"d0",8,2,2},{"d00",2,3,2},{"a0",4,4,2}};
            static const Item prefix[]={{"ab",8,1,2},{"a",1,2,2},{"abc",2,3,2},{"b",4,4,2}};
            static const Item mixed[]={{"aB",1,1,2},{"Ab",2,2,2},{"AB",4,3,2},{"a",8,4,2}};
            static const Item two[]={{"zeta",2,4660,2},{"alpha",1,42,2},{"beta",4,2018915346u,3}};
            static const Item inter[]={{"m1",1,1,2},{"m2",8,2,3},{"m3",2,3,2},{"m4",4,4,3}};
            custom(&image,"byte_order_mixed",ascii,4);
            custom(&image,"byte_order_digits",digits,4);
            custom(&image,"byte_order_prefix",prefix,4);
            custom(&image,"byte_order_case",mixed,4);
            custom(&image,"two_sections_classic",two,3);
            custom(&image,"two_sections_interleaved",inter,4);
        }
        /* ---- the declaration index tiebreak of the name order is unreachable:
         *      both producers refuse two data items of the same name. Asserted. */
        {
            const char *twin_dup="module m\ntarget x86_64-nexora-uefi\nsection .rdata {\n"
                "export data aa:u8=1\nexport data aa:u8=2\n}\n"
                "section .text {\nexport fn main()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";
            Reference dup;
            int refused=!reference_for(twin_dup,&dup);
            if(!refused)reference_free(&dup);
            CHECKL(refused,"C frontend refuses two data items of one name","tie_break_unreachable");
            CHECKL(refused&&strstr(dup.why,"duplicate")!=NULL,
                   "C frontend names the duplicate diagnostic","tie_break_unreachable");
            rejected_text(&image,twin_dup,65536,800,"producer refuses two data items of one name");
        }
        /* ---- the retained refusals ---- */
        rejected_owned(&image,source_for(0,4,4,0,0),65536,800,"zero calls rejected transactionally");
        rejected_owned(&image,source_for(65,4,4,0,0),65536,800,"65 calls rejected transactionally");
        rejected_owned(&image,source_for(4,0,0,0,0),65536,800,"zero data rejected transactionally");
        rejected_owned(&image,source_for(4,65,65,0,0),65536,800,"65 data rejected transactionally");
        rejected_owned(&image,source_for(2,4,4,0,MODE_BAD_FIRST),65536,800,"invalid first call target rejected");
        rejected_owned(&image,source_for(2,4,4,1,MODE_BAD_LAST),65536,800,"invalid last call target rejected");
        rejected_owned(&image,source_for(2,4,4,0,MODE_ARITY),65536,800,"call arguments rejected");
        rejected_owned(&image,source_for(2,4,4,0,MODE_AFTER_RET),65536,800,"statement after ret rejected");
        rejected_owned(&image,source_for(2,4,4,0,MODE_EXTRA_FN),65536,800,"extra function rejected");
        rejected_owned(&image,source_for(2,4,4,0,MODE_EXTRA_SEC),65536,800,"extra section rejected");
        {
            const char*bad_range="module m\ntarget x86_64-nexora-uefi\nsection .rdata {\ndata d00:u8=256\n}\nsection .text {\nfn main()->u64\neffects {}\nclobbers {} {\ncall helper()\ncall helper()\nret\n}\nfn helper()->u64\neffects {}\nclobbers {} {\nret\n}\n}\n";
            rejected_text(&image,bad_range,65536,800,"out-of-range scalar rejected transactionally");
        }
        {
            const char*collide="module m\ntarget x86_64-nexora-uefi\nsection .rdata {\ndata helper:u8=1\n}\nsection .text {\nfn main()->u64\neffects {}\nclobbers {} {\ncall helper()\ncall helper()\nret\n}\nfn helper()->u64\neffects {}\nclobbers {} {\nret\n}\n}\n";
            rejected_text(&image,collide,65536,800,"helper/data name collision rejected transactionally");
        }
        rejected_owned(&image,source_for(2,4,4,0,0),16,827,"short PE output rejected transactionally");
    }
    if(image.memory)nova_host_unmap(&image);
    if(compiled)nt_artifact_free(&compiler);
    for(unsigned i=0;i<18;i++)free(sources[i]);
    
    /* ---- the contract oracle: the varied contract text of the C object
     *      writer, through the C reader and through the Nova accessor ---- */
    {
        NovaHostImage accessor = {0};
        NtArtifact accessor_artifact = {0};
        if (contract_image(&accessor, &accessor_artifact)) contract_suite(&accessor);
        if (accessor.memory) nova_host_unmap(&accessor);
        nt_artifact_free(&accessor_artifact);
    }
printf("NTASM_NOVA_X64_LOWER_NXO_LOCAL_MULTI_DATA_PE checks=%u failures=%u cases=%u\n",checks,failures,cases);
    return failures?1:0;
}
