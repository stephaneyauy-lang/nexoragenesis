#include "../../../compiler/c/nova/frontend/nova.h"
#include "../../../compiler/c/nova/runtime/run_host.h"
#include "../../../compiler/c/nova/runtime/runtime_v2.h"
#include "../../../compiler/c/ntasm/formats/object.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checks,failures,cases;
#define CHECK(c,m) do{checks++;if(!(c)){failures++;fprintf(stderr,"FAIL %s\n",m);}}while(0)
static char *loadf(const char *p,size_t *n){
    FILE*f=fopen(p,"rb");if(!f)return NULL;
    fseek(f,0,SEEK_END);long z=ftell(f);fseek(f,0,SEEK_SET);
    char*b=z>=0?malloc((size_t)z+1):NULL;
    if(!b||fread(b,1,(size_t)z,f)!=(size_t)z){free(b);fclose(f);return NULL;}
    fclose(f);b[z]=0;*n=(size_t)z;return b;
}
static uint64_t r64(const uint8_t*b){uint64_t v=0;for(unsigned i=0;i<8;i++)v|=(uint64_t)b[i]<<(i*8);return v;}
static uint64_t run(const NovaHostImage*i,const char*source,uint8_t*out,size_t cap){
    NovaContextV2 c={0};CHECK(nova_context_init_v2(&c),"context init");
    uint64_t sh=nova_borrow_v2(&c,(void*)source,strlen(source),0);
    uint64_t oh=nova_borrow_v2(&c,out,cap,1);uint64_t args[]={sh,strlen(source),oh,cap};
    uint64_t code=i->entry(&c,args,4);if(c.error)fprintf(stderr,"Nova runtime error=%llu source=%llu offset=%llu return=%llu\n",(unsigned long long)c.error,(unsigned long long)c.error_source,(unsigned long long)c.error_offset,(unsigned long long)code);CHECK(c.error==0,"runtime clean");
    CHECK(nova_context_destroy_v2(&c),"context cleanup");cases++;return code;
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

/* The same text in static storage, for a symbol table that only borrows the
 * string until nt_object_write has copied it. Four slots, so a table of up to
 * four symbols can be built without allocating. NULL when the C writer
 * produced nothing for that name. */
static const char *c_contract_static(const char *probe, const char *name, unsigned slot)
{
    static char storage[4][1024];
    char *copy = c_contract(probe, name);
    const char *result = NULL;
    if (slot >= 4) { free(copy); return NULL; }
    if (copy) {
        size_t n = strlen(copy);
        if (n + 1 < sizeof storage[0]) {
            memcpy(storage[slot], copy, n + 1);
            result = storage[slot];
        }
        free(copy);
    }
    return result;
}

/* The name the C object writer gave that symbol, in full, from a fresh
 * nt_object_compile of `probe`. The bare name is what a fixture names; the
 * qualified name is what the object carries, and the object is the artefact
 * this gate byte-compares, so the expectation is built from the writer's own
 * string and not from a literal. NULL when the writer produced no such
 * symbol. */
static const char *c_name_static(const char *probe, const char *name, unsigned slot)
{
    static char storage[4][256];
    NtFInput input = {"d", probe, probe ? strlen(probe) : 0};
    NtObject object;
    NtDiagnostic error;
    const char *result = NULL;
    size_t k, nl = strlen(name);
    if (slot >= 4) return NULL;
    memset(&object, 0, sizeof object);
    memset(&error, 0, sizeof error);
    if (!nt_object_compile(&input, 1, &object, &error)) {
        fprintf(stderr, "C_NAME_REFUSED name=%s code=%u %s\n", name, error.code,
                error.message);
        return NULL;
    }
    for (k = 0; k < object.symbol_count; k++) {
        const char *written = object.symbols[k].name;
        size_t l = written ? strlen(written) : 0;
        if (l > nl && written[l - 1 - nl] == '.' && !memcmp(written + l - nl, name, nl)) {
            if (l + 1 < sizeof storage[0]) { memcpy(storage[slot], written, l + 1); result = storage[slot]; }
            break;
        }
    }
    nt_object_free(&object);
    return result;
}

/* The C expressible twin of the local call/ret source: the same two
 * declarations in the same order, each body reduced to "return 0".
 * contract_text reads no body text, so the twin and the real source describe
 * the same declarations and the C object writer writes the same contract for
 * both. Its MODULE is the producer's own, because the C object writer
 * qualifies every symbol name with the module of the source it was given
 * (object_build.c nt_object_compile) and this twin is the C oracle for the
 * producer's own name table; a twin under any other module would answer with
 * a prefix the producer never has. Held in static storage because the symbol
 * table borrows the two strings until nt_object_write has copied them. */
static const char *local_twin(int helper_first)
{
    static char storage[2][512];
    /* `export`, because the producer source this twin oracles says it: the
     * reference reads the export bit off the declaration (object_build.c:317)
     * and names the entry only for an exported main (object_build.c:343-347,
     * codegen.c:1557-1562), so a twin that dropped it would describe a
     * different program than the fixture it is the oracle for. */
    static const char *const MAIN = "export fn main()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n";
    static const char *const HELPER = "fn helper()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n";
    int n = snprintf(storage[helper_first ? 1 : 0], sizeof storage[0],
                     "module m\ntarget x86_64-nexora-uefi\nsection .text {\n%s%s}\n",
                     helper_first ? HELPER : MAIN, helper_first ? MAIN : HELPER);
    if (n <= 0 || (size_t)n >= sizeof storage[0]) return NULL;
    return storage[helper_first ? 1 : 0];
}
static void parity_case(const NovaHostImage*image,const char*source,int helper_first){
    uint8_t text[]={195,0,0,0,0,0,195};
    uint64_t site=helper_first?2:1;
    if(helper_first){text[0]=195;text[1]=0xe8;text[6]=195;}
    else{text[0]=0xe8;text[5]=195;text[6]=195;}
    char*helper_contract=(char*)c_contract_static(local_twin(helper_first),"helper",0);
    char*main_contract=(char*)c_contract_static(local_twin(helper_first),"main",1);
    CHECK(helper_contract&&main_contract,"C canonical contracts for the local twin");
    const char*helper_name=c_name_static(local_twin(helper_first),"helper",2);
    const char*main_name=c_name_static(local_twin(helper_first),"main",3);
    CHECK(helper_name&&main_name,"C canonical names for the local twin");
    /* A twin the C writer refused leaves no oracle to compare against, so the
     * table carries a name the producer can never write and the byte parity
     * below fails rather than passing on a table nobody built. */
    NtObjectSymbol symbols[]={
        {(char*)(helper_name?helper_name:"(no C name)"),helper_contract,1,NT_OBJECT_FUNCTION,helper_first?0:6,1},
        {(char*)(main_name?main_name:"(no C name)"),main_contract,1,NT_OBJECT_FUNCTION|NT_OBJECT_EXPORT,helper_first?1:0,6}
    };
    NtObjectReloc relocation={1,NT_OBJECT_REL32,1,site,0};
    NtObject object={0};object.target=1;object.entry_symbol=2;
    object.sections[0]=(NtBuffer){text,sizeof text,sizeof text};
    object.symbols=symbols;object.symbol_count=2;object.relocations=&relocation;object.relocation_count=1;
    NtDiagnostic error={0};NtBuffer expected_nxo={0};
    CHECK(nt_object_write(&object,&expected_nxo,&error),"C NXO writer");
    NtArtifact executable={0};
    CHECK(nt_object_materialize(&object,&executable,&error),"C materialize");
    CHECK(nt_make_pe(&executable),"C PE writer");
    uint8_t out[65536];memset(out,0xcc,sizeof out);uint64_t code=run(image,source,out,sizeof out);
    uint64_t nxo_size=r64(out),pe_size=r64(out+8);
    if(code!=0||nxo_size!=expected_nxo.size||pe_size!=executable.pe.size)fprintf(stderr,"result code=%llu nxo=%llu/%zu pe=%llu/%zu\n",(unsigned long long)code,(unsigned long long)nxo_size,expected_nxo.size,(unsigned long long)pe_size,executable.pe.size);
    CHECK(code==0&&nxo_size==expected_nxo.size&&
          !memcmp(out+16,expected_nxo.bytes,expected_nxo.size),"NXO byte parity");
    CHECK(code==0&&pe_size==executable.pe.size&&
          !memcmp(out+16+nxo_size,executable.pe.bytes,executable.pe.size),"PE byte parity");
    CHECK(executable.text.size==7&&executable.text.bytes[site-1]==0xe8&&
          executable.text.bytes[site]==(helper_first?0xfa:1)&&
          executable.text.bytes[site+1]==(helper_first?0xff:0),"REL32 displacement");
    CHECK(executable.entry==(helper_first?1:0),"entry follows main source order");
    CHECK(object.sections[0].size==7&&object.symbol_count==2&&object.relocation_count==1,
          "NXO sections symbols relocation");
    free(expected_nxo.bytes);nt_artifact_free(&executable);
}
static void rejected(const NovaHostImage*i,const char*source,size_t cap,uint64_t expected,const char*label){
    uint8_t out[65536];memset(out,0xcc,sizeof out);uint64_t code=run(i,source,out,cap);
    int intact=code==expected;for(size_t j=0;j<cap;j++)intact&=out[j]==0xcc;CHECK(intact,label);
}
int main(void){
    const char*paths[]={
        "compiler/nova/backend/x64/x64_lower_nxo.nova",
        "compiler/nova/backend/x64/x64_lower_control.nova",
        "compiler/nova/backend/x64/x64_lower_fixed.nova",
        "compiler/nova/backend/x64/x64_fixed.nova",
        "compiler/nova/analysis/types/register_widths.nova",
        "compiler/nova/formats/nxo/nxo.nova",
        "compiler/nova/formats/pe/pe.nova",
        "compiler/nova/formats/nxo/nxo_link_pe.nova",
        "compiler/nova/formats/nxo/nxo_merge.nova",
        "compiler/nova/frontend/parser.nova",
        "compiler/nova/frontend/ast.nova",
        "compiler/nova/frontend/lexer.nova",
        "tests/nova/tests/x64-lower-nxo-local-pe-entry.nova",
        "compiler/nova/backend/x64/x64_lower_nxo_pe.nova",
        "compiler/nova/formats/nxo/nxo_pe.nova"
    ,
        "compiler/nova/macros/macro_splice.nova",
        "compiler/nova/macros/macro_expand.nova",
        "compiler/nova/macros/constant_eval.nova"};
    char*sources[18]={0};NtFInput inputs[18];int all=1;
    for(unsigned i=0;i<18;i++){size_t n=0;sources[i]=loadf(paths[i],&n);inputs[i]=(NtFInput){paths[i],sources[i],n};if(!sources[i])all=0;}
    CHECK(all,"sources load");NtArtifact compiler={0};
    int compiled=all&&nova_compile_many_v2(inputs,18,&compiler);CHECK(compiled,"Nova modules compile");
    if(!compiled)fprintf(stderr,"E%u %zu:%zu %s\n",compiler.error.code,compiler.error.line,compiler.error.column,compiler.error.message);
    NovaHostImage image={0};
    CHECK(compiled&&nova_host_map(&compiler,&image),"PE entry host map");
    if(image.memory){
        /* WHY THESE TWO SAY `export fn main`. The reference sets NT_OBJECT_EXPORT
         * from the declaration's own `exported` bit (object_build.c:317) and names
         * the entry only for an EXPORTED main (object_build.c:343-347,
         * codegen.c:1557-1562), so a main without the modifier is a legal object
         * with entry_symbol = 0 and flags = NT_OBJECT_FUNCTION alone. The C
         * reference refuses this call/ret body (a bare ret has no available
         * stack/frame balance proof: 503), so the reference is asked about
         * local_twin above, and the two must declare the SAME program for the
         * comparison to mean anything. The producer used to hardcode the export
         * bit on main, which made producer and twin agree in the output even
         * though they declared different programs; that was hiding the
         * difference, not proving parity. */
        const char*main_first="module m\ntarget x86_64-nexora-uefi\nsection .text {\nexport fn main()->u64\neffects {}\nclobbers {} {\ncall helper()\nret\n}\nfn helper()->u64\neffects {}\nclobbers {} {\nret\n}\n}\n";
        const char*helper_first="module m\ntarget x86_64-nexora-uefi\nsection .text {\nfn helper()->u64\neffects {}\nclobbers {} {\nret\n}\nexport fn main()->u64\neffects {}\nclobbers {} {\ncall helper()\nret\n}\n}\n";
        parity_case(&image,main_first,0);parity_case(&image,helper_first,1);
        const char*bad="module m\ntarget x86_64-nexora-uefi\nsection .text {\nfn main()->u64\neffects {}\nclobbers {} {\nret\n}\n}\n";
        rejected(&image,bad,65536,800,"invalid local-call shape transactional");
        rejected(&image,main_first,8,827,"short PE output transactional");
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
printf("NTASM_NOVA_X64_LOWER_NXO_LOCAL_PE checks=%u failures=%u cases=%u\n",checks,failures,cases);
    return failures?1:0;
}
