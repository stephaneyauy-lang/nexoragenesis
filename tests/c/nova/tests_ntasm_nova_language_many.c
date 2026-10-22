#include "../../../compiler/c/nova/frontend/nova.h"
#include "../../../compiler/c/nova/runtime/run_host.h"
#include "../../../compiler/c/nova/runtime/runtime_v2.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checks, failures, cases;
#define CHECK(c, m)                                                            \
  do {                                                                         \
    checks++;                                                                  \
    if (!(c)) {                                                                \
      failures++;                                                              \
      fprintf(stderr, "FAIL %s\n", m);                                        \
    }                                                                          \
  } while (0)

#define NODES 65536
#define SIDES 4096
#define BINDS 8192
#define FIELDS 2048
#define MODULES 1024
#define OUTW 256
#define WORDS (NODES + SIDES + BINDS + FIELDS + MODULES + OUTW)
#define GUARD UINT64_C(0xcccccccccccccccc)

#define K_PROGRAM 25
#define K_MODULE 1
#define K_IMPORT 2
#define K_STRUCT 3
#define K_FIELD 4
#define K_FN 5
#define K_CALL 17

#define SLOTS_MANY 18

typedef struct {
    uint64_t returned;
    uint64_t runtime;
    uint64_t code;
    uint64_t node_count;
    uint64_t out[OUTW];
} ManyResult;

static char *loadf(const char *path, size_t *length) {
  FILE *f = fopen(path, "rb");
  if (!f) return NULL;
  fseek(f, 0, SEEK_END);
  long z = ftell(f);
  fseek(f, 0, SEEK_SET);
  char *b = z >= 0 ? malloc((size_t)z + 1) : NULL;
  if (!b || fread(b, 1, (size_t)z, f) != (size_t)z) {
    free(b); fclose(f); return NULL;
  }
  fclose(f); b[z] = 0; *length = (size_t)z; return b;
}


static uint64_t node_word(const uint64_t *nodes, uint64_t id, uint64_t w) {
    if (id == 0 || id > NODES / 16 || w >= 16) return 0;
    return nodes[(id - 1) * 16 + w];
}

static ManyResult run_many_ex(const NovaHostImage *image, const char *blob, size_t blob_len,
                              const uint64_t *spans, uint64_t count, uint64_t root_idx,
                              uint64_t mod_cap) {
    ManyResult r = {0};
    uint64_t *scratch = (uint64_t *)malloc(WORDS * sizeof(uint64_t));
    CHECK(scratch != NULL, "A8_MANY scratch memory allocated");
    if (!scratch) return r;
    for (size_t i = 0; i < WORDS; i++) scratch[i] = GUARD;

    NovaContextV2 c = {0};
    int c_ok = nova_context_init_v2(&c);
    CHECK(c_ok == 1, "A8_MANY context initialized");
    if (!c_ok) { free(scratch); return r; }

    uint64_t sh = nova_borrow_v2(&c, (void *)blob, blob_len, 0);
    uint64_t sph = nova_borrow_v2(&c, (void *)spans, count * 2 * sizeof(uint64_t), 0);
    uint64_t n1 = nova_borrow_v2(&c, scratch, NODES * 8, 1);
    uint64_t n2 = nova_borrow_v2(&c, scratch + NODES, SIDES * 8, 1);
    uint64_t n3 = nova_borrow_v2(&c, scratch + NODES + SIDES, BINDS * 8, 1);
    uint64_t n4 = nova_borrow_v2(&c, scratch + NODES + SIDES + BINDS, FIELDS * 8, 1);
    uint64_t n5 = nova_borrow_v2(&c, scratch + NODES + SIDES + BINDS + FIELDS, mod_cap * 8, 1);
    uint64_t oh = nova_borrow_v2(&c, scratch + NODES + SIDES + BINDS + FIELDS + MODULES, OUTW * 8, 1);

    CHECK(c.error == 0, "A8_MANY borrows completed without context error");
    CHECK(sh != 0 && (count == 0 || sph != 0) && n1 != 0 && n2 != 0 && n3 != 0 && n4 != 0 && n5 != 0 && oh != 0,
          "A8_MANY borrow handles non-zero");

    uint64_t args[SLOTS_MANY] = {
        sh, (uint64_t)blob_len,
        sph, count * 2,
        count, root_idx,
        n1, (uint64_t)NODES,
        n2, (uint64_t)SIDES,
        n3, (uint64_t)BINDS,
        n4, (uint64_t)FIELDS,
        n5, (uint64_t)mod_cap,
        oh, (uint64_t)OUTW
    };

    r.returned = image->entry(&c, args, SLOTS_MANY);
    r.runtime = c.error;

    uint64_t *out_words = scratch + NODES + SIDES + BINDS + FIELDS + MODULES;
    r.code = out_words[0];
    r.node_count = out_words[5];
    memcpy(r.out, out_words, OUTW * sizeof(uint64_t));

    /* Generic AST structural validations for successful parses */
    CHECK(r.node_count <= NODES / 16, "A8_MANY published node count bounded");
    if (r.runtime == 0 && r.code == 0 && r.node_count > 0 && r.node_count <= NODES / 16) {
        const uint64_t *nodes = scratch;
        CHECK(node_word(nodes, 1, 0) == K_PROGRAM, "A8_MANY root node 1 is K_PROGRAM (25)");
        uint64_t root_id = 1;
        uint64_t mod_child_count = 0;
        uint64_t ch = node_word(nodes, root_id, 2);
        while (ch != 0 && mod_child_count <= r.node_count) {
            CHECK(node_word(nodes, ch, 0) == K_MODULE, "A8_MANY program child is K_MODULE");
            CHECK(node_word(nodes, ch, 1) == root_id, "A8_MANY module parent is K_PROGRAM");
            mod_child_count++;
            ch = node_word(nodes, ch, 4);
        }
        CHECK(mod_child_count == count, "A8_MANY module count matches input count");

        for (uint64_t i = 1; i <= r.node_count; i++) {
            uint64_t p = node_word(nodes, i, 1);
            uint64_t fc = node_word(nodes, i, 2);
            uint64_t lc = node_word(nodes, i, 3);
            uint64_t ns = node_word(nodes, i, 4);
            CHECK(p <= r.node_count, "A8_MANY parent index in bounds");
            CHECK(fc <= r.node_count && lc <= r.node_count, "A8_MANY child index in bounds");
            CHECK(ns <= r.node_count, "A8_MANY sibling index in bounds");

            uint64_t kind = node_word(nodes, i, 0);
            if (kind == K_IMPORT) {
                uint64_t target_mod = node_word(nodes, i, 15);
                CHECK(target_mod > 0, "A8_MANY K_IMPORT target module id non-zero");
            }
            if (kind == K_CALL) {
                uint64_t aux = node_word(nodes, i, 13);
                if (aux == 0) {
                    uint64_t ord = node_word(nodes, i, 15);
                    uint64_t matched_fn = 0;
                    for (uint64_t j = 1; j <= r.node_count; j++) {
                        if (node_word(nodes, j, 0) == K_FN && node_word(nodes, j, 15) == ord) {
                            matched_fn++;
                        }
                    }
                    CHECK(matched_fn == 1, "A8_MANY direct K_CALL matches exactly one declared K_FN");
                }
            }
        }
    }

    CHECK(nova_context_destroy_v2(&c), "A8_MANY context destroyed");
    free(scratch);
    return r;
}

static ManyResult run_many(const NovaHostImage *image, const char *blob, size_t blob_len,
                           const uint64_t *spans, uint64_t count, uint64_t root_idx) {
    return run_many_ex(image, blob, blob_len, spans, count, root_idx, MODULES);
}

static unsigned audit_nova_many_sources(const NovaHostImage *image, const char *list_path) {
    if (!list_path || !image) return 0;
    FILE *f = fopen(list_path, "r");
    if (!f) {
        fprintf(stderr, "NOVA_MANY_AUDIT cannot open list file: %s\n", list_path);
        return 2;
    }

    char *paths[64];
    char *file_bufs[64];
    size_t file_lens[64];
    uint64_t spans[64 * 2];
    unsigned count = 0;
    char line[1024];
    int read_error = 0;

    while (fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] != '\n' && !feof(f)) {
            fprintf(stderr, "NOVA_MANY_AUDIT line truncated in %s\n", list_path);
            read_error = 1;
            break;
        }
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
            line[--len] = '\0';
        }
        if (len == 0) continue;

        if (count >= 64) {
            fprintf(stderr, "NOVA_MANY_AUDIT source count exceeds 64\n");
            read_error = 1;
            break;
        }

        paths[count] = (char *)malloc(len + 1);
        if (!paths[count]) { read_error = 1; break; }
        memcpy(paths[count], line, len + 1);

        size_t flen = 0;
        char *fbuf = loadf(line, &flen);
        if (!fbuf) {
            fprintf(stderr, "NOVA_MANY_AUDIT failed to read source file: %s\n", line);
            free(paths[count]);
            read_error = 1;
            break;
        }
        file_bufs[count] = fbuf;
        file_lens[count] = flen;
        count++;
    }
    fclose(f);

    if (read_error || count == 0) {
        for (unsigned i = 0; i < count; i++) {
            free(paths[i]);
            free(file_bufs[i]);
        }
        return 2;
    }

    /* Compute total bytes and construct contiguous blob */
    size_t total_bytes = 0;
    for (unsigned i = 0; i < count; i++) {
        if (SIZE_MAX - total_bytes < file_lens[i]) {
            fprintf(stderr, "NOVA_MANY_AUDIT size overflow\n");
            read_error = 1;
            break;
        }
        total_bytes += file_lens[i];
    }

    char *blob = NULL;
    if (!read_error && total_bytes > 0) {
        blob = (char *)malloc(total_bytes);
        if (!blob) read_error = 1;
    }

    if (read_error || !blob) {
        for (unsigned i = 0; i < count; i++) {
            free(paths[i]);
            free(file_bufs[i]);
        }
        if (blob) free(blob);
        return 2;
    }

    size_t cur_off = 0;
    for (unsigned i = 0; i < count; i++) {
        spans[i * 2] = (uint64_t)cur_off;
        spans[i * 2 + 1] = (uint64_t)file_lens[i];
        memcpy(blob + cur_off, file_bufs[i], file_lens[i]);
        cur_off += file_lens[i];
    }

    /* Large caller capacities for 52-source producer closure */
    const size_t AUDIT_NODES = 4194304;
    const size_t AUDIT_SCOPES = 65536;
    const size_t AUDIT_BINDS = 262144;
    const size_t AUDIT_FIELDS = 65536;
    const size_t AUDIT_MODULES = 32768;
    const size_t AUDIT_OUT = 256;
    const size_t AUDIT_WORDS = AUDIT_NODES + AUDIT_SCOPES + AUDIT_BINDS + AUDIT_FIELDS + AUDIT_MODULES + AUDIT_OUT;

    uint64_t *scratch = (uint64_t *)calloc(AUDIT_WORDS, sizeof(uint64_t));
    unsigned audit_rc = 2;

    if (scratch) {
        NovaContextV2 ctx = {0};
        if (nova_context_init_v2(&ctx)) {
            uint64_t sh = nova_borrow_v2(&ctx, (void *)blob, total_bytes, 0);
            uint64_t sph = nova_borrow_v2(&ctx, (void *)spans, count * 2 * sizeof(uint64_t), 0);
            uint64_t n1 = nova_borrow_v2(&ctx, scratch, AUDIT_NODES * 8, 1);
            uint64_t n2 = nova_borrow_v2(&ctx, scratch + AUDIT_NODES, AUDIT_SCOPES * 8, 1);
            uint64_t n3 = nova_borrow_v2(&ctx, scratch + AUDIT_NODES + AUDIT_SCOPES, AUDIT_BINDS * 8, 1);
            uint64_t n4 = nova_borrow_v2(&ctx, scratch + AUDIT_NODES + AUDIT_SCOPES + AUDIT_BINDS, AUDIT_FIELDS * 8, 1);
            uint64_t n5 = nova_borrow_v2(&ctx, scratch + AUDIT_NODES + AUDIT_SCOPES + AUDIT_BINDS + AUDIT_FIELDS, AUDIT_MODULES * 8, 1);
            uint64_t oh = nova_borrow_v2(&ctx, scratch + AUDIT_NODES + AUDIT_SCOPES + AUDIT_BINDS + AUDIT_FIELDS + AUDIT_MODULES, AUDIT_OUT * 8, 1);

            uint64_t args[SLOTS_MANY] = {
                sh, (uint64_t)total_bytes,
                sph, (uint64_t)(count * 2),
                (uint64_t)count, 0,
                n1, (uint64_t)AUDIT_NODES,
                n2, (uint64_t)AUDIT_SCOPES,
                n3, (uint64_t)AUDIT_BINDS,
                n4, (uint64_t)AUDIT_FIELDS,
                n5, (uint64_t)AUDIT_MODULES,
                oh, (uint64_t)AUDIT_OUT
            };

            uint64_t returned = image->entry(&ctx, args, SLOTS_MANY);
            uint64_t *out = scratch + AUDIT_NODES + AUDIT_SCOPES + AUDIT_BINDS + AUDIT_FIELDS + AUDIT_MODULES;
            uint64_t code = out[0];
            uint64_t reason = out[1];
            uint64_t err_line = out[2];
            uint64_t err_col = out[3];
            uint64_t err_start = out[4];
            uint64_t node_count = out[5];
            uint64_t root_id = out[6];

            const char *fail_path = "none";
            if (code != 0 || ctx.error != 0) {
                for (unsigned i = 0; i < count; i++) {
                    uint64_t s_off = spans[i * 2];
                    uint64_t s_len = spans[i * 2 + 1];
                    if (err_start >= s_off && err_start < s_off + s_len) {
                        fail_path = paths[i];
                        break;
                    }
                }
            }

            printf("NOVA_MANY_AUDIT files=%u bytes=%zu returned=%llu runtime=%llu code=%llu reason=%llu line=%llu column=%llu offset=%llu nodes=%llu root=%llu file=%s\n",
                   count, total_bytes, (unsigned long long)returned, (unsigned long long)ctx.error,
                   (unsigned long long)code, (unsigned long long)reason, (unsigned long long)err_line,
                   (unsigned long long)err_col, (unsigned long long)err_start, (unsigned long long)node_count,
                   (unsigned long long)root_id, fail_path);

            if (returned == 0 && ctx.error == 0 && code == 0 && node_count > 0 && root_id > 0) {
                audit_rc = 0;
            }
            nova_context_destroy_v2(&ctx);
        }
        free(scratch);
    }

    for (unsigned i = 0; i < count; i++) {
        free(paths[i]);
        free(file_bufs[i]);
    }
    free(blob);
    return audit_rc;
}

int main(void) {
    printf("tests_ntasm_nova_language_many starting...\n");

    /* Compile parser + entry wrapper using nova_compile_many_v2 */
    size_t len_entry = 0, len_parse = 0;
    char *src_entry = loadf("tests/nova/tests/nova-language-many-entry.nova", &len_entry);
    CHECK(src_entry != NULL, "A8_MANY loaded tests/nova-language-many-entry.nova");
    char *src_parse = loadf("compiler/nova/frontend/nova_language_parse.nova", &len_parse);
    CHECK(src_parse != NULL, "A8_MANY loaded compiler/nova/frontend/nova_language_parse.nova");

    if (!src_entry || !src_parse) {
        if (src_entry) free(src_entry);
        if (src_parse) free(src_parse);
        fprintf(stderr, "A8_MANY failed loading compile sources\n");
        return 1;
    }

    NtFInput inputs[2] = {
        { "tests/nova/tests/nova-language-many-entry.nova", src_entry, len_entry },
        { "compiler/nova/frontend/nova_language_parse.nova", src_parse, len_parse }
    };

    NtArtifact art = {0};
    int compile_ok = nova_compile_many_v2(inputs, 2, &art);
    CHECK(compile_ok == 1, "A8_MANY compiled entry + parse artifact");
    free(src_entry);
    free(src_parse);

    if (compile_ok != 1) {
        fprintf(stderr, "A8_MANY compilation failed E%u %s\n", art.error.code, art.error.message); nt_artifact_free(&art);
        return 1;
    }

    NovaHostImage image = {0};
    int map_ok = nova_host_map(&art, &image);
    CHECK(map_ok == 1, "A8_MANY mapped host image");
    nt_artifact_free(&art);

    if (map_ok != 1) {
        fprintf(stderr, "A8_MANY host map failed; aborting\n");
        return 1;
    }

    /* Positive Case 1: 3 modules with forward references, export fn and record */
    cases++;
    const char *b1 = 
        "module m_root;\nimport m_mid;\nexport fn run() -> u64 { return m_mid.use_pair(); }\n"
        "module m_mid;\nimport m_leaf;\nexport fn use_pair() -> u64 { let p: m_leaf.Pair = m_leaf.make(); return p.x; }\n"
        "module m_leaf;\nexport struct Pair { x: u64 }\nexport fn make() -> Pair { return Pair{x: 42}; }\n";
    size_t l1 = strlen(b1);
    size_t s1_m1 = 0, l1_m1 = strlen("module m_root;\nimport m_mid;\nexport fn run() -> u64 { return m_mid.use_pair(); }\n");
    size_t s1_m2 = l1_m1, l1_m2 = strlen("module m_mid;\nimport m_leaf;\nexport fn use_pair() -> u64 { let p: m_leaf.Pair = m_leaf.make(); return p.x; }\n");
    size_t s1_m3 = l1_m1 + l1_m2, l1_m3 = l1 - s1_m3;
    uint64_t spans1[] = { (uint64_t)s1_m1, (uint64_t)l1_m1, (uint64_t)s1_m2, (uint64_t)l1_m2, (uint64_t)s1_m3, (uint64_t)l1_m3 };

    NtFInput ref_in1[] = {
        { "m_root.nova", b1 + s1_m1, l1_m1 },
        { "m_mid.nova", b1 + s1_m2, l1_m2 },
        { "m_leaf.nova", b1 + s1_m3, l1_m3 }
    };
    CHECK(nova_check_many_v2(ref_in1, 3, NULL), "A8_MANY pos1 C reference accepts 3-module forward imports");

    ManyResult r1 = run_many(&image, b1, l1, spans1, 3, 0);
    CHECK(r1.runtime == 0, "A8_MANY pos1 candidate runtime clean");
    CHECK(r1.code == 0, "A8_MANY pos1 candidate accepted");
    CHECK(r1.returned == r1.code, "A8_MANY pos1 returned matches code");
    CHECK(r1.node_count > 0, "A8_MANY pos1 candidate published tree");
    CHECK(r1.out[6] == 1, "A8_MANY pos1 root node is 1");

    /* Positive Case 2: Same private function name in different modules */
    cases++;
    const char *b2 = 
        "module mod_a;\nimport mod_b;\nfn helper() -> u64 { return 10; }\nexport fn run() -> u64 { return helper() + mod_b.calc(); }\n"
        "module mod_b;\nfn helper() -> u64 { return 20; }\nexport fn calc() -> u64 { return helper(); }\n";
    size_t l2 = strlen(b2);
    size_t s2_a = 0, l2_a = strlen("module mod_a;\nimport mod_b;\nfn helper() -> u64 { return 10; }\nexport fn run() -> u64 { return helper() + mod_b.calc(); }\n");
    size_t s2_b = l2_a, l2_b = l2 - l2_a;
    uint64_t spans2[] = { (uint64_t)s2_a, (uint64_t)l2_a, (uint64_t)s2_b, (uint64_t)l2_b };

    NtFInput ref_in2[] = {
        { "mod_a.nova", b2 + s2_a, l2_a },
        { "mod_b.nova", b2 + s2_b, l2_b }
    };
    CHECK(nova_check_many_v2(ref_in2, 2, NULL), "A8_MANY pos2 C reference accepts distinct private functions");
    ManyResult r2 = run_many(&image, b2, l2, spans2, 2, 0);
    CHECK(r2.runtime == 0 && r2.code == 0 && r2.returned == r2.code && r2.node_count > 0,
          "A8_MANY pos2 candidate accepted private collisions across units");

    /* Positive Case 3: Mutual/Cyclic imports between module headers */
    cases++;
    const char *b3 = 
        "module cyc_a;\nimport cyc_b;\nexport fn a() -> u64 { return 1; }\nexport fn call_b() -> u64 { return cyc_b.b(); }\n"
        "module cyc_b;\nimport cyc_a;\nexport fn b() -> u64 { return cyc_a.a(); }\n";
    size_t l3 = strlen(b3);
    size_t s3_a = 0, l3_a = strlen("module cyc_a;\nimport cyc_b;\nexport fn a() -> u64 { return 1; }\nexport fn call_b() -> u64 { return cyc_b.b(); }\n");
    size_t s3_b = l3_a, l3_b = l3 - l3_a;
    uint64_t spans3[] = { (uint64_t)s3_a, (uint64_t)l3_a, (uint64_t)s3_b, (uint64_t)l3_b };
    NtFInput ref_in3[] = { { "cyc_a.nova", b3 + s3_a, l3_a }, { "cyc_b.nova", b3 + s3_b, l3_b } };
    CHECK(nova_check_many_v2(ref_in3, 2, NULL), "A8_MANY pos3 C reference accepts import cycles");
    ManyResult r3 = run_many(&image, b3, l3, spans3, 2, 0);
    CHECK(r3.runtime == 0 && r3.code == 0 && r3.returned == r3.code && r3.node_count > 0,
          "A8_MANY pos3 candidate accepts cyclic import graphs");

    /* Positive Case 4: Split files sharing the same module name */
    cases++;
    const char *b4 = 
        "module split_mod;\nexport struct S { x: u64 }\n"
        "module split_mod;\nexport fn run(s: S) -> u64 { return s.x; }\n";
    size_t l4 = strlen(b4);
    size_t s4_1 = 0, l4_1 = strlen("module split_mod;\nexport struct S { x: u64 }\n");
    size_t s4_2 = l4_1, l4_2 = l4 - l4_1;
    uint64_t spans4[] = { (uint64_t)s4_1, (uint64_t)l4_1, (uint64_t)s4_2, (uint64_t)l4_2 };
    NtFInput ref_in4[] = { { "s1.nova", b4 + s4_1, l4_1 }, { "s2.nova", b4 + s4_2, l4_2 } };
    CHECK(nova_check_many_v2(ref_in4, 2, NULL), "A8_MANY pos4 C reference accepts split module files");
    ManyResult r4 = run_many(&image, b4, l4, spans4, 2, 1);
    CHECK(r4.runtime == 0 && r4.code == 0 && r4.returned == r4.code && r4.node_count > 0,
          "A8_MANY pos4 candidate merges split module files into single module space");

    /* Positive Case 5: Local variable name shadowing an imported module name */
    cases++;
    const char *b5 = 
        "module shadow_root;\nimport ext_mod;\nexport fn run() -> u64 { let ext_mod: u64 = 42; return ext_mod; }\n"
        "module ext_mod;\nexport fn val() -> u64 { return 100; }\n";
    size_t l5 = strlen(b5);
    size_t s5_1 = 0, l5_1 = strlen("module shadow_root;\nimport ext_mod;\nexport fn run() -> u64 { let ext_mod: u64 = 42; return ext_mod; }\n");
    size_t s5_2 = l5_1, l5_2 = l5 - l5_1;
    uint64_t spans5[] = { (uint64_t)s5_1, (uint64_t)l5_1, (uint64_t)s5_2, (uint64_t)l5_2 };
    NtFInput ref_in5[] = { { "sr.nova", b5 + s5_1, l5_1 }, { "ext.nova", b5 + s5_2, l5_2 } };
    CHECK(nova_check_many_v2(ref_in5, 2, NULL), "A8_MANY pos5 C reference accepts local variable shadowing imported module");
    ManyResult r5 = run_many(&image, b5, l5, spans5, 2, 0);
    CHECK(r5.runtime == 0 && r5.code == 0 && r5.returned == r5.code && r5.node_count > 0,
          "A8_MANY pos5 candidate preserves local shadow over imported module");

    /* Negative Case 1: Missing import declaration */
    cases++;
    const char *bn1 = "module neg1;\nexport fn run() -> u64 { return other.foo(); }\n" "module other;\nexport fn foo() -> u64 { return 1; }\n";
    size_t ln1 = strlen(bn1), ln1_1 = strlen("module neg1;\nexport fn run() -> u64 { return other.foo(); }\n");
    uint64_t spans_n1[] = { 0, (uint64_t)ln1_1, (uint64_t)ln1_1, (uint64_t)(ln1 - ln1_1) };
    NtFInput ref_in_n1[] = { { "n1.nova", bn1, ln1_1 }, { "other.nova", bn1 + ln1_1, ln1 - ln1_1 } };
    CHECK(!nova_check_many_v2(ref_in_n1, 2, NULL), "A8_MANY neg1 C reference rejects missing import");
    ManyResult rn1 = run_many(&image, bn1, ln1, spans_n1, 2, 0);
    CHECK(rn1.runtime == 0 && rn1.code != 0 && rn1.returned == rn1.code && rn1.node_count == 0,
          "A8_MANY neg1 candidate rejects missing import");

    /* Negative Case 2: Calling private (unexported) function */
    cases++;
    const char *bn2 = "module neg2;\nimport priv_mod;\nexport fn run() -> u64 { return priv_mod.secret(); }\n" "module priv_mod;\nfn secret() -> u64 { return 1; }\n";
    size_t ln2 = strlen(bn2), ln2_1 = strlen("module neg2;\nimport priv_mod;\nexport fn run() -> u64 { return priv_mod.secret(); }\n");
    uint64_t spans_n2[] = { 0, (uint64_t)ln2_1, (uint64_t)ln2_1, (uint64_t)(ln2 - ln2_1) };
    NtFInput ref_in_n2[] = { { "n2.nova", bn2, ln2_1 }, { "priv.nova", bn2 + ln2_1, ln2 - ln2_1 } };
    CHECK(!nova_check_many_v2(ref_in_n2, 2, NULL), "A8_MANY neg2 C reference rejects private function call");
    ManyResult rn2 = run_many(&image, bn2, ln2, spans_n2, 2, 0);
    CHECK(rn2.runtime == 0 && rn2.code != 0 && rn2.returned == rn2.code && rn2.node_count == 0,
          "A8_MANY neg2 candidate rejects private function call");

    /* Negative Case 3: Using private (unexported) type */
    cases++;
    const char *bn3 = "module neg3;\nimport type_mod;\nexport fn run(p: type_mod.Secret) -> u64 { return 1; }\n" "module type_mod;\nstruct Secret { x: u64 }\n";
    size_t ln3 = strlen(bn3), ln3_1 = strlen("module neg3;\nimport type_mod;\nexport fn run(p: type_mod.Secret) -> u64 { return 1; }\n");
    uint64_t spans_n3[] = { 0, (uint64_t)ln3_1, (uint64_t)ln3_1, (uint64_t)(ln3 - ln3_1) };
    NtFInput ref_in_n3[] = { { "n3.nova", bn3, ln3_1 }, { "type_mod.nova", bn3 + ln3_1, ln3 - ln3_1 } };
    CHECK(!nova_check_many_v2(ref_in_n3, 2, NULL), "A8_MANY neg3 C reference rejects private type use");
    ManyResult rn3 = run_many(&image, bn3, ln3, spans_n3, 2, 0);
    CHECK(rn3.runtime == 0 && rn3.code != 0 && rn3.returned == rn3.code && rn3.node_count == 0,
          "A8_MANY neg3 candidate rejects private type use");

    /* Negative Case 4: Unqualified use of imported export (MUST be qualified) */
    cases++;
    const char *bn4 = "module neg4;\nimport exp_mod;\nexport fn run() -> u64 { return exported_fn(); }\n" "module exp_mod;\nexport fn exported_fn() -> u64 { return 1; }\n";
    size_t ln4 = strlen(bn4), ln4_1 = strlen("module neg4;\nimport exp_mod;\nexport fn run() -> u64 { return exported_fn(); }\n");
    uint64_t spans_n4[] = { 0, (uint64_t)ln4_1, (uint64_t)ln4_1, (uint64_t)(ln4 - ln4_1) };
    NtFInput ref_in_n4[] = { { "n4.nova", bn4, ln4_1 }, { "exp.nova", bn4 + ln4_1, ln4 - ln4_1 } };
    CHECK(!nova_check_many_v2(ref_in_n4, 2, NULL), "A8_MANY neg4 C reference rejects unqualified call of imported function");
    ManyResult rn4 = run_many(&image, bn4, ln4, spans_n4, 2, 0);
    CHECK(rn4.runtime == 0 && rn4.code != 0 && rn4.returned == rn4.code && rn4.node_count == 0,
          "A8_MANY neg4 candidate rejects unqualified call of imported function");

    /* Negative Case 5: Duplicate function in same module across split files */
    cases++;
    const char *bn5 = "module dup_split;\nexport fn clash() -> u64 { return 1; }\n" "module dup_split;\nexport fn clash() -> u64 { return 2; }\n";
    size_t ln5 = strlen(bn5), ln5_1 = strlen("module dup_split;\nexport fn clash() -> u64 { return 1; }\n");
    uint64_t spans_n5[] = { 0, (uint64_t)ln5_1, (uint64_t)ln5_1, (uint64_t)(ln5 - ln5_1) };
    NtFInput ref_in_n5[] = { { "d1.nova", bn5, ln5_1 }, { "d2.nova", bn5 + ln5_1, ln5 - ln5_1 } };
    CHECK(!nova_check_many_v2(ref_in_n5, 2, NULL), "A8_MANY neg5 C reference rejects duplicate global in split module");
    ManyResult rn5 = run_many(&image, bn5, ln5, spans_n5, 2, 0);
    CHECK(rn5.runtime == 0 && rn5.code != 0 && rn5.returned == rn5.code && rn5.node_count == 0,
          "A8_MANY neg5 candidate rejects duplicate global in split module");

    /* Negative Case 6: Invalid root index out of range */
    cases++;
    ManyResult rn6 = run_many(&image, b1, l1, spans1, 3, 99);
    CHECK(rn6.runtime == 0 && rn6.code != 0 && rn6.returned == rn6.code && rn6.node_count == 0,
          "A8_MANY neg6 rejects out-of-range root index");

    /* Negative Case 7: Span count > 64 boundary */
    cases++;
    uint64_t spans_large[65 * 2] = {0};
    ManyResult rn7 = run_many(&image, b1, l1, spans_large, 65, 0);
    CHECK(rn7.runtime == 0 && rn7.code == 812 && rn7.returned == 812 && rn7.node_count == 0,
          "A8_MANY neg7 rejects count > 64 with E_TOO_SMALL");

    /* Negative Case 8: Count 0 */
    cases++;
    ManyResult rn8 = run_many(&image, b1, l1, spans1, 0, 0);
    CHECK(rn8.runtime == 0 && rn8.code != 0 && rn8.returned == rn8.code && rn8.node_count == 0,
          "A8_MANY neg8 rejects count 0");

    /* Negative Case 9: Span offset overflow past blob length */
    cases++;
    uint64_t spans_oflow[] = { (uint64_t)(l1 + 10), 10 };
    ManyResult rn9 = run_many(&image, b1, l1, spans_oflow, 1, 0);
    CHECK(rn9.runtime == 0 && rn9.code != 0 && rn9.returned == rn9.code && rn9.node_count == 0,
          "A8_MANY neg9 rejects span offset past blob length");

    /* Negative Case 10: Span length overflows past blob length */
    cases++;
    uint64_t spans_len_oflow[] = { 0, (uint64_t)(l1 + 100) };
    ManyResult rn10 = run_many(&image, b1, l1, spans_len_oflow, 1, 0);
    CHECK(rn10.runtime == 0 && rn10.code != 0 && rn10.returned == rn10.code && rn10.node_count == 0,
          "A8_MANY neg10 rejects span length overflowing blob");

    /* Negative Case 11: Overlapping spans */
    cases++;
    uint64_t spans_overlap[] = { 0, 50, 25, 50 };
    ManyResult rn11 = run_many(&image, b1, l1, spans_overlap, 2, 0);
    CHECK(rn11.runtime == 0 && rn11.code != 0 && rn11.returned == rn11.code && rn11.node_count == 0,
          "A8_MANY neg11 rejects overlapping spans");

    /* Negative Case 12: Insufficient modules buffer capacity */
    cases++;
    ManyResult rn12 = run_many_ex(&image, b1, l1, spans1, 3, 0, 4);
    CHECK(rn12.runtime == 0 && rn12.code == 812 && rn12.returned == 812 && rn12.node_count == 0,
          "A8_MANY neg12 rejects insufficient modules capacity with E_TOO_SMALL");

    const char *many_list = getenv("NOVA_MANY_SOURCE_LIST");
    unsigned audit_rc = many_list ? audit_nova_many_sources(&image, many_list) : 0;

    nova_host_unmap(&image);
    printf("NTASM_NOVA_LANGUAGE_MANY checks=%u failures=%u cases=%u\n",
           checks, failures, cases);
    return failures ? 1 : (audit_rc ? 2 : 0);
}
