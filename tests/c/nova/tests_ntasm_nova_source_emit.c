#define _GNU_SOURCE
#include <unistd.h>
#include <signal.h>
static pid_t bounded_fork(void) {
    pid_t p = fork();
    if (p == 0) alarm(5);
    return p;
}
#define fork bounded_fork
#define main prior_pe_exec_main
#include "tests_ntasm_pe_exec.c"
#undef main
#undef fork

#include "../../../compiler/c/nova/frontend/nova.h"
#include "../../../compiler/c/nova/runtime/run_host.h"
#include "../../../compiler/c/nova/runtime/runtime_v2.h"
#include "../../../compiler/c/nova/backend/machine_driver.h"
#include <sys/stat.h>
#include <sys/types.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define WORDS_NODES  65536
#define WORDS_SCOPES 4096
#define WORDS_BINDS  8192
#define WORDS_FIELDS 8192
#define BYTES_OUT    65536
#define WORDS_REPORT 16

typedef struct {
    uint64_t *nodes;
    uint64_t *scopes;
    uint64_t *binds;
    uint64_t *fields;
    uint8_t *out;
    uint64_t *len;
    uint64_t *rep;
} WorkBuffers;

typedef struct {
    uint64_t returned;
    uint64_t runtime_err;
} RunResult;

typedef struct {
    const char *name;
    const char *source;
    uint64_t want;
} TestCase;

static const TestCase POSITIVES[] = {
    {"return42",
     "module m;\nfn main()->u64 { return 42; }\n",
     42},
    {"return43",
     "module m;\nfn main()->u64 { return 43; }\n",
     43},
    {"returnmax",
     "module m;\nfn main()->u64 { return 18446744073709551615; }\n",
     UINT64_MAX},
    {"arithmetic",
     "module m;\nfn main()->u64 { return 6 * 7 + 1; }\n",
     43},
    {"immutable_let",
     "module m;\nfn main()->u64 { let x: u64 = 6; return x * 7; }\n",
     42},
    {"forward_call",
     "module m;\nfn main()->u64 { return add(40, 2); }\nfn add(a: u64, b: u64)->u64 { return a + b; }\n",
     42},
    {"choose_zero",
     "module m;\nfn choose(x: u64)->u64 { if x == 0 { return 42; } else { return 43; } }\nfn main()->u64 { return choose(0); }\n",
     42},
    {"choose_one",
     "module m;\nfn choose(x: u64)->u64 { if x == 0 { return 42; } else { return 43; } }\nfn main()->u64 { return choose(1); }\n",
     43},
    {"helper_stmt",
     "module m;\nfn helper()->u64 { return 0; }\nfn main()->u64 { helper(); return 42; }\n",
     42},
    {"bool_if",
     "module m;\nfn yes()->bool { return true; }\nfn main()->u64 { if yes() { return 42; } else { return 0; } }\n",
     42},
    {"unary_not_true",
     "module m;\nfn main()->u64 { if !true { return 1; } else { return 0; } }\n",
     0},
    {"unary_not_false",
     "module m;\nfn main()->u64 { if !false { return 1; } else { return 0; } }\n",
     1},
    {"unary_bitwise_not",
     "module m;\nfn main()->u64 { return ~0; }\n",
     UINT64_MAX},
    {"unary_neg_u64",
     "module m;\nfn main()->u64 { return -1; }\n",
     UINT64_MAX},
    {"unary_neg_u64_fn",
     "module m;\nfn neg(x: u64)->u64 { return -x; }\nfn main()->u64 { return neg(7); }\n",
     UINT64_MAX - 6},
    {"unary_neg_u64_zero",
     "module m;\nfn neg(x: u64)->u64 { return -x; }\nfn main()->u64 { return neg(0); }\n",
     0},
    {"unary_neg_i64",
     "module m;\nfn main()->i64 { return -7; }\n",
     UINT64_MAX - 6},
    {"nested_elseif_zero",
     "module m;\nfn choose3(x: u64)->u64 { if x == 0 { return 40; } else if x == 1 { return 41; } else { return 42; } }\nfn main()->u64 { return choose3(0); }\n",
     40},
    {"nested_elseif_one",
     "module m;\nfn choose3(x: u64)->u64 { if x == 0 { return 40; } else if x == 1 { return 41; } else { return 42; } }\nfn main()->u64 { return choose3(1); }\n",
     41},
    {"nested_elseif_two",
     "module m;\nfn choose3(x: u64)->u64 { if x == 0 { return 40; } else if x == 1 { return 41; } else { return 42; } }\nfn main()->u64 { return choose3(2); }\n",
     42}
};

static void make_dir(const char *path) {
    int rc = mkdir(path, 0777);
    CHECK(rc == 0 || errno == EEXIST, "mkdir %s: rc=%d errno=%d (%s)", path, rc, errno, strerror(errno));
}

static void persist_file(const char *dir, const char *file, const void *data, size_t sz) {
    char path[512];
    int n = snprintf(path, sizeof path, "%s/%s", dir, file);
    CHECK(n > 0 && (size_t)n < sizeof path, "path snprintf fits buffer");
    if (n <= 0 || (size_t)n >= sizeof path) return;
    FILE *f = fopen(path, "wb");
    CHECK(f != NULL, "persist fopen %s", path);
    if (f) {
        size_t written = fwrite(data, 1, sz, f);
        CHECK(written == sz, "persist fwrite %s", path);
        int closed = fclose(f);
        CHECK(closed == 0, "persist fclose %s", path);
    }
}

static int compile_module_image(const char *const *paths, unsigned count,
                                NtArtifact *art, NovaHostImage *img) {
    NtFInput *inputs = (NtFInput *)calloc(count, sizeof(NtFInput));
    CHECK(inputs != NULL, "allocate NtFInput array for %u sources", count);
    if (!inputs) return 0;
    int ok = 1;
    for (unsigned i = 0; i < count; i++) {
        size_t sz = 0;
        uint8_t *text = readall(paths[i], &sz);
        CHECK(text != NULL, "read source %s", paths[i]);
        if (!text) {
            ok = 0;
            break;
        }
        inputs[i].name = paths[i];
        inputs[i].text = (char *)text;
        inputs[i].length = sz;
    }

    if (ok) {
        int comp = nova_compile_many_v2(inputs, count, art);
        CHECK(comp != 0 && art->error.code == 0, "nova_compile_many_v2 for %s: E%u %s",
              paths[0], art->error.code, art->error.message);
        if (comp && art->error.code == 0) {
            int mapped = nova_host_map(art, img);
            CHECK(mapped != 0 && img->entry != NULL, "nova_host_map for %s", paths[0]);
            if (!mapped || !img->entry) ok = 0;
        } else {
            ok = 0;
        }
    }

    for (unsigned i = 0; i < count; i++) {
        if (inputs[i].text) free((void *)inputs[i].text);
    }
    free(inputs);
    return ok;
}

static int alloc_work_buffers(WorkBuffers *w) {
    w->nodes = (uint64_t *)calloc(WORDS_NODES, sizeof(uint64_t));
    w->scopes = (uint64_t *)calloc(WORDS_SCOPES, sizeof(uint64_t));
    w->binds = (uint64_t *)calloc(WORDS_BINDS, sizeof(uint64_t));
    w->fields = (uint64_t *)calloc(WORDS_FIELDS, sizeof(uint64_t));
    w->out = (uint8_t *)calloc(BYTES_OUT, 1);
    w->len = (uint64_t *)calloc(1, sizeof(uint64_t));
    w->rep = (uint64_t *)calloc(WORDS_REPORT, sizeof(uint64_t));
    return (w->nodes && w->scopes && w->binds && w->fields && w->out && w->len && w->rep);
}

static void free_work_buffers(WorkBuffers *w) {
    if (w->nodes) free(w->nodes);
    if (w->scopes) free(w->scopes);
    if (w->binds) free(w->binds);
    if (w->fields) free(w->fields);
    if (w->out) free(w->out);
    if (w->len) free(w->len);
    if (w->rep) free(w->rep);
    memset(w, 0, sizeof *w);
}

static RunResult run_adapter(NovaHostImage *img, const char *src, size_t src_len, WorkBuffers *w) {
    RunResult res = {0, 0};
    NovaContextV2 ctx = {0};
    if (!nova_context_init_v2(&ctx)) {
        CHECK(0, "nova_context_init_v2 failed");
        res.returned = 1;
        res.runtime_err = NV2_RUNTIME;
        return res;
    }
    uint64_t h_src = nova_borrow_v2(&ctx, (void *)src, src_len, 0);
    uint64_t h_nodes = nova_borrow_v2(&ctx, (void *)w->nodes, WORDS_NODES * 8, 1);
    uint64_t h_scopes = nova_borrow_v2(&ctx, (void *)w->scopes, WORDS_SCOPES * 8, 1);
    uint64_t h_binds = nova_borrow_v2(&ctx, (void *)w->binds, WORDS_BINDS * 8, 1);
    uint64_t h_fields = nova_borrow_v2(&ctx, (void *)w->fields, WORDS_FIELDS * 8, 1);
    uint64_t h_out = nova_borrow_v2(&ctx, (void *)w->out, BYTES_OUT, 1);
    uint64_t h_len = nova_borrow_v2(&ctx, (void *)w->len, 8, 1);
    uint64_t h_rep = nova_borrow_v2(&ctx, (void *)w->rep, WORDS_REPORT * 8, 1);

    uint64_t args[16] = {
        h_src, src_len,
        h_nodes, WORDS_NODES,
        h_scopes, WORDS_SCOPES,
        h_binds, WORDS_BINDS,
        h_fields, WORDS_FIELDS,
        h_out, BYTES_OUT,
        h_len, 1,
        h_rep, WORDS_REPORT
    };

    res.returned = img->entry(&ctx, args, 16);
    res.runtime_err = ctx.error;
    if (!nova_context_destroy_v2(&ctx)) {
        CHECK(0, "nova_context_destroy_v2 failed");
        res.runtime_err = NV2_RUNTIME;
    }
    return res;
}

static RunResult run_probe(NovaHostImage *img, const char *src, size_t src_len,
                          uint64_t count, WorkBuffers *w, uint64_t out_cap, uint64_t rep_cap) {
    RunResult res = {0, 0};
    NovaContextV2 ctx = {0};
    if (!nova_context_init_v2(&ctx)) {
        CHECK(0, "nova_context_init_v2 failed");
        res.returned = 1;
        res.runtime_err = NV2_RUNTIME;
        return res;
    }
    uint64_t h_src = nova_borrow_v2(&ctx, (void *)src, src_len, 0);
    uint64_t h_nodes = nova_borrow_v2(&ctx, (void *)w->nodes, WORDS_NODES * 8, 1);
    uint64_t h_out = nova_borrow_v2(&ctx, (void *)w->out, out_cap, 1);
    uint64_t h_len = nova_borrow_v2(&ctx, (void *)w->len, 8, 1);
    uint64_t h_rep = nova_borrow_v2(&ctx, (void *)w->rep, rep_cap * 8, 1);

    uint64_t args[11] = {
        h_src, src_len,
        h_nodes, WORDS_NODES,
        count,
        h_out, out_cap,
        h_len, 1,
        h_rep, rep_cap
    };

    res.returned = img->entry(&ctx, args, 11);
    res.runtime_err = ctx.error;
    if (!nova_context_destroy_v2(&ctx)) {
        CHECK(0, "nova_context_destroy_v2 failed");
        res.runtime_err = NV2_RUNTIME;
    }
    return res;
}

int main(void) {
    printf("Starting tests_ntasm_nova_source_emit validation...\n");
    NtArtifact adapter_art = {0};
    NovaHostImage adapter_img = {0};
    NtArtifact probe_art = {0};
    NovaHostImage probe_img = {0};
    NtMachineImage *producer = NULL;
    WorkBuffers w = {0};
    unsigned native_executions = 0;
    const unsigned positive_count = sizeof(POSITIVES) / sizeof(POSITIVES[0]);

    const char *adapter_paths[3] = {
        "tests/nova/tests/nova-source-emit-entry.nova",
        "compiler/nova/frontend/nova_language_parse.nova",
        "compiler/nova/frontend/nova_source_emit.nova"
    };
    if (!compile_module_image(adapter_paths, 3, &adapter_art, &adapter_img)) {
        goto cleanup;
    }

    const char *probe_paths[2] = {
        "tests/nova/tests/nova-source-emit-probe-entry.nova",
        "compiler/nova/frontend/nova_source_emit.nova"
    };
    if (!compile_module_image(probe_paths, 2, &probe_art, &probe_img)) {
        goto cleanup;
    }

    NtDiagnostic mach_err = {0};
    producer = nt_machine_open(".", &mach_err);
    CHECK(producer != NULL, "nt_machine_open: E%u %s", mach_err.code, mach_err.message);
    if (!producer) {
        goto cleanup;
    }

    if (!alloc_work_buffers(&w)) {
        CHECK(0, "allocate pipeline working buffers");
        goto cleanup;
    }

    make_dir("../build");
    make_dir("../build/nova-source-emit");

    /* Positive Test Cases */
    for (unsigned i = 0; i < positive_count; i++) {
        cases++;
        const TestCase *tc = &POSITIVES[i];

        /* C-reference typecheck */
        NtFInput ref_input = {"test_ref.nova", (char *)tc->source, strlen(tc->source)};
        NtDiagnostic ref_diag = {0};
        int ref_ok = nova_check_many_v2(&ref_input, 1, &ref_diag);
        CHECK(ref_ok != 0 && ref_diag.code == 0,
              "%s C reference typecheck passed: E%u %s", tc->name, ref_diag.code, ref_diag.message);
        if (!ref_ok) continue;

        memset(w.nodes, 0, WORDS_NODES * sizeof(uint64_t));
        memset(w.scopes, 0, WORDS_SCOPES * sizeof(uint64_t));
        memset(w.binds, 0, WORDS_BINDS * sizeof(uint64_t));
        memset(w.fields, 0, WORDS_FIELDS * sizeof(uint64_t));
        memset(w.out, 0, BYTES_OUT);
        w.len[0] = 0;
        memset(w.rep, 0, WORDS_REPORT * sizeof(uint64_t));

        size_t src_len = strlen(tc->source);
        RunResult r = run_adapter(&adapter_img, tc->source, src_len, &w);
        CHECK(r.runtime_err == 0, "%s adapter runtime error code 0, got=%" PRIu64, tc->name, r.runtime_err);
        CHECK(r.returned == 0, "%s adapter returned success 0, got=%" PRIu64, tc->name, r.returned);
        CHECK(w.rep[9] == 2, "%s adapter phase reached emit (2), got=%" PRIu64, tc->name, w.rep[9]);
        CHECK(w.len[0] > 0 && w.len[0] < BYTES_OUT, "%s emitted valid length=%" PRIu64, tc->name, w.len[0]);

        if (r.runtime_err != 0 || r.returned != 0 || w.len[0] == 0 || w.len[0] >= BYTES_OUT) {
            continue;
        }

        char case_dir[256];
        int cn = snprintf(case_dir, sizeof case_dir, "../build/nova-source-emit/case-%02u", i);
        CHECK(cn > 0 && (size_t)cn < sizeof case_dir, "case_dir snprintf fits buffer");
        if (cn <= 0 || (size_t)cn >= sizeof case_dir) continue;
        make_dir(case_dir);
        persist_file(case_dir, "source.ntasm", w.out, (size_t)w.len[0]);

        NtBuffer pe_out = {0};
        NtMachineReport m_rep = {0};
        int m_ok = nt_machine_pe(producer, (char *)w.out, (size_t)w.len[0], &pe_out, &m_rep);
        CHECK(m_ok != 0 && pe_out.size > 0 && m_rep.runtime == 0,
              "%s NTASM pipeline produced PE: ok=%d size=%zu ret=%" PRIu64 " code=%" PRIu64 " stage=%" PRIu64,
              tc->name, m_ok, pe_out.size, m_rep.returned, m_rep.code, m_rep.stage);

        if (m_ok && pe_out.size > 0) {
            persist_file(case_dir, "binary.efi", pe_out.bytes, pe_out.size);
            uint64_t got = 0;
            char why[256] = {0};
            int r_rc = run_child(pe_out.bytes, pe_out.size, &got, why, sizeof why);
            CHECK(r_rc == 0 && got == tc->want,
                  "%s child exec rc=%d got=%" PRIu64 " want=%" PRIu64 " why=%s",
                  tc->name, r_rc, got, tc->want, why);
            if (r_rc == 0 && got == tc->want) {
                native_executions++;
            }
        }
        if (pe_out.bytes) free(pe_out.bytes);
    }

    /* Negative: Valid Nova containing unsupported mutable local */
    {
        cases++;
        const char *mut_src = "module m;\nfn main()->u64 { let mut x: u64 = 1; return x; }\n";
        size_t mut_len = strlen(mut_src);
        memset(w.nodes, 0, WORDS_NODES * sizeof(uint64_t));
        memset(w.scopes, 0, WORDS_SCOPES * sizeof(uint64_t));
        memset(w.binds, 0, WORDS_BINDS * sizeof(uint64_t));
        memset(w.fields, 0, WORDS_FIELDS * sizeof(uint64_t));
        memset(w.out, 0, BYTES_OUT);
        w.len[0] = 0xAA;
        memset(w.rep, 0, WORDS_REPORT * sizeof(uint64_t));

        RunResult r = run_adapter(&adapter_img, mut_src, mut_len, &w);
        CHECK(r.runtime_err == 0, "mutable local runtime clean");
        CHECK(r.returned == 1, "mutable local returned ERR_UNSUPPORTED (1), got=%" PRIu64, r.returned);
        CHECK(w.rep[9] == 2, "mutable local rejected at phase 2 (emit)");
        CHECK(w.rep[1] == 1, "mutable local report[1] is ERR_UNSUPPORTED (1)");
        CHECK(w.len[0] == 0, "mutable local length is 0");
    }

    /* Negative: Malformed Nova source */
    {
        cases++;
        const char *mal_src = "module m;\nfn main() { return; \n";
        size_t mal_len = strlen(mal_src);
        w.len[0] = 0xBB;
        memset(w.rep, 0, WORDS_REPORT * sizeof(uint64_t));

        RunResult r = run_adapter(&adapter_img, mal_src, mal_len, &w);
        CHECK(r.runtime_err == 0, "malformed source runtime clean");
        CHECK(r.returned != 0, "malformed source returns nonzero parser error");
        CHECK(w.rep[9] == 1, "malformed source rejected at phase 1 (parse)");
        CHECK(w.len[0] == 0, "malformed source length is 0");
    }

    /* Probes: Fresh AST from return42 baseline */
    const char *baseline_src = "module m;\nfn main()->u64 { return 42; }\n";
    size_t base_len = strlen(baseline_src);
    memset(w.nodes, 0, WORDS_NODES * sizeof(uint64_t));
    memset(w.scopes, 0, WORDS_SCOPES * sizeof(uint64_t));
    memset(w.binds, 0, WORDS_BINDS * sizeof(uint64_t));
    memset(w.fields, 0, WORDS_FIELDS * sizeof(uint64_t));
    memset(w.out, 0, BYTES_OUT);
    w.len[0] = 0;
    memset(w.rep, 0, WORDS_REPORT * sizeof(uint64_t));
    RunResult r_base = run_adapter(&adapter_img, baseline_src, base_len, &w);
    CHECK(r_base.runtime_err == 0 && r_base.returned == 0 && w.rep[5] > 0,
          "fresh return42 AST established node_count=%" PRIu64, w.rep[5]);
    if (r_base.runtime_err != 0 || r_base.returned != 0 || w.rep[5] == 0) {
        goto cleanup;
    }
    uint64_t node_count = w.rep[5];

    /* Probe Mutant 1: Root kind 0 -> ERR_DAMAGED_AST (3) */
    {
        cases++;
        uint64_t orig_kind = w.nodes[0];
        w.nodes[0] = 0;
        w.len[0] = 0xCC;
        memset(w.rep, 0, WORDS_REPORT * sizeof(uint64_t));
        RunResult r = run_probe(&probe_img, baseline_src, base_len, node_count, &w, BYTES_OUT, WORDS_REPORT);
        CHECK(r.runtime_err == 0, "probe root kind 0 runtime clean");
        CHECK(r.returned == 3, "probe root kind 0 returns ERR_DAMAGED_AST (3), got=%" PRIu64, r.returned);
        CHECK(w.len[0] == 0, "probe root kind 0 length is 0");
        w.nodes[0] = orig_kind;
    }

    /* Probe Mutant 2: Root first_child = count + 1 -> ERR_DAMAGED_AST (3) */
    {
        cases++;
        uint64_t orig_fc = w.nodes[2];
        w.nodes[2] = node_count + 1;
        w.len[0] = 0xDD;
        memset(w.rep, 0, WORDS_REPORT * sizeof(uint64_t));
        RunResult r = run_probe(&probe_img, baseline_src, base_len, node_count, &w, BYTES_OUT, WORDS_REPORT);
        CHECK(r.runtime_err == 0, "probe oob child runtime clean");
        CHECK(r.returned == 3, "probe oob child returns ERR_DAMAGED_AST (3), got=%" PRIu64, r.returned);
        CHECK(w.len[0] == 0, "probe oob child length is 0");
        w.nodes[2] = orig_fc;
    }

    /* Probe Mutant 3: Short out capacity (cap 5) -> ERR_BOUND (2) and sentinel intact */
    {
        cases++;
        w.out[5] = 0xEE;
        w.len[0] = 0xFF;
        memset(w.rep, 0, WORDS_REPORT * sizeof(uint64_t));
        RunResult r = run_probe(&probe_img, baseline_src, base_len, node_count, &w, 5, WORDS_REPORT);
        CHECK(r.runtime_err == 0, "probe short out capacity runtime clean");
        CHECK(r.returned == 2, "probe short out capacity returns ERR_BOUND (2), got=%" PRIu64, r.returned);
        CHECK(w.len[0] == 0, "probe short out capacity length is 0");
        CHECK(w.out[5] == 0xEE, "probe short out capacity sentinel intact");
    }

    /* Probe Mutant 4: Short report capacity (cap 3) -> ERR_BOUND (2) */
    {
        cases++;
        w.len[0] = 0x42;
        RunResult r = run_probe(&probe_img, baseline_src, base_len, node_count, &w, BYTES_OUT, 3);
        CHECK(r.runtime_err == 0, "probe short report capacity runtime clean");
        CHECK(r.returned == 2, "probe short report capacity returns ERR_BOUND (2), got=%" PRIu64, r.returned);
        CHECK(w.len[0] == 0, "probe short report capacity length is 0");
    }

    /* Probes on reachable K_UNARY (24) from real compiled unary source */
    {
        const char *u_src = "module m;\nfn main()->u64 { return ~0; }\n";
        size_t u_len = strlen(u_src);
        memset(w.nodes, 0, WORDS_NODES * sizeof(uint64_t));
        memset(w.scopes, 0, WORDS_SCOPES * sizeof(uint64_t));
        memset(w.binds, 0, WORDS_BINDS * sizeof(uint64_t));
        memset(w.fields, 0, WORDS_FIELDS * sizeof(uint64_t));
        memset(w.out, 0, BYTES_OUT);
        w.len[0] = 0;
        memset(w.rep, 0, WORDS_REPORT * sizeof(uint64_t));

        RunResult r_u = run_adapter(&adapter_img, u_src, u_len, &w);
        if (r_u.runtime_err == 0 && r_u.returned == 0 && w.rep[5] > 0) {
            uint64_t u_count = w.rep[5];
            uint64_t target_u = 0;
            for (uint64_t i = 1; i <= u_count; i++) {
                if (w.nodes[(i - 1) * 16 + 0] == 24) { /* K_UNARY */
                    target_u = i;
                    break;
                }
            }
            CHECK(target_u != 0, "located reachable K_UNARY (24) in baseline unary AST");
            if (target_u != 0) {
                /* Mutant 5: reachable K_UNARY with unknown operator token -> ERR_UNSUPPORTED (1) */
                cases++;
                uint64_t orig_aux = w.nodes[(target_u - 1) * 16 + 13];
                w.nodes[(target_u - 1) * 16 + 13] = 63; /* '?' unknown operator */
                w.len[0] = 0x55;
                memset(w.rep, 0, WORDS_REPORT * sizeof(uint64_t));
                RunResult r5 = run_probe(&probe_img, u_src, u_len, u_count, &w, BYTES_OUT, WORDS_REPORT);
                CHECK(r5.runtime_err == 0, "probe unary unknown op runtime clean");
                CHECK(r5.returned == 1, "probe unary unknown op returns ERR_UNSUPPORTED (1), got=%" PRIu64, r5.returned);
                CHECK(w.len[0] == 0, "probe unary unknown op length is 0");
                w.nodes[(target_u - 1) * 16 + 13] = orig_aux;

                /* Mutant 6: reachable K_UNARY with distinct last_child (two children) -> ERR_DAMAGED_AST (3) */
                cases++;
                uint64_t orig_lc = w.nodes[(target_u - 1) * 16 + 3];
                w.nodes[(target_u - 1) * 16 + 3] = target_u; /* distinct invalid child pointer */
                w.len[0] = 0x66;
                memset(w.rep, 0, WORDS_REPORT * sizeof(uint64_t));
                RunResult r6 = run_probe(&probe_img, u_src, u_len, u_count, &w, BYTES_OUT, WORDS_REPORT);
                CHECK(r6.runtime_err == 0, "probe unary broken arity runtime clean");
                CHECK(r6.returned == 3, "probe unary broken arity returns ERR_DAMAGED_AST (3), got=%" PRIu64, r6.returned);
                CHECK(w.len[0] == 0, "probe unary broken arity length is 0");
                w.nodes[(target_u - 1) * 16 + 3] = orig_lc;
            }
        } else {
            CHECK(0, "unary baseline compile failed, probes guarded until producer implements unary");
        }
    }
cleanup:
    CHECK(native_executions == positive_count,
          "native execution parity: executed=%u expected=%u", native_executions, positive_count);

    printf("NTASM_NOVA_SOURCE_EMIT checks=%u failures=%u cases=%u native=%u\n",
           checks, failures, cases, native_executions);
    if (producer) nt_machine_close(producer);
    if (adapter_img.entry) nova_host_unmap(&adapter_img);
    nt_artifact_free(&adapter_art);
    if (probe_img.entry) nova_host_unmap(&probe_img);
    nt_artifact_free(&probe_art);
    free_work_buffers(&w);

    return failures ? 1 : 0;
}
