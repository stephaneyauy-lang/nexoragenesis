/* BOOTSTRAP_C_TEST — A7.01, schéma NTIR (coordinateur Claude, 4 octobre 2026). CANDIDAT.
 * Le document de départ est le brouillon de la session A7 (spec/formats/ntir-v0.md, 13 h 44), remis en tableaux lisibles
 * par cette porte.
 *
 * Deux lectures du même fait, désaccordées exprès :
 *   - le DOCUMENT spec/formats/ntir-v0.md, lu par ses tableaux ;
 *   - le MODULE ntir.nova, interrogé par ntir-schema-entry.nova (constantes exportées, kind_at/kind_text,
 *     header_text), puis jugé sur des IMAGES réellement produites (parse -> ntir.build -> verify ->
 *     serialize). Chaque ligne sérialisée est relue CHAMP PAR CHAMP selon l'ordre et les séparateurs du
 *     document, jusqu'à la fin de ligne ; les règles de refus du document sont rejouées en ABÎMANT des
 *     images réelles et en exigeant le code écrit.
 * Usage, depuis la racine du dépôt : NTIR_DOC=… NTIR_ENTRY=… ntir_schema [--dump] SOURCE.ntasm …
 * Bannière : NTASM_NOVA_NTIR_SCHEMA checks=N failures=N cases=N */
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../../compiler/c/nova/frontend/nova.h"
#include "../../../compiler/c/nova/runtime/run_host.h"

static unsigned checks, failures, cases;
#define CHECK(c, ...)                                                      \
    do {                                                                   \
        checks++;                                                          \
        if (!(c)) {                                                        \
            failures++;                                                    \
            fprintf(stderr, "FAIL ");                                      \
            fprintf(stderr, __VA_ARGS__);                                  \
            fputc('\n', stderr);                                           \
        }                                                                  \
    } while (0)

static char *loadf(const char *p, size_t *n)
{
    FILE *f = fopen(p, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long l = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *b = malloc(l > 0 ? (size_t)l + 1 : 1);
    if (!b || fread(b, 1, (size_t)l, f) != (size_t)l) { fclose(f); free(b); return NULL; }
    fclose(f);
    b[l] = 0;
    *n = (size_t)l;
    return b;
}

static const char *MODULES[] = {"compiler/nova/formats/ntir/ntir.nova", "compiler/nova/frontend/parser.nova",
                                "compiler/nova/frontend/lexer.nova", "compiler/nova/frontend/ast.nova",
                                "compiler/nova/analysis/types/register_widths.nova"};
#define NMOD (sizeof MODULES / sizeof *MODULES)
static NovaHostImage IMG;
enum { TEXTCAP = 1 << 20, WORDS = 1 << 18 };
static uint8_t TEXT[TEXTCAP];
static uint64_t UNUSED[8], OUT[WORDS], REPORT[64], LEN[1];

static uint64_t ask(const char *source, uint64_t mode, uint64_t index)
{
    static char none[1];
    NovaContextV2 c = {0};
    uint64_t a[14];
    size_t sn = source ? strlen(source) : 0;
    memset(REPORT, 0, sizeof REPORT);
    LEN[0] = 0;
    nova_context_init_v2(&c);
    a[0] = nova_borrow_v2(&c, source ? (void *)source : none, sn, 0); a[1] = sn;
    a[2] = mode; a[3] = index;
    a[4] = nova_borrow_v2(&c, UNUSED, sizeof UNUSED, 1); a[5] = 8;
    a[6] = nova_borrow_v2(&c, OUT, sizeof OUT, 1); a[7] = WORDS;
    a[8] = nova_borrow_v2(&c, TEXT, TEXTCAP, 1); a[9] = TEXTCAP;
    a[10] = nova_borrow_v2(&c, LEN, sizeof LEN, 1); a[11] = 1;
    a[12] = nova_borrow_v2(&c, REPORT, sizeof REPORT, 1); a[13] = 64;
    uint64_t code = IMG.entry(&c, a, 14);
    CHECK(c.error == 0, "runtime clean (mode %" PRIu64 " index %" PRIu64 ", error %" PRIu64 ")", mode, index, c.error);
    nova_context_destroy_v2(&c);
    cases++;
    return code;
}
static const char *text_of(void)
{
    static char s[4096];
    size_t n = LEN[0] < sizeof s - 1 ? (size_t)LEN[0] : sizeof s - 1;
    memcpy(s, TEXT, n);
    s[n] = 0;
    return s;
}

enum { T_CONST, T_HEADER, T_NODE, T_KIND, T_SER_HEAD, T_SER_NODE, T_REFUSAL, T_COUNT };
static const char *HEADINGS[T_COUNT] = {"## 2.", "## 3.", "## 4.", "## 5.", "## 6.", "## 7.", "## 8."};
typedef struct { char c[4][128]; } Row;
static Row ROWS[T_COUNT][128];
static unsigned NROWS[T_COUNT];

static void strip(char *s)
{
    char *b = s;
    while (*b == ' ' || *b == '`') b++;
    memmove(s, b, strlen(b) + 1);
    size_t l = strlen(s);
    while (l && (s[l - 1] == ' ' || s[l - 1] == '`')) s[--l] = 0;
}
static void parse_doc(const char *doc)
{
    int table = -1, header_seen[T_COUNT] = {0};
    const char *p = doc;
    while (*p) {
        const char *e = strchr(p, '\n');
        size_t l = e ? (size_t)(e - p) : strlen(p);
        char line[1024];
        snprintf(line, sizeof line, "%.*s", (int)(l < 1023 ? l : 1023), p);
        if (l && l < 1024 && line[l - 1] == '\r') line[l - 1] = 0;
        if (!strncmp(line, "## ", 3)) {
            table = -1;
            for (int t = 0; t < T_COUNT; t++)
                if (!strncmp(line, HEADINGS[t], strlen(HEADINGS[t]))) table = t;
        } else if (table >= 0 && line[0] == '|' && !strstr(line, "---") && NROWS[table] < 128) {
            Row r;
            memset(&r, 0, sizeof r);
            char *q = line + 1;
            int k = 0;
            while (k < 4 && *q) {
                char *bar = strchr(q, '|');
                if (!bar) break;
                *bar = 0;
                size_t ql = strlen(q) < 127 ? strlen(q) : 127;
                memcpy(r.c[k], q, ql);
                r.c[k][ql] = 0;
                strip(r.c[k]);
                k++;
                q = bar + 1;
            }
            if (!header_seen[table]) header_seen[table] = 1;
            else ROWS[table][NROWS[table]++] = r;
        }
        p = e ? e + 1 : p + l;
    }
}
static const Row *find(int t, int col, const char *key)
{
    for (unsigned i = 0; i < NROWS[t]; i++) if (!strcmp(ROWS[t][i].c[col], key)) return &ROWS[t][i];
    return NULL;
}
static uint64_t num(const char *s) { return strtoull(s, NULL, 0); }
static int header_word(const char *field)
{
    const Row *r = find(T_HEADER, 1, field);
    return r ? (int)num(r->c[0]) : -1;
}

static const char *CONST_NAMES[20] = {"FORMAT_MAJOR", "FORMAT_MINOR", "KIND_BASE", "HEADER_WORDS", "NODE_WORDS",
                                      "KIND_COUNT", "CLASS_NONE", "CLASS_MEMORY", "CLASS_IMMEDIATE",
                                      "CLASS_RELOCATABLE", "CLASS_CONTROL", "CLASS_LABEL", "CLASS_LIMIT",
                                      "FAMILY_LIMIT", "WIDTH_MEMORY", "WIDTH_POINTER", "SIGNED_UNSIGNED",
                                      "SIGNED_SIGNED", "SIGNED_NONE", "E_TYPE_REFUSED"};

/* séparateur du document -> texte attendu : SP = un espace ; un jeton finissant par '=' est précédé d'un espace */
static void sep_text(const char *tok, char *out, size_t n)
{
    size_t l = strlen(tok);
    if (!strcmp(tok, "SP")) snprintf(out, n, " ");
    else if (l && tok[l - 1] == '=') snprintf(out, n, " %s", tok);
    else snprintf(out, n, "%s", tok);
}


/* Corpus par défaut quand la porte est lancée SANS source, comme ngbuild.sh le fait : toutes les sources
 * de examples/ntasm-v0/c-bootstrap/, triées. Une porte de routine rejoue ainsi les preuves de sérialisation
 * (remarque de Codex, 4 octobre 2026). */
#include <dirent.h>
static int cmpstr(const void *a, const void *b) { return strcmp(*(char *const *)a, *(char *const *)b); }
static int default_corpus(char **out, int cap)
{
    const char *dir = "examples/ntasm-v0/c-bootstrap";
    DIR *d = opendir(dir);
    int n = 0;
    for (struct dirent *e; d && (e = readdir(d)) && n < cap;) {
        size_t l = strlen(e->d_name);
        if (l > 6 && !strcmp(e->d_name + l - 6, ".ntasm")) {
            out[n] = malloc(strlen(dir) + l + 2);
            sprintf(out[n], "%s/%s", dir, e->d_name);
            n++;
        }
    }
    if (d) closedir(d);
    qsort(out, (size_t)n, sizeof *out, cmpstr);
    return n;
}

int main(int argc, char **argv)
{
    int dump = argc > 1 && !strcmp(argv[1], "--dump");
    char *corpus[256];
    int ncorpus = 0;
    for (int i = 1 + dump; i < argc && ncorpus < 256; i++) corpus[ncorpus++] = argv[i];
    int defaulted = 0;
    if (ncorpus == 0) { ncorpus = default_corpus(corpus, 256); defaulted = 1; }
    printf("CORPUS sources=%d origin=%s\n", ncorpus, defaulted ? "default examples/ntasm-v0/c-bootstrap" : "argv");
    const char *entry = getenv("NTIR_ENTRY") ? getenv("NTIR_ENTRY") : "tests/nova/tests/ntir-schema-entry.nova";
    const char *docp = getenv("NTIR_DOC") ? getenv("NTIR_DOC") : "spec/formats/ntir-v0.md";
    NtFInput in[NMOD + 1];
    char *src[NMOD + 1];
    size_t n = 0;
    src[0] = loadf(entry, &n);
    CHECK(src[0] != NULL, "entry %s readable", entry);
    if (!src[0]) return 1;
    in[0] = (NtFInput){entry, src[0], n};
    for (unsigned i = 0; i < NMOD; i++) {
        src[i + 1] = loadf(MODULES[i], &n);
        CHECK(src[i + 1] != NULL, "module %s readable", MODULES[i]);
        if (!src[i + 1]) return 1;
        in[i + 1] = (NtFInput){MODULES[i], src[i + 1], n};
    }
    NtArtifact art = {0};
    int ok = nova_compile_many_v2(in, NMOD + 1, &art);
    CHECK(ok, "modules compile: E%u %zu:%zu %s", art.error.code, art.error.line, art.error.column, art.error.message);
    CHECK(ok && nova_host_map(&art, &IMG) && IMG.entry, "image maps");
    if (!IMG.entry) return 1;

    uint64_t consts[20];
    CHECK(ask(NULL, 0, 0) == 0, "mode 0 answers");
    for (int i = 0; i < 20; i++) consts[i] = REPORT[i];
    uint64_t KB = consts[2], HW = consts[3], NW = consts[4], KC = consts[5];
    CHECK(ask(NULL, 3, 0) == 0, "mode 3 answers");
    char tag[64];
    snprintf(tag, sizeof tag, "%s", text_of());
    if (dump) {
        printf("CONST header_text %s\n", tag);
        for (int i = 0; i < 20; i++) printf("CONST %s %" PRIu64 "\n", CONST_NAMES[i], consts[i]);
        for (uint64_t i = 1; i <= KC; i++) { ask(NULL, 2, i); printf("KIND %" PRIu64 " %" PRIu64 " %s\n", i, REPORT[0], text_of()); }
    }

    size_t dn = 0;
    char *doc = loadf(docp, &dn);
    CHECK(doc != NULL, "document %s readable", docp);
    if (doc) parse_doc(doc);
    for (int t = 0; t < T_COUNT; t++) CHECK(NROWS[t] > 0, "document table %s has rows", HEADINGS[t]);

    const Row *r = find(T_CONST, 0, "header_text");
    CHECK(r && !strcmp(r->c[1], tag), "header_text: document %s, module %s", r ? r->c[1] : "ABSENT", tag);
    for (int i = 0; i < 20; i++) {
        r = find(T_CONST, 0, CONST_NAMES[i]);
        CHECK(r && num(r->c[1]) == consts[i], "constant %s: document %s, module %" PRIu64, CONST_NAMES[i],
              r ? r->c[1] : "ABSENT", consts[i]);
    }
    CHECK(NROWS[T_HEADER] == HW, "header table rows %u, module HEADER_WORDS %" PRIu64, NROWS[T_HEADER], HW);
    CHECK(NROWS[T_NODE] == NW, "node table rows %u, module NODE_WORDS %" PRIu64, NROWS[T_NODE], NW);
    for (uint64_t w = 0; w < HW; w++) { char k[24]; snprintf(k, sizeof k, "%" PRIu64, w); CHECK(find(T_HEADER, 0, k), "header word %s documented", k); }
    for (uint64_t w = 0; w < NW; w++) { char k[24]; snprintf(k, sizeof k, "%" PRIu64, w); CHECK(find(T_NODE, 0, k), "node word %s documented", k); }
    CHECK(NROWS[T_KIND] == KC, "kind table rows %u, module KIND_COUNT %" PRIu64, NROWS[T_KIND], KC);
    for (uint64_t i = 1; i <= KC; i++) {
        ask(NULL, 2, i);
        char key[24];
        snprintf(key, sizeof key, "%" PRIu64, REPORT[0]);
        r = find(T_KIND, 0, key);
        CHECK(r && !strcmp(r->c[1], text_of()), "kind %s: document %s, module %s", key, r ? r->c[1] : "ABSENT", text_of());
        CHECK(REPORT[0] == KB + i - 1, "kind_at(%" PRIu64 ") = KIND_BASE + %" PRIu64, i, i - 1);
    }
    /* les mots d'en-tête que les règles nomment */
    int w_magic = header_word("magic"), w_major = header_word("major"), w_minor = header_word("minor"),
        w_count = header_word("node_count"), w_stride = header_word("stride"), w_ast = header_word("ast_node_count");
    CHECK(w_magic >= 0 && w_major >= 0 && w_minor >= 0 && w_count >= 0 && w_stride >= 0 && w_ast >= 0,
          "the header table names magic, major, minor, node_count, stride and ast_node_count");
    const Row *magic = find(T_CONST, 0, "magic");
    CHECK(magic != NULL, "document names the magic value");

    unsigned accepted = 0, refused = 0, kinds_seen = 0, refusal_runs = 0;
    int seen[256] = {0};
    for (int s = 0; s < ncorpus; s++) {
        size_t sn = 0;
        char *source = loadf(corpus[s], &sn);
        CHECK(source != NULL, "source %s readable", corpus[s]);
        if (!source) continue;
        uint64_t code = ask(source, 4, 0);
        if (code != 0) {
            refused++;
            printf("NTIR_IMAGE %s refused=%" PRIu64 "\n", corpus[s], code);
            free(source);
            continue;
        }
        accepted++;
        uint64_t count = w_count >= 0 ? OUT[w_count] : 0;
        CHECK(magic && w_magic >= 0 && OUT[w_magic] == num(magic->c[1]), "%s: magic word 0x%" PRIx64, corpus[s], w_magic >= 0 ? OUT[w_magic] : 0);
        CHECK(w_major >= 0 && w_minor >= 0 && OUT[w_major] == consts[0] && OUT[w_minor] == consts[1], "%s: version words", corpus[s]);
        CHECK(w_stride >= 0 && OUT[w_stride] == NW, "%s: stride word holds NODE_WORDS", corpus[s]);
        CHECK(w_ast >= 0 && OUT[w_ast] == count, "%s: ast_node_count equals node_count", corpus[s]);
        char *txt = calloc(1, (size_t)LEN[0] + 1);
        memcpy(txt, TEXT, (size_t)LEN[0]);
        char *nl = strchr(txt, '\n');
        CHECK(nl != NULL, "%s: serialization has a header line", corpus[s]);
        if (!nl) { free(txt); free(source); continue; }
        *nl = 0;
        CHECK(!strncmp(txt, tag, strlen(tag)), "%s: serialization begins with %s", corpus[s], tag);
        for (unsigned i = 0; i < NROWS[T_SER_HEAD]; i++) {
            char needle[64];
            snprintf(needle, sizeof needle, " %s", ROWS[T_SER_HEAD][i].c[0]);
            const char *at = strstr(txt, needle);
            uint64_t w = num(ROWS[T_SER_HEAD][i].c[1]);
            CHECK(at && w < HW && strtoull(at + strlen(needle), NULL, 10) == OUT[w], "%s: header label %s holds word %" PRIu64,
                  corpus[s], ROWS[T_SER_HEAD][i].c[0], w);
        }
        char *line = nl + 1;
        uint64_t id = 0;
        while (*line) {
            char *e = strchr(line, '\n');
            if (e) *e = 0;
            id++;
            char *pos = line, *end;
            uint64_t v = strtoull(pos, &end, 10);
            CHECK(end != pos && v == id, "%s: node line %" PRIu64 " starts with its id", corpus[s], id);
            pos = end;
            const uint64_t *rec = OUT + HW + (id - 1) * NW;
            int line_ok = 1;
            for (unsigned i = 0; i < NROWS[T_SER_NODE] && line_ok; i++) {
                char sep[32];
                sep_text(ROWS[T_SER_NODE][i].c[1], sep, sizeof sep);
                uint64_t w = num(ROWS[T_SER_NODE][i].c[2]);
                int sep_ok = !strncmp(pos, sep, strlen(sep));
                if (sep_ok) pos += strlen(sep);
                v = strtoull(pos, &end, 10);
                int val_ok = sep_ok && end != pos && w < NW && v == rec[w];
                CHECK(val_ok, "%s node %" PRIu64 ": field %u (separator '%s', word %" PRIu64 ") at \"%.20s\"", corpus[s], id, i + 1, sep, w, pos);
                if (!val_ok) line_ok = 0;
                pos = end;
            }
            CHECK(!line_ok || *pos == 0, "%s node %" PRIu64 ": nothing after the last documented field (\"%.20s\")", corpus[s], id, pos);
            char key[24];
            snprintf(key, sizeof key, "%" PRIu64, rec[0]);
            CHECK(find(T_KIND, 0, key) != NULL, "%s node %" PRIu64 ": kind %s is in the document", corpus[s], id, key);
            if (rec[0] >= KB && rec[0] < KB + KC && !seen[rec[0] - KB]) { seen[rec[0] - KB] = 1; kinds_seen++; }
            if (!e) break;
            line = e + 1;
        }
        CHECK(id == count, "%s: %" PRIu64 " node lines, node_count %" PRIu64, corpus[s], id, count);
        /* les refus du document, rejoués en abîmant cette image réelle */
        static uint64_t backup[WORDS];
        memcpy(backup, OUT, sizeof OUT);
        for (unsigned i = 0; i < NROWS[T_REFUSAL]; i++) {
            /* colonne « mot » : un mot d'en-tête « k », ou un mot de nœud « N<id>.<k> » */
            const char *where = ROWS[T_REFUSAL][i].c[1];
            uint64_t want = num(ROWS[T_REFUSAL][i].c[0]), val = num(ROWS[T_REFUSAL][i].c[2]), w;
            if (where[0] == 'N') {
                char *dot = NULL;
                uint64_t node = strtoull(where + 1, &dot, 10), k = dot && *dot == '.' ? strtoull(dot + 1, NULL, 10) : NW;
                w = node >= 1 && node <= count && k < NW ? HW + (node - 1) * NW + k : WORDS;
            } else {
                w = num(where);
                if (w >= HW) w = WORDS;
            }
            memcpy(OUT, backup, sizeof OUT);
            CHECK(w < WORDS && OUT[w] != val, "%s refusal row %u (%s): the damage names a word and changes it", corpus[s], i + 1, where);
            if (w < WORDS) OUT[w] = val;
            uint64_t got = ask(NULL, 5, 0);
            CHECK(got == want, "%s refusal row %u: %s set to %" PRIu64 " -> verify %" PRIu64 ", document %" PRIu64,
                  corpus[s], i + 1, where, val, got, want);
            refusal_runs++;
        }
        memcpy(OUT, backup, sizeof OUT);
        CHECK(ask(NULL, 5, 0) == 0, "%s: the restored image verifies clean", corpus[s]);
        printf("NTIR_IMAGE %s accepted nodes=%" PRIu64 "\n", corpus[s], count);
        free(txt);
        free(source);
    }
    CHECK(accepted > 0, "PROOF_INVALID: no source produced a verified image");
    CHECK(refusal_runs > 0, "PROOF_INVALID: no refusal row was replayed");
    printf("NTIR_KINDS_SEEN %u of %" PRIu64 " (printed, not required)\n", kinds_seen, KC);
    printf("NTASM_NOVA_NTIR_SCHEMA checks=%u failures=%u cases=%u images_accepted=%u images_refused=%u refusal_runs=%u\n",
           checks, failures, cases, accepted, refused, refusal_runs);
    free(doc);
    nova_host_unmap(&IMG);
    nt_artifact_free(&art);
    for (unsigned i = 0; i <= NMOD; i++) free(src[i]);
    if (defaulted) for (int i = 0; i < ncorpus; i++) free(corpus[i]);
    return failures != 0;
}
