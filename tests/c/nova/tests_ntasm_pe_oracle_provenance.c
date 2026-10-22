/* tests_ntasm_pe_oracle_provenance.c -- THE DOCUMENT IS THE SPECIFICATION,
 * AND THE TREE IS THE WITNESS, AND THEY ARE NOT ALLOWED TO AGREE BY ACCIDENT.
 *
 * WHAT IS BEING CHECKED. compiler/c/nova/pe/pe_oracle.c is not a
 * second implementation of the PE writer: it is the TAIL of
 * compiler/c/ntasm/frontend/ntasm.c, copied, plus one forwarding function. The
 * document that SAYS SO is compiler/c/nova/pe_oracle-source.json.
 * A document nobody re-derives is a comment. So this gate believes none of
 * it: every field is recomputed from the bytes on disk, and the document is
 * only ever the second term of a comparison.
 *
 * WHY THE WAITING QUANTITY MAY COME FROM THE DOCUMENT HERE. The rule this
 * project follows is that a check whose expected value is derived from the
 * module under test proves only self-consistency. The document is not the
 * module under test: it is the ORACLE'S MANIFEST, it is written by a
 * different act than the copy it describes, and falsifying it is a legal and
 * meaningful negative control. What the rule forbids -- an expected value that
 * moves because the produced quantity moved -- cannot happen here, because
 * the document is never an OUTPUT of this gate. Hence four negative controls
 * are not optional decoration: without them this file could not tell a
 * working check from a check that always passes.
 *
 * TWO CLASSES OF WRONG, TWO TOKENS. A field that is FALSE IN THE DOCUMENT is
 * PROV-JSON-*. A field that is FALSE IN THE TREE (the document is right, the
 * bytes moved) is PROV-TREE-*. Collapsing them into one token would make the
 * log useless for the only question a reader has after a red run: which side
 * do I go fix?
 *
 *   PROV-JSON-SOURCE-PATH    source is absolute, or carries '\' or ':'.
 *                            This is the defect that was corrected in this
 *                            document on 2026-10-04: it used to say
 *                            "C:\NexoraGenesis\...", a path that cannot be
 *                            resolved by anything that is not that one
 *                            machine. Control (c) replays it.
 *   PROV-JSON-SHA            recomputed sha256 of source != the declared one
 *   PROV-JSON-SUFFIX-OFFSET  the anchor, LOCATED in source, is not at
 *                            suffix_offset. Located, not read: the offset is
 *                            never taken on trust, or a wrong offset would
 *                            only ever show up as a byte mismatch and the
 *                            field that is actually wrong would stay silent.
 *   PROV-JSON-EXTRA-FUNCTION what follows the copied suffix in the oracle is
 *                            not exactly the declared function and nothing else
 *   PROV-JSON-LAYOUT-PATH    layout_source or layout_copy is not repo-relative
 *   PROV-JSON-LAYOUT-SHA     sha256(layout_source) != layout_sha256
 *   PROV-JSON-PARSE          a declared field is absent, or is not the kind of
 *                            value the document says it is (a string where a
 *                            number belongs, an escape this reader refuses).
 *                            A reader that guesses at a malformed document is
 *                            a reader whose green run means nothing, so this
 *                            one refuses.
 *   PROV-TREE-SOURCE-MISSING the named source file is not there
 *   PROV-TREE-ANCHOR-UNIQUE  the anchor occurs != 1 time in source
 *   PROV-TREE-SUFFIX         the oracle's bytes at its anchor are NOT the
 *                            source's bytes from its anchor, byte for byte
 *   PROV-TREE-ORACLE-MISSING / PROV-TREE-ORACLE-ANCHOR-UNIQUE
 *   PROV-TREE-LAYOUT         layout_source and layout_copy are not equal
 *   PROV-TREE-LAYOUT-MISSING
 *   PROV-JSON-MISSING-KEY    a declared key is absent
 *   PROV-JSON-DUPLICATE-KEY  a declared key appears more than once; a
 *                            document with two answers to one question has no
 *                            answer, and a parser that takes the first one is
 *                            not reading a document
 *   PROV-JSON-UNREADABLE     the document itself could not be read
 *   PROV-SHA-SELFTEST        the built-in sha256 fails a known-answer vector.
 *                            Without it, a digest that returned a constant
 *                            would make every digest comparison pass forever
 *                            and PROV-JSON-SHA would be a decoration.
 *
 * WHAT THIS DOES NOT LOOK AT, printed on every run so a green banner cannot
 * be over-read: the oracle's PREFACE (the 294 bytes before its anchor: the
 * comment, the includes, the NtArtifact/#define block) is not compared with
 * anything -- only the suffix is; the forwarded function's BODY is not
 * semantically verified, only its exact spelling as declared; neither file is
 * compiled or linked here, so this says nothing about whether either one
 * builds; nothing checks that ngbuild.sh, or any other driver, READS this
 * document, so a document read by nobody and a document read by everybody
 * look identical here; and nothing checks the two PE layout headers against
 * ntasm.c itself, only against each other and against their declared digest.
 *
 * ARGS.  --json <path>    document, default tests/c/nova/pe_oracle-source.json
 *         --oracle <path>  oracle,    default compiler/c/nova/pe/pe_oracle.c
 *         --root <path>    repo root; default: deduced from argv[0] by walking
 *                          up for compiler/c/nova/, else "."
 *                          (drivers run gates with cwd = repo root).
 * The defaults are the tree, and a negative control names a different file.
 */
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_DOC   (64u * 1024u)
#define MAX_FILE  (16u * 1024u * 1024u)
#define PATHCAP   1024

static unsigned checks, failures, skipped;

/* ============================ sha256 (FIPS 180-4) ============================
 * Self-contained on purpose: this tree has no digest helper to call, and a
 * gate that reached outside its own translation unit for one would be a new
 * convention rather than a reuse. Known-answer tested at run time -- see
 * PROV-SHA-SELFTEST. */
typedef struct { uint32_t h[8]; } Sha256;

static uint32_t sha_ror(uint32_t x, int r) { return (x >> r) | (x << (32 - r)); }

static void sha256_block(Sha256 *s, const unsigned char *p)
{
    static const uint32_t K[64] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
    uint32_t w[64], a, b, c, d, e, f, g, h, t1, t2;
    int i;
    for (i = 0; i < 16; i++)
        w[i] = (uint32_t)p[i*4] << 24 | (uint32_t)p[i*4+1] << 16 |
               (uint32_t)p[i*4+2] << 8 | (uint32_t)p[i*4+3];
    for (; i < 64; i++) {
        uint32_t s0 = sha_ror(w[i-15],7) ^ sha_ror(w[i-15],18) ^ (w[i-15] >> 3);
        uint32_t s1 = sha_ror(w[i-2],17) ^ sha_ror(w[i-2],19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a = s->h[0]; b = s->h[1]; c = s->h[2]; d = s->h[3];
    e = s->h[4]; f = s->h[5]; g = s->h[6]; h = s->h[7];
    for (i = 0; i < 64; i++) {
        uint32_t S1 = sha_ror(e,6) ^ sha_ror(e,11) ^ sha_ror(e,25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t S0 = sha_ror(a,2) ^ sha_ror(a,13) ^ sha_ror(a,22);
        uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
        t1 = h + S1 + ch + K[i] + w[i];
        t2 = S0 + mj;
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    s->h[0] += a; s->h[1] += b; s->h[2] += c; s->h[3] += d;
    s->h[4] += e; s->h[5] += f; s->h[6] += g; s->h[7] += h;
}

static void sha256(const unsigned char *p, size_t n, char *out /* 65 */)
{
    static const uint32_t iv[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                                   0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    Sha256 s;
    unsigned char tail[128];
    size_t i, r, pad;
    uint64_t bits = (uint64_t)n * 8;
    memcpy(s.h, iv, sizeof iv);
    for (i = 0; i + 64 <= n; i += 64) sha256_block(&s, p + i);
    r = n - i;
    memcpy(tail, p + i, r);
    tail[r] = 0x80;
    pad = (r < 56) ? 64 : 128;
    memset(tail + r + 1, 0, pad - r - 1 - 8);
    for (int k = 0; k < 8; k++) tail[pad-1-k] = (unsigned char)(bits >> (k*8));
    sha256_block(&s, tail);
    if (pad == 128) sha256_block(&s, tail + 64);
    for (i = 0; i < 8; i++) sprintf(out + i*8, "%08x", s.h[i]);
    out[64] = 0;
}

/* ================================ byte plumbing ============================ */

typedef struct { unsigned char *p; size_t n; int ok; } Blob;

static int read_file(const char *path, Blob *b, size_t cap)
{
    FILE *f = fopen(path, "rb");
    long len;
    unsigned char *buf;
    b->p = NULL; b->n = 0; b->ok = 0;
    if (!f) return -1;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    len = ftell(f);
    if (len < 0 || (unsigned long)len > cap) { fclose(f); return -1; }
    rewind(f);
    buf = (unsigned char *)malloc((size_t)len + 1u);
    if (!buf) { fclose(f); return -1; }
    if (len > 0 && fread(buf, 1, (size_t)len, f) != (size_t)len) {
        free(buf); fclose(f); return -1;
    }
    buf[len] = 0;
    fclose(f);
    b->p = buf; b->n = (size_t)len; b->ok = 1;
    return 0;
}

static int file_exists(const char *p)
{
    FILE *f = fopen(p, "rb");
    if (!f) return 0;
    fclose(f);
    return 1;
}

/* Count occurrences of needle in hay, and record the offset of the first one
 * in *first. -1 in *first means "not present". */
static size_t count_occ(const unsigned char *hay, size_t n,
                        const char *needle, long *first)
{
    size_t nl = strlen(needle), i, hits = 0;
    long fi = -1;
    if (nl == 0 || n < nl) { if (first) *first = -1; return 0; }
    for (i = 0; i + nl <= n; i++) {
        if (memcmp(hay + i, needle, nl) == 0) {
            if (fi < 0) fi = (long)i;
            hits++;
        }
    }
    if (first) *first = fi;
    return hits;
}

static void path_join(char *dst, size_t cap, const char *root, const char *rel)
{
    size_t i = 0, n;
    if (rel[0] == '/' || rel[0] == '\\' || !root || !root[0]) {
        n = strlen(rel);
        if (n > cap - 1) n = cap - 1;
        memcpy(dst, rel, n);
        dst[n] = 0;
        return;
    }
    n = strlen(root);
    if (n > cap - 2) n = cap - 2;
    memcpy(dst, root, n);
    i = n;
    if (i && dst[i-1] != '/') dst[i++] = '/';
    n = strlen(rel);
    if (n > cap - 1 - i) n = cap - 1 - i;
    memcpy(dst + i, rel, n);
    dst[i + n] = 0;
}

/* ============================ the mini JSON reader =========================
 * Enough to read a FLAT object of "key": "value" and "key": number. It is not
 * a general parser and does not pretend to be: it has no nesting, no escapes
 * beyond the two that can appear in a path, and it refuses -- loudly -- what
 * it cannot read rather than guessing. A reader that guesses is a reader whose
 * green run means nothing. */

static const char *skip_ws(const char *p)
{
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    return p;
}

/* Pointer just past the ':' following top-level "key", or NULL. */
static const char *json_value(const char *doc, const char *key)
{
    char needle[128];
    const char *p = doc;
    size_t n = strlen(key);
    if (n + 3 > sizeof needle) return NULL;
    needle[0] = '"';
    memcpy(needle + 1, key, n);
    needle[n + 1] = '"';
    needle[n + 2] = 0;
    while ((p = strstr(p, needle)) != NULL) {
        const char *q = skip_ws(p + n + 2);
        if (*q == ':') return skip_ws(q + 1);
        p = q;
    }
    return NULL;
}

static size_t json_count_key(const char *doc, const char *key)
{
    char needle[128];
    const char *p = doc;
    size_t n = strlen(key), hits = 0;
    if (n + 3 > sizeof needle) return 0;
    needle[0] = '"';
    memcpy(needle + 1, key, n);
    needle[n + 1] = '"';
    needle[n + 2] = 0;
    while ((p = strstr(p, needle)) != NULL) { hits++; p += n + 2; }
    return hits;
}

/* 0 = ok, -1 = absent, -2 = malformed. */
static int json_str(const char *doc, const char *key, char *out, size_t cap)
{
    const char *p = json_value(doc, key);
    size_t i = 0;
    if (!p) return -1;
    if (*p != '"') return -2;
    p++;
    while (*p && *p != '"') {
        char c = *p++;
        if (c == '\\') {
            char e = *p++;
            if (e == '"' || e == '\\') c = e;
            else return -2;          /* no other escape is legal in this doc */
        }
        if (i + 1 >= cap) return -2;
        out[i++] = c;
    }
    if (*p != '"') return -2;
    out[i] = 0;
    return 0;
}

static int json_num(const char *doc, const char *key, long *out)
{
    const char *p = json_value(doc, key);
    char *end = NULL;
    long v;
    if (!p) return -1;
    if (*p != '-' && (*p < '0' || *p > '9')) return -2;
    v = strtol(p, &end, 10);
    if (end == p) return -2;
    { const char *e = skip_ws(end);
      if (*e != 0 && *e != ',' && *e != '}' && *e != ']') return -2; }
    *out = v;
    return 0;
}

/* ================================ reporting =============================== */

static void report(const char *token, int pass, const char *fmt, ...)
{
    va_list ap;
    checks++;
    fprintf(stdout, "PE_ORACLE_PROVENANCE CHECK %-28s %s ", token,
            pass ? "PASS" : "FAIL");
    va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
    va_end(ap);
    fputc('\n', stdout);
    if (!pass) failures++;
}

static void skip(const char *what, const char *why)
{
    skipped++;
    fprintf(stdout, "PE_ORACLE_PROVENANCE SKIP   %-28s %s (%s)\n", what, "not-run", why);
}

/* A repo-relative POSIX path: not absolute, no '\', no ':', no '..' segment.
 * The ':' and '\' rules are the ones the corrected document needed, and they
 * are refused rather than tolerated because a Windows path in a POSIX document
 * is not a path, it is a string that happens to have slashes in it. */
static const char *path_form_error(const char *p)
{
    size_t i;
    if (!p || !p[0]) return "empty";
    if (p[0] == '/') return "absolute";
    for (i = 0; p[i]; i++) {
        if (p[i] == '\\') return "backslash";
        if (p[i] == ':')  return "drive-letter-colon";
    }
    for (i = 0; p[i]; i++) {
        if (p[i] == '/' && p[i+1] == '.' && p[i+2] == '.' &&
            (p[i+3] == 0 || p[i+3] == '/'))
            return "dotdot-segment";
    }
    return 0;
}

/* The tail of the oracle after the copied suffix must be EXACTLY the declared
 * function and nothing else. "Exactly" is measured, not asserted: it starts
 * with the declared signature, it opens exactly one brace, it closes exactly
 * one brace, the body carries no newline, and the last two bytes are "}\n".
 * A second function appended after it would make the brace count two. */
static const char *extra_fn_error(const unsigned char *tail, size_t n,
                                  const char *declared)
{
    size_t dl = strlen(declared), nl = 0, i;
    if (n < 2) return "tail-shorter-than-newline-pair";
    if (tail[0] != '\n') return "no-blank-line-before-function";
    if (tail[n-1] != '\n') return "no-trailing-newline";
    if (tail[n-2] != '}') return "does-not-end-in-closing-brace";
    if (n < 2 + dl || memcmp(tail + 1, declared, dl) != 0)
        return "does-not-begin-with-declared-signature";
    for (i = 1; i + 1 < n; i++) {
        if (tail[i] == '\n') return "newline-inside-function";
        if (tail[i] == '{') nl++;
        if (tail[i] == '}') nl--;
    }
    if (nl != 0) return "unbalanced-braces-or-two-functions";
    return 0;
}

int main(int argc, char **argv)
{
    const char *json_arg = 0, *oracle_arg = 0, *root_arg = 0;
    const char *probe = "tests/c/nova/pe_oracle-source.json";
    char root[PATHCAP] = ".";
    char json_path[PATHCAP], oracle_path[PATHCAP];
    char src_path[PATHCAP], lay_src_path[PATHCAP], lay_cpy_path[PATHCAP];
    char source[512], sha[128], anchor[256], extra_fn[256];
    char layout_source[512], layout_copy[512], layout_sha[128];
    long suffix_offset = -1;
    Blob doc, src, orc, lsrc, lcpy;
    char got_src_sha[65], got_lay_sha[65];
    long src_anchor_off = -1, orc_anchor_off = -1;
    size_t suffix_len;
    const char *e;
    int i;
    /* Initialised because `done:` frees all five, and a jump to it can happen
     * before read_file() has touched one of them. */
    doc.p = NULL; doc.n = 0; doc.ok = 0;
    src.p = NULL; src.n = 0; src.ok = 0;
    orc.p = NULL; orc.n = 0; orc.ok = 0;
    lsrc.p = NULL; lsrc.n = 0; lsrc.ok = 0;
    lcpy.p = NULL; lcpy.n = 0; lcpy.ok = 0;

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--json") && i + 1 < argc)          json_arg = argv[++i];
        else if (!strcmp(argv[i], "--oracle") && i + 1 < argc)   oracle_arg = argv[++i];
        else if (!strcmp(argv[i], "--root") && i + 1 < argc)     root_arg = argv[++i];
        else {
            fprintf(stderr, "usage: %s [--json P] [--oracle P] [--root P]\n", argv[0]);
            return 2;
        }
    }

    if (root_arg) {
        snprintf(root, sizeof root, "%s", root_arg);
    } else {
        /* THE ORDER OF THE TWO PROBES IS THE FIX, and it is a measured one.
         *
         * A reader asked this question: a replay with the binary in ANOTHER
         * copy exited green for one reason only -- the root was deduced from
         * argv[0], which walks up from the BINARY, not from the working
         * directory. That reads a coherent tree, just not the one the reader
         * was standing in, and every one of its checks is about that other
         * tree. A gate that answers about a subject nobody named is a gate
         * whose green says nothing about the tree in front of you.
         *
         * So: the CURRENT DIRECTORY is probed FIRST, and argv[0] is only
         * consulted when the working directory cannot answer. Probing for the
         * document is the honest test -- a build directory is not a root, and
         * a root that cannot answer is not a root. The order is the whole
         * repair; the walk itself was never the defect. */
        {
          const char *argv0 = argv[0];
          char cand[PATHCAP];
          size_t cut;
          path_join(json_path, sizeof json_path, ".", probe);
          if (!file_exists(json_path)) {
            snprintf(cand, sizeof cand, "%s", argv0);
            for (cut = strlen(cand); cut > 0; cut--) {
              char save;
              if (cand[cut-1] != '/' && cand[cut-1] != '\\') continue;
              save = cand[cut-1];
              cand[cut-1] = 0;
              path_join(json_path, sizeof json_path, cand, probe);
              if (file_exists(json_path)) { snprintf(root, sizeof root, "%s", cand); break; }
              cand[cut-1] = save;
            }
            /* root stays "." when neither the working directory nor any
             * ancestor of argv[0] answered; the read below then fails loudly
             * instead of reading a neighbouring tree. */
          }
        }
    }

    path_join(json_path, sizeof json_path, root,
              json_arg ? json_arg : "tests/c/nova/pe_oracle-source.json");
    path_join(oracle_path, sizeof oracle_path, root,
              oracle_arg ? oracle_arg : "compiler/c/nova/pe/pe_oracle.c");

    printf("PE_ORACLE_PROVENANCE NOT_CHECKED "
           "oracle_preface_bytes_before_anchor;"
           "semantics_of_the_forwarded_function_body;"
           "whether_either_file_compiles_or_links;"
           "whether_any_driver_reads_this_document;"
           "layout_headers_against_ntasm.c_itself;"
           "which_tree_you_meant_when_root_is_not_given:"
           "the_working_directory_wins_and_argv0_is_only_a_fallback_"
           "so_a_binary_elsewhere_cannot_answer_about_a_neighbouring_copy;"
           "pass_root_explicitly_if_you_replay_a_frozen_copy\n");
    printf("PE_ORACLE_PROVENANCE INPUT root=%s json=%s oracle=%s\n",
           root, json_path, oracle_path);

    /* ---- 0. the digest itself, before any conclusion depends on it ---- */
    sha256((const unsigned char *)"", 0, got_src_sha);
    report("PROV-SHA-SELFTEST",
           !strcmp(got_src_sha,
                   "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
           "sha256(\"\")=%s", got_src_sha);
    sha256((const unsigned char *)"abc", 3, got_src_sha);
    report("PROV-SHA-SELFTEST",
           !strcmp(got_src_sha,
                   "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
           "sha256(\"abc\")=%s", got_src_sha);

    /* ---- 1. read the document ---- */
    if (read_file(json_path, &doc, MAX_DOC) != 0) {
        report("PROV-JSON-UNREADABLE", 0, "cannot read %s", json_path);
        goto done;
    }

    {
        static const char *KEYS[8] = {
            "source", "sha256", "suffix_offset", "suffix_anchor",
            "suffix_extra_function", "layout_source", "layout_copy",
            "layout_sha256"};
        int k, missing = 0, dup = 0;
        for (k = 0; k < 8; k++) {
            size_t c = json_count_key((const char *)doc.p, KEYS[k]);
            if (c == 0) missing++;
            if (c > 1) dup++;
        }
        report("PROV-JSON-MISSING-KEY", missing == 0,
               "keys_present=%d/8 missing=%d", 8 - missing, missing);
        report("PROV-JSON-DUPLICATE-KEY", dup == 0,
               "duplicated_keys=%d", dup);
    }

    if (json_str((const char *)doc.p, "source", source, sizeof source) != 0 ||
        json_str((const char *)doc.p, "sha256", sha, sizeof sha) != 0 ||
        json_str((const char *)doc.p, "suffix_anchor", anchor, sizeof anchor) != 0 ||
        json_str((const char *)doc.p, "suffix_extra_function", extra_fn, sizeof extra_fn) != 0 ||
        json_str((const char *)doc.p, "layout_source", layout_source, sizeof layout_source) != 0 ||
        json_str((const char *)doc.p, "layout_copy", layout_copy, sizeof layout_copy) != 0 ||
        json_str((const char *)doc.p, "layout_sha256", layout_sha, sizeof layout_sha) != 0 ||
        json_num((const char *)doc.p, "suffix_offset", &suffix_offset) != 0) {
        report("PROV-JSON-PARSE", 0, "a declared field is absent or malformed");
        goto done;
    }
    printf("PE_ORACLE_PROVENANCE DECLARED source=%s sha256=%s suffix_offset=%ld "
           "anchor=%s\n", source, sha, suffix_offset, anchor);
    printf("PE_ORACLE_PROVENANCE DECLARED layout_source=%s layout_copy=%s "
           "layout_sha256=%s\n", layout_source, layout_copy, layout_sha);

    /* ---- 2. FIELD 1: source (path form, then the file, then its digest) ---- */
    e = path_form_error(source);
    report("PROV-JSON-SOURCE-PATH", e == 0, "source=%s%s%s", source,
           e ? " rejected=" : "", e ? e : " repo-relative");
    if (e) skip("PROV-JSON-SHA", "source-path-rejected");
    if (e) skip("PROV-TREE-SUFFIX", "source-path-rejected");
    else {
        path_join(src_path, sizeof src_path, root, source);
        if (read_file(src_path, &src, MAX_FILE) != 0) {
            report("PROV-TREE-SOURCE-MISSING", 0, "cannot read %s", src_path);
            skip("PROV-JSON-SHA", "source-unreadable");
            skip("PROV-TREE-SUFFIX", "source-unreadable");
        } else {
            sha256(src.p, src.n, got_src_sha);
            report("PROV-JSON-SHA", !strcmp(got_src_sha, sha),
                   "recomputed=%s declared=%s bytes=%zu", got_src_sha, sha, src.n);

            {   /* locate, never trust */
                size_t hits = count_occ(src.p, src.n, anchor, &src_anchor_off);
                report("PROV-TREE-ANCHOR-UNIQUE", hits == 1,
                       "anchor=\"%s\" occurrences=%zu offset=%ld",
                       anchor, hits, src_anchor_off);
            }
            if (src_anchor_off >= 0) {
                report("PROV-JSON-SUFFIX-OFFSET", src_anchor_off == suffix_offset,
                       "located=%ld declared=%ld", src_anchor_off, suffix_offset);
                suffix_len = src.n - (size_t)src_anchor_off;
            } else {
                report("PROV-JSON-SUFFIX-OFFSET", 0,
                       "anchor absent from source, offset not comparable");
                suffix_len = 0;
            }

            /* ---- 3. FIELD 2: the copied suffix, byte for byte ---- */
            if (read_file(oracle_path, &orc, MAX_FILE) != 0) {
                report("PROV-TREE-ORACLE-MISSING", 0, "cannot read %s", oracle_path);
                skip("PROV-TREE-SUFFIX", "oracle-unreadable");
                skip("PROV-JSON-EXTRA-FUNCTION", "oracle-unreadable");
            } else {
                size_t hits = count_occ(orc.p, orc.n, anchor, &orc_anchor_off);
                report("PROV-TREE-ORACLE-ANCHOR-UNIQUE", hits == 1,
                       "anchor occurrences_in_oracle=%zu offset=%ld",
                       hits, orc_anchor_off);
                if (hits != 1) {
                    report("PROV-TREE-SUFFIX", 0,
                           "oracle anchor occurs %zu times, suffix not comparable",
                           hits);
                    skip("PROV-JSON-EXTRA-FUNCTION", "oracle-anchor-not-unique");
                } else {
                    size_t have = orc.n - (size_t)orc_anchor_off;
                    if (have < suffix_len) {
                        report("PROV-TREE-SUFFIX", 0,
                               "oracle suffix shorter: have=%zu need=%zu",
                               have, suffix_len);
                        skip("PROV-JSON-EXTRA-FUNCTION", "oracle-suffix-truncated");
                    } else if (memcmp(orc.p + orc_anchor_off,
                                     src.p + src_anchor_off, suffix_len) != 0) {
                        size_t k = 0;
                        while (k < suffix_len &&
                               orc.p[orc_anchor_off + k] == src.p[src_anchor_off + k])
                            k++;
                        report("PROV-TREE-SUFFIX", 0,
                               "first difference at suffix offset %zu: "
                               "source=0x%02x oracle=0x%02x (suffix_len=%zu)",
                               k, src.p[src_anchor_off + k],
                               orc.p[orc_anchor_off + k], suffix_len);
                    } else {
                        report("PROV-TREE-SUFFIX", 1,
                               "%zu bytes identical from offset %ld", suffix_len,
                               src_anchor_off);
                    }
                    e = extra_fn_error(orc.p + orc_anchor_off + suffix_len,
                                       have - suffix_len, extra_fn);
                    report("PROV-JSON-EXTRA-FUNCTION", e == 0,
                           "declared=\"%s\"%s%s", extra_fn,
                           e ? " rejected=" : "", e ? e : " exactly-and-nothing-else");
                }
            }
        }
    }

    /* ---- 4. FIELD 4: the two layout headers and their declared digest ---- */
    e = path_form_error(layout_source);
    report("PROV-JSON-LAYOUT-PATH", e == 0, "layout_source=%s%s%s", layout_source,
           e ? " rejected=" : "", e ? e : " repo-relative");
    { const char *e2 = path_form_error(layout_copy);
      report("PROV-JSON-LAYOUT-PATH", e2 == 0, "layout_copy=%s%s%s", layout_copy,
             e2 ? " rejected=" : "", e2 ? e2 : " repo-relative"); }
    if (path_form_error(layout_source) || path_form_error(layout_copy)) {
        skip("PROV-JSON-LAYOUT-SHA", "layout-path-rejected");
        skip("PROV-TREE-LAYOUT", "layout-path-rejected");
    } else {
        path_join(lay_src_path, sizeof lay_src_path, root, layout_source);
        path_join(lay_cpy_path, sizeof lay_cpy_path, root, layout_copy);
        if (read_file(lay_src_path, &lsrc, MAX_FILE) != 0 ||
            read_file(lay_cpy_path, &lcpy, MAX_FILE) != 0) {
            report("PROV-TREE-LAYOUT-MISSING", 0, "cannot read %s / %s",
                   lay_src_path, lay_cpy_path);
            skip("PROV-JSON-LAYOUT-SHA", "layout-unreadable");
            skip("PROV-TREE-LAYOUT", "layout-unreadable");
        } else {
            sha256(lsrc.p, lsrc.n, got_lay_sha);
            report("PROV-JSON-LAYOUT-SHA", !strcmp(got_lay_sha, layout_sha),
                   "recomputed=%s declared=%s bytes=%zu", got_lay_sha,
                   layout_sha, lsrc.n);
            report("PROV-TREE-LAYOUT",
                   lsrc.n == lcpy.n &&
                   (lsrc.n == 0 || memcmp(lsrc.p, lcpy.p, lsrc.n) == 0),
                   "%s(%zu bytes) vs %s(%zu bytes) byte-for-byte %s",
                   layout_source, lsrc.n, layout_copy, lcpy.n,
                   (lsrc.n == lcpy.n &&
                    (lsrc.n == 0 || memcmp(lsrc.p, lcpy.p, lsrc.n) == 0))
                       ? "identical" : "DIFFERENT");
        }
    }

done:
    free(doc.p); free(src.p); free(orc.p); free(lsrc.p); free(lcpy.p);
    printf("PE_ORACLE_PROVENANCE FIELDS 4 source sha256 suffix layout "
           "(document has 8 keys; fields are re-derived groups, not keys)\n");
    printf("PE_ORACLE_PROVENANCE checks=%u failures=%u fields=4 skipped=%u\n",
           checks, failures, skipped);
    return failures ? 1 : 0;
}
