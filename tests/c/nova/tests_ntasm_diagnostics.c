/* NTASM diagnostics foundation gate: bounded diagnostic list, parser
 * resynchronisation policy and one vertical slice of the validator pass
 * chain. Every expectation is anchored either on the C oracle
 * (nt_frontend_compile in frontend.c) or on structure this gate computes
 * itself; nothing is derived from the Nova module under test. */
#include "../../../compiler/c/ntasm/frontend/frontend.h"
#include "../../../compiler/c/nova/frontend/nova.h"
#include "../../../compiler/c/nova/runtime/run_host.h"
#include "../../../compiler/c/nova/runtime/runtime_v2.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* The closure walk, for the control on this gate's own module list. It is a
   header and not an object precisely so that a harness can opt in without the
   driver's shared object list being edited. */
#include "ntasm_pipeline_parity.h"

static unsigned checks, failures, cases;
static const uint64_t guard = UINT64_C(0xcccccccccccccccc);

/* Capacity the module must declare, and therefore the result buffer the
 * entry needs: eighteen header words plus seven words per entry. */
static const uint64_t CAPACITY = 32;
static const uint64_t MIN_WORDS = 18 + 7 * CAPACITY;
static const uint64_t HEADER = 16;
static const uint64_t SLICE_HEADER = 18;
static const uint64_t PROBE_CAPACITY = 64;
static const uint64_t MAX_ROWS = 16;

#define CMD_COLLECT 1
#define CMD_COLLECT_REVERSE 2
#define CMD_RESYNC 3
#define CMD_REGION 4
#define CMD_SLICE 5

static const char *PROBE_HEAD = "module m\ntarget x86_64-nexora-none\n";
#define HEAD "module m\ntarget x86_64-nexora-none\n"

#define CHECK(c, m)                                                            \
  do {                                                                         \
    checks++;                                                                  \
    if (!(c)) {                                                                \
      failures++;                                                              \
      fprintf(stderr, "FAIL %s\n", m);                                        \
    }                                                                          \
  } while (0)

typedef struct {
  uint64_t returned, runtime, out[256];
} Run;

static Run run_cmd(const NovaHostImage *i, uint64_t command, const char *s,
                   uint64_t words) {
  Run r;
  unsigned k;
  NovaContextV2 c = {0};
  for (k = 0; k < 256; k++)
    r.out[k] = guard;
  r.out[0] = command;
  r.returned = 0;
  r.runtime = UINT64_MAX;
  if (!nova_context_init_v2(&c))
    return r;
  {
    uint64_t sh = nova_borrow_v2(&c, (void *)s, strlen(s), 0);
    uint64_t oh = nova_borrow_v2(&c, r.out, words * 8, 1);
    uint64_t a[] = {sh, strlen(s), oh, words};
    r.returned = i->entry(&c, a, 4);
    r.runtime = c.error;
  }
  CHECK(nova_context_destroy_v2(&c), "context cleanup");
  return r;
}

static Run collect(const NovaHostImage *i, const char *s) {
  return run_cmd(i, CMD_COLLECT, s, 256);
}
static Run collect_reverse(const NovaHostImage *i, const char *s) {
  return run_cmd(i, CMD_COLLECT_REVERSE, s, 256);
}

static char *dup_text(const char *s) {
  size_t n = strlen(s);
  char *out = (char *)malloc(n + 1);
  if (out)
    memcpy(out, s, n + 1);
  return out;
}

/* ---- expectations computed by the gate itself ------------------------ */

typedef struct {
  unsigned code;
  uint64_t line, column, start, end;
} Diag;

/* First diagnostic of the C oracle for one buffer; 1 when it rejected. */
static int oracle(const char *name, const char *text, Diag *out) {
  NtFInput in;
  NtFProgram p;
  int ok, failed = 0;
  memset(out, 0, sizeof(*out));
  in.name = name;
  in.text = text;
  in.length = strlen(text);
  ok = nt_frontend_compile(&in, 1, &p);
  if (!ok && p.diagnostic_count) {
    out->code = p.diagnostics[0].code;
    out->line = p.diagnostics[0].span.line;
    out->column = p.diagnostics[0].span.column;
    out->start = p.diagnostics[0].span.start;
    out->end = p.diagnostics[0].span.end;
    failed = 1;
  }
  nt_frontend_free(&p);
  return failed;
}

/* The buffer the module probes one construct with. */
static char *probe_buffer(const char *source, uint64_t begin, uint64_t end) {
  size_t head = strlen(PROBE_HEAD);
  size_t len = strlen(source);
  char *out;
  if (begin > end || end > len)
    return NULL;
  out = (char *)malloc(head + (size_t)(end - begin) + 1);
  if (!out)
    return NULL;
  memcpy(out, PROBE_HEAD, head);
  memcpy(out + head, source + begin, (size_t)(end - begin));
  out[head + (size_t)(end - begin)] = 0;
  return out;
}

/* Byte offset of a one-based line and column: the gate's own reading of the
 * mapping a pipeline diagnostic must go through. */
static uint64_t offset_of(const char *source, uint64_t line, uint64_t column) {
  size_t len = strlen(source);
  uint64_t at = 0, current = 1, base = 0;
  if (line == 0 || column == 0)
    return UINT64_MAX;
  while (at < len && current < line) {
    if (source[at] == '\n') {
      current++;
      base = at + 1;
    }
    at++;
  }
  if (current != line)
    return UINT64_MAX;
  if (base + column > len)
    return UINT64_MAX;
  return base + column - 1;
}

static uint64_t last_offset(const char *hay, const char *needle) {
  const char *at = NULL;
  const char *scan = hay;
  for (;;) {
    const char *found = strstr(scan, needle);
    if (!found)
      break;
    at = found;
    scan = found + 1;
  }
  return at ? (uint64_t)(at - hay) : UINT64_MAX;
}

/* The total order finalize must produce: (source,start,end,code,reason). */
static int key_cmp(const Run *r, uint64_t i, uint64_t j) {
  static const uint64_t field[5] = {2, 5, 6, 0, 1};
  uint64_t a, b;
  int k;
  for (k = 0; k < 5; k++) {
    a = r->out[HEADER + i * 7 + field[k]];
    b = r->out[HEADER + j * 7 + field[k]];
    if (a != b)
      return a < b ? -1 : 1;
  }
  return 0;
}

static uint64_t entry(const Run *r, uint64_t i, uint64_t f) {
  return r->out[HEADER + i * 7 + f];
}
static uint64_t slice_entry(const Run *r, uint64_t i, uint64_t f) {
  return r->out[SLICE_HEADER + i * 7 + f];
}

/* ---- fixtures -------------------------------------------------------- */

static char *fixture_valid(void) {
  return dup_text("module m\ntarget x86_64-nexora-none\n"
                  "section .rdata {\ndata answer:u64=42\n}\n"
                  "section .text {\n"
                  "fn helper(in x:u64 @rcx)->u64\neffects {}\nclobbers {} {\n"
                  "let y:u64=x\nreturn y\n}\n"
                  "fn main()->u64\neffects {}\nclobbers {rax} {\n"
                  "call helper(1)\nreturn 0\n}\n}\n");
}

/* A malformed statement inside a body, with real ';' terminators around it. */
static const char *SRC_STMT =
    "module m\ntarget x86_64-nexora-none\nsection .text {\n"
    "fn f()->u64\neffects {}\nclobbers {} {\n"
    "let x:u64=1;\n? ? ?;\nlet y:u64=2;\nreturn x\n}\n}\n";

/* Two malformed top-level declarations with a good one between them. */
static const char *SRC_TWO =
    "module m\ntarget x86_64-nexora-none\n"
    "default_abi !!!\nconst x:u64=1\n"
    "default_abi ???\nconst y:u64=2\n";

/* One malformed declaration then a good one: the recovery boundary that
 * follows the error is the head of that next top-level keyword. */
static const char *SRC_DECL =
    "module m\ntarget x86_64-nexora-none\n"
    "default_abi !!!\nconst x:u64=1\n";

/* Fifty declarations, the first and the fiftieth malformed. */
static char *fixture_far(void) {
  size_t cap = 4096, at = 0;
  char *out = (char *)malloc(cap);
  unsigned i;
  if (!out)
    return NULL;
  at += (size_t)snprintf(out + at, cap - at, "%s", HEAD);
  for (i = 1; i <= 50; i++) {
    if (i == 1 || i == 50)
      at += (size_t)snprintf(out + at, cap - at, "default_abi !!!\n");
    else
      at += (size_t)snprintf(out + at, cap - at, "const k%u:u64=%u\n", i, i);
  }
  return out;
}

/* n malformed declarations: n distinct diagnostics from the parser. */
static char *fixture_overflow(unsigned n) {
  size_t cap = 64 + 24 * (size_t)n, at = 0;
  char *out = (char *)malloc(cap);
  unsigned i;
  if (!out)
    return NULL;
  at += (size_t)snprintf(out + at, cap - at, "%s", HEAD);
  for (i = 0; i < n; i++)
    at += (size_t)snprintf(out + at, cap - at, "default_abi !!!\n");
  return out;
}

/* A bad declaration then a trailing section left unterminated: the trailing
 * construct has no complete end and its probe must be refused, not reported. */
static const char *SRC_TRUNC =
    "module m\ntarget x86_64-nexora-none\n"
    "default_abi !!!\nconst x:u64=1\n"
    "section .text {\nfn f()->u64\neffects {}\nclobbers {} {\nreturn 0\n";

static const char *SRC_LEX =
    "module m\ntarget x86_64-nexora-none\nconst x:u64=\x7f\n";

/* Two independent failures inside the slice with no cascade between them: an
 * unknown feature (features, 341) and an unknown versions domain (versions,
 * 347). versions runs before features, so the returned code is 347 while the
 * first stored entry is 341: source order and pipeline order differ, and
 * finalize is what reconciles them. */
static const char *SRC_SEM_PAIR =
    "module m\ntarget x86_64-nexora-none\n"
    "features {avx512}\n"
    "versions {\nfoo 0.1\n}\n";

/* Two independent failures plus a duplicate name cascade. */
static const char *SRC_SEM_TWO =
    "module m\ntarget x86_64-nexora-none\n"
    "versions {\nfoo 0.1\n}\n"
    "section .text {\n"
    "fn f()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n"
    "fn f()->u64\neffects {}\nclobbers {} {\nreturn 1\n}\n}\n";

/* A failure that lives past the slice: a call to an undeclared name. */
static const char *SRC_SEM_OUTSIDE =
    "module m\ntarget x86_64-nexora-none\nsection .text {\n"
    "fn main()->u64\neffects {}\nclobbers {} {\ncall absent()\nreturn 0\n}\n}\n";

typedef struct {
  const char *name;
  const char *text;
  uint64_t code;
} SemCase;

static const SemCase SEM_CASES[] = {
    {"duplicate function",
     "module m\ntarget x86_64-nexora-none\nsection .text {\n"
     "fn f()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n"
     "fn f()->u64\neffects {}\nclobbers {} {\nreturn 1\n}\n}\n",
     300},
    {"unknown target", "module m\ntarget x86_64-other-none\n", 345},
    {"unknown domain",
     "module m\ntarget x86_64-nexora-none\nversions {\nfoo 0.1\n}\n", 347},
    {"unknown feature", "module m\ntarget x86_64-nexora-none\nfeatures {avx512}\n",
     341},
    /* Removed: "symbol collision", the fn/data pair across two sections,
     * pinned at 319. 319 is symbol_names.check, and it used to keep ONE
     * namespace for functions, data and import aliases, so it refused
     * `data same` in .rdata against `fn same` in .text. The C oracle keeps
     * TWO: duplicate_function (frontend.c:2950), called by parse_function
     * (:3043) and parse_import (:2968), walks functions only, and the
     * variable loop in parse_data (:3163) walks module globals only.
     * nt_object_compile accepts this source with two symbols. It has left
     * this table, which enumerates codes the pipeline REFUSES, because the
     * pipeline accepts it. The accept set is pinned where it belongs, in
     * tests_ntasm_symbol_names.c. */
    {"unknown type",
     "module m\ntarget x86_64-nexora-none\nsection .text {\n"
     "fn f(in p:telepathy @rdi)->u64\neffects {}\nclobbers {} {\n"
     "return 0\n}\n}\n",
     350},
    {"constant type", "module m\ntarget x86_64-nexora-none\nconst ready:bool=1\n",
     361},
    {"import alias",
     "module m\ntarget x86_64-nexora-none\n"
     "import a.f as x: fn()->u64\neffects {}\nclobbers {}\n"
     "import b.f as x: fn()->u64\neffects {}\nclobbers {}\n",
     313},
};
static const size_t SEM_COUNT = sizeof(SEM_CASES) / sizeof(SEM_CASES[0]);

/* ---- shared assertions ----------------------------------------------- */

/* No two stored diagnostics may name the same construct, and the stored
 * order must be the declared total order. */
static void expect_coherent(const char *name, const Run *r) {
  uint64_t n = r->out[1], i, j;
  checks++;
  cases++;
  if (n > CAPACITY) {
    failures++;
    fprintf(stderr, "FAIL coherence %s count=%llu past capacity\n", name,
            (unsigned long long)n);
    return;
  }
  if (r->out[4] != 0 || r->out[5] != 1) {
    failures++;
    fprintf(stderr, "FAIL coherence %s incoherent=%llu ordered=%llu\n", name,
            (unsigned long long)r->out[4], (unsigned long long)r->out[5]);
    return;
  }
  for (i = 0; i < n; i++)
    for (j = i + 1; j < n; j++) {
      if (key_cmp(r, i, j) >= 0) {
        failures++;
        fprintf(stderr, "FAIL order %s entries %llu %llu not increasing\n", name,
                (unsigned long long)i, (unsigned long long)j);
        return;
      }
      if (entry(r, i, 0) == entry(r, j, 0) && entry(r, i, 2) == entry(r, j, 2) &&
          entry(r, i, 5) == entry(r, j, 5) && entry(r, i, 6) == entry(r, j, 6)) {
        failures++;
        fprintf(stderr, "FAIL duplicate span %s E%llu at %llu-%llu twice\n", name,
                (unsigned long long)entry(r, i, 0),
                (unsigned long long)entry(r, i, 5),
                (unsigned long long)entry(r, i, 6));
        return;
      }
    }
}

/* The stored list must be exactly the set the C oracle produces: the whole
 * file's first diagnostic, plus one per top-level construct whose own
 * isolated parse fails strictly inside that construct. */
static void expect_oracle_parity(const NovaHostImage *image, const char *name,
                                 const char *source) {
  Run r, regions;
  Diag whole;
  uint64_t rows, head_len, i, k, n;
  checks++;
  cases++;
  r = collect(image, source);
  regions = run_cmd(image, CMD_REGION, source, 256);
  if (r.returned || r.runtime || regions.returned || regions.runtime) {
    failures++;
    fprintf(stderr, "FAIL parity setup %s collect=%llu region=%llu\n", name,
            (unsigned long long)r.returned, (unsigned long long)regions.returned);
    return;
  }
  if (regions.out[2] != strlen(PROBE_HEAD)) {
    failures++;
    fprintf(stderr, "FAIL probe header %s length=%llu want=%llu\n", name,
            (unsigned long long)regions.out[2],
            (unsigned long long)strlen(PROBE_HEAD));
    return;
  }
  if (!oracle(name, source, &whole)) {
    failures++;
    fprintf(stderr,
            "FAIL parity %s the C oracle accepts a source expected to fail\n",
            name);
    return;
  }
  if (r.out[6] != whole.code || entry(&r, 0, 0) != whole.code ||
      entry(&r, 0, 3) != whole.line || entry(&r, 0, 4) != whole.column ||
      entry(&r, 0, 5) != whole.start || entry(&r, 0, 6) != whole.end) {
    failures++;
    fprintf(stderr,
            "FAIL first diagnostic %s list E%llu %llu:%llu %llu-%llu oracle "
            "E%u %llu:%llu %llu-%llu\n",
            name, (unsigned long long)entry(&r, 0, 0),
            (unsigned long long)entry(&r, 0, 3),
            (unsigned long long)entry(&r, 0, 4),
            (unsigned long long)entry(&r, 0, 5), (unsigned long long)entry(&r, 0, 6),
            whole.code, (unsigned long long)whole.line,
            (unsigned long long)whole.column, (unsigned long long)whole.start,
            (unsigned long long)whole.end);
    return;
  }
  head_len = regions.out[2];
  rows = regions.out[1] > MAX_ROWS ? MAX_ROWS : regions.out[1];
  for (i = 0; i < rows; i++) {
    uint64_t begin = regions.out[3 + i * 4];
    uint64_t end = regions.out[3 + i * 4 + 1];
    uint64_t span = end - begin;
    char *buffer = probe_buffer(source, begin, end);
    Diag d;
    uint64_t at;
    int admit;
    if (!buffer) {
      failures++;
      fprintf(stderr, "FAIL parity buffer %s row %llu\n", name,
              (unsigned long long)i);
      return;
    }
    admit = oracle(name, buffer, &d);
    if (admit && d.start > head_len && d.start < head_len + span &&
        d.end <= head_len + span) {
      uint64_t want_start = begin + (d.start - head_len);
      uint64_t want_end = begin + (d.end - head_len);
      for (at = 0; at < r.out[1] && at <= CAPACITY; at++)
        if (entry(&r, at, 0) == d.code && entry(&r, at, 5) == want_start &&
            entry(&r, at, 6) == want_end)
          break;
      if (at == r.out[1]) {
        failures++;
        fprintf(stderr, "FAIL parity missing %s E%u at %llu-%llu\n", name, d.code,
                (unsigned long long)want_start, (unsigned long long)want_end);
        free(buffer);
        return;
      }
    }
    free(buffer);
  }
  n = r.out[1];
  if (n > CAPACITY) {
    failures++;
    fprintf(stderr, "FAIL parity %s count=%llu past capacity\n", name,
            (unsigned long long)n);
    return;
  }
  for (k = 0; k < n; k++) {
    uint64_t start = entry(&r, k, 5);
    uint64_t stop = entry(&r, k, 6);
    unsigned code = (unsigned)entry(&r, k, 0);
    int found = (k == 0);
    for (i = 0; !found && i < rows; i++) {
      uint64_t begin = regions.out[3 + i * 4];
      uint64_t end = regions.out[3 + i * 4 + 1];
      uint64_t span = end - begin;
      char *buffer;
      Diag d;
      buffer = probe_buffer(source, begin, end);
      if (!buffer)
        continue;
      if (oracle(name, buffer, &d) && d.start > head_len &&
          d.start < head_len + span && d.end <= head_len + span &&
          begin + (d.start - head_len) == start &&
          begin + (d.end - head_len) == stop)
        found = 1;
      free(buffer);
    }
    if (!found) {
      failures++;
      fprintf(stderr, "FAIL parity phantom %s E%u at %llu-%llu\n", name, code,
              (unsigned long long)start, (unsigned long long)stop);
      return;
    }
  }
}

/* ---- A10: the four diagnostic families on complete sources -------------
 *
 * A10 asks for width, register, section and ABI diagnostics "verified on
 * concrete cases", and the completion document is explicit that a probe or
 * a prefix does not validate a deliverable. Every row below is therefore a
 * COMPLETE .nova program -- module head, target, sections, full function
 * bodies -- and the gate drives it through the real thirty four stage
 * pipeline that validate.validate runs. That pipeline is the reference leg
 * of CMD_SLICE: out[2] is its code and out[12..15] are the four scratch
 * words of the failing pass.
 *
 * Four things are demanded of a row, and none of them is a literal copied
 * out of the module under test:
 *   - the code the pipeline returns;
 *   - scratch words 2 and 3, which is where a pass publishes the "family"
 *     of A10 -- the reason that tells two 328 apart, the two widths a 318
 *     disagrees about -- left unconstrained where the pass has no such word;
 *   - the line AND the column, re-derived here by counting LF up to the
 *     marked bytes of the program, so a pass that reported a position of
 *     zero, or of the wrong line, or of the type node instead of the
 *     register node, would be caught;
 *   - and the repaired twin: the SAME program with the defect fixed must be
 *     accepted. Without that leg a row proves nothing, because the code it
 *     asserts could be an accident of the fixture rather than the answer to
 *     the defect named in `marker`.
 */
#define SKIP UINT64_MAX

typedef struct {
  const char *family;
  const char *name;
  uint64_t code; /* what validate.validate must return */
  uint64_t w2;   /* scratch word 2, or SKIP when the pass has no reason */
  uint64_t w3;   /* scratch word 3, or SKIP */
  const char *marker;
  const char *broken;
  const char *fixed;
} A10Case;

/* 1-based line and column of the first occurrence of `marker`, counted the
 * way a user reads an error message. Derived from the bytes of the program
 * this gate just handed to the pipeline, never from the pipeline. */
static int mark_pos(const char *text, const char *marker, uint64_t *line,
                    uint64_t *column) {
  const char *hit = strstr(text, marker);
  uint64_t at = 0, l = 1, base = 0;
  if (!hit)
    return 0;
  while (at < (uint64_t)(hit - text)) {
    if (text[at] == '\n') {
      l++;
      base = at + 1;
    }
    at++;
  }
  *line = l;
  *column = (uint64_t)(hit - text) - base + 1;
  return 1;
}

static void expect_family(const NovaHostImage *image, const A10Case *c) {
  Run r;
  uint64_t line = 0, column = 0;
  int placed = mark_pos(c->broken, c->marker, &line, &column);
  cases++;
  checks++;
  if (!placed) {
    failures++;
    fprintf(stderr, "FAIL family %s/%s marker \"%s\" absent from the program\n",
            c->family, c->name, c->marker);
    return;
  }
  r = run_cmd(image, CMD_SLICE, c->broken, 256);
  if (r.returned || r.runtime) {
    failures++;
    fprintf(stderr, "FAIL family %s/%s pipeline returned=%llu runtime=%llu\n",
            c->family, c->name, (unsigned long long)r.returned,
            (unsigned long long)r.runtime);
    return;
  }
  if (r.out[2] != c->code || r.out[12] != line || r.out[13] != column ||
      (c->w2 != SKIP && r.out[14] != c->w2) ||
      (c->w3 != SKIP && r.out[15] != c->w3)) {
    failures++;
    fprintf(stderr,
            "FAIL family %s/%s want E%llu %llu:%llu w2=%s w3=%s got E%llu "
            "%llu:%llu w2=%llu w3=%llu\n",
            c->family, c->name, (unsigned long long)c->code,
            (unsigned long long)line, (unsigned long long)column,
            c->w2 == SKIP ? "-" : "pinned", c->w3 == SKIP ? "-" : "pinned",
            (unsigned long long)r.out[2], (unsigned long long)r.out[12],
            (unsigned long long)r.out[13], (unsigned long long)r.out[14],
            (unsigned long long)r.out[15]);
    return;
  }
  /* The repaired twin, same program, defect gone. */
  r = run_cmd(image, CMD_SLICE, c->fixed, 256);
  cases++;
  checks++;
  if (r.returned || r.runtime || r.out[2] != 0) {
    failures++;
    fprintf(stderr,
            "FAIL family %s/%s repaired twin refused E%llu at %llu:%llu "
            "returned=%llu\n",
            c->family, c->name, (unsigned long long)r.out[2],
            (unsigned long long)r.out[12], (unsigned long long)r.out[13],
            (unsigned long long)r.returned);
  }
}
/* Width. The two widths a 318 disagrees about are published as scratch words
 * 2 and 3, so a row here pins the pair, not just the verdict. */
static const A10Case A10_CASES[] = {
    {"largeur", "register narrower than its type", 318, 64, 32, "ecx)",
     "module m\ntarget x86_64-nexora-none\nsection .text {\n"
     "fn f(in x:u64 @ecx)->u64\neffects {}\nclobbers {} {\nreturn x\n}\n}\n",
     "module m\ntarget x86_64-nexora-none\nsection .text {\n"
     "fn f(in x:u64 @rcx)->u64\neffects {}\nclobbers {} {\nreturn x\n}\n}\n"},
    {"largeur", "register wider than its type", 318, 32, 64, "rax)",
     "module m\ntarget x86_64-nexora-none\nsection .text {\n"
     "fn f(in x:u32 @rax)->u32\neffects {}\nclobbers {} {\nreturn x\n}\n}\n",
     "module m\ntarget x86_64-nexora-none\nsection .text {\n"
     "fn f(in x:u32 @eax)->u32\neffects {}\nclobbers {} {\nreturn x\n}\n}\n"},
    {"largeur", "pointer bound to a 32 bit register", 329, 2, SKIP, "edi)",
     "module m\ntarget x86_64-nexora-none\nsection .text {\n"
     "fn f(in p:ptr<user,u64> @edi)->u64\neffects {}\nclobbers {} {\n"
     "return 0\n}\n}\n",
     "module m\ntarget x86_64-nexora-none\nsection .text {\n"
     "fn f(in p:ptr<user,u64> @rdi)->u64\neffects {}\nclobbers {} {\n"
     "return 0\n}\n}\n"},

    /* Registre. 317 and 320 are the two alias rules: a width spelling is the
     * same physical family, so @rcx/@ecx collide and {r10,r10d} duplicate. */
    {"registre", "same register bound twice", 317, SKIP, SKIP, "rcx)",
     "module m\ntarget x86_64-nexora-none\nsection .text {\n"
     "fn f(in a:u64 @rcx,in b:u64 @rcx)->u64\neffects {}\nclobbers {} {\n"
     "return a\n}\n}\n",
     "module m\ntarget x86_64-nexora-none\nsection .text {\n"
     "fn f(in a:u64 @rcx,in b:u64 @rdx)->u64\neffects {}\nclobbers {} {\n"
     "return a\n}\n}\n"},
    {"registre", "same family through a width alias", 317, SKIP, SKIP,
     "ecx)",
     "module m\ntarget x86_64-nexora-none\nsection .text {\n"
     "fn f(in a:u64 @rcx,in b:u64 @ecx)->u64\neffects {}\nclobbers {} {\n"
     "return a\n}\n}\n",
     "module m\ntarget x86_64-nexora-none\nsection .text {\n"
     "fn f(in a:u64 @rcx,in b:u64 @rdx)->u64\neffects {}\nclobbers {} {\n"
     "return a\n}\n}\n"},
    {"registre", "family repeated in one clobbers set", 320, SKIP, SKIP,
     "rax}",
     "module m\ntarget x86_64-nexora-none\nsection .text {\n"
     "fn f()->u64\neffects {}\nclobbers {rax,rax} {\nreturn 0\n}\n}\n",
     "module m\ntarget x86_64-nexora-none\nsection .text {\n"
     "fn f()->u64\neffects {}\nclobbers {rax,rcx} {\nreturn 0\n}\n}\n"},
    {"registre", "clobber name outside the catalogue", 330, SKIP, SKIP,
     "foo}",
     "module m\ntarget x86_64-nexora-none\nsection .text {\n"
     "fn f()->u64\neffects {}\nclobbers {foo} {\nreturn 0\n}\n}\n",
     "module m\ntarget x86_64-nexora-none\nsection .text {\n"
     "fn f()->u64\neffects {}\nclobbers {rax} {\nreturn 0\n}\n}\n"},
    {"registre", "callee clobbers not covered by the caller", 331, 1, SKIP,
     "leaf()\n",
     "module m\ntarget x86_64-nexora-none\nsection .text {\n"
     "fn leaf()->u64\neffects {}\nclobbers {rax} {\nreturn 0\n}\n"
     "fn main()->u64\neffects {}\nclobbers {} {\ncall leaf()\nreturn 0\n}\n}\n",
     "module m\ntarget x86_64-nexora-none\nsection .text {\n"
     "fn leaf()->u64\neffects {}\nclobbers {rax} {\nreturn 0\n}\n"
     "fn main()->u64\neffects {}\nclobbers {rax} {\ncall leaf()\n"
     "return 0\n}\n}\n"},
    /* 328 reason 4: a @GPR spelling the sixteen family catalogue does not
     * know. tests_ntasm_validate.c carries no pipeline case for it. */
    {"registre", "unknown @GPR", 328, 4, SKIP, "foo)",
     "module m\ntarget x86_64-nexora-none\nsection .text {\n"
     "fn f(in a:u64 @foo)->u64\neffects {}\nclobbers {} {\nreturn a\n}\n}\n",
     "module m\ntarget x86_64-nexora-none\nsection .text {\n"
     "fn f(in a:u64 @rcx)->u64\neffects {}\nclobbers {} {\nreturn a\n}\n}\n"},

    /* Section. The whole family is one case: a name repeated inside one
     * section, which is semantics.index at 300. A name repeated ACROSS two
     * sections was the second case here, pinned at 319, and it was wrong for
     * the reason the comment above gives: `data same` and `fn same` are two
     * names in two namespaces, and the oracle accepts the source. A genuine
     * cross section duplicate, two data items of one name in .rdata and
     * .data, is still refused, at 319, and is pinned in
     * tests_ntasm_symbol_names.c. Nothing else about sections is diagnosed. */
    {"section", "name repeated inside one section", 300, SKIP, SKIP, "f()->u64\neffects {}\nclobbers {} {\nreturn 1",
     "module m\ntarget x86_64-nexora-none\nsection .text {\n"
     "fn f()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n"
     "fn f()->u64\neffects {}\nclobbers {} {\nreturn 1\n}\n}\n",
     "module m\ntarget x86_64-nexora-none\nsection .text {\n"
     "fn f()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n"
     "fn g()->u64\neffects {}\nclobbers {} {\nreturn 1\n}\n}\n"},

    /* ABI: all seven 328 reasons and both 329 reasons, each on a complete
     * program, each with its reason word pinned so two 328 cannot be
     * confused for one another. */
    {"ABI", "unknown default_abi", 327, 1, SKIP, "alien-abi",
     "module m\ntarget x86_64-nexora-none\ndefault_abi alien-abi\n"
     "section .text {\nfn f()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n",
     "module m\ntarget x86_64-nexora-none\ndefault_abi nx64-abi-v0\n"
     "section .text {\nfn f()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n"},
    {"ABI", "fifth unbound in-parameter", 328, 2, SKIP, "in e:u64",
     "module m\ntarget x86_64-nexora-none\nsection .text {\n"
     "fn f(in a:u64,in b:u64,in c:u64,in d:u64,in e:u64)->u64\neffects {}\n"
     "clobbers {} {\nreturn a\n}\n}\n",
     "module m\ntarget x86_64-nexora-none\nsection .text {\n"
     "fn f(in a:u64,in b:u64,in c:u64,in d:u64 @r9)->u64\neffects {}\n"
     "clobbers {} {\nreturn a\n}\n}\n"},
    {"ABI", "out without a register", 328, 3, SKIP, "out a:u64",
     "module m\ntarget x86_64-nexora-none\nsection .text {\n"
     "fn f(out a:u64)->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n",
     "module m\ntarget x86_64-nexora-none\nsection .text {\n"
     "fn f(out a:u64 @rcx)->u64\neffects {}\nclobbers {} {\nreturn a\n}\n}\n"},
    {"ABI", "reserved output family", 328, 5, SKIP, "rax)",
     "module m\ntarget x86_64-nexora-none\nsection .text {\n"
     "fn f(out a:u64 @rax)->u64\neffects {}\nclobbers {} {\nreturn a\n}\n}\n",
     "module m\ntarget x86_64-nexora-none\nsection .text {\n"
     "fn f(out a:u64 @rcx)->u64\neffects {}\nclobbers {} {\nreturn a\n}\n}\n"},
    {"ABI", "output family also in clobbers", 328, 6, SKIP, "fn f(",
     "module m\ntarget x86_64-nexora-none\nsection .text {\n"
     "fn f(out a:u64 @rcx)->u64\neffects {}\nclobbers {ecx} {\n"
     "return a\n}\n}\n",
     "module m\ntarget x86_64-nexora-none\nsection .text {\n"
     "fn f(out a:u64 @rcx)->u64\neffects {}\nclobbers {rax} {\n"
     "return a\n}\n}\n"},
    {"ABI", "explicit binding hits the default", 328, 7, SKIP, "rcx)",
     "module m\ntarget x86_64-nexora-none\nsection .text {\n"
     "fn f(in a:u64,in b:u64 @rcx)->u64\neffects {}\nclobbers {} {\n"
     "return a\n}\n}\n",
     "module m\ntarget x86_64-nexora-none\nsection .text {\n"
     "fn f(in a:u64 @rcx,in b:u64 @rdx)->u64\neffects {}\nclobbers {} {\n"
     "return a\n}\n}\n"},
    {"ABI", "out type is not a machine scalar", 329, 1, SKIP, "out a:bool",
     "module m\ntarget x86_64-nexora-none\nsection .text {\n"
     "fn f(out a:bool @al)->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n",
     "module m\ntarget x86_64-nexora-none\nsection .text {\n"
     "fn f(out a:u8 @cl)->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n"},
    {"ABI", "call arity", 311, SKIP, SKIP, "helper()",
     "module m\ntarget x86_64-nexora-none\nsection .text {\n"
     "fn helper(in x:u64 @rcx)->u64\neffects {}\nclobbers {} {\n"
     "return x\n}\nfn main()->u64\neffects {}\nclobbers {} {\n"
     "call helper()\nreturn 0\n}\n}\n",
     "module m\ntarget x86_64-nexora-none\nsection .text {\n"
     "fn helper(in x:u64 @rcx)->u64\neffects {}\nclobbers {} {\n"
     "return x\n}\nfn main()->u64\neffects {}\nclobbers {} {\n"
     "call helper(1)\nreturn 0\n}\n}\n"},
    {"ABI", "argument type does not match the parameter", 354, 1, SKIP,
     "y)",
     "module m\ntarget x86_64-nexora-none\nsection .text {\n"
     "fn g(in x:u64 @rdi)->u64\neffects {}\nclobbers {} {\nreturn x\n}\n"
     "fn f(in y:u32 @edi)->u64\neffects {}\nclobbers {} {\n"
     "call g(y)\nreturn 0\n}\n}\n",
     "module m\ntarget x86_64-nexora-none\nsection .text {\n"
     "fn g(in x:u64 @rdi)->u64\neffects {}\nclobbers {} {\nreturn x\n}\n"
     "fn f(in y:u64 @rdi)->u64\neffects {}\nclobbers {} {\n"
     "call g(y)\nreturn 0\n}\n}\n"},
};
static const size_t A10_COUNT = sizeof A10_CASES / sizeof A10_CASES[0];

/* ---- A10, the half that is a measurement rather than a family ---------- */

/* A10 asks for SECTION diagnostics. Three are asked for by name: a symbol
 * referenced across a section it is not visible from, a data reference
 * without a relocation, and a section alignment the loader will not honour.
 * None of the three exists. The gate cannot assert the absence of a
 * diagnostic, so it asserts the opposite fact instead, on a COMPLETE
 * program a user would actually write: a function declared in .rdata and
 * called from .text is ACCEPTED. refs.resolve builds one flat module wide
 * callable table with no section term, so there is no mechanism by which
 * the cross section call could ever be refused.
 *
 * This case is the regression guard for the finding. The day a lot adds a
 * section visibility rule, this row goes red and the finding is corrected by
 * the code, not by the document. */
static const char *A10_CROSS_SECTION =
    "module m\ntarget x86_64-nexora-none\nsection .rdata {\n"
    "fn helper()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n"
    "section .text {\nfn main()->u64\neffects {}\nclobbers {} {\n"
    "call helper()\nreturn 0\n}\n}\n";

/* A10 also asks whether a data reference without a relocation is diagnosed.
 * The sentence this comment used to open with, that the language has no
 * construct naming a data symbol as an operand, is no longer true: wave 7's
 * producer work added one. `load rax,[answer]:ptr<user,u64>` names a data
 * symbol; x64_lower_nxo.nova:2486-2530 recognises it, encodes the address RIP
 * relative with a zero displacement and records a REL32 beside the field it
 * left zero. Measured against nt_object_compile: one data read yields one
 * REL32, two data reads in one function yield two at .text offsets 36 and 43,
 * seven bytes apart, and a call plus a data read yield one relocation each. A
 * shape the reader declines is not silently encoded: it falls through to the
 * register based encoder, which refuses it at 406 or 409
 * (x64_lower_fixed.nova:113-118). The invariant therefore holds, and it is
 * guarded by the byte comparison of the whole NXO object taken BEFORE
 * materialisation, at tests_ntasm_x64_lower_nxo_function_bodies.c:284-292.
 *
 * What is still true of a data symbol is that declaring one and never
 * referencing it is accepted: it is only ever a payload. And two data
 * symbols of one name in two sections are caught, by 319, for being a NAME
 * collision in the link namespace and not for anything to do with sections. */
static const char *A10_DATA_PAYLOAD =
    "module m\ntarget x86_64-nexora-none\nsection .rdata {\n"
    "data answer:u64=42\n}\nsection .text {\n"
    "fn main()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";

/* 346 is published, and spec/ntasm/ntasm.md records it as having no gate case.
 * This row is that missing case, and it is a case of NON reachability: the
 * only source that could make targets.check see a target count other than
 * one is a module with a second target line, and parser.nova:632 consumes
 * exactly one target immediately after the module head, so that source is
 * refused by the PARSER before any semantic pass runs. The measurement is
 * on expect_unreachable_346 below, which demands the refusal and the
 * untouched result buffer, not a code: 346 has no reachable emission, and a
 * gate case that asserted it would be asserting a number nothing produces. */
static const char *A10_ONE_TARGET =
    "module m\ntarget x86_64-nexora-none\nsection .text {\n"
    "fn f()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";

static const char *A10_TWO_TARGETS =
    "module m\ntarget x86_64-nexora-none\ntarget x86_64-nexora-none\n"
    "section .text {\nfn f()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";

/* The substrate's own reach, measured rather than asserted. diagnostics is a
 * list, a position map and a resynchronisation policy; slice_validate is
 * the part that reads a diagnostic, and it re-runs the first
 * slice_passes() stages of the pipeline. The four families of A10 sit at
 * stages 14 register_bindings, 15 register_widths, 16 clobbers, 17 abi and
 * 33 call_clobbers, all of them past the eighth. So for every one of them
 * the list this module owns comes back EMPTY while the pipeline returns the
 * diagnostic. That is a property of the declaration slice_passes()=8, and
 * the gate pins it: a lot that widens the slice turns these rows red and
 * has to say so. */
static const char *A10_SLICE_BLIND[] = {
    "module m\ntarget x86_64-nexora-none\nsection .text {\n"
    "fn f(in x:u64 @ecx)->u64\neffects {}\nclobbers {} {\nreturn x\n}\n}\n",
    "module m\ntarget x86_64-nexora-none\nsection .text {\n"
    "fn f(in a:u64 @rcx,in b:u64 @rcx)->u64\neffects {}\nclobbers {} {\n"
    "return a\n}\n}\n",
    "module m\ntarget x86_64-nexora-none\nsection .text {\n"
    "fn f(out a:u64 @rax)->u64\neffects {}\nclobbers {} {\nreturn a\n}\n}\n",
};
static const uint64_t A10_SLICE_BLIND_CODE[] = {318, 317, 328};
static const char *A10_SLICE_BLIND_NAME[] = {"largeur 318", "registre 317",
                                            "ABI 328"};

static void expect_accepted(const NovaHostImage *image, const char *name,
                            const char *source) {
  Run r = run_cmd(image, CMD_SLICE, source, 256);
  cases++;
  checks++;
  if (r.returned || r.runtime || r.out[2] != 0) {
    failures++;
    fprintf(stderr, "FAIL absent %s pipeline returned E%llu at %llu:%llu\n",
            name, (unsigned long long)r.out[2], (unsigned long long)r.out[12],
            (unsigned long long)r.out[13]);
  }
}

/* 346 is emitted by targets.check only when the tree carries a number of
 * target nodes other than one. parser.nova:632 consumes exactly one target
 * immediately after the module head and no other branch of source_tree
 * creates one, so no parseable tree can carry two. The only source that
 * could is refused by the PARSER, and that is what this row measures: the
 * command returns 800 and writes nothing past the command word, so no
 * semantic pass, and therefore no targets.check, ever runs on it.
 *
 * The second leg is a well formed single target module, so the refusal is a
 * fact about the two target source and not about this command refusing
 * sources in general. It is the control a claim of unreachability needs. */
static void expect_unreachable_346(const NovaHostImage *image,
                                   const char *two_targets) {
  Run r = run_cmd(image, CMD_SLICE, two_targets, 256);
  uint64_t k;
  int untouched = 1;
  cases++;
  checks++;
  for (k = 1; k < 256; k++)
    if (r.out[k] != guard)
      untouched = 0;
  if (r.returned != 800 || r.runtime || !untouched || r.out[0] != CMD_SLICE) {
    failures++;
    fprintf(stderr,
            "FAIL unreachable 346 returned=%llu untouched=%d runtime=%llu -- a "
            "two target source reached a semantic pass\n",
            (unsigned long long)r.returned, untouched,
            (unsigned long long)r.runtime);
  }
  expect_accepted(image, "one target", A10_ONE_TARGET);
}

/* The slice leg empty, the reference leg carrying the diagnostic. */
static void expect_slice_blind(const NovaHostImage *image, const char *name,
                               const char *source, uint64_t code) {
  Run r = run_cmd(image, CMD_SLICE, source, 256);
  cases++;
  checks++;
  if (r.returned || r.runtime || r.out[17] != 8 || r.out[1] != 0 ||
      r.out[3] != 0 || r.out[2] != code) {
    failures++;
    fprintf(stderr,
            "FAIL slice blind %s passes=%llu slice=%llu recorded=%llu "
            "reference=E%llu\n",
            name, (unsigned long long)r.out[17], (unsigned long long)r.out[1],
            (unsigned long long)r.out[3], (unsigned long long)r.out[2]);
  }
}


int main(void) {
  const char *paths[] = {
      "tests/nova/tests/diagnostics-entry.nova",
      "compiler/nova/analysis/diagnostics.nova",
      "compiler/nova/analysis/validate.nova","compiler/nova/macros/macro_splice.nova","compiler/nova/formats/ntir/ntir.nova",
      "compiler/nova/macros/macro_expand.nova",
      "compiler/nova/analysis/types/constant_types.nova",
      "compiler/nova/macros/constant_eval.nova",
      "compiler/nova/analysis/types/initializer_types.nova",
      "compiler/nova/analysis/types/condition_types.nova",
      "compiler/nova/analysis/types/literal_initializers.nova",
      "compiler/nova/frontend/targets.nova",
      "compiler/nova/frontend/versions.nova",
      "compiler/nova/analysis/abi/feature_requirements.nova",
      "compiler/nova/analysis/abi/features.nova",
      "compiler/nova/analysis/types/pointer_spaces.nova",
      "compiler/nova/analysis/control_flow.nova",
      "compiler/nova/analysis/types/return_types.nova",
      "compiler/nova/analysis/abi/body_clobbers.nova",
      "compiler/nova/analysis/abi/body_intrinsics.nova",
      "compiler/nova/analysis/abi/body_effects.nova",
      "compiler/nova/analysis/calls/call_contracts.nova",
      "compiler/nova/analysis/abi/abi.nova",
      "compiler/nova/analysis/calls/call_clobbers.nova",
      "compiler/nova/analysis/calls/call_effects.nova",
      "compiler/nova/analysis/calls/call_types.nova",
      "compiler/nova/analysis/calls/calls.nova",
      "compiler/nova/frontend/refs.nova",
      "compiler/nova/analysis/abi/clobbers.nova",
      "compiler/nova/analysis/abi/contracts.nova",
      "compiler/nova/analysis/abi/effects.nova",
      "compiler/nova/analysis/types/register_widths.nova",
      "compiler/nova/frontend/register_bindings.nova",
      "compiler/nova/frontend/bindings.nova",
      "compiler/nova/frontend/locals.nova",
      "compiler/nova/frontend/parameters.nova",
      "compiler/nova/analysis/types/types.nova",
      "compiler/nova/frontend/symbol_names.nova",
      "compiler/nova/analysis/calls/callable_names.nova",
      "compiler/nova/analysis/semantics.nova",
      "compiler/nova/frontend/parser.nova",
      "compiler/nova/frontend/ast.nova",
      "compiler/nova/frontend/lexer.nova",
      /* machine_ir.nova, because validate.nova IMPORTS it (toolchain/
         ntasm-nova/validate.nova:43) and calls machine_ir.lower and
         machine_ir.verify at stage 35.  A list that does not carry it compiles
         nothing: the product refuses with `E302 <line>:<col> Nova imported
         module is not among compiler inputs', and the refusal is CORRECT --
         it is a fact about this list, not about the compiler.  ng_parity_paths
         in ntasm_pipeline_parity.h carries the same row for the same reason. */
      "compiler/nova/ir/machine_ir.nova"};
  const size_t path_count = sizeof(paths) / sizeof(paths[0]);
  /* The two buffers used to be the literal 43, which is the length of the list
     ABOVE -- so the list could not grow by one row without someone editing a
     number in a second place, and that is the drift this row exists to stop.
     NG_DIAG_PATHS_MAX is room for the list to outgrow itself, and the static
     assertion turns a list that outgrew the room into a COMPILE failure naming
     the count, which is a different failure from a silent overwrite. */
#define NG_DIAG_PATHS_MAX 64
  char *sources[NG_DIAG_PATHS_MAX];
  NtFInput inputs[NG_DIAG_PATHS_MAX];
  _Static_assert(sizeof(paths) / sizeof(paths[0]) <= NG_DIAG_PATHS_MAX,
                 "the diagnostics image outgrew NG_DIAG_PATHS_MAX");
  NovaHostImage image = {0};
  NtArtifact artifact = {0};
  size_t i;
  int loaded = 1, compiled;

  memset(sources, 0, sizeof(sources));
  memset(inputs, 0, sizeof(inputs));
  for (i = 0; i < path_count; i++) {
    FILE *f;
    long size;
    f = fopen(paths[i], "rb");
    if (!f) {
      loaded = 0;
      fprintf(stderr, "MISSING %s\n", paths[i]);
      continue;
    }
    fseek(f, 0, SEEK_END);
    size = ftell(f);
    fseek(f, 0, SEEK_SET);
    sources[i] = (char *)malloc((size_t)size + 1);
    if (!sources[i] || fread(sources[i], 1, (size_t)size, f) != (size_t)size) {
      free(sources[i]);
      sources[i] = NULL;
      loaded = 0;
    } else {
      sources[i][size] = 0;
    }
    fclose(f);
    inputs[i].name = paths[i];
    inputs[i].text = sources[i];
    inputs[i].length = sources[i] ? (size_t)size : 0;
  }
  /* THE CONTROL THIS LIST NEVER HAD.  `paths` is this gate's own compiler
     input list, so it is a hand-maintained copy of an image the tree derives,
     and until now nothing asked whether it still IS that image.  On
     2026-10-02 machine_ir.nova became stage 35 of validate.nova and this list
     did not carry it, so the compile was refused with E302 and the gate
     reported `checks=3 failures=2` -- a count measured on the three assertions
     that run before the image, out of the 161 the gate actually has.  The
     control is asked BEFORE the compile, so a list that is short is named as a
     list, and not as a product refusal two stages downstream. */
  {
    char why[160];
    int closed = ng_parity_closure_is(paths[0], paths, path_count, why, sizeof why);
    CHECK(closed, closed ? "the diagnostics module list is the closure of its entry" : why);
    fprintf(stderr, "%s the diagnostics module list is the closure of %s: %s\n",
            closed ? "CLOSE-OK" : "CLOSE-NO", paths[0], closed ? "yes" : why);
  }
  CHECK(loaded, "sources load");
  compiled = loaded && nova_compile_many_v2(inputs, path_count, &artifact);
  CHECK(compiled, "modules compile");
  if (!compiled)
    fprintf(stderr, "E%u %zu:%zu %s\n", artifact.error.code, artifact.error.line,
            artifact.error.column, artifact.error.message);
  CHECK(compiled && nova_host_map(&artifact, &image), "image maps");

  if (image.memory) {
    Run r, s;
    char *text;
    uint64_t k;

    /* 1. the declared capacity is reported. */
    text = fixture_valid();
    r = collect(&image, text);
    cases++;
    checks++;
    if (r.returned || r.runtime || r.out[15] != CAPACITY) {
      failures++;
      fprintf(stderr, "FAIL capacity ret=%llu runtime=%llu capacity=%llu\n",
              (unsigned long long)r.returned, (unsigned long long)r.runtime,
              (unsigned long long)r.out[15]);
    }
    free(text);

    /* 2. a valid file yields no diagnostic at all: no phantom. */
    text = fixture_valid();
    r = collect(&image, text);
    cases++;
    checks++;
    if (r.returned || r.runtime || r.out[6] != 0 || r.out[1] != 0 ||
        r.out[14] != 0 || r.out[12] != 0) {
      failures++;
      fprintf(stderr, "FAIL clean parse parse=%llu count=%llu found=%llu\n",
              (unsigned long long)r.out[6], (unsigned long long)r.out[1],
              (unsigned long long)r.out[14]);
    }
    free(text);

    /* 3. two independent errors in one file, distinct spans. */
    r = collect(&image, SRC_TWO);
    cases++;
    checks++;
    if (r.returned || r.runtime || r.out[1] != 2 || r.out[4] != 0 ||
        r.out[5] != 1 || entry(&r, 0, 5) == entry(&r, 1, 5) ||
        entry(&r, 0, 0) != 200 || entry(&r, 1, 0) != 200) {
      failures++;
      fprintf(stderr, "FAIL two errors count=%llu codes=%llu,%llu\n",
              (unsigned long long)r.out[1], (unsigned long long)entry(&r, 0, 0),
              (unsigned long long)entry(&r, 1, 0));
    }
    expect_coherent("two errors", &r);
    expect_oracle_parity(&image, "two errors", SRC_TWO);

    /* 4. an error in declaration 1 and another in declaration 50. The
     *    offending token of "default_abi !!!" is its first '!', twelve bytes
     *    into the declaration. */
    text = fixture_far();
    r = collect(&image, text);
    cases++;
    checks++;
    if (text) {
      uint64_t first = (uint64_t)strstr(text, "default_abi") - (uint64_t)text;
      uint64_t last = last_offset(text, "default_abi");
      if (r.returned || r.runtime || r.out[1] != 2 ||
          entry(&r, 0, 5) != first + 12 || entry(&r, 1, 5) != last + 12) {
        failures++;
        fprintf(stderr,
                "FAIL far errors count=%llu starts=%llu,%llu want=%llu,%llu\n",
                (unsigned long long)r.out[1], (unsigned long long)entry(&r, 0, 5),
                (unsigned long long)entry(&r, 1, 5),
                (unsigned long long)(first + 12), (unsigned long long)(last + 12));
      }
      expect_coherent("far errors", &r);
    }
    free(text);

    /* 5. resynchronisation after a malformed statement lands on a ';'. */
    r = collect(&image, SRC_STMT);
    cases++;
    checks++;
    {
      uint64_t want =
          (uint64_t)(strstr(SRC_STMT, "? ? ?;") - SRC_STMT) + 6;
      if (r.returned || r.runtime || r.out[1] != 1 || r.out[9] != 1 ||
          r.out[8] != want || r.out[6] != 200) {
        failures++;
        fprintf(stderr,
                "FAIL statement resync count=%llu kind=%llu offset=%llu want=%llu\n",
                (unsigned long long)r.out[1], (unsigned long long)r.out[9],
                (unsigned long long)r.out[8], (unsigned long long)want);
      }
    }
    expect_oracle_parity(&image, "statement resync", SRC_STMT);

    /* 6. resynchronisation after a malformed declaration lands on the next
     *    top-level keyword head. */
    r = collect(&image, SRC_DECL);
    cases++;
    checks++;
    {
      uint64_t want = (uint64_t)(strstr(SRC_DECL, "const x") - SRC_DECL);
      if (r.returned || r.runtime || r.out[1] != 1 || r.out[9] != 2 ||
          r.out[8] != want || r.out[10] != 16) {
        failures++;
        fprintf(stderr,
                "FAIL declaration resync count=%llu kind=%llu offset=%llu "
                "keyword=%llu want=%llu\n",
                (unsigned long long)r.out[1], (unsigned long long)r.out[9],
                (unsigned long long)r.out[8], (unsigned long long)r.out[10],
                (unsigned long long)want);
      }
    }
    expect_oracle_parity(&image, "declaration resync", SRC_DECL);

    /* 7. capacity overflow is refused and counted, never silently dropped. */
    text = fixture_overflow(40);
    r = collect(&image, text);
    cases++;
    checks++;
    if (r.returned || r.runtime || r.out[1] != CAPACITY ||
        r.out[2] != 40 - CAPACITY || r.out[3] != 1 || r.out[14] != 40 ||
        r.out[4] != 0 || r.out[5] != 1) {
      failures++;
        fprintf(stderr,
                "FAIL overflow count=%llu dropped=%llu rejected=%llu found=%llu\n",
                (unsigned long long)r.out[1], (unsigned long long)r.out[2],
                (unsigned long long)r.out[3], (unsigned long long)r.out[14]);
    }
    expect_coherent("overflow", &r);
    free(text);

    /* 8. the module and target constructs duplicate the probe head and the
     *    trailing section is left unterminated: all three probes fail on a
     *    region edge and are refused, so the unbalanced section contributes
     *    no diagnostic and the list holds only the one real error. */
    r = collect(&image, SRC_TRUNC);
    cases++;
    checks++;
    if (r.returned || r.runtime || r.out[1] != 1 || r.out[14] != 1 ||
        r.out[12] != 3 || r.out[11] != 5) {
      failures++;
      fprintf(stderr,
              "FAIL truncation count=%llu probes=%llu refused=%llu found=%llu\n",
              (unsigned long long)r.out[1], (unsigned long long)r.out[11],
              (unsigned long long)r.out[12], (unsigned long long)r.out[14]);
    }
    expect_oracle_parity(&image, "truncation", SRC_TRUNC);

    /* 9. a lexical failure stops recovery: no token stream to resynchronise. */
    r = collect(&image, SRC_LEX);
    cases++;
    checks++;
    {
      Diag d;
      int failed = oracle("lex", SRC_LEX, &d);
      if (r.returned || r.runtime || r.out[1] != 1 || r.out[14] != 0 ||
          !failed || entry(&r, 0, 0) != d.code || entry(&r, 0, 5) != d.start ||
          entry(&r, 0, 3) != d.line || entry(&r, 0, 4) != d.column) {
        failures++;
        fprintf(stderr, "FAIL lexical count=%llu code=%llu oracle=%u\n",
                (unsigned long long)r.out[1], (unsigned long long)entry(&r, 0, 0),
                d.code);
      }
    }

    /* 10. two runs of the same source agree word for word. */
    {
      Run a = collect(&image, SRC_TWO);
      Run b = collect(&image, SRC_TWO);
      int same = a.returned == b.returned && a.runtime == b.runtime;
      for (k = 0; k < HEADER + 7 * CAPACITY && same; k++)
        if (a.out[k] != b.out[k])
          same = 0;
      cases++;
      checks++;
      if (!same) {
        failures++;
        fprintf(stderr, "FAIL determinism two runs differ\n");
      }
    }

    /* 11. discovery order does not change the stored order. */
    {
      Run a = collect(&image, SRC_TWO);
      Run b = collect_reverse(&image, SRC_TWO);
      int same = a.returned == 0 && b.returned == 0 && a.runtime == 0 &&
                 b.runtime == 0 && a.out[1] == b.out[1] && a.out[1] == 2;
      for (k = 0; k < HEADER + 7 * CAPACITY && same; k++)
        if (a.out[k] != b.out[k])
          same = 0;
      cases++;
      checks++;
      if (!same) {
        failures++;
        fprintf(stderr, "FAIL order independence counts %llu and %llu\n",
                (unsigned long long)a.out[1], (unsigned long long)b.out[1]);
      }
    }

    /* 12. the boundary sequence is a real forward scan of the stream. */
    {
      Run b = run_cmd(&image, CMD_RESYNC, SRC_STMT, 256);
      uint64_t semi = (uint64_t)(strstr(SRC_STMT, "? ? ?;") - SRC_STMT) + 6;
      int terminator = 0, keyword = 0, forward = 1;
      cases++;
      checks++;
      for (k = 0; k < b.out[1] && k < MAX_ROWS; k++) {
        uint64_t kind = b.out[2 + k * 4];
        uint64_t index = b.out[2 + k * 4 + 1];
        uint64_t offset = b.out[2 + k * 4 + 2];
        if (kind == 1 && offset == semi)
          terminator = 1;
        if (kind == 2)
          keyword = 1;
        if (kind < 1 || kind > 3)
          forward = 0;
        if (k && index <= b.out[2 + (k - 1) * 4 + 1])
          forward = 0;
      }
      if (b.returned || b.runtime || b.out[1] < 6 || !terminator || !keyword ||
          !forward) {
        failures++;
        fprintf(stderr,
                "FAIL boundary scan rows=%llu terminator=%d keyword=%d "
                "forward=%d\n",
                (unsigned long long)b.out[1], terminator, keyword, forward);
      }
    }

    /* 13. construct heads are the declared keywords at depth zero. */
    {
      Run b = run_cmd(&image, CMD_REGION, SRC_TWO, 256);
      static const uint64_t want_keyword[6] = {1, 2, 10, 16, 10, 16};
      static const char *want_text[6] = {"module", "target", "default_abi",
                                         "const", "default_abi", "const"};
      int ok = b.returned == 0 && b.runtime == 0 && b.out[1] == 6;
      uint64_t head[6];
      const char *cursor = SRC_TWO;
      cases++;
      checks++;
      /* the six construct heads, each the next occurrence after the last */
      for (k = 0; k < 6; k++) {
        const char *at = strstr(cursor, want_text[k]);
        head[k] = at ? (uint64_t)(at - SRC_TWO) : UINT64_MAX;
        if (at)
          cursor = at + 1;
      }
      for (k = 0; ok && k < 6; k++) {
        uint64_t begin = head[k];
        uint64_t want_end = k + 1 < 6 ? head[k + 1] : strlen(SRC_TWO);
        if (b.out[3 + k * 4] != begin || b.out[3 + k * 4 + 1] != want_end ||
            b.out[3 + k * 4 + 2] != want_keyword[k]) {
          failures++;
          fprintf(stderr,
                  "FAIL construct regions row %llu got %llu-%llu id %llu want "
                  "%llu-%llu id %llu\n",
                  (unsigned long long)k, (unsigned long long)b.out[3 + k * 4],
                  (unsigned long long)b.out[3 + k * 4 + 1],
                  (unsigned long long)b.out[3 + k * 4 + 2],
                  (unsigned long long)begin, (unsigned long long)want_end,
                  (unsigned long long)want_keyword[k]);
          ok = 0;
        }
      }
      if (!ok && b.out[1] != 6) {
        failures++;
        fprintf(stderr, "FAIL construct regions rows=%llu want 6\n",
                (unsigned long long)b.out[1]);
      }
    }

    /* 14. every single error inside the slice keeps the code and the four
     *     scratch words of validate.validate. */
    for (i = 0; i < SEM_COUNT; i++) {
      s = run_cmd(&image, CMD_SLICE, SEM_CASES[i].text, 256);
      {
        uint64_t n = s.returned == 0 && s.out[3] <= CAPACITY ? s.out[3] : 0;
        int ok = s.returned == 0 && s.runtime == 0 && n >= 1;
        uint64_t seen = 0;
        cases++;
        checks++;
        for (k = 0; k < 4; k++)
          if (s.out[8 + k] != s.out[12 + k])
            ok = 0;
        if (s.out[1] != SEM_CASES[i].code || s.out[2] != SEM_CASES[i].code ||
            s.out[6] != 0 || s.out[7] != 1 || s.out[17] != 8)
          ok = 0;
        /* the returned code must be one of the recorded diagnostics */
        for (k = 0; k < n; k++)
          if (slice_entry(&s, k, 0) == s.out[1])
            seen = 1;
        if (seen == 0)
          ok = 0;
        /* and every recorded position must be a real place in the source */
        for (k = 0; k < n; k++)
          if (offset_of(SEM_CASES[i].text, slice_entry(&s, k, 3),
                        slice_entry(&s, k, 4)) != slice_entry(&s, k, 5))
            ok = 0;
        if (!ok) {
          failures++;
          fprintf(stderr, "FAIL slice %s slice=%llu reference=%llu count=%llu\n",
                  SEM_CASES[i].name, (unsigned long long)s.out[1],
                  (unsigned long long)s.out[2], (unsigned long long)s.out[3]);
        }
      }
    }

    /* 15. two independent failures inside the slice, both reported, source
     *     order, distinct spans, code of the first pass in pipeline order. */
    s = run_cmd(&image, CMD_SLICE, SRC_SEM_PAIR, 256);
    cases++;
    checks++;
    {
      int ok = s.returned == 0 && s.runtime == 0 && s.out[3] == 2 &&
               s.out[6] == 0 && s.out[7] == 1 && s.out[1] == 347 &&
               s.out[2] == 347 && slice_entry(&s, 0, 0) == 341 &&
               slice_entry(&s, 1, 0) == 347 && slice_entry(&s, 0, 3) == 3 &&
               slice_entry(&s, 1, 3) == 5;
      for (k = 0; k < 4; k++)
        if (s.out[8 + k] != s.out[12 + k])
          ok = 0;
      if (ok && (slice_entry(&s, 0, 5) >= slice_entry(&s, 1, 5) ||
                 offset_of(SRC_SEM_PAIR, slice_entry(&s, 0, 3),
                           slice_entry(&s, 0, 4)) != slice_entry(&s, 0, 5) ||
                 offset_of(SRC_SEM_PAIR, slice_entry(&s, 1, 3),
                           slice_entry(&s, 1, 4)) != slice_entry(&s, 1, 5)))
        ok = 0;
      if (!ok) {
        failures++;
        fprintf(stderr,
                "FAIL slice independence count=%llu codes=%llu,%llu slice=%llu\n",
                (unsigned long long)s.out[3],
                (unsigned long long)slice_entry(&s, 0, 0),
                (unsigned long long)slice_entry(&s, 1, 0),
                (unsigned long long)s.out[1]);
      }
    }

    /* 16. a second independent pair, where one failure is a duplicate name */
    s = run_cmd(&image, CMD_SLICE, SRC_SEM_TWO, 256);
    cases++;
    checks++;
    {
      uint64_t n = s.returned == 0 && s.out[3] <= CAPACITY ? s.out[3] : 0;
      int has_300 = 0, has_347 = 0, distinct = 1;
      uint64_t at_300 = 0, at_347 = 0;
      if (n < 2 || s.out[1] != 300 || s.out[2] != 300 || s.out[6] != 0 ||
          s.out[7] != 1)
        distinct = 0;
      for (k = 0; k < n; k++) {
        if (slice_entry(&s, k, 0) == 300) {
          has_300 = 1;
          at_300 = slice_entry(&s, k, 5);
        }
        if (slice_entry(&s, k, 0) == 347) {
          has_347 = 1;
          at_347 = slice_entry(&s, k, 5);
        }
      }
      if (!has_300 || !has_347 || at_300 == at_347)
        distinct = 0;
      for (k = 0; k < 4; k++)
        if (s.out[8 + k] != s.out[12 + k])
          distinct = 0;
      if (!distinct) {
        failures++;
        fprintf(stderr, "FAIL slice pair count=%llu slice=%llu\n",
                (unsigned long long)s.out[3], (unsigned long long)s.out[1]);
      }
    }

    /* 16. a failure past the slice leaves the slice empty. */
    s = run_cmd(&image, CMD_SLICE, SRC_SEM_OUTSIDE, 256);
    cases++;
    checks++;
    if (s.returned || s.runtime || s.out[1] != 0 || s.out[2] != 310 ||
        s.out[3] != 0) {
      failures++;
      fprintf(stderr, "FAIL slice boundary slice=%llu reference=%llu count=%llu\n",
              (unsigned long long)s.out[1], (unsigned long long)s.out[2],
              (unsigned long long)s.out[3]);
    }

    /* 17. a short result buffer and an unusable source are both refused
     *     without a write. */
    {
      int untouched = 1;
      Run short_buffer = run_cmd(&image, CMD_COLLECT, SRC_TWO, MIN_WORDS - 1);
      Run bad_source = run_cmd(&image, CMD_SLICE, "target x86_64-nexora-none\n", 256);
      for (k = 1; k < 256; k++)
        if (short_buffer.out[k] != guard)
          untouched = 0;
      cases++;
      checks++;
      if (short_buffer.returned != 800 || short_buffer.runtime || !untouched ||
          short_buffer.out[0] != CMD_COLLECT || bad_source.returned != 800 ||
          bad_source.runtime || bad_source.out[0] != CMD_SLICE ||
          bad_source.out[1] != guard) {
        failures++;
        fprintf(stderr, "FAIL refusal short=%llu untouched=%d bad=%llu\n",
                (unsigned long long)short_buffer.returned, untouched,
                (unsigned long long)bad_source.returned);
      }
    }

    /* 18. the probe accounting is self consistent. */
    r = collect(&image, SRC_TWO);
    cases++;
    checks++;
    if (r.returned || r.runtime || r.out[11] != 6 || r.out[13] > PROBE_CAPACITY ||
        r.out[13] > r.out[14] || r.out[14] > r.out[11]) {
      failures++;
      fprintf(stderr, "FAIL probe accounting probes=%llu stashed=%llu found=%llu\n",
              (unsigned long long)r.out[11], (unsigned long long)r.out[13],
              (unsigned long long)r.out[14]);
    }

    /* 19. A10: the four diagnostic families, on complete sources, through
     *     the real thirty four stage pipeline. */
    for (i = 0; i < A10_COUNT; i++)
      expect_family(&image, &A10_CASES[i]);

    /* 20. the section family, measured by what is NOT refused. */
    expect_accepted(&image, "cross section call", A10_CROSS_SECTION);
    expect_accepted(&image, "data is payload only", A10_DATA_PAYLOAD);

    /* 21. 346: the gate case the spec says does not exist, as a case of
     *     non reachability. */
    expect_unreachable_346(&image, A10_TWO_TARGETS);

    /* 22. the substrate's declared reach, measured on one row per family
     *     that sits past the eighth stage. */
    for (i = 0; i < 3; i++)
      expect_slice_blind(&image, A10_SLICE_BLIND_NAME[i], A10_SLICE_BLIND[i],
                         A10_SLICE_BLIND_CODE[i]);
  }

  if (image.memory)
    nova_host_unmap(&image);
  if (compiled)
    nt_artifact_free(&artifact);
  for (i = 0; i < path_count; i++)
    free(sources[i]);
  printf("NTASM_NOVA_DIAGNOSTICS checks=%u failures=%u cases=%u\n", checks,
         failures, cases);
  return failures ? 1 : 0;
}
