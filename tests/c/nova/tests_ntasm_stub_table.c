/* Structured stub declarations, spec/ntasm/ntasm.md section 11: the Nova declaration
 * pass, the canonical generated-stub lowering, and the exact boundary between
 * the two interrupt witness profiles the backend proves and everything a
 * general generator would still need. Where the C reference in
 * compiler/c/ntasm/frontend/frontend.c can express a case, nt_frontend_compile is
 * run on the same source and its verdict, and for the positive cases the body
 * it generated, are compared step by step. Where it cannot express the case,
 * the comment on that case says so and only the Nova side is asserted; no
 * expectation is ever derived from Nova output.
 *
 * The 305 refusal vocabulary is confronted with the oracle reason by reason.
 * stub_table.nova answers a refused declaration with a reason in out[2]; the C
 * front-end answers the same declaration with a diagnostic of its own, and
 * this gate now compares the two answers directly: for every reason the
 * declaration pass can publish, the diagnostic class and the diagnostic
 * wording the oracle produces on the same source are recorded and re-measured
 * on every run, so a reason renamed in the tree and a C diagnostic
 * reclassified or reworded both red the gate. A witness the oracle accepts is
 * a measured absence, not a guess: the reason has no C counterpart, and the
 * gate requires the oracle to publish no diagnostic at all on it. The
 * retained accept/refuse bit is not replaced by any of this, it is widened:
 * every witness still goes through refuse/accept, and the class and the
 * wording are compared in addition to the bit. The reason set is closed twice
 * over, once against the literals stub_table.nova publishes and once against a
 * sweep of counter-values per field, so a reason that exists in the tree with
 * no row here, and a reason that is reachable but unregistered, are both
 * failures. Where the two vocabularies disagree, the disagreement is declared
 * with the way they disagree and confronted from both sides, so a new
 * disagreement and a stale declaration both fail instead of passing as
 * agreement. */
#include "../../../compiler/c/ntasm/frontend/frontend.h"
#include "../../../compiler/c/ntasm/backend/codegen.h"
#include "../../../compiler/c/ntasm/backend/x64.h"
#include "../../../compiler/c/nova/pe/pe_oracle.h"
#include "../../../compiler/c/nova/frontend/nova.h"
#include "../../../compiler/c/nova/runtime/run_host.h"
#include "ng_run_dir.h"
#include "../../../compiler/c/nova/runtime/runtime_v2.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static unsigned checks, failures, cases;
#define CHECK(c, m)                                                            \
  do {                                                                         \
    checks++;                                                                  \
    if (!(c)) {                                                                \
      failures++;                                                              \
      fprintf(stderr, "FAIL %s\n", m);                                        \
    }                                                                          \
  } while (0)

#define OUT_WORDS 8192
static const uint64_t guard = UINT64_C(0xcccccccccccccccc);
static uint64_t out_words[OUT_WORDS];

static const char *const HEAD = "module stubs\ntarget x86_64-nexora-none\n";
/* The section block every fixture ends with. A structured syscall stub calls a
 * handler that must be a declared callable, so the handler lives here and the
 * one case that needs a clobbering handler asks for a different block. */
static const char *const TAIL =
    "section .text {\nfn main()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";

/* ------------------------------------------------------------------ helpers */

static char *dup_string(const char *text) {
  size_t n = strlen(text) + 1;
  char *copy = (char *)malloc(n);
  if (copy) memcpy(copy, text, n);
  return copy;
}

static char *join3(const char *a, const char *b, const char *c) {
  size_t n = strlen(a) + strlen(b) + strlen(c) + 1;
  char *out = (char *)malloc(n);
  if (out) snprintf(out, n, "%s%s%s", a, b, c);
  return out;
}

/* The module head, one stub table body and the section block. */
static char *assemble(const char *body, const char *section) {
  return join3(HEAD, body, section ? section : TAIL);
}

/* A section block declaring main and the handler, the handler clobbering the
 * set given. */
static char *section_block(const char *handler_clobbers) {
  static char buffer[512];
  snprintf(buffer, sizeof buffer,
           "section .text {\nfn main()->u64\neffects {}\nclobbers {} {\n"
           "return 0\n}\nfn dispatch()->u64\neffects {}\nclobbers %s {\n"
           "return 42\n}\n}\n",
           handler_clobbers);
  return dup_string(buffer);
}

/* One stub entry carrying the fifteen fields the parser requires, in order. */
static char *entry(const char *key, const char *handler, const char *entry_abi,
                   const char *exit_abi, const char *exit_policy,
                   const char *frame, const char *error, const char *save,
                   const char *clobbers, const char *align, const char *swapgs,
                   const char *interrupts, const char *section,
                   const char *visibility, const char *symbol) {
  static char buffer[1024];
  snprintf(buffer, sizeof buffer,
           "stub %s {\nhandler %s\nentry_abi %s\nexit_abi %s\nexit %s\n"
           "frame %s\nbindings {}\nhardware_error_code %s\nsave %s\n"
           "clobbers %s\nstack_align %s\nswapgs %s\ninterrupts %s\n"
           "section %s\nvisibility %s\nsymbol %s\n}\n",
           key, handler, entry_abi, exit_abi, exit_policy, frame, error, save,
           clobbers, align, swapgs, interrupts, section, visibility, symbol);
  return dup_string(buffer);
}

/* A stub table body holding one entry. */
static char *table_one(const char *kind, const char *key, const char *handler,
                       const char *entry_abi, const char *exit_abi,
                       const char *exit_policy, const char *frame,
                       const char *error, const char *save,
                       const char *clobbers, const char *align,
                       const char *swapgs, const char *interrupts,
                       const char *section, const char *visibility,
                       const char *symbol) {
  static char buffer[2048];
  char *one = entry(key, handler, entry_abi, exit_abi, exit_policy, frame, error,
                    save, clobbers, align, swapgs, interrupts, section,
                    visibility, symbol);
  if (!one) return NULL;
  snprintf(buffer, sizeof buffer, "stub_table t kind %s {\n%s}\n", kind, one);
  free(one);
  return dup_string(buffer);
}

/* A stub table body holding two entries, in the order given. */
static char *table_two(const char *kind, const char *first, const char *second) {
  static char buffer[4096];
  snprintf(buffer, sizeof buffer, "stub_table t kind %s {\n%s%s}\n", kind, first,
           second);
  return dup_string(buffer);
}

/* A stub table body holding `count` structured syscall entries numbered from
 * zero, each generating its own symbol. Used for the entry-limit boundary. */
static char *table_many(unsigned count) {
  size_t n = (size_t)count * 384 + 4096;
  char *body = (char *)malloc(n);
  if (!body) return NULL;
  size_t used = (size_t)snprintf(body, n, "stub_table t kind syscall {\n");
  for (unsigned i = 0; i < count; i++) {
    char key[16];
    char symbol[32];
    snprintf(key, sizeof key, "%u", i);
    snprintf(symbol, sizeof symbol, "syscall_stub_%u", i);
    char *one = entry(key, "dispatch", "nx64-abi-v0", "nx64-abi-v0", "return",
                      "syscall.frame", "false", "{}", "{}", "16", "never",
                      "preserve", ".text", "export", symbol);
    if (!one) {
      free(body);
      return NULL;
    }
    used += (size_t)snprintf(body + used, n - used, "%s", one);
    free(one);
  }
  snprintf(body + used, n - used, "}\n");
  return body;
}

/* The frozen field values of the three proven profiles, as macro argument
 * lists, so a case only spells out the field it varies. */
#define UD_BODY                                                                    \
  "advance_saved_rip_2", "nx64-interrupt-same-cpl-v0",                           \
      "nx64-iretq-same-cpl-v0", "iretq", "x86_64.frame.no_error.same_cpl",       \
      "false", "{rax}", "{}", "0", "never", "preserve", ".text", "export"
#define GP_BODY                                                                    \
  "advance_saved_rip_2", "nx64-interrupt-same-cpl-error-v0",                     \
      "nx64-iretq-same-cpl-error-v0", "iretq", "x86_64.frame.error.same_cpl",     \
      "true", "{rax}", "{}", "0", "never", "preserve", ".text", "export"
#define SYSCALL_BODY                                                               \
  "dispatch", "nx64-abi-v0", "nx64-abi-v0", "return", "syscall.frame", "false",   \
      "{}", "{}", "16", "never", "preserve", ".text", "export"

static char *ud_entry(const char *key, const char *symbol) {
  return entry(key, UD_BODY, symbol);
}
static char *gp_entry(const char *key, const char *symbol) {
  return entry(key, GP_BODY, symbol);
}
static char *syscall_entry(const char *key, const char *symbol) {
  return entry(key, SYSCALL_BODY, symbol);
}
static char *interrupt_ud(const char *key, const char *symbol) {
  return table_one("interrupt", key, UD_BODY, symbol);
}
static char *interrupt_gp(const char *key, const char *symbol) {
  return table_one("interrupt", key, GP_BODY, symbol);
}
static char *syscall_table(const char *key, const char *symbol) {
  return table_one("syscall", key, SYSCALL_BODY, symbol);
}

/* One-based line and column of a byte offset inside the source. */
static int offset_position(const char *source, const char *at, uint64_t *line,
                           uint64_t *column) {
  if (at < source) return 0;
  uint64_t l = 1, c = 1;
  for (const char *p = source; p < at; p++) {
    if (*p == '\n') {
      l++;
      c = 1;
    } else {
      c++;
    }
  }
  *line = l;
  *column = c;
  return 1;
}

/* One-based line and column of the first occurrence of needle. */
static int locate(const char *source, const char *needle, uint64_t *line,
                  uint64_t *column) {
  const char *at = strstr(source, needle);
  if (!at) return 0;
  return offset_position(source, at, line, column);
}

/* One-based line and column of the keyword of the nth `stub <key>` entry,
 * counting from one. */
static int locate_stub(const char *source, const char *key, unsigned nth,
                       uint64_t *line, uint64_t *column) {
  char needle[64];
  snprintf(needle, sizeof needle, "stub %s ", key);
  const char *at = source;
  for (unsigned i = 1; i <= nth; i++) {
    at = strstr(at, needle);
    if (!at) return 0;
    if (i < nth) at += strlen(needle);
  }
  return offset_position(source, at, line, column);
}

/* --------------------------------------------------------------- the runs */

typedef struct {
  uint64_t returned, runtime;
  const uint64_t *out;
} Run;

static Run run_mode(const NovaHostImage *image, const char *source,
                    uint64_t words, uint64_t mode, uint64_t index) {
  Run result;
  for (unsigned i = 0; i < OUT_WORDS; i++) out_words[i] = guard;
  if (words > 5) {
    out_words[4] = mode;
    out_words[5] = index;
  }
  NovaContextV2 context;
  memset(&context, 0, sizeof context);
  result.returned = UINT64_MAX;
  result.runtime = UINT64_MAX;
  result.out = out_words;
  if (!nova_context_init_v2(&context)) return result;
  uint64_t source_handle =
      nova_borrow_v2(&context, (void *)source, strlen(source), 0);
  uint64_t out_handle =
      nova_borrow_v2(&context, out_words, words * sizeof(uint64_t), 1);
  uint64_t args[] = {source_handle, strlen(source), out_handle, words};
  result.returned = image->entry(&context, args, 4);
  result.runtime = context.error;
  CHECK(nova_context_destroy_v2(&context), "context cleanup");
  return result;
}

static Run run(const NovaHostImage *image, const char *source, uint64_t words,
               uint64_t mode) {
  return run_mode(image, source, words, mode, 0);
}

/* The plan of one record through the query channel, which answers what the
 * generator derives from a declaration even when no proven profile covers it.
 * The expected plan is spelled out here from the declaration, because the C
 * reference cannot express these cases at all. */
static void plan_query(const NovaHostImage *image, const char *name,
                       const char *source, uint64_t index, uint64_t kind,
                       uint64_t key, uint64_t frame, uint64_t steps,
                       uint64_t saves, const uint64_t (*want)[3],
                       unsigned want_rows) {
  Run r = run_mode(image, source, OUT_WORDS, 3, index);
  cases++;
  checks++;
  int bad = r.returned || r.runtime || r.out[0] != kind || r.out[1] != key ||
            r.out[2] != frame || r.out[3] != steps || r.out[4] || r.out[5] != saves;
  for (unsigned i = 0; !bad && i < want_rows; i++)
    if (out_words[12 + i * 3] != want[i][0] ||
        out_words[12 + i * 3 + 1] != want[i][1] ||
        out_words[12 + i * 3 + 2] != want[i][2])
      bad = 1;
  if (bad) {
    failures++;
    fprintf(stderr,
            "FAIL plan_query %s ret=%llu out=%llu,%llu,%llu,%llu saves=%llu\n",
            name, (unsigned long long)r.returned, (unsigned long long)r.out[0],
            (unsigned long long)r.out[1], (unsigned long long)r.out[2],
            (unsigned long long)r.out[3], (unsigned long long)r.out[5]);
    for (unsigned i = 0; i < want_rows; i++)
      fprintf(stderr, "  step %u got %llu,%llu,%llu want %llu,%llu,%llu\n", i,
              (unsigned long long)out_words[12 + i * 3],
              (unsigned long long)out_words[12 + i * 3 + 1],
              (unsigned long long)out_words[12 + i * 3 + 2],
              (unsigned long long)want[i][0], (unsigned long long)want[i][1],
              (unsigned long long)want[i][2]);
    fprintf(stderr, "  source:\n%s\n", source);
  }
}

/* The C reference verdict for the same source, 1 when it accepts. */
static int c_verdict(const char *source, NtFProgram *out) {
  NtFInput input = {"oracle", source, strlen(source)};
  return nt_frontend_compile(&input, 1, out);
}

static void report_c(const char *name, const NtFProgram *c) {
  for (size_t i = 0; i < c->diagnostic_count; i++)
    fprintf(stderr, "  %s C E%u %u:%u %s\n", name, c->diagnostics[i].code,
            c->diagnostics[i].span.line, c->diagnostics[i].span.column,
            c->diagnostics[i].message);
}

/* One-based line and column of the value node of a stub field: the bytes
 * after the field keyword, past `skip` leading bytes of the value itself. The
 * keyword must be a whole word, so `exit` never matches inside `exit_abi` and
 * `save` never matches inside `advance_saved_rip_2`. A section value is
 * `.name`, and the node the diagnostic points at is the name, so its case
 * skips the dot. The expected text is verified, which keeps the expectation
 * tied to the fixture rather than to a column arithmetic. */
static int locate_field(const char *source, const char *field,
                        const char *expected, unsigned skip, uint64_t *line,
                        uint64_t *column) {
  size_t width = strlen(field);
  const char *at = source;
  for (;;) {
    at = strstr(at, field);
    if (!at) return 0;
    if (at[width] == ' ' || at[width] == '\t' || at[width] == '\n') break;
    at += width;
  }
  at += width;
  while (*at == ' ' || *at == '\t') at++;
  at += skip;
  if (strncmp(at, expected, strlen(expected)) != 0) return 0;
  return offset_position(source, at, line, column);
}

/* A refusal whose diagnostic points at the value node of a stub field. The
 * marker is the field keyword, a space, then the exact bytes of the value
 * node, optionally prefixed with "+N" to skip N bytes of the value before the
 * node starts: a register set value is "{rax}" and the node inside it is the
 * name, a section value is ".text" and its node is the name after the dot. A
 * marker without a space is looked up as plain text, which is how the
 * table-level diagnostics are located. */
static int marker_position(const char *source, const char *marker,
                           uint64_t *line, uint64_t *column) {
  const char *space = strchr(marker, ' ');
  if (!space) return locate(source, marker, line, column);
  char field[32];
  size_t n = (size_t)(space - marker);
  if (n >= sizeof field) return 0;
  memcpy(field, marker, n);
  field[n] = 0;
  const char *expected = space + 1;
  unsigned skip = 0;
  if (expected[0] == '+') {
    expected++;
    while (*expected >= '0' && *expected <= '9') {
      skip = skip * 10 + (unsigned)(*expected - '0');
      expected++;
    }
  }
  return locate_field(source, field, expected, skip, line, column);
}

/* --------------------------------------------------------------- assertions */

/* c_state: 1 the C must accept, 0 the C must refuse, -1 not consulted. */
static void refuse(const NovaHostImage *image, const char *name,
                   const char *source, uint64_t mode, uint64_t code,
                   uint64_t reason, const char *marker, uint64_t detail,
                   int c_state) {
  uint64_t line = 0, column = 0;
  int positioned = marker ? marker_position(source, marker, &line, &column) : 0;
  if (marker && !positioned) {
    checks++;
    failures++;
    fprintf(stderr, "FAIL fixture marker not found for %s: %s\n", name, marker);
  }
  NtFProgram c;
  memset(&c, 0, sizeof c);
  int c_ok = c_state < 0 ? 0 : c_verdict(source, &c);
  Run r = run(image, source, 64, mode);
  cases++;
  checks++;
  int bad = r.returned != code || r.runtime != 0;
  if (!bad && code == 305)
    bad = r.out[2] != reason || r.out[3] != detail ||
          (positioned && (r.out[0] != line || r.out[1] != column));
  if (!bad && code == 306) bad = r.out[2] != reason;
  if (!bad && code == 800) bad = r.out[0] != guard;
  if (!bad && c_state >= 0) bad = (c_ok != 0) != (c_state != 0);
  if (bad) {
    failures++;
    fprintf(stderr,
            "FAIL refuse %s ret=%llu runtime=%llu out=%llu,%llu,%llu,%llu "
            "want code=%llu reason=%llu at=%llu:%llu detail=%llu c=%d\n",
            name, (unsigned long long)r.returned,
            (unsigned long long)r.runtime, (unsigned long long)r.out[0],
            (unsigned long long)r.out[1], (unsigned long long)r.out[2],
            (unsigned long long)r.out[3], (unsigned long long)code,
            (unsigned long long)reason, (unsigned long long)line,
            (unsigned long long)column, (unsigned long long)detail,
            c_state < 0 ? -1 : c_ok);
    fprintf(stderr, "  source:\n%s\n", source);
  }
  if (c_state >= 0) {
    report_c(name, &c);
    nt_frontend_free(&c);
  }
}

/* A refusal whose diagnostic points at the keyword of the nth `stub <key>`
 * entry, which is how the table-level key rules and the symbol rules report.
 * c_state: 1 the C must accept, 0 the C must refuse, -1 not consulted. */
static void refuse_entry(const NovaHostImage *image, const char *name,
                         const char *source, uint64_t mode, uint64_t code,
                         uint64_t reason, const char *key, unsigned nth,
                         uint64_t detail, int c_state) {
  uint64_t line = 0, column = 0;
  int positioned = locate_stub(source, key, nth, &line, &column);
  CHECK(positioned, "fixture entry located");
  NtFProgram c;
  memset(&c, 0, sizeof c);
  int c_ok = c_state < 0 ? 0 : c_verdict(source, &c);
  Run r = run(image, source, 64, mode);
  cases++;
  checks++;
  int bad = r.returned != code || r.runtime != 0 || r.out[2] != reason ||
            r.out[3] != detail || (positioned &&
                                   (r.out[0] != line || r.out[1] != column));
  if (!bad && c_state >= 0) bad = (c_ok != 0) != (c_state != 0);
  if (bad) {
    failures++;
    fprintf(stderr,
            "FAIL refuse_entry %s ret=%llu runtime=%llu out=%llu,%llu,%llu,%llu "
            "want code=%llu reason=%llu at=%llu:%llu detail=%llu c=%d\n",
            name, (unsigned long long)r.returned,
            (unsigned long long)r.runtime, (unsigned long long)r.out[0],
            (unsigned long long)r.out[1], (unsigned long long)r.out[2],
            (unsigned long long)r.out[3], (unsigned long long)code,
            (unsigned long long)reason, (unsigned long long)line,
            (unsigned long long)column, (unsigned long long)detail,
            c_state < 0 ? -1 : c_ok);
    fprintf(stderr, "  source:\n%s\n", source);
  }
  if (c_state >= 0) {
    report_c(name, &c);
    nt_frontend_free(&c);
  }
}

static void accept(const NovaHostImage *image, const char *name,
                   const char *source, uint64_t tables, uint64_t entries,
                   int c_state) {
  NtFProgram c;
  memset(&c, 0, sizeof c);
  int c_ok = c_state < 0 ? 0 : c_verdict(source, &c);
  Run r = run(image, source, 64, 0);
  cases++;
  checks++;
  int bad = r.returned || r.runtime || r.out[0] != tables ||
            r.out[1] != entries || r.out[2] || r.out[3];
  if (!bad && c_state >= 0) bad = (c_ok != 0) != (c_state != 0);
  if (bad) {
    failures++;
    fprintf(stderr,
            "FAIL accept %s ret=%llu runtime=%llu out=%llu,%llu,%llu,%llu "
            "want %llu,%llu c=%d\n",
            name, (unsigned long long)r.returned,
            (unsigned long long)r.runtime, (unsigned long long)r.out[0],
            (unsigned long long)r.out[1], (unsigned long long)r.out[2],
            (unsigned long long)r.out[3], (unsigned long long)tables,
            (unsigned long long)entries, c_state < 0 ? -1 : c_ok);
    fprintf(stderr, "  source:\n%s\n", source);
  }
  if (c_state >= 0) {
    report_c(name, &c);
    nt_frontend_free(&c);
  }
}

/* ------------------------------------------- C generated-body comparison */

static const NtFFunction *c_function(const NtFProgram *c, const char *name,
                                     size_t length) {
  for (size_t i = 0; i < c->function_count; i++) {
    const NtFFunction *fn = &c->functions[i];
    if (fn->name && strlen(fn->name) == length &&
        !memcmp(fn->name, name, length))
      return fn;
  }
  return NULL;
}

static int expr_register(const NtFExpr *x, uint64_t family) {
  return x->kind == NTF_X_REGISTER && (uint64_t)x->reg.family == family &&
         x->reg.bits == 64 && !x->reg.high8;
}

static int expr_stack(const NtFExpr *x, uint64_t displacement) {
  return x->kind == NTF_X_MEMORY && x->memory.base.family == 4 &&
         x->memory.base.bits == 64 && x->memory.index.family == -1 &&
         x->memory.scale == 1 && x->memory.segment == 0 &&
         (uint64_t)x->memory.displacement == displacement && !x->memory.symbol;
}

static int stmt_name(const NtFStmt *s, const char *name) {
  return s->kind == NTF_S_INSTRUCTION && s->name && !strcmp(s->name, name) &&
         !s->condition && !s->then_branch && !s->else_branch && !s->variable;
}

static int operands(const NtFProgram *c, const NtFStmt *s, const NtFExpr **a,
                    const NtFExpr **b) {
  NtFId first = s->expression;
  if (!first || (size_t)first > c->expression_count) return 0;
  const NtFExpr *x = &c->expressions[first - 1];
  NtFId second = x->next;
  if (second && ((size_t)second > c->expression_count ||
                 c->expressions[second - 1].next))
    return 0;
  *a = x;
  *b = second ? &c->expressions[second - 1] : NULL;
  return 1;
}

/* The ABI the C must have generated for this record: an interrupt stub keeps
 * the entry ABI of its frame class, a structured syscall stub the plain
 * nx64-abi-v0. */
static int abi_matches(const uint64_t *record, const char *abi) {
  if (!abi) return 0;
  if (record[0] == 2) return !strcmp(abi, "nx64-abi-v0");
  if (record[2] == 0) return !strcmp(abi, "nx64-interrupt-same-cpl-v0");
  return !strcmp(abi, "nx64-interrupt-same-cpl-error-v0");
}

/* Compare the plan of one lowered record against the body the C reference
 * generated for the same symbol, step by step. The plan register ids are the
 * one-based register_widths.family values and the C uses a zero-based
 * NtFRegister.family, so every family comparison is offset by one. */
static int plan_matches_c(const char *source, const uint64_t *out,
                          const NtFProgram *c, uint64_t index, char *why,
                          size_t why_len) {
  const uint64_t *record = out + 4 + 12 * index;
  const char *symbol = source + record[6];
  size_t symbol_length = (size_t)(record[7] - record[6]);
  const char *handler = source + record[8];
  size_t handler_length = (size_t)(record[9] - record[8]);
  const NtFFunction *fn = c_function(c, symbol, symbol_length);
  if (!fn) {
    snprintf(why, why_len, "no C function named %.*s", (int)symbol_length,
             symbol);
    return 0;
  }
  if (!abi_matches(record, fn->abi) || !fn->section ||
      strcmp(fn->section, ".text") ||
      fn->exported != (int)(record[10] & 1u)) {
    snprintf(why, why_len, "C signature of %.*s differs", (int)symbol_length,
             symbol);
    return 0;
  }
  if (!fn->body || (size_t)fn->body > c->statement_count) {
    snprintf(why, why_len, "C function %.*s has no body", (int)symbol_length,
             symbol);
    return 0;
  }
  const NtFStmt *block = &c->statements[fn->body - 1];
  if (block->kind != NTF_S_BLOCK) {
    snprintf(why, why_len, "C body of %.*s is not a block", (int)symbol_length,
             symbol);
    return 0;
  }
  uint64_t id = block->first;
  for (uint64_t i = 0; i < record[3]; i++) {
    const uint64_t *step = out + record[4] + 3 * i;
    if (!id || (size_t)id > c->statement_count) {
      snprintf(why, why_len, "C body ends before plan step %llu",
               (unsigned long long)i);
      return 0;
    }
    const NtFStmt *s = &c->statements[id - 1];
    const NtFExpr *a = NULL;
    const NtFExpr *b = NULL;
    int ok = 0;
    switch (step[0]) {
    case 1:
      ok = stmt_name(s, "push") && operands(c, s, &a, &b) && !b &&
           expr_register(a, step[1] - 1);
      break;
    case 2:
      ok = stmt_name(s, "load") && operands(c, s, &a, &b) && b &&
           expr_register(a, 0) && expr_stack(b, step[2]);
      break;
    case 3:
      ok = stmt_name(s, "add") && operands(c, s, &a, &b) && b &&
           expr_register(a, 0) && b->kind == NTF_X_LITERAL &&
           b->value == step[2] && !b->negative;
      break;
    case 4:
      ok = stmt_name(s, "store") && operands(c, s, &a, &b) && b &&
           expr_stack(a, step[1]) && expr_register(b, 0);
      break;
    case 5:
      ok = stmt_name(s, "pop") && operands(c, s, &a, &b) && !b &&
           expr_register(a, step[1] - 1);
      break;
    case 6:
      ok = stmt_name(s, "add") && operands(c, s, &a, &b) && b &&
           expr_register(a, step[1] - 1) && b->kind == NTF_X_LITERAL &&
           b->value == step[2] && !b->negative;
      break;
    case 7:
      ok = stmt_name(s, "iretq") && s->terminal && !s->expression;
      break;
    case 8:
      ok = s->kind == NTF_S_RETURN && s->terminal && operands(c, s, &a, &b) &&
           !b && a->kind == NTF_X_CALL && a->name &&
           strlen(a->name) == handler_length &&
           !memcmp(a->name, handler, handler_length);
      break;
    default:
      snprintf(why, why_len, "unknown plan opcode %llu",
               (unsigned long long)step[0]);
      return 0;
    }
    if (!ok) {
      snprintf(why, why_len, "plan step %llu does not match the C body",
               (unsigned long long)i);
      return 0;
    }
    id = s->next;
  }
  if (id) {
    snprintf(why, why_len, "C body is longer than the plan");
    return 0;
  }
  return 1;
}

/* Lower the source, check the records, then compare each plan with the body
 * the C generated when the C could express the case. */
static void lower_plan(const NovaHostImage *image, const char *name,
                       const char *source, uint64_t records, uint64_t steps,
                       const uint64_t *keys, const uint64_t *frames,
                       const uint64_t *step_counts, int compare_c) {
  NtFProgram c;
  memset(&c, 0, sizeof c);
  int c_ok = compare_c ? c_verdict(source, &c) : 0;
  Run r = run(image, source, OUT_WORDS, 2);
  cases++;
  checks++;
  int bad = r.returned || r.runtime || r.out[0] != 1 || r.out[1] != records ||
            r.out[2] != steps || r.out[3];
  for (uint64_t i = 0; !bad && i < records; i++) {
    const uint64_t *record = out_words + 4 + 12 * i;
    if (record[1] != keys[i] || record[2] != frames[i] ||
        record[3] != step_counts[i] || record[11] || record[0] != keys[i] + 0)
      if (record[1] != keys[i] || record[2] != frames[i] ||
          record[3] != step_counts[i] || record[11])
        bad = 1;
  }
  if (!bad && compare_c) {
    if (!c_ok) bad = 1;
    for (uint64_t i = 0; !bad && i < records; i++) {
      char why[160];
      why[0] = 0;
      if (!plan_matches_c(source, out_words, &c, i, why, sizeof why)) {
        bad = 1;
        fprintf(stderr, "  %s record %llu: %s\n", name,
                (unsigned long long)i, why);
      }
    }
  }
  if (bad) {
    failures++;
    fprintf(stderr,
            "FAIL lower %s ret=%llu runtime=%llu out=%llu,%llu,%llu c=%d\n", name,
            (unsigned long long)r.returned, (unsigned long long)r.runtime,
            (unsigned long long)r.out[0], (unsigned long long)r.out[1],
            (unsigned long long)r.out[2], compare_c ? c_ok : -1);
    fprintf(stderr, "  source:\n%s\n", source);
  }
  if (compare_c) {
    report_c(name, &c);
    nt_frontend_free(&c);
  }
}

/* ================= the 305 reason vocabulary, confronted with the oracle === */

/* The frozen fields of the three proven profiles, in the order the entry
 * builder writes them: key, handler, entry_abi, exit_abi, exit, frame,
 * hardware_error_code, save, clobbers, stack_align, swapgs, interrupts,
 * section, visibility, symbol. Bindings is the empty set in every generated
 * stub and the builder always writes it, so it is not a slot here. */
static const char *const UD_FIELDS[15] = {
    "6",  "advance_saved_rip_2",  "nx64-interrupt-same-cpl-v0",
    "nx64-iretq-same-cpl-v0",    "iretq",
    "x86_64.frame.no_error.same_cpl", "false",
    "{rax}", "{}", "0",  "never", "preserve", ".text", "export", "isr"};
static const char *const GP_FIELDS[15] = {
    "13", "advance_saved_rip_2",  "nx64-interrupt-same-cpl-error-v0",
    "nx64-iretq-same-cpl-error-v0", "iretq",
    "x86_64.frame.error.same_cpl", "true",
    "{rax}", "{}", "0",  "never", "preserve", ".text", "export", "isr13"};
static const char *const SY_FIELDS[15] = {
    "0",   "dispatch", "nx64-abi-v0", "nx64-abi-v0",
    "return", "syscall.frame", "false",
    "{}", "{}", "16", "never", "preserve", ".text", "export", "entry0"};

/* The entry of `base` with one field ordinal replaced, and optionally with
 * another key and another symbol. Ordinal 255 leaves the profile alone. The
 * caller frees the result. */
static char *fields_entry(const char *const base[15], unsigned ordinal,
                          const char *value, const char *key,
                          const char *symbol) {
  const char *copy[15];
  if (!base) return NULL;
  for (unsigned i = 0; i < 15; i++) copy[i] = base[i];
  if (ordinal != 255) {
    if (!value || ordinal > 14) return NULL;
    copy[ordinal] = value;
  }
  if (key) copy[0] = key;
  if (symbol) copy[14] = symbol;
  return entry(copy[0], copy[1], copy[2], copy[3], copy[4], copy[5], copy[6],
               copy[7], copy[8], copy[9], copy[10], copy[11], copy[12],
               copy[13], copy[14]);
}

/* A one-entry table of the same shape, and the table body with its one
 * `bindings {}` field replaced, which is the only field the entry builder
 * cannot vary. The caller frees every result. */
static char *fields_table(const char *kind, const char *const base[15],
                          unsigned ordinal, const char *value, const char *key,
                          const char *symbol) {
  static char buffer[4096];
  char *one = fields_entry(base, ordinal, value, key, symbol);
  if (!one) return NULL;
  /* A truncated fixture would silently stop exercising the field it varies, so
   * an oversized one is a build failure and the row reds, not a shorter
   * declaration. */
  int written = snprintf(buffer, sizeof buffer, "stub_table t kind %s {\n%s}\n",
                         kind, one);
  free(one);
  if (written < 0 || (size_t)written >= sizeof buffer) return NULL;
  return dup_string(buffer);
}
static char *bind_table(const char *body, const char *field) {
  static const char empty[] = "bindings {}";
  const char *at = body ? strstr(body, empty) : NULL;
  if (!at) return NULL;
  size_t n = strlen(body) + strlen(field) + 16;
  char *bigger = (char *)malloc(n);
  if (!bigger) return NULL;
  snprintf(bigger, n, "%.*s%s%s", (int)(at - body), body, field,
           at + sizeof empty - 1);
  return bigger;
}

/* One witness row per reason and per profile that names it differently, plus
 * the declarations the two vocabularies disagree about. The reason is the
 * value stub_table.nova must publish in out[2]; LEGAL is the sentinel of a
 * row whose declaration is legal in Nova, so the declaration pass must answer
 * 0 there and the whole row is a measured divergence. The class and the
 * wording are the answer the C front-end gives on that same declaration, both
 * read out of the NtFProgram nt_frontend_compile returned and never out of the
 * C source, and both compared again on every run. A class of zero records a
 * measured absence: the oracle accepts the witness, so the rule has no C
 * counterpart at all and the gate requires the oracle to publish no diagnostic
 * on it. `rule` names the rule so a red names the reason. */
#define LEGAL UINT64_MAX
typedef struct {
  uint64_t reason;
  unsigned c_code;
  const char *c_message;
  const char *rule;
  const char *witness;
} ReasonRow;

static const ReasonRow REASONS[] = {
    {1, 600, "only safe-return syscall stub tables are implemented",
     "stub table kind is neither interrupt nor syscall", "kind timer"},
    {2, 200, "interrupt table requires at least one stub",
     "interrupt table declares no entry", "empty interrupt table"},
    {3, 300, "duplicate stub number", "key declared twice in one syscall table",
     "two syscall entries keyed 0"},
    {3, 300, "duplicate interrupt vector 6",
     "key declared twice in one interrupt table", "two #UD entries"},
    {4, 201, "stub table entry limit exceeded",
     "entry count past the table capacity", "the 513th syscall entry"},
    {5, 503, "witness profiles support only #UD vector 6 or #GP vector 13",
     "interrupt key outside the eight bit vector range", "#UD at vector 300"},
    {6, 403, "unsupported structured stub ABI",
     "entry ABI outside the frozen syscall profile", "alien-abi-v0 on syscall"},
    {6, 403, "interrupt witness ABI mismatch",
     "entry or exit ABI outside the frozen interrupt profile",
     "alien-abi-v0 on #UD"},
    {7, 600, "only safe return structured stubs are implemented",
     "exit policy outside the frozen syscall profile", "sysretq on syscall"},
    {7, 503, "interrupt witness exit must be iretq",
     "exit policy outside the frozen interrupt profile", "iretd on #UD"},
    {8, 503, "unknown structured stub frame",
     "frame outside the frozen syscall profile", "alien.frame on syscall"},
    {8, 503, "interrupt frame mismatch",
     "frame outside the frozen interrupt profile", "alien.frame on #UD"},
    {9, 503, "#UD must not declare a hardware error code",
     "error code contradicts the frame of an interrupt stub",
     "error true on #UD"},
    {9, 503, "safe return stub cannot consume hardware error code",
     "error code contradicts the frame of a syscall stub",
     "error true on syscall"},
    {10, 403, "structured stub requires stack_align 16",
     "stack alignment the syscall profile does not admit", "align 0 on syscall"},
    {10, 403, "raw interrupt witness requires stack_align 0",
     "stack alignment the interrupt profile does not admit",
     "align 16 on #UD"},
    {11, 503, "same-CPL witness requires swapgs never",
     "swapgs policy outside the frozen interrupt profile", "always on #UD"},
    {11, 503, "safe return stub requires swapgs never",
     "swapgs policy outside the frozen syscall profile", "always on syscall"},
    {12, 503, "interrupt witness must preserve interrupt policy",
     "interrupt policy outside the frozen interrupt profile",
     "disable on #UD"},
    {12, 503, "safe return stub requires interrupt preservation",
     "interrupt policy outside the frozen syscall profile", "disable on syscall"},
    {13, 200, "expected 'text'", "section outside the frozen interrupt profile",
     ".data on #UD"},
    {13, 503, "structured executable stub must use .text",
     "section outside the frozen syscall profile", ".data on syscall"},
    {14, 503, "invalid interrupt visibility",
     "visibility outside the frozen interrupt profile", "hidden on #UD"},
    {14, 503, "invalid stub visibility",
     "visibility outside the frozen syscall profile", "hidden on syscall"},
    {15, 300, "duplicate stub symbol 'entry0'",
     "two generated stubs publishing the same symbol",
     "keys 0 and 1 both named entry0"},
    {15, 300, "duplicate function 'entry0'",
     "a generated symbol colliding with a declared function",
     "a stub named entry0 over a declared entry0"},
    {16, 0, NULL, "a key gap inside one table", "syscall keys 0 and 2"},
    {16, 0, NULL, "a key gap inside one table", "#UD 6 then #GP 13"},
    {17, 502, "function 'entry0' omits an inferred clobber",
     "a handler clobbers outside the save set", "dispatch clobbering rbx"},
    {18, 301, "unknown function 'ghost'",
     "a syscall handler that is not a declared callable", "handler ghost"},
    {19, 200, "only empty set is supported",
     "a generated stub that binds a material parameter", "bindings {a:u64 @rcx}"},
    {20, 200, "only empty set is supported",
     "a generated stub that declares a clobber", "clobbers {rbx}"},
    {21, 200, "expected 'rax'", "an interrupt stub that saves nothing",
     "save {} on #UD"},
    {21, 200, "only empty set is supported",
     "a syscall stub that saves a register", "save {rbx} on syscall"},
    {22, 200, "expected 'rax'", "an unspellable register in the save set",
     "save {foo}"},
    {22, 200, "witness save set must be {rax}",
     "a save set wider than the save area", "save of seventeen registers"},
    {23, 503, "interrupt witness handler policy must advance_saved_rip_2",
     "an interrupt handler that is no advance policy",
     "handler rewind_saved_rip_2"},
    {23, 503, "interrupt witness handler policy must advance_saved_rip_2",
     "a handler policy whose advance is a leading zero",
     "handler advance_saved_rip_0"},
    {LEGAL, 503, "interrupt witness handler policy must advance_saved_rip_2",
     "a handler policy the C witness does not admit, and Nova admits",
     "handler advance_saved_rip_4"},
};
#define REASON_ROWS ((unsigned)(sizeof REASONS / sizeof REASONS[0]))

/* The declaration each row is measured on, and the section block it needs or
 * NULL for the default one. Both are heap strings the caller frees. */
static int reason_fixture(unsigned row, char **body, char **section) {
  static const char seventeen[] =
      "{rax,rcx,rdx,rbx,rsp,rbp,rsi,rdi,r8,r9,r10,r11,r12,r13,r14,r15,rip}";
  *section = NULL;
  switch (row) {
  case 0:
    *body = fields_table("timer", SY_FIELDS, 255, NULL, NULL, NULL);
    *section = section_block("{}");
    break;
  case 1:
    *body = dup_string("stub_table t kind interrupt {\n}\n");
    break;
  case 2: {
    char *a = fields_entry(SY_FIELDS, 255, NULL, "0", "entry0");
    char *b = fields_entry(SY_FIELDS, 255, NULL, "0", "entry1");
    *body = a && b ? table_two("syscall", a, b) : NULL;
    free(a);
    free(b);
    *section = section_block("{}");
    break;
  }
  case 3: {
    char *a = fields_entry(UD_FIELDS, 255, NULL, "6", "first");
    char *b = fields_entry(UD_FIELDS, 255, NULL, "6", "second");
    *body = a && b ? table_two("interrupt", a, b) : NULL;
    free(a);
    free(b);
    break;
  }
  case 4:
    *body = table_many(513);
    *section = section_block("{}");
    break;
  case 5:
    *body = fields_table("interrupt", UD_FIELDS, 255, NULL, "300", "isr300");
    break;
  case 6:
    *body = fields_table("syscall", SY_FIELDS, 2, "alien-abi-v0", NULL, NULL);
    *section = section_block("{}");
    break;
  case 7:
    *body = fields_table("interrupt", UD_FIELDS, 2, "alien-abi-v0", NULL, NULL);
    break;
  case 8:
    *body = fields_table("syscall", SY_FIELDS, 4, "sysretq", NULL, NULL);
    *section = section_block("{}");
    break;
  case 9:
    *body = fields_table("interrupt", UD_FIELDS, 4, "iretd", NULL, NULL);
    break;
  case 10:
    *body = fields_table("syscall", SY_FIELDS, 5, "alien.frame", NULL, NULL);
    *section = section_block("{}");
    break;
  case 11:
    *body = fields_table("interrupt", UD_FIELDS, 5, "alien.frame", NULL, NULL);
    break;
  case 12:
    *body = fields_table("interrupt", UD_FIELDS, 6, "true", NULL, NULL);
    break;
  case 13:
    *body = fields_table("syscall", SY_FIELDS, 6, "true", NULL, NULL);
    *section = section_block("{}");
    break;
  case 14:
    *body = fields_table("syscall", SY_FIELDS, 9, "0", NULL, NULL);
    *section = section_block("{}");
    break;
  case 15:
    *body = fields_table("interrupt", UD_FIELDS, 9, "16", NULL, NULL);
    break;
  case 16:
    *body = fields_table("interrupt", UD_FIELDS, 10, "always", NULL, NULL);
    break;
  case 17:
    *body = fields_table("syscall", SY_FIELDS, 10, "always", NULL, NULL);
    *section = section_block("{}");
    break;
  case 18:
    *body = fields_table("interrupt", UD_FIELDS, 11, "disable", NULL, NULL);
    break;
  case 19:
    *body = fields_table("syscall", SY_FIELDS, 11, "disable", NULL, NULL);
    *section = section_block("{}");
    break;
  case 20:
    *body = fields_table("interrupt", UD_FIELDS, 12, ".data", NULL, NULL);
    break;
  case 21:
    *body = fields_table("syscall", SY_FIELDS, 12, ".data", NULL, NULL);
    *section = section_block("{}");
    break;
  case 22:
    *body = fields_table("interrupt", UD_FIELDS, 13, "hidden", NULL, NULL);
    break;
  case 23:
    *body = fields_table("syscall", SY_FIELDS, 13, "hidden", NULL, NULL);
    *section = section_block("{}");
    break;
  case 24: {
    char *a = fields_entry(SY_FIELDS, 255, NULL, "0", "entry0");
    char *b = fields_entry(SY_FIELDS, 255, NULL, "1", "entry0");
    *body = a && b ? table_two("syscall", a, b) : NULL;
    free(a);
    free(b);
    *section = section_block("{}");
    break;
  }
  case 25: {
    static char block[640];
    snprintf(block, sizeof block,
             "section .text {\nfn main()->u64\neffects {}\nclobbers {} {\n"
             "return 0\n}\nfn dispatch()->u64\neffects {}\nclobbers {} {\n"
             "return 42\n}\nfn entry0()->u64\neffects {}\nclobbers {} {\n"
             "return 7\n}\n}\n");
    *body = fields_table("syscall", SY_FIELDS, 255, NULL, "0", "entry0");
    *section = dup_string(block);
    break;
  }
  case 26: {
    char *a = fields_entry(SY_FIELDS, 255, NULL, "0", "entry0");
    char *b = fields_entry(SY_FIELDS, 255, NULL, "2", "entry2");
    *body = a && b ? table_two("syscall", a, b) : NULL;
    free(a);
    free(b);
    *section = section_block("{}");
    break;
  }
  case 27: {
    char *a = fields_entry(UD_FIELDS, 255, NULL, "6", "isr6");
    char *b = fields_entry(GP_FIELDS, 255, NULL, "13", "isr13");
    *body = a && b ? table_two("interrupt", a, b) : NULL;
    free(a);
    free(b);
    break;
  }
  case 28:
    *body = fields_table("syscall", SY_FIELDS, 255, NULL, "0", "entry0");
    *section = section_block("{rbx}");
    break;
  case 29:
    *body = fields_table("syscall", SY_FIELDS, 1, "ghost", NULL, NULL);
    *section = section_block("{}");
    break;
  case 30: {
    char *plain = fields_table("interrupt", UD_FIELDS, 255, NULL, "6", "isr6");
    *body = bind_table(plain, "bindings {a:u64 @rcx}\n");
    free(plain);
    break;
  }
  case 31:
    *body = fields_table("interrupt", UD_FIELDS, 8, "{rbx}", NULL, NULL);
    break;
  case 32:
    *body = fields_table("interrupt", UD_FIELDS, 7, "{}", NULL, NULL);
    break;
  case 33:
    *body = fields_table("syscall", SY_FIELDS, 7, "{rbx}", NULL, NULL);
    *section = section_block("{}");
    break;
  case 34:
    *body = fields_table("interrupt", UD_FIELDS, 7, "{foo}", NULL, NULL);
    break;
  case 35:
    *body = fields_table("interrupt", UD_FIELDS, 7, seventeen, NULL, NULL);
    break;
  case 36:
    *body = fields_table("interrupt", UD_FIELDS, 1, "rewind_saved_rip_2", NULL,
                         NULL);
    break;
  case 37:
    *body = fields_table("interrupt", UD_FIELDS, 1, "advance_saved_rip_0", NULL,
                         NULL);
    break;
  case 38:
    *body = fields_table("interrupt", UD_FIELDS, 1, "advance_saved_rip_4", NULL,
                         NULL);
    break;
  default:
    *body = NULL;
    break;
  }
  return *body != NULL;
}

/* What the oracle actually answered for one witness, kept so the closure
 * checks below compare a run against the table instead of the table against
 * itself. */
typedef struct {
  unsigned code;
  int accepted;
  char message[sizeof(((NtFDiagnostic *)0)->message)];
} Witness;

/* Both verdicts on one source, and the two verdicts compared to each other:
 * the reason stub_table.nova published against the class and the wording the
 * C front-end published, with the retained accept/refuse bit checked first and
 * a witness the oracle accepts required to carry no diagnostic at all. */
static void confront_reason(const NovaHostImage *image, const ReasonRow *row,
                            unsigned index, Witness *observed) {
  char *body = NULL;
  char *section = NULL;
  int built = reason_fixture(index, &body, &section);
  char *source = built ? assemble(body, section) : NULL;
  NtFProgram c;
  memset(&c, 0, sizeof c);
  int c_ok = source ? c_verdict(source, &c) : 0;
  unsigned code = c.diagnostic_count ? c.diagnostics[0].code : 0;
  observed[index].code = code;
  observed[index].accepted = source ? (c_ok != 0) : -1;
  observed[index].message[0] = 0;
  if (c.diagnostic_count)
    snprintf(observed[index].message, sizeof observed[index].message, "%s",
             c.diagnostics[0].message);
  Run r;
  memset(&r, 0, sizeof r);
  r.returned = UINT64_MAX;
  r.runtime = UINT64_MAX;
  if (source) r = run(image, source, 64, 0);
  cases++;
  checks++;
  /* A LEGAL row is a declaration both vocabularies must agree on being legal
   * in Nova and illegal in the C: the declaration pass must answer 0, and the
   * class and the wording the oracle gives are confronted all the same. */
  int bad = !source || r.runtime != 0;
  if (!bad && row->reason == LEGAL) bad = r.returned != 0;
  if (!bad && row->reason != LEGAL)
    bad = r.returned != 305 || r.out[2] != row->reason;
  /* the retained bit, and the measured absence it alone cannot express */
  if (!bad) bad = (c_ok != 0) != (row->c_code == 0);
  if (!bad && row->c_code == 0) bad = c.diagnostic_count != 0;
  /* the class and the wording, which is the confrontation proper */
  if (!bad && row->c_code != 0)
    bad = c.diagnostic_count == 0 || code != row->c_code ||
          strcmp(c.diagnostics[0].message, row->c_message) != 0;
  if (bad) {
    failures++;
    fprintf(stderr,
            "FAIL reason %s witness %s (%s): nova %llu runtime=%llu reason=%llu, "
            "oracle accepted=%d E%u \"%s\", want E%u \"%s\"\n",
            row->reason == LEGAL ? "LEGAL" : "?", row->witness, row->rule,
            (unsigned long long)r.returned, (unsigned long long)r.runtime,
            (unsigned long long)r.out[2], c_ok, code,
            c.diagnostic_count ? c.diagnostics[0].message : "",
            row->c_code, row->c_code ? row->c_message : "(accepted)");
    if (source) fprintf(stderr, "  source:\n%s\n", source);
  }
  if (source) nt_frontend_free(&c);
  free(body);
  free(section);
  free(source);
}

/* Every reason id the tree can publish, read out of the module the harness just
 * compiled rather than out of the table above, so a reason added to, renamed
 * in or deleted from stub_table.nova is a set difference and not a silent
 * hole. The two anchors are the only two shapes a 305 reason takes there: the
 * entry level verdict word and the table level reason variable. The
 * `code=305;reason=verdict[2];` site forwards a verdict and publishes no
 * literal of its own, and is skipped because no digit follows its anchor; the
 * `reason!=` tests of the detail filter never match the anchor. */
static unsigned scan_reasons(const char *module, uint64_t *out, unsigned cap) {
  static const char *const anchors[2] = {"verdict[2]=", "reason="};
  unsigned found = 0;
  if (!module) return 0;
  for (unsigned a = 0; a < 2; a++) {
    size_t width = strlen(anchors[a]);
    for (const char *at = module; (at = strstr(at, anchors[a])) != NULL;
         at += width) {
      at += width;
      if (*at < '0' || *at > '9') continue;
      uint64_t id = 0;
      while (*at >= '0' && *at <= '9') {
        id = id * 10 + (uint64_t)(*at - '0');
        at++;
      }
      unsigned i = 0;
      while (i < found && out[i] != id) i++;
      if (i < found || found >= cap) continue;
      out[found++] = id;
    }
  }
  return found;
}

/* The reason ids stub_table.nova states in prose, read out of the comment above
 * collect: the module's own list of the same set, written by the same hand as
 * the literals and therefore no oracle at all, but a third witness, so the
 * count the module claims, the set the module emits and the set the gate names
 * are confronted with each other instead of one being taken on trust. The list
 * is a run of comment lines, so the line starts and the comment leaders are
 * folded away first and an item is then a number the anchor or a comma
 * introduces. A list that does not fit the fold is reported as no list at all
 * rather than as a shorter one, so the closure below fails instead of
 * comparing against a truncation. */
static unsigned scan_reason_prose(const char *module, uint64_t *out,
                                  unsigned cap) {
  static const char anchor[] = "Reasons:";
  char flat[2048];
  size_t n = 0;
  const char *at = module ? strstr(module, anchor) : NULL;
  if (!at) return 0;
  at += sizeof anchor - 1;
  int fresh = 0; /* the anchor sits mid-line, so the fold starts inside it */
  while (*at) {
    if (*at == '\n') {
      fresh = 1;
      at++;
      continue;
    }
    if (fresh) {
      fresh = 0;
      while (*at == ' ' || *at == '\t') at++;
      if (at[0] == '/' && at[1] == '/') {
        at += 2;
        continue;
      }
      break; /* the comment ended, the list is over */
    }
    if (n + 1 >= sizeof flat) return 0;
    flat[n++] = *at++;
  }
  flat[n] = 0;
  unsigned found = 0;
  for (const char *p = flat;;) {
    while (*p == ' ' || *p == '\t') p++;
    if (*p < '0' || *p > '9') break;
    uint64_t id = 0;
    while (*p >= '0' && *p <= '9') {
      id = id * 10 + (uint64_t)(*p - '0');
      p++;
    }
    unsigned i = 0;
    while (i < found && out[i] != id) i++;
    if (i == found && found < cap) out[found++] = id;
    while (*p && *p != ',') p++;
    if (*p != ',') break;
    p++;
  }
  return found;
}

/* The distinct reason ids the table names, in first-appearance order. */
static unsigned table_reasons(uint64_t *out, unsigned cap) {
  unsigned found = 0;
  for (unsigned i = 0; i < REASON_ROWS; i++) {
    if (REASONS[i].reason == LEGAL) continue;
    unsigned j = 0;
    while (j < found && out[j] != REASONS[i].reason) j++;
    if (j == found && found < cap) out[found++] = REASONS[i].reason;
  }
  return found;
}
static int reason_in_rows(uint64_t id) {
  for (unsigned i = 0; i < REASON_ROWS; i++)
    if (REASONS[i].reason == id) return 1;
  return 0;
}
/* A C class this gate accounts for: every non-zero class a row records, plus
 * zero, which is a witness the oracle accepts and therefore no diagnostic. */
static int code_in_rows(unsigned code) {
  if (!code) return 1;
  for (unsigned i = 0; i < REASON_ROWS; i++)
    if (REASONS[i].c_code == code) return 1;
  return 0;
}
static int id_in(const uint64_t *set, unsigned count, uint64_t id) {
  for (unsigned i = 0; i < count; i++)
    if (set[i] == id) return 1;
  return 0;
}
/* The distinct C classes a list of (class, wording) pairs uses, and the number
 * of those classes that two different Nova reasons collapse onto. */
static unsigned distinct_classes(const unsigned *codes, unsigned count) {
  unsigned found = 0;
  for (unsigned i = 0; i < count; i++) {
    if (!codes[i]) continue;
    unsigned j = 0;
    while (j < found && codes[j] != codes[i]) j++;
    if (j == found) found++;
  }
  return found;
}
static unsigned distinct_keys(const unsigned *codes, const char *const *words,
                              unsigned count) {
  unsigned found = 0;
  for (unsigned i = 0; i < count; i++) {
    unsigned j = 0;
    while (j < i && (codes[j] != codes[i] || strcmp(words[j], words[i]) != 0))
      j++;
    if (j == i) found++;
  }
  return found;
}
static unsigned shared_keys(const unsigned *codes, const char *const *words,
                            const uint64_t *reasons, unsigned count) {
  uint64_t seen[64];
  unsigned found = 0;
  for (unsigned i = 0; i < count; i++) {
    unsigned j = 0;
    while (j < i && (codes[j] != codes[i] || strcmp(words[j], words[i]) != 0))
      j++;
    if (j != i) continue;
    unsigned distinct = 0;
    for (unsigned m = 0; m < count; m++) {
      if (codes[m] != codes[i] || strcmp(words[m], words[i]) != 0) continue;
      if (id_in(seen, distinct, reasons[m])) continue;
      if (distinct < 64) seen[distinct++] = reasons[m];
    }
    if (distinct > 1) found++;
  }
  return found;
}

/* The reason set the tree publishes and the reason set the table names,
 * compared in both directions, with the two distinct counts confronted. A
 * reason added to, renamed in or deleted from stub_table.nova moves one of
 * the two sets and fails here. */
static void confront_reason_set(const char *module) {
  uint64_t prose[64];
  uint64_t named[64];
  uint64_t scanned[64];
  unsigned found = scan_reasons(module, scanned, 64);
  unsigned stated = scan_reason_prose(module, prose, 64);
  unsigned count = table_reasons(named, 64);
  cases++;
  checks++;
  int bad = 0;
  for (unsigned i = 0; i < found && !bad; i++)
    if (!reason_in_rows(scanned[i])) {
      bad = 1;
      fprintf(stderr,
              "FAIL reason set: stub_table.nova publishes reason %llu and no "
              "row of the gate names it\n",
              (unsigned long long)scanned[i]);
    }
  for (unsigned i = 0; i < count && !bad; i++)
    if (!id_in(scanned, found, named[i])) {
      bad = 1;
      fprintf(stderr,
              "FAIL reason set: the gate names reason %llu and stub_table.nova "
              "never publishes it\n",
              (unsigned long long)named[i]);
    }
  /* the prose list the module states against the literals it emits */
  for (unsigned i = 0; i < stated && !bad; i++)
    if (!id_in(scanned, found, prose[i])) {
      bad = 1;
      fprintf(stderr,
              "FAIL reason set: the comment of stub_table.nova lists reason "
              "%llu and no literal of the module emits it\n",
              (unsigned long long)prose[i]);
    }
  for (unsigned i = 0; i < found && !bad; i++)
    if (!id_in(prose, stated, scanned[i])) {
      bad = 1;
      fprintf(stderr,
              "FAIL reason set: stub_table.nova emits reason %llu and its own "
              "comment does not list it\n",
              (unsigned long long)scanned[i]);
    }
  if (!bad && (count != found || stated != found)) {
    bad = 1;
    fprintf(stderr,
            "FAIL reason set: the gate names %u distinct reasons, the module "
            "emits %u, the module comment lists %u\n",
            count, found, stated);
  }
  if (bad) failures++;
}

/* The C diagnostic classes and wordings the run actually produced over the
 * whole witness corpus, confronted against the classes and wordings the table
 * records, in both directions. This is the reverse difference: a C
 * diagnostic no reason accounts for, and a class or a wording this gate claims
 * the oracle uses when it does not. The count of diagnostics two different
 * Nova reasons collapse onto is confronted too, so the C's coarser vocabulary
 * stays a measured fact instead of a sentence in a comment. */
static void confront_c_vocabulary(const Witness *observed) {
  unsigned run_codes[64];
  uint64_t run_reasons[64];
  const char *run_words[64];
  unsigned run_count = 0;
  unsigned kept_codes[64];
  uint64_t kept_reasons[64];
  const char *kept_words[64];
  unsigned kept_count = 0;
  for (unsigned i = 0; i < REASON_ROWS; i++) {
    run_codes[run_count] = observed[i].code;
    run_words[run_count] = observed[i].message;
    run_reasons[run_count] = REASONS[i].reason;
    run_count++;
    kept_codes[kept_count] = REASONS[i].c_code;
    kept_words[kept_count] = REASONS[i].c_message ? REASONS[i].c_message : "";
    kept_reasons[kept_count] = REASONS[i].reason;
    kept_count++;
  }
  unsigned run_classes = distinct_classes(run_codes, run_count);
  unsigned kept_classes = distinct_classes(kept_codes, kept_count);
  unsigned run_pairs = distinct_keys(run_codes, run_words, run_count);
  unsigned kept_pairs = distinct_keys(kept_codes, kept_words, kept_count);
  unsigned run_shared = shared_keys(run_codes, run_words, run_reasons, run_count);
  unsigned kept_shared =
      shared_keys(kept_codes, kept_words, kept_reasons, kept_count);
  /* a witness the oracle accepts is a reason with no C counterpart: the count
   * comes from the accept bit the run measured, not from the class being zero,
   * so a refusal that somehow carried no diagnostic cannot pass for one */
  unsigned run_absent = 0, kept_absent = 0;
  for (unsigned i = 0; i < run_count; i++)
    if (observed[i].accepted) run_absent++;
  for (unsigned i = 0; i < kept_count; i++)
    if (!kept_codes[i]) kept_absent++;
  cases++;
  checks++;
  int bad = 0;
  for (unsigned i = 0; i < run_count && !bad; i++)
    if (!code_in_rows(run_codes[i])) {
      bad = 1;
      fprintf(stderr,
              "FAIL c vocabulary: the oracle answered E%u \"%s\" on reason "
              "%llu and no recorded class covers it\n",
              run_codes[i], run_words[i], (unsigned long long)run_reasons[i]);
    }
  if (!bad && run_classes != kept_classes) {
    bad = 1;
    fprintf(stderr,
            "FAIL c vocabulary: the oracle used %u diagnostic classes across "
            "the witnesses, the gate records %u\n",
            run_classes, kept_classes);
  }
  if (!bad && run_pairs != kept_pairs) {
    bad = 1;
    fprintf(stderr,
            "FAIL c vocabulary: the oracle produced %u class-and-wording "
            "pairs, the gate records %u\n",
            run_pairs, kept_pairs);
  }
  if (!bad && run_shared != kept_shared) {
    bad = 1;
    fprintf(stderr,
            "FAIL c vocabulary: %u C diagnostics are shared by two different "
            "Nova reasons, the gate records %u\n",
            run_shared, kept_shared);
  }
  if (!bad && run_absent != kept_absent) {
    bad = 1;
    fprintf(stderr,
            "FAIL c vocabulary: the oracle has no vocabulary for %u of the "
            "witnesses, the gate records %u\n",
            run_absent, kept_absent);
  }
  if (bad) failures++;
}

/* Two counter-values per field ordinal of the frozen profiles, none of them
 * the frozen one. The sweep is the behavioural half of the reason-set
 * closure: it reaches the declaration pass over a corpus the curated rows do
 * not enumerate, so a reason that is reachable but unregistered fails here
 * even when the reason-set scan of the tree has not changed. Any 305 reason
 * the sweep reaches must be one the table names, and any diagnostic class the
 * oracle produces on the way must be one the table accounts for. */
static const char *const SWEEP_VALUES[15][2] = {
    {"300", "7"},
    {"ghost", "rewind_saved_rip_2"},
    {"alien-abi-v0", "nx64-abi"},
    {"alien-abi-v0", "nx64-abi"},
    {"sysretq", "iretd"},
    {"alien.frame", "x86_64.frame.other"},
    {"maybe", "true"},
    {"{foo}", "{rax,rcx}"},
    {"{rbx}", "{rax}"},
    {"8", "24"},
    {"always", "sometimes"},
    {"disable", "mask"},
    {".data", ".rdata"},
    {"hidden", "public"},
    {"isr6", "main"},
};

/* The probes on which the two vocabularies disagree, and the way they
 * disagree: `nova` is what the declaration pass must answer, 0 for a
 * declaration it admits and 305 for one it refuses, and the class and the
 * wording are what the oracle must publish on the same source, zero and none
 * for a declaration it admits. A disagreement is not a failure, an
 * undeclared one is: the sweep confronts the set it measured against this one
 * in both directions, so a new disagreement and a stale entry both fail. */
typedef struct {
  const char *kind;
  unsigned ordinal;
  unsigned value;
  uint64_t nova;
  unsigned c_code;
  const char *c_message;
} Divergence;

static const Divergence DIVERGENCES[] = {
    {"interrupt", 0, 1, 0, 503,
     "witness profiles support only #UD vector 6 or #GP vector 13"},
    {"interrupt", 6, 0, 305, 0, NULL},
    {"interrupt", 7, 1, 0, 200, "witness save set must be {rax}"},
};
#define DIVERGENCE_ROWS ((unsigned)(sizeof DIVERGENCES / sizeof DIVERGENCES[0]))

static const Divergence *declared_divergence(const char *kind,
                                             unsigned ordinal, unsigned value) {
  for (unsigned i = 0; i < DIVERGENCE_ROWS; i++)
    if (DIVERGENCES[i].ordinal == ordinal && DIVERGENCES[i].value == value &&
        !strcmp(DIVERGENCES[i].kind, kind))
      return &DIVERGENCES[i];
  return NULL;
}

static void sweep_reasons(const NovaHostImage *image) {
  static const char *const kinds[2] = {"interrupt", "syscall"};
  static const char *const *const bases[2] = {UD_FIELDS, SY_FIELDS};
  unsigned seen[DIVERGENCE_ROWS];
  memset(seen, 0, sizeof seen);
  for (unsigned p = 0; p < 2; p++) {
    for (unsigned ordinal = 0; ordinal < 15; ordinal++) {
      for (unsigned v = 0; v < 2; v++) {
        char *body =
            fields_table(kinds[p], bases[p], ordinal, SWEEP_VALUES[ordinal][v],
                         NULL, NULL);
        char *section = strcmp(kinds[p], "syscall") == 0 ? section_block("{}")
                                                         : NULL;
        char *source = body ? assemble(body, section) : NULL;
        NtFProgram c;
        memset(&c, 0, sizeof c);
        int c_ok = source ? c_verdict(source, &c) : 0;
        unsigned code = c.diagnostic_count ? c.diagnostics[0].code : 0;
        Run r;
        memset(&r, 0, sizeof r);
        r.returned = UINT64_MAX;
        r.runtime = UINT64_MAX;
        if (source) r = run(image, source, 64, 0);
        cases++;
        checks++;
        int bad = !source || r.runtime != 0 ||
                  (r.returned != 0 && r.returned != 305 && r.returned != 800);
        /* a 305 reason the gate does not name is a hole in the vocabulary */
        if (!bad && r.returned == 305 && !reason_in_rows(r.out[2])) {
          bad = 1;
          fprintf(stderr,
                  "FAIL sweep %s field %u = %s: the declaration pass answered "
                  "reason %llu, which no row of the gate names\n",
                  kinds[p], ordinal, SWEEP_VALUES[ordinal][v],
                  (unsigned long long)r.out[2]);
        }
        /* a C diagnostic class no row accounts for is a C vocabulary the gate
         * does not know: the reverse difference, measured */
        if (!bad && code && !code_in_rows(code)) {
          bad = 1;
          fprintf(stderr,
                  "FAIL sweep %s field %u = %s: the oracle answered E%u "
                  "\"%s\", a class no row of the gate accounts for\n",
                  kinds[p], ordinal, SWEEP_VALUES[ordinal][v], code,
                  c.diagnostics[0].message);
        }
        /* the two verdicts agreeing or not, confronted against the declared
         * set of disagreements in both directions */
        if (!bad && ((r.returned == 305) == (c_ok != 0))) {
          const Divergence *d = declared_divergence(kinds[p], ordinal, v);
          uint64_t want = r.returned == 305 ? 305 : 0;
          const char *message = c.diagnostic_count ? c.diagnostics[0].message
                                                   : NULL;
          if (!d) {
            bad = 1;
            fprintf(stderr,
                    "FAIL sweep %s field %u = %s: the declaration pass answers "
                    "%llu and the oracle %s, an undeclared disagreement\n",
                    kinds[p], ordinal, SWEEP_VALUES[ordinal][v],
                    (unsigned long long)r.returned, c_ok ? "accepts" : "refuses");
          } else {
            seen[d - DIVERGENCES] = 1;
            if (d->nova != want || d->c_code != code ||
                (d->c_code == 0) != (message == NULL) ||
                (message && strcmp(d->c_message, message) != 0)) {
              bad = 1;
              fprintf(stderr,
                      "FAIL sweep %s field %u = %s: measured nova=%llu E%u "
                      "\"%s\", the declared disagreement is nova=%llu E%u "
                      "\"%s\"\n",
                      kinds[p], ordinal, SWEEP_VALUES[ordinal][v],
                      (unsigned long long)r.returned, code,
                      message ? message : "", (unsigned long long)d->nova,
                      d->c_code, d->c_message ? d->c_message : "");
            }
          }
        }
        if (bad) {
          failures++;
          if (source) fprintf(stderr, "  source:\n%s\n", source);
        }
        if (source) nt_frontend_free(&c);
        free(body);
        free(section);
        free(source);
      }
    }
  }
  /* a declared disagreement the sweep no longer reaches is stale */
  for (unsigned i = 0; i < DIVERGENCE_ROWS; i++)
    if (!seen[i]) {
      cases++;
      checks++;
      failures++;
      fprintf(stderr,
              "FAIL sweep divergence %s field %u = %s is declared but the sweep "
              "no longer measures it\n",
              DIVERGENCES[i].kind, DIVERGENCES[i].ordinal,
              SWEEP_VALUES[DIVERGENCES[i].ordinal][DIVERGENCES[i].value]);
    }
}

/* ================================================= the image route of A6 ==== */
/*
 * Everything above confronts the DECLARATION pass and the abstract plan. This
 * block confronts the IMAGE: stub_table now encodes the plan into x86-64 and
 * lays the result out as a PE, and this is where those bytes are checked
 * against the C oracle rather than against a literal.
 *
 * Three oracles, none of them a transcription:
 *
 *  1. nt_codegen_x64. The C reference lowers a structured stub declaration to
 *     real machine bytes through emit_raw_interrupt_stub, so the bytes of a
 *     generated stub can be read straight out of a C run on the same source.
 *     Every body the Nova encoder writes is compared with the body the C
 *     produced, symbol by symbol, on every run. This is the oracle for the
 *     encoder.
 *
 *  2. nova_oracle_make_pe, the frozen C PE writer. The whole file the Nova
 *     emitter produced is compared with the file the C writer produces for
 *     the same text, entry and section sizes, byte for byte. This is the
 *     oracle for the image, not only for the body.
 *
 *  3. nt_x64_encode, the frozen C encoder, for the probe. The probe is the
 *     fixed code that takes a real #UD through a generated stub so a firmware
 *     can execute it. No probe byte is a literal here: the expectation is
 *     assembled by calling the C encoder once per instruction, at run time,
 *     and the result is compared with what stub_table wrote. There is no
 *     fixture in this block without an oracle.
 *
 * The image entry below is test scaffolding written here, in the harness,
 * because the tree entry module tests/stub-table-entry.nova dispatches only
 * check, measure, lower and plan_for, and this lot does not own that file. It
 * marshals arguments and nothing else: it parses, indexes, and calls the
 * export. The producer under test is stub_table.nova either way.
 */

static const char *const IMAGE_ENTRY =
    "module stub_table_image_entry;\n"
    "import ntasm_ast;\n"
    "import ntasm_parser;\n"
    "import semantics;\n"
    "import stub_table;\n"
    "export fn main(source:buf<u8>,out:buf<u64>,pe:buf<u8>,path:buf<u8>,"
    "mode:buf<u64>)->u64 {\n"
    "if len(out)<8 || len(mode)<1 { return 800; }\n"
    "let tree:ntasm_ast.Tree=ntasm_parser.parse(source,1);\n"
    "if tree.ok==false { ntasm_ast.release(tree); return 800; }\n"
    "let scratch:buf<u64>=alloc(runtime(),4);\n"
    "let code:u64=semantics.index(source,tree,scratch);\n"
    "rt_free(runtime(),scratch);\n"
    "if code!=0 { ntasm_ast.release(tree); return code; }\n"
    "let mut verdict:u64=0;\n"
    "if mode[0]==0 { verdict=stub_table.build_pe(source,tree,out,pe); }\n"
    "else if mode[0]==1 { verdict=stub_table.build_witness_pe(source,tree,out,pe); }\n"
    "else if mode[0]==2 { verdict=stub_table.build_pe_and_write(source,tree,out,path); }\n"
    "else if mode[0]==3 { verdict=stub_table.build_witness_pe_and_write(source,tree,out,path); }\n"
    "else if mode[0]==4 { verdict=stub_table.build_diagnostic_pe(source,tree,out,pe); }\n"
    "else { verdict=stub_table.build_diagnostic_pe_and_write(source,tree,out,path); }\n"
    "ntasm_ast.release(tree);\n"
    "return verdict;\n"
    "}\n";

/* The .text of an image begins at this file offset in every PE nt_make_pe
 * writes, and the gate reads it there rather than trusting a section table. */
#define IMG_TEXT_RAW 1024u
#define IMG_PE_CAP (1u << 20)
#define IMG_PE_BYTES 0xccu

typedef struct {
  uint64_t returned, runtime;
  const uint64_t *out;
} ImgRun;

static ImgRun img_run(const NovaHostImage *image, const char *source,
                      uint64_t words, uint64_t mode, uint8_t *pe,
                      size_t pe_size, const char *path) {
  ImgRun result;
  uint64_t mode_word = mode;
  for (unsigned i = 0; i < OUT_WORDS; i++) out_words[i] = guard;
  memset(pe, IMG_PE_BYTES, pe_size);
  result.returned = UINT64_MAX;
  result.runtime = UINT64_MAX;
  result.out = out_words;
  NovaContextV2 context;
  memset(&context, 0, sizeof context);
  if (!nova_context_init_v2(&context)) return result;
  uint64_t source_handle = nova_borrow_v2(&context, (void *)source,
                                          strlen(source), 0);
  uint64_t out_handle =
      nova_borrow_v2(&context, out_words, words * sizeof(uint64_t), 1);
  uint64_t pe_handle = nova_borrow_v2(&context, pe, pe_size, 1);
  uint64_t path_handle = nova_borrow_v2(&context, (void *)path, strlen(path), 0);
  uint64_t mode_handle = nova_borrow_v2(&context, &mode_word, sizeof mode_word, 0);
  uint64_t args[] = {source_handle, strlen(source), out_handle, words,
                     pe_handle, pe_size,         path_handle, strlen(path),
                     mode_handle, 1};
  result.returned = image->entry(&context, args, 10);
  result.runtime = context.error;
  CHECK(nova_context_destroy_v2(&context), "image context cleanup");
  return result;
}

/* The bytes the C reference generates for one declared stub symbol, read out
 * of a real nt_codegen_x64 run on the same source. The caller frees. */
static uint8_t *c_stub_body(const char *source, const char *symbol,
                            size_t *size) {
  *size = 0;
  NtFProgram program;
  memset(&program, 0, sizeof program);
  NtFInput input = {"oracle", source, strlen(source)};
  if (!nt_frontend_compile(&input, 1, &program)) {
    nt_frontend_free(&program);
    return NULL;
  }
  NtCodeImage image;
  memset(&image, 0, sizeof image);
  NtCodeDiagnostic diagnostic;
  memset(&diagnostic, 0, sizeof diagnostic);
  if (!nt_codegen_x64(&program, &image, &diagnostic)) {
    nt_code_image_free(&image);
    nt_frontend_free(&program);
    return NULL;
  }
  uint8_t *found = NULL;
  for (size_t j = 0; j < image.symbol_count; j++) {
    if (image.symbols[j].section != NT_CODE_SECTION_TEXT) continue;
    if (strcmp(image.symbols[j].name, symbol)) continue;
    found = malloc(image.symbols[j].size);
    if (!found) break;
    memcpy(found, image.bytes + image.symbols[j].offset, image.symbols[j].size);
    *size = image.symbols[j].size;
    break;
  }
  nt_code_image_free(&image);
  nt_frontend_free(&program);
  return found;
}

/* The number of bodies, and the size of the one the C generated, for the
 * measurement of a fixture the image route refuses. */
static void c_stub_measure(const char *source, const char *symbol,
                           size_t *size, size_t *relocations) {
  *size = 0;
  *relocations = 0;
  NtFProgram program;
  memset(&program, 0, sizeof program);
  NtFInput input = {"oracle", source, strlen(source)};
  if (!nt_frontend_compile(&input, 1, &program)) {
    nt_frontend_free(&program);
    return;
  }
  NtCodeImage image;
  memset(&image, 0, sizeof image);
  NtCodeDiagnostic diagnostic;
  memset(&diagnostic, 0, sizeof diagnostic);
  if (nt_codegen_x64(&program, &image, &diagnostic)) {
    for (size_t j = 0; j < image.symbol_count; j++)
      if (image.symbols[j].section == NT_CODE_SECTION_TEXT &&
          !strcmp(image.symbols[j].name, symbol))
        *size = image.symbols[j].size;
    *relocations = image.relocation_count;
  }
  nt_code_image_free(&image);
  nt_frontend_free(&program);
}

/* The whole PE the frozen C writer produces for one text, entry and section
 * shape. The caller frees *pe. */
static uint8_t *pe_oracle_image(const uint8_t *text, size_t text_size,
                                size_t entry, size_t *size) {
  *size = 0;
  NovaOraclePeImage image;
  memset(&image, 0, sizeof image);
  image.text.bytes = malloc(text_size ? text_size : 1);
  if (!image.text.bytes) return NULL;
  memcpy(image.text.bytes, text, text_size);
  image.text.size = text_size;
  image.text.capacity = text_size;
  image.entry = entry;
  if (!nova_oracle_make_pe(&image)) {
    free(image.text.bytes);
    free(image.pe.bytes);
    return NULL;
  }
  free(image.text.bytes);
  *size = image.pe.size;
  return image.pe.bytes;
}

/* The probe, assembled by the frozen C encoder one instruction at a time. The
 * caller frees. Returns the byte count through *size, zero on a refusal. */
static size_t probe_from_oracle(uint8_t *out, size_t cap, uint64_t vector) {
  NtX64Context context = {NT_X64_ALL_FEATURES, 0};
  /* A 64 bit IDT entry is SIXTEEN bytes: the CPU addresses vector N at
   * base + N*16, so the eight this used to compute put the gate twelve entries
   * from the trap. compiler/c/ntasm/formats/ud2_probe.c sizes its GATE the
   * same way. */
  uint64_t slot = vector * 16;
  struct {
    const char *mnemonic;
    NtX64Operand operands[2];
    unsigned count;
  } form[24];
  unsigned n = 0;
  memset(form, 0, sizeof form);

#define IMG_REG(w, r)                                                           \
  (NtX64Operand) { .kind = NT_X64_REG, .width = (w), .reg = (r), .base = -1,   \
                   .index = -1 }
#define IMG_IMM(w, v)                                                           \
  (NtX64Operand) { .kind = NT_X64_IMM, .width = (w), .imm = (v), .base = -1,   \
                   .index = -1 }
#define IMG_IMMS(w, v)                                                          \
  (NtX64Operand) { .kind = NT_X64_IMM, .width = (w), .imm = (v), .is_signed = 1, \
                   .base = -1, .index = -1 }
#define IMG_MEM(w, b, d)                                                        \
  (NtX64Operand) { .kind = NT_X64_MEM, .width = (w), .base = (b), .index = -1, \
                   .scale = 1, .disp = (d), .segment = NT_X64_SEG_NONE }
#define IMG_NONE                                                                \
  (NtX64Operand) { .kind = NT_X64_NONE, .base = -1, .index = -1 }
/* A direct relative branch target: rel32 measured from the next instruction.
 * A MEMRIP operand here would be an INDIRECT call through memory (ff /2), not
 * the E8 the pc-relative idiom needs. */
#define IMG_REL(v)                                                                \
  (NtX64Operand) { .kind = NT_X64_REL, .width = 64, .imm = (v), .is_signed = 1,  \
                   .base = -1, .index = -1 }
/* The operand count goes through a volatile so that a form with no operand
 * does not read as a constant range the compiler can fold, and so that the
 * table and the loop that fills it stay one expression wide. */
static volatile unsigned img_count_;
#define IMG_FORM(m, c, ...)                                                    \
  do {                                                                         \
    form[n].mnemonic = (m);                                                    \
    img_count_ = (unsigned)(c);                                                \
    form[n].count = img_count_;                                                \
    NtX64Operand img_tmp_[] = {__VA_ARGS__};                                   \
    form[n].operands[0] = img_tmp_[0];                                         \
    if (img_count_ > 1u) form[n].operands[1] = img_tmp_[1];                      \
    n++;                                                                       \
  } while (0)

  /* The gate selector is read at run time, so the image carries the load and
   * the store and no literal: nothing here pins a selector, and the case below
   * that reads the constructed gate back pins the field the CPU reads.
   *
   * Three properties of this list are load bearing and are what the four gate
   * cases pin:
   *   - slot is vector*16, because a 64 bit IDT entry is SIXTEEN bytes wide;
   *   - the type byte is 0x8E, DPL 0, because the probe runs at CPL 0 and a
   *     DPL 3 gate is refused with the same #GP(vector*8+2) a missing one is;
   *   - the offset is built by call/pop/add, so it is a LINEAR address and not
   *     the distance from the load base, which is what a lea would give. */
  IMG_FORM("sidt", 1, IMG_MEM(80, 4, 4080));
  IMG_FORM("mov", 2, IMG_REG(64, 2), IMG_MEM(64, 4, 4082));
  IMG_FORM("mov", 2, IMG_REG(16, 0), IMG_MEM(16, 2, 2));
  IMG_FORM("sub", 2, IMG_REG(64, 4), IMG_IMM(64, 8224));
  IMG_FORM("mov", 2, IMG_MEM(16, 4, (int64_t)(slot + 2)), IMG_REG(16, 0));
  IMG_FORM("call", 1, IMG_REL(0));
  IMG_FORM("pop", 1, IMG_REG(64, 0));
  /* 79 is witness_len minus the offset the pop leaves rax at. The call pushes
   * the address of the byte after itself, which is the pop at 37, NOT the add
   * at 38; reading it as 38 put the gate on the probe's own ret, one byte
   * below the stub, and a ret in the gate target returns to the saved RIP,
   * which is the ud2. The encoder takes the sign extended imm8 form, 48 83 C0,
   * and the Nova emitter emits the same three bytes, so the pin holds. */
  IMG_FORM("add", 2, IMG_REG(64, 0), IMG_IMM(64, 87));
  IMG_FORM("mov", 2, IMG_MEM(16, 4, (int64_t)(slot + 0)), IMG_REG(16, 0));
  IMG_FORM("mov", 2, IMG_MEM(8, 4, (int64_t)(slot + 4)), IMG_IMM(8, 0));
  IMG_FORM("mov", 2, IMG_MEM(8, 4, (int64_t)(slot + 5)), IMG_IMM(8, 0x8E));
  IMG_FORM("mov", 2, IMG_MEM(64, 4, (int64_t)(slot + 8)), IMG_IMM(64, 0));
  IMG_FORM("shr", 2, IMG_REG(64, 0), IMG_IMM(32, 16));
  IMG_FORM("mov", 2, IMG_MEM(16, 4, (int64_t)(slot + 6)), IMG_REG(16, 0));
  IMG_FORM("mov", 2, IMG_MEM(16, 4, 8192), IMG_IMM(16, 8191));
  IMG_FORM("mov", 2, IMG_MEM(64, 4, 8194), IMG_REG(64, 4));
  IMG_FORM("lidt", 1, IMG_MEM(80, 4, 8192));
  IMG_FORM("mov", 2, IMG_REG(32, 0), IMG_IMM(32, 42));
  IMG_FORM("ud2", 0, IMG_NONE);
  IMG_FORM("add", 2, IMG_REG(64, 4), IMG_IMM(64, 8224));
  /* The probe puts the firmware's own table back before it returns: a probe
   * that leaves its table installed leaves 511 entries of frame behind it,
   * and the first timer interrupt after the return vectors through them. */
  IMG_FORM("lidt", 1, IMG_MEM(80, 4, 12304));
  IMG_FORM("ret", 0, IMG_NONE);
#undef IMG_FORM
#undef IMG_MEM
#undef IMG_IMMS
#undef IMG_IMM
#undef IMG_REG
#undef IMG_NONE
#undef IMG_REL

  size_t total = 0;
  for (unsigned i = 0; i < n; i++) {
    NtX64Instruction instruction;
    memset(&instruction, 0, sizeof instruction);
    if (nt_x64_encode(form[i].mnemonic, form[i].operands, form[i].count,
                      context, &instruction) != NT_X64_OK)
      return 0;
    if (total + instruction.length > cap) return 0;
    memcpy(out + total, instruction.bytes, instruction.length);
    total += instruction.length;
  }
  return total;
}

/* Every byte after the image inside the caller's buffer is still the guard the
 * harness filled it with, so a producer that reported a size it did not write,
 * or wrote past it, both red. */
static int img_guards_intact(const uint8_t *pe, size_t size, size_t cap) {
  for (size_t i = size; i < cap; i++)
    if (pe[i] != IMG_PE_BYTES) return 0;
  return 1;
}

/* The record directory entry for record i, and the name it names. */
static const char *img_record_name(const char *source, const uint64_t *out,
                                   unsigned i) {
  static char name[64];
  uint64_t start = out[6 + i * 4], end = out[7 + i * 4];
  if (end <= start || end - start >= sizeof name) return NULL;
  memcpy(name, source + start, (size_t)(end - start));
  name[end - start] = 0;
  return name;
}

static int img_text_size(const uint64_t *out, unsigned records) {
  unsigned last = records ? records - 1 : 0;
  return (int)(out[4 + last * 4] + out[5 + last * 4]);
}

/* ---- the image cases, and the artifact that reaches the image exports ---- */

/* A section block the C codegen accepts: nt_codegen_x64 requires an exported
 * entry, which the declaration fixtures above deliberately do not carry. */
static const char *const IMAGE_TAIL =
    "section .text {\nexport fn main()->u64\neffects {}\nclobbers {} {\n"
    "return 0\n}\n}\n";

/* One image: run the export, then confront the produced bytes. The C oracle
 * body of every record named by the directory, then the whole file against
 * the frozen C PE writer, then the caller guard. */
static void image_case(const NovaHostImage *image, const char *name,
                       const char *source, uint64_t mode) {
  uint8_t *pe = malloc(IMG_PE_CAP);
  if (!pe) {
    cases++;
    CHECK(0, "image allocation");
    return;
  }
  ImgRun r = img_run(image, source, OUT_WORDS, mode, pe, IMG_PE_CAP, "unused");
  cases++;
  checks++;
  int bad = r.returned != 0 || r.runtime != 0;
  if (bad) {
    failures++;
    fprintf(stderr,
            "FAIL image %s ret=%llu runtime=%llu out=%llu,%llu,%llu,%llu\n",
            name, (unsigned long long)r.returned, (unsigned long long)r.runtime,
            (unsigned long long)r.out[0], (unsigned long long)r.out[1],
            (unsigned long long)r.out[2], (unsigned long long)r.out[3]);
    free(pe);
    return;
  }
  unsigned records = (unsigned)r.out[1];
  size_t size = (size_t)r.out[0];
  if (size < IMG_TEXT_RAW || size > IMG_PE_CAP || r.out[3] != 0) bad = 1;
  int text_size = bad ? 0 : img_text_size(r.out, records);
  if (bad || text_size <= 0 || IMG_TEXT_RAW + (size_t)text_size > size) bad = 1;

  /* 1. every generated body, against nt_codegen_x64 on the same source */
  for (unsigned i = 0; !bad && i < records; i++) {
    const char *symbol = img_record_name(source, r.out, i);
    size_t oracle_size = 0;
    uint8_t *oracle = symbol ? c_stub_body(source, symbol, &oracle_size) : NULL;
    if (!oracle) {
      bad = 1;
      fprintf(stderr, "FAIL image %s record %u: the C oracle emitted no %s\n",
              name, i, symbol ? symbol : "symbol");
    } else {
      uint64_t offset = r.out[4 + i * 4], body = r.out[5 + i * 4];
      if (body != oracle_size ||
          memcmp(pe + IMG_TEXT_RAW + offset, oracle, oracle_size) != 0) {
        bad = 1;
        fprintf(stderr,
                "FAIL image %s body %s nova=%llu oracle=%zu at .text+%llu\n",
                name, symbol, (unsigned long long)body, oracle_size,
                (unsigned long long)offset);
        for (size_t k = 0; k < oracle_size; k++)
          fprintf(stderr, "  [%zu] nova=%02x oracle=%02x\n", k,
                  pe[IMG_TEXT_RAW + offset + k], oracle[k]);
      }
    }
    free(oracle);
    checks++;
  }
  if (bad) {
    failures++;
    free(pe);
    return;
  }

  /* 2. the whole file, against the frozen C PE writer */
  size_t oracle_size = 0;
  uint8_t *oracle = pe_oracle_image(pe + IMG_TEXT_RAW, (size_t)text_size,
                                    (size_t)r.out[2], &oracle_size);
  checks++;
  if (!oracle || oracle_size != size ||
      memcmp(pe, oracle, size) != 0) {
    failures++;
    fprintf(stderr, "FAIL image %s PE parity nova=%zu oracle=%zu entry=%llu\n",
            name, size, oracle_size, (unsigned long long)r.out[2]);
    if (oracle)
      for (size_t k = 0; k < size && k < oracle_size; k++)
        if (pe[k] != oracle[k]) {
          fprintf(stderr, "  first difference at %zu: nova=%02x oracle=%02x\n",
                  k, pe[k], oracle[k]);
          break;
        }
  }
  free(oracle);


  /* 3. the caller guard past the image */
  checks++;
  if (!img_guards_intact(pe, size, IMG_PE_CAP)) {
    failures++;
    fprintf(stderr, "FAIL image %s wrote past the reported size\n", name);
  }
  free(pe);
}

/* A refusal of the image route, with the reason and the two words the route
 * answers it with. The C oracle is consulted for the refusals where it can
 * express the same declaration, and its answer is recorded, not guessed. */
static void image_refuse(const NovaHostImage *image, const char *name,
                         const char *source, uint64_t mode, uint64_t code,
                         uint64_t reason, uint64_t records) {
  uint8_t *pe = malloc(IMG_PE_CAP);
  if (!pe) {
    cases++;
    CHECK(0, "image refusal allocation");
    return;
  }
  ImgRun r = img_run(image, source, OUT_WORDS, mode, pe, IMG_PE_CAP, "unused");
  cases++;
  checks++;
  int bad = r.returned != code || r.runtime != 0 || r.out[2] != reason ||
            r.out[1] != records || r.out[3] != 0;
  if (bad) {
    failures++;
    fprintf(stderr,
            "FAIL image refusal %s ret=%llu runtime=%llu out1=%llu out2=%llu "
            "out3=%llu want %llu/%llu/%llu\n",
            name, (unsigned long long)r.returned, (unsigned long long)r.runtime,
            (unsigned long long)r.out[1], (unsigned long long)r.out[2],
            (unsigned long long)r.out[3], (unsigned long long)records,
            (unsigned long long)reason, (unsigned long long)code);
  }
  free(pe);
}

/* ---- the four gate properties, asserted over the bytes actually emitted ----
 *
 * The witness case above already pins every byte of the probe against
 * nt_x64_encode, so these cases are not about the encoding. They are about the
 * four things the encoding is allowed to be, each of which has silently
 * produced a #GP(vector*8+2) that reads exactly like a missing gate, and each
 * of which is therefore worth a case of its own. Every case is a predicate
 * over the probe bytes, and every case carries a negative twin: the same
 * predicate, run over a copy of the real bytes with the property broken, has
 * to REJECT. A predicate that cannot reject is not a case.
 */

/* Index of the first occurrence of m bytes in p[0..n), plus one, or 0. */
static size_t gate_find(const uint8_t *p, size_t n, const uint8_t *s, size_t m) {
  if (m == 0 || n < m) return 0;
  for (size_t i = 0; i + m <= n; i++)
    if (memcmp(p + i, s, m) == 0) return i + 1;
  return 0;
}

/* 1. The high half of the gate offset.
 *
 * A 64 bit gate names its target with offset[15:0] at entry bytes 0-1 and
 * offset[31:16] at bytes 6-7, so the two halves are SIXTEEN bits apart. The
 * probe used to shift by 32, which is silent for every image this project
 * loads - a 32 bit linear address has nothing at bits 32-47, so both the right
 * half and the wrong half are zero and the gate still names a truncated
 * address. The case pins the shift the CPU's addressing requires. */
static int gate_prop_offset_high(const uint8_t *p, size_t n) {
  static const uint8_t shr16[] = {0x48, 0xC1, 0xE8, 0x10}; /* shr rax, 16 */
  static const uint8_t shr32[] = {0x48, 0xC1, 0xE0, 0x20}; /* shr rax, 32 */
  /* the store of that half, at slot+6 = 6*16+6 = 102 = 0x66 */
  static const uint8_t store[] = {0x66, 0x89, 0x44, 0x24, 0x66};
  return gate_find(p, n, shr16, 4) != 0 && gate_find(p, n, shr32, 4) == 0 &&
         gate_find(p, n, store, 5) != 0;
}

/* 2. The stride. The CPU addresses vector N at base + N*16, because a 64 bit
 * IDT entry is sixteen bytes wide. A probe that writes its gate eight bytes
 * per vector puts it twelve entries from the trap, and the entry the CPU reads
 * is untouched frame with a type byte of zero: not present, refused with
 * #GP(vector*8+2). The case pins the displacement the CPU itself uses, not
 * the arithmetic that produced it. */
static int gate_prop_stride(const uint8_t *p, size_t n) {
  static const uint8_t off_lo16[] = {0x66, 0x89, 0x44, 0x24, 0x60}; /* slot+0 */
  static const uint8_t off_lo8[]  = {0x66, 0x89, 0x44, 0x24, 0x30}; /* 6*8   */
  static const uint8_t sel16[]    = {0x66, 0x89, 0x44, 0x24, 0x62}; /* slot+2 */
  static const uint8_t sel8[]     = {0x66, 0x89, 0x44, 0x24, 0x32}; /* 6*8+2 */
  static const uint8_t type16[]   = {0xC6, 0x44, 0x24, 0x65, 0x8E}; /* slot+5 */
  return gate_find(p, n, off_lo16, 5) != 0 && gate_find(p, n, off_lo8, 5) == 0 &&
         gate_find(p, n, sel16, 5) != 0 && gate_find(p, n, sel8, 5) == 0 &&
         gate_find(p, n, type16, 5) != 0;
}

/* 3. The selector. A gate naming a selector the firmware is not running in is
 * refused with a #GP whose error code IS that selector, which is how a
 * hardcoded 0x0038 looked identical to a missing gate for as long as the
 * firmware happened to be at 0x0038. The probe therefore READS the selector
 * out of a gate the firmware itself installed, and the case fails if any
 * sixteen bit immediate load appears at all. */
static int gate_prop_selector(const uint8_t *p, size_t n) {
  static const uint8_t sidt[]  = {0x0F, 0x01, 0x8C, 0x24}; /* sidt [rsp+d32]  */
  static const uint8_t base[]  = {0x48, 0x8B, 0x94, 0x24}; /* mov rdx,[rsp+d32]*/
  static const uint8_t gate[]  = {0x66, 0x8B, 0x42, 0x02}; /* mov ax,[rdx+2]  */
  static const uint8_t lit[]   = {0x66, 0xB8};           /* mov ax, imm16    */
  return gate_find(p, n, sidt, 4) != 0 && gate_find(p, n, base, 4) != 0 &&
         gate_find(p, n, gate, 4) != 0 && gate_find(p, n, lit, 2) == 0;
}

/* 4. The frame. The probe reserves its block with a sub and gives it back with
 * an add of the SAME size, and never masks rsp. A mask would be load bearing
 * for no path and would break the caller that already entered with rsp 16 byte
 * aligned, which is the entry the established consumer gives. */
static int gate_prop_frame(const uint8_t *p, size_t n) {
  static const uint8_t sub[]   = {0x48, 0x81, 0xEC};
  static const uint8_t add[]   = {0x48, 0x81, 0xC4};
  static const uint8_t mask8[] = {0x48, 0x83, 0xE4}; /* and rsp, imm8  */
  static const uint8_t mask32[]= {0x48, 0x81, 0xE4}; /* and rsp, imm32 */
  size_t a = gate_find(p, n, sub, 3), b = gate_find(p, n, add, 3);
  if (!a || !b) return 0;
  if (gate_find(p, n, mask8, 3) || gate_find(p, n, mask32, 3)) return 0;
  return memcmp(p + a + 2, p + b + 2, 4) == 0; /* identical imm32 */
}

/* 5. The stub's frame arithmetic.
 *
 * The gate is only half the trap. Once the CPU vectors, the generated stub has
 * to advance the saved RIP by exactly the length of the instruction that
 * raised the vector, and it has to do that in the slot the CPU actually put
 * the saved RIP in. Both are silent when wrong and both were wrong here: the
 * gate named the probe's own `ret` instead of the stub, and a `ret` in the
 * gate target pops the saved RIP and CS and returns to the instruction that
 * raised the vector, so the trap re-arms itself forever. The boot showed it
 * as 646000 identical #UDs at one address before anyone read this.
 *
 * A #UD at CPL 0 pushes RIP, CS and RFLAGS and no error code, so after the
 * stub's own `push rax` the saved RIP is at [rsp+8]. The case pins that slot,
 * the two byte advance, and the iretq that consumes what was pushed.
 */
static int gate_prop_stub_frame(const uint8_t *p, size_t n) {
  static const uint8_t load[]  = {0x48, 0x8B, 0x44, 0x24, 0x08}; /* [rsp+8]  */
  static const uint8_t store[] = {0x48, 0x89, 0x44, 0x24, 0x08}; /* [rsp+8]  */
  static const uint8_t by2[]   = {0x48, 0x83, 0xC0, 0x02};      /* add rax,2 */
  static const uint8_t iretq[] = {0x48, 0xCF};
  static const uint8_t load16[]  = {0x48, 0x8B, 0x44, 0x24, 0x10};
  static const uint8_t store16[] = {0x48, 0x89, 0x44, 0x24, 0x10};
  return gate_find(p, n, load, 5) != 0 && gate_find(p, n, store, 5) != 0 &&
         gate_find(p, n, by2, 4) != 0 && gate_find(p, n, iretq, 2) != 0 &&
         gate_find(p, n, load16, 5) == 0 && gate_find(p, n, store16, 5) == 0;
}

/* 6-8. The transfer clauses, read off the EMITTED STUB and not off the
 * declaration.
 *
 * WHY THESE THREE ARE SEPARATE FROM CASE 5. The `swapgs`, `interrupts` and
 * `exit` FIELDS were already confronted reason by reason: a declaration that
 * says `swapgs always` is refused with 11 and `interrupts disable` with 12,
 * and both refusals are compared to the C oracle's own wording. That is a
 * check on the TABLE. It says the declaration may only spell one policy; it
 * says nothing about whether the bytes the emitter then wrote honour it, and
 * a table rule is satisfiable by a writer that ignores the field entirely.
 *
 * So the three are checked where they are actually performed, on the 18 bytes
 * this module emitted for the #UD witness: 50 48 8b 44 24 08 48 83 c0 02
 * 48 89 44 24 08 58 48 cf -- push rax, load [rsp+8], add rax,2, store [rsp+8],
 * pop rax, iretq. No `swapgs` opcode, no interrupt mask, and an `iretq` that
 * is the LAST instruction rather than merely one somewhere in the body.
 *
 * SCOPE, PUBLISHED BECAUSE A READER CANNOT SEE IT: these run on the #UD
 * (vector 6, no error code, save set {rax}) profile ONLY. The #GP profile and
 * the syscall profile are declared and their plans are compared against the C
 * body, but neither is run through these three. Generalising them to those
 * profiles would be exactly the inference this file refuses elsewhere, so the
 * limitation is in the case rather than in a report.
 *
 * LIMIT OF THE TWO SINGLE-BYTE SEARCHES: `cli` and `sti` are one-byte opcodes,
 * so a byte scan for them can in principle match an immediate or a
 * displacement. It can only make the predicate REFUSE, never accept, so the
 * failure mode is a red on a legal body and not a green on an illegal one.
 * `swapgs` is three bytes and has no such ambiguity.
 */
static int gate_prop_no_swapgs(const uint8_t *p, size_t n) {
  static const uint8_t swapgs[] = {0x0F, 0x01, 0xF8};
  return gate_find(p, n, swapgs, 3) == 0;
}

static int gate_prop_no_interrupt_mask(const uint8_t *p, size_t n) {
  static const uint8_t cli[] = {0xFA};
  static const uint8_t sti[] = {0xFB};
  return gate_find(p, n, cli, 1) == 0 && gate_find(p, n, sti, 1) == 0;
}

/* The terminal transfer is TERMINAL: the last instruction of the emitted body
 * is the iretq. Case 5 only asks that an iretq occurs somewhere, which a stub
 * that fell through into further code would satisfy. */
static int gate_prop_terminal_transfer(const uint8_t *p, size_t n) {
  static const uint8_t iretq[] = {0x48, 0xCF};
  if (n < 2) return 0;
  return memcmp(p + n - 2, iretq, 2) == 0;
}

typedef int (*GateProp)(const uint8_t *, size_t);

/* on_stub says which buffer the case reads: the probe builds the gate, the
 * generated stub consumes the frame the gate lets the CPU push.
 *
 * profile_free says whether the case may be asked of a stub of ANY profile, and
 * it is a SEPARATE axis from on_stub because the two were conflated and the
 * conflation was a defect: on_stub alone would have carried `stub frame` into
 * the #GP run, where it refused — and correctly so, because it demands the
 * saved RIP at [rsp+8] and the ABSENCE of [rsp+16], which is the no-error
 * profile and nothing else. A boolean cannot say "this one is about the
 * transfer, and the transfer is the same whichever frame carried it", and that
 * is exactly the claim the third case now carries on two bodies instead of
 * one. */
static const struct {
  const char *name;
  GateProp prop;
  int on_stub;
  int profile_free;
} GATE_CASES[] = {
    /* the high half: the silent shift-by-32 mistake */
    {"offset[31:16]", gate_prop_offset_high, 0, 0},
    /* the stride: the gate back at vector*8, twelve entries from the trap */
    {"stride", gate_prop_stride, 0, 0},
    /* the selector: a literal instead of the firmware's own gate */
    {"selector", gate_prop_selector, 0, 0},
    /* the frame: a different number given back than was reserved */
    {"symmetric frame", gate_prop_frame, 0, 0},
    /* the stub: the saved-RIP slot of the NO-ERROR profile, the advance, and
     * the iretq. Not profile-free: the [rsp+16] absence below is the frame
     * class itself, so this case is #UD-shaped and says so here rather than
     * being discovered refusing on #GP. */
    {"stub frame", gate_prop_stub_frame, 1, 0},
    /* the transfer clauses: no swapgs, no interrupt mask, and an iretq that is
     * the LAST instruction. Profile-free, and the run over #GP is what turns
     * that word from a claim into a measurement. */
    {"no swapgs", gate_prop_no_swapgs, 1, 1},
    {"no interrupt mask", gate_prop_no_interrupt_mask, 1, 1},
    {"terminal transfer", gate_prop_terminal_transfer, 1, 1},
};

/* Break one property in a copy of the real probe and require the predicate to
 * notice. Returns non-zero when the negative proof held. */
static int gate_negative(const uint8_t *p, size_t n, GateProp prop) {
  static const uint8_t shr16[] = {0x48, 0xC1, 0xE8, 0x10};
  static const uint8_t shr32[] = {0x48, 0xC1, 0xE0, 0x20};
  static const uint8_t off16[] = {0x66, 0x89, 0x44, 0x24, 0x60};
  static const uint8_t off8[]  = {0x66, 0x89, 0x44, 0x24, 0x30};
  static const uint8_t load[]  = {0x66, 0x8B, 0x42, 0x02};
  static const uint8_t lit[]   = {0x66, 0xB8, 0x38, 0x00};
  uint8_t *copy = malloc(n);
  int held = 0;
  if (!copy) return 0;
  memcpy(copy, p, n);
  if (prop == gate_prop_offset_high) {
    size_t at = gate_find(copy, n, shr16, 4);
    if (at) { memcpy(copy + at - 1, shr32, 4); held = !prop(copy, n); }
  } else if (prop == gate_prop_stride) {
    size_t at = gate_find(copy, n, off16, 5);
    if (at) { memcpy(copy + at - 1, off8, 5); held = !prop(copy, n); }
  } else if (prop == gate_prop_selector) {
    size_t at = gate_find(copy, n, load, 4);
    if (at) { memcpy(copy + at - 1, lit, 4); held = !prop(copy, n); }
  } else if (prop == gate_prop_stub_frame) {
    /* advance the saved RIP one qword too far, as if this trap carried an
     * error code that a #UD at CPL 0 does not carry */
    size_t at = gate_find(copy, n, (const uint8_t[]){0x48, 0x8B, 0x44, 0x24, 0x08}, 5);
    if (at) { copy[at + 4] = 0x10; held = !prop(copy, n); }
  } else if (prop == gate_prop_frame) {
    size_t at = gate_find(copy, n, (const uint8_t[]){0x48, 0x81, 0xC4}, 3);
    if (at) { copy[at + 3] ^= 0x01; held = !prop(copy, n); }
  } else if (prop == gate_prop_no_swapgs) {
    /* length-preserved: the four byte `add rax,2` becomes `swapgs; nop`, so
     * the body keeps its size and only the opcode under test changes */
    size_t at = gate_find(copy, n, (const uint8_t[]){0x48, 0x83, 0xC0, 0x02}, 4);
    if (at) {
      memcpy(copy + at - 1, (const uint8_t[]){0x0F, 0x01, 0xF8, 0x90}, 4);
      held = !prop(copy, n);
    }
  } else if (prop == gate_prop_no_interrupt_mask) {
    /* the `pop rax` becomes a `cli`, one byte for one byte */
    size_t at = gate_find(copy, n, (const uint8_t[]){0x58}, 1);
    if (at) { copy[at - 1] = 0xFA; held = !prop(copy, n); }
  } else if (prop == gate_prop_terminal_transfer) {
    /* the trailing iretq becomes a ret: the transfer is no longer TERMINAL.
     * Case 5 asks that an iretq occur somewhere and this body has none, so
     * the twin isolates terminality from presence. */
    if (n >= 2) {
      copy[n - 2] = 0x48;
      copy[n - 1] = 0xC3; /* ret */
      held = !prop(copy, n);
    }
  }
  free(copy);
  return held;
}

static void gate_cases(const uint8_t *probe, size_t pn, const uint8_t *stub,
                       size_t sn) {
  for (size_t i = 0; i < sizeof GATE_CASES / sizeof GATE_CASES[0]; i++) {
    const uint8_t *p = GATE_CASES[i].on_stub ? stub : probe;
    size_t n = GATE_CASES[i].on_stub ? sn : pn;
    cases++;
    checks++;
    if (!GATE_CASES[i].prop(p, n)) {
      failures++;
      fprintf(stderr, "FAIL gate %s: the emitted probe does not carry it\n",
              GATE_CASES[i].name);
      continue;
    }
    /* the negative proof: same predicate, property broken, must reject */
    checks++;
    if (!gate_negative(p, n, GATE_CASES[i].prop)) {
      failures++;
      fprintf(stderr,
              "FAIL gate %s: the predicate accepted a probe with the property "
              "broken, so it pins nothing\n",
              GATE_CASES[i].name);
    }
  }
}

/* The transfer predicates over an emitted stub, WITHOUT the four probe cases.
 *
 * WHY A SECOND RUNNER AND NOT A SECOND CALL OF gate_cases. gate_cases reads
 * `probe` for four of its five cases, and the probe is something
 * `build_witness_pe` emits for ONE declared vector. A stub built by plain
 * `build_pe` carries no probe at all, so passing it a second pair would run
 * four probe predicates against an empty buffer and report four reds that say
 * nothing about the stub. This runner therefore reads the stub and only the
 * stub, which is what makes the second pair legitimate rather than a guess.
 *
 * It is ALSO the instrument that answers whether the transfer clauses are
 * indexed by vector or by profile: it carries no vector, takes the bytes, and
 * asks. Two bodies of DIFFERENT profiles, both answering, is a second instance
 * of the same rule; one body answering is a profile that was chosen.
 */
/* How many members of GATE_CASES each stub run actually asked, and how many
 * it did not, BY NAME. A member skipped without being named is a member that
 * reads as tested and is not, so the skip is published rather than performed:
 * a reader who sees `asked 3 of 8` can go and ask why the other five are not
 * answered here. */
static void transfer_cases(const uint8_t *stub, size_t sn, const char *label) {
  unsigned asked = 0, not_asked = 0;
  for (size_t i = 0; i < sizeof GATE_CASES / sizeof GATE_CASES[0]; i++) {
    /* profile_free, NOT on_stub: `stub frame` reads the stub too and is #UD
     * shaped, so selecting on on_stub would ask it about #GP and take a red
     * that says nothing about the transfer. */
    if (!GATE_CASES[i].profile_free) {
      not_asked++;
      continue;
    }
    asked++;
    cases++;
    checks++;
    if (!GATE_CASES[i].prop(stub, sn)) {
      failures++;
      fprintf(stderr,
              "FAIL transfer %s %s: the emitted stub does not carry it\n", label,
              GATE_CASES[i].name);
      continue;
    }
    /* the negative twin, so a second instance is not a weaker proof than the
     * first: it must still reject the property broken */
    checks++;
    if (!gate_negative(stub, sn, GATE_CASES[i].prop)) {
      failures++;
      fprintf(stderr,
              "FAIL transfer %s %s: the predicate accepted a stub with the "
              "property broken, so it pins nothing\n",
              label, GATE_CASES[i].name);
    }
  }
  fprintf(stderr,
          "TRANSFER_COVER label=%s predicates=%u members_asked=%u "
          "members_not_asked=%u\n",
          label, (unsigned)(sizeof GATE_CASES / sizeof GATE_CASES[0]), asked,
          not_asked);
}

/* THE PROFILES, AS DATA, AND WHY THE LIST IS THE WHOLE CLASS.
 *
 * A profile here is a COUPLE — a vector and whether the CPU pushes an error
 * code for it — because those are the two things a frame differs on, and
 * because the thing that decides them is a pair and not a name.
 *
 * This table is not a choice, it is a TRANSCRIPT of what the producer admits:
 * `encodable` in stub_table.nova publishes exactly two couples, (6, no error
 * code) and (13, error code), and refuses every other by 306. So the class is
 * closed BY THE PRODUCER, and the closure is what `profile_class_closed`
 * checks: it walks vectors and both error-code settings, and requires that
 * every couple outside this table is REFUSED rather than emitted. Without that
 * check this table would be a list of two that happens to match today, and it
 * would go stale silently the day the producer admitted a third vector.
 *
 * So the product is GATE_CASES x PROFILES filtered by profile_free: 3 x 2 = 6
 * members, every one of them asked. A fourth vector does not need code edited
 * here to be exercised — it needs to be added to `encodable`, and this gate
 * then REFUSES to keep quiet about it.
 */
typedef struct {
  const char *label;
  uint64_t vector;
  int error_code;
} Profile;

static const Profile PROFILES[] = {
    {"ud", 6, 0},
    {"gp", 13, 1},
};

/* The declared vector of a profile, and its error-code spelling, so the pair
 * is BUILT from the table rather than written out again at each call site: a
 * table whose callers disagree with it is two tables. */
static char *profile_body(const Profile *p) {
  return p->error_code ? interrupt_gp("13", "isr13") : interrupt_ud("6", "isr6");
}

/* The declared vector of a profile that is NOT in the table, as a source the
 * producer is expected to refuse. Used only by the closure check.
 *
 * It goes through the SAME `entry` helper the fixtures use, so the closure walk
 * cannot drift from the shape it claims to be probing: a hand-written source
 * here would have been a second spelling of a stub, and the first version of
 * this function WAS one — it emitted a bare `stub N { }` with no enclosing
 * table, every couple came back 800, and the check reported 510 couples
 * "emitted". A refusal code that means "this text did not parse" is not a
 * refusal of the profile, and an instrument that cannot tell those two apart
 * would have declared the class closed on 510 parse errors. */
static char *outside_body(uint64_t vector, int error_code) {
  char key[8];
  snprintf(key, sizeof key, "%llu", (unsigned long long)vector);
  return entry(key, "advance_saved_rip_2",
               error_code ? "nx64-interrupt-same-cpl-error-v0"
                          : "nx64-interrupt-same-cpl-v0",
               error_code ? "nx64-iretq-same-cpl-error-v0"
                          : "nx64-iretq-same-cpl-v0",
               "iretq",
               error_code ? "x86_64.frame.error.same_cpl"
                          : "x86_64.frame.no_error.same_cpl",
               error_code ? "true" : "false", "{rax}", "{}", "0", "never",
               "preserve", ".text", "export", "isrX");
}

/* The same couple inside a one-table wrapper, which is the shape `build_pe`
 * consumes. `entry` alone is not a module the image route will read. */
static char *outside_source(uint64_t vector, int error_code) {
  char *one = outside_body(vector, error_code);
  if (!one) return NULL;
  static char buffer[2048];
  snprintf(buffer, sizeof buffer,
           "stub_table t kind interrupt {\n%s}\n", one);
  free(one);
  return buffer;
}

static int in_profiles(uint64_t vector, int error_code) {
  for (size_t i = 0; i < sizeof PROFILES / sizeof PROFILES[0]; i++)
    if (PROFILES[i].vector == vector && PROFILES[i].error_code == error_code)
      return 1;
  return 0;
}

/* IS THE CLASS CLOSED? Every couple this producer can be given, outside the
 * table, must be REFUSED by the image route. A couple that is EMITTED here is
 * a third profile the transfer predicates are not being run against, and that
 * is precisely the gap a list-of-two leaves open.
 *
 * The walk is over the whole published vector range and both error-code
 * settings, so it does not depend on which two the table happens to name: the
 * producer, not this list, decides the size of the class. */
static void profile_class_closed(const NovaHostImage *image) {
  uint8_t *pe = malloc(IMG_PE_CAP);
  if (!pe) {
    cases++;
    CHECK(0, "closure allocation");
    return;
  }
  unsigned refused = 0, emitted = 0;
  for (uint64_t v = 0; v <= 255; v++) {
    for (int e = 0; e <= 1; e++) {
      if (in_profiles(v, e)) continue;
      char *one = outside_source(v, e);
      char *source = one ? assemble(one, NULL) : NULL;
      if (!source) {
        /* a source this harness could not even build is a hole in the WALK,
         * not a refusal of the couple, and it must not be counted as one */
        cases++;
        checks++;
        failures++;
        fprintf(stderr,
                "FAIL profile class: vector %llu error_code %d produced no "
                "source, so the walk cannot decide this couple\n",
                (unsigned long long)v, e);
        /* `one` is a static buffer: not freed here either */
        continue;
      }
      ImgRun r = img_run(image, source, OUT_WORDS, 0, pe, IMG_PE_CAP, "unused");
      cases++;
      checks++;
      /* 306 is `lower` refusing to invent an encoding, which is the refusal
       * the class boundary is made of. Anything else that ACCEPTS is a member
       * of the class this table does not name — and so is anything that failed
       * to parse (800), because a source the producer cannot read has not been
       * refused on its MERITS. */
      if (r.returned == 306) {
        refused++;
      } else {
        emitted++;
        failures++;
        fprintf(stderr,
                "FAIL profile class: vector %llu error_code %d was not refused "
                "by 306 (ret=%llu) and is not in PROFILES, so the transfer "
                "predicates are not asked of it\n",
                (unsigned long long)v, e, (unsigned long long)r.returned);
      }
      /* `one` is a static buffer inside outside_source: it is NOT freed here,
       * and freeing it is exactly what -Werror=free-nonheap-object caught */
      free(source);
    }
  }
  fprintf(stderr,
          "PROFILE_CLASS members=%u refused_outside=%u emitted_outside=%u\n",
          (unsigned)(sizeof PROFILES / sizeof PROFILES[0]), refused, emitted);
  free(pe);
}

/* The stub bytes of one record inside an image produced by `build_pe`, with
 * the number of bytes the export itself reported for it. The offset and the
 * length are read from out[], which is the export's own answer and not a
 * recomputation: a producer that reported a length it did not write is caught
 * by the memcmp below, and one that wrote past it by the terminator check. */
static void transfer_image(const NovaHostImage *image, const char *label,
                           const char *source) {
  uint8_t *pe = malloc(IMG_PE_CAP);
  if (!pe) {
    cases++;
    CHECK(0, "transfer image allocation");
    return;
  }
  ImgRun r = img_run(image, source, OUT_WORDS, 0, pe, IMG_PE_CAP, "unused");
  cases++;
  if (r.returned != 0 || r.runtime != 0 || r.out[1] != 1 || r.out[5] == 0) {
    failures++;
    fprintf(stderr,
            "FAIL transfer image %s ret=%llu runtime=%llu records=%llu body=%llu\n",
            label, (unsigned long long)r.returned, (unsigned long long)r.runtime,
            (unsigned long long)r.out[1], (unsigned long long)r.out[5]);
    free(pe);
    return;
  }
  size_t offset = (size_t)r.out[4], body = (size_t)r.out[5];
  if (IMG_TEXT_RAW + offset + body > (size_t)r.out[0]) {
    failures++;
    fprintf(stderr, "FAIL transfer image %s: the body runs past the image\n", label);
    free(pe);
    return;
  }
  transfer_cases(pe + IMG_TEXT_RAW + offset, body, label);
  free(pe);
}

static void image_route(const NovaHostImage *image) {
  char *body = NULL;
  char *source = NULL;

  /* #UD vector 6: the image is the C body, byte for byte, inside a PE the C
   * writer would have produced. */
  body = interrupt_ud("6", "isr6");
  source = assemble(body, IMAGE_TAIL);
  image_case(image, "ud_image", source, 0);
  free(body);
  free(source);

  /* #GP vector 13: the error code slot removal is in the image too, and the
   * C oracle is what says so. */
  body = interrupt_gp("13", "isr13");
  source = assemble(body, IMAGE_TAIL);
  image_case(image, "gp_image", source, 0);
  free(body);
  free(source);

  /* EVERY MEMBER OF THE CLASS, in the order the table gives, and the closure
   * of the class beside it. The two bodies this walks are the two the producer
   * admits — #UD (6, no error code, 18 bytes) and #GP (13, error code, 22
   * bytes) — and they differ on the frame arithmetic and agree on the transfer,
   * which is the measured shape of the claim rather than something this
   * comment asserts. `profile_class_closed` then walks all 512 couples the
   * range allows and requires every one outside the table to be REFUSED, so
     * the class cannot grow without this run going red. */
  for (size_t i = 0; i < sizeof PROFILES / sizeof PROFILES[0]; i++) {
    body = profile_body(&PROFILES[i]);
    source = assemble(body, IMAGE_TAIL);
    transfer_image(image, PROFILES[i].label, source);
    free(body);
    free(source);
  }
  profile_class_closed(image);

  /* Two tables, one record each: the records come out in canonical key order
   * and the symbols go into the object in ascending name order, so the two
   * orders disagree on purpose and the image has to follow the symbol one. */
  {
    char *first = interrupt_ud("6", "isr6");
    char *second = interrupt_gp("13", "isr13");
    char buffer[4096];
    snprintf(buffer, sizeof buffer, "%s%s", first, second);
    source = assemble(buffer, IMAGE_TAIL);
    image_case(image, "two_image", source, 0);
    free(first);
    free(second);
    free(source);
  }

  /* The witness: the same generated stub preceded by the probe, with every
   * probe byte assembled by the frozen C encoder at run time. */
  body = interrupt_ud("6", "isr6");
  source = assemble(body, IMAGE_TAIL);
  {
    uint8_t expected[512];
    size_t probe = probe_from_oracle(expected, sizeof expected, 6);
    uint8_t *pe = malloc(IMG_PE_CAP);
    CHECK(pe != NULL, "witness allocation");
    if (pe && probe) {
      ImgRun r = img_run(image, source, OUT_WORDS, 1, pe, IMG_PE_CAP, "unused");
      cases++;
      checks++;
      int bad = r.returned != 0 || r.runtime != 0 || r.out[1] != 1 ||
                r.out[2] != 0 || r.out[3] != 0 ||
                r.out[4] != probe || r.out[5] == 0;
      if (bad) {
        failures++;
        fprintf(stderr,
                "FAIL witness ret=%llu runtime=%llu out1=%llu out2=%llu "
                "out4=%llu probe=%zu\n",
                (unsigned long long)r.returned, (unsigned long long)r.runtime,
                (unsigned long long)r.out[1], (unsigned long long)r.out[2],
                (unsigned long long)r.out[4], probe);
      } else if (memcmp(pe + IMG_TEXT_RAW, expected, probe) != 0) {
        failures++;
        for (size_t k = 0; k < probe; k++)
          fprintf(stderr, "FAIL witness probe [%zu] nova=%02x oracle=%02x\n", k,
                  pe[IMG_TEXT_RAW + k], expected[k]);
      }
      /* the stub itself still has to be the C body */
      if (!bad) {
        checks++;
        size_t oracle_size = 0;
        uint8_t *oracle = c_stub_body(source, "isr6", &oracle_size);
        if (!oracle || oracle_size != r.out[5] ||
            memcmp(pe + IMG_TEXT_RAW + r.out[4], oracle, oracle_size) != 0) {
          failures++;
          fprintf(stderr, "FAIL witness stub nova=%llu oracle=%zu\n",
                  (unsigned long long)r.out[5], oracle_size);
        }
        free(oracle);
      }
      /* and the whole file still has to be the C writer's file */
      if (!bad) {
        size_t oracle_size = 0;
        uint8_t *oracle = pe_oracle_image(pe + IMG_TEXT_RAW,
                                          (size_t)(probe + r.out[5]), 0,
                                          &oracle_size);
        checks++;
        if (!oracle || oracle_size != r.out[0] ||
            memcmp(pe, oracle, (size_t)r.out[0]) != 0) {
          failures++;
          fprintf(stderr, "FAIL witness PE parity nova=%llu oracle=%zu\n",
                  (unsigned long long)r.out[0], oracle_size);
          if (oracle)
            for (size_t k = 0; k < (size_t)r.out[0] && k < oracle_size; k++)
              if (pe[k] != oracle[k]) {
                fprintf(stderr,
                        "  first difference at %zu: nova=%02x oracle=%02x\n",
                        k, pe[k], oracle[k]);
                break;
              }
        }
        free(oracle);
      }
      /* The four gate properties, over the bytes this emitter actually
       * produced. They run on the witness image and not on the oracle copy,
       * because what they are about is what the Nova side emits. */
      gate_cases(pe + IMG_TEXT_RAW, probe, pe + IMG_TEXT_RAW + r.out[4],
                 (size_t)r.out[5]);
    }
    if (!pe || !probe) {
      cases++;
      checks++;
      failures++;
      fprintf(stderr,
              "FAIL witness did not run: allocation=%s probe=%zu\n",
              pe ? "ok" : "failed", probe);
    }
    free(pe);
  }
  free(body);
  free(source);

  /* The refusals of the image route. Each is measured, not asserted from a
   * literal, and the two that the C can express are confronted with it. */

  /* A structured syscall stub: the C lowers the same declaration to a framed
   * body with a REL32 to the handler, which is exactly what this emitter
   * refuses to invent. The measurement is in the gate so the boundary is
   * documented by a number and not by a claim. */
  body = syscall_table("0", "entry0");
  {
    char exported[1024];
    snprintf(exported, sizeof exported,
             "section .text {\nexport fn main()->u64\neffects {}\nclobbers {} "
             "{\nreturn 0\n}\nfn dispatch()->u64\neffects {}\nclobbers {} "
             "{\nreturn 42\n}\n}\n");
    source = assemble(body, exported);
  }
  {
    size_t bytes = 0, relocations = 0;
    c_stub_measure(source, "entry0", &bytes, &relocations);
    checks++;
    if (bytes < 64 || relocations != 1) {
      failures++;
      fprintf(stderr,
              "FAIL syscall oracle shape: the C emitted %zu bytes and %zu "
              "relocations, the image route claims a link it does not do\n",
              bytes, relocations);
    }
  }
  /* A6, 13 October 2026: build_pe keeps refusing a syscall table (306 reason
   * 6): the safe-return syscall stub is an ordinary function and is produced
   * by the common chain (stub_table.graft, machine_pipeline), where its
   * acceptance is required against the reference compiling this same kind of
   * declaration (machine_corpus, stub-syscall-* and stub-pair-*). An
   * acceptance expected HERE was measured red on 13 October 2026 (1445/1,
   * this row only); that acceptance moved to the chain's route, not away. */
  image_refuse(image, "syscall_image", source, 0, 306, 6, 1);
  free(body);
  free(source);

  /* A legal declaration no proven profile covers. */
  body = interrupt_ud("7", "isr7");
  source = assemble(body, IMAGE_TAIL);
  image_refuse(image, "vector7_image", source, 0, 306, 1, 1);
  free(body);
  free(source);

  /* A save set the proven profiles do not preserve. */
  body = table_one("interrupt", "6", "advance_saved_rip_2",
                   "nx64-interrupt-same-cpl-v0", "nx64-iretq-same-cpl-v0",
                   "iretq", "x86_64.frame.no_error.same_cpl", "false", "{rbx}",
                   "{}", "0", "never", "preserve", ".text", "export", "isr6");
  source = assemble(body, IMAGE_TAIL);
  image_refuse(image, "rbx_image", source, 0, 306, 2, 1);
  free(body);
  free(source);

  /* A module that declares no stub at all. */
  source = assemble("", IMAGE_TAIL);
  image_refuse(image, "empty_image", source, 0, 306, 7, 0);
  free(source);

  /* A declaration refusal reaches the image route with the same verdict the
   * declaration pass publishes, not with an image reason. */
  body = table_one("interrupt", "6", "advance_saved_rip_0",
                   "nx64-interrupt-same-cpl-v0", "nx64-iretq-same-cpl-v0",
                   "iretq", "x86_64.frame.no_error.same_cpl", "false", "{rax}",
                   "{}", "0", "never", "preserve", ".text", "export", "isr6");
  source = assemble(body, IMAGE_TAIL);
  {
    uint64_t line = 0, column = 0;
    int found = marker_position(source, "handler advance_saved_rip_0", &line,
                                &column);
    uint8_t *pe = malloc(IMG_PE_CAP);
    CHECK(pe != NULL, "declaration refusal allocation");
    if (pe) {
      ImgRun r =
          img_run(image, source, OUT_WORDS, 0, pe, IMG_PE_CAP, "unused");
      cases++;
      checks++;
      int bad = r.returned != 305 || r.runtime != 0 || r.out[0] != line ||
                r.out[1] != column || r.out[2] != 23 || r.out[3] != 0 ||
                !found;
      if (bad) {
        failures++;
        fprintf(stderr,
                "FAIL image declaration refusal ret=%llu out=%llu,%llu,%llu\n",
                (unsigned long long)r.returned, (unsigned long long)r.out[0],
                (unsigned long long)r.out[1], (unsigned long long)r.out[2]);
      }
      free(pe);
    }
  }
  free(body);
  free(source);

  /* The directory does not fit: the refusal names the words it needs and the
   * words it was given. */
  body = interrupt_ud("6", "isr6");
  source = assemble(body, IMAGE_TAIL);
  {
    uint8_t *pe = malloc(IMG_PE_CAP);
    CHECK(pe != NULL, "capacity allocation");
    if (pe) {
      ImgRun r = img_run(image, source, 8, 0, pe, IMG_PE_CAP, "unused");
      cases++;
      checks++;
      if (r.returned != 306 || r.runtime || r.out[0] != 12 || r.out[1] != 8 ||
          r.out[2] != 3 || r.out[3]) {
        failures++;
        fprintf(stderr,
                "FAIL image capacity ret=%llu out=%llu,%llu,%llu\n",
                (unsigned long long)r.returned, (unsigned long long)r.out[0],
                (unsigned long long)r.out[1], (unsigned long long)r.out[2]);
      }
      free(pe);
    }
  }
  /* A caller's byte buffer too short for the image. */
  {
    uint8_t small[64];
    ImgRun r = img_run(image, source, OUT_WORDS, 0, small, sizeof small,
                       "unused");
    cases++;
    checks++;
    if (r.returned != 840 || r.runtime || r.out[0] < 64 || r.out[2] != 9) {
      failures++;
      fprintf(stderr, "FAIL image short buffer ret=%llu out0=%llu out2=%llu\n",
              (unsigned long long)r.returned, (unsigned long long)r.out[0],
              (unsigned long long)r.out[2]);
    }
  }
  free(body);
  free(source);

  /* The file route: the bytes on disk are the bytes the producer claims, and
   * a refusal opens no path at all. */
  body = interrupt_ud("6", "isr6");
  source = assemble(body, IMAGE_TAIL);
  {
    /* $TMPDIR/ng-stub-table-image-<pid> was already unique between concurrent
     * runs -- the pid is -- so this is not a repair of a collision and it is
     * not claimed to be. It is one mechanism for the four harnesses in this
     * directory instead of four, and one that puts the file under NG_BUILD
     * when the driver supplied one. */
    char why[NG_RUN_DIR_MAX];
    char written[NG_RUN_DIR_MAX + 64];
    const char *path = ng_run_file("ng-stub-table-image.efi", written,
                                   sizeof written, why, sizeof why);
    CHECK(path != NULL, "the run owns a private path for the stub table image");
    if (!path) fprintf(stderr, "FAIL TEMP-ISOLATION %s\n", why);
    remove(written);
    uint8_t *pe = malloc(IMG_PE_CAP);
    uint8_t *sink = malloc(IMG_PE_CAP);
    CHECK(pe != NULL && sink != NULL, "file route allocation");
    if (pe && sink) {
      /* The file must hold the bytes the in memory route produced for the same
       * source. Each run gets its own buffer because a run fills the byte
       * buffer it is handed with the guard before it starts. */
      ImgRun memory = img_run(image, source, OUT_WORDS, 0, pe, IMG_PE_CAP,
                              "unused");
      ImgRun r =
          img_run(image, source, OUT_WORDS, 2, sink, IMG_PE_CAP, written);
      FILE *f = fopen(written, "rb");
      long on_disk = f ? 0 : -1;
      uint8_t *read_back = NULL;
      if (f) {
        fseek(f, 0, SEEK_END);
        on_disk = ftell(f);
        fseek(f, 0, SEEK_SET);
        read_back = malloc(on_disk > 0 ? (size_t)on_disk : 1);
        if (read_back) {
          if (fread(read_back, 1, (size_t)on_disk, f) != (size_t)on_disk)
            on_disk = -1;
        } else {
          on_disk = -1;
        }
        fclose(f);
      }
      cases++;
      checks++;
      if (memory.returned != 0 || r.returned != 0 || r.runtime ||
          on_disk < 0 || (uint64_t)on_disk != r.out[0] ||
          (uint64_t)on_disk != memory.out[0] || !read_back ||
          memcmp(read_back, pe, (size_t)on_disk) != 0) {
        failures++;
        fprintf(stderr,
                "FAIL image file memory=%llu ret=%llu runtime=%llu "
                "claimed=%llu memory=%llu disk=%ld readback=%s\n",
                (unsigned long long)memory.returned,
                (unsigned long long)r.returned, (unsigned long long)r.runtime,
                (unsigned long long)r.out[0],
                (unsigned long long)memory.out[0], on_disk,
                read_back ? "yes" : "no");
      }
      free(read_back);
      free(sink);
      free(pe);
    } else {
      free(sink);
      free(pe);
    }
    remove(written);
    /* A refused declaration must not create the file it was refused for. */
    {
      char *refused = table_one("interrupt", "6", "advance_saved_rip_0",
                                "nx64-interrupt-same-cpl-v0",
                                "nx64-iretq-same-cpl-v0", "iretq",
                                "x86_64.frame.no_error.same_cpl", "false",
                                "{rax}", "{}", "0", "never", "preserve", ".text",
                                "export", "isr6");
      char *refused_source = assemble(refused, IMAGE_TAIL);
      uint8_t *pe = malloc(IMG_PE_CAP);
      if (pe) {
        ImgRun r = img_run(image, refused_source, OUT_WORDS, 2, pe, IMG_PE_CAP,
                           written);
        cases++;
        checks++;
        if (r.returned != 305 || r.runtime || fopen(written, "rb")) {
          failures++;
          fprintf(stderr,
                  "FAIL image file refusal ret=%llu created the file anyway\n",
                  (unsigned long long)r.returned);
        }
        free(pe);
      }
      remove(written);
      free(refused);
      free(refused_source);
    }
  }
  free(body);
  free(source);

  /* The witness route refuses a vector the probe does not raise. */
  body = interrupt_gp("13", "isr13");
  source = assemble(body, IMAGE_TAIL);
  image_refuse(image, "witness_vector13", source, 1, 306, 10, 1);
  free(body);
  free(source);
  /* And a witness over two records has no single IDT slot to describe. */
  {
    char *first = interrupt_ud("6", "isr6");
    char *second = interrupt_ud("6", "isr7");
    char buffer[4096];
    snprintf(buffer, sizeof buffer, "%s%s", first, second);
    source = assemble(buffer, IMAGE_TAIL);
    image_refuse(image, "witness_two", source, 1, 306, 10, 2);
    free(first);
    free(second);
    free(source);
  }
}

/* ------------------------------------------------------------------- main */

int main(void) {
  const char *paths[] = {"tests/nova/tests/stub-table-entry.nova",
                         "compiler/nova/frontend/stub_table.nova",
                         "compiler/nova/analysis/types/register_widths.nova",
                         "compiler/nova/formats/nxo/nxo_pe.nova",
                         "compiler/nova/formats/nxo/nxo.nova",
                         "compiler/nova/formats/pe/pe.nova",
                         "compiler/nova/analysis/semantics.nova",
                         "compiler/nova/frontend/parser.nova",
                         "compiler/nova/frontend/ast.nova",
                         "compiler/nova/frontend/lexer.nova"};
  char *sources[10] = {0};
  NtFInput inputs[10];
  for (unsigned i = 0; i < 10; i++) {
    FILE *f = fopen(paths[i], "rb");
    if (!f) continue;
    fseek(f, 0, SEEK_END);
    long z = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (z >= 0) {
      char *data = (char *)malloc((size_t)z + 1);
      if (data && fread(data, 1, (size_t)z, f) == (size_t)z) {
        data[z] = 0;
        sources[i] = data;
      } else {
        free(data);
      }
    }
    fclose(f);
    inputs[i] = (NtFInput){paths[i], sources[i], sources[i] ? strlen(sources[i]) : 0};
  }
  int loaded = 1;
  for (unsigned i = 0; i < 10; i++)
    if (!sources[i]) loaded = 0;
  CHECK(loaded, "sources load");
  NtArtifact artifact = {0};
  int compiled = loaded && nova_compile_many_v2(inputs, 10, &artifact);
  CHECK(compiled, "Nova modules compile");
  if (!compiled)
    fprintf(stderr, "E%u %zu:%zu %s\n", artifact.error.code, artifact.error.line,
            artifact.error.column, artifact.error.message);
  NovaHostImage image = {0};
  CHECK(compiled && nova_host_map(&artifact, &image), "image maps");

  /* The image artifact: the same stub_table.nova, with the NXO and PE
   * modules it now imports, behind the marshalling entry written above. The
   * seven module set above is untouched, so the declaration and plan coverage
   * that gate has carried since it was written still runs on the same code. */
  const char *image_paths[] = {"stub_table_image_entry.nova",
                               "compiler/nova/frontend/stub_table.nova",
                               "compiler/nova/analysis/types/register_widths.nova",
                               "compiler/nova/formats/nxo/nxo_pe.nova",
                               "compiler/nova/formats/nxo/nxo.nova",
                               "compiler/nova/formats/pe/pe.nova",
                               "compiler/nova/analysis/semantics.nova",
                               "compiler/nova/frontend/parser.nova",
                               "compiler/nova/frontend/ast.nova",
                               "compiler/nova/frontend/lexer.nova"};
  char *image_sources[10] = {0};
  NtFInput image_inputs[10];
  for (unsigned i = 0; i < 10; i++) {
    if (!strcmp(image_paths[i], "stub_table_image_entry.nova")) {
      image_sources[i] = dup_string(IMAGE_ENTRY);
    } else {
      FILE *f = fopen(image_paths[i], "rb");
      if (f) {
        fseek(f, 0, SEEK_END);
        long z = ftell(f);
        fseek(f, 0, SEEK_SET);
        if (z >= 0) {
          char *data = (char *)malloc((size_t)z + 1);
          if (data && fread(data, 1, (size_t)z, f) == (size_t)z) {
            data[z] = 0;
            image_sources[i] = data;
          } else {
            free(data);
          }
        }
        fclose(f);
      }
    }
    image_inputs[i] = (NtFInput){image_paths[i], image_sources[i],
                                image_sources[i] ? strlen(image_sources[i]) : 0};
  }
  int image_loaded = 1;
  for (unsigned i = 0; i < 10; i++)
    if (!image_sources[i]) image_loaded = 0;
  CHECK(image_loaded, "image module sources load");
  NtArtifact image_artifact = {0};
  int image_compiled = image_loaded && nova_compile_many_v2(image_inputs, 10,
                                                             &image_artifact);
  CHECK(image_compiled, "image Nova modules compile");
  if (!image_compiled)
    fprintf(stderr, "image E%u %zu:%zu %s\n", image_artifact.error.code,
            image_artifact.error.line, image_artifact.error.column,
            image_artifact.error.message);
  NovaHostImage image_image = {0};
  CHECK(image_compiled && nova_host_map(&image_artifact, &image_image),
        "image artifact maps");
  if (image_image.memory) {
    image_route(&image_image);
  } else {
    cases++;
    checks++;
    failures++;
    fprintf(stderr, "FAIL image cases did not run: no mapped image\n");
  }

  /* The QEMU campaign hook. It is off unless NG_STUB_TABLE_IMAGE names a
   * path, and when it is set the gate does nothing else: it writes the
   * witness image and reports the size, so the PE a firmware boots is the one
   * the code above pins. It runs BEFORE the artifact is unmapped, because the
   * mapped machine code is what the entry runs on, and it owns the teardown on
   * the way out because it returns before the teardown below. */
  {
    const char *target = getenv("NG_STUB_TABLE_IMAGE");
    if (target && image_image.memory) {
      char *witness = interrupt_ud("6", "isr6");
      char *program = assemble(witness, IMAGE_TAIL);
      uint8_t *sink = malloc(IMG_PE_CAP);

      /* NG_STUB_TABLE_DIAGNOSTIC selects the early-return diagnostic image,
       * which proves only that the entry is entered and returns. The shipped
       * witness is mode 3 and never carries those six bytes. */
      uint64_t wmode = getenv("NG_STUB_TABLE_DIAGNOSTIC") ? 5 : 3;
      ImgRun r =
          img_run(&image_image, program, OUT_WORDS, wmode, sink, IMG_PE_CAP,
                  target);
      printf("NTASM_NOVA_STUB_TABLE_IMAGE ret=%llu bytes=%llu mode=%llu "
             "out1=%llu out2=%llu out3=%llu path=%s\n",
             (unsigned long long)r.returned, (unsigned long long)r.out[0],
             (unsigned long long)wmode, (unsigned long long)r.out[1],
             (unsigned long long)r.out[2], (unsigned long long)r.out[3],
             target);
      free(sink);
      free(witness);
      free(program);
      nova_host_unmap(&image_image);
      if (image_compiled) nt_artifact_free(&image_artifact);
      for (unsigned i = 0; i < 10; i++) free(image_sources[i]);
      /* The hook returns before the bottom of main, so it owns the teardown of
       * the DECLARATION artifact too. Skipping it is what LeakSanitizer caught
       * first: compile_profile hands the three section buffers of an artifact
       * to the artifact and frees the rest of the code image itself
       * (nova.c:2509-2519), so an artifact nobody frees keeps all of them. */
      if (compiled) nt_artifact_free(&artifact);
      for (unsigned i = 0; i < 10; i++) free(sources[i]);
      return r.returned ? 1 : 0;
    }
  }

  if (image_image.memory) nova_host_unmap(&image_image);
  if (image_compiled) nt_artifact_free(&image_artifact);
  for (unsigned i = 0; i < 10; i++) free(image_sources[i]);
  if (image.memory) {
    char *body = NULL;
    char *source = NULL;
    char *section = NULL;

    /* ---- positives the C reference expresses exactly ---- */

    /* #UD vector 6: the C generates push/load/add/store/pop/iretq and the
     * plan must be that body step for step. */
    body = interrupt_ud("6", "isr6");
    source = assemble(body, NULL);
    accept(&image, "ud_accept", source, 1, 1, 1);
    {
      const uint64_t keys[] = {6};
      const uint64_t frames[] = {0};
      const uint64_t counts[] = {6};
      lower_plan(&image, "ud_plan", source, 1, 6, keys, frames, counts, 1);
    }
    free(body);
    free(source);

    /* #GP vector 13: the C adds the error-code slot removal before iretq. */
    body = interrupt_gp("13", "isr13");
    source = assemble(body, NULL);
    accept(&image, "gp_accept", source, 1, 1, 1);
    {
      const uint64_t keys[] = {13};
      const uint64_t frames[] = {1};
      const uint64_t counts[] = {7};
      lower_plan(&image, "gp_plan", source, 1, 7, keys, frames, counts, 1);
    }
    free(body);
    free(source);

    /* Structured syscall stub 0: the C generates a terminal handler call. */
    body = syscall_table("0", "entry0");
    section = section_block("{}");
    source = assemble(body, section);
    accept(&image, "syscall_accept", source, 1, 1, 1);
    {
      const uint64_t keys[] = {0};
      const uint64_t frames[] = {0};
      const uint64_t counts[] = {1};
      lower_plan(&image, "syscall_plan", source, 1, 1, keys, frames, counts, 1);
    }
    {
      Run m = run(&image, source, 64, 1);
      cases++;
      checks++;
      if (m.returned || m.runtime || m.out[0] != 1 || m.out[1] != 1 ||
          m.out[2] != 1 || m.out[3]) {
        failures++;
        fprintf(stderr, "FAIL measure syscall ret=%llu out=%llu,%llu,%llu\n",
                (unsigned long long)m.returned, (unsigned long long)m.out[0],
                (unsigned long long)m.out[1], (unsigned long long)m.out[2]);
      }
    }
    free(section);
    free(body);
    free(source);

    /* Structured syscall stubs declared out of numeric order. The plan must
     * follow the canonical numeric key (spec 11, case V0-STUB-001). The C
     * emits its generated functions in source order, so the ordering
     * assertion is spec-derived and the C is asked to accept the
     * declarations and to generate the same bodies, in its own order. */
    {
      char *first = syscall_entry("1", "entry1");
      char *second = syscall_entry("0", "entry0");
      char *table = table_two("syscall", first, second);
      section = section_block("{}");
      source = assemble(table, section);
      accept(&image, "reverse_accept", source, 1, 2, 1);
      {
        const uint64_t keys[] = {0, 1};
        const uint64_t frames[] = {0, 0};
        const uint64_t counts[] = {1, 1};
        lower_plan(&image, "reverse_plan", source, 2, 2, keys, frames, counts,
                   1);
      }
      /* The C order is the source order, measured so the divergence is on the
       * record and not merely asserted in prose. */
      {
        NtFProgram c;
        memset(&c, 0, sizeof c);
        int c_ok = c_verdict(source, &c);
        const char *first_name =
            c.function_count > 0 && c.functions[0].name ? c.functions[0].name : "";
        cases++;
        checks++;
        if (!c_ok || strcmp(first_name, "entry1") != 0) {
          failures++;
          fprintf(stderr, "FAIL c_source_order first=%s c=%d\n", first_name,
                  c_ok);
        }
        nt_frontend_free(&c);
      }
      free(first);
      free(second);
      free(table);
      free(section);
      free(source);
    }

    /* Four scrambled keys, dense from zero: the canonical order must be
     * 0,1,2,3 and every plan must still match the C body it generated. */
    {
      char *entries[4];
      char table[8192];
      size_t used;
      entries[0] = syscall_entry("3", "entry3");
      entries[1] = syscall_entry("1", "entry1");
      entries[2] = syscall_entry("0", "entry0");
      entries[3] = syscall_entry("2", "entry2");
      used = (size_t)snprintf(table, sizeof table, "stub_table t kind syscall {\n");
      for (unsigned i = 0; i < 4; i++) {
        used += (size_t)snprintf(table + used, sizeof table - used, "%s",
                                 entries[i]);
        free(entries[i]);
      }
      snprintf(table + used, sizeof table - used, "}\n");
      section = section_block("{}");
      source = assemble(table, section);
      accept(&image, "scrambled_accept", source, 1, 4, 1);
      {
        const uint64_t keys[] = {0, 1, 2, 3};
        const uint64_t frames[] = {0, 0, 0, 0};
        const uint64_t counts[] = {1, 1, 1, 1};
        lower_plan(&image, "scrambled_plan", source, 4, 4, keys, frames, counts,
                   1);
      }
      free(section);
      free(source);
    }

    /* A local interrupt stub keeps its visibility in the record and is still
     * encodable. */
    body = table_one("interrupt", "6", "advance_saved_rip_2",
                     "nx64-interrupt-same-cpl-v0", "nx64-iretq-same-cpl-v0",
                     "iretq", "x86_64.frame.no_error.same_cpl", "false", "{rax}",
                     "{}", "0", "never", "preserve", ".text", "local", "isr6");
    source = assemble(body, NULL);
    accept(&image, "local_accept", source, 1, 1, 1);
    {
      Run l = run(&image, source, OUT_WORDS, 2);
      uint64_t flags = out_words[4 + 10];
      cases++;
      checks++;
      if (l.returned || l.runtime || (flags & 1u) != 0 || (flags & 2u) != 2) {
        failures++;
        fprintf(stderr, "FAIL local_flags flags=%llu ret=%llu\n",
                (unsigned long long)flags, (unsigned long long)l.returned);
      }
    }
    free(body);
    free(source);

    /* An exported interrupt stub sets both flag bits. */
    body = interrupt_ud("6", "isr6");
    source = assemble(body, NULL);
    {
      Run l = run(&image, source, OUT_WORDS, 2);
      uint64_t flags = out_words[4 + 10];
      cases++;
      checks++;
      if (l.returned || l.runtime || flags != 3) {
        failures++;
        fprintf(stderr, "FAIL export_flags flags=%llu ret=%llu\n",
                (unsigned long long)flags, (unsigned long long)l.returned);
      }
    }
    free(body);
    free(source);

    /* A module with no stub table at all is accepted with empty counts. */
    source = assemble("", NULL);
    accept(&image, "no_table", source, 0, 0, 1);
    free(source);

    /* ---- refusals the C reference expresses ---- */

    /* Unknown table kind: the C refuses with 600 unsupported. */
    {
      char *one = syscall_entry("0", "entry0");
      char table[4096];
      snprintf(table, sizeof table, "stub_table t kind timer {\n%s}\n", one);
      section = section_block("{}");
      source = assemble(table, section);
      /* The diagnostic points at the kind value node, which is the name
       * after the `kind` keyword. */
      refuse(&image, "kind_unknown", source, 0, 305, 1, "kind timer", 0, 0);
      free(one);
      free(section);
      free(source);
    }

    /* An empty interrupt table. The C refuses it as a syntax error. The
     * diagnostic points at the table node. */
    source = assemble("stub_table t kind interrupt {\n}\n", NULL);
    refuse(&image, "empty_interrupt", source, 0, 305, 2, "stub_table", 0, 0);
    free(source);

    /* Duplicate structured syscall key: the C refuses with 300 duplicate.
     * The diagnostic points at the second entry. */
    {
      char *a = syscall_entry("0", "entry0");
      char *b = syscall_entry("0", "entry1");
      char *table = table_two("syscall", a, b);
      section = section_block("{}");
      source = assemble(table, section);
      refuse_entry(&image, "duplicate_syscall", source, 0, 305, 3, "0", 2, 0, 0);
      free(a);
      free(b);
      free(table);
      free(section);
      free(source);
    }

    /* Duplicate interrupt vector: the C refuses with 300 duplicate. */
    {
      char *a = ud_entry("6", "first");
      char *b = ud_entry("6", "second");
      char *table = table_two("interrupt", a, b);
      source = assemble(table, NULL);
      refuse_entry(&image, "duplicate_vector", source, 0, 305, 3, "6", 2, 6, 0);
      free(a);
      free(b);
      free(table);
      free(source);
    }

    /* Entry limit: 512 structured syscall entries are accepted by the C and
     * by this pass; the 513th is refused by both, the C with 201 limit. */
    {
      char *many = table_many(512);
      section = section_block("{}");
      source = assemble(many, section);
      accept(&image, "limit_512", source, 1, 512, 1);
      free(source);
      free(section);
      free(many);
    }
    {
      char *many = table_many(513);
      section = section_block("{}");
      source = assemble(many, section);
      refuse_entry(&image, "limit_513", source, 0, 305, 4, "512", 1, 512, 0);
      free(source);
      free(section);
      free(many);
    }

    /* Unsupported entry ABI on a structured syscall stub: the C refuses 403. */
    body = table_one("syscall", "0", "dispatch", "alien-abi-v0", "nx64-abi-v0",
                     "return", "syscall.frame", "false", "{}", "{}", "16",
                     "never", "preserve", ".text", "export", "entry0");
    section = section_block("{}");
    source = assemble(body, section);
    refuse(&image, "abi_entry", source, 0, 305, 6, "entry_abi alien-abi-v0", 0, 0);
    free(section);
    free(body);
    free(source);

    /* Unsupported exit policy: the C refuses 600 unsupported. */
    body = table_one("syscall", "0", "dispatch", "nx64-abi-v0", "nx64-abi-v0",
                     "sysretq", "syscall.frame", "false", "{}", "{}", "16",
                     "never", "preserve", ".text", "export", "entry0");
    section = section_block("{}");
    source = assemble(body, section);
    refuse(&image, "exit_policy", source, 0, 305, 7, "exit sysretq", 0, 0);
    free(section);
    free(body);
    free(source);

    /* Unknown frame: the C refuses 503 contract. */
    body = table_one("syscall", "0", "dispatch", "nx64-abi-v0", "nx64-abi-v0",
                     "return", "alien.frame", "false", "{}", "{}", "16",
                     "never", "preserve", ".text", "export", "entry0");
    section = section_block("{}");
    source = assemble(body, section);
    refuse(&image, "frame_unknown", source, 0, 305, 8, "frame alien.frame", 0, 0);
    free(section);
    free(body);
    free(source);

    /* An interrupt entry whose error code contradicts its frame: the C
     * refuses 503 contract. */
    body = table_one("interrupt", "6", "advance_saved_rip_2",
                     "nx64-interrupt-same-cpl-v0", "nx64-iretq-same-cpl-v0",
                     "iretq", "x86_64.frame.no_error.same_cpl", "true", "{rax}",
                     "{}", "0", "never", "preserve", ".text", "export", "isr6");
    source = assemble(body, NULL);
    refuse(&image, "error_code", source, 0, 305, 9, "hardware_error_code true",
           0, 0);
    free(body);
    free(source);

    /* A structured syscall stub that does not require stack_align 16: the C
     * refuses 403 ABI. */
    body = table_one("syscall", "0", "dispatch", "nx64-abi-v0", "nx64-abi-v0",
                     "return", "syscall.frame", "false", "{}", "{}", "0",
                     "never", "preserve", ".text", "export", "entry0");
    section = section_block("{}");
    source = assemble(body, section);
    refuse(&image, "align_syscall", source, 0, 305, 10, "stack_align 0", 0, 0);
    free(section);
    free(body);
    free(source);

    /* An interrupt stub that claims an aligned entry frame: the C refuses
     * 403 ABI. */
    body = table_one("interrupt", "6", "advance_saved_rip_2",
                     "nx64-interrupt-same-cpl-v0", "nx64-iretq-same-cpl-v0",
                     "iretq", "x86_64.frame.no_error.same_cpl", "false", "{rax}",
                     "{}", "16", "never", "preserve", ".text", "export", "isr6");
    source = assemble(body, NULL);
    refuse(&image, "align_interrupt", source, 0, 305, 10, "stack_align 16", 16,
           0);
    free(body);
    free(source);

    /* A stub that would perform swapgs: the C refuses 503 contract. */
    body = table_one("interrupt", "6", "advance_saved_rip_2",
                     "nx64-interrupt-same-cpl-v0", "nx64-iretq-same-cpl-v0",
                     "iretq", "x86_64.frame.no_error.same_cpl", "false", "{rax}",
                     "{}", "0", "always", "preserve", ".text", "export", "isr6");
    source = assemble(body, NULL);
    refuse(&image, "swapgs", source, 0, 305, 11, "swapgs always", 0, 0);
    free(body);
    free(source);

    /* A stub that masks interrupts: the C refuses 503 contract. */
    body = table_one("interrupt", "6", "advance_saved_rip_2",
                     "nx64-interrupt-same-cpl-v0", "nx64-iretq-same-cpl-v0",
                     "iretq", "x86_64.frame.no_error.same_cpl", "false", "{rax}",
                     "{}", "0", "never", "disable", ".text", "export", "isr6");
    source = assemble(body, NULL);
    refuse(&image, "interrupts_masked", source, 0, 305, 12,
           "interrupts disable", 0, 0);
    free(body);
    free(source);

    /* A generated stub outside .text: the C refuses 503 contract. */
    body = table_one("interrupt", "6", "advance_saved_rip_2",
                     "nx64-interrupt-same-cpl-v0", "nx64-iretq-same-cpl-v0",
                     "iretq", "x86_64.frame.no_error.same_cpl", "false", "{rax}",
                     "{}", "0", "never", "preserve", ".data", "export", "isr6");
    source = assemble(body, NULL);
    refuse(&image, "section", source, 0, 305, 13, "section +1data", 0, 0);
    free(body);
    free(source);

    /* An unknown visibility: the C refuses 503 contract. */
    body = table_one("interrupt", "6", "advance_saved_rip_2",
                     "nx64-interrupt-same-cpl-v0", "nx64-iretq-same-cpl-v0",
                     "iretq", "x86_64.frame.no_error.same_cpl", "false", "{rax}",
                     "{}", "0", "never", "preserve", ".text", "hidden", "isr6");
    source = assemble(body, NULL);
    refuse(&image, "visibility", source, 0, 305, 14, "visibility hidden", 0, 0);
    free(body);
    free(source);

    /* Two stubs generating the same symbol: the C refuses 300 duplicate. */
    {
      char *a = syscall_entry("0", "entry0");
      char *b = syscall_entry("1", "entry0");
      char *table = table_two("syscall", a, b);
      section = section_block("{}");
      source = assemble(table, section);
      refuse_entry(&image, "duplicate_symbol", source, 0, 305, 15, "1", 1, 0, 0);
      free(a);
      free(b);
      free(table);
      free(section);
      free(source);
    }

    /* A generated symbol that collides with a declared function. The C
     * refuses it with 300 duplicate: its check runs against whatever the
     * module table already holds, and the declared function collides with the
     * stub the table introduced. The Nova rule is stated over the module
     * namespace directly, so it does not depend on which parse ran first. */
    {
      char *table = syscall_table("0", "entry0");
      section = section_block("{}");
      {
        char block[512];
        snprintf(block, sizeof block,
                 "section .text {\nfn main()->u64\neffects {}\nclobbers {} {\n"
                 "return 0\n}\nfn dispatch()->u64\neffects {}\nclobbers {} {\n"
                 "return 42\n}\nfn entry0()->u64\neffects {}\nclobbers {} {\n"
                 "return 7\n}\n}\n");
        source = assemble(table, block);
      }
      refuse_entry(&image, "symbol_vs_function", source, 0, 305, 15, "0", 1, 0,
                   0);
      free(section);
      free(table);
      free(source);
    }

    /* A handler contract wider than the stub save set: the C refuses it at
     * verification with 502 clobber, at the same entry position. */
    {
      char *table = syscall_table("0", "entry0");
      section = section_block("{rbx}");
      source = assemble(table, section);
      refuse_entry(&image, "handler_clobber", source, 0, 305, 17, "0", 1, 4, 0);
      free(section);
      free(table);
      free(source);
    }

    /* A syscall handler that is not a declared callable: the C refuses it
     * with 301 name. */
    body = table_one("syscall", "0", "ghost", "nx64-abi-v0", "nx64-abi-v0",
                     "return", "syscall.frame", "false", "{}", "{}", "16",
                     "never", "preserve", ".text", "export", "entry0");
    section = section_block("{}");
    source = assemble(body, section);
    refuse_entry(&image, "handler_unknown", source, 0, 305, 18, "0", 1, 0, 0);
    free(section);
    free(body);
    free(source);

    /* A generated stub that binds a material parameter: the C refuses it as a
     * syntax error, and the bindings of a generated stub must stay empty. */
    {
      static const char empty[] = "bindings {}";
      static const char bound_field[] = "bindings {a:u64 @rcx}\n";
      char *text = ud_entry("6", "isr6");
      const char *at = strstr(text, empty);
      CHECK(at != NULL, "bindings marker present");
      char bigger[2048];
      bigger[0] = 0;
      if (at)
        snprintf(bigger, sizeof bigger, "%.*s%s%s",
                 (int)(at - text), text, bound_field, at + sizeof empty - 1);
      body = table_two("interrupt", bigger, "");
      free(text);
      source = assemble(body, NULL);
      refuse(&image, "bindings", source, 0, 305, 19, "bindings {a:u64 @rcx}", 0,
             0);
      free(body);
      free(source);
    }

    /* A generated stub that declares a clobber: the save set is the only
     * preservation mechanism, and the C refuses it as a syntax error. */
    body = table_one("interrupt", "6", "advance_saved_rip_2",
                     "nx64-interrupt-same-cpl-v0", "nx64-iretq-same-cpl-v0",
                     "iretq", "x86_64.frame.no_error.same_cpl", "false", "{rax}",
                     "{rbx}", "0", "never", "preserve", ".text", "export", "isr6");
    source = assemble(body, NULL);
    refuse(&image, "clobbers", source, 0, 305, 20, "clobbers {rbx}", 0, 0);
    free(body);
    free(source);

    /* An interrupt stub that saves nothing: the C refuses it as a syntax
     * error, and the profile requires a save set. */
    body = table_one("interrupt", "6", "advance_saved_rip_2",
                     "nx64-interrupt-same-cpl-v0", "nx64-iretq-same-cpl-v0",
                     "iretq", "x86_64.frame.no_error.same_cpl", "false", "{}",
                     "{}", "0", "never", "preserve", ".text", "export", "isr6");
    source = assemble(body, NULL);
    refuse(&image, "save_empty", source, 0, 305, 21, "save {}", 0, 0);
    free(body);
    free(source);

    /* A structured syscall stub that saves a register: the C refuses it as a
     * syntax error. */
    body = table_one("syscall", "0", "dispatch", "nx64-abi-v0", "nx64-abi-v0",
                     "return", "syscall.frame", "false", "{rbx}", "{}", "16",
                     "never", "preserve", ".text", "export", "entry0");
    section = section_block("{}");
    source = assemble(body, section);
    refuse(&image, "save_syscall", source, 0, 305, 21, "save {rbx}", 0, 0);
    free(section);
    free(body);
    free(source);

    /* An unknown register spelling in the save set: the C refuses it as a
     * syntax error. */
    body = table_one("interrupt", "6", "advance_saved_rip_2",
                     "nx64-interrupt-same-cpl-v0", "nx64-iretq-same-cpl-v0",
                     "iretq", "x86_64.frame.no_error.same_cpl", "false",
                     "{foo}", "{}", "0", "never", "preserve", ".text", "export",
                     "isr6");
    source = assemble(body, NULL);
    refuse(&image, "save_unknown_register", source, 0, 305, 22, "save +1foo", 0,
           0);
    free(body);
    free(source);

    /* An interrupt handler that is not an advance_saved_rip_<N> policy: the C
     * refuses it with 503 contract, because it admits only the witness policy
     * advance_saved_rip_2. */
    body = table_one("interrupt", "6", "rewind_saved_rip_2",
                     "nx64-interrupt-same-cpl-v0", "nx64-iretq-same-cpl-v0",
                     "iretq", "x86_64.frame.no_error.same_cpl", "false", "{rax}",
                     "{}", "0", "never", "preserve", ".text", "export", "isr6");
    source = assemble(body, NULL);
    refuse(&image, "handler_policy", source, 0, 305, 23,
           "handler rewind_saved_rip_2", 0, 0);
    free(body);
    free(source);

    /* A handler policy whose advance is a leading zero: the digits are read
     * from the policy, so a zero advance is a refusal, not a silent zero. */
    body = table_one("interrupt", "6", "advance_saved_rip_0",
                     "nx64-interrupt-same-cpl-v0", "nx64-iretq-same-cpl-v0",
                     "iretq", "x86_64.frame.no_error.same_cpl", "false", "{rax}",
                     "{}", "0", "never", "preserve", ".text", "export", "isr6");
    source = assemble(body, NULL);
    refuse(&image, "handler_policy_zero", source, 0, 305, 23,
           "handler advance_saved_rip_0", 0, 0);
    free(body);
    free(source);

    /* An interrupt key outside the architecture range: the C refuses it too,
     * but only because its two witness profiles cover #UD and #GP, so the
     * case is oracle-free on the reason and the C refusal is recorded. */
    body = interrupt_ud("300", "isr300");
    source = assemble(body, NULL);
    refuse_entry(&image, "vector_range", source, 0, 305, 5, "300", 1, 300, 0);
    free(body);
    free(source);

    /* ---- the forbidden-gap rule: the C reference does not implement it ---- */

    /* A structured syscall table declaring 0 and 2. The C accepts this table
     * and generates both stubs, so the refusal itself is oracle-free; the
     * divergence is measured here rather than asserted in prose. The
     * diagnostic points at the entry after the hole and names the missing key
     * in out[3]. */
    {
      char *a = syscall_entry("0", "entry0");
      char *b = syscall_entry("2", "entry2");
      char *table = table_two("syscall", a, b);
      section = section_block("{}");
      source = assemble(table, section);
      refuse_entry(&image, "gap_syscall", source, 0, 305, 16, "2", 1, 1, 1);
      free(a);
      free(b);
      free(table);
      free(section);
      free(source);
    }

    /* The same rule on an interrupt table: 6 then 13 leaves vectors 7 to 12
     * undeclared. The C accepts this pair, as its own gate records. */
    {
      char *a = ud_entry("6", "isr6");
      char *b = gp_entry("13", "isr13");
      char *table = table_two("interrupt", a, b);
      source = assemble(table, NULL);
      refuse_entry(&image, "gap_interrupt", source, 0, 305, 16, "13", 1, 7, 1);
      free(a);
      free(b);
      free(table);
      free(source);
    }

    /* ---- the lowering boundary ---- */

    /* Vector 7 is a legal declaration: the spec fixes no vector list, and the
     * C refuses it only because its two witness profiles cover #UD and #GP.
     * The declaration pass accepts it and the lowering refuses to emit it. */
    body = interrupt_ud("7", "isr7");
    source = assemble(body, NULL);
    accept(&image, "vector7_declaration", source, 1, 1, 0);
    refuse(&image, "vector7_lowering", source, 2, 306, 1, NULL, 0, -1);
    free(body);
    free(source);

    /* A save set the proven profile does not preserve: rbx instead of rax.
     * The declaration is legal, the lowering refuses it, and the query
     * channel still answers the derivation. The plan is asserted against the
     * declaration, not against any C output, because the C cannot express a
     * save set other than {rax}. */
    body = table_one("interrupt", "6", "advance_saved_rip_2",
                     "nx64-interrupt-same-cpl-v0", "nx64-iretq-same-cpl-v0",
                     "iretq", "x86_64.frame.no_error.same_cpl", "false", "{rbx}",
                     "{}", "0", "never", "preserve", ".text", "export", "isr6");
    source = assemble(body, NULL);
    accept(&image, "rbx_declaration", source, 1, 1, 0);
    refuse(&image, "rbx_lowering", source, 2, 306, 2, NULL, 0, -1);
    {
      static const uint64_t want[6][3] = {{1, 4, 0}, {2, 1, 8}, {3, 1, 2},
                                          {4, 8, 1}, {5, 4, 0}, {7, 0, 0}};
      plan_query(&image, "rbx_plan", source, 0, 1, 6, 0, 6, 1, want, 6);
    }
    free(body);
    free(source);

    /* Two saved registers declared in descending order: the derivation is
     * canonical, so the prologue pushes rax then rbx and the epilogue pops
     * rbx then rax. Spec-derived, the C cannot express a two-register set. */
    body = table_one("interrupt", "6", "advance_saved_rip_2",
                     "nx64-interrupt-same-cpl-v0", "nx64-iretq-same-cpl-v0",
                     "iretq", "x86_64.frame.no_error.same_cpl", "false",
                     "{rax,rbx}", "{}", "0", "never", "preserve", ".text",
                     "export", "isr6");
    source = assemble(body, NULL);
    accept(&image, "two_saves_declaration", source, 1, 1, 0);
    refuse(&image, "two_saves_lowering", source, 2, 306, 2, NULL, 0, -1);
    {
      static const uint64_t want[8][3] = {{1, 1, 0}, {1, 4, 0}, {2, 1, 8},
                                          {3, 1, 2}, {4, 8, 1}, {5, 4, 0},
                                          {5, 1, 0}, {7, 0, 0}};
      plan_query(&image, "two_saves_plan", source, 0, 1, 6, 0, 8, 2, want, 8);
    }
    free(body);
    free(source);

    /* The same derivation on the error-code frame: the saved RIP moves to
     * sixteen, the slot removal appears and the epilogue still ends in iretq.
     * This is the general rule; the C proves it for {rax} only. */
    body = table_one("interrupt", "13", "advance_saved_rip_2",
                     "nx64-interrupt-same-cpl-error-v0",
                     "nx64-iretq-same-cpl-error-v0", "iretq",
                     "x86_64.frame.error.same_cpl", "true", "{rax,rbx}", "{}",
                     "0", "never", "preserve", ".text", "export", "isr13");
    source = assemble(body, NULL);
    accept(&image, "error_two_saves_declaration", source, 1, 1, 0);
    {
      static const uint64_t want[9][3] = {
          {1, 1, 0}, {1, 4, 0}, {2, 1, 16}, {3, 1, 2}, {4, 16, 1},
          {5, 4, 0}, {5, 1, 0}, {6, 5, 8}, {7, 0, 0}};
      plan_query(&image, "error_two_saves_plan", source, 0, 1, 13, 1, 9, 2, want,
                 9);
    }
    free(body);
    free(source);

    /* A query past the last record answers 306 reason 4 with the count. */
    body = interrupt_ud("6", "isr6");
    source = assemble(body, NULL);
    {
      Run r = run_mode(&image, source, OUT_WORDS, 3, 1);
      cases++;
      checks++;
      if (r.returned != 306 || r.runtime || r.out[0] != 1 || r.out[1] != 1 ||
          r.out[2] != 4) {
        failures++;
        fprintf(stderr, "FAIL plan_query_range ret=%llu out=%llu,%llu,%llu\n",
                (unsigned long long)r.returned, (unsigned long long)r.out[0],
                (unsigned long long)r.out[1], (unsigned long long)r.out[2]);
      }
    }
    /* A query whose twelve-word record does not fit answers 306 reason 5
     * with the words it needs, and writes nothing past the caller's buffer. */
    {
      Run r = run_mode(&image, source, 16, 3, 0);
      cases++;
      checks++;
      if (r.returned != 306 || r.runtime || r.out[0] != 12 + 3 * 6 ||
          r.out[1] != 16 || r.out[2] != 5 || r.out[3]) {
        failures++;
        fprintf(stderr, "FAIL plan_query_capacity ret=%llu out=%llu,%llu,%llu\n",
                (unsigned long long)r.returned, (unsigned long long)r.out[0],
                (unsigned long long)r.out[1], (unsigned long long)r.out[2]);
      }
    }
    free(body);
    free(source);

    /* A handler policy that advances by four bytes: legal, not encodable. */
    body = table_one("interrupt", "6", "advance_saved_rip_4",
                     "nx64-interrupt-same-cpl-v0", "nx64-iretq-same-cpl-v0",
                     "iretq", "x86_64.frame.no_error.same_cpl", "false", "{rax}",
                     "{}", "0", "never", "preserve", ".text", "export", "isr6");
    source = assemble(body, NULL);
    accept(&image, "advance4_declaration", source, 1, 1, 0);
    refuse(&image, "advance4_lowering", source, 2, 306, 1, NULL, 0, -1);
    free(body);
    free(source);

    /* A caller output that cannot hold the records and the plans. */
    body = interrupt_gp("13", "isr13");
    source = assemble(body, NULL);
    {
      uint64_t needed = 4 + 12 + 3 * 7;
      Run r = run(&image, source, 8, 2);
      cases++;
      checks++;
      if (r.returned != 306 || r.runtime || r.out[0] != needed ||
          r.out[1] != 8 || r.out[2] != 3 || r.out[3]) {
        failures++;
        fprintf(stderr,
                "FAIL capacity out=%llu,%llu,%llu ret=%llu want %llu,8,3\n",
                (unsigned long long)r.out[0], (unsigned long long)r.out[1],
                (unsigned long long)r.out[2], (unsigned long long)r.returned,
                (unsigned long long)needed);
      }
    }
    free(body);
    free(source);

    /* ---- refusals of the shared kind ---- */

    /* A source that does not parse. */
    {
      const char *broken = "target x86_64-nexora-none\n";
      Run r = run(&image, broken, 64, 0);
      cases++;
      checks++;
      if (r.returned != 800 || r.runtime || r.out[0] != guard) {
        failures++;
        fprintf(stderr, "FAIL broken ret=%llu out0=%llu\n",
                (unsigned long long)r.returned, (unsigned long long)r.out[0]);
      }
    }

    /* A caller output shorter than four words never reaches any pass. */
    body = interrupt_ud("6", "isr6");
    source = assemble(body, NULL);
    {
      Run r = run(&image, source, 3, 0);
      cases++;
      checks++;
      if (r.returned != 800 || r.out[0] != guard) {
        failures++;
        fprintf(stderr, "FAIL short ret=%llu out0=%llu\n",
                (unsigned long long)r.returned, (unsigned long long)r.out[0]);
      }
    }
    free(body);
    free(source);

    /* Four words reach the declaration pass, which is all they hold. */
    body = interrupt_ud("6", "isr6");
    source = assemble(body, NULL);
    {
      Run r = run(&image, source, 4, 0);
      cases++;
      checks++;
      if (r.returned || r.out[0] != 1 || r.out[1] != 1) {
        failures++;
        fprintf(stderr, "FAIL four_words ret=%llu out=%llu,%llu\n",
                (unsigned long long)r.returned, (unsigned long long)r.out[0],
                (unsigned long long)r.out[1]);
      }
    }
    free(body);
    free(source);

    /* Seven words cannot carry the twelve-word record of the query channel,
     * so it refuses instead of writing past the caller's buffer. */
    body = interrupt_ud("6", "isr6");
    source = assemble(body, NULL);
    {
      Run r = run(&image, source, 7, 0);
      cases++;
      checks++;
      if (r.returned || r.out[0] != 1) {
        failures++;
        fprintf(stderr, "FAIL seven_words ret=%llu out0=%llu\n",
                (unsigned long long)r.returned, (unsigned long long)r.out[0]);
      }
    }
    free(body);
    free(source);

    /* ---- the 305 reason vocabulary, confronted with the oracle ---- */

    /* Every reason the declaration pass can publish, one witness row per
     * reason and per profile that names it differently. The two verdicts are
     * compared to each other: the reason stub_table.nova wrote, and the class
     * and the wording the C front-end wrote on the same declaration. */
    {
      static Witness observed[REASON_ROWS];
      for (unsigned i = 0; i < REASON_ROWS; i++)
        confront_reason(&image, &REASONS[i], i, observed);
      confront_c_vocabulary(observed);
    }
    /* The reason set the tree publishes, read out of the module compiled
     * above, against the reason set the rows name. */
    confront_reason_set(sources[1]);
    /* The behavioural half of the same closure: a corpus of counter-values
     * per field, so a reachable but unregistered reason fails even when the
     * literals of the tree have not moved. */
    sweep_reasons(&image);
  }

  if (image.memory) nova_host_unmap(&image);
  if (compiled) nt_artifact_free(&artifact);
  for (unsigned i = 0; i < 10; i++) free(sources[i]);
  printf("NTASM_NOVA_STUB_TABLE checks=%u failures=%u cases=%u\n", checks,
         failures, cases);
  return failures ? 1 : 0;
}
