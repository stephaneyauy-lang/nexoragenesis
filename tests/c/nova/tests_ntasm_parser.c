#include "../../../compiler/c/ntasm/frontend/frontend.h"
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
typedef struct {
  uint64_t *words;
  size_t word_count;
  uint64_t returned, runtime_error;
} Parsed;
static char *load(const char *path, size_t *length) {
  FILE *f = fopen(path, "rb");
  if (!f)
    return NULL;
  fseek(f, 0, SEEK_END);
  long size = ftell(f);
  fseek(f, 0, SEEK_SET);
  char *data = size >= 0 ? (char *)malloc((size_t)size + 1) : NULL;
  if (!data || fread(data, 1, (size_t)size, f) != (size_t)size) {
    free(data);
    fclose(f);
    return NULL;
  }
  fclose(f);
  data[size] = 0;
  *length = (size_t)size;
  return data;
}
static Parsed parse(const NovaHostImage *image, const char *source,
                    size_t length) {
  Parsed result = {0};
  result.word_count = 10 + (length * 2 + 32) * 12;
  result.words = (uint64_t *)calloc(result.word_count, sizeof(uint64_t));
  NovaContextV2 context;
  if (!result.words || !nova_context_init_v2(&context)) {
    result.runtime_error = UINT64_MAX;
    return result;
  }
  uint64_t source_handle =
      nova_borrow_v2(&context, (void *)source, (uint64_t)length, 0);
  uint64_t output_handle = nova_borrow_v2(
      &context, result.words,
      (uint64_t)(result.word_count * sizeof(*result.words)), 1);
  uint64_t args[] = {source_handle, length, output_handle, result.word_count};
  result.returned = image->entry(&context, args, 4);
  result.runtime_error = context.error;
  CHECK(nova_context_destroy_v2(&context), "parser context cleanup");
  return result;
}
static int ast_well_formed(const Parsed *parsed, size_t source_length) {
  if (!parsed->words || !parsed->words[0] || parsed->words[9] == 0)
    return 0;
  uint64_t count = parsed->words[9];
  for (uint64_t id = 1; id <= count; id++) {
    const uint64_t *node = parsed->words + 10 + (id - 1) * 12;
    if (!node[0] || node[6] > node[7] || node[7] > source_length ||
        node[8] > count || node[9] > count || node[10] > count)
      return 0;
  }
  return parsed->words[10] == 1;
}
static uint64_t kind_count(const Parsed *parsed, uint64_t kind) {
  uint64_t count = 0;
  for (uint64_t id = 1; id <= parsed->words[9]; id++)
    if (parsed->words[10 + (id - 1) * 12] == kind)
      count++;
  return count;
}
static void expect_valid(const NovaHostImage *image, const char *name,
                         const char *source, uint64_t required_kind) {
  Parsed parsed = parse(image, source, strlen(source));
  NtFInput input = {name, source, strlen(source)};
  NtFProgram c;
  int c_ok = nt_frontend_compile(&input, 1, &c);
  int ok = !parsed.runtime_error && parsed.returned == 0 && parsed.words[0] &&
           ast_well_formed(&parsed, strlen(source)) && c_ok &&
           (!required_kind || kind_count(&parsed, required_kind));
  checks++;
  cases++;
  if (!ok) {
    failures++;
    fprintf(stderr,
            "FAIL valid %s nova=%llu runtime=%llu code=%llu reason=%llu "
            "at=%llu:%llu nodes=%llu c_ok=%d\n",
            name, (unsigned long long)parsed.returned,
            (unsigned long long)parsed.runtime_error,
            (unsigned long long)(parsed.words ? parsed.words[1] : 0),
            (unsigned long long)(parsed.words ? parsed.words[2] : 0),
            (unsigned long long)(parsed.words ? parsed.words[4] : 0),
            (unsigned long long)(parsed.words ? parsed.words[5] : 0),
            (unsigned long long)(parsed.words ? parsed.words[9] : 0), c_ok);
    for (size_t i = 0; i < c.diagnostic_count; i++)
      fprintf(stderr, " C E%u %u:%u %s\n", c.diagnostics[i].code,
              c.diagnostics[i].span.line, c.diagnostics[i].span.column,
              c.diagnostics[i].message);
  }
  nt_frontend_free(&c);
  free(parsed.words);
}
static void expect_parse_only(const NovaHostImage *image, const char *name,
                              const char *source, uint64_t required_kind) {
  Parsed parsed = parse(image, source, strlen(source));
  int ok = !parsed.runtime_error && parsed.returned == 0 && parsed.words[0] &&
           ast_well_formed(&parsed, strlen(source)) &&
           (!required_kind || kind_count(&parsed, required_kind));
  checks++;
  cases++;
  if (!ok) {
    failures++;
    fprintf(stderr,
            "FAIL parse-only %s return=%llu runtime=%llu E%llu reason=%llu "
            "at=%llu:%llu nodes=%llu\n",
            name, (unsigned long long)parsed.returned,
            (unsigned long long)parsed.runtime_error,
            (unsigned long long)(parsed.words ? parsed.words[1] : 0),
            (unsigned long long)(parsed.words ? parsed.words[2] : 0),
            (unsigned long long)(parsed.words ? parsed.words[4] : 0),
            (unsigned long long)(parsed.words ? parsed.words[5] : 0),
            (unsigned long long)(parsed.words ? parsed.words[9] : 0));
  }
  free(parsed.words);
}
static const uint64_t *node_at(const Parsed *parsed, uint64_t id) {
  if (!id || id > parsed->words[9])
    return NULL;
  return parsed->words + 10 + (id - 1) * 12;
}
/* Nova-only diagnostic assertion. frontend.c has no align_stack surface, so
   align_stack refusals are asserted on the Nova parser alone and never
   compared against the C frontend. A refused source returns its code from the
   entry module, so the verdict reads the diagnostic words, not the return. */
static void expect_nova_error(const NovaHostImage *image, const char *name,
                              const char *source, uint64_t reason) {
  Parsed parsed = parse(image, source, strlen(source));
  int ok = !parsed.runtime_error && parsed.words && !parsed.words[0] &&
           !parsed.words[9] && parsed.words[1] == 200 &&
           parsed.words[2] == reason;
  checks++;
  cases++;
  if (!ok) {
    failures++;
    fprintf(stderr,
            "FAIL nova error %s return=%llu runtime=%llu E%llu reason=%llu "
            "(want E200 reason %llu) nodes=%llu at=%llu:%llu\n",
            name, (unsigned long long)parsed.returned,
            (unsigned long long)parsed.runtime_error,
            (unsigned long long)(parsed.words ? parsed.words[1] : 0),
            (unsigned long long)(parsed.words ? parsed.words[2] : 0),
            (unsigned long long)reason,
            (unsigned long long)(parsed.words ? parsed.words[9] : 0),
            (unsigned long long)(parsed.words ? parsed.words[4] : 0),
            (unsigned long long)(parsed.words ? parsed.words[5] : 0));
  }
  free(parsed.words);
}
/* Counts nodes of one kind in a parse-only tree: used to prove that a
   construct the parser accepts twice produces two independent nodes. */
static void expect_kind_count(const NovaHostImage *image, const char *name,
                              const char *source, uint64_t kind,
                              uint64_t expected) {
  Parsed parsed = parse(image, source, strlen(source));
  uint64_t seen = parsed.words ? kind_count(&parsed, kind) : 0;
  int ok = !parsed.runtime_error && parsed.returned == 0 && parsed.words[0] &&
           ast_well_formed(&parsed, strlen(source)) && seen == expected;
  checks++;
  cases++;
  if (!ok) {
    failures++;
    fprintf(stderr, "FAIL kind count %s kind=%llu seen=%llu want=%llu "
                    "return=%llu runtime=%llu E%llu nodes=%llu\n",
            name, (unsigned long long)kind, (unsigned long long)seen,
            (unsigned long long)expected, (unsigned long long)parsed.returned,
            (unsigned long long)parsed.runtime_error,
            (unsigned long long)(parsed.words ? parsed.words[1] : 0),
            (unsigned long long)(parsed.words ? parsed.words[9] : 0));
  }
  free(parsed.words);
}
/* Reads the parser keyword table back through the entry module's
   empty-source mode: out[0]=ok out[1]=byte length out[2..]=the table bytes. */
static char *keyword_table(const NovaHostImage *image, uint64_t *count,
                           size_t *length) {
  enum { KEYWORD_WORDS = 4096 };
  char *table = NULL;
  uint64_t *words = (uint64_t *)calloc(KEYWORD_WORDS, sizeof(uint64_t));
  if (!words)
    return NULL;
  NovaContextV2 context;
  if (!nova_context_init_v2(&context)) {
    free(words);
    return NULL;
  }
  static const char empty[1] = {0};
  uint64_t source_handle = nova_borrow_v2(&context, (void *)empty, 0, 0);
  uint64_t output_handle = nova_borrow_v2(
      &context, words, (uint64_t)(KEYWORD_WORDS * sizeof(*words)), 1);
  uint64_t args[] = {source_handle, 0, output_handle, KEYWORD_WORDS};
  uint64_t returned = image->entry(&context, args, 4);
  CHECK(nova_context_destroy_v2(&context), "keyword table context cleanup");
  if (returned != 0 || !words[0] || words[1] == 0 || words[1] + 2 > KEYWORD_WORDS)
    goto done;
  table = (char *)malloc(words[1] + 1);
  if (!table)
    goto done;
  for (uint64_t i = 0; i < words[1]; i++)
    table[i] = (char)words[2 + i];
  table[words[1]] = 0;
  *length = (size_t)words[1];
  *count = 0;
  for (size_t i = 0; i < *length; i++)
    if (!table[i])
      (*count)++;
done:
  free(words);
  return table;
}
/* One-based position of a NUL-terminated name in the flat table, zero absent. */
static uint64_t keyword_index(const char *table, size_t length,
                              const char *name) {
  uint64_t index = 1;
  size_t at = 0;
  while (at < length) {
    size_t start = at;
    while (at < length && table[at])
      at++;
    size_t want = strlen(name);
    if (at - start == want && !memcmp(table + start, name, want))
      return index;
    index++;
    at++;
  }
  return 0;
}
struct KeywordSlot {
  const char *name;
  uint64_t index;
};
/* The frozen tail of the flat keyword table, read back from the parser itself.
   Every pass names these identifiers by numeric index, so appending
   align_stack must leave all twelve pre-existing indices untouched. */
static const struct KeywordSlot kFrozenTail[] = {
    {"stack_align", 65}, {"swapgs", 66},   {"interrupts", 67},
    {"visibility", 68},  {"local", 69},     {"export", 70},
    {"true", 71},        {"false", 72},     {"symbol", 73},
    {"expr", 74},        {"fs", 75},        {"gs", 76},
    {"align_stack", 77},
};
#define KEYWORD_TOTAL 77
static void expect_frozen_keyword_indices(const NovaHostImage *image) {
  uint64_t count = 0;
  size_t length = 0;
  char *table = keyword_table(image, &count, &length);
  checks++;
  cases++;
  if (!table) {
    failures++;
    fprintf(stderr, "FAIL frozen keyword indices table unavailable\n");
    return;
  }
  if (count != KEYWORD_TOTAL) {
    failures++;
    fprintf(stderr, "FAIL frozen keyword count got=%llu want=%d\n",
            (unsigned long long)count, KEYWORD_TOTAL);
  }
  for (size_t i = 0; i < sizeof(kFrozenTail) / sizeof(kFrozenTail[0]); i++) {
    uint64_t got = keyword_index(table, length, kFrozenTail[i].name);
    checks++;
    if (got != kFrozenTail[i].index) {
      failures++;
      fprintf(stderr, "FAIL frozen keyword %s got=%llu want=%llu\n",
              kFrozenTail[i].name, (unsigned long long)got,
              (unsigned long long)kFrozenTail[i].index);
    }
  }
  free(table);
}
static void expect_logical_shape(const NovaHostImage *image, const char *name,
                                 const char *source, uint64_t root_aux,
                                 int check_child, uint64_t child_aux) {
  Parsed parsed = parse(image, source, strlen(source));
  NtFInput input = {name, source, strlen(source)};
  NtFProgram c;
  int c_ok = nt_frontend_compile(&input, 1, &c);
  uint64_t condition_id = 0;
  for (uint64_t id = 1; id <= parsed.words[9]; id++) {
    const uint64_t *node = node_at(&parsed, id);
    if (node && node[0] == 30) {
      condition_id = node[8];
      break;
    }
  }
  const uint64_t *root = node_at(&parsed, condition_id);
  const uint64_t *left = root ? node_at(&parsed, root[8]) : NULL;
  const uint64_t *right = left ? node_at(&parsed, left[10]) : NULL;
  const uint64_t *checked = right;
  if (root_aux == 268 && left && left[0] == 35 && left[11] == 40) {
    checked = node_at(&parsed, left[8]);
    if (!checked || node_at(&parsed, left[8])[10] != 0)
      checked = NULL;
  }
  int ok = !parsed.runtime_error && parsed.returned == 0 &&
           ast_well_formed(&parsed, strlen(source)) && c_ok && root &&
           root[0] == 35 && root[11] == root_aux && left && right &&
           root[9] == left[10] && right[10] == 0 &&
           (!check_child || (checked && checked[0] == 35 &&
                             checked[11] == child_aux));
  checks++;
  cases++;
  if (!ok)
    fprintf(stderr, "FAIL logical shape %s root=%llu left=%llu right=%llu c_ok=%d\n",
            name, (unsigned long long)(root ? root[11] : 0),
            (unsigned long long)(left ? left[11] : 0),
            (unsigned long long)(right ? right[11] : 0), c_ok);
  nt_frontend_free(&c);
  free(parsed.words);
}
static void expect_logical_type_error(const char *name, const char *source) {
  NtFInput input = {name, source, strlen(source)};
  NtFProgram c;
  int compiled = nt_frontend_compile(&input, 1, &c);
  int type_error = !compiled && c.diagnostic_count &&
                   c.diagnostics[0].code == NTF_E_TYPE;
  checks++;
  cases++;
  if (!type_error)
    fprintf(stderr, "FAIL logical C type error %s compiled=%d diagnostics=%zu\n",
            name, compiled, c.diagnostic_count);
  nt_frontend_free(&c);
}
static void expect_syntax_error(const NovaHostImage *image, const char *name,
                                const char *source) {
  Parsed parsed = parse(image, source, strlen(source));
  NtFInput input = {name, source, strlen(source)};
  NtFProgram c;
  int c_ok = nt_frontend_compile(&input, 1, &c);
  int c_syntax = !c_ok && c.diagnostic_count &&
                 (c.diagnostics[0].code == 100 || c.diagnostics[0].code == 200);
  int ok = !parsed.runtime_error && !parsed.words[0] && !parsed.words[9] &&
           parsed.words[1] == c.diagnostics[0].code && c_syntax &&
           parsed.words[3] == c.diagnostics[0].span.source &&
           parsed.words[4] == c.diagnostics[0].span.line &&
           parsed.words[5] == c.diagnostics[0].span.column &&
           parsed.words[6] == c.diagnostics[0].span.start &&
           parsed.words[7] == c.diagnostics[0].span.end;
  checks++;
  cases++;
  if (!ok)
    fprintf(stderr,
            "FAIL invalid %s nova=%llu E%llu %llu:%llu %llu-%llu "
            "C=%d E%u %u:%u %zu-%zu\n",
            name, (unsigned long long)parsed.returned,
            (unsigned long long)(parsed.words ? parsed.words[1] : 0),
            (unsigned long long)(parsed.words ? parsed.words[4] : 0),
            (unsigned long long)(parsed.words ? parsed.words[5] : 0),
            (unsigned long long)(parsed.words ? parsed.words[6] : 0),
            (unsigned long long)(parsed.words ? parsed.words[7] : 0), c_ok,
            c.diagnostic_count ? c.diagnostics[0].code : 0,
            c.diagnostic_count ? c.diagnostics[0].span.line : 0,
            c.diagnostic_count ? c.diagnostics[0].span.column : 0,
            c.diagnostic_count ? c.diagnostics[0].span.start : 0,
            c.diagnostic_count ? c.diagnostics[0].span.end : 0);
  if (!ok)
    failures++;
  nt_frontend_free(&c);
  free(parsed.words);
}
/* The type closer, pinned at the exact boundary.
 *
 * Wave 7 reported that a long one-line `fn` signature stopped parsing with
 * E200 "expected > after buffer element" hundreds of characters from the
 * cause, and proposed "the line gets long". That premise is FALSE and this
 * gate is the evidence, not a test of a long line: it pins the rule that
 * actually decides whether a type closes.
 *
 * The rule: a generic type's closing `>` must be a token whose kind is `>`
 * (62) or `>>` (267, split by type_close at parser.nova:145-150). `>=` is
 * folded into ONE GE token (265) by lexer.nova:201-202, which is exactly
 * what the frozen C lexer does at frontend.c:441-443, so `array<u8,4>=` can
 * never close the type. This is a frozen-lexer expressiveness limitation
 * shared byte-for-byte with the C oracle, NOT a Nova lexer defect, and the
 * C frontend refuses the same spellings at the same columns below.
 *
 * Each case asserts the Nova verdict AND the C oracle's code/line/column
 * together, so a future change that moves the boundary on one side only
 * fails here instead of silently diverging. */
static void type_closer_case(const NovaHostImage *image, const char *name,
                             const char *declaration, int nova_ok,
                             uint64_t nova_reason, int split_closer) {
  char source[1024];
  snprintf(source, sizeof source,
           "module closers\ntarget x86_64-nexora-none\nsection .rdata {\n%s\n}\n"
           "section .text {\nfn main()->u64\neffects {}\nclobbers {} {\n"
           "return 0\n}\n}\n",
           declaration);
  Parsed parsed = parse(image, source, strlen(source));
  NtFInput input = {name, source, strlen(source)};
  NtFProgram c;
  int c_ok = nt_frontend_compile(&input, 1, &c);
  /* The C frontend also type-checks, so a spelling whose closer the lexer DID
   * accept can still be refused later with E400/E401. Only a PARSE refusal
   * (E200) is this boundary; any other code means the type closed and the
   * failure belongs to a later pass. */
  int c_parse_refused =
      !c_ok && c.diagnostic_count && c.diagnostics[0].code == 200;
  int nova_refused = !parsed.runtime_error && parsed.words &&
                     !parsed.words[0] && parsed.words[1] == 200;
  int nova_accepted =
      parsed.words && parsed.words[0] && ast_well_formed(&parsed, strlen(source));
  /* The invariant under test is that both frozen frontends reach the SAME parse
   * verdict on the closer. A GE spelling must be a parse refusal in both, or
   * the fold has diverged between them. */
  int verdicts_agree = nova_ok ? !c_parse_refused : c_parse_refused;
  /* Both frontends must also point at the same byte, except when the closer is
   * a split `>>`: the C frontend rewrites the token in place and reports the
   * SECOND '>' (expect_type_close, frontend.c:632-643) while the Nova parser
   * reports the split token's own start (type_close, parser.nova:145-150).
   * That one-column difference is real, and is why the two cannot be compared
   * by column in that case. */
  int columns_agree =
      split_closer || nova_ok || c_ok ||
      (c_parse_refused && c.diagnostics[0].span.line == parsed.words[4] &&
       c.diagnostics[0].span.column == parsed.words[5]);
  int ok = !parsed.runtime_error && parsed.words && verdicts_agree &&
           columns_agree &&
           (nova_ok ? nova_accepted
                    : (nova_refused && parsed.words[2] == nova_reason));
  checks++;
  cases++;
  if (!ok) {
    failures++;
    fprintf(stderr,
            "FAIL type closer %s (%s)\n"
            "  nova ok=%llu E%llu r%llu at %llu:%llu | C ok=%d E%u %u:%u\n"
            "  want nova_ok=%d reason=%llu split_closer=%d\n",
            name, declaration, (unsigned long long)parsed.words[0],
            (unsigned long long)parsed.words[1],
            (unsigned long long)parsed.words[2],
            (unsigned long long)parsed.words[4],
            (unsigned long long)parsed.words[5], c_ok,
            c_ok ? 0 : c.diagnostics[0].code,
            c_ok ? 0 : c.diagnostics[0].span.line,
            c_ok ? 0 : c.diagnostics[0].span.column, nova_ok,
            (unsigned long long)nova_reason, split_closer);
  }
  nt_frontend_free(&c);
  free(parsed.words);
}

/* A function signature's shape, newline placement, and length are NOT part of
 * the rule: nova.c's lexer treats \n as whitespace and nothing else reads it
 * (nova.c:232-240), and the two forms below differ only in whitespace. The
 * C frontend's lexer is identical in this respect (frontend.c:323-325). Any
 * future change that made line shape significant would break these cases, so
 * they are the standing refutation of the wave-7 "long line" mechanism. */
static void signature_reflow_case(const NovaHostImage *image, const char *name,
                                  const char *one_line, const char *reflowed) {
  char source[2048];
  const char *forms[2] = {one_line, reflowed};
  uint64_t nodes[2] = {0, 0};
  for (int form = 0; form < 2; form++) {
    snprintf(source, sizeof source,
             "module reflow\ntarget x86_64-nexora-none\nsection .text {\n"
             "%s\neffects {}\nclobbers {} {\nreturn 0\n}\n"
             "fn main()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n",
             forms[form]);
    Parsed parsed = parse(image, source, strlen(source));
    int ok = !parsed.runtime_error && parsed.words && parsed.words[0] &&
             ast_well_formed(&parsed, strlen(source));
    checks++;
    if (!ok) {
      failures++;
      fprintf(stderr, "FAIL signature reflow %s form=%d E%llu r%llu\n", name,
              form, (unsigned long long)parsed.words[1],
              (unsigned long long)parsed.words[2]);
    }
    nodes[form] = parsed.words ? parsed.words[9] : 0;
    free(parsed.words);
  }
  cases++;
  checks++;
  /* Same parse must yield the same node count: the tree is identical, so no
   * information was lost to the newline. */
  if (nodes[0] != nodes[1]) {
    failures++;
    fprintf(stderr,
            "FAIL signature reflow node mismatch %s one_line=%llu reflowed=%llu\n",
            name, (unsigned long long)nodes[0], (unsigned long long)nodes[1]);
  }
}

/* Every owned fixture must actually be driven through the stage that names it.
 * Wave 7 found positive-module.ntasm had never been parsed by any gate: it was
 * only fed to the lexer-parity comparison, and its `array<u8,4>=` never closed
 * a type, so it had been passing for as long as the gate existed by not being
 * run. A positive fixture that does not parse is a hole, not a fixture. */
static void fixture_parses(const NovaHostImage *image, const char *path) {
  size_t length = 0;
  char *text = load(path, &length);
  CHECK(text != NULL, "fixture loads");
  if (!text)
    return;
  Parsed parsed = parse(image, text, length);
  int ok = !parsed.runtime_error && parsed.words && parsed.words[0] &&
           ast_well_formed(&parsed, length);
  checks++;
  cases++;
  if (!ok) {
    failures++;
    fprintf(stderr,
            "FAIL fixture does not parse %s E%llu r%llu at %llu:%llu "
            "runtime=%llu\n",
            path, (unsigned long long)(parsed.words ? parsed.words[1] : 0),
            (unsigned long long)(parsed.words ? parsed.words[2] : 0),
            (unsigned long long)(parsed.words ? parsed.words[4] : 0),
            (unsigned long long)(parsed.words ? parsed.words[5] : 0),
            (unsigned long long)parsed.runtime_error);
  }
  free(parsed.words);
  free(text);
}

/* External positive/negative grammar corpus, including the first-error and
   fresh-unit recovery policy. Expected diagnostics are independently pinned
   in cases.csv, which exists before the test is run. */
static void grammar_corpus(const NovaHostImage *image) {
  const char *base = "tests/nova/tests/grammar-v0";
  char path[512], line[200];
  snprintf(path, sizeof path, "%s/cases.csv", base);
  FILE *f = fopen(path, "rb");
  CHECK(f != NULL, "grammar corpus manifest opens");
  if (!f) return;
  CHECK(fgets(line, sizeof line, f) && !strcmp(line,"file,code,reason,required_kind\n"), "grammar corpus header");
  unsigned count=0;
  while (fgets(line, sizeof line, f)) {
    char name[100], tail;
    unsigned code, reason, kind;
    int fields=sscanf(line,"%99[^,],%u,%u,%u %c",name,&code,&reason,&kind,&tail);
    CHECK(fields==4, "grammar manifest row parses exactly");
    if (fields!=4) continue;
    CHECK(!strchr(name,'/') && !strstr(name,".."), "grammar fixture stays in corpus");
    if (strchr(name,'/') || strstr(name,"..")) continue;
    snprintf(path,sizeof path,"%s/%s",base,name);
    size_t length=0;char *source=load(path,&length);
    CHECK(source!=NULL,"grammar fixture exists");
    if (!source) continue;
    Parsed result=parse(image,source,length);
    int good=result.words && result.runtime_error==0 && result.returned==code &&
             result.words[1]==code && result.words[2]==reason;
    if (good && code==0) good=result.words[0] && ast_well_formed(&result,length) &&
                             kind_count(&result,kind)>0;
    if (good && code!=0) good=!result.words[0] && result.words[9]==0 &&
                              result.words[4]>0 && result.words[5]>0 &&
                              result.words[6]<=result.words[7] && result.words[7]<=length;
    CHECK(good,"grammar fixture verdict and tree/diagnostic contract");
    if (!good) fprintf(stderr,"FAIL grammar %s got=%llu/%llu want=%u/%u runtime=%llu\n",name,
      (unsigned long long)result.returned,(unsigned long long)(result.words?result.words[2]:0),code,reason,
      (unsigned long long)result.runtime_error);
    free(result.words);free(source);++count;++cases;
  }
  CHECK(!ferror(f),"grammar corpus read completes");fclose(f);
  CHECK(count==20,"grammar corpus has exactly twenty executed rows");
  printf("GRAMMAR_CORPUS cases=%u\n",count);
}
int main(void) {
  const char *paths[] = {"tests/nova/tests/parser-entry.nova",
                         "compiler/nova/frontend/parser.nova",
                         "compiler/nova/frontend/ast.nova",
                         "compiler/nova/frontend/lexer.nova"};
  char *sources[4] = {0};
  NtFInput inputs[4];
  for (size_t i = 0; i < 4; i++) {
    size_t length = 0;
    sources[i] = load(paths[i], &length);
    inputs[i] = (NtFInput){paths[i], sources[i], length};
  }
  CHECK(sources[0] && sources[1] && sources[2] && sources[3],
        "parser Nova sources load");
  NtArtifact artifact;
  int compiled = sources[0] && sources[1] && sources[2] && sources[3] &&
                 nova_compile_many_v2(inputs, 4, &artifact);
  CHECK(compiled, "parser Nova modules compile");
  if (!compiled)
    fprintf(stderr, "Nova compile E%u %zu:%zu %s\n", artifact.error.code,
            artifact.error.line, artifact.error.column, artifact.error.message);
  NovaHostImage image = {0};
  CHECK(compiled && nova_host_map(&artifact, &image), "parser image maps");
  if (image.memory) {
    const char *basic =
        "module test\ntarget x86_64-nexora-none\nsection .text {\n"
        "fn main()->u64\neffects {}\nclobbers {} {\nreturn 42\n}\n}\n";
    expect_valid(&image, "basic", basic, 18);
    const char *control =
        "module control\ntarget x86_64-nexora-none\nsection .text {\n"
        "fn helper(in value:u64 @rcx)->u64\neffects {}\nclobbers {} {\n"
        "return value+1\n}\nfn main()->u64\neffects {}\nclobbers {} {\n"
        "let value:u64=(4+6)*4\nif value==40 {\nreturn helper(value)\n} "
        "else {\nreturn 0\n}\n}\n}\n";
    expect_valid(&image, "control_and_precedence", control, 30);
    const char *logical_precedence =
        "module logical\ntarget x86_64-nexora-none\nsection .text {\n"
        "fn main(in a:bool @al,in b:bool @cl,in c:bool @dl)->u64\n"
        "effects {}\nclobbers {} {\nif a || b && c {\nreturn 1\n} "
        "else {\nreturn 0\n}\n}\n}\n";
    expect_logical_shape(&image, "logical_and_binds_inside_or",
                         logical_precedence, 269, 1, 268);
    const char *logical_parentheses =
        "module logical_group\ntarget x86_64-nexora-none\nsection .text {\n"
        "fn main(in a:bool @al,in b:bool @cl,in c:bool @dl)->u64\n"
        "effects {}\nclobbers {} {\nif (a || b) && c {\nreturn 1\n} "
        "else {\nreturn 0\n}\n}\n}\n";
    expect_logical_shape(&image, "parentheses_override_logical_precedence",
                         logical_parentheses, 268, 1, 269);
    const char *logical_c_mismatch =
        "module logical_bad\ntarget x86_64-nexora-none\nsection .text {\n"
        "fn main(in ready:bool @al,in x:u64 @rcx)->u64\n"
        "effects {}\nclobbers {} {\nif ready && x {\nreturn 1\n} "
        "else {\nreturn 0\n}\n}\n}\n";
    expect_logical_type_error("logical_requires_bool", logical_c_mismatch);
    const char *memory_source =
        "module memory\ntarget x86_64-nexora-none\nsection .rdata {\n"
        "data answer:u64=42\n}\nsection .text {\n"
        "fn main()->u64\neffects {reads_mem(user)}\nclobbers {rax} {\n"
        "load rax,[answer]:ptr<user,u64>\nreturn rax\n}\n}\n";
    expect_valid(&image, "data_and_memory", memory_source, 34);
    const char *macro_source =
        "module macros\ntarget x86_64-nexora-none\n"
        "comptime(fuel=64,call_depth=8,arena_bytes=1048576,"
        "ast_nodes=1024,expansion_depth=8,constant_bytes=64) {\nreturn 0;\n}\n"
        "macro finish(v:ast.expr)->ast.stmt {\n"
        "return quote(stmt) { return $v+1; };\n}\nsection .text {\n"
        "fn main()->u64\neffects {}\nclobbers {} {\n"
        "expand finish(41)\n}\n}\n";
    expect_valid(&image, "comptime_macro", macro_source, 13);
    const char *macro_declarations =
        "module macro_decls\ntarget x86_64-nexora-none\n"
        "macro make(T:ast.type,v:ast.expr)->ast.decl {\n"
        "return quote(decl) { export data answer:$T=$v; };\n}\n"
        "macro body(v:ast.expr)->ast.block {\nreturn quote(block) {\n"
        "let temp:u64=$v;\nreturn temp;\n};\n}\n"
        "section .rdata {\nexpand make(quote(type) { u64 },42)\n}\n"
        "section .text {\nfn main()->u64\neffects {reads_mem(user)}\n"
        "clobbers {rax} {\nload rax,[answer]:ptr<user,u64>\n"
        "expand body(rax)\n}\n}\n";
    expect_valid(&image, "macro_decl_type_block_quotes", macro_declarations,
                 43);
    const char *stub_source =
        "module interrupts\ntarget x86_64-nexora-none\n"
        "stub_table faults kind interrupt {\nstub 6 {\n"
        "handler advance_saved_rip_2\n"
        "entry_abi nx64-interrupt-same-cpl-v0\n"
        "exit_abi nx64-iretq-same-cpl-v0\nexit iretq\n"
        "frame x86_64.frame.no_error.same_cpl\nbindings {}\n"
        "hardware_error_code false\nsave {rax}\nclobbers {}\n"
        "stack_align 0\nswapgs never\ninterrupts preserve\n"
        "section .text\nvisibility export\nsymbol isr6\n}\n}\n"
        "section .text {\nfn main()->u64\neffects {}\nclobbers {} {\n"
        "return 0\n}\n}\n";
    expect_valid(&image, "structured_stub", stub_source, 15);
    const char *format_only =
        "module format\ntarget x86_64-nexora-none\n"
        "versions {\nntir 1.0\nmachine_ir 1.0\nsections 1.0\n"
        "symbols 1.0\nrelocations 1.0\nnxo 1.0\n}\n"
        "default_abi nx64-abi-v0\noutput pe-coff-v0\nfeatures {lm,syscall}\n";
    expect_parse_only(&image, "format_headers", format_only, 4);
    const char *import_only =
        "module app\ntarget x86_64-nexora-none\n"
        "import math.add as add: fn(in a:u64 @rcx,in b:u64 @rdx)->u64\n"
        "effects {}\nclobbers {}\nrequires {stack_aligned(16)}\n"
        "ensures {stack_aligned(16)}\n";
    expect_parse_only(&image, "typed_import", import_only, 9);
    expect_syntax_error(&image, "missing_module",
                        "target x86_64-nexora-none\n");
    expect_syntax_error(&image, "missing_return_expression",
                        "module test\ntarget x86_64-nexora-none\n"
                        "section .text {\nfn main()->u64\neffects {}\n"
                        "clobbers {} {\nreturn +\n}\n}\n");
    expect_syntax_error(&image, "missing_target",
                        "module test\nsection .text {\n}\n");
    expect_syntax_error(&image, "parameter_missing_colon",
                        "module test\ntarget x86_64-nexora-none\nsection .text {\n"
                        "fn f(in value u64)->u64\neffects {}\nclobbers {} {\n"
                        "return 0\n}\n}\n");
    expect_syntax_error(&image, "unterminated_block",
                        "module test\ntarget x86_64-nexora-none\nsection .text {\n"
                        "fn main()->u64\neffects {}\nclobbers {} {\nreturn 0\n");
    expect_syntax_error(&image, "pointer_missing_close",
                        "module test\ntarget x86_64-nexora-none\nsection .text {\n"
                        "fn f(in p:ptr<user,u64 @rcx)->u64\neffects {}\n"
                        "clobbers {} {\nreturn 0\n}\n}\n");
    const char *complex_address =
        "module address\ntarget x86_64-nexora-none\nsection .text {\n"
        "fn read(in base:ptr<user,u64> @rdi,in index:u64 @rsi)->u64\n"
        "effects {reads_mem(user)}\nclobbers {rax} {\n"
        "load rax,[rdi+rsi*8+16]:ptr<user,u64>\nreturn rax\n}\n}\n";
    expect_valid(&image, "complex_address", complex_address, 34);
    const char *integer_widths =
        "module widths\ntarget x86_64-nexora-none\nsection .text {\n"
        "fn widths(in a:u8 @dil,in b:u16 @si,in c:u32 @edx,"
        "in d:u64 @rcx)->u64\neffects {}\nclobbers {} {\n"
        "return d\n}\n}\n";
    expect_valid(&image, "integer_widths", integer_widths, 19);
    const char *typed_call =
        "module calls\ntarget x86_64-nexora-none\nsection .text {\n"
        "fn caller(in x:u32 @edi)->u64\neffects {}\nclobbers {} {\n"
        "call callee(x)\nreturn 0\n}\n"
        "fn callee(in y:u32 @edi)->u32\neffects {}\nclobbers {} {\n"
        "return y\n}\n}\n";
    expect_valid(&image, "typed_call", typed_call, 28);
    const char *nested_branch =
        "module branches\ntarget x86_64-nexora-none\nsection .text {\n"
        "fn choose(in x:u64 @rdi)->u64\neffects {}\nclobbers {} {\n"
        "if x>9 {\nreturn 42\n} else {\nif x==9 {\nreturn 9\n} "
        "else {\nreturn 0\n}\n}\n}\n}\n";
    expect_valid(&image, "nested_branch", nested_branch, 30);
    const char *declared_effects =
        "module effects\ntarget x86_64-nexora-none\nsection .text {\n"
        "fn mutate()->u64\neffects {reads_mem(user),writes_mem(user),"
        "changes_flags}\nclobbers {rax,rcx,r11} {\nreturn 42\n}\n}\n";
    expect_valid(&image, "declared_effects", declared_effects, 20);
    const char *contracts =
        "module contracts\ntarget x86_64-nexora-none\nsection .text {\n"
        "fn read(in p:ptr<user,u64> @rdi)->u64\n"
        "effects {reads_mem(user)}\nclobbers {rax}\n"
        "requires {non_null(p)}\nensures {} {\nreturn 0\n}\n}\n";
    expect_valid(&image, "contracts", contracts, 22);
    const char *versioned_features =
        "module formats\ntarget x86_64-nexora-none\nversions {\nntir 1.0\n"
        "machine_ir 1.0\nsections 1.0\nsymbols 1.0\n"
        "relocations 1.0\nnxo 1.0\n}\nfeatures {lm,syscall}\n";
    expect_parse_only(&image, "versioned_features", versioned_features, 8);
    expect_syntax_error(&image, "missing_memory_close",
                        "module bad\ntarget x86_64-nexora-none\nsection .text {\n"
                        "fn f()->u64\neffects {reads_mem(user)}\n"
                        "clobbers {rax} {\nload rax,[rax+8:ptr<user,u64>\n"
                        "return rax\n}\n}\n");
    /* spec/ntasm/ntasm.md section 9, kept word for word: it is normative for the
       syntactic surface it shows, and align_stack 16 is part of it. */
    const char *spec_section9 =
        "module kernel.syscalls\n"
        "target x86_64-nexora-none\n"
        "\n"
        "section .syscall {\n"
        "    export fn syscall_entry(\n"
        "        in number: u64 @rax,\n"
        "        in arg0: u64 @rdi,\n"
        "        in arg1: u64 @rsi\n"
        "    ) -> never\n"
        "    effects { privileged, reads_mem, writes_mem, changes_flags }\n"
        "    clobbers { rax, rcx, r11 } {\n"
        "        swapgs\n"
        "        load rsp, [gs:kernel_rsp]:ptr<kernel, u64>\n"
        "        align_stack 16\n"
        "        call nx_syscall_dispatch\n"
        "        sysretq\n"
        "    }\n"
        "}\n";
    expect_parse_only(&image, "spec_section9_align_stack", spec_section9, 45);
    const char *align_plain =
        "module aligned\ntarget x86_64-nexora-none\nsection .text {\n"
        "fn entry()->u64\neffects {privileged}\nclobbers {rax} {\n"
        "align_stack 16\nreturn 0\n}\n}\n";
    expect_parse_only(&image, "align_stack_statement", align_plain, 45);
    const char *align_twice =
        "module twice\ntarget x86_64-nexora-none\nsection .text {\n"
        "fn entry()->u64\neffects {privileged}\nclobbers {rax} {\n"
        "align_stack 16\nalign_stack 16\nreturn 0\n}\n}\n";
    expect_kind_count(&image, "align_stack_twice_parses", align_twice, 45, 2);
    const char *align_missing =
        "module missing\ntarget x86_64-nexora-none\nsection .text {\n"
        "fn entry()->u64\neffects {privileged}\nclobbers {rax} {\n"
        "align_stack\nreturn 0\n}\n}\n";
    expect_nova_error(&image, "align_stack_missing_operand", align_missing, 4);
    const char *align_name =
        "module named\ntarget x86_64-nexora-none\nsection .text {\n"
        "fn entry()->u64\neffects {privileged}\nclobbers {rax} {\n"
        "align_stack sixteen\nreturn 0\n}\n}\n";
    expect_nova_error(&image, "align_stack_operand_not_literal", align_name, 4);
    const char *align_string =
        "module stringy\ntarget x86_64-nexora-none\nsection .text {\n"
        "fn entry()->u64\neffects {privileged}\nclobbers {rax} {\n"
        "align_stack \"16\"\nreturn 0\n}\n}\n";
    expect_nova_error(&image, "align_stack_operand_not_integer", align_string, 4);
    const char *align_in_section =
        "module loose\ntarget x86_64-nexora-none\nsection .text {\n"
        "align_stack 16\n}\n";
    expect_nova_error(&image, "align_stack_outside_function_in_section",
                      align_in_section, 7);
    const char *align_at_top =
        "module loose_top\ntarget x86_64-nexora-none\nalign_stack 16\n";
    expect_nova_error(&image, "align_stack_outside_function_at_top", align_at_top,
                      6);
    expect_frozen_keyword_indices(&image);

    /* --- The type-closer boundary, pinned exactly. See type_closer_case. ---
     * Accepted: a bare `>` and a split `>>`. Refused: `>=`, because it lexes
     * as ONE token (lexer.nova:201-202, mirroring frontend.c:441-443). */
    type_closer_case(&image, "closer_array_bare_gt", "data t:array<u8,4> =1", 1, 0,
                     0);
    type_closer_case(&image, "closer_ptr_bare_gt", "data t:ptr<user,u64> =1", 1, 0,
                     0);
    type_closer_case(&image, "closer_array_ge", "data t:array<u8,4>=1", 0, 10, 0);
    type_closer_case(&image, "closer_ptr_ge", "data t:ptr<user,u64>=1", 0, 10, 0);
    type_closer_case(&image, "closer_array_ge_eq", "data t:array<u8,4>==1", 0, 10,
                     0);
    /* `>>` IS split by type_close (parser.nova:145-150), so the inner type
     * closes and the leftover `=` becomes a data-type error instead. That
     * different diagnostic is the proof the split happened, and it is why
     * these two cases carry split_closer=1. */
    type_closer_case(&image, "closer_array_shr", "data t:array<u8,4>>=1", 0, 4, 1);
    type_closer_case(&image, "closer_nested_bare", "data t:array<array<u8,2>,2> =1",
                     1, 0, 0);
    type_closer_case(&image, "closer_nested_ge", "data t:array<array<u8,2>,2>=1",
                     0, 10, 0);
    type_closer_case(&image, "closer_nested_shr", "data t:array<array<u8,2>,2>>=1",
                     0, 4, 1);

    /* --- Signature reflow: the standing refutation of "the line gets long".
     * Each pair differs ONLY in whitespace and must parse to the same tree. */
    signature_reflow_case(
        &image, "contract_length",
        "fn contract_length(in source:ptr<user,u64>,in tree:u64,"
        "in work:ptr<user,u64>,in base:u64)->u64",
        "fn contract_length(in source:ptr<user,u64>,in tree:u64,\n"
        "                   in work:ptr<user,u64>,in base:u64)->u64");
    signature_reflow_case(
        &image, "emit_probe",
        "fn emit_probe(in text:ptr<user,u64>,in at:u64,in early:u64)->u64",
        "fn emit_probe(in text:ptr<user,u64>,in at:u64,\n"
        "              in early:u64)->u64");
    /* The tree's own worst case in shape. A sweep of all 1553 shipped fn
     * signatures (wave 8) found the longest single-line signature is 243
     * characters (x64_fixed.nova:769) and the heaviest is 30 of the 64 Nova
     * ABI slots (stub_table.nova:1519, nine buffers). Neither dimension has
     * any limit at length, and the slot count sits at 47% of its cap. The nx64
     * ABI separately caps a call at four register arguments, so this case
     * stays at the swept width without tripping that unrelated limit. */
    signature_reflow_case(
        &image, "wide_scalars",
        "fn wide(in a0:u64,in a1:u64,in a2:u64,in a3:u64)->u64",
        "fn wide(in a0:u64,\n"
        "         in a1:u64,\n"
        "         in a2:u64,\n"
        "         in a3:u64)->u64");

    /* Signature contracts may start on the return-type line, as frontend.c
     * parse_function permits. Required contract keywords remain mandatory. */
    expect_valid(&image, "inline_contracts",
        "module inline_contracts\ntarget x86_64-nexora-uefi\nsection .text {\n"
        "export fn main()->u64 effects {} clobbers {} {\nreturn 42\n}\n}\n", 18);
    expect_valid(&image, "inline_abi",
        "module inline_abi\ntarget x86_64-nexora-uefi\nsection .text {\n"
        "export fn main()->u64 abi nx64-abi-v0\neffects {} clobbers {} {\nreturn 42\n}\n}\n", 18);
    expect_nova_error(&image, "inline_missing_effects",
        "module inline_bad\ntarget x86_64-nexora-uefi\nsection .text {\n"
        "fn main()->u64 clobbers {} {\nreturn 42\n}\n}\n", 4);
    expect_nova_error(&image, "inline_missing_clobbers",
        "module inline_bad\ntarget x86_64-nexora-uefi\nsection .text {\n"
        "fn main()->u64 effects {} {\nreturn 42\n}\n}\n", 4);
    /* --- Every owned positive fixture must parse. positive-module.ntasm did
     * not, for as long as the gate existed. */
    fixture_parses(&image,
                   "tests/nova/tests/fixtures/positive-module.ntasm");
    grammar_corpus(&image);
  }
  if (image.memory)
    nova_host_unmap(&image);
  if (compiled)
    nt_artifact_free(&artifact);
  for (size_t i = 0; i < 4; i++)
    free(sources[i]);
  printf("NTASM_NOVA_PARSER checks=%u failures=%u cases=%u\n", checks,
         failures, cases);
  return failures ? 1 : 0;
}
