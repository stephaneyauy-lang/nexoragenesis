/* A9 NTASM CLI product gate. The shipped command surface and the shipped
 * guide must agree, and the source -> PE path the guide documents must still
 * produce a real, byte-stable PE through nt_cli() itself.
 *
 * The product binary is main.c + cli.c + the C oracle library. cli.c is not in
 * ngbuild.sh's LIBS, so this gate compiles it in directly; the code under test
 * is the shipped cli.c, not a copy of it.
 *
 * Every expectation is anchored on an artefact: the binary's own --help
 * stdout, the bytes nt_cli writes, the exit codes nt_cli returns, the examples
 * the guide names, the sha256 the guide records, and nt_pe_inspect (the C
 * oracle) on the emitted image. Nothing here restates the guide back to
 * itself: the guide is the specification, nt_cli is the implementation, and
 * the two are compared.
 *
 * QEMU is deliberately absent. Booting the image needs mkfs.vfat, mtools and
 * qemu, which AGENTS.md classifies as host runners, never as a suite check.
 * The boot half of the A9 path is documented in docs/guides/ntasm-cli.md and proven
 * by the recorded QEMU evidence, not by this gate. */
#define _POSIX_C_SOURCE 200809L
#include "../../../compiler/c/ntasm/cli/cli.c"
#include "ng_run_dir.h"
#include <dirent.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static unsigned checks, failures, cases;

static const char DOC_PATH[] = "docs/guides/ntasm-cli.md";
static const char EXAMPLE_DIR[] = "examples/ntasm-v0/c-bootstrap";

#define CHECK(c, m)                                                            \
  do {                                                                         \
    checks++;                                                                  \
    if (!(c)) {                                                                \
      failures++;                                                              \
      fprintf(stderr, "FAIL: %s\n", m);                                        \
    }                                                                          \
  } while (0)

/* ---- whole-file read ---------------------------------------------------- */

static char *slurp(const char *path, size_t *length) {
  FILE *f = fopen(path, "rb");
  if (!f)
    return NULL;
  size_t cap = 4096, used = 0;
  char *buffer = malloc(cap);
  if (!buffer) {
    fclose(f);
    return NULL;
  }
  for (;;) {
    if (used + 1 == cap) {
      char *bigger = realloc(buffer, cap * 2);
      if (!bigger) {
        free(buffer);
        fclose(f);
        return NULL;
      }
      buffer = bigger;
      cap *= 2;
    }
    size_t got = fread(buffer + used, 1, cap - 1 - used, f);
    used += got;
    if (got == 0)
      break;
  }
  int bad = ferror(f);
  fclose(f);
  if (bad) {
    free(buffer);
    return NULL;
  }
  buffer[used] = 0;
  if (length)
    *length = used;
  return buffer;
}

/* ---- stdout / stderr capture -------------------------------------------- */

typedef struct {
  FILE *sink;
  int saved;
} Capture;

static void capture_begin(Capture *c, FILE *stream) {
  fflush(stream);
  c->sink = tmpfile();
  c->saved = dup(fileno(stream));
  dup2(fileno(c->sink), fileno(stream));
}

static size_t capture_end(Capture *c, FILE *stream, char *out, size_t cap) {
  fflush(stream);
  dup2(c->saved, fileno(stream));
  close(c->saved);
  rewind(c->sink);
  size_t got = fread(out, 1, cap - 1, c->sink);
  out[got] = 0;
  fclose(c->sink);
  return got;
}

/* argv is not const: nt_cli takes char **, and the signature is the
 * product's, not this gate's. */
static int run_cli(char **argv, int argc, char *out, char *err) {
  Capture c_out, c_err;
  capture_begin(&c_out, stdout);
  capture_begin(&c_err, stderr);
  int rc = nt_cli(argc, argv);
  capture_end(&c_err, stderr, err, 8192);
  capture_end(&c_out, stdout, out, 8192);
  return rc;
}

/* A text block is compared without its final newline, so a guide block and a
 * program that ends every line with one describe the same text. */
static void drop_final_newline(char *text) {
  size_t n = strlen(text);
  if (n && text[n - 1] == '\n')
    text[n - 1] = 0;
}

/* ---- fenced block extraction from the guide ----------------------------- */

/* Body of the `occurrence`-th (0-based) fenced block whose info string is
 * exactly `tag`, NUL terminated. NULL when there is no such block. */
static char *block(const char *doc, const char *tag, size_t occurrence,
                   size_t *out_len) {
  size_t tag_len = strlen(tag);
  size_t seen = 0;
  const char *p = doc;
  while ((p = strstr(p, "```")) != NULL) {
    const char *info = p + 3;
    size_t info_len = strcspn(info, "\n");
    const char *body = info + info_len + 1;
    int match = info_len == tag_len && !strncmp(info, tag, tag_len);
    if (!match) {
      p = body;
      continue;
    }
    if (seen++ != occurrence) {
      p = body;
      continue;
    }
    const char *close = strstr(body, "\n```");
    if (!close)
      return NULL;
    size_t len = (size_t)(close - body);
    char *result = malloc(len + 1);
    if (!result)
      return NULL;
    memcpy(result, body, len);
    result[len] = 0;
    if (out_len)
      *out_len = len;
    return result;
  }
  return NULL;
}

/* ---- token sets --------------------------------------------------------- */

#define MAX_TOKENS 64
typedef struct {
  size_t count;
  char *token[MAX_TOKENS];
} TokenSet;

static int separator(char c) {
  return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '|';
}

static int add_token(TokenSet *set, const char *start, size_t len) {
  for (size_t i = 0; i < set->count; ++i)
    if (strlen(set->token[i]) == len && !strncmp(set->token[i], start, len))
      return 1; /* already present */
  if (set->count == MAX_TOKENS)
    return 0;
  char *copy = malloc(len + 1);
  if (!copy)
    return 0;
  memcpy(copy, start, len);
  copy[len] = 0;
  set->token[set->count++] = copy;
  return 1;
}

static void free_tokens(TokenSet *set) {
  for (size_t i = 0; i < set->count; ++i)
    free(set->token[i]);
  set->count = 0;
}

static int has_token(const TokenSet *set, const char *needle) {
  for (size_t i = 0; i < set->count; ++i)
    if (!strcmp(set->token[i], needle))
      return 1;
  return 0;
}

/* Whitespace delimited words. */
static int words_of(const char *text, TokenSet *set, char lead) {
  memset(set, 0, sizeof(*set));
  int overflow = 0;
  for (const char *p = text; *p;) {
    while (*p && separator(*p))
      ++p;
    if (!*p)
      break;
    const char *start = p;
    while (*p && !separator(*p))
      ++p;
    if (*start == lead && !overflow)
      overflow = !add_token(set, start, (size_t)(p - start));
  }
  return !overflow;
}

/* ---- the guide's table of shipped examples ----------------------------- */

typedef struct {
  size_t count;
  char *id[MAX_TOKENS];
  char hash[MAX_TOKENS][65];
} ExampleTable;

static int hex64(const char *p, size_t len) {
  if (len != 64)
    return 0;
  for (size_t i = 0; i < len; ++i) {
    char c = p[i];
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
      return 0;
  }
  return 1;
}

static int examples_from_block(const char *text, ExampleTable *table) {
  memset(table, 0, sizeof(*table));
  const char *line = text;
  while (*line) {
    const char *end = strchr(line, '\n');
    if (!end)
      end = line + strlen(line);
    const char *cursor = line;
    while (cursor < end && separator(*cursor))
      ++cursor;
    const char *id = cursor;
    while (cursor < end && !separator(*cursor))
      ++cursor;
    while (cursor < end && separator(*cursor))
      ++cursor;
    const char *hash = cursor;
    while (cursor < end && !separator(*cursor))
      ++cursor;
    if (cursor > id && hex64(hash, (size_t)(cursor - hash))) {
      if (table->count == MAX_TOKENS)
        return 0;
      size_t id_len = (size_t)(hash - id);
      while (id_len && separator(id[id_len - 1]))
        --id_len;
      char *copy = malloc(id_len + 1);
      if (!copy)
        return 0;
      memcpy(copy, id, id_len);
      copy[id_len] = 0;
      table->id[table->count] = copy;
      memcpy(table->hash[table->count], hash, 64);
      table->hash[table->count][64] = 0;
      ++table->count;
    }
    line = *end ? end + 1 : end;
  }
  return 1;
}

static void free_examples(ExampleTable *table) {
  for (size_t i = 0; i < table->count; ++i)
    free(table->id[i]);
  table->count = 0;
}

/* ---- artefacts ---------------------------------------------------------- */

static size_t file_bytes(const char *path, unsigned char *out, size_t cap) {
  FILE *f = fopen(path, "rb");
  if (!f)
    return 0;
  size_t got = fread(out, 1, cap, f);
  int bad = ferror(f);
  fclose(f);
  return bad ? 0 : got;
}

static int file_exists(const char *path) {
  FILE *f = fopen(path, "rb");
  if (!f)
    return 0;
  fclose(f);
  return 1;
}

static int files_identical(const char *left, const char *right) {
  FILE *a = fopen(left, "rb"), *b = fopen(right, "rb");
  if (!a || !b) {
    if (a)
      fclose(a);
    if (b)
      fclose(b);
    return 0;
  }
  int same = 1;
  for (;;) {
    unsigned char ba[4096], bb[4096];
    size_t na = fread(ba, 1, sizeof(ba), a), nb = fread(bb, 1, sizeof(bb), b);
    if (na != nb || (na && memcmp(ba, bb, na))) {
      same = 0;
      break;
    }
    if (na < sizeof(ba))
      break;
  }
  fclose(a);
  fclose(b);
  return same;
}

/* Minimal SHA-256, so the guide's recorded digests are compared against a
 * computation instead of against a second copy of the guide's number. */
typedef struct {
  uint32_t h[8];
  uint64_t bits;
  unsigned char block[64];
  size_t fill;
} Sha256;

static uint32_t ror(uint32_t v, unsigned n) {
  return (v >> n) | (v << (32 - n));
}

static void sha256_block(Sha256 *s, const unsigned char *p) {
  static const uint32_t K[64] = {
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
      0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
      0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
      0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
      0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
      0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
      0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
      0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
      0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
  uint32_t w[64];
  for (unsigned i = 0; i < 16; ++i)
    w[i] = (uint32_t)p[i * 4] << 24 | (uint32_t)p[i * 4 + 1] << 16 |
           (uint32_t)p[i * 4 + 2] << 8 | (uint32_t)p[i * 4 + 3];
  for (unsigned i = 16; i < 64; ++i) {
    uint32_t s0 = ror(w[i - 15], 7) ^ ror(w[i - 15], 18) ^ (w[i - 15] >> 3);
    uint32_t s1 = ror(w[i - 2], 17) ^ ror(w[i - 2], 19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }
  uint32_t a = s->h[0], b = s->h[1], c = s->h[2], d = s->h[3];
  uint32_t e = s->h[4], f = s->h[5], g = s->h[6], h = s->h[7];
  for (unsigned i = 0; i < 64; ++i) {
    uint32_t s1 = ror(e, 6) ^ ror(e, 11) ^ ror(e, 25);
    uint32_t ch = (e & f) ^ (~e & g);
    uint32_t t1 = h + s1 + ch + K[i] + w[i];
    uint32_t s0 = ror(a, 2) ^ ror(a, 13) ^ ror(a, 22);
    uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
    uint32_t t2 = s0 + maj;
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }
  s->h[0] += a;
  s->h[1] += b;
  s->h[2] += c;
  s->h[3] += d;
  s->h[4] += e;
  s->h[5] += f;
  s->h[6] += g;
  s->h[7] += h;
}

static void sha256_init(Sha256 *s) {
  static const uint32_t iv[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
  memcpy(s->h, iv, sizeof(iv));
  s->bits = 0;
  s->fill = 0;
}

static void sha256_update(Sha256 *s, const unsigned char *p, size_t n) {
  s->bits += (uint64_t)n * 8;
  while (n) {
    size_t take = 64 - s->fill;
    if (take > n)
      take = n;
    memcpy(s->block + s->fill, p, take);
    s->fill += take;
    p += take;
    n -= take;
    if (s->fill == 64) {
      sha256_block(s, s->block);
      s->fill = 0;
    }
  }
}

static int sha256_file(const char *path, char out[65]) {
  FILE *f = fopen(path, "rb");
  if (!f)
    return 0;
  Sha256 s;
  sha256_init(&s);
  for (;;) {
    unsigned char buf[8192];
    size_t got = fread(buf, 1, sizeof(buf), f);
    sha256_update(&s, buf, got);
    if (got < sizeof(buf))
      break;
  }
  int bad = ferror(f);
  fclose(f);
  if (bad)
    return 0;
  uint64_t bits = s.bits;
  unsigned char pad = 0x80, zero = 0;
  sha256_update(&s, &pad, 1);
  while (s.fill != 56)
    sha256_update(&s, &zero, 1);
  for (unsigned i = 0; i < 8; ++i)
    s.block[56 + i] = (unsigned char)(bits >> ((7 - i) * 8));
  sha256_block(&s, s.block);
  static const char digits[] = "0123456789abcdef";
  for (unsigned i = 0; i < 8; ++i)
    for (unsigned b = 0; b < 4; ++b) {
      /* A digest word is written most significant byte first; the shift
       * alone is not the byte, so the byte is masked out of the word. */
      unsigned byte = (unsigned)((s.h[i] >> ((3 - b) * 8)) & 0xffu);
      out[i * 8 + b * 2] = digits[byte >> 4];
      out[i * 8 + b * 2 + 1] = digits[byte & 15];
    }
  out[64] = 0;
  return 1;
}

/* ---- PE observation through the C oracle -------------------------------- */

static uint32_t le32(const unsigned char *p) {
  return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 |
         (uint32_t)p[3] << 24;
}

static uint16_t le16(const unsigned char *p) {
  return (uint16_t)((uint32_t)p[0] | (uint32_t)p[1] << 8);
}

/* The image nt_cli wrote, described by nt_pe_inspect and by its own header
 * bytes. Both are read from the file, not from the writer's report. */
static int image_is_wellformed_uefi(const char *path, NtPeInfo *info) {
  unsigned char buf[65536];
  size_t size = file_bytes(path, buf, sizeof(buf));
  memset(info, 0, sizeof(*info));
  /* A file that filled the buffer was truncated by the read, not by the
   * writer; either way it is not the artefact the guide describes. */
  if (size < 1024 || size >= sizeof(buf))
    return 0;
  NtDiagnostic error = {0};
  if (!nt_pe_inspect(buf, size, info, &error))
    return 0;
  if (size < 0x40 || buf[0] != 'M' || buf[1] != 'Z')
    return 0;
  size_t pe_at = le32(buf + 0x3c);
  if (pe_at + 24 + 70 > size)
    return 0;
  const unsigned char *pe = buf + pe_at;
  if (memcmp(pe, "PE\0\0", 4))
    return 0;
  const unsigned char *opt = pe + 24;
  return le16(pe + 4) == 0x8664 && le16(opt) == 0x20b && le16(opt + 68) == 10;
}

/* ---- work directory ----------------------------------------------------- */

static char *g_dir;
static char *g_example_source;
static char *g_example_efi;

static char *in_dir(const char *name) {
  size_t n = strlen(g_dir) + strlen(name) + 2;
  char *p = malloc(n);
  if (p)
    snprintf(p, n, "%s/%s", g_dir, name);
  return p;
}

static int write_file(const char *path, const char *text) {
  FILE *f = fopen(path, "wbx");
  if (!f)
    return 0;
  size_t len = strlen(text);
  size_t wrote = len ? fwrite(text, 1, len, f) : 0;
  int bad = (wrote != len) || fflush(f) || fclose(f);
  return !bad;
}

/* ---- main --------------------------------------------------------------- */


/* Equality in both directions, with one named, non-product experiment. */
static int example_member(const ExampleTable *t, const char *file) {
  char want[180];
  for (size_t i=0;i<t->count;++i) {
    snprintf(want,sizeof want,"%s.ntasm",t->id[i]);
    if (!strcmp(want,file)) return 1;
  }
  return !strcmp(file,"call-private-stmt.ntasm");
}
static int examples_closed(const ExampleTable *t, const char *dir) {
  DIR *d=opendir(dir);struct dirent *e;size_t count=0;
  if (!d) return 0;
  int good=t->count==7;
  while ((e=readdir(d))!=NULL) {
    size_t n=strlen(e->d_name);
    if(n<6 || strcmp(e->d_name+n-6,".ntasm"))continue;
    ++count;if(!example_member(t,e->d_name))good=0;
  }
  closedir(d);
  if(count!=t->count+1)good=0;
  for(size_t i=0;i<=t->count;++i) {
    char path[1024];
    if(i<t->count)snprintf(path,sizeof path,"%s/%s.ntasm",dir,t->id[i]);
    else snprintf(path,sizeof path,"%s/call-private-stmt.ntasm",dir);
    struct stat st;
    if(stat(path,&st)!=0 || !S_ISREG(st.st_mode))good=0;
    for(size_t j=0;j<i && i<t->count;++j)
      if(!strcmp(t->id[j],t->id[i]))good=0;
  }
  return good;
}
static void examples_closure_controls(const ExampleTable *t) {
  char *shadow=in_dir("example-census");
  CHECK(mkdir(shadow,0700)==0,"census shadow is freshly created");
  for(size_t i=0;i<=t->count;++i) {
    char path[1024];
    if(i<t->count)snprintf(path,sizeof path,"%s/%s.ntasm",shadow,t->id[i]);
    else snprintf(path,sizeof path,"%s/call-private-stmt.ntasm",shadow);
    CHECK(write_file(path,"// census only\n"),"shadow member created");
  }
  CHECK(examples_closed(t,shadow),"closed shadow is accepted");
  char path[1024];snprintf(path,sizeof path,"%s/unlisted.ntasm",shadow);
  CHECK(write_file(path,"// unlisted\n"),"unlisted member created");
  CHECK(!examples_closed(t,shadow),"unlisted ninth file rejected");
  CHECK(unlink(path)==0,"only owned mutation removed");
  CHECK(examples_closed(t,shadow),"removal restores closure");
  snprintf(path,sizeof path,"%s/%s.ntasm",shadow,t->id[0]);
  CHECK(unlink(path)==0,"owned expected member removed");
  CHECK(!examples_closed(t,shadow),"missing promised file rejected");
  free(shadow);
}
int main(void) {
  char out[8192], err[8192];

  char *doc = slurp(DOC_PATH, NULL);
  if (!doc) {
    fprintf(stderr, "cannot read %s\n", DOC_PATH);
    return 2;
  }
  /* The work directory was mkdtemp("/tmp/ng-cli-XXXXXX"). mkdtemp is atomic and
   * names a directory nobody else holds, so two concurrent runs never collided
   * on it -- this is a unification and not a repair, and it is not claimed to
   * be a repair. What it does gain is the driver: ng_run_dir puts the directory
   * under NG_BUILD when the driver supplied one, so the CLI gate's leftovers
   * land in the same durable place as its log instead of in a /tmp the host
   * reclaims, and the path is printed so a failing case can be inspected.
   * It also stops being the one place in this directory with a private
   * mechanism, which is the drift this lot exists to close. */
  char why[NG_RUN_DIR_MAX];
  g_dir = (char *)ng_run_dir(why, sizeof why);
  if (!g_dir) {
    fprintf(stderr, "cannot create work directory: %s\n", why);
    return 2;
  }
  fprintf(stderr, "RUN_DIR %s\n", g_dir);
  g_example_source = in_dir("worked-example.ntasm");
  g_example_efi = in_dir("worked-example.efi");

  /* 1. The guide must carry the binary's own --help output, byte for byte. */
  cases++;
  char *documented_usage = block(doc, "text", 0, NULL);
  char *help_args[] = {"ntasm", "--help"};
  int help_rc = run_cli(help_args, 2, out, err);
  drop_final_newline(out);
  CHECK(help_rc == 0, "ntasm --help is a successful request, not a usage error");
  CHECK(out[0] != 0, "--help writes the surface to stdout");
  CHECK(err[0] == 0, "--help writes nothing to stderr");
  CHECK(documented_usage != NULL, "guide opens with the verbatim --help block");
  CHECK(documented_usage && !strncmp(documented_usage, "usage:", 6),
        "the first text block of the guide is the --help transcript");
  CHECK(documented_usage && !strcmp(documented_usage, out),
        "guide's verbatim --help block equals the binary's stdout");

  /* 2. Verb set: exactly what the binary declares, no more, no less. The
   * verb is the word after "ntasm " at the start of a usage line, so the
   * "MORE.ntasm" placeholder inside a synopsis is not mistaken for one. */
  cases++;
  TokenSet declared;
  memset(&declared, 0, sizeof(declared));
  int have_declared = 1;
  for (const char *line = out; *line;) {
    const char *eol = strchr(line, '\n');
    if (!eol)
      eol = line + strlen(line);
    const char *p = line;
    while (p < eol && (*p == ' ' || *p == '\t'))
      ++p;
    if ((size_t)(eol - p) > 6 && !strncmp(p, "usage: ", 7))
      p += 7;
    if ((size_t)(eol - p) > 6 && !strncmp(p, "ntasm ", 6)) {
      const char *start = p + 6, *end = start;
      while (end < eol && !separator(*end))
        ++end;
      if (end != start)
        have_declared &= add_token(&declared, start, (size_t)(end - start));
    }
    line = *eol ? eol + 1 : eol;
  }
  CHECK(have_declared, "the binary's --help declares a parseable verb set");
  CHECK(declared.count == 6, "the shipped CLI declares exactly six verbs");
  static const char *expected_verbs[] = {"assemble", "check", "inspect",
                                         "object",  "link",  "run"};
  for (size_t i = 0; i < 6; ++i)
    CHECK(has_token(&declared, expected_verbs[i]),
          "the declared verb set contains the documented verb");
  /* `run` LEFT this list on 2026-10-02, when it became the tool's sixth verb.
   * `execute` stays absent on purpose: the verb that runs an image is spelled
   * `run`, and a tool that grew a second spelling for the same request would
   * be the ambiguity this list exists to prevent. */
  static const char *absent_verbs[] = {"build", "emit",   "compile", "format",
                                       "test",  "start",  "execute"};
  for (size_t i = 0; i < 7; ++i)
    CHECK(!has_token(&declared, absent_verbs[i]),
          "the declared verb set contains no undocumented verb");

  /* 3. The worked example is staged first, because the -o flag check below
   *    assembles it: a flag proven on an empty file proves nothing. */
  cases++;
  char *documented_example = block(doc, "ntasm", 0, NULL);
  CHECK(documented_example && documented_example[0],
        "guide carries a complete worked example");
  int example_staged = 0;
  if (documented_example) {
    example_staged = write_file(g_example_source, documented_example);
    CHECK(example_staged, "worked example is written to disk for the compiler");
  }

  /* 4. Every flag the binary declares must be accepted by the binary. */
  cases++;
  TokenSet flags;
  int have_flags = words_of(out, &flags, '-');
  CHECK(have_flags, "the declared flag set is parseable");
  for (size_t i = 0; i < flags.count; ++i) {
    const char *w = flags.token[i];
    if (!strcmp(w, "--version") || !strcmp(w, "-h") || !strcmp(w, "--help")) {
      char *args[] = {"ntasm", (char *)w};
      CHECK(run_cli(args, 2, out, err) == 0,
            "a flag the binary declares is accepted by the binary");
    } else if (!strcmp(w, "-o")) {
      char *probe = in_dir("flag-probe.efi");
      char *args[] = {"ntasm", "assemble", g_example_source, "-o", probe};
      CHECK(run_cli(args, 5, out, err) == 0,
            "-o in its documented position writes the output");
      free(probe);
    } else if (!strcmp(w, "--expect")) {
      char *expect_args[] = {"ntasm", "run", g_example_source, "--expect", "0"};
      int rc = run_cli(expect_args, 5, out, err);
      CHECK(rc != 2, "--expect in its documented position is not a usage error");
    } else if (!strcmp(w, "--backend")) {
      /* A7, 7 October 2026: the Machine IR chain is reached through this flag
       * on every verb, and the two answers must be told apart by their own
       * markers: a `mir` build that printed the C marker would be the silent
       * fallback the flag promises not to have. */
      char *mir_probe = in_dir("flag-probe-mir.efi");
      char *mir_args[] = {"ntasm", "assemble", "--backend", "mir",
                          g_example_source, "-o", mir_probe};
      CHECK(run_cli(mir_args, 7, out, err) == 0,
            "--backend mir assembles the worked example through the Machine IR "
            "chain");
      CHECK(strstr(out, "NTASM_MIR_PE") != NULL &&
                strstr(out, "provenance=NEXORA_MIR") != NULL &&
                strstr(out, "NTASM_C_") == NULL,
            "--backend mir reports the Machine IR marker and provenance, never "
            "the C ones");
      char *inspect_mir[] = {"ntasm", "inspect", mir_probe};
      CHECK(run_cli(inspect_mir, 3, out, err) == 0 &&
                strstr(out, "\"subsystem\":\"UEFI\"") != NULL,
            "the Machine IR image is a PE the inspector validates");
      char *c_probe = in_dir("flag-probe-c.efi");
      char *c_args[] = {"ntasm", "assemble", "--backend", "c",
                        g_example_source, "-o", c_probe};
      CHECK(run_cli(c_args, 7, out, err) == 0 &&
                strstr(out, "NTASM_C_ASSEMBLED") != NULL,
            "--backend c names the C reference explicitly");
      char *bad_probe = in_dir("flag-probe-bad.efi");
      char *bad_args[] = {"ntasm", "assemble", "--backend", "zzz",
                          g_example_source, "-o", bad_probe};
      CHECK(run_cli(bad_args, 7, out, err) == 2 && !file_exists(bad_probe),
            "an unknown backend is a usage error and writes no file");
      char *run_mir[] = {"ntasm", "run", "--backend", "mir", g_example_source,
                         "--expect", "42"};
      CHECK(run_cli(run_mir, 7, out, err) == 2 && strstr(err, "E605") != NULL &&
                strstr(out, "NTASM_C_RUN") == NULL,
            "run refuses --backend mir rather than run the C build under it");
      free(mir_probe);
      free(c_probe);
      free(bad_probe);
    } else if (!strcmp(w, "--root")) {
      /* The tree is taken EXACTLY: `.` is the repository root this gate runs
       * from, and the gate's own work directory holds no toolchain, so naming
       * it must be refused rather than searched upwards into the real tree. */
      char *root_probe = in_dir("flag-probe-root.efi");
      char *root_args[] = {"ntasm", "assemble", "--backend", "mir", "--root", ".",
                           g_example_source, "-o", root_probe};
      CHECK(run_cli(root_args, 9, out, err) == 0,
            "--root naming the tree builds through the Machine IR chain");
      char *wrong_probe = in_dir("flag-probe-wrong-root.efi");
      char *wrong_args[] = {"ntasm", "assemble", "--backend", "mir", "--root",
                            (char *)g_dir, g_example_source, "-o", wrong_probe};
      CHECK(run_cli(wrong_args, 9, out, err) == 1 && !file_exists(wrong_probe),
            "--root naming a directory that is not the tree is refused, and no "
            "file is written");
      free(root_probe);
      free(wrong_probe);
    } else {
      CHECK(0, "the declared flag set contains only documented flags");
    }
  }

  /* info is filled by the oracle only; entry_efi stays empty until it is, so
   * a malformed image reports an empty entry rather than uninitialised data. */
  NtPeInfo info;
  char entry_efi[16] = {0};
  if (example_staged) {
    char *check_args[] = {"ntasm", "check", g_example_source};
    CHECK(run_cli(check_args, 3, out, err) == 0,
          "check accepts the guide's worked example");
    CHECK(strstr(out, "NTASM_C_CHECK_OK") != NULL,
          "check reports the documented success marker");

    char *assemble_args[] = {"ntasm", "assemble", g_example_source, "-o",
                             g_example_efi};
    CHECK(run_cli(assemble_args, 5, out, err) == 0,
          "assemble emits a PE for the worked example");
    CHECK(strstr(out, "NTASM_C_ASSEMBLED") != NULL &&
              strstr(out, "provenance=BOOTSTRAP_EXTERNAL_C") != NULL,
          "assemble reports the documented marker and provenance");

    /* 5. The artefact is a real x86_64 EFI image, per nt_pe_inspect. */
    cases++;
    int image_ok = image_is_wellformed_uefi(g_example_efi, &info);
    CHECK(image_ok, "the emitted artefact is a well formed x86_64 EFI image");
    if (image_ok) {
      snprintf(entry_efi, sizeof(entry_efi), "%u", info.entry_rva);
      CHECK(info.section_count == 4,
            "the image carries the four expected sections");
      CHECK(info.entry_rva >= info.header_size &&
                info.entry_rva < info.image_size,
            "the entry point lies inside the image it was read from");
    }
    unsigned char head[2];
    CHECK(file_bytes(g_example_efi, head, 2) == 2 && head[0] == 'M' &&
              head[1] == 'Z',
          "the file begins with the DOS signature the loader needs");

    char *inspect_args[] = {"ntasm", "inspect", g_example_efi};
    CHECK(run_cli(inspect_args, 3, out, err) == 0,
          "inspect validates the emitted PE");
    CHECK(strstr(out, "\"format\":\"PE32+\"") != NULL &&
              strstr(out, "\"subsystem\":\"UEFI\"") != NULL,
          "inspect reports the documented format and subsystem");
    char expected_entry[64];
    snprintf(expected_entry, sizeof(expected_entry), "\"entry_rva\":%u",
             info.entry_rva);
    CHECK(!image_ok || strstr(out, expected_entry) != NULL,
          "inspect reports the same entry RVA the C oracle read from the file");

    /* 6. Byte stability, and the object route to the same image. */
    cases++;
    char *again_path = in_dir("worked-example-again.efi");
    char *again_args[] = {"ntasm", "assemble", g_example_source, "-o",
                          again_path};
    CHECK(run_cli(again_args, 5, out, err) == 0,
          "the worked example assembles a second time");
    CHECK(files_identical(g_example_efi, again_path),
          "two assemblies of one source are byte identical");

    char *object_path = in_dir("worked-example.nxo");
    char *linked_path = in_dir("worked-example-linked.efi");
    char *object_args[] = {"ntasm", "object", g_example_source, "-o",
                           object_path};
    CHECK(run_cli(object_args, 5, out, err) == 0,
          "object emits an NXO unit for the worked example");
    char *link_args[] = {"ntasm", "link", object_path, "-o", linked_path};
    CHECK(run_cli(link_args, 5, out, err) == 0,
          "link materialises the NXO unit into a PE");
    CHECK(strstr(out, "NTASM_C_LINKED") != NULL,
          "link reports the documented marker");
    CHECK(files_identical(g_example_efi, linked_path),
          "for a single module, assemble and object+link produce the same PE, "
          "as the guide says");
    free(again_path);
    free(object_path);
    free(linked_path);
  }

  /* 7. Exit codes the guide promises, each read from the guide and observed. */
  cases++;
  char *exit_block = block(doc, "text", 1, NULL);
  CHECK(exit_block != NULL, "guide carries an explicit exit code table");
  int documented_exit[8] = {0};
  if (exit_block) {
    for (const char *p = exit_block; (p = strstr(p, "exit ")) != NULL;
         p += 5) {
      if (p != exit_block && p[-1] != '\n')
        continue;
      int code = atoi(p + 5);
      if (code >= 0 && code < 8)
        documented_exit[code] = 1;
    }
    for (int code = 0; code <= 4; ++code)
      CHECK(documented_exit[code],
            "guide documents the exit code the CLI actually uses");
  }

  /* 8. Each documented code is produced by a real invocation. */
  cases++;
  {
    char *version_args[] = {"ntasm", "--version"};
    CHECK(run_cli(version_args, 2, out, err) == 0,
          "exit 0 is returned by a successful request");
    CHECK(strstr(out, "provenance=BOOTSTRAP_EXTERNAL_C") != NULL,
          "--version states the bootstrap provenance on stdout");

    char *no_args[] = {"ntasm"};
    CHECK(run_cli(no_args, 1, out, err) == 2,
          "exit 2 is returned when the command line cannot be read");
    char *unknown[] = {"ntasm", "frobnicate", g_example_source};
    CHECK(run_cli(unknown, 3, out, err) == 2,
          "an undocumented verb is a usage error");
    CHECK(err[0] != 0 && !strncmp(err, "usage:", 6) && out[0] == 0,
          "a usage error writes the usage text to stderr and nothing to stdout");

    char *broken = in_dir("broken.ntasm");
    char *broken_efi = in_dir("broken.efi");
    write_file(broken, "module broken\ntarget x86_64-nexora-uefi\nsection .text { fn");
    char *broken_args[] = {"ntasm", "assemble", broken, "-o", broken_efi};
    CHECK(run_cli(broken_args, 5, out, err) == 1,
          "exit 1 is returned when a source is rejected");
    CHECK(strstr(err, ": E") != NULL, "a rejected source names a diagnostic");
    CHECK(!file_exists(broken_efi),
          "a rejected source leaves no artefact behind");
    free(broken);
    free(broken_efi);

    char *absent = in_dir("absent.ntasm");
    char *absent_efi = in_dir("absent.efi");
    char *absent_args[] = {"ntasm", "assemble", absent, "-o", absent_efi};
    CHECK(run_cli(absent_args, 5, out, err) == 3,
          "exit 3 is returned when an input cannot be read");
    CHECK(strstr(err, "E001") != NULL, "an unreadable input reports E001");
    free(absent);
    free(absent_efi);
  }

  /* 8b. `run` -- the verb that executes the image. The source and the expected
   * value are both written HERE, so the expectation is not read back out of
   * the tool's own stdout: a verb that ignored the image and printed a
   * constant would pass a check that parsed its own answer. */
  cases++;
  {
    char *runner = in_dir("runner.ntasm");
    write_file(runner, "module probe.run_seven\ntarget x86_64-nexora-uefi\n"
                       "section .text {\n"
                       "    export fn main() -> u64\n"
                       "    effects {}\n"
                       "    clobbers {rax} {\n"
                       "        return 7;\n"
                       "    }\n"
                       "}\n");
    char *right[] = {"ntasm", "run", runner, "--expect", "7"};
    CHECK(run_cli(right, 5, out, err) == 0,
          "exit 0 is returned when the executed image returns the value "
          "--expect named");
    CHECK(strstr(out, "NTASM_C_RUN") != NULL,
          "run reports the documented marker");

    /* The negative control. Same image, one more than it returns: 4, not 0.
     * Zero is what a verb that executed nothing also returns, so the value
     * has to be able to move the code. */
    char *wrong[] = {"ntasm", "run", runner, "--expect", "8"};
    CHECK(run_cli(wrong, 5, out, err) == 4,
          "exit 4 is returned when the image built, ran and returned "
          "something else");
    CHECK(strstr(out, "result=7") != NULL,
          "the result line names what the image returned, not what was "
          "expected");

    /* And the other side of the same verb: a build that refuses is 1, never 4.
     * 1 and 4 are different codes for different events, and this is the case
     * that would stop being true if the two were collapsed. */
    char *unbuildable = in_dir("unbuildable.ntasm");
    write_file(unbuildable, "module probe.unbuildable\n"
                            "target x86_64-nexora-uefi\nsection .text { fn");
    char *refused[] = {"ntasm", "run", unbuildable, "--expect", "7"};
    CHECK(run_cli(refused, 5, out, err) == 1,
          "exit 1 is returned when run would not build, and it is not the code "
          "for a wrong result");
    CHECK(!strstr(out, "NTASM_C_RUN"),
          "a run that refused to build prints no result line, so it cannot be "
          "confused with one that ran");

    char *no_expect[] = {"ntasm", "run", runner};
    CHECK(run_cli(no_expect, 3, out, err) == 2,
          "run without --expect is a usage error, not a silent success");
    free(runner);
    free(unbuildable);
  }

  /* 9. The refusals the guide lists, each observed. */
  cases++;
  if (example_staged) {
    char *twice_path = in_dir("twice.efi");
    char *twice_args[] = {"ntasm", "assemble", g_example_source, "-o",
                          twice_path};
    CHECK(run_cli(twice_args, 5, out, err) == 0,
          "first assembly into a fresh path succeeds");
    unsigned char before[65536], after[65536];
    size_t before_len = file_bytes(twice_path, before, sizeof(before));
    CHECK(run_cli(twice_args, 5, out, err) == 3,
          "an existing output is refused with exit 3");
    CHECK(strstr(err, "E700") != NULL, "the refusal names E700");
    size_t after_len = file_bytes(twice_path, after, sizeof(after));
    CHECK(before_len && before_len == after_len &&
              !memcmp(before, after, before_len),
          "the refused output keeps its previous bytes");
    free(twice_path);

    /* The guide's positional rule for -o is a real constraint. */
    char *misplaced_out = in_dir("misplaced.efi");
    char *misplaced[] = {"ntasm", "assemble", "-o", misplaced_out,
                         g_example_source};
    CHECK(run_cli(misplaced, 5, out, err) == 2,
          "-o before the source is a usage error, as the guide says");
    CHECK(!file_exists(misplaced_out), "a usage error writes no file");
    free(misplaced_out);

    char *two_inspect[] = {"ntasm", "inspect", g_example_efi, g_example_efi};
    CHECK(run_cli(two_inspect, 4, out, err) == 2,
          "inspect takes exactly one input, as the guide says");
    char *inspect_source[] = {"ntasm", "inspect", g_example_source};
    CHECK(run_cli(inspect_source, 3, out, err) == 1,
          "inspect refuses a source file presented as an image");
  }

  /* 10. Every complete example the guide lists must assemble and inspect,
   *     and hash to the digest the guide records. */
  cases++;
  char *table = block(doc, "text", 3, NULL);
  CHECK(table != NULL, "guide carries the table of shipped examples");
  ExampleTable examples;
  memset(&examples, 0, sizeof(examples));
  if (table && examples_from_block(table, &examples)) {
    CHECK(examples_closed(&examples, EXAMPLE_DIR),
          "guide corpus equals directory minus the named experiment");
    if(examples.count==7) examples_closure_controls(&examples);
    for (size_t i = 0; i < examples.count; ++i) {
      char name[512];
      snprintf(name, sizeof(name), "%s/%s.ntasm", EXAMPLE_DIR, examples.id[i]);
      char *efi = in_dir("example.efi");
      unlink(efi);
      char *check_args[] = {"ntasm", "check", (char *)name};
      int check_rc = run_cli(check_args, 3, out, err);
      char *asm_args[] = {"ntasm", "assemble", (char *)name, "-o", efi};
      int asm_rc = run_cli(asm_args, 5, out, err);
      char *insp_args[] = {"ntasm", "inspect", efi};
      int insp_rc = run_cli(insp_args, 3, out, err);
      CHECK(check_rc == 0 && asm_rc == 0 && insp_rc == 0,
            "a complete example named by the guide passes check, assemble and "
            "inspect");
      char digest[65] = {0};
      CHECK(sha256_file(efi, digest) &&
                !strcmp(digest, examples.hash[i]),
            "a complete example hashes to the sha256 the guide records");
      free(efi);
    }
  } else {
    CHECK(0, "guide's example table parses into id and sha256 pairs");
  }

  /* 11. The guide's own worked example digest is a promise about the bytes. */
  cases++;
  char *digest_block = block(doc, "text", 2, NULL);
  CHECK(digest_block != NULL, "guide records the worked example digest");
  if (digest_block && example_staged) {
    char fresh[65] = {0};
    CHECK(sha256_file(g_example_efi, fresh),
          "worked example artefact is readable for hashing");
    CHECK(fresh[0] && strstr(digest_block, fresh) != NULL,
          "the worked example reproduces the sha256 the guide records");
  }

  free_examples(&examples);
  free(table);
  free(digest_block);
  free(exit_block);
  free(documented_example);
  free(documented_usage);
  free_tokens(&declared);
  free_tokens(&flags);
  free(g_example_source);
  free(g_example_efi);
  /* g_dir points at the header's static buffer, not at the heap: it is not
   * freed here, and the work directory is deliberately LEFT IN PLACE for the
   * run that produced it, which is where a failing case is inspected. The path
   * it lives under is no longer /tmp -- main prints it as RUN_DIR, and under
   * NG_BUILD it is inside the driver's own per-run directory. */
  free(doc);

  printf("NTASM_NOVA_CLI checks=%u failures=%u cases=%u entry_rva=%s\n", checks,
         failures, cases, entry_efi);
  return failures ? 1 : 0;
}
