#define _POSIX_C_SOURCE 200809L
#include "machine_driver.h"
#include "../frontend/nova.h"
#include "../runtime/run_host.h"
#include "../runtime/runtime_v2.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <direct.h>
#include <windows.h>
#else
#include <unistd.h>
#endif

/* ---------------------------------------------------------------------------
 * THE C DRIVER. See machine_driver.h for what this is and is not. What follows
 * is the machinery: find the root, load two closures, compile them, map them,
 * check what each module says about itself, and call them.
 *
 * TWO IMAGES, MEASURED. One image holding both faces does not fit: the closure
 * of `machine_pipeline` AND `ntasm_nxo_link_pe` is fifty-one modules and
 * `nova_compile_many_v2` emits 17071326 bytes of .text for it, while
 * `nova/run_host.c` refuses to map anything above 16777216. The symptom was a
 * driver that refused to OPEN, which says nothing about the producer. So the
 * pipeline image is forty-nine modules (16296367 bytes) and the link image is
 * six (1373533), and each has its own entry under toolchain/ntasm-nova.
 *
 * THE MODULE LISTS ARE THE IMPORT CLOSURES OF THE TWO ENTRIES, written out
 * rather than discovered, for the reason every other module list in this tree is
 * written out: a closure computed at run time would make a missing module look
 * like a source that compiles to less, and a toolchain that quietly got smaller
 * is the one failure nobody notices. A missing entry here is a refusal at load,
 * named by path, not a silent drop.
 *
 * THE ORDER IS DETERMINISTIC AND MEANINGLESS. `nova_compile_many_v2` resolves
 * imports across the whole set, so the order changes the compiler's internal
 * counters and nothing else. Sorted after the entry, so a diff of a list is a
 * diff of the closure and not of an edit that only moved a line.
 * ------------------------------------------------------------------------- */
static const char *const PIPELINE_MODULES[] = {
    "compiler/nova/drivers/machine-driver-entry.nova",
    "compiler/nova/analysis/abi/abi.nova",
    "compiler/nova/frontend/ast.nova",
    "compiler/nova/frontend/bindings.nova",
    "compiler/nova/analysis/abi/body_clobbers.nova",
    "compiler/nova/analysis/abi/body_effects.nova",
    "compiler/nova/analysis/abi/body_intrinsics.nova",
    "compiler/nova/analysis/calls/call_clobbers.nova",
    "compiler/nova/analysis/calls/call_contracts.nova",
    "compiler/nova/analysis/calls/call_effects.nova",
    "compiler/nova/analysis/calls/call_types.nova",
    "compiler/nova/analysis/calls/callable_names.nova",
    "compiler/nova/analysis/calls/calls.nova",
    "compiler/nova/analysis/abi/clobbers.nova",
    "compiler/nova/analysis/types/condition_types.nova",
    "compiler/nova/macros/constant_eval.nova",
    "compiler/nova/analysis/types/constant_types.nova",
    "compiler/nova/analysis/abi/contracts.nova",
    "compiler/nova/analysis/control_flow.nova",
    "compiler/nova/analysis/abi/effects.nova",
    "compiler/nova/analysis/abi/feature_requirements.nova",
    "compiler/nova/analysis/abi/features.nova",
    "compiler/nova/analysis/types/initializer_types.nova",
    "compiler/nova/frontend/lexer.nova",
    "compiler/nova/analysis/types/literal_initializers.nova",
    "compiler/nova/frontend/locals.nova",
    "compiler/nova/ir/machine_ir.nova",
    "compiler/nova/ir/machine_pipeline.nova",
    "compiler/nova/backend/nova/machine_emit.nova",
    "compiler/nova/macros/macro_expand.nova",
    "compiler/nova/macros/macro_splice.nova",
    "compiler/nova/formats/ntir/ntir.nova",
    "compiler/nova/formats/nxo/nxo.nova",
    "compiler/nova/formats/nxo/nxo_pe.nova",
    "compiler/nova/frontend/parameters.nova",
    "compiler/nova/frontend/parser.nova",
    "compiler/nova/formats/pe/pe.nova",
    "compiler/nova/analysis/types/pointer_spaces.nova",
    "compiler/nova/frontend/refs.nova",
    "compiler/nova/frontend/register_bindings.nova",
    "compiler/nova/analysis/types/register_widths.nova",
    "compiler/nova/analysis/types/return_types.nova",
    "compiler/nova/analysis/semantics.nova",
    "compiler/nova/frontend/stub_table.nova",
    "compiler/nova/frontend/symbol_names.nova",
    "compiler/nova/frontend/targets.nova",
    "compiler/nova/analysis/types/types.nova",
    "compiler/nova/analysis/validate.nova",
    "compiler/nova/frontend/versions.nova",
    "compiler/nova/backend/x64/x64_fixed.nova",
};
#define PIPELINE_N ((size_t)(sizeof PIPELINE_MODULES / sizeof PIPELINE_MODULES[0]))

static const char *const LINK_MODULES[] = {
    "compiler/nova/drivers/machine-link-entry.nova",
    "compiler/nova/formats/nxo/nxo.nova",
    "compiler/nova/formats/nxo/nxo_link_pe.nova",
    "compiler/nova/formats/nxo/nxo_merge.nova",
    "compiler/nova/formats/nxo/nxo_pe.nova",
    "compiler/nova/formats/pe/pe.nova",
};
#define LINK_N ((size_t)(sizeof LINK_MODULES / sizeof LINK_MODULES[0]))

/* The report is a buffer this driver lends and its WIDTH comes from the modules
 * (mode 0). 64 is a generous multiple of both widths they declare; a generous
 * buffer is not a second guess about the layout, because every index the driver
 * reads is the module's own. */
#define REPORT_WORDS 64

/* The pipeline's ten stages, as `stage[]` indices in the pipeline's own order.
 * Only the first eight arrive in the mode 0 vocabulary; 8 and 9 are asked for on
 * their own because report[8] and report[9] are where a refusal writes. */
enum { MG_STAGE_PARSE = 0,  MG_STAGE_EXPAND,    MG_STAGE_VALIDATE,
       MG_STAGE_NTIR,      MG_STAGE_LOWER,      MG_STAGE_VERIFY,
       MG_STAGE_OBJECT,    MG_STAGE_READ,       MG_STAGE_LINK,
       MG_STAGE_DELIVER };

struct NtMachineImage {
  NtArtifact artifact;
  NovaHostImage image;
  /* The link image is opened on the first multi-module request and kept, so a
   * second link costs no compilation. `link_tried` records an attempt that
   * FAILED as well as one that succeeded: without it a failed open would be
   * retried on every call and every retry would recompile six modules. */
  NtArtifact link_artifact;
  NovaHostImage link_image;
  int link_tried;
  /* Why the link image refused to open, kept because `nt_machine_link` has no
   * diagnostic parameter of its own and the caller must still be able to print
   * the reason instead of a class. */
  NtDiagnostic link_error;
  char root[1024];
  uint64_t report_words;
  uint64_t want_object, want_pe, want_link;
  uint64_t e_output, e_bound;
  uint64_t stage[10];
};

static void say(NtDiagnostic *error, unsigned code, const char *text) {
  if (!error)
    return;
  memset(error, 0, sizeof *error);
  error->code = code;
  snprintf(error->message, sizeof error->message, "%s", text);
}

static int readable(const char *path) {
  FILE *f = fopen(path, "rb");
  if (!f)
    return 0;
  fclose(f);
  return 1;
}

/* A DIRECTORY IS A ROOT WHEN IT HOLDS BOTH MARKERS. One marker is a guess, and
 * the reason is worth keeping in the code: a path that only proves the marker it
 * happens to contain is a statement about the filesystem and not about this
 * product. */
static int is_root(const char *dir) {
  char path[2048];
  snprintf(path, sizeof path, "%s/%s", dir, NG_MACHINE_MARKER_ENTRY);
  if (!readable(path))
    return 0;
  snprintf(path, sizeof path, "%s/%s", dir, NG_MACHINE_MARKER_HOST);
  return readable(path);
}

/* The parent of a directory, or 0 at a filesystem root. Both separators, because
 * a root found on Windows and a root found under WSL are both roots and this
 * tool is built for both. Returning 0 rather than the same directory is what
 * stops the upward search from spending its remaining levels on "/". */
static int parent_of(const char *dir, char *out, size_t room) {
  size_t n = strlen(dir);
  while (n > 0 && (dir[n - 1] == '/' || dir[n - 1] == '\\'))
    n--;
  size_t cut = n;
  while (cut > 0 && dir[cut - 1] != '/' && dir[cut - 1] != '\\')
    cut--;
  while (cut > 1 && (dir[cut - 1] == '/' || dir[cut - 1] == '\\'))
    cut--;
  /* "/", "C:" and "C:/" are the three places with no parent. */
  if (cut == 0 || cut == 1 || (cut == 2 && dir[1] == ':'))
    return 0;
  if (cut + 1 > room)
    return 0;
  memcpy(out, dir, cut);
  out[cut] = '\0';
  return 1;
}

static int search_upwards(const char *start, char *out, size_t room) {
  char walk[2048];
  if (strlen(start) + 1 > sizeof walk)
    return 0;
  snprintf(walk, sizeof walk, "%s", start);
  for (int level = 0; level < NG_MACHINE_ROOT_WALK; ++level) {
    if (is_root(walk)) {
      if (strlen(walk) + 1 > room)
        return 0;
      snprintf(out, room, "%s", walk);
      return 1;
    }
    if (!parent_of(walk, walk, sizeof walk))
      return 0;
  }
  return 0;
}

static int executable_directory(char *out, size_t room) {
  char path[2048];
#ifdef _WIN32
  DWORD n = GetModuleFileNameA(NULL, path, (DWORD)sizeof path);
  if (!n || n >= sizeof path)
    return 0;
#else
  ssize_t n = readlink("/proc/self/exe", path, sizeof path - 1);
  if (n <= 0)
    return 0;
  path[n] = '\0';
#endif
  size_t len = strlen(path);
  while (len > 0 && path[len - 1] != '/' && path[len - 1] != '\\')
    len--;
  if (!len || len + 1 > room)
    return 0;
  memcpy(out, path, len);
  out[len] = '\0';
  return 1;
}

int nt_machine_root(const char *requested, char *out, size_t room,
                    NtDiagnostic *error) {
  if (room < 1024) {
    say(error, 4, "root buffer is smaller than the 1024 bytes this API needs");
    return 0;
  }
  /* THE CALLER'S OWN ANSWER IS TAKEN EXACTLY. No walking upwards here, and that
   * is the whole point: a `--root` that does not name a root must be refused,
   * because a wrong root silently replaced by an ancestor is a tool that ran
   * somewhere else and said nothing. */
  if (requested && requested[0]) {
    if (!is_root(requested)) {
      char detail[192];
      snprintf(detail, sizeof detail, "%s holds no %s", requested,
               NG_MACHINE_MARKER_ENTRY);
      say(error, 4, detail);
      return 0;
    }
    snprintf(out, room, "%s", requested);
    return 1;
  }
  /* The environment is the same contract as the flag: exact, or refused. */
  const char *env = getenv("NTASM_ROOT");
  if (env && env[0]) {
    if (!is_root(env)) {
      char detail[192];
      snprintf(detail, sizeof detail, "NTASM_ROOT=%s holds no %s", env,
               NG_MACHINE_MARKER_ENTRY);
      say(error, 4, detail);
      return 0;
    }
    snprintf(out, room, "%s", env);
    return 1;
  }
  char start[2048];
  if (executable_directory(start, sizeof start) &&
      search_upwards(start, out, room))
    return 1;
  if (getcwd(start, sizeof start) && search_upwards(start, out, room))
    return 1;
  char detail[192];
  snprintf(detail, sizeof detail,
           "no %s found from the executable or the working directory",
           NG_MACHINE_MARKER_ENTRY);
  say(error, 4, detail);
  return 0;
}

/* A file, whole, or nothing. The Nova compiler wants a NUL-terminated text and
 * a length; both come from one read, and a file that changed under the read is
 * refused rather than half-loaded. */
static char *load_file(const char *path, size_t *length) {
  FILE *f = fopen(path, "rb");
  if (!f)
    return NULL;
  if (fseek(f, 0, SEEK_END) != 0) {
    fclose(f);
    return NULL;
  }
  long n = ftell(f);
  if (n < 0 || fseek(f, 0, SEEK_SET) != 0) {
    fclose(f);
    return NULL;
  }
  char *text = malloc((size_t)n + 1);
  if (!text) {
    fclose(f);
    return NULL;
  }
  size_t got = fread(text, 1, (size_t)n, f);
  int extra = fgetc(f), failed = ferror(f), closed = fclose(f);
  if (got != (size_t)n || extra != EOF || failed || closed) {
    free(text);
    return NULL;
  }
  text[got] = '\0';
  *length = got;
  return text;
}

/* Load, compile, map. Both images go through this one function, and the two
 * lists differ only in what they name. */
static int build_image(const char *root, const char *const *modules, size_t count,
                       const char *what, NtArtifact *artifact,
                       NovaHostImage *image, NtDiagnostic *error) {
  static NtFInput inputs[64];
  static char paths[64][2048];
  char *texts[64];
  size_t loaded = 0;
  if (count > 64) {
    say(error, 5, "module list is larger than this driver holds");
    return 0;
  }
  for (size_t i = 0; i < count; ++i) {
    snprintf(paths[i], sizeof paths[i], "%s/%s", root, modules[i]);
    size_t length = 0;
    char *text = load_file(paths[i], &length);
    if (!text) {
      char detail[256];
      snprintf(detail, sizeof detail, "%.60s could not be read under %.100s",
               modules[i], root);
      say(error, 5, detail);
      for (size_t k = 0; k < loaded; ++k)
        free(texts[k]);
      return 0;
    }
    texts[loaded] = text;
    /* The name handed to the compiler is the FULL path, so a Nova diagnostic
     * names the file the reader can open and not a relative path that depends
     * on where the tool happened to be started. */
    inputs[loaded] = (NtFInput){paths[i], text, length};
    loaded++;
  }
  int compiled = nova_compile_many_v2(inputs, loaded, artifact);
  for (size_t i = 0; i < loaded; ++i)
    free(texts[i]);
  if (!compiled) {
    /* The compile refusal is the producer's own diagnostic and is carried
     * through unchanged: renaming it here would make this driver the only
     * thing in the tree whose codes mean something else. */
    if (error) {
      NtDiagnostic *e = &artifact->error;
      memset(error, 0, sizeof *error);
      error->code = e->code;
      error->offset = e->offset;
      error->line = e->line;
      error->column = e->column;
      error->source_index = e->source_index;
      snprintf(error->message, sizeof error->message, "%s", e->message);
      size_t at = strlen(error->message);
      if (e->source_index >= 1 && e->source_index <= count)
        snprintf(error->message + at, sizeof error->message - at, " in %s",
                 paths[e->source_index - 1]);
    }
    nt_artifact_free(artifact);
    return 0;
  }
  if (!nova_host_map(artifact, image)) {
    /* WHY IT DID NOT MAP, in the four numbers the mapper itself tests. The
     * refusal used to say only "could not be mapped", which is a fact about
     * this driver and not about the image; these four are the image's. */
    char detail[192];
    snprintf(detail, sizeof detail,
             "the %s image could not be mapped: text=%zu entry=%zu rdata=%zu "
             "data=%zu (the mapper refuses above 16 MiB)",
             what, artifact->text.size, artifact->entry, artifact->rdata.size,
             artifact->data.size);
    say(error, 6, detail);
    nt_artifact_free(artifact);
    return 0;
  }
  return 1;
}

/* ONE CALL, ONE SET OF PAGES, and the vocabulary comes back through the same
 * entry every image comes back through. A disagreement between the two mode
 * numbers is a refusal to open rather than a warning: a caller that believed
 * the wrong face selected would read report[8] as a stage it is not.
 *
 * The calls here are cheap -- nothing is compiled inside them -- and they exist
 * so that the numbers this driver writes into its own API are the MODULE's
 * numbers and not a second copy of them. */
static int ask(const NovaHostImage *image, uint64_t want, uint64_t *report,
               uint64_t length_words, NtDiagnostic *error, const char *what) {
  uint64_t length[2] = {0, 0};
  unsigned char scratch[64];
  memset(scratch, 0, sizeof scratch);
  memset(report, 0, REPORT_WORDS * sizeof(uint64_t));
  NovaContextV2 c = {0};
  if (!nova_context_init_v2(&c)) {
    say(error, 6, "the host could not open a Nova execution context");
    return 0;
  }
  uint64_t sh = nova_borrow_v2(&c, scratch, sizeof scratch, 0);
  uint64_t oh = nova_borrow_v2(&c, scratch, sizeof scratch, 1);
  uint64_t lh = nova_borrow_v2(&c, length, sizeof length, 1);
  uint64_t rh = nova_borrow_v2(&c, report, REPORT_WORDS * sizeof(uint64_t), 1);
  uint64_t args[] = {sh, sizeof scratch, want, 0, oh, sizeof scratch,
                     lh, 2,          rh,   REPORT_WORDS};
  image->entry(&c, args, 10);
  /* Read the context BEFORE it is destroyed: the fault's own coordinates are
   * the only place they exist. */
  uint64_t fault = c.error, source = c.error_source, offset = c.error_offset;
  (void)length_words;
  nova_context_destroy_v2(&c);
  if (fault) {
    char detail[192];
    snprintf(detail, sizeof detail,
             "the %s producer faulted in the host publishing its vocabulary "
             "(error=%llu source=%llu offset=%llu)",
             what, (unsigned long long)fault, (unsigned long long)source,
             (unsigned long long)offset);
    say(error, 6, detail);
    return 0;
  }
  return 1;
}

/* The pipeline image's vocabulary, which is also where the LINK stage and the
 * DELIVERY stage come from: the report has no room for them. */
static int learn(NtMachineImage *image, NtDiagnostic *error) {
  uint64_t report[REPORT_WORDS];
  if (!ask(&image->image, NG_MACHINE_VOCABULARY, report, REPORT_WORDS, error,
           "pipeline"))
    return 0;
  image->report_words = report[3];
  image->want_object = report[0];
  image->want_pe = report[1];
  image->want_link = report[2];
  image->e_output = report[4];
  image->e_bound = report[5];
  image->stage[MG_STAGE_PARSE] = report[6];
  image->stage[MG_STAGE_EXPAND] = report[7];
  image->stage[MG_STAGE_VALIDATE] = report[8];
  image->stage[MG_STAGE_NTIR] = report[9];
  image->stage[MG_STAGE_LOWER] = report[10];
  image->stage[MG_STAGE_OBJECT] = report[11];
  image->stage[MG_STAGE_READ] = report[12];
  image->stage[MG_STAGE_VERIFY] = report[13];
  if (image->want_object != NG_MACHINE_OBJECT ||
      image->want_pe != NG_MACHINE_PE || image->want_link != NG_MACHINE_LINK) {
    char detail[192];
    snprintf(detail, sizeof detail,
             "the module publishes modes object=%llu pe=%llu link=%llu and the "
             "header says %d/%d/%d",
             (unsigned long long)image->want_object,
             (unsigned long long)image->want_pe,
             (unsigned long long)image->want_link, NG_MACHINE_OBJECT,
             NG_MACHINE_PE, NG_MACHINE_LINK);
    say(error, 7, detail);
    return 0;
  }
  if (image->report_words == 0 || image->report_words > REPORT_WORDS) {
    char detail[160];
    snprintf(detail, sizeof detail,
             "the module asks for a %llu word report and this driver lends %d",
             (unsigned long long)image->report_words, REPORT_WORDS);
    say(error, 7, detail);
    return 0;
  }
  if (!ask(&image->image, NG_MACHINE_STAGES, report, REPORT_WORDS, error,
           "pipeline"))
    return 0;
  image->stage[MG_STAGE_LINK] = report[0];
  image->stage[MG_STAGE_DELIVER] = report[1];
  return 1;
}

/* THE LINK ENTRY'S TWO LITERALS ARE CHECKED AGAINST THE PIPELINE'S. The link
 * entry cannot import `machine_pipeline` -- that is the reason it is a separate
 * file -- so it writes the delivery code and the link stage as words. They are
 * published rather than trusted: this is the check, and it runs once, at the
 * first link. */
static int learn_link(NtMachineImage *image, NtDiagnostic *error) {
  uint64_t report[REPORT_WORDS];
  if (!ask(&image->link_image, NG_MACHINE_VOCABULARY, report, REPORT_WORDS,
           error, "link"))
    return 0;
  if (report[0] != image->want_link) {
    char detail[160];
    snprintf(detail, sizeof detail,
             "the link entry publishes mode %llu and the pipeline entry "
             "publishes %llu",
             (unsigned long long)report[0],
             (unsigned long long)image->want_link);
    say(error, 7, detail);
    return 0;
  }
  if (report[2] != image->e_output || report[3] != image->stage[MG_STAGE_LINK]) {
    char detail[192];
    snprintf(detail, sizeof detail,
             "the link entry publishes delivery=%llu stage=%llu and the pipeline "
             "publishes delivery=%llu stage=%llu",
             (unsigned long long)report[2], (unsigned long long)report[3],
             (unsigned long long)image->e_output,
             (unsigned long long)image->stage[MG_STAGE_LINK]);
    say(error, 7, detail);
    return 0;
  }
  if (report[1] == 0 || report[1] > REPORT_WORDS) {
    char detail[160];
    snprintf(detail, sizeof detail,
             "the link entry asks for a %llu word report and this driver lends "
             "%d",
             (unsigned long long)report[1], REPORT_WORDS);
    say(error, 7, detail);
    return 0;
  }
  return 1;
}

NtMachineImage *nt_machine_open(const char *requested, NtDiagnostic *error) {
  NtMachineImage *image = calloc(1, sizeof *image);
  if (!image) {
    say(error, 3, "allocation failed");
    return NULL;
  }
  if (!nt_machine_root(requested, image->root, sizeof image->root, error)) {
    free(image);
    return NULL;
  }
  if (!build_image(image->root, PIPELINE_MODULES, PIPELINE_N, "pipeline",
                   &image->artifact, &image->image, error)) {
    free(image);
    return NULL;
  }
  if (!learn(image, error)) {
    nova_host_unmap(&image->image);
    nt_artifact_free(&image->artifact);
    free(image);
    return NULL;
  }
  return image;
}

void nt_machine_close(NtMachineImage *image) {
  if (!image)
    return;
  if (image->link_tried) {
    nova_host_unmap(&image->link_image);
    nt_artifact_free(&image->link_artifact);
  }
  nova_host_unmap(&image->image);
  nt_artifact_free(&image->artifact);
  free(image);
}

/* WHY THE LINK IMAGE REFUSED TO OPEN. `nt_machine_link` reports the CLASS on
 * the NtMachineReport -- 6 for a host fault and 7 for a vocabulary mismatch --
 * and this returns the sentence. The two are separate on purpose: a class a
 * caller can only print is a fact about this driver, and the sentence names the
 * file that could not be read. Valid until `nt_machine_close`. */
const NtDiagnostic *nt_machine_link_error(const NtMachineImage *image) {
  return image ? &image->link_error : 0;
}

/* ONE CALL TO A MODULE, and every way it can come back is a refusal. The three
 * facts read here are kept apart on purpose:
 *
 *   ctx.error  the HOST faulted. The module's own answer stays published beside
 *              it, because merging "the module refused" with "the runtime
 *              faulted" into one number produces a verdict-looking value that is
 *              neither.
 *   returned   what the module said.
 *   length     what the module actually wrote.
 *
 * and returned 0 WITH length 0 is a refusal of its own: a success with no image
 * is the shape a silent fallback looks like from the outside, and this driver
 * has no fallback.
 *
 * `code` is whatever MODULE fired and `runtime` is the host's own class; the two
 * are never merged, which is why an allocation failure below reports a runtime
 * class and not a stage code. */
static int invoke(const NovaHostImage *image, const uint8_t *input,
                  size_t input_size, uint64_t want, uint64_t count,
                  uint8_t *out, size_t out_size, uint64_t *length,
                  NtMachineReport *report) {
  uint64_t words[REPORT_WORDS];
  memset(words, 0, sizeof words);
  memset(report, 0, sizeof *report);
  *length = 0;
  NovaContextV2 c = {0};
  if (!nova_context_init_v2(&c)) {
    report->runtime = 6;
    return 0;
  }
  uint64_t ih = nova_borrow_v2(&c, (void *)input, input_size, 0);
  uint64_t oh = nova_borrow_v2(&c, out, out_size, 1);
  uint64_t lh = nova_borrow_v2(&c, length, sizeof *length, 1);
  uint64_t rh = nova_borrow_v2(&c, words, sizeof words, 1);
  uint64_t args[] = {ih, input_size, want, count, oh, out_size,
                     lh, 1,          rh,   REPORT_WORDS};
  report->returned = image->entry(&c, args, 10);
  report->runtime = c.error;
  report->runtime_source = c.error_source;
  report->runtime_offset = c.error_offset;
  nova_context_destroy_v2(&c);
  report->stage = words[8];
  report->code = words[9];
  if (report->runtime) {
    /* A host fault outranks every reading of the report: the module's numbers
     * may be untouched garbage, and publishing them would name a stage that
     * never refused anything. */
    report->stage = 0;
    report->code = 0;
    return 0;
  }
  if (report->returned == 0 && *length == 0)
    return 0;
  report->object_size = words[5];
  report->pe_size = words[6];
  report->symbols = words[7];
  report->entry = words[10];
  report->text_size = words[12];
  return 1;
}

static int deliver(const uint8_t *bytes, uint64_t written, NtBuffer *out,
                   NtMachineReport *report) {
  if (!written || written > NG_MACHINE_OUTPUT_BYTES)
    return 0;
  out->bytes = malloc((size_t)written);
  if (!out->bytes) {
    report->runtime = 3;
    return 0;
  }
  memcpy(out->bytes, bytes, (size_t)written);
  out->size = out->capacity = (size_t)written;
  return 1;
}

static int publish(NtMachineImage *image, const char *source, size_t length,
                   uint64_t want, NtBuffer *out, NtMachineReport *report) {
  uint8_t *bytes = malloc(NG_MACHINE_OUTPUT_BYTES);
  if (!bytes) {
    report->runtime = 3;
    return 0;
  }
  uint64_t written = 0;
  int ok = invoke(&image->image, (const uint8_t *)source, length, want, 0,
                  bytes, NG_MACHINE_OUTPUT_BYTES, &written, report);
  ok = ok && deliver(bytes, written, out, report);
  free(bytes);
  return ok;
}

int nt_machine_object(NtMachineImage *image, const char *source, size_t length,
                      NtBuffer *out, NtMachineReport *report) {
  memset(out, 0, sizeof *out);
  return publish(image, source, length, image->want_object, out, report);
}

int nt_machine_pe(NtMachineImage *image, const char *source, size_t length,
                  NtBuffer *out, NtMachineReport *report) {
  memset(out, 0, sizeof *out);
  return publish(image, source, length, image->want_pe, out, report);
}

/* THE ARENA, built here and nowhere else. `link_pe_list` reads `count` 16-byte
 * (offset,length) descriptors followed by the payloads, and that arithmetic is
 * the one tests_ntasm_nxo_link_pe_list.c writes by hand; this is that function
 * over containers this driver produced. The objects are COPIED into the arena
 * rather than described in place, so the linker cannot reach back into the
 * caller's buffers and so one descriptor cannot name a byte of a second object. */
int nt_machine_link(NtMachineImage *image, const NtBuffer *objects, size_t count,
                    NtBuffer *out, NtMachineReport *report) {
  memset(out, 0, sizeof *out);
  memset(report, 0, sizeof *report);
  if (!count || count > 64) {
    report->stage = image->stage[MG_STAGE_LINK];
    report->code = 800;
    return 0;
  }
  if (!image->link_tried) {
    image->link_tried = 1;
    if (!build_image(image->root, LINK_MODULES, LINK_N, "link",
                     &image->link_artifact, &image->link_image,
                     &image->link_error)) {
      report->runtime = 6;
      return 0;
    }
    if (!learn_link(image, &image->link_error)) {
      report->runtime = 7;
      return 0;
    }
  }
  size_t total = count * 16;
  for (size_t i = 0; i < count; ++i) {
    if (!objects[i].bytes || !objects[i].size) {
      report->stage = image->stage[MG_STAGE_LINK];
      report->code = 800;
      return 0;
    }
    total += objects[i].size;
  }
  uint8_t *arena = calloc(total, 1);
  uint8_t *bytes = malloc(NG_MACHINE_OUTPUT_BYTES);
  if (!arena || !bytes) {
    free(arena);
    free(bytes);
    report->runtime = 3;
    return 0;
  }
  size_t at = count * 16;
  for (size_t i = 0; i < count; ++i) {
    uint64_t record[2] = {(uint64_t)at, (uint64_t)objects[i].size};
    memcpy(arena + i * 16, record, 16);
    memcpy(arena + at, objects[i].bytes, objects[i].size);
    at += objects[i].size;
  }
  uint64_t written = 0;
  int ok = invoke(&image->link_image, arena, total, image->want_link, count,
                  bytes, NG_MACHINE_OUTPUT_BYTES, &written, report);
  ok = ok && deliver(bytes, written, out, report);
  free(arena);
  free(bytes);
  return ok;
}