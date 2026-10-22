/* _POSIX_C_SOURCE is declared before ANY header, including the first project
 * one, because it selects declarations and not code: this file needs fileno,
 * fsync, link and getpid, none of which -std=c11 exposes by itself. The value
 * is the one tests_ntasm_cli.c declares before it #includes this file, so the
 * gate and the product see the same declarations; redefining it to the same
 * token sequence is a no-op, not a conflict. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include "cli.h"
#include "../frontend/ntasm.h"
#include "../formats/object.h"
#include "../formats/pe.h"
#include "../../nova/runtime/run_host.h"
#include "../../nova/backend/machine_driver.h"
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Build the name of this process's own temporary for PATH. It is PATH plus a
 * suffix, never a directory and never TMPDIR: see write_output's comment for
 * why that is the same-filesystem argument and not a stylistic choice. The
 * pid and the attempt counter are in the name so two writers of the same PATH
 * cannot pick the same one, and the caller opens it "wbx" anyway, so a
 * collision fails instead of overwriting somebody else's bytes. */
static void temporary_name(char *out, size_t room, const char *path,
                           unsigned attempt) {
  snprintf(out, room, "%s.ntasm-tmp-%lu-%u", path, (unsigned long)getpid(),
           attempt);
}

/* Where an output file comes from, and why it is not the path itself.
 *
 * This used to be fopen(path, "wbx") and a stream into it. That is a direct
 * write to the destination: the first byte that lands destroys whatever was
 * there, and a write that fails half way leaves a half file AT THE OUTPUT
 * PATH. Measured on this tree with a real short write (RLIMIT_FSIZE set
 * below the image's size, SIGXFSZ ignored so the write returns instead of
 * killing the process): the writer refused, printed E701 and exited 3, and
 * the destination still existed, holding a prefix of an image that had never
 * been finished. The refusal was right; what it left behind was not, because
 * a truncated file is indistinguishable from a delivered artefact until
 * something reads it.
 *
 * So the bytes go to a temporary and the destination name is claimed only
 * once the whole image is on disk:
 *
 *   <dest>.ntasm-tmp-<pid>-<n>   written, flushed, fsync'd, closed
 *   link(<temp>, <dest>)         the destination appears, complete
 *   remove(<temp>)               only this process's own temporary goes
 *
 * WHY link() AND NOT rename(). rename() REPLACES an existing destination.
 * This tool refuses to overwrite one -- E700, exit 3, the previous bytes left
 * alone -- and rename() would break that refusal to make publishing
 * convenient, which is the one thing the change must not do. link() cannot
 * replace: it fails EEXIST and touches nothing, and it does so atomically, so
 * two writers racing for one destination still leave exactly one winner and
 * one refusal. The sibling writer nova/cli.c's publish() already makes this
 * choice for the same reason.
 *
 * THE TEMPORARY IS IN THE DESTINATION'S OWN DIRECTORY, and that is the whole
 * same-filesystem argument. Its name is the destination's name plus a suffix,
 * so it is resolved through the same directory entry: one directory, one
 * filesystem, and linking inside a directory is a metadata operation the
 * kernel performs atomically. A temporary anywhere else -- TMPDIR, /tmp, a
 * scratch tree -- may be a different filesystem, and link() there is either
 * refused outright or emulated as a copy, which is precisely the window this
 * exists to close. Nothing about the destination's permissions can break
 * this: the temporary needs the very same directory entry the destination
 * needs, so if the destination could be created the temporary can too.
 *
 * Only this process's own temporary is removed, and only on the path that did
 * not publish. The destination is never opened for writing at all. */
/* THE PROVENANCE IS A PARAMETER AND NOT A CONSTANT IN THIS FUNCTION, and it is
 * one because the tool now publishes images from two different producers. The
 * C reference path still answers `BOOTSTRAP_EXTERNAL_C`, byte for byte,
 * because two gates pin that string on its own lines; the Machine IR path
 * answers `NEXORA_MIR`, because an image emitted by machine_x64 from a Machine
 * IR did not come from the quarantined external assembler, and a line claiming
 * otherwise would be false in the exact way a provenance line exists to
 * prevent. */
static int write_output(const char *path, const NtBuffer *bytes,
                        const char *marker, const char *provenance) {
  size_t length = strlen(path);
  if (length > 32000)
    return 3;
  char temporary[32000 + 80];
  FILE *output = NULL;
  for (unsigned attempt = 0; attempt < 100; ++attempt) {
    temporary_name(temporary, sizeof temporary, path, attempt);
    output = fopen(temporary, "wbx");
    if (output || errno != EEXIST)
      break;
  }
  if (!output) {
    fprintf(stderr, "%s: E700: %s\n", path, strerror(errno));
    return 3;
  }
  size_t written = fwrite(bytes->bytes, 1, bytes->size, output);
  int flush_error = fflush(output);
  /* fsync before the name is claimed: the destination must never point at
   * bytes that are still only in a buffer. Without it the ordering below
   * guarantees that the file is COMPLETE, not that it is DURABLE. */
  int sync_error = fsync(fileno(output));
  int close_error = fclose(output);
  if (written != bytes->size || flush_error || sync_error || close_error) {
    remove(temporary);
    fputs("E701: incomplete output, do not execute\n", stderr);
    return 3;
  }
  int refused = link(temporary, path) != 0;
  int reason = errno;
  remove(temporary);
  if (refused) {
    errno = reason;
    fprintf(stderr, "%s: E700: %s\n", path, strerror(errno));
    return 3;
  }
  printf("%s bytes=%zu provenance=%s\n", marker, bytes->size, provenance);
  return 0;
}

static int read_input(const char *path, NtFInput *result) {
  memset(result, 0, sizeof(*result));
  result->name = path;
  FILE *input = fopen(path, "rb");
  if (!input) {
    fprintf(stderr, "%s: E001: %s\n", path, strerror(errno));
    return 0;
  }
  if (fseek(input, 0, SEEK_END) != 0) {
    fclose(input);
    fputs("E002: input is not seekable\n", stderr);
    return 0;
  }
  long length = ftell(input);
  if (length < 0 || length > 16 * 1024 * 1024 ||
      fseek(input, 0, SEEK_SET) != 0) {
    fclose(input);
    fputs("E002: invalid source size\n", stderr);
    return 0;
  }
  char *source = malloc((size_t)length + 1);
  if (!source) {
    fclose(input);
    fputs("E003: allocation failed\n", stderr);
    return 0;
  }
  size_t count = fread(source, 1, (size_t)length, input);
  int extra = fgetc(input), read_error = ferror(input),
      close_error = fclose(input);
  if (count != (size_t)length || extra != EOF || read_error || close_error) {
    free(source);
    fputs("E002: source changed or read failed\n", stderr);
    return 0;
  }
  source[count] = 0;
  result->text = source;
  result->length = count;
  return 1;
}
static void release_inputs(NtFInput *inputs, size_t count) {
  for (size_t j = 0; j < count; ++j)
    free((void *)inputs[j].text);
}
/* ---------------------------------------------------------------------------
 * THE Machine IR PATH.
 *
 * WHAT IT IS. `--backend mir` on `assemble`, `object`, `link` and `check`
 * drives `compiler/nova/drivers/machine-driver-entry.nova` (and, for `link`,
 * `machine-link-entry.nova`): source text -> parse ->
 * macro expansion -> NTIR -> Machine IR -> NXO -> PE. Every byte published
 * here was emitted by `machine_emit.nova` reading a Machine IR that
 * `machine_ir.nova` verified (machine_x64.nova until 6 October 2026).
 *
 * WHAT IT IS NOT, AND THAT IS THE PART THAT MATTERS. It does not fall back.
 * A refusal from the pipeline is a refusal from the pipeline: there is no
 * `nt_compile_many` call on this path, no second attempt, and no AST answer
 * dressed as a Machine IR one. A tool that falls back silently cannot be told
 * apart from a tool that works, which is the property this path exists to have
 * and the only property a caller can act on.
 *
 * THE C REFERENCE STAYS AND STAYS REACHABLE. `assemble`, `object`, `link` and
 * `check` still mean the frozen C pipeline by default; `--backend mir` routes
 * EVERY ONE OF THEM here and `--backend c` names the reference explicitly.
 * The parity is guarded now (tests_ntasm_machine_corpus.c: the corpus through
 * both producers, executed and compared), and the default stays on the
 * reference for one measured reason: app.ntasm + math.ntasm assembles with
 * the C pipeline and is refused by the Nova macro expander (374, hygiene,
 * spec/ntasm/ntasm.md section 13), so moving the default would turn a corpus pair
 * that builds today into a refusal. That is an expander question, not an
 * emitter one. `run` has no Machine IR form -- it maps the C reference image
 * in-process -- and with `--backend mir` it REFUSES rather than run the C
 * build under a Machine IR flag.
 *
 * SEVERAL MODULES ARE SEVERAL OBJECTS AND ONE LINK, never one object. Each
 * source becomes its own NXO through `machine_pipeline.build_object`, and the
 * containers go to `ntasm_nxo_link_pe.link_pe_list`. Nothing is concatenated
 * and no source is dropped: `object --backend mir` with more than one source
 * is REFUSED rather than answering about the first one, which is what a tool
 * that quietly ignored the rest of its command line would do.
 *
 * THERE IS NO SECOND SPELLING. This path was first reached through two verbs
 * of its own, `assemble-machine` and `object-machine`. They were removed on 7
 * October 2026 when `--backend mir` came to cover every verb: two spellings of
 * one request are the ambiguity tests_ntasm_cli.c refuses (exactly six verbs,
 * only documented flags), and the user's brief named an experimental verb as a
 * transitional step, not a delivery.
 * ------------------------------------------------------------------------- */

/* Options are removed before anything looks at a position, so the existing
 * `argv[argc-2] == "-o"` and `argv[2 .. argc-3]` arithmetic below keeps
 * working unchanged whether or not they were given. `--root` and `--backend`
 * each consume the word after them; a source file named `--root` is therefore
 * not a source file, which is the same trade every option parser makes. */
static int strip_options(int *argc, char **argv, const char **root, int *mir) {
  int n = *argc, w = 1;
  for (int i = 1; i < n; ++i) {
    if (!strcmp(argv[i], "--root")) {
      if (i + 1 >= n)
        return 0;
      *root = argv[++i];
    } else if (!strcmp(argv[i], "--backend")) {
      if (i + 1 >= n)
        return 0;
      const char *backend = argv[++i];
      if (!strcmp(backend, "mir"))
        *mir = 1;
      else if (!strcmp(backend, "c"))
        *mir = 0;
      else
        return 0;
    } else {
      argv[w++] = argv[i];
    }
  }
  /* NOT UNCONDITIONALLY: a caller that passes a five-word array -- the CLI
   * gate does, twice, on the same array -- has no sixth word to write. When
   * nothing was removed w == n and argv[n] is already the terminator the
   * C runtime left there. */
  if (w < n)
    argv[w] = 0;
  *argc = w;
  return 1;
}

/* The Machine IR producer's own numbers, never renamed: `code` is whatever
 * module fired and `stage` is that module's report[8]. The stage is printed as
 * a NUMBER because it is one -- machine_pipeline publishes STAGE_* functions
 * and a table of names written here would be a second copy of them that could
 * only ever agree today. */
/* What machine_produce is asked for. LINK reads NXO containers -- objects the
 * Machine IR producer wrote -- and links them through ntasm_nxo_link_pe, the
 * Nova linker, never through the C one. CHECK runs the whole chain to the
 * object and writes nothing. */
enum { MIR_OBJECT = 0, MIR_PE = 1, MIR_LINK = 2, MIR_CHECK = 3 };
static int machine_produce(const char *root, char **names, NtFInput *inputs,
                           size_t count, int mode, const char *output) {
  NtDiagnostic error = {0};
  NtMachineImage *image = nt_machine_open(root, &error);
  if (!image) {
    fprintf(stderr, "<machine-driver>:%zu:%zu: E%03u: %s\n", error.line,
            error.column, error.code,
            error.message[0] ? error.message : "the producer did not open");
    return 1;
  }
  NtBuffer objects[64];
  NtBuffer result = {0};
  NtMachineReport report;
  memset(objects, 0, sizeof objects);
  memset(&report, 0, sizeof report);
  int ok = 0;
  int want_pe = mode == MIR_PE || mode == MIR_LINK;
  if (mode == MIR_CHECK) {
    size_t checked = 0;
    while (checked < count) {
      NtBuffer object = {0};
      int one = nt_machine_object(image, inputs[checked].text,
                                  inputs[checked].length, &object, &report);
      free(object.bytes);
      if (!one)
        break;
      checked++;
    }
    ok = checked == count;
    if (ok) {
      nt_machine_close(image);
      printf("NTASM_MIR_CHECK_OK phase=machine_ir objects=%zu\n", count);
      return 0;
    }
    names += checked;
  } else if (mode == MIR_LINK) {
    for (size_t j = 0; j < count; ++j) {
      objects[j].bytes = (uint8_t *)inputs[j].text;
      objects[j].size = inputs[j].length;
    }
    ok = nt_machine_link(image, objects, count, &result, &report);
    memset(objects, 0, sizeof objects);
  } else if (count == 1) {
    ok = want_pe ? nt_machine_pe(image, inputs[0].text, inputs[0].length,
                                 &result, &report)
                 : nt_machine_object(image, inputs[0].text, inputs[0].length,
                                     &result, &report);
  } else if (!want_pe) {
    nt_machine_close(image);
    fprintf(stderr,
            "%s: E604: the Machine IR producer emits one object per module; "
            "pass one source, or use assemble --backend mir\n",
            output);
    return 1;
  } else {
    size_t built = 0;
    while (built < count &&
           nt_machine_object(image, inputs[built].text, inputs[built].length,
                             objects + built, &report))
      built++;
    if (built == count)
      ok = nt_machine_link(image, objects, count, &result, &report);
  }
  for (size_t j = 0; j < count; ++j)
    free(objects[j].bytes);
  if (!ok) {
    /* THREE REFUSALS AND THREE MESSAGES. A host fault, a success with no
     * image and a stage refusal all produce no file, and a reader told only
     * "no file" would have to guess which of the three happened. */
    if (report.runtime) {
      /* The link image's own sentence, when there is one. `nt_machine_close`
       * frees the image, so this is read BEFORE the close and not after -- a
       * pointer into a freed image is a use-after-free that happens to print
       * the right thing. */
      const NtDiagnostic *link = nt_machine_link_error(image);
      fprintf(stderr,
              "%s: E603: the Machine IR producer faulted in the host "
              "(runtime=%llu source=%llu offset=%llu)%s%s\n",
              names[0], (unsigned long long)report.runtime,
              (unsigned long long)report.runtime_source,
              (unsigned long long)report.runtime_offset,
              link && link->message[0] ? " link image: " : "",
              link && link->message[0] ? link->message : "");
    } else if (!report.returned) {
      fprintf(stderr,
              "%s: E604: the Machine IR producer returned success with "
              "no image\n",
              names[0]);
    } else {
      fprintf(stderr,
              "%s: E%03u: the Machine IR producer refused at stage %llu\n",
              names[0], (unsigned)report.code,
              (unsigned long long)report.stage);
    }
    nt_machine_close(image);
    free(result.bytes);
    return 1;
  }
  /* A LINK names the linker, not the code: the containers it read may have
   * been written by either producer, so `NEXORA_MIR` -- which says the bytes
   * came from the Machine IR emitter -- would be a claim about objects this
   * call never saw being built. */
  int rc = write_output(output, &result,
                        mode == MIR_LINK ? "NTASM_MIR_LINKED"
                        : want_pe        ? "NTASM_MIR_PE"
                                         : "NTASM_MIR_OBJECT",
                        mode == MIR_LINK ? "NEXORA_NOVA_LINKER" : "NEXORA_MIR");
  free(result.bytes);
  nt_machine_close(image);
  return rc;
}


/* One text, two destinations: --help puts it on stdout and succeeds, a
 * command line the tool cannot read puts it on stderr and fails. A tool that
 * answers a request for help with a usage error is not usable. */
static const char USAGE[] =
    "usage: ntasm assemble SOURCE.ntasm [MORE.ntasm ...] -o OUTPUT.efi\n"
    "       ntasm check SOURCE.ntasm [MORE.ntasm ...]\n"
    "       ntasm run SOURCE.ntasm [MORE.ntasm ...] --expect RESULT\n"
    "       ntasm inspect PROGRAM.efi|UNIT.nxo\n"
    "       ntasm object SOURCE.ntasm [MORE.ntasm ...] -o UNIT.nxo\n"
    "       ntasm link UNIT.nxo [MORE.nxo ...] -o OUTPUT.efi\n"
    "\n"
    "options:\n"
    "  -h --help  write this text to stdout and exit 0\n"
    "  --version  write the version and provenance to stdout and exit 0\n"
    "  -o PATH    write PATH; assemble, object and link require it, and it must be\n"
    "             the argument immediately before PATH\n"
    "  --backend c|mir  producer for assemble, object, link and check; c "
    "(the default)\n"
    "             is the frozen C reference and mir is the Nova Machine IR "
    "chain.\n"
    "             There is NO fallback: a Machine IR refusal is a refusal, and "
    "run\n"
    "             refuses --backend mir because it has no Machine IR form.\n"
    "  --root DIR the tree holding compiler/nova and "
    "bootstrap/quarantine;\n"
    "             taken exactly, never searched upwards. Without it the "
    "tool walks\n"
    "             up from its own executable and then from the working "
    "directory.\n"
    "  --expect N required by run, as the argument immediately before N: the\n"
    "             u64 the executed image must return, and the tool exits 4 "
    "when it\n"
    "             returns anything else\n";

int nt_cli(int argc, char **argv) {
  const char *root = NULL;
  /* THE ONE INITIALISER THAT PICKS THE DEFAULT PRODUCER. It is 0 -- the
   * frozen C reference -- for the measured reason written at the head of the
   * Machine IR path above (one corpus pair the C pipeline builds is refused by
   * the Nova macro expander). Making `assemble`, `object`, `link` and `check`
   * mean the Machine IR chain is this `0` becoming a `1` and nothing else:
   * every branch below already asks. */
  int mir = 0;
  if (!strip_options(&argc, argv, &root, &mir)) {
    fputs(USAGE, stderr);
    return 2;
  }
  if (argc == 2 && (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help") ||
                    !strcmp(argv[1], "help"))) {
    fputs(USAGE, stdout);
    return 0;
  }
  if (argc == 2 && !strcmp(argv[1], "--version")) {
    puts("ntasm 0.0.1-c-bootstrap provenance=BOOTSTRAP_EXTERNAL_C "
         "B2.1=not-delivered");
    return 0;
  }
  int check_only = argc >= 3 && !strcmp(argv[1], "check");
  int inspect = argc == 3 && !strcmp(argv[1], "inspect");
  int object_mode = argc >= 5 && !strcmp(argv[1], "object");
  int link_mode = argc >= 5 && !strcmp(argv[1], "link");
  int run_mode = argc >= 5 && !strcmp(argv[1], "run") &&
                 !strcmp(argv[argc - 2], "--expect");
  /* `link --backend mir` reads NXO containers and links them through
   * `ntasm_nxo_link_pe`, the Nova linker; without the flag it is the C one.
   * The containers carry no IR, so the two linkers answer about the same
   * bytes, and tests on 6 October 2026 measured them writing the same PE. */
  /* EVERY VERB THE FLAG NAMES GOES TO THE MACHINE IR PRODUCER, or none does.
   * The first version of this line routed `assemble` only, so `object
   * --backend mir` wrote a C object and `check --backend mir` ran the C
   * frontend: a silent fallback under the one flag that promises there is
   * none. Measured 6 October 2026 by reading this condition, and closed here
   * for all four verbs. */
  int has_output = argc >= 5 && !strcmp(argv[argc - 2], "-o");
  int machine = mir && has_output &&
                (!strcmp(argv[1], "assemble") || object_mode || link_mode);
  int machine_writes_object = machine && !strcmp(argv[1], "object");
  int machine_links = machine && link_mode && mir;
  if (mir && run_mode) {
    fputs("E605: run maps the C reference image in-process and has no Machine "
          "IR form; build with `assemble --backend mir` and load the PE, or "
          "pass --backend c\n",
          stderr);
    return 2;
  }
  int assemble = argc >= 5 &&
                 (!strcmp(argv[1], "assemble") || object_mode || link_mode) &&
                 !strcmp(argv[argc - 2], "-o");
  size_t input_count = inspect      ? 1
                       : check_only ? (size_t)(argc - 2)
                       : assemble || run_mode ? (size_t)(argc - 4)
                                              : 0;
  if (!input_count || input_count > 64) {
    fputs(USAGE, stderr);
    return 2;
  }
  NtFInput inputs[64] = {{0}};
  size_t total = 0;
  for (size_t j = 0; j < input_count; ++j) {
    if (!read_input(argv[2 + j], inputs + j)) {
      release_inputs(inputs, j);
      return 3;
    }
    total += inputs[j].length;
    if (total > 64 * 1024 * 1024) {
      release_inputs(inputs, j + 1);
      fputs("E002: input unit exceeds 64 MiB\n", stderr);
      return 3;
    }
  }
  if (machine) {
    int produced = machine_produce(root, argv + 2, inputs, input_count,
                                   machine_links           ? MIR_LINK
                                   : machine_writes_object ? MIR_OBJECT
                                                           : MIR_PE,
                                   argv[argc - 1]);
    release_inputs(inputs, input_count);
    return produced;
  }
  if (mir && check_only) {
    int checked = machine_produce(root, argv + 2, inputs, input_count,
                                  MIR_CHECK, NULL);
    release_inputs(inputs, input_count);
    return checked;
  }
  if (inspect) {
    if (inputs[0].length >= 8 && !memcmp(inputs[0].text, "NXOV0001", 8)) {
      NtObject object = {0};
      NtDiagnostic error = {0};
      int ok = nt_object_read((const uint8_t *)inputs[0].text, inputs[0].length,
                              &object, &error);
      release_inputs(inputs, input_count);
      if (!ok) {
        fprintf(stderr, "%s:offset%zu: E%03u: %s\n", argv[2], error.offset,
                error.code, error.message);
        nt_object_free(&object);
        return 1;
      }
      printf("{\"format\":\"NXOV0001\",\"target\":%u,\"symbols\":%zu,"
             "\"relocations\":%zu,\"entry_symbol\":%u}\n",
             object.target, object.symbol_count, object.relocation_count,
             object.entry_symbol);
      nt_object_free(&object);
      return 0;
    }
    NtPeInfo info;
    NtDiagnostic diagnostic;
    int inspected = nt_pe_inspect((const uint8_t *)inputs[0].text,
                                  inputs[0].length, &info, &diagnostic);
    release_inputs(inputs, input_count);
    if (!inspected) {
      fprintf(stderr, "%s:offset%zu: E%03u: %s\n", argv[2], diagnostic.offset,
              diagnostic.code, diagnostic.message);
      return 1;
    }
    printf("{\"format\":\"PE32+\",\"machine\":\"x86_64\",\"subsystem\":"
           "\"UEFI\",\"entry_rva\":%u,\"image_base\":%" PRIu64
           ",\"image_size\":%u,\"sections\":%u,\"dir64_count\":%u}\n",
           info.entry_rva, info.image_base, info.image_size, info.section_count,
           info.relocation_count);
    return 0;
  }
  if (object_mode || link_mode) {
    NtObject object = {0};
    NtBuffer encoded = {0};
    NtArtifact artifact = {0};
    NtDiagnostic error = {0};
    NtObject link_inputs[64] = {{0}};
    int ok;
    if (object_mode) {
      ok = nt_object_compile(inputs, input_count, &object, &error) &&
           nt_object_write(&object, &encoded, &error);
    } else {
      ok = 1;
      for (size_t j = 0; j < input_count; ++j) {
        if (!nt_object_read((const uint8_t *)inputs[j].text, inputs[j].length,
                            link_inputs + j, &error)) {
          error.source_index = (uint32_t)(j + 1);
          ok = 0;
          break;
        }
      }
      ok = ok && nt_object_link(link_inputs, input_count, &object, &error) &&
           nt_object_materialize(&object, &artifact, &error) &&
           nt_make_pe(&artifact);
    }
    release_inputs(inputs, input_count);
    int result = 1;
    if (ok) {
      result =
          write_output(argv[argc - 1], object_mode ? &encoded : &artifact.pe,
                       object_mode ? "NTASM_C_OBJECT" : "NTASM_C_LINKED",
                       "BOOTSTRAP_EXTERNAL_C");
    } else {
      const char *name =
          error.source_index >= 1 && error.source_index <= input_count
              ? argv[1 + error.source_index]
              : "<build>";
      fprintf(stderr, "%s:%zu:%zu: E%03u: %s\n", name, error.line, error.column,
              error.code ? error.code : 600,
              error.message[0] ? error.message : "PE generation failed");
    }
    free(encoded.bytes);
    nt_artifact_free(&artifact);
    nt_object_free(&object);
    for (size_t j = 0; j < input_count; ++j)
      nt_object_free(link_inputs + j);
    return result;
  }
  if (check_only) {
    NtFProgram program = {0};
    int checked = nt_frontend_compile(inputs, input_count, &program);
    release_inputs(inputs, input_count);
    if (!checked) {
      if (program.diagnostic_count) {
        const NtFDiagnostic *d = &program.diagnostics[0];
        const char *name = d->span.source >= 1 && d->span.source <= input_count
                               ? argv[1 + d->span.source]
                               : "<build>";
        fprintf(stderr, "%s:%u:%u: E%03u: %s\n", name, d->span.line,
                d->span.column, d->code, d->message);
      } else {
        fputs("E900: frontend check failed\n", stderr);
      }
      nt_frontend_free(&program);
      return 1;
    }
    nt_frontend_free(&program);
    puts("NTASM_C_CHECK_OK phase=frontend");
    return 0;
  }
  /* The verb that closes the loop: the same build `assemble` performs, then
   * the image is mapped and CALLED, and the value it returns is compared with
   * the one the caller named. A build that would not finish exits 1, the same
   * code a rejected source gets, because that is what it is; an image that
   * built, ran and returned something else exits 4, a code nothing else in
   * this table can return. Zero is reserved for a run that returned exactly
   * what was asked for, so a verb that executed nothing could not reach it. */
  if (run_mode) {
    char *end = NULL;
    uint64_t expected = 0;
    if (argv[argc - 1][0] == '-') {
      fputs(USAGE, stderr);
      release_inputs(inputs, input_count);
      return 2;
    }
    expected = strtoull(argv[argc - 1], &end, 10);
    if (!end || *end || end == argv[argc - 1]) {
      fputs(USAGE, stderr);
      release_inputs(inputs, input_count);
      return 2;
    }
    NtArtifact artifact = {0};
    int built = nt_compile_many(inputs, input_count, &artifact);
    release_inputs(inputs, input_count);
    if (!built) {
      const char *error_source =
          artifact.error.source_index >= 1 &&
                  artifact.error.source_index <= input_count
              ? argv[1 + artifact.error.source_index]
              : "<build>";
      fprintf(stderr, "%s:%zu:%zu: E%03u: %s\n", error_source,
              artifact.error.line, artifact.error.column, artifact.error.code,
              artifact.error.message);
      nt_artifact_free(&artifact);
      return 1;
    }
    NovaHostImage image;
    if (!nova_host_map(&artifact, &image)) {
      nt_artifact_free(&artifact);
      fputs("E602: image could not be mapped for execution\n", stderr);
      return 1;
    }
    uint64_t produced = image.entry(NULL, NULL, 0);
    nova_host_unmap(&image);
    nt_artifact_free(&artifact);
    printf("NTASM_C_RUN result=%" PRIu64 " expected=%" PRIu64 "\n", produced,
           expected);
    if (produced != expected) {
      fprintf(stderr,
              "E702: image returned %" PRIu64 ", --expect named %" PRIu64
              "\n",
              produced, expected);
      return 4;
    }
    return 0;
  }
  NtArtifact a;
  int ok = nt_compile_many(inputs, input_count, &a);
  release_inputs(inputs, input_count);
  if (!ok) {
    const char *error_source =
        a.error.source_index >= 1 && a.error.source_index <= input_count
            ? argv[1 + a.error.source_index]
            : "<build>";
    fprintf(stderr, "%s:%zu:%zu: E%03u: %s\n", error_source, a.error.line,
            a.error.column, a.error.code, a.error.message);
    nt_artifact_free(&a);
    return 1;
  }
  if (!nt_make_pe(&a)) {
    nt_artifact_free(&a);
    fputs("E600: PE generation failed\n", stderr);
    return 1;
  }
  int result = write_output(argv[argc - 1], &a.pe, "NTASM_C_ASSEMBLED",
                            "BOOTSTRAP_EXTERNAL_C");
  nt_artifact_free(&a);
  return result;
}
