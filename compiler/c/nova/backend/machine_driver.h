#ifndef NG_NOVA_MACHINE_DRIVER_H
#define NG_NOVA_MACHINE_DRIVER_H
#include "../../ntasm/frontend/ntasm.h"

/* ---------------------------------------------------------------------------
 * THE C BOOTSTRAP DRIVER FOR THE Nova/Machine IR PRODUCER.
 *
 * WHAT IT IS AND WHAT IT IS NOT. A8 -- writing the driver in Nova -- is not the
 * object of this lot, so the caller on the C side is allowed. The BYTES are
 * not: every image this driver returns was emitted by `machine_emit.nova` from a
 * Machine IR that `machine_ir.nova` verified, through the production entries
 * `compiler/nova/drivers/machine-driver-entry.nova` and
 * `compiler/nova/drivers/machine-link-entry.nova`. This file compiles those
 * programs, maps them, and calls them. It never calls `nt_compile_many`, never
 * calls `nt_object_compile`, and never falls back to either: a refusal is a
 * refusal and there is no path here that produces an image the AST pipeline
 * produced.
 *
 * WHY THE MODES ARE DECLARED HERE AND CHECKED AGAINST THE MODULES. The faces
 * below are selected by numbers that appear in this header AND in the Nova
 * entries. Two files writing the same number and never comparing them is how a
 * caller ends up reading report[8] as a stage it is not, so `nt_machine_open`
 * asks the pipeline module for its own numbers (mode 0) and REFUSES to hand
 * back an image when they differ, and `nt_machine_link` asks the link module
 * for its numbers and compares THOSE against the pipeline's.
 * ------------------------------------------------------------------------- */
enum {
  NG_MACHINE_VOCABULARY = 0,
  NG_MACHINE_OBJECT = 1,
  NG_MACHINE_PE = 2,
  NG_MACHINE_LINK = 4,
  NG_MACHINE_STAGES = 8
};

/* The output buffer the driver lends a module. It is the same width the pipeline
 * gate uses (tests_ntasm_machine_pipeline.c lends 1 MiB and measures 336-byte
 * objects and 3072-byte images), doubled, because a caller refused for a short
 * buffer has learned nothing about the program. A program larger than this is
 * refused by the module with its OWN delivery code, which is a named refusal and
 * not a truncation. */
#define NG_MACHINE_OUTPUT_BYTES (4u * 1024u * 1024u)

/* Where a refusal came from. `returned` is what the MODULE answered and
 * `runtime` is what the HOST answered, and they are two different facts: a
 * module that answers 0 with an empty output buffer and a run the host faulted
 * both produce no image, and only one of them is a policy. `stage` and `code`
 * are the refusing stage's own report words -- report[8] and report[9] -- and
 * `code` is whatever module fired it, never renamed here. */
typedef struct {
  uint64_t returned;
  uint64_t runtime, runtime_source, runtime_offset;
  uint64_t stage, code;
  uint64_t object_size, pe_size, symbols, entry, text_size;
} NtMachineReport;

/* One set of compiled, mapped pages plus the vocabulary read out of them. Not
 * thread-safe by construction: one image is one set of pages and one Nova
 * execution context at a time. */
typedef struct NtMachineImage NtMachineImage;

/* The repository root, found and PROVEN rather than guessed.
 *
 * `requested` is the caller's own answer -- `--root DIR` or the NTASM_ROOT
 * environment variable -- and it is taken EXACTLY, with no walking upwards: a
 * wrong `--root` must be refused, not silently replaced by an ancestor that
 * happens to hold a toolchain. When `requested` is NULL or empty the search
 * walks up from the executable's own directory and then from the working
 * directory, at most NG_MACHINE_ROOT_WALK levels each.
 *
 * A directory is a root when it holds BOTH markers below. One marker is a guess:
 * a tree with a toolchain and no C bootstrap is not this tree, and a tree with
 * the C bootstrap and no Nova sources cannot build a producer. */
#define NG_MACHINE_ROOT_WALK 6
#define NG_MACHINE_MARKER_ENTRY "compiler/nova/drivers/machine-driver-entry.nova"
#define NG_MACHINE_MARKER_HOST "compiler/c/nova/frontend/nova.h"

/* 1 on success, 0 on refusal, with `error` carrying the reason. `room` must be
 * at least 1024. */
int nt_machine_root(const char *requested, char *out, size_t room,
                    NtDiagnostic *error);

/* TWO IMAGES, NOT ONE, and the reason is measured rather than chosen: the
 * closure of `machine_pipeline` together with `ntasm_nxo_link_pe` is
 * fifty-one modules and compiles to 17071326 bytes of .text, while
 * `nova/run_host.c` refuses to map anything above 16777216. The driver holds a
 * forty-nine module pipeline image and a six module link image, each with its
 * own Nova entry. The link image is opened on the first multi-module request and
 * kept, so a second link costs no compilation. */
NtMachineImage *nt_machine_open(const char *requested, NtDiagnostic *error);
void nt_machine_close(NtMachineImage *image);
/* Why the link image refused to open. `nt_machine_link` reports the CLASS on the
 * NtMachineReport -- 6 for a host fault, 7 for a vocabulary mismatch -- and this
 * returns the sentence naming the file. Valid until `nt_machine_close`. */
const NtDiagnostic *nt_machine_link_error(const NtMachineImage *image);

/* The three faces. Each returns 1 only when a non-empty image exists; on 0 the
 * report says which stage refused and `out` is left empty. */
int nt_machine_object(NtMachineImage *image, const char *source, size_t length,
                      NtBuffer *out, NtMachineReport *report);
int nt_machine_pe(NtMachineImage *image, const char *source, size_t length,
                  NtBuffer *out, NtMachineReport *report);
/* Several NXO containers -- each produced by nt_machine_object from its own
 * source text -- into one PE, through ntasm_nxo_link_pe.link_pe_list. The
 * objects are read and never modified or freed. */
int nt_machine_link(NtMachineImage *image, const NtBuffer *objects, size_t count,
                    NtBuffer *out, NtMachineReport *report);
#endif