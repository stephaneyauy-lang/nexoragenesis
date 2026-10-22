#ifndef GENESIS_NTASM_H
#define GENESIS_NTASM_H
#include "frontend.h"
#include <stddef.h>
#include <stdint.h>

typedef struct {
  unsigned code;
  uint32_t source_index; /* one-based NtFInput index; zero for global errors */
  size_t offset, line, column;
  char message[192];
} NtDiagnostic;
typedef struct {
  uint8_t *bytes;
  size_t size, capacity;
} NtBuffer;
/* One absolute site a loader must fix up when the image is NOT mapped at
 * NT_PE_IMAGE_BASE. `size` is the width of the write at `offset`. It is
 * carried here rather than assumed by the consumer: every writer of this table
 * filters to DIR64, so a consumer that assumed 8 was reading a fact about the
 * writers out of two files rather than out of the type, and the first second
 * absolute width would have been written twice and forgotten once.
 *
 * THE TARGET IS INSIDE THE IMAGE BY INVARIANT, NOT BY A CHECK HERE.
 * object.c:74-77 forces every non-import symbol into its own section and
 * object.c:93 does the same for the site, and both run before this table is
 * filled, so pe_layout.h:50-65 can add NT_PE_IMAGE_BASE + target with no range
 * test because there is nothing left to test. Nothing here validates that. If
 * object.c ever relaxes it, this table will silently accept an out-of-image
 * target -- which is why the guarantee is written here instead of being left to
 * be inferred. */
typedef struct {
  uint32_t section; /* 1=text,2=user rdata excluding PE anchor,3=data */
  uint64_t offset;
  uint32_t size; /* width of the write at offset, in bytes; never 0 */
} NtBaseReloc;
typedef struct {
  NtBuffer text, pe;
  size_t entry;
  NtDiagnostic error;
  NtBuffer rdata, data;
  NtBaseReloc *base_relocations;
  size_t base_relocation_count;
} NtArtifact;

/* In-memory producer. Owns no input memory; result is always releasable.
 * No output is usable on error. No external translator is ever invoked. */
int nt_compile(const char *source, size_t length, NtArtifact *out);
int nt_compile_many(const NtFInput *inputs, size_t count, NtArtifact *out);
int nt_make_pe(NtArtifact *artifact);
void nt_artifact_free(NtArtifact *artifact);
#endif
