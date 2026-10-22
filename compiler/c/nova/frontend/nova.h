#ifndef NG_NOVA_BOOTSTRAP_H
#define NG_NOVA_BOOTSTRAP_H
#include "../../ntasm/frontend/ntasm.h"
/* BOOTSTRAP_EXTERNAL_C: Nova source is parsed/type-checked here and lowered
 * directly to the shared x64 encoder. GCC/Clang never translate Nova input.
 * Language ABI 1: u8/u64/bool values use ms_abi scalar slots. buf<u8>
 * parameters use two slots (pointer, length); at most four slots total.
 * Index violations return NOVA_BOUNDS_ERROR before any access.
 */
#define NOVA_BOUNDS_ERROR UINT64_C(0x8000000400000000)
int nova_compile(const char *source, size_t length, NtArtifact *out);
int nova_compile_many(const NtFInput *sources, size_t count, NtArtifact *out);
/* Safe execution ABI 2; legacy functions above remain for v1 proof replay. */
int nova_compile_v2(const char *source, size_t length, NtArtifact *out);
int nova_compile_many_v2(const NtFInput *sources, size_t count,
                         NtArtifact *out);
int nova_check_many_v2(const NtFInput *sources, size_t count,
                       NtDiagnostic *error);
/* C_SEED_ORACLE only: opt-in closed-image link compaction. Existing APIs above
 * retain byte-identical behavior. NULL options keeps ALL exported symbols as
 * roots. ENTRY_ONLY_CLOSED_APPLICATION explicitly states that Nova module
 * visibility does not expose extra binary entry points; data/rdata function
 * addresses remain roots in both policies. Unknown references fail closed. */
enum {
  NOVA_SEED_ALL_EXPORTS = 0,
  NOVA_SEED_ENTRY_ONLY_CLOSED_APPLICATION = 1
};
typedef struct {
  uint64_t version, size;
  uint32_t root_policy, reserved;
} NovaSeedReachabilityOptions;
typedef struct {
  size_t text_before, text_after, functions_before, functions_kept;
  size_t roots_entry, roots_exported, roots_data;
  size_t function_references, relocations_before, relocations_after;
  uint32_t root_policy, graph_complete;
} NovaSeedReachabilityStats;
int nova_compile_many_v2_seed_reachable(const NtFInput *, size_t, NtArtifact *,
    const NovaSeedReachabilityOptions *, NovaSeedReachabilityStats *);
#endif
