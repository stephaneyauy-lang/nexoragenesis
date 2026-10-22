#!/usr/bin/env python3
"""lot160_coverage_census.py -- WHICH HARNESSES THE ROUTINE PASS ACTUALLY BUILDS.

The register->file rule is DERIVED FROM legacy/tools/coldproof/ngbuild.sh, not assumed:

  GATES       a STEM.  resolve_gate() (ngbuild.sh:821-844) maps it to
              $root/nova/tests_ntasm_<stem>.c -- unless the stem is also a
              NOVA_GATES member, which resolves to $root/nova/<stem>.c.
              The loop is ngbuild.sh:846-849.
  NOVA_GATES  a BARE NAME, used verbatim as $root/nova/<name>.c, with no
              prefix stripping at all (ngbuild.sh:857-859).
  ROOT_GATES  a LITERAL FILENAME THAT ALREADY CARRIES .c, used verbatim as
              $root/<name> (ngbuild.sh:974-976).  Nothing is stripped.

So `tests_ntasm_` is stripped for exactly ONE array (the nova name filter) and
for NO array at the root level: a root entry IS the filename.  A census that
strips `tests_` from a root file and looks the stem up in GATES misses all 28
ROOT_GATES registrations, and counts every root harness as absent.

Everything here is a measurement of ONE instant.  The census is printed with
the digests it was taken against, because a census read across two instants of
a moving tree is two censuses (see the UNREGISTERED_HARNESS list, which grows
under a running suite).

usage: python3 lot160_coverage_census.py [--json]
"""
import hashlib
import json
import os
import re
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
NGB = os.path.join(ROOT, "tools", "coldproof", "ngbuild.sh")
CDIR = os.path.join(ROOT, "bootstrap", "quarantine", "c")


def arrays(text):
    """The three registration arrays, read positionally exactly as the shell reads them."""
    out = {}
    for name in ("GATES", "NOVA_GATES", "ROOT_GATES",
                 "NOVA_LIBS", "ROOT_LIBS", "NOVA_NOT_A_GATE", "ROOT_NOT_A_GATE"):
        lines = text.split("\n")
        got, i = [], 0
        while i < len(lines):
            if lines[i].startswith(name + "=("):
                i += 1
                while i < len(lines) and not lines[i].startswith(")"):
                    got.append(lines[i])
                    i += 1
                break
            i += 1
        out[name] = got
    return out


def flat(block):
    return [t for line in block for t in line.split()]


def not_a_gate(block):
    """The reason strings are multi-line quoted, so re-join and take the quotes."""
    names = []
    for m in re.finditer(r'"((?:[^"\\]|\\.)*)"', "\n".join(block)):
        names.append(m.group(1).split("|")[0])
    return names


def main():
    raw = open(NGB, "rb").read()
    digest = hashlib.sha256(raw).hexdigest()
    text = raw.decode("utf8", "replace")
    A = arrays(text)

    gates = flat(A["GATES"])
    nova_gates = flat(A["NOVA_GATES"])
    root_gates = flat(A["ROOT_GATES"])
    nova_nag = not_a_gate(A["NOVA_NOT_A_GATE"])
    root_nag = not_a_gate(A["ROOT_NOT_A_GATE"])

    # --- the population, from the filesystem, by the rule above ---------------
    nova_dir = os.path.join(CDIR, "nova")
    disk_nova = sorted(f for f in os.listdir(nova_dir)
                       if f.startswith("tests_ntasm_") and f.endswith(".c"))
    disk_nova_stems = {f[len("tests_ntasm_"):-2]: f for f in disk_nova}
    disk_root_tests = sorted(f for f in os.listdir(CDIR)
                             if f.startswith("tests_") and f.endswith(".c"))
    disk_root_all = sorted(f for f in os.listdir(CDIR) if f.endswith(".c"))

    unregistered = sorted(s for s in disk_nova_stems if s not in set(gates))

    # --- the two rails the driver itself runs, reproduced ---------------------
    # rail 1: comm -13 .gates .harnesses  -> UNREGISTERED_HARNESS
    rail1 = unregistered
    # rail 2: comm -23 .root_c .root_declared -> UNDECLARED_ROOT_C_FILE
    root_declared = set(root_gates) | set(flat(A["ROOT_LIBS"])) | set(root_nag)
    rail2 = sorted(set(disk_root_all) - root_declared)
    # rail 3: comm -13 .root_c .root_declared -> STALE_ROOT_DECLARATION
    rail3 = sorted(root_declared - set(disk_root_all))
    # rail 4: nova .c not tests_ntasm_* and not declared
    nova_declared = set(n + ".c" for n in nova_gates) | set(flat(A["NOVA_LIBS"])) | set(nova_nag)
    nova_other = sorted(f for f in os.listdir(nova_dir)
                        if f.endswith(".c") and not f.startswith("tests_ntasm_"))
    rail4 = sorted(set(nova_other) - nova_declared)

    root_unreg = sorted(set(disk_root_tests) - set(root_gates) - set(root_nag))

    routine = len(set(gates)) + len(set(nova_gates)) + len(set(root_gates))

    if "--json" in sys.argv:
        print(json.dumps({
            "ngbuild_sha256": digest,
            "population_tests_dash_c": len(disk_nova) + len(disk_root_tests),
            "gates": len(set(gates)), "nova_gates": len(set(nova_gates)),
            "root_gates": len(set(root_gates)), "routine_pass_gate_executions": routine,
            "unregistered_nova": rail1, "undeclared_root_c": rail2,
            "stale_root_declaration": rail3, "undeclared_nova_c": rail4,
            "root_tests_not_a_gate": root_unreg,
        }, indent=1))
        return 0

    print("NGBUILD            %s" % NGB)
    print("NGBUILD_SHA256     %s" % digest)
    print("")
    print("POPULATION  tests_*.c under c/ and c/nova/   %d   (%d nova + %d root)"
          % (len(disk_nova) + len(disk_root_tests), len(disk_nova), len(disk_root_tests)))
    print("REGISTERED  GATES=%d  NOVA_GATES=%d  ROOT_GATES=%d   TOTAL=%d"
          % (len(set(gates)), len(set(nova_gates)), len(set(root_gates)), routine))
    print("ROUTINE_PASS_GATE_EXECUTIONS  %d" % routine)
    print("")
    print("--- UNREGISTERED (rail 1: on disk, stem absent from GATES) : %d" % len(rail1))
    for s in rail1:
        print("    %-34s %7d bytes" % (s, os.path.getsize(os.path.join(nova_dir, disk_nova_stems[s]))))
    print("    total %d bytes" % sum(os.path.getsize(os.path.join(nova_dir, disk_nova_stems[s]))
                                    for s in rail1))
    print("")
    print("--- root tests_*.c that are neither ROOT_GATES nor ROOT_NOT_A_GATE : %d"
          % len(root_unreg))
    for s in root_unreg:
        print("    %s" % s)
    print("--- root tests_*.c declared NOT_A_GATE with a written reason : %d"
          % len([f for f in disk_root_tests if f in set(root_nag)]))
    for s in sorted(f for f in disk_root_tests if f in set(root_nag)):
        print("    %s" % s)
    print("")
    print("UNDECLARED_ROOT_C_FILE  %s" % (rail2 or "none"))
    print("STALE_ROOT_DECLARATION  %s" % (rail3 or "none"))
    print("UNDECLARED_NOVA_C_FILE  %s" % (rail4 or "none"))
    print("")
    print("GATES entries with no file: %s"
          % ([g for g in gates if g not in disk_nova_stems and g not in set(nova_gates)] or "none"))
    return 0


if __name__ == "__main__":
    sys.exit(main())