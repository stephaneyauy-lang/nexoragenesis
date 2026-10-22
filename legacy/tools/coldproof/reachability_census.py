#!/usr/bin/env python3
"""reachability_census.py — NTASM B2.1. THIRD VERSION.

Answers one question the suite cannot: does any pipeline stage enter another?

Four classes, each of which W208SevenOrphans forced into existence by reporting that the
instrument did not have them:

  1 IDENTITY IS THE DECLARED NAME, NOT THE FILENAME. `module X;`, not `x.nova`.
    14 modules differ (ast.nova -> module ntasm_ast, nxo_pe.nova -> ntasm_nxo_pe).
    Keying callers on the filename reported live, wired modules as uncalled.

  2 A FIXTURE IS CONSUMED AS DATA AND NEVER COMPILED. Positive test: a file under
    tests/fixtures/ whose path is named by some compiler/c/nova/*.c.

  3 AN ENTRY IS CALLED BY THE HOST. It exports nothing — the host calls its `main` —
    and the harness that drives it is named for the stem WITHOUT the -entry suffix
    (tests_ntasm_lexer.c drives tests/lexer-entry.nova). Without this, every entry
    carried two wrong labels: "surface vide" AND "harnais: NON".

  4 A FIXTURE'S `appel.C` IS NOT MEASURED AT ALL. It is not "measured and overridden":
    a fixture named `bump` collides with two unrelated `static void bump(uint64_t)`
    in the C harnesses, and the census printed appel.C=2 for it. The verdict was
    right — DONNEE DE TEST took precedence — but a false number was still computed and
    printed on every run. That is the shape of the bug the previous two versions had.

Run:  python3 reachability_census.py [REPO_ROOT]
Test: python3 reachability_census.py --self-test
Exit: 0 reporting, 1 if the self-test fails.
"""
import re
import sys
import pathlib
import tempfile

NOVA_CALL = re.compile(r"\b([a-z][a-z0-9_]*)\.([a-z_][a-z0-9_]*)\s*\(")
EXPORT = re.compile(r"^export\s+fn\s+([a-z_][a-z0-9_]*)", re.M)
MODULE = re.compile(r"^module\s+([a-z0-9_]+)\s*;", re.M)

FIX = "DONNEE DE TEST — jamais compilee comme module"
ENT = "PORTE — appelee par l HOTE, n exporte rien"


def identity(path):
    text = path.read_text(encoding="utf-8", errors="replace")
    m = MODULE.search(text)
    return (m.group(1) if m else path.stem), text


def is_fixture(path, c_files):
    if "fixtures" not in path.parts:
        return False
    name = str(path).split("toolchain/", 1)[-1]
    return any(name in t or path.name in t for t in c_files)


def collect(root):
    d = root / "toolchain" / "ntasm-nova"
    if not d.is_dir():
        raise SystemExit("reachability_census: %s introuvable" % d)

    cdir = root / "bootstrap" / "quarantine" / "c" / "nova"
    ctext = {}
    if cdir.is_dir():
        for p in cdir.glob("*.c"):
            ctext[p.name] = p.read_text(encoding="utf-8", errors="replace")
    c_all = list(ctext.values())

    mods, exports, fixtures, entries = {}, {}, set(), set()
    for p in sorted(d.rglob("*.nova")):
        name, text = identity(p)
        label = name
        if name in mods:                      # two files declaring one module: keep both visible
            label = "%s#%s" % (name, p.stem)
        mods[label] = p
        exports[label] = set(EXPORT.findall(text))
        if is_fixture(p, c_all):
            fixtures.add(label)
        if "entry" in p.stem:
            entries.add(label)

    callers_nova = {n: set() for n in mods}
    for name, p in mods.items():
        if name in fixtures:
            continue
        for callee, _fn in NOVA_CALL.findall(
                p.read_text(encoding="utf-8", errors="replace")):
            if callee in mods and callee != name:
                callers_nova[callee].add(name)

    harness, callers_c = {}, {}
    for name, p in mods.items():
        stem = p.stem
        harness[name] = (("tests_ntasm_%s.c" % stem) in ctext or
                         ("tests_ntasm_%s.c" % stem.replace("-entry", "")) in ctext)
        if name in fixtures:
            callers_c[name] = set()          # NOT MEASURED. See class 4.
            continue
        ex = exports[name]
        callers_c[name] = {f for f, t in ctext.items()
                           if any(re.search(r"\b%s\b\s*\(" % e, t) for e in ex)}
    return mods, exports, callers_nova, callers_c, harness, fixtures, entries


def verdict(n, cn, cc, h, fx, en):
    if fx:
        return FIX
    if en:
        return ENT
    if n == 0:
        return "surface vide"
    if cn and cc:
        return "branche (Nova + C)"
    if cn:
        return "branche (Nova seulement)"
    if cc:
        return "appele par le C seulement"
    if h:
        return "HARNIS PROPRE UNIQUEMENT — isole"
    return "AUCUN APPELANT, AUCUN HARNIS"


def self_test(root):
    """Must be able to FAIL, and must cover the class of the last four defects:
    a name that resolves differently depending on WHICH FIELD you read it from."""
    ok = True
    with tempfile.TemporaryDirectory() as td:
        t = pathlib.Path(td)
        (t / "toolchain" / "ntasm-nova" / "tests" / "fixtures").mkdir(parents=True)
        (t / "bootstrap" / "quarantine" / "c" / "nova").mkdir(parents=True)
        n = t / "toolchain" / "ntasm-nova"
        c = t / "bootstrap" / "quarantine" / "c" / "nova"

        # 1. declared name != stem, and it IS called by another module
        (n / "thing.nova").write_text(
            "module ntasm_thing;\nexport fn convert()->u64 { return 0; }\n")
        (n / "caller.nova").write_text(
            "module ntasm_caller;\nexport fn go()->u64 { return ntasm_thing.convert(); }\n")
        # 2. a fixture whose export name COLLIDES with an unrelated C identifier
        (n / "tests" / "fixtures" / "blob.nova").write_text(
            "module ntasm_blob;\nexport fn bump()->u64 { return 0; }\n")
        (c / "other.c").write_text("static void bump(uint64_t x){(void)x;}\n")
        (c / "third.c").write_text("static void bump(uint64_t x){(void)x;}\n")
        (c / "h.c").write_text(
            'const char *p = "tests/nova/tests/fixtures/blob.nova";\n')
        # 3. an entry: exports nothing, driven by a harness named WITHOUT -entry
        (n / "tests" / "thing-entry.nova").write_text(
            "module ntasm_thing_entry;\nfn main()->u64 { return 0; }\n")
        (c / "tests_ntasm_thing.c").write_text("int main(void){return 0;}\n")
        # 4. a genuine orphan
        (n / "lonely.nova").write_text(
            "module ntasm_lonely;\nexport fn y()->u64 { return 0; }\n")

        mods, ex, cn, cc, h, fx, en = collect(t)
        v = {k: verdict(len(ex[k]), len(cn[k]), len(cc[k]), h[k], k in fx, k in en)
             for k in mods}

        c1 = v.get("ntasm_thing", "").startswith("branche")
        c2 = v.get("ntasm_blob", "") == FIX
        c3 = v.get("ntasm_lonely", "") == "AUCUN APPELANT, AUCUN HARNIS"
        c4 = v.get("ntasm_thing_entry", "") == ENT
        # class 4: the fixture's C-caller count must be zero, never the two collisions
        c5 = len(cc.get("ntasm_blob", [])) == 0

        print("   cas 1  declare ntasm_thing, fichier thing.nova     -> %s"
              % v.get("ntasm_thing", "?"))
        print("   cas 2  fixture dont l export collide avec du C      -> %s  appel.C=%d"
              % (v.get("ntasm_blob", "?"), len(cc.get("ntasm_blob", []))))
        print("   cas 3  entree appelee par l hote                   -> %s"
              % v.get("ntasm_thing_entry", "?"))
        print("   cas 4  module reellement orphelin                   -> %s"
              % v.get("ntasm_lonely", "?"))
        print("   verifications c1=%s c2=%s c3=%s c4(entree)=%s c5(colli.=0)=%s"
              % (c1, c2, c3, c4, c5))
        ok = c1 and c2 and c3 and c4 and c5

    mods, ex, cn, cc, h, fx, en = collect(root)
    real = verdict(len(ex.get("ntasm_ast", [])), len(cn.get("ntasm_ast", [])),
                   len(cc.get("ntasm_ast", [])), h.get("ntasm_ast", False),
                   "ntasm_ast" in fx, "ntasm_ast" in en)
    print("   arbre reel  ntasm_ast (declare par ast.nova) -> %s" % real)
    print("   SELF-TEST %s" % ("OK — le controle sait echouer" if ok else "ECHEC"))
    return 0 if ok else 1


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    root = pathlib.Path(args[0] if args else
                        "/mnt/d/Projets/Racine-C/NexoraGenesis").resolve()
    if "--self-test" in sys.argv:
        return self_test(root)
    mods, exports, cn, cc, h, fx, en = collect(root)
    print("== NTASM — census d'atteignabilite, v3 ==")
    print("   %d modules  ·  identite par « module X; », jamais par le nom de fichier\n"
          % len(mods))
    print("   %-28s %7s %8s %8s %8s  %s" %
          ("module declare", "exports", "appel.N", "appel.C", "harnais", "verdict"))
    print("   " + "-" * 88)
    counts = {}
    for name in sorted(mods):
        v = verdict(len(exports[name]), len(cn[name]), len(cc[name]), h[name],
                    name in fx, name in en)
        counts[v] = counts.get(v, 0) + 1
        print("   %-28s %7d %8d %8s %8s  %s" %
              (name, len(exports[name]), len(cn[name]),
               "—" if name in fx else len(cc[name]),
               "oui" if h[name] else "NON", v))
    print("\n== Resume ==")
    for v, k in sorted(counts.items(), key=lambda x: -x[1]):
        print("   %-46s %d" % (v, k))
    print("\n   Un etage appele par un AUTRE module entre dans la chaine. Une PORTE est")
    print("   appelee par l hote. Une DONNEE DE TEST n est ni l un ni l autre. La reussite")
    print("   d un harnais est une propriete du module, pas un chemin.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())