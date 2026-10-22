#!/usr/bin/env python3
"""ntlayout.py - a LAYOUT instrument for the NTASM NXO relocatable object.

It is NOT a determinism check. It performs no cross-build comparison of any
kind: it is handed ONE object file and decides whether that object's LAYOUT is
well formed. Two objects with identical bytes and two objects that differ only
in layout are both decidable by it, and a stable-but-wrong layout is red while
a correct layout is green. Nothing in this file hashes an output to compare it
with another output.

What "layout" means here is the arrangement upstream of the emitted image:
which section each symbol lands in, at what offset, with what size and flags;
the canonical order of the symbol table; the canonical order and non-overlap of
the relocation table; the entry symbol; and the per-symbol typed contract text.
None of that reaches the PE. The PE carries section payloads and resolved
relocation values (object_materialize.c:42-76) and nothing else, so a defect in
any field audited below is INVISIBLE to a digest of the PE and survives a
digest comparison by construction.

The field layout audited is the one nt_object_write lays down
(compiler/c/ntasm/formats/object.c:105-195) and nt_object_read parses
(object.c:227-336). Both are 240-byte header, 48-byte section records, 64-byte
symbol records, 40-byte relocation records, one shared string table.

Usage:  ntlayout.py FILE.nxo [FILE.nxo ...]
Exit 0 when every object's layout holds, 1 when any check fails, 2 on a file
this instrument cannot read at all (which is NOT the same as a pass).
"""

import struct
import sys

MAGIC = b"NXOV0001"
HEADER = 240
SECTION_REC = 48
SYMBOL_REC = 64
RELOC_REC = 40
MAX_FILE = 64 * 1024 * 1024
MAX_SYMBOLS = 65536
MAX_RELOCS = 1048576

NT_TEXT, NT_RDATA, NT_DATA = 1, 2, 3
SECTION_NAMES = {NT_TEXT: "text", NT_RDATA: "rdata", NT_DATA: "data"}
NT_EXPORT, NT_FUNCTION, NT_VARIABLE, NT_IMPORT = 1, 2, 4, 8
RELOC_WIDTH = {1: 4, 2: 8}  # REL32, DIR64
RELOC_NAME = {1: "rel32", 2: "dir64"}
SECTION_BY_NAME = {".text": NT_TEXT, ".rdata": NT_RDATA, ".data": NT_DATA}
TARGET_NAMES = {1: "x86_64-nexora-uefi", 2: "x86_64-nexora-none"}
ABI_PROFILES = {"nx64-abi-v0", "efi-x64-v0"}


def contract_field(contract, key):
    """Read one `key=value` field out of a typed contract.

    Contracts are the flat `fn;...` / `data;...` text of
    object_build.c:174-203, so a field runs to the next `;` or to the end of
    the parameter list. Only the fields this instrument cross-checks against
    the symbol record are needed, and an absent field is reported as None so
    the caller can say so rather than reading a default.
    """
    prefix = key + "="
    start = 0
    while True:
        at = contract.find(prefix, start)
        if at < 0:
            return None
        # Only accept the field at a field boundary, so `section=` cannot be
 # matched inside another key's value.
        if at == 0 or contract[at - 1] == ";":
            end = contract.find(";", at)
            return contract[at + len(prefix):] if end < 0 else contract[
                at + len(prefix):end]
        start = at + 1


class Unreadable(Exception):
    pass


class Layout:
    """One decoded object, with every field the auditor needs. Decoding is
    deliberately permissive: this instrument audits LAYOUT, so a file it
    cannot decode is reported as unreadable rather than silently passed."""

    def __init__(self, raw):
        if len(raw) < HEADER:
            raise Unreadable("shorter than the 240-byte header")
        if raw[:8] != MAGIC:
            raise Unreadable("missing NXOV0001 magic")
        (self.version, self.target, self._s1, self._s2, self.symbol_count,
         self.reloc_count) = struct.unpack_from("<6I", raw, 8)
        (self.section_table, self.sym_at, self.rel_at, self.str_at,
         self.strings, self.payload, self.total) = struct.unpack_from(
            "<7Q", raw, 32)
        (self.entry_symbol,) = struct.unpack_from("<I", raw, 88)
        if self.version != 1:
            raise Unreadable("unknown object version %d" % self.version)
        if self.symbol_count > MAX_SYMBOLS or self.reloc_count > MAX_RELOCS:
            raise Unreadable("symbol/relocation count beyond the format limits")
        self.sections = []
        for j in range(3):
            ident, perms, align, size, off = struct.unpack_from(
                "<IIQQQ", raw, self.section_table + j * SECTION_REC)
            self.sections.append(
                {"id": ident, "perms": perms, "align": align, "size": size,
                 "offset": off})
        self.symbols = []
        for j in range(self.symbol_count):
            r = self.sym_at + j * SYMBOL_REC
            if r + SYMBOL_REC > len(raw):
                raise Unreadable("symbol record %d past end of file" % j)
            # String offsets in a symbol record are RELATIVE to the string
            # table, not absolute: nt_object_write emits a running `text_at`
            # (object.c:163-183) and the reader resolves it as `b + ta + no`
            # (object.c:289-290). Reading them as absolute made every contract
            # decode as binary noise on the first run of this instrument.
            n_at, n_len, section, flags = struct.unpack_from("<4I", raw, r)
            offset, size = struct.unpack_from("<QQ", raw, r + 16)
            c_at, c_len = struct.unpack_from("<2I", raw, r + 32)
            self.symbols.append({
                "index": j,
                "name": self._text(raw, self.str_at + n_at, n_len,
                                   "symbol name"),
                "contract": self._text(raw, self.str_at + c_at, c_len,
                                       "contract"),
                "section": section, "flags": flags, "offset": offset,
                "size": size})
        self.relocs = []
        for j in range(self.reloc_count):
            r = self.rel_at + j * RELOC_REC
            if r + RELOC_REC > len(raw):
                raise Unreadable("relocation record %d past end of file" % j)
            section, kind = struct.unpack_from("<2I", raw, r)
            (offset,) = struct.unpack_from("<Q", raw, r + 8)
            (target,) = struct.unpack_from("<I", raw, r + 16)
            (addend,) = struct.unpack_from("<q", raw, r + 24)
            self.relocs.append({"index": j, "section": section, "kind": kind,
                                "offset": offset, "target": target,
                                "addend": addend})

    @staticmethod
    def _text(raw, at, length, what):
        if at + length > len(raw):
            raise Unreadable("%s string runs past end of file" % what)
        try:
            return raw[at:at + length].decode("ascii")
        except UnicodeDecodeError:
            raise Unreadable("%s is not ASCII" % what)

    def payload_span(self, section):
        """Byte span of a section payload in the FILE, or None if empty."""
        s = self.sections[section - 1]
        if not s["size"]:
            return None
        return (s["offset"], s["size"])


def describe(path, o):
    """Print the layout before any verdict. An instrument that prints only a
    count is a number about a set it cannot see."""
    print("LAYOUT %s version=%d target=%d entry_symbol=%d symbols=%d "
          "relocs=%d" % (path, o.version, o.target, o.entry_symbol,
                         o.symbol_count, o.reloc_count))
    for j, s in enumerate(o.sections, 1):
        print("  section %d %-5s perms=%d align=%d size=%d file_offset=%s"
              % (j, SECTION_NAMES.get(j, "?"), s["perms"], s["align"],
                 s["size"], s["offset"] if s["size"] else "-"))
    for s in o.symbols:
        print("  sym[%d] %-28s section=%d offset=%-6d size=%-6d flags=%s"
              % (s["index"], s["name"], s["section"], s["offset"], s["size"],
                 describe_flags(s["flags"])))
        print("        contract=%s" % s["contract"])
    for r in o.relocs:
        target = o.symbols[r["target"] - 1]["name"] if 1 <= r["target"] <= len(
            o.symbols) else "<out of range %d>" % r["target"]
        print("  reloc[%d] %-5s section=%d offset=%-6d target=%s addend=%d"
              % (r["index"], RELOC_NAME.get(r["kind"], "kind%d" % r["kind"]),
                 r["section"], r["offset"], target, r["addend"]))


def describe_flags(flags):
    parts = []
    for bit, name in ((NT_EXPORT, "export"), (NT_FUNCTION, "function"),
                      (NT_VARIABLE, "variable"), (NT_IMPORT, "import")):
        if flags & bit:
            parts.append(name)
    return ",".join(parts) or "none"


def audit(path, o, failures):
    """Append human-readable layout failures. Every check below is a property
    of ONE object; none of them references another build."""

    def bad(msg):
        failures.append("%s: %s" % (path, msg))

    # --- section table: the arrangement the payloads sit in -------------
    for j, s in enumerate(o.sections, 1):
        if s["id"] != j:
            bad("section record %d carries id %d; the table is not in "
                "section order" % (j, s["id"]))
        if s["size"] and s["offset"] + s["size"] > len(o.raw):
            bad("section %d payload runs %d bytes past end of file"
                % (j, s["offset"] + s["size"] - len(o.raw)))
        # An empty section still records the cursor where its payload WOULD
        # begin: nt_object_write assigns offsets[j] = size before adding
        # o->sections[j].size (object.c:127-133). So a nonzero offset on a
        # zero-size section is the format working, not a defect. What is
        # checkable is that the offset is the end of the previous section.
        if not s["size"] and j > 1 and s["offset"] < o.sections[j - 2][
                "offset"] + o.sections[j - 2]["size"]:
            bad("empty section %d records file offset %d, which is before the "
                "end of section %d at %d"
                % (j, s["offset"], j - 1,
                   o.sections[j - 2]["offset"] + o.sections[j - 2]["size"]))
    order = [j for j in (1, 2, 3) if o.sections[j - 1]["size"]]
    spans = sorted((o.sections[j - 1]["offset"], o.sections[j - 1]["size"], j)
                   for j in order)
    for a, b in zip(spans, spans[1:]):
        if a[0] + a[1] > b[0]:
            bad("sections %d and %d overlap in the file: %d+%d vs %d"
                % (a[2], b[2], a[0], a[1], b[0]))
    for off, size, j in spans:
        if off % o.sections[j - 1]["align"]:
            bad("section %d payload at file offset %d is not a multiple of "
                "its declared alignment %d"
                % (j, off, o.sections[j - 1]["align"]))

    # --- symbol table: canonical ORDER, and each symbol inside its section
    previous = None
    for s in o.symbols:
        if previous is not None and not previous["name"] < s["name"]:
            bad("symbol table is not strictly ascending at index %d: %r does "
                "not sort before %r" % (s["index"], previous["name"], s["name"]))
        previous = s
        role = s["flags"] & (NT_FUNCTION | NT_VARIABLE)
        if s["flags"] & ~(NT_EXPORT | NT_FUNCTION | NT_VARIABLE | NT_IMPORT):
            bad("symbol %s carries undefined flag bits 0x%x"
                % (s["name"], s["flags"] & ~15))
        if role not in (NT_FUNCTION, NT_VARIABLE):
            bad("symbol %s is neither a function nor a variable "
                "(flags=%s)" % (s["name"], describe_flags(s["flags"])))
        if s["flags"] & NT_IMPORT:
            if s["section"] or s["offset"] or s["size"]:
                bad("import symbol %s claims section %d offset %d size %d; an "
                    "unresolved import occupies nothing"
                    % (s["name"], s["section"], s["offset"], s["size"]))
            if s["flags"] & NT_EXPORT:
                bad("import symbol %s is also marked export" % s["name"])
        else:
            if not s["section"] or s["section"] > 3:
                bad("symbol %s is defined but names section %d"
                    % (s["name"], s["section"]))
            elif s["offset"] + s["size"] > o.sections[s["section"] - 1]["size"]:
                bad("symbol %s spans [%d,%d) and leaves section %s, which is "
                    "%d bytes"
                    % (s["name"], s["offset"], s["offset"] + s["size"],
                       SECTION_NAMES.get(s["section"], "?"),
                       o.sections[s["section"] - 1]["size"]))
            if role == NT_FUNCTION and s["section"] != NT_TEXT:
                bad("function %s is in section %s; functions belong in text"
                    % (s["name"], SECTION_NAMES.get(s["section"], "?")))
            if role == NT_FUNCTION and not s["size"]:
                bad("function %s has size 0" % s["name"])
        if not s["contract"]:
            bad("symbol %s carries an empty typed contract" % s["name"])
        else:
            # The contract must AGREE with the record that carries it. The
            # producer writes both from one source of truth
            # (object_build.c:165-209, using s->section at :176 and :202), so
            # a disagreement is a layout defect that no byte of the PE can
            # show: materialize copies payloads and applies relocations
            # (object_materialize.c:42-76) and never reads a contract. This is
            # the check that makes the instrument a LAYOUT instrument - it
            # compares two statements about the same symbol inside one file,
            # and is therefore indifferent to whether any other build agrees.
            # The two contract kinds spell the section differently and both
            # are real: a FUNCTION contract writes the section as a name
            # (`section=.text`, object_build.c:176) while a DATA contract
            # writes it as the raw number (`section=%u`,
            # object_build.c:202). An earlier version of this check knew only
            # the named form and reported two healthy corpus objects as
            # broken - the instrument was wrong, not the tree.
            declared = contract_field(s["contract"], "section")
            if declared is None:
                bad("symbol %s has a contract with no section= field: %r"
                    % (s["name"], s["contract"]))
            else:
                if declared.isdigit():
                    named = int(declared)
                    if not 1 <= named <= 3:
                        bad("symbol %s declares section number %s in its "
                            "contract, outside 1..3"
                            % (s["name"], declared))
                else:
                    named = SECTION_BY_NAME.get(declared)
                    if named is None:
                        bad("symbol %s declares unknown section %r in its "
                            "contract" % (s["name"], declared))
                if named is not None and not (s["flags"] & NT_IMPORT) \
                        and s["section"] != named:
                    bad("symbol %s is recorded in section %d (%s) but its "
                        "contract declares section %r; the record and the "
                        "contract disagree about the same symbol"
                        % (s["name"], s["section"],
                           SECTION_NAMES.get(s["section"], "?"), declared))
            target = contract_field(s["contract"], "target")
            if target is not None:
                expected = TARGET_NAMES.get(o.target)
                if expected is not None and target != expected:
                    bad("symbol %s declares target %r but the object header "
                        "declares target %d (%s)"
                        % (s["name"], target, o.target, expected))
            abi = contract_field(s["contract"], "abi")
            if abi is not None and abi not in ABI_PROFILES:
                # The two profiles this tree actually implements are
                # frontend.c:2830 (nx64-abi-v0) and frontend.c:2894
                # (efi-x64-v0); nt_object_compile defaults to the first
                # (object_build.c:175). A contract naming anything else
                # describes a calling convention no consumer here can honour,
                # and it is written down ONLY in the contract: the linker
                # compares contract strings for equality (object_link.c:156)
                # and materialize never reads one.
                bad("symbol %s declares ABI profile %r, which is not one of "
                    "the %d profiles this tree implements (%s)"
                    % (s["name"], abi, len(ABI_PROFILES),
                       ", ".join(sorted(ABI_PROFILES))))

    # Defined symbols must not overlap inside their section. This is a layout
    # property no digest of the PE states, because the PE stores only the
    # section payload and would be byte-identical with overlapping symbols.
    placed = {}
    for s in o.symbols:
        if s["flags"] & NT_IMPORT or not s["section"] or not s["size"]:
            continue
        placed.setdefault(s["section"], []).append(s)
    for section, members in placed.items():
        members.sort(key=lambda x: (x["offset"], x["name"]))
        for a, b in zip(members, members[1:]):
            if a["offset"] + a["size"] > b["offset"]:
                bad("symbols %s [%d,%d) and %s [%d,%d) overlap in %s"
                    % (a["name"], a["offset"], a["offset"] + a["size"],
                       b["name"], b["offset"], b["offset"] + b["size"],
                       SECTION_NAMES.get(section, "?")))

    # --- entry symbol ----------------------------------------------------
    # An entry symbol is OPTIONAL in a compilation unit: nt_object_compile sets
    # it only for the exported `main` whose offset equals the codegen entry
    # (object_build.c:343-347), so a library unit such as math.nxo correctly
    # carries none. An earlier version of this check demanded one from every
    # target-1 object and was wrong: it reported a healthy library as broken.
    # What must hold is that an entry, when present, is a defined function in
    # text - the invariant nt_object_validate enforces at object.c:79-85,
    # restated here without going through the reader.
    if o.entry_symbol:
        if not 1 <= o.entry_symbol <= o.symbol_count:
            bad("entry symbol index %d is out of range (%d symbols)"
                % (o.entry_symbol, o.symbol_count))
        else:
            e = o.symbols[o.entry_symbol - 1]
            if e["section"] != NT_TEXT or not (e["flags"] & NT_FUNCTION) or (
                    e["flags"] & NT_IMPORT):
                bad("entry symbol %s is in %s with flags %s; the entry must "
                    "be a DEFINED function in text"
                    % (e["name"], SECTION_NAMES.get(e["section"], "?"),
                       describe_flags(e["flags"])))
    elif any(s["section"] == NT_TEXT and (s["flags"] & NT_FUNCTION) and
             s["name"].split(".")[-1] == "main" and
             (s["flags"] & NT_EXPORT) for s in o.symbols):
        bad("this object defines an exported `main` in text but records no "
            "entry symbol; the entry is unresolvable at link time")

    # --- relocation table: canonical order, in-bounds sites, live targets -
    previous = None
    for r in o.relocs:
        width = RELOC_WIDTH.get(r["kind"], 0)
        if not width:
            bad("relocation %d has unknown kind %d" % (r["index"], r["kind"]))
            continue
        if r["section"] < 1 or r["section"] > 3:
            bad("relocation %d names section %d" % (r["index"], r["section"]))
        elif r["offset"] + width > o.sections[r["section"] - 1]["size"]:
            bad("relocation %d at %s+%d width %d leaves that section, which "
                "is %d bytes"
                % (r["index"], SECTION_NAMES.get(r["section"], "?"),
                   r["offset"], width, o.sections[r["section"] - 1]["size"]))
        if not 1 <= r["target"] <= o.symbol_count:
            bad("relocation %d targets symbol index %d, outside the %d "
                "symbols" % (r["index"], r["target"], o.symbol_count))
        if previous is not None:
            if r["section"] < previous["section"]:
                bad("relocation %d is in section %d, before relocation %d in "
                    "section %d; the table is not in section order"
                    % (r["index"], r["section"], previous["index"],
                       previous["section"]))
            elif r["section"] == previous["section"]:
                if r["offset"] < previous["offset"] + RELOC_WIDTH.get(
                        previous["kind"], 0):
                    bad("relocation %d at offset %d is not canonically ordered "
                        "after relocation %d at offset %d"
                        % (r["index"], r["offset"], previous["index"],
                           previous["offset"]))
        previous = r


def perturb_abi(src, dst):
    """Write a COPY of `src` to `dst` with one contract's `abi=` field
    rewritten, and say what it did.

    This lives beside the audit rather than in a harness so there is exactly
    one implementation of the perturbation. The first version of it lived in a
    throwaway script, computed its patch offset as str_at + len(contract) - 16,
    overwrote the file header, and produced a case that LOOKED like a caught
    defect when nothing had been shown. The offset is recovered by locating
    the exact marker bytes, the substitution is length-preserving by
    construction, and both facts are asserted here rather than assumed.

    The perturbed object is the purest demonstration available: the defect is
    in a typed contract, materialization never reads a contract, and the linked
    PE is byte-identical to the unperturbed one's. A digest check cannot see
    it; the audit above does.
    """
    try:
        with open(src, "rb") as handle:
            raw = handle.read()
    except OSError as exc:
        sys.stderr.write("cannot read %s (%s)\n" % (src, exc))
        return 2
    o = Layout(raw)
    at = -1
    for s in o.symbols:
        c = s["contract"]
        if "abi=nx64-abi-v0" not in c:
            continue
        needle = c.encode()
        # `at` is where the CONTRACT begins; the marker sits at a known offset
        # inside it. Splicing at the contract start was the first version's
        # bug and it produced a contract reading "abi=nx64-abi-v14-nexora-
        # ux64-uefi" - still caught, but by the wrong check and for the wrong
        # reason, which is a demonstration that does not demonstrate.
        inner = c.find("abi=nx64-abi-v0")
        at = raw.find(needle, o.str_at, o.str_at + o.strings) + inner
        break
    if at < 0:
        sys.stderr.write("no nx64-abi-v0 contract in %s; cannot perturb\n" % src)
        return 2
    patched = raw[:at] + b"abi=nx64-abi-v1" + \
        raw[at + len(b"abi=nx64-abi-v0"):]
    if len(patched) != len(raw):
        sys.stderr.write("perturbation changed the file length\n")
        return 2
    changed = sum(1 for x, y in zip(raw, patched) if x != y)
    with open(dst, "wb") as handle:
        handle.write(patched)
    print("LAYOUT_PERTURBATION src=%s dst=%s field=abi "
          "from=nx64-abi-v0 to=nx64-abi-v1 bytes_changed=%d of %d"
          % (src, dst, changed, len(raw)))
    return 0



def main(argv):
    if len(argv) == 4 and argv[1] == "--perturb-abi":
        return perturb_abi(argv[2], argv[3])
    if len(argv) < 2:
        sys.stderr.write(
            "usage: ntlayout.py FILE.nxo [FILE.nxo ...]\n"
            "       ntlayout.py --perturb-abi SRC.nxo DST.nxo\n")
        return 2
    failures, unreadable, objects, symbols, relocs = [], [], 0, 0, 0
    for path in argv[1:]:
        try:
            with open(path, "rb") as handle:
                raw = handle.read()
        except OSError as exc:
            unreadable.append("%s: cannot read (%s)" % (path, exc))
            continue
        try:
            o = Layout(raw)
            o.raw = raw
        except Unreadable as exc:
            unreadable.append("%s: %s" % (path, exc))
            continue
        objects += 1
        symbols += o.symbol_count
        relocs += o.reloc_count
        describe(path, o)
        audit(path, o, failures)
    print("LAYOUT_SUMMARY objects=%d symbols=%d relocs=%d failures=%d "
          "unreadable=%d" % (objects, symbols, relocs, len(failures),
                             len(unreadable)))
    for line in unreadable:
        print("LAYOUT_UNREADABLE %s" % line)
    for line in failures:
        print("LAYOUT_FAILURE %s" % line)
    return 1 if (failures or unreadable) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
