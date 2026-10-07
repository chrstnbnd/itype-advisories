# ITYPE-06: iType zone-record out-of-bounds writes via A6, SZPS/SZP2 and SHC

**CVE status:** Requested from MITRE; not yet assigned  
**Researchers:** Christian Bond and Irmina Backes

## Summary

Opcode A6 writes font-controlled words into interpreter record state. SZPS and
SZP2 can then select that state as the active zone, and SHC consumes its
coordinate, seed and tag fields. No step verifies that the selected record and
the pointers inside it belong to the active glyph zone, so a font can direct
coordinate and tag writes outside those objects.

The three opcodes are covered by one advisory because the write requires all
three steps: A6 supplies the state, SZPS/SZP2 selects it, and SHC consumes it.

## Affected component

- Component: Monotype iType TrueType-bytecode interpreter
- Library: `/usr/lib/libfreetype.so.6.16.0`
- SHA-256: `bda2e16c1e7981997114c42f6134ebef2aff1b0ed3f18396bf2cf5317b76dc61`
- Firmware build tested: 5.19.4.0.1
- Other iType versions and products: not assessed

## Relationship to FreeType

The library carries FreeType's filename and SONAME, but the vulnerable
interpreter is a separate implementation. SONAME `6.16.0` is FreeType 2.9.0,
in which `Ins_SHC` bounds the contour against `exc->zp2.n_contours`, and
`Ins_SZPS` and `Ins_SZP2` reject an invalid zone selection rather than storing
it. The interpreter described here performs no equivalent check. These
findings do not describe a defect in FreeType's own TrueType interpreter.

## Impact and preconditions

Opening a crafted AZW3 document reaches this handler. The proof configuration
uses a system font with the boldness setting at 0. The user must open the
document, so this is not a zero-click issue.

A proof of concept achieved native code execution as the unprivileged
application framework user (`uid=9000`). Privilege escalation beyond that user
is not part of this advisory.

## Weakness

- CWE-787: Out-of-bounds Write
- CWE-129: Improper Validation of Array Index
- CWE-20: Improper Input Validation

## Fix

Validate the state A6 creates, and reject any zone record or embedded pointer
outside the active glyph-zone objects, before SZPS/SZP2 selects it and before
SHC consumes it.

## Reproducer

A minimal font that triggers this issue is held by the researchers. It is
available to Monotype or to a licensee's product-security team on request,
through GitHub to @chrstnbnd.
