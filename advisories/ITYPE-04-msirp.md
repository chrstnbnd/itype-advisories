# ITYPE-04: iType MSIRP point-index out-of-bounds write

**CVE status:** Requested from MITRE; not yet assigned  
**Researchers:** Christian Bond and Irmina Backes

## Summary

The MSIRP bytecode handler takes a point index from the font program, computes a
coordinate, and stores it through that index. It does not check the index
against the bounds of the selected point zone, so a font can write outside the
coordinate arrays.

## Affected component

- Component: Monotype iType TrueType-bytecode interpreter
- Library: `/usr/lib/libfreetype.so.6.16.0`
- SHA-256: `bda2e16c1e7981997114c42f6134ebef2aff1b0ed3f18396bf2cf5317b76dc61`
- Firmware build tested: 5.19.4.0.1
- Other iType versions and products: not assessed

## Relationship to FreeType

The library carries FreeType's filename and SONAME, but the vulnerable
interpreter is a separate implementation. SONAME `6.16.0` is FreeType 2.9.0,
in which `Ins_MSIRP` bounds both the destination and the reference point with
`BOUNDS( point, exc->zp1.n_points )` and `BOUNDS( exc->GS.rp0,
exc->zp0.n_points )`. The interpreter described here performs no equivalent
check. These findings do not describe a defect in FreeType's own TrueType
interpreter.

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

## Fix

Check the destination point against the selected zone before each coordinate
store.

## Reproducer

A minimal font that triggers this issue is held by the researchers. It is
available to Monotype or to a licensee's product-security team on request,
through GitHub to @chrstnbnd.
