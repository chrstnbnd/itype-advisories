# ITYPE-01: iType RS/WS storage out-of-bounds read and write

**CVE status:** Requested from MITRE; not yet assigned  
**Researchers:** Christian Bond and Irmina Backes

## Summary

The RS and WS bytecode handlers take a storage index from the font program
and use it to read and write the interpreter's storage array. Neither handler
checks the index against the declared storage count, so a font can read and
write outside the array.

RS and WS are covered by one advisory because they are the read and write halves
of the same unchecked storage access.

## Affected component

- Component: Monotype iType TrueType-bytecode interpreter
- Library: `/usr/lib/libfreetype.so.6.16.0`
- SHA-256: `bda2e16c1e7981997114c42f6134ebef2aff1b0ed3f18396bf2cf5317b76dc61`
- Firmware build tested: 5.19.4.0.1
- Other iType versions and products: not assessed

## Relationship to FreeType

The library carries FreeType's filename and SONAME, but the vulnerable
interpreter is a separate implementation. SONAME `6.16.0` is FreeType 2.9.0,
in which `Ins_RS` and `Ins_WS` bound the index with `BOUNDSL( I,
exc->storeSize )`. The interpreter described here performs no equivalent
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

- CWE-125: Out-of-bounds Read
- CWE-787: Out-of-bounds Write
- CWE-129: Improper Validation of Array Index

## Fix

Reject any storage index that is not below the active storage count, in both
handlers, before the address is calculated.

## Reproducer

A minimal font that triggers this issue is held by the researchers. It is
available to Monotype or to a licensee's product-security team on request,
through GitHub to @chrstnbnd.
