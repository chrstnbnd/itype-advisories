# Seven memory-safety vulnerabilities in the Monotype iType bytecode interpreter

Monotype iType is a widely licensed embedded font engine. Its TrueType bytecode
interpreter runs hinting programs embedded in font files. Seven of its opcode
handlers use an index taken from the font program without checking it against
the array it indexes, so a crafted font can read and write memory outside those
arrays.

Each of the seven is a separate handler with its own missing check and its own
fix. They are listed separately for that reason.

| Advisory | Vulnerable operation | Weakness | CVE status |
|---|---|---|---|
| [ITYPE-01](advisories/ITYPE-01-storage-rs-ws.md) | RS/WS storage access | OOB read and write | Requested; not yet assigned |
| [ITYPE-02](advisories/ITYPE-02-wcvtp.md) | WCVTP table write | OOB write | Requested; not yet assigned |
| [ITYPE-03](advisories/ITYPE-03-deltac.md) | DELTAC table update | OOB read-modify-write | Requested; not yet assigned |
| [ITYPE-04](advisories/ITYPE-04-msirp.md) | MSIRP point movement | OOB write | Requested; not yet assigned |
| [ITYPE-05](advisories/ITYPE-05-miap.md) | MIAP point movement | OOB write | Requested; not yet assigned |
| [ITYPE-06](advisories/ITYPE-06-a6-szps-shc.md) | A6 / SZPS / SZP2 / SHC zone records | OOB writes | Requested; not yet assigned |
| [ITYPE-07](advisories/ITYPE-07-mirp.md) | MIRP point movement | OOB write | Requested; not yet assigned |

## Affected component

- Component: Monotype iType TrueType-bytecode interpreter
- Library: `/usr/lib/libfreetype.so.6.16.0`
- SHA-256: `bda2e16c1e7981997114c42f6134ebef2aff1b0ed3f18396bf2cf5317b76dc61`
- Firmware build tested: 5.19.4.0.1

## This is not a FreeType vulnerability

The affected library carries FreeType's filename and SONAME, but the vulnerable
interpreter is a separate implementation compiled into it.

SONAME `6.16.0` is FreeType 2.9.0. In that release every handler named above
bounds the index these findings report as unchecked — `Ins_RS` and `Ins_WS`
against `exc->storeSize`, `Ins_WCVTP` and `Ins_DELTAC` against `exc->cvtSize`,
`Ins_MSIRP`, `Ins_MIAP` and `Ins_MIRP` against the active zone's `n_points`,
and `Ins_SHC` against `exc->zp2.n_contours`. Any reader can confirm this in the
FreeType sources.

These findings therefore do not describe a defect in FreeType's own TrueType
interpreter.

## Impact and preconditions

Opening a crafted AZW3 document reaches the interpreter. The proof
configuration uses a system font with the boldness setting at 0. The user must
open the document, so none of these are zero-click issues.

A proof of concept achieved native code execution as the unprivileged
application framework user (`uid=9000`). Privilege escalation beyond that user
is not part of these advisories.

Disabling bytecode execution for embedded fonts removes reach to every handler
listed here and is an effective containment measure.

## Scope

These advisories cover the build identified above. Other iType versions, and
other products that embed iType, are not assessed here. Whether a given product
is exposed depends on whether it renders untrusted font programs: a product that
renders only its own bundled fonts is not reachable through these handlers.

## Reproducer

A minimal font that triggers each issue is held by the researchers. These
advisories contain no exploit code and no weaponized proof artifacts.

Reproducers are available to Monotype or to a licensee's product-security team
on request, through GitHub to @chrstnbnd.

## Disclosure

See [TIMELINE.md](TIMELINE.md).

Researchers: **Christian Bond and Irmina Backes**.
